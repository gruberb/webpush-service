//! User agent sessions over WebSocket, compatible with Firefox.
//!
//! RFC 8030 delivers messages to user agents with HTTP/2 server push, which
//! browsers have removed. Firefox instead holds a WebSocket to its push
//! server and speaks a small JSON protocol, defined in practice by Firefox
//! (`dom/push/PushServiceWebSocket.sys.mjs`) and Mozilla's autopush. This
//! module implements the server side of that protocol, so Firefox can use
//! this service by setting `dom.push.serverURL`.
//!
//! ```text
//!  Firefox                                  session task            hub   store
//!    | upgrade "push-notification"               |                    |      |
//!    | hello {uaid?}                             |                    |      |
//!    |------------------------------------------>| resume or create -------->|
//!    |                                           | Gone to old session|      |
//!    |                                           | register(Ua) ----->|      |
//!    | hello {uaid, status 200, use_webpush}     |                    |      |
//!    |<------------------------------------------|                    |      |
//!    | notification ... (backlog, oldest first)  | pending ------------------>|
//!    |<------------------------------------------|                    |      |
//!    | register / unregister / ack / {}          |                    |      |
//!    |------------------------------------------>|                    |      |
//!    | notification (live)                       |<---- Message ------|      |
//!    |<------------------------------------------|                    |      |
//! ```
//!
//! Registering with the hub before reading the backlog means a message stored
//! between the two steps still reaches the session, as a live event. As a
//! result a message can arrive both ways, so deliveries are deduplicated by
//! message id. Every new session resends every unacknowledged message, which
//! is the redelivery RFC 8030 §6.2 asks for; Firefox discards duplicates by
//! `version`. See `docs/websocket-protocol.md`.

use std::{collections::HashSet, sync::Arc, time::Duration};

use axum::{
    extract::{
        State,
        ws::{CloseFrame, Message as Frame, WebSocket, WebSocketUpgrade, close_code},
    },
    response::Response,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    App, BoxError, api, headers,
    hub::{Event, Key},
    now_ms,
    store::{Message, Store},
};

/// Subprotocol Firefox requests on the push WebSocket.
const SUBPROTOCOL: &str = "push-notification";
/// A client that has not sent `hello` by then is disconnected.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest accepted client message. Client messages are small JSON objects.
const MAX_MESSAGE: usize = 64 * 1024;

/// A message from the user agent, tagged by `messageType`. Fields the
/// service does not use are ignored.
#[derive(Debug, Deserialize)]
#[serde(tag = "messageType", rename_all = "snake_case")]
enum ClientMessage {
    /// Session start. Firefox sends `uaid` only when it holds subscriptions.
    Hello {
        /// The user agent id from a previous session.
        uaid: Option<String>,
    },
    /// Create a subscription.
    Register {
        /// The user agent's name for the subscription, a UUID.
        #[serde(rename = "channelID")]
        channel_id: String,
        /// Application server key to restrict the subscription to
        /// (RFC 8292 §4.1), base64url.
        key: Option<String>,
    },
    /// Delete a subscription. The `code` field (reason) is informational.
    Unregister {
        /// The subscription to delete.
        #[serde(rename = "channelID")]
        channel_id: String,
    },
    /// Acknowledge delivered messages.
    Ack {
        /// One entry per acknowledged message.
        updates: Vec<AckUpdate>,
    },
    /// A message reached the user agent but its service worker failed.
    /// Informational; delivery already happened.
    Nack {},
    /// Subscribe to Mozilla broadcasts. Not part of Web Push; ignored.
    BroadcastSubscribe {},
    /// Keep-alive in its verbose form. The usual form is `{}`.
    Ping,
}

/// One acknowledged message.
#[derive(Debug, Deserialize)]
struct AckUpdate {
    /// The subscription the message was delivered on.
    #[serde(rename = "channelID")]
    channel_id: String,
    /// The message id, as sent in the notification's `version`.
    version: String,
    /// 100 delivered, 101 decryption failed, 102 not delivered.
    code: Option<u16>,
}

/// Parse a text frame. `{}` is the short form of a ping.
fn parse(text: &str) -> Option<ClientMessage> {
    let value: Value = serde_json::from_str(text).ok()?;
    if value.as_object().is_some_and(serde_json::Map::is_empty) {
        return Some(ClientMessage::Ping);
    }
    serde_json::from_value(value).ok()
}

/// Accept the WebSocket upgrade on `/` and run the session.
pub async fn upgrade<S: Store>(State(app): State<Arc<App<S>>>, ws: WebSocketUpgrade) -> Response {
    ws.protocols([SUBPROTOCOL])
        .max_message_size(MAX_MESSAGE)
        .on_upgrade(move |socket| async move {
            if let Err(e) = Session::run(socket, app).await {
                tracing::debug!(error = %e, "session");
            }
        })
}

/// What the session loop woke up for.
enum Step {
    /// A frame from the user agent, or the end of the connection.
    Frame(Option<Result<Frame, axum::Error>>),
    /// An event from the hub, or the hub dropping the registration.
    Event(Option<Event>),
}

/// One connected user agent.
struct Session<S> {
    /// The connection.
    socket: WebSocket,
    /// Shared service state.
    app: Arc<App<S>>,
    /// The user agent this session serves.
    uaid: String,
    /// Message ids already sent on this connection.
    sent: HashSet<String>,
}

impl<S: Store> Session<S> {
    /// Handshake, backlog, then serve until either side ends the session.
    async fn run(mut socket: WebSocket, app: Arc<App<S>>) -> Result<(), BoxError> {
        let first = tokio::time::timeout(HELLO_TIMEOUT, next_text(&mut socket)).await;
        let Ok(Some(ClientMessage::Hello { uaid })) = first else {
            return close(&mut socket, close_code::PROTOCOL, "expected hello").await;
        };
        let uaid = match uaid {
            Some(u) if is_uaid(&u) && app.store.user_agent_exists(&u).await? => u,
            _ => app.store.create_user_agent().await?,
        };

        // One session per user agent: the previous one, if any, ends.
        let key = Key::Ua(uaid.clone());
        app.hub.notify(&key, &Event::Gone);
        let mut rx = app.hub.register(key.clone());
        let mut session = Session {
            socket,
            app,
            uaid,
            sent: HashSet::new(),
        };
        let result = session.serve(&mut rx).await;
        drop(rx);
        session.app.hub.prune(&key);
        result
    }

    /// Everything after the hub registration.
    async fn serve(
        &mut self,
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<Event>,
    ) -> Result<(), BoxError> {
        self.send(&json!({
            "messageType": "hello",
            "uaid": self.uaid,
            "status": 200,
            "use_webpush": true,
            "broadcasts": {},
        }))
        .await?;
        for m in self.app.store.pending(&self.uaid, now_ms()).await? {
            self.notify(&m).await?;
        }

        loop {
            let step = tokio::select! {
                frame = self.socket.recv() => Step::Frame(frame),
                event = rx.recv() => Step::Event(event),
            };
            match step {
                Step::Frame(None | Some(Err(_) | Ok(Frame::Close(_)))) => return Ok(()),
                Step::Frame(Some(Ok(Frame::Text(text)))) => match parse(&text) {
                    Some(msg) => self.handle(msg).await?,
                    None => return self.close(close_code::PROTOCOL, "invalid message").await,
                },
                Step::Frame(Some(Ok(Frame::Binary(_)))) => {
                    return self.close(close_code::UNSUPPORTED, "text only").await;
                }
                Step::Event(Some(Event::Message(m))) => self.notify(&m).await?,
                Step::Event(Some(Event::Gone) | None) => {
                    return self.close(close_code::NORMAL, "replaced").await;
                }
                // WebSocket-level pings are answered by the library, and
                // receipt events are never sent to a user agent key.
                Step::Frame(Some(Ok(_))) | Step::Event(Some(Event::Receipt(..))) => {}
            }
        }
    }

    /// Act on one client message.
    async fn handle(&mut self, msg: ClientMessage) -> Result<(), BoxError> {
        match msg {
            ClientMessage::Hello { .. } => {
                self.close(close_code::PROTOCOL, "duplicate hello").await?;
            }
            ClientMessage::Register { channel_id, key } => {
                let reply = self.register(&channel_id, key.as_deref()).await?;
                self.send(&reply).await?;
            }
            ClientMessage::Unregister { channel_id } => {
                if let Some(ch) = channel(&channel_id) {
                    let receipts = self.app.store.delete_subscription(&self.uaid, &ch).await?;
                    api::notify_receipts(&self.app.hub, receipts);
                }
                self.send(&json!({
                    "messageType": "unregister",
                    "channelID": channel_id,
                    "status": 200,
                }))
                .await?;
            }
            ClientMessage::Ack { updates } => {
                for update in updates {
                    self.ack(&update).await?;
                }
            }
            ClientMessage::Ping => self.send_text("{}").await?,
            ClientMessage::Nack {} | ClientMessage::BroadcastSubscribe {} => {}
        }
        Ok(())
    }

    /// Create or confirm a subscription and build the `register` reply.
    async fn register(&mut self, channel_id: &str, key: Option<&str>) -> Result<Value, BoxError> {
        let reply = |status: u16| json!({ "messageType": "register", "channelID": channel_id, "status": status });
        let Some(ch) = channel(channel_id) else {
            return Ok(reply(400));
        };
        let vapid = match key.map(vapid_key) {
            None => None,
            Some(Some(k)) => Some(k),
            Some(None) => return Ok(reply(400)),
        };
        let sub = match self.app.store.channel(&self.uaid, &ch).await? {
            // Registering again with the same key is idempotent; Firefox
            // retries a register whose reply it did not see.
            Some(sub) if sub.vapid == vapid => sub,
            Some(_) => return Ok(reply(409)),
            None => {
                self.app
                    .store
                    .create_subscription(&self.uaid, &ch, vapid)
                    .await?
            }
        };
        let mut ok = reply(200);
        ok["pushEndpoint"] = format!("{}/push/{}", self.app.origin, sub.push).into();
        Ok(ok)
    }

    /// Process one acknowledgement. Codes 101 and 102 mean the user agent
    /// could not use the message, so it will not be retried: 410 receipt.
    async fn ack(&mut self, update: &AckUpdate) -> Result<(), BoxError> {
        let status = match update.code.unwrap_or(100) {
            100 => 204,
            101 | 102 => 410,
            _ => return Ok(()),
        };
        let Some(ch) = channel(&update.channel_id) else {
            return Ok(());
        };
        if !headers::is_id(&update.version) {
            return Ok(());
        }
        let owner = Some((self.uaid.as_str(), ch.as_str()));
        if let Some(m) = self
            .app
            .store
            .delete_message(&update.version, owner)
            .await?
        {
            api::owe_receipt(&self.app, &m, status).await?;
        }
        Ok(())
    }

    /// Send a message to the user agent, once per connection. Only the
    /// channel, the message id, the body, and its content coding are sent;
    /// TTL, Urgency, Topic, and VAPID data never are (RFC 8030 §5.3, §5.4,
    /// RFC 8292 §4.2).
    async fn notify(&mut self, m: &Message) -> Result<(), BoxError> {
        if !self.sent.insert(m.id.clone()) {
            return Ok(());
        }
        let mut n = json!({
            "messageType": "notification",
            "channelID": m.channel_id,
            "version": m.id,
        });
        if !m.body.is_empty() {
            n["data"] = URL_SAFE_NO_PAD.encode(&m.body).into();
        }
        if let Some(encoding) = &m.cenc {
            n["headers"] = json!({ "encoding": encoding });
        }
        self.send(&n).await
    }

    /// Send a JSON message.
    async fn send(&mut self, value: &Value) -> Result<(), BoxError> {
        self.send_text(&value.to_string()).await
    }

    /// Send a text frame.
    async fn send_text(&mut self, text: &str) -> Result<(), BoxError> {
        Ok(self.socket.send(Frame::Text(text.into())).await?)
    }

    /// End the session with a close frame.
    async fn close(&mut self, code: u16, reason: &'static str) -> Result<(), BoxError> {
        close(&mut self.socket, code, reason).await
    }
}

/// The next client message, skipping WebSocket control frames. `None` when
/// the connection ends or the frame is not a valid message.
async fn next_text(socket: &mut WebSocket) -> Option<ClientMessage> {
    loop {
        match socket.recv().await? {
            Ok(Frame::Text(text)) => return parse(&text),
            Ok(Frame::Ping(_) | Frame::Pong(_)) => {}
            _ => return None,
        }
    }
}

/// Send a close frame. Errors are ignored: the peer may already be gone.
async fn close(socket: &mut WebSocket, code: u16, reason: &'static str) -> Result<(), BoxError> {
    let frame = CloseFrame {
        code,
        reason: reason.into(),
    };
    let _ = socket.send(Frame::Close(Some(frame))).await;
    Ok(())
}

/// A user agent id as this service issues them: 32 lowercase hex characters.
fn is_uaid(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A channel id normalized to a lowercase hyphenated UUID, or `None` if it is
/// not a UUID. Firefox compares channel ids case-insensitively.
fn channel(s: &str) -> Option<String> {
    let valid = s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        });
    valid.then(|| s.to_ascii_lowercase())
}

/// Decode an application server key: base64url with or without padding
/// (Firefox pads), 65 octets, an uncompressed point on P-256.
fn vapid_key(s: &str) -> Option<[u8; 65]> {
    let key: [u8; 65] = URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .ok()?
        .try_into()
        .ok()?;
    (key[0] == 0x04 && p256::PublicKey::from_sec1_bytes(&key).is_ok()).then_some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_firefox_messages() {
        assert!(matches!(parse("{}"), Some(ClientMessage::Ping)));
        assert!(matches!(
            parse(r#"{"messageType":"hello","broadcasts":{},"use_webpush":true}"#),
            Some(ClientMessage::Hello { uaid: None })
        ));
        assert!(matches!(
            parse(r#"{"messageType":"nack","version":"x","code":301}"#),
            Some(ClientMessage::Nack {})
        ));
        assert!(parse("not json").is_none());
        assert!(parse(r#"{"messageType":"launch"}"#).is_none());
    }

    #[test]
    fn channel_ids() {
        let id = "D9B74644-4F97-46AA-B8FA-9393985CD6CD";
        assert_eq!(
            channel(id).as_deref(),
            Some("d9b74644-4f97-46aa-b8fa-9393985cd6cd")
        );
        assert_eq!(channel("d9b746444f9746aab8fa9393985cd6cd"), None);
        assert_eq!(channel("zzzzzzzz-4f97-46aa-b8fa-9393985cd6cd"), None);
    }
}
