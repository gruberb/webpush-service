//! User agent sessions over WebSocket, compatible with Firefox.
//!
//! RFC 8030 delivers messages to user agents with HTTP/2 server push, which
//! browsers have removed. Firefox instead holds a WebSocket to its push
//! server and speaks a small JSON protocol, defined in practice by Firefox
//! (`dom/push/PushServiceWebSocket.sys.mjs`). This module implements the
//! server side of that protocol, so Firefox can use this service by setting
//! `dom.push.serverURL`.
//!
//! ```text
//!  user agent                               session task         hub/route   store
//!    | upgrade "push-notification"               |                    |        |
//!    | hello {uaid?}                             |                    |        |
//!    |------------------------------------------>| known uaid? --------------->|
//!    |                                           | listen(UserAgent) >|        |
//!    | hello {uaid, status 200, use_webpush}     |                    |        |
//!    |<------------------------------------------|                    |        |
//!    | notification ... (first backlog batch)    | pending(batch) ------------>|
//!    |<------------------------------------------|                    |        |
//!    | register / unregister / ack / {}          |                    |        |
//!    |------------------------------------------>|                    |        |
//!    | notification (live)                       |<----- Message -----|        |
//!    |<------------------------------------------|                    |        |
//! ```
//!
//! Listening before reading the backlog means a message stored between the
//! two steps still reaches the session, as a live event. As a result a
//! message can arrive both ways, so deliveries are deduplicated by message
//! id. Every new session resends every unacknowledged message, which is the
//! redelivery RFC 8030 §6.2 asks for; Firefox discards duplicates by
//! `version`.
//!
//! A user agent that says `hello` without a known `uaid` gets a fresh one,
//! but nothing is stored until its first `register`, so clients that connect
//! and never subscribe leave no state behind.
//!
//! The backlog goes out in batches of `websocket.backlog_batch`; the next
//! batch is read once every message sent so far has been acknowledged. See
//! `docs/websocket-protocol.md`.

use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Extension,
    extract::{
        State,
        ws::{CloseFrame, Message as Frame, WebSocket, WebSocketUpgrade, close_code},
    },
    response::Response,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::{Value, json};
use webpush_store::{BoxError, Recipient, Store, UserAgent, is_uaid, new_uaid, now_ms};

use crate::{
    app::App,
    headers,
    hub::{Event, Notification},
    notify::Listener,
    subscription::{self, Registered},
    telemetry,
    transport::ConnectionPermit,
};

/// Subprotocol Firefox requests on the push WebSocket.
const SUBPROTOCOL: &str = "push-notification";
/// Largest accepted client message. Client messages are small JSON objects.
const MAX_MESSAGE: usize = 64 * 1024;
/// How often a connected user agent's `last_seen` is refreshed, so a session
/// that stays open for months does not expire.
const TOUCH_INTERVAL: Duration = Duration::from_secs(6 * 3600);

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
    /// Subscribe to broadcasts. Broadcasts are not part of Web Push and
    /// this service offers none, so the message is accepted and ignored.
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

/// Accept the WebSocket upgrade on `/` and run the session. The session
/// holds its connection's permit, so it counts against
/// `public.max_connections` until it closes.
pub async fn upgrade<S: Store>(
    State(app): State<Arc<App<S>>>,
    permit: Option<Extension<ConnectionPermit>>,
    ws: WebSocketUpgrade,
) -> Response {
    let tasks = app.shutdown.tasks.clone();
    ws.protocols([SUBPROTOCOL])
        .max_message_size(MAX_MESSAGE)
        .on_upgrade(move |socket| {
            tasks.track_future(async move {
                let _permit = permit;
                let _open = telemetry::Gauge::new(telemetry::SESSIONS, "");
                if let Err(e) = Session::run(socket, app).await {
                    tracing::debug!(error = %e, "session");
                }
            })
        })
}

/// What the session loop woke up for.
enum Step {
    /// A frame from the user agent, or the end of the connection.
    Frame(Option<Result<Frame, axum::Error>>),
    /// An event from the hub, or the hub dropping the listener.
    Event(Option<Event>),
    /// Time to ping, check liveness, and refresh `last_seen`.
    Tick,
    /// The service is shutting down.
    Stop,
}

/// One connected user agent.
struct Session<S: Store> {
    /// The connection.
    socket: WebSocket,
    /// Shared service state.
    app: Arc<App<S>>,
    /// The user agent this session serves.
    uaid: String,
    /// Whether the user agent is stored. A new user agent is stored on its
    /// first `register`.
    stored: bool,
    /// Message ids already sent on this connection.
    sent: HashSet<String>,
    /// Sent and not yet acknowledged; the next backlog batch waits for this
    /// to empty.
    unacked: HashSet<String>,
    /// Whether the last backlog batch was full, so more may be stored.
    more: bool,
    /// Last time anything arrived from the user agent.
    heard: Instant,
    /// Last time `last_seen` was refreshed.
    touched: Instant,
}

impl<S: Store> Session<S> {
    /// Handshake, backlog, then serve until either side ends the session.
    async fn run(mut socket: WebSocket, app: Arc<App<S>>) -> Result<(), BoxError> {
        let first = tokio::time::timeout(app.cfg.websocket.hello_timeout, next_text(&mut socket));
        let Ok(Some(ClientMessage::Hello { uaid })) = first.await else {
            return close(&mut socket, close_code::PROTOCOL, "expected hello").await;
        };
        let known = match uaid {
            Some(u) if is_uaid(&u) => app.store.user_agent(&u).await?,
            _ => None,
        };
        // Bridged user agents do not hold sessions; treat their ids as
        // unknown rather than let a session take one over.
        let (uaid, stored) = match known {
            Some(ua) if ua.bridge.is_none() => {
                app.store.touch_user_agent(&ua.uaid, now_ms()).await?;
                (ua.uaid, true)
            }
            _ => (new_uaid(), false),
        };

        // One session per user agent: the previous one, here or on another
        // node, ends.
        let mut listener = app.listen(Recipient::UserAgent(uaid.clone())).await?;
        let now = Instant::now();
        let mut session = Session {
            socket,
            app,
            uaid,
            stored,
            sent: HashSet::new(),
            unacked: HashSet::new(),
            more: false,
            heard: now,
            touched: now,
        };
        session.serve(&mut listener).await
    }

    /// Everything after the listener is registered.
    async fn serve(&mut self, listener: &mut Listener<S>) -> Result<(), BoxError> {
        self.send(&json!({
            "messageType": "hello",
            "uaid": self.uaid,
            "status": 200,
            "use_webpush": true,
            "broadcasts": {},
        }))
        .await?;
        if self.stored {
            self.next_batch().await?;
        }

        let ws = &self.app.cfg.websocket;
        let (ping, pong_timeout) = (ws.ping_interval, ws.pong_timeout);
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + ping, ping);
        let stopping = self.app.shutdown.stopping.clone();
        loop {
            let step = tokio::select! {
                frame = self.socket.recv() => Step::Frame(frame),
                event = listener.rx.recv() => Step::Event(event),
                _ = tick.tick() => Step::Tick,
                () = stopping.cancelled() => Step::Stop,
            };
            match step {
                Step::Frame(None | Some(Err(_) | Ok(Frame::Close(_)))) => return Ok(()),
                Step::Frame(Some(Ok(frame))) => {
                    self.heard = Instant::now();
                    match frame {
                        Frame::Text(text) => match parse(&text) {
                            Some(msg) => self.handle(msg).await?,
                            None => {
                                return self.close(close_code::PROTOCOL, "invalid message").await;
                            }
                        },
                        Frame::Binary(_) => {
                            return self.close(close_code::UNSUPPORTED, "text only").await;
                        }
                        // Pings are answered by the library; pongs only
                        // prove liveness.
                        _ => {}
                    }
                }
                Step::Event(Some(Event::Message(n))) => {
                    self.notify(&n).await?;
                }
                Step::Event(Some(Event::Gone)) => {
                    return self.close(close_code::NORMAL, "replaced").await;
                }
                Step::Event(None) => {
                    // Dropped for falling behind; the client reconnects and
                    // reads what it missed from storage.
                    return self.close(close_code::AGAIN, "try again").await;
                }
                Step::Event(Some(Event::Receipt(..))) => {}
                Step::Tick => {
                    if self.heard.elapsed() > ping + pong_timeout {
                        return self.close(close_code::AWAY, "idle").await;
                    }
                    self.socket.send(Frame::Ping(bytes::Bytes::new())).await?;
                    if self.stored && self.touched.elapsed() > TOUCH_INTERVAL {
                        self.touched = Instant::now();
                        self.app
                            .store
                            .touch_user_agent(&self.uaid, now_ms())
                            .await?;
                    }
                }
                Step::Stop => return self.close(close_code::AWAY, "shutting down").await,
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
                if let Some(ch) = subscription::channel_id(&channel_id)
                    && self.stored
                {
                    let receipts = self.app.store.delete_subscription(&self.uaid, &ch).await?;
                    self.app.notify_receipts(receipts).await;
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
                if self.unacked.is_empty() && self.more {
                    self.next_batch().await?;
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
        let Some(ch) = subscription::channel_id(channel_id) else {
            return Ok(reply(400));
        };
        let vapid = match key.map(subscription::vapid_key) {
            None => None,
            Some(Some(k)) => Some(k),
            Some(None) => return Ok(reply(400)),
        };
        if !self.stored {
            let ua = UserAgent {
                uaid: self.uaid.clone(),
                bridge: None,
                last_seen: now_ms(),
            };
            self.app.store.create_user_agent(&ua).await?;
            self.stored = true;
        }
        let sub = match subscription::register(&self.app.store, &self.uaid, &ch, vapid).await? {
            Registered::Created(sub) | Registered::Existing(sub) => sub,
            Registered::Conflict => return Ok(reply(409)),
        };
        let mut ok = reply(200);
        ok["pushEndpoint"] = format!("{}/push/{}", self.app.origin(), sub.push).into();
        Ok(ok)
    }

    /// Process one acknowledgement. Codes 101 and 102 mean the user agent
    /// could not use the message, so it will not be retried: 410 receipt.
    async fn ack(&mut self, update: &AckUpdate) -> Result<(), BoxError> {
        self.unacked.remove(&update.version);
        let status = match update.code.unwrap_or(100) {
            100 => 204,
            101 | 102 => 410,
            _ => return Ok(()),
        };
        let Some(ch) = subscription::channel_id(&update.channel_id) else {
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
            self.app.owe_receipt(&m, status).await?;
        }
        Ok(())
    }

    /// Send the next batch of stored messages.
    async fn next_batch(&mut self) -> Result<(), BoxError> {
        let batch = self.app.cfg.websocket.backlog_batch;
        let pending = self.app.store.pending(&self.uaid, now_ms(), batch).await?;
        self.more = pending.len() == batch;
        let mut new = 0;
        for m in &pending {
            if self.notify(&Notification::from(m)).await? {
                new += 1;
            }
        }
        // A batch of messages already sent live makes no progress; the rest
        // of the backlog waits for the next session.
        if new == 0 {
            self.more = false;
        }
        Ok(())
    }

    /// Send a message to the user agent, once per connection. Returns whether
    /// it was sent now. Only the channel, the message id, the body, and its
    /// content coding are sent; TTL, Urgency, Topic, and VAPID data never are
    /// (RFC 8030 §5.3, §5.4, RFC 8292 §4.2).
    async fn notify(&mut self, n: &Notification) -> Result<bool, BoxError> {
        if !self.sent.insert(n.id.clone()) {
            return Ok(false);
        }
        self.unacked.insert(n.id.clone());
        let mut msg = json!({
            "messageType": "notification",
            "channelID": n.channel_id,
            "version": n.id,
        });
        if !n.body.is_empty() {
            msg["data"] = URL_SAFE_NO_PAD.encode(&n.body).into();
        }
        if let Some(encoding) = &n.encoding {
            msg["headers"] = json!({ "encoding": encoding });
        }
        self.send(&msg).await?;
        metrics::counter!(telemetry::DELIVERED, "via" => "websocket").increment(1);
        Ok(true)
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
}
