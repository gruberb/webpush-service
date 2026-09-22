//! Delivering events to connections, on this node or on another.
//!
//! A single node delivers through the [`Hub`](crate::hub::Hub) alone. In a
//! cluster, the node that holds a connection records itself in the store as
//! the connection's route, and other nodes forward events to it:
//!
//! ```text
//!  endpoint node                    store                  connection node
//!  -------------                    -----                  ---------------
//!                                                 hello:   set_route(ua, me)
//!  POST /push/{id}
//!    insert_message ------------->  message
//!    hub: no local session
//!    route(ua) ------------------>  node url
//!    POST {node}/internal/v1/notify ---------------------> hub.notify(ua)
//!                                                            200 delivered
//!                                                            404 not here:
//!    clear_route(ua, node) ------>  (only if still node)       stale route
//! ```
//!
//! The message is stored before anything is forwarded, so a failed forward
//! loses nothing: the session reads it from storage on its next connect.
//! A node that registers a session sets its route before reading the
//! backlog; since the endpoint stores before it reads the route, every
//! message is either in that backlog or forwarded to the new node.
//!
//! Routes are removed by the node that owns them when the connection ends,
//! and by any node that finds them stale (the target answers 404 or cannot
//! be reached). [`Store::clear_route`] only removes a route that still names
//! the node in question, so a stale cleanup never removes a newer route.

use std::sync::Arc;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::Receiver;
use webpush_store::{Message, Receipt, Recipient, Store};

use crate::{
    BoxError,
    app::App,
    config::Cluster,
    hub::{Event, Notification, Notified},
    telemetry,
};

/// Path of the delivery endpoint on the internal listener.
pub const NOTIFY_PATH: &str = "/internal/v1/notify";

/// This node's identity in the cluster and the client it forwards with.
pub struct ClusterLink {
    /// This node's internal URL, as recorded in routes.
    pub node_url: String,
    /// SHA-256 of the shared token. Incoming tokens are hashed and compared
    /// to it, so the comparison time says nothing about the token.
    token_digest: Vec<u8>,
    /// The token, sent on forwards.
    token: String,
    /// HTTP client for forwards.
    client: reqwest::Client,
}

impl ClusterLink {
    /// A link for the given cluster settings.
    pub fn new(cfg: &Cluster) -> Result<Self, BoxError> {
        Ok(Self {
            node_url: cfg.node_url.trim_end_matches('/').to_owned(),
            token_digest: digest(&SHA256, cfg.token.as_bytes()).as_ref().to_vec(),
            token: cfg.token.clone(),
            client: reqwest::Client::builder()
                .timeout(cfg.notify_timeout)
                .build()?,
        })
    }

    /// Whether `presented` is the cluster token.
    pub fn authorized(&self, presented: &str) -> bool {
        digest(&SHA256, presented.as_bytes()).as_ref() == self.token_digest.as_slice()
    }
}

/// The listener for one recipient. Dropping it unregisters from the hub and,
/// in a cluster, removes this node's route.
pub struct Listener<S: Store> {
    /// Events for the connection.
    pub rx: Receiver<Event>,
    /// Who is listening.
    to: Recipient,
    /// Hub registration id.
    id: u64,
    /// Shared state, for the cleanup on drop.
    app: Arc<App<S>>,
}

impl<S: Store> Drop for Listener<S> {
    fn drop(&mut self) {
        if !self.app.hub.unregister(&self.to, self.id) {
            // Replaced by a newer listener on this node, or dropped for
            // falling behind; the route is not ours to remove.
            return;
        }
        if self.app.cluster.is_some() {
            let (app, to) = (self.app.clone(), self.to.clone());
            self.app.shutdown.tasks.spawn(async move {
                if let Some(c) = &app.cluster
                    && let Err(e) = app.store.clear_route(&to, &c.node_url).await
                {
                    tracing::warn!(error = %e, "clear route");
                }
            });
        }
    }
}

impl<S: Store> App<S> {
    /// Become the listener for `to`, replacing any earlier listener on this
    /// node or, in a cluster, on another node.
    pub async fn listen(self: &Arc<Self>, to: Recipient) -> Result<Listener<S>, BoxError> {
        let (id, rx) = self.hub.register(to.clone());
        let listener = Listener {
            rx,
            to: to.clone(),
            id,
            app: self.clone(),
        };
        if let Some(c) = &self.cluster {
            let previous = self.store.set_route(&to, &c.node_url).await?;
            if let Some(node) = previous.filter(|n| *n != c.node_url) {
                // Close the superseded connection early. If this is lost,
                // that connection only lingers until its client goes away.
                let app = self.clone();
                self.shutdown.tasks.spawn(async move {
                    app.forward(&node, &to, &Event::Gone).await;
                });
            }
        }
        Ok(listener)
    }

    /// Deliver `event` to the listener for `to`, wherever it is. Delivery is
    /// best effort: storage holds everything a listener needs to catch up.
    pub async fn notify(&self, to: &Recipient, event: Event) {
        match self.hub.notify(to, event.clone()) {
            Notified::Delivered => return,
            Notified::Dropped => {
                metrics::counter!(telemetry::LISTENER_DROPPED).increment(1);
                return;
            }
            Notified::Absent => {}
        }
        let Some(c) = &self.cluster else { return };
        let node = match self.store.route(to).await {
            Ok(Some(node)) => node,
            Ok(None) => return,
            Err(e) => {
                tracing::warn!(error = %e, "route lookup");
                return;
            }
        };
        if node == c.node_url {
            // This node's route without a listener: left behind by a
            // listener dropped for falling behind.
            self.clear_stale(to, &node).await;
            return;
        }
        self.forward(&node, to, &event).await;
    }

    /// Hand `event` to `node`, and remove its route if it no longer holds
    /// the connection.
    async fn forward(&self, node: &str, to: &Recipient, event: &Event) {
        let Some(c) = &self.cluster else { return };
        let body = Envelope::new(to, event);
        let result = c
            .client
            .post(format!("{node}{NOTIFY_PATH}"))
            .bearer_auth(&c.token)
            .json(&body)
            .send()
            .await;
        let outcome = match result {
            Ok(r) if r.status().is_success() => "delivered",
            Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND => {
                self.clear_stale(to, node).await;
                "stale"
            }
            Err(e) if e.is_connect() => {
                self.clear_stale(to, node).await;
                "unreachable"
            }
            Ok(r) => {
                tracing::warn!(status = r.status().as_u16(), "forward");
                "failed"
            }
            Err(e) => {
                tracing::warn!(error = %e.without_url(), "forward");
                "failed"
            }
        };
        metrics::counter!(telemetry::REMOTE_NOTIFY, "outcome" => outcome).increment(1);
    }

    /// Announce queued receipts to their streams.
    pub async fn notify_receipts(&self, receipts: Vec<(u64, Receipt)>) {
        for (seq, r) in receipts {
            metrics::counter!(telemetry::RECEIPTS, "status" => r.status.to_string()).increment(1);
            let to = Recipient::Receipts(r.rsub.clone());
            self.notify(&to, Event::Receipt(seq, r)).await;
        }
    }

    /// Queue and announce the receipt `m` owes with `status`, if it
    /// requested one (RFC 8030 §5.1).
    pub async fn owe_receipt(&self, m: &Message, status: u16) -> Result<(), BoxError> {
        let Some(rsub) = &m.rsub else { return Ok(()) };
        let r = Receipt {
            rsub: rsub.clone(),
            msg_id: m.id.clone(),
            status,
        };
        if let Some(seq) = self.store.enqueue_receipt(&r).await? {
            self.notify_receipts(vec![(seq, r)]).await;
        }
        Ok(())
    }

    /// Remove `node`'s route for `to`, if it still names that node.
    async fn clear_stale(&self, to: &Recipient, node: &str) {
        if let Err(e) = self.store.clear_route(to, node).await {
            tracing::warn!(error = %e, "clear stale route");
        }
    }
}

/// An event on its way between nodes.
#[derive(Debug, Serialize, Deserialize)]
pub struct Envelope {
    /// The listener it is for.
    to: WireRecipient,
    /// What happened.
    event: WireEvent,
}

/// [`Recipient`] on the wire.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireRecipient {
    /// A user agent session, by `uaid`.
    UserAgent(String),
    /// A receipt stream, by receipt subscription id.
    Receipts(String),
}

/// [`Event`] on the wire.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WireEvent {
    /// A push message for a session.
    Message {
        /// Message id.
        id: String,
        /// Subscription.
        channel_id: String,
        /// Body, base64url.
        body: String,
        /// Content coding.
        encoding: Option<String>,
    },
    /// A receipt for a stream.
    Receipt {
        /// Queue sequence number.
        seq: u64,
        /// Receipt subscription.
        rsub: String,
        /// The message the receipt is about.
        message: String,
        /// 204 or 410.
        status: u16,
    },
    /// The listener has been replaced or its resource deleted.
    Gone,
}

impl Envelope {
    /// Wrap an event for the wire.
    fn new(to: &Recipient, event: &Event) -> Self {
        let to = match to {
            Recipient::UserAgent(u) => WireRecipient::UserAgent(u.clone()),
            Recipient::Receipts(r) => WireRecipient::Receipts(r.clone()),
        };
        let event = match event {
            Event::Message(n) => WireEvent::Message {
                id: n.id.clone(),
                channel_id: n.channel_id.clone(),
                body: URL_SAFE_NO_PAD.encode(&n.body),
                encoding: n.encoding.clone(),
            },
            Event::Receipt(seq, r) => WireEvent::Receipt {
                seq: *seq,
                rsub: r.rsub.clone(),
                message: r.msg_id.clone(),
                status: r.status,
            },
            Event::Gone => WireEvent::Gone,
        };
        Self { to, event }
    }

    /// Unwrap an event received from another node. `None` if malformed.
    pub fn open(self) -> Option<(Recipient, Event)> {
        let to = match self.to {
            WireRecipient::UserAgent(u) => Recipient::UserAgent(u),
            WireRecipient::Receipts(r) => Recipient::Receipts(r),
        };
        let event = match self.event {
            WireEvent::Message {
                id,
                channel_id,
                body,
                encoding,
            } => Event::Message(Arc::new(Notification {
                id,
                channel_id,
                body: Bytes::from(URL_SAFE_NO_PAD.decode(body).ok()?),
                encoding,
            })),
            WireEvent::Receipt {
                seq,
                rsub,
                message,
                status,
            } => Event::Receipt(
                seq,
                Receipt {
                    rsub,
                    msg_id: message,
                    status,
                },
            ),
            WireEvent::Gone => Event::Gone,
        };
        Some((to, event))
    }
}
