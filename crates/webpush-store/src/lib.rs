//! Storage for a Web Push service.
//!
//! [`Store`] is the contract every backend implements. It is written in terms
//! of the protocol (user agents, subscriptions, messages, receipts, and the
//! routes that tell a cluster where a connection lives), not rows or keys, so
//! each adapter can use its own consistency tools:
//!
//! ```text
//!   endpoint service, connection service, reaper
//!                      |
//!                 Store (trait)
//!                /             \
//!         MemoryStore       BigtableStore        (feature "bigtable")
//!         one Mutex         single-row atomic writes, CheckAndMutateRow
//! ```
//!
//! The guarantees the service relies on are listed on the trait and checked
//! by [`contract::check`], which every adapter should run in its tests.

pub mod contract;
mod memory;

#[cfg(feature = "bigtable")]
mod bigtable;

use std::{
    future::Future,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;

pub use memory::MemoryStore;

#[cfg(feature = "bigtable")]
pub use bigtable::{BigtableConfig, BigtableStore};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

/// Boxed error returned by storage adapters.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A user agent: the software on one device that owns subscriptions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserAgent {
    /// User agent id: 32 lowercase hex characters, see [`new_uaid`].
    pub uaid: String,
    /// How messages reach the user agent when it is not connected to the
    /// service itself. `None` for user agents that hold a WebSocket session.
    pub bridge: Option<BridgeAddress>,
    /// Last time the user agent was seen, Unix milliseconds. User agents not
    /// seen for longer than the configured expiry are deleted.
    pub last_seen: u64,
}

/// Where a bridge (a platform push service such as FCM or APNs) delivers
/// messages for a user agent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeAddress {
    /// Name of the configured bridge, for example `fcm`.
    pub bridge: String,
    /// The application registered with that bridge.
    pub app_id: String,
    /// The device token the platform issued to the application.
    pub token: String,
}

/// A connection that can wait for events: a user agent session or a receipt
/// stream. In a cluster, [`Store::set_route`] records which node holds it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Recipient {
    /// A user agent session, by `uaid`. Receives the messages of all its
    /// subscriptions.
    UserAgent(String),
    /// A receipt stream, by receipt subscription id.
    Receipts(String),
}

/// A subscription: one `channelID` of one user agent, reachable through one
/// push resource.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subscription {
    /// The user agent that owns the subscription.
    pub uaid: String,
    /// The user agent's name for the subscription, a lowercase UUID.
    pub channel_id: String,
    /// Push resource id: the application server's capability to send. It is
    /// random and unrelated to `uaid` and `channel_id` (RFC 8030 §8.2).
    pub push: String,
    /// Uncompressed P-256 key the subscription is restricted to
    /// (RFC 8292 §4).
    pub vapid: Option<[u8; 65]>,
}

/// A stored push message (RFC 8030 §5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// Message id: the last segment of its `Location`, and the `version` the
    /// user agent acknowledges.
    pub id: String,
    /// Owning user agent.
    pub uaid: String,
    /// Owning subscription within the user agent.
    pub channel_id: String,
    /// Push resource the message arrived on.
    pub push: String,
    /// Replacement key (RFC 8030 §5.4), scoped to the subscription.
    pub topic: Option<String>,
    /// The entity body exactly as the application server sent it.
    pub body: Bytes,
    /// `Content-Type` of the push request, returned on message reads.
    pub ctype: Option<String>,
    /// `Content-Encoding` of the push request, forwarded to the user agent.
    pub cenc: Option<String>,
    /// Effective TTL in seconds.
    pub ttl: u32,
    /// Delivery urgency (RFC 8030 §5.3).
    pub urgency: Urgency,
    /// Acceptance time, Unix milliseconds.
    pub accepted: u64,
    /// Unix milliseconds after which the message must not be delivered.
    pub expiry: u64,
    /// Receipt subscription, if the application server asked for receipts.
    pub rsub: Option<String>,
}

/// A delivery receipt owed to an application server (RFC 8030 §5.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    /// Receipt subscription the receipt is delivered to.
    pub rsub: String,
    /// The message the receipt is about.
    pub msg_id: String,
    /// 204 when acknowledged, 410 when not delivered (RFC 8030 §6.2, §6.3).
    pub status: u16,
}

/// Message urgency (RFC 8030 §5.3). Ordered from lowest to highest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Urgency {
    /// On power and Wi-Fi only; for example, advertisements.
    VeryLow,
    /// On either power or Wi-Fi; for example, topic updates.
    Low,
    /// On neither power nor Wi-Fi; for example, chat messages. The default
    /// for messages sent without `Urgency`.
    Normal,
    /// Even on low battery; for example, incoming calls.
    High,
}

impl Urgency {
    /// Parse a header value. Only the four tokens defined in RFC 8030 §5.3
    /// are accepted.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "very-low" => Some(Self::VeryLow),
            "low" => Some(Self::Low),
            "normal" => Some(Self::Normal),
            "high" => Some(Self::High),
            _ => None,
        }
    }

    /// The header token for this urgency.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VeryLow => "very-low",
            Self::Low => "low",
            Self::Normal => "normal",
            Self::High => "high",
        }
    }
}

/// Persistent state of the push service.
///
/// Methods return `impl Future + Send` so implementations can be written
/// with `async fn` and still be driven from spawned tasks. Every method is
/// fallible only for backend failures; "not found" is `None` or `false`.
///
/// Guarantees every implementation must provide:
///
/// - A message with a topic atomically replaces the stored message with the
///   same `(uaid, channel_id, topic)`, including its TTL, urgency, and
///   receipt subscription (RFC 8030 §5.4).
/// - [`Store::delete_message`] deletes only the message currently stored
///   under that id, so the id of a replaced message never matches.
/// - [`Store::pending`] returns unexpired messages oldest first.
/// - Receipt sequence numbers increase within a process.
/// - [`Store::clear_route`] removes a route only while it names the given
///   node.
pub trait Store: Send + Sync + 'static {
    /// Store a new user agent. The caller generates the id with
    /// [`new_uaid`].
    fn create_user_agent(
        &self,
        ua: &UserAgent,
    ) -> impl Future<Output = Result<(), BoxError>> + Send;

    /// Look up a user agent.
    fn user_agent(
        &self,
        uaid: &str,
    ) -> impl Future<Output = Result<Option<UserAgent>, BoxError>> + Send;

    /// Record that the user agent was seen at `now` (Unix milliseconds).
    /// Returns whether it exists.
    fn touch_user_agent(
        &self,
        uaid: &str,
        now: u64,
    ) -> impl Future<Output = Result<bool, BoxError>> + Send;

    /// Replace the device token of a bridged user agent. Returns whether a
    /// bridged user agent with that id exists.
    fn update_bridge_token(
        &self,
        uaid: &str,
        token: &str,
    ) -> impl Future<Output = Result<bool, BoxError>> + Send;

    /// Delete a user agent with its subscriptions and messages. Returns the
    /// 410 receipts queued for deleted messages that requested one.
    fn delete_user_agent(
        &self,
        uaid: &str,
    ) -> impl Future<Output = Result<Vec<(u64, Receipt)>, BoxError>> + Send;

    /// Delete every user agent last seen before `cutoff` (Unix milliseconds),
    /// as [`Store::delete_user_agent`] does. Returns the number of user
    /// agents deleted and the receipts queued.
    fn expire_user_agents(
        &self,
        cutoff: u64,
    ) -> impl Future<Output = Result<(usize, Vec<(u64, Receipt)>), BoxError>> + Send;

    /// Every subscription of `uaid`, in no particular order.
    fn subscriptions(
        &self,
        uaid: &str,
    ) -> impl Future<Output = Result<Vec<Subscription>, BoxError>> + Send;

    /// The subscription `channel_id` of `uaid`, if registered.
    fn channel(
        &self,
        uaid: &str,
        channel_id: &str,
    ) -> impl Future<Output = Result<Option<Subscription>, BoxError>> + Send;

    /// Register `channel_id` for `uaid` with a fresh push resource. The
    /// caller has checked that the channel does not exist.
    fn create_subscription(
        &self,
        uaid: &str,
        channel_id: &str,
        vapid: Option<[u8; 65]>,
    ) -> impl Future<Output = Result<Subscription, BoxError>> + Send;

    /// Look up a subscription by its push resource id.
    fn subscription_by_push(
        &self,
        push: &str,
    ) -> impl Future<Output = Result<Option<Subscription>, BoxError>> + Send;

    /// Delete a subscription and its messages. Returns the 410 receipts
    /// queued for deleted messages that requested one (RFC 8030 §6.2).
    /// Deleting an unknown subscription returns no receipts.
    fn delete_subscription(
        &self,
        uaid: &str,
        channel_id: &str,
    ) -> impl Future<Output = Result<Vec<(u64, Receipt)>, BoxError>> + Send;

    /// Store a message, replacing a message with the same topic.
    fn insert_message(&self, m: &Message) -> impl Future<Output = Result<(), BoxError>> + Send;

    /// Up to `limit` unexpired messages for every subscription of `uaid` at
    /// `now` (Unix milliseconds), oldest first.
    fn pending(
        &self,
        uaid: &str,
        now: u64,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<Message>, BoxError>> + Send;

    /// Look up a message by id. `None` if unknown, deleted, or replaced.
    fn message(&self, id: &str) -> impl Future<Output = Result<Option<Message>, BoxError>> + Send;

    /// Delete message `id` and return it. When `owner` is given as
    /// `(uaid, channel_id)`, the message must belong to it. `None` if
    /// unknown, replaced, already deleted, or owned by someone else.
    fn delete_message(
        &self,
        id: &str,
        owner: Option<(&str, &str)>,
    ) -> impl Future<Output = Result<Option<Message>, BoxError>> + Send;

    /// Create a receipt subscription and return its id (RFC 8030 §5.1).
    fn create_receipt_sub(&self) -> impl Future<Output = Result<String, BoxError>> + Send;

    /// Whether receipt subscription `rsub` exists.
    fn receipt_sub_exists(&self, rsub: &str)
    -> impl Future<Output = Result<bool, BoxError>> + Send;

    /// Delete a receipt subscription and its queue. Returns whether it
    /// existed.
    fn delete_receipt_sub(&self, rsub: &str)
    -> impl Future<Output = Result<bool, BoxError>> + Send;

    /// Queue a receipt and return its sequence number. `None` when the
    /// receipt subscription no longer exists and the receipt was dropped.
    fn enqueue_receipt(
        &self,
        r: &Receipt,
    ) -> impl Future<Output = Result<Option<u64>, BoxError>> + Send;

    /// Receipts waiting for delivery to `rsub`, oldest first.
    fn queued_receipts(
        &self,
        rsub: &str,
    ) -> impl Future<Output = Result<Vec<(u64, Receipt)>, BoxError>> + Send;

    /// Remove a delivered receipt from the queue.
    fn delete_receipt(
        &self,
        rsub: &str,
        seq: u64,
    ) -> impl Future<Output = Result<(), BoxError>> + Send;

    /// Delete messages with receipts that expired by `now` (Unix
    /// milliseconds) without being acknowledged, and queue their 410
    /// receipts (RFC 8030 §6.2). Returns the queued receipts.
    fn reap(&self, now: u64) -> impl Future<Output = Result<Vec<(u64, Receipt)>, BoxError>> + Send;

    /// Record that `node` holds the connection for `to`, replacing any
    /// earlier node. Returns the node recorded before, if any. Adapters
    /// without an atomic swap may return a slightly stale previous node; it
    /// is only used to close a superseded connection early.
    fn set_route(
        &self,
        to: &Recipient,
        node: &str,
    ) -> impl Future<Output = Result<Option<String>, BoxError>> + Send;

    /// The node that holds the connection for `to`, if any.
    fn route(
        &self,
        to: &Recipient,
    ) -> impl Future<Output = Result<Option<String>, BoxError>> + Send;

    /// Remove the route for `to`, but only if it still names `node`, so a
    /// node never removes a route another node has taken over. Returns
    /// whether it did.
    fn clear_route(
        &self,
        to: &Recipient,
        node: &str,
    ) -> impl Future<Output = Result<bool, BoxError>> + Send;
}

/// Receipt queue sequence numbers: microsecond wall clock, bumped so that
/// numbers issued by this process never repeat. Unique per process only.
pub(crate) fn next_seq() -> u64 {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = now_ms() * 1000;
    let next = |last: u64| now.max(last + 1);
    next(
        LAST.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |l| Some(next(l)))
            .unwrap_or_default(),
    )
}

/// A fresh user agent id: 128 random bits as 32 lowercase hex characters.
#[must_use]
pub fn new_uaid() -> String {
    use std::fmt::Write;
    random_bytes::<16>()
        .iter()
        .fold(String::with_capacity(32), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Whether `s` has the form [`new_uaid`] produces.
#[must_use]
pub fn is_uaid(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A fresh resource id: 128 bits from the OS CSPRNG, base64url. Ids are
/// independent of each other, so no URI reveals another (RFC 8030 §8.2,
/// §8.3).
#[must_use]
pub fn new_id() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes::<16>())
}

/// `N` octets from the OS CSPRNG.
fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    // The OS generator failing is unrecoverable: ids would be predictable.
    getrandom::fill(&mut bytes).expect("OS random number generator");
    bytes
}

/// Current wall-clock time in milliseconds since the Unix epoch.
///
/// # Panics
///
/// If the system clock is set before 1970.
#[must_use]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
