//! A reference implementation of an IETF Web Push service.
//!
//! | Specification | Title | Where |
//! |---|---|---|
//! | [RFC 8030] | Generic Event Delivery Using HTTP Push | [`serve`]: push, TTL, Urgency, Topic, receipts |
//! | [RFC 8292] | Voluntary Application Server Identification (VAPID) | [`serve`], [`vapid`] |
//! | [RFC 8291] | Message Encryption for Web Push | [`ece::webpush`] |
//! | [RFC 8188] | Encrypted Content-Encoding for HTTP | [`ece`] |
//! | Mozilla push protocol | WebSocket protocol spoken by Firefox | [`serve`]: the user agent side |
//!
//! The application server side follows the RFCs. The user agent side of
//! RFC 8030 relies on HTTP/2 server push, which browsers have removed, so
//! user agents connect over the WebSocket protocol Firefox uses instead.
//! Pointing Firefox's `dom.push.serverURL` at this service is enough to use
//! it. The protocol, the privacy model, and the implementation are explained
//! in the repository's `docs/` directory. This page covers the Rust API.
//!
//! # Protocol overview
//!
//! ```text
//!  User agent (Firefox)            Push service                 App server
//!      | wss:// "push-notification"     |                            |
//!      |===============================>|                            |
//!      | hello / hello uaid             |                            |
//!      |<------------------------------>|                            |
//!      | register channelID             |                            |
//!      |------------------------------->|                            |
//!      | register pushEndpoint          |                            |
//!      |<-------------------------------|                            |
//!      |       pushEndpoint + encryption keys (out of band)          |
//!      |------------------------------------------------------------>|
//!      |                                | POST pushEndpoint          |
//!      |                                |<---------------------------|
//!      |                                | 201 Location: message      |
//!      |                                |--------------------------->|
//!      | notification (encrypted data)  |                            |
//!      |<-------------------------------|                            |
//!      | ack                            |                            |
//!      |------------------------------->| receipt 204, if requested  |
//!      |                                |===========================>|
//! ```
//!
//! # Running
//!
//! [`serve`] takes any [`store::Store`]. [`store::MemoryStore`] needs no
//! setup; `store::BigtableStore` is available with the `bigtable` feature,
//! and other databases plug in by implementing the trait.
//!
//! ```no_run
//! use std::time::Duration;
//!
//! # async fn run() -> Result<(), webpush_service::BoxError> {
//! let cfg = webpush_service::Config {
//!     origin: "https://push.example.net".into(),
//!     tls_cert_pem: std::fs::read_to_string("cert.pem")?,
//!     tls_key_pem: std::fs::read_to_string("key.pem")?,
//!     max_ttl: 60 * 24 * 3600,
//!     max_payload: 4096,
//!     reaper_interval: Duration::from_secs(1),
//! };
//! let store = webpush_service::store::MemoryStore::new();
//! let listener = tokio::net::TcpListener::bind("0.0.0.0:443").await?;
//! webpush_service::serve(listener, cfg, store).await
//! # }
//! ```
//!
//! [RFC 8030]: https://www.rfc-editor.org/rfc/rfc8030
//! [RFC 8188]: https://www.rfc-editor.org/rfc/rfc8188
//! [RFC 8291]: https://www.rfc-editor.org/rfc/rfc8291
//! [RFC 8292]: https://www.rfc-editor.org/rfc/rfc8292

#![warn(missing_docs)]

pub mod ece;
pub mod store;
pub mod vapid;

mod api;
mod conn;
mod headers;
mod hub;
mod receipts;
mod ws;

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::elliptic_curve::rand_core::{OsRng, RngCore};

/// Push service configuration. See the [crate example](crate#running).
#[derive(Clone)]
pub struct Config {
    /// Public origin of the service, for example `https://push.example.net`,
    /// without a trailing slash. It is the base of every push endpoint,
    /// `Location`, and `Link` target, and the value VAPID `aud` claims must
    /// match (RFC 8292 §2).
    pub origin: String,
    /// Certificate chain, PEM encoded, leaf first.
    pub tls_cert_pem: String,
    /// Private key for the leaf certificate, PEM encoded.
    pub tls_key_pem: String,
    /// Longest time a message is stored, in seconds. Requested TTLs above it
    /// are reduced, and the response `TTL` header reports the value used
    /// (RFC 8030 §5.2).
    pub max_ttl: u32,
    /// Largest accepted push message body, in octets. Larger bodies get 413.
    /// Must be at least 4096 (RFC 8030 §7.2).
    pub max_payload: usize,
    /// How often expired messages that requested receipts are swept, which is
    /// when their 410 receipts go out (RFC 8030 §6.2).
    pub reaper_interval: Duration,
}

/// Boxed error returned by the service entry points and storage adapters.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// State shared by the request handlers, sessions, streams, and the reaper.
struct App<S> {
    /// Copy of [`Config::origin`].
    origin: String,
    /// Copy of [`Config::max_ttl`].
    max_ttl: u32,
    /// Persistent state.
    store: S,
    /// Fan-out to open connections.
    hub: hub::Hub,
}

/// Run the push service on `listener` until the returned future is dropped.
///
/// Every connection is TLS; there is no plaintext listener (RFC 8030 §8).
/// ALPN selects HTTP/2 or HTTP/1.1. User agents connect with a WebSocket
/// upgrade on `/`; application servers use the HTTP endpoints.
///
/// See the [crate example](crate#running).
///
/// # Errors
///
/// Returns before accepting connections if the configuration is invalid
/// (unparseable TLS material, [`Config::max_payload`] below 4096). Errors on
/// individual connections are logged and do not stop the service.
pub async fn serve<S: store::Store>(
    listener: tokio::net::TcpListener,
    cfg: Config,
    store: S,
) -> Result<(), BoxError> {
    if cfg.max_payload < 4096 {
        return Err("max_payload must be at least 4096 (RFC 8030 §7.2)".into());
    }
    let tls = conn::tls_config(&cfg)?;
    let app = Arc::new(App {
        origin: cfg.origin.clone(),
        max_ttl: cfg.max_ttl,
        store,
        hub: hub::Hub::default(),
    });
    let router = api::router(app.clone(), cfg.max_payload);
    let _reaper = AbortOnDrop(tokio::spawn(reaper(app, cfg.reaper_interval)));
    conn::serve(listener, tls, router).await
}

/// Expire unacknowledged messages that asked for receipts and deliver their
/// 410s (RFC 8030 §6.2).
async fn reaper<S: store::Store>(app: Arc<App<S>>, interval: Duration) {
    let mut tick = tokio::time::interval(interval);
    loop {
        tick.tick().await;
        match app.store.reap(now_ms()).await {
            Ok(receipts) => api::notify_receipts(&app.hub, receipts),
            Err(e) => tracing::warn!(error = %e, "reaper"),
        }
    }
}

/// Cancels a background task when the owning scope ends, so the reaper stops
/// with the service.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A fresh resource id: 128 bits from the OS CSPRNG, base64url. Ids are
/// independent of each other, so no URI reveals another (RFC 8030 §8.2, §8.3).
fn new_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Current wall-clock time in milliseconds since the Unix epoch.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_millis()
        .try_into()
        .expect("unix milliseconds fit in u64")
}
