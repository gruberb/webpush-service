//! The interface between a Web Push service and a platform push service.
//!
//! Mobile operating systems do not let applications keep their own
//! connection to a push service in the background. Messages for them go
//! through the platform's push service instead: Firebase Cloud Messaging
//! (FCM) on Android, the Apple Push Notification service (APNs) on Apple
//! platforms. A [`Bridge`] hands one Web Push message to such a service.
//!
//! ```text
//!  application server --POST /push/{id}--> push service --Bridge::send--> FCM / APNs
//!                                                                             |
//!                                            mobile application <-------------+
//! ```
//!
//! The push service stays opaque to the payload: the encrypted body is
//! forwarded as base64url together with the fields a user agent needs to
//! decrypt and route it, the same fields the WebSocket `notification`
//! message has. See [`Notification::fields`].
//!
//! A bridge takes over storage and retry from the push service: once
//! [`Bridge::send`] succeeds, the platform service owns delivery. The push
//! service therefore cannot observe acknowledgement and does not offer
//! delivery receipts for bridged subscriptions.

use std::{collections::BTreeMap, fmt, future::Future, pin::Pin, sync::Arc, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

/// Boxed error for failures a bridge cannot classify further.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A boxed, sendable future, so bridges can be stored as trait objects.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// How urgently the platform should deliver a message.
///
/// RFC 8030 §5.3 defines four urgencies; platform services only distinguish
/// normal from high priority. The push service maps `high` to
/// [`Priority::High`] and everything else to [`Priority::Normal`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Priority {
    /// Delivered when the platform sees fit, possibly batched.
    Normal,
    /// Delivered immediately, waking the device if needed.
    High,
}

/// One Web Push message for a bridged user agent.
#[derive(Clone, Debug)]
pub struct Notification<'a> {
    /// The subscription the message belongs to.
    pub channel_id: &'a str,
    /// The message id.
    pub version: &'a str,
    /// The encrypted body exactly as the application server sent it, or
    /// `None` for a message without a body.
    pub data: Option<&'a [u8]>,
    /// The body's `Content-Encoding`, normally `aes128gcm`.
    pub encoding: Option<&'a str>,
    /// How long the platform may hold the message for an offline device.
    pub ttl: Duration,
    /// Delivery priority.
    pub priority: Priority,
}

impl Notification<'_> {
    /// The fields every bridge delivers to the application, as string pairs:
    /// `channelID`, `version`, and, for messages with a body, `data`
    /// (base64url without padding) and `encoding`. The names match the
    /// WebSocket `notification` message, so a client can share its decoding
    /// between both transports.
    ///
    /// ```
    /// use std::time::Duration;
    /// use webpush_bridge::{Notification, Priority};
    ///
    /// let n = Notification {
    ///     channel_id: "5b8a2f0e-7a4c-4b8e-9d5f-2c1e3a4b5c6d",
    ///     version: "AAAAAAAAAAAAAAAAAAAAAA",
    ///     data: Some(b"\x01\x02"),
    ///     encoding: Some("aes128gcm"),
    ///     ttl: Duration::from_secs(60),
    ///     priority: Priority::Normal,
    /// };
    /// let fields = n.fields();
    /// assert_eq!(fields["data"], "AQI");
    /// assert_eq!(fields["encoding"], "aes128gcm");
    /// ```
    #[must_use]
    pub fn fields(&self) -> BTreeMap<&'static str, String> {
        let mut fields = BTreeMap::from([
            ("channelID", self.channel_id.to_owned()),
            ("version", self.version.to_owned()),
        ]);
        if let Some(data) = self.data {
            fields.insert("data", URL_SAFE_NO_PAD.encode(data));
            if let Some(encoding) = self.encoding {
                fields.insert("encoding", encoding.to_owned());
            }
        }
        fields
    }
}

/// Where a bridge delivers: an application registered with the platform and
/// the device token the platform issued to it.
#[derive(Clone, Copy, Debug)]
pub struct Address<'a> {
    /// The application, as configured for the bridge.
    pub app_id: &'a str,
    /// The platform's device token.
    pub token: &'a str,
}

/// Why a bridge did not deliver a message.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The application id is not configured for this bridge.
    UnknownApp,
    /// The platform reports the token as invalid or no longer registered.
    /// The user agent should be deleted.
    TokenGone,
    /// The message exceeds the platform's payload limit.
    TooLarge,
    /// The platform is rate limiting. Retry after the given delay, if known.
    Throttled {
        /// The platform's `Retry-After`, if it sent one.
        retry_after: Option<Duration>,
    },
    /// The platform refused the request for another reason, such as a
    /// malformed field. Retrying will not help.
    Rejected(String),
    /// The platform could not be reached, failed, or refused the
    /// credentials. Retrying later may help.
    Unavailable(BoxError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownApp => f.write_str("application is not configured for this bridge"),
            Self::TokenGone => f.write_str("device token is no longer valid"),
            Self::TooLarge => f.write_str("message exceeds the platform payload limit"),
            Self::Throttled { .. } => f.write_str("platform is rate limiting"),
            Self::Rejected(reason) => write!(f, "platform rejected the message: {reason}"),
            Self::Unavailable(e) => write!(f, "platform unavailable: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unavailable(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

impl Error {
    /// A short, stable name for metrics and logs.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::UnknownApp => "unknown_app",
            Self::TokenGone => "token_gone",
            Self::TooLarge => "too_large",
            Self::Throttled { .. } => "throttled",
            Self::Rejected(_) => "rejected",
            Self::Unavailable(_) => "unavailable",
        }
    }
}

/// A platform push service.
///
/// Implementations hold their credentials and HTTP client, and are shared
/// between requests.
pub trait Bridge: Send + Sync + 'static {
    /// The name user agents register with, for example `fcm`.
    fn name(&self) -> &'static str;

    /// Whether `app_id` is configured, checked when a user agent registers.
    fn has_app(&self, app_id: &str) -> bool;

    /// Hand one message to the platform.
    fn send<'a>(
        &'a self,
        to: Address<'a>,
        notification: &'a Notification<'a>,
    ) -> BoxFuture<'a, Result<(), Error>>;
}

/// An HTTP client for bridges: rustls with the `ring` provider, HTTP/2
/// allowed, and a request timeout.
///
/// # Errors
///
/// The TLS configuration cannot be built, which only happens if the
/// platform certificate verifier fails to initialize.
pub fn http_client(timeout: Duration) -> Result<reqwest::Client, BoxError> {
    ensure_crypto_provider();
    Ok(reqwest::Client::builder().timeout(timeout).build()?)
}

/// An HTTP/2-only client for bridges that require it (APNs). Plain `http://`
/// endpoints, used by test doubles, get HTTP/2 with prior knowledge.
///
/// # Errors
///
/// As for [`http_client`].
pub fn http2_client(timeout: Duration, plaintext: bool) -> Result<reqwest::Client, BoxError> {
    ensure_crypto_provider();
    let builder = reqwest::Client::builder().timeout(timeout);
    let builder = if plaintext {
        builder.http2_prior_knowledge()
    } else {
        builder
    };
    Ok(builder.build()?)
}

/// Install `ring` as the process-wide rustls provider unless the
/// application already chose one.
fn ensure_crypto_provider() {
    // Fails only when a provider is already installed, which is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// A shared, type-erased bridge.
pub type SharedBridge = Arc<dyn Bridge>;
