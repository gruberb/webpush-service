//! Creating subscriptions, shared by the WebSocket `register` message and
//! the registration API for bridged user agents.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use webpush_store::{BoxError, Store, Subscription};

/// Result of [`register`].
pub enum Registered {
    /// A new subscription.
    Created(Subscription),
    /// The subscription already existed with the same key. Registering
    /// again is idempotent, so a client can retry a register whose reply it
    /// did not see.
    Existing(Subscription),
    /// The channel exists with a different application server key.
    Conflict,
}

/// Create subscription `channel_id` for `uaid`, restricted to `vapid` if
/// given (RFC 8292 §4.1), or confirm an identical one.
pub async fn register<S: Store>(
    store: &S,
    uaid: &str,
    channel_id: &str,
    vapid: Option<[u8; 65]>,
) -> Result<Registered, BoxError> {
    Ok(match store.channel(uaid, channel_id).await? {
        Some(sub) if sub.vapid == vapid => Registered::Existing(sub),
        Some(_) => Registered::Conflict,
        None => Registered::Created(store.create_subscription(uaid, channel_id, vapid).await?),
    })
}

/// A channel id normalized to a lowercase hyphenated UUID, or `None` if it is
/// not a UUID. Clients compare channel ids case-insensitively.
pub fn channel_id(s: &str) -> Option<String> {
    let valid = s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        });
    valid.then(|| s.to_ascii_lowercase())
}

/// Decode an application server key: base64url with or without padding,
/// 65 octets, an uncompressed point on P-256 (RFC 8292 §3.2).
pub fn vapid_key(s: &str) -> Option<[u8; 65]> {
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
    fn channel_ids() {
        let id = "D9B74644-4F97-46AA-B8FA-9393985CD6CD";
        assert_eq!(
            channel_id(id).as_deref(),
            Some("d9b74644-4f97-46aa-b8fa-9393985cd6cd")
        );
        assert_eq!(channel_id("d9b746444f9746aab8fa9393985cd6cd"), None);
        assert_eq!(channel_id("zzzzzzzz-4f97-46aa-b8fa-9393985cd6cd"), None);
    }
}
