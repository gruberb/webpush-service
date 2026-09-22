//! RFC 8292 conformance of the push service: restricted subscriptions,
//! created by a `register` message with the application server key, and
//! enforcement of VAPID credentials on push.

mod common;

use common::*;

/// A TTL long enough that no test sees the message expire.
const TTL60: (&str, &str) = ("ttl", "60");

/// A server, an application server client, and a user agent whose
/// subscription is restricted to `key` (RFC 8292 §4.1, FX-06).
async fn restricted(key: &AppServerKey) -> (TestServer, Http, Ua, Sub) {
    let server = TestServer::start().await;
    let http = server.http().await;
    let mut ua = server.ua().await;
    ua.hello(None).await;
    let sub = ua.subscribe(Some(key)).await;
    (server, http, ua, sub)
}

/// A server with an unrestricted subscription.
async fn unrestricted() -> (TestServer, Http, Ua, Sub) {
    let server = TestServer::start().await;
    let http = server.http().await;
    let mut ua = server.ua().await;
    ua.hello(None).await;
    let sub = ua.subscribe(None).await;
    (server, http, ua, sub)
}

/// Push with the given `Authorization` value.
async fn push_auth(http: &Http, sub: &Sub, auth: &str) -> Resp {
    http.request("POST", &sub.push, &[TTL60, ("authorization", auth)], b"x")
        .await
}

/// VAP-07 (MUST): registering with an application server key creates a
/// subscription.
#[tokio::test(flavor = "multi_thread")]
async fn vapid_restricted_subscribe() {
    let key = AppServerKey::new();
    let (_server, _http, _ua, sub) = restricted(&key).await;
    assert!(sub.push.contains("/push/"));
}

/// VAP-08 (MUST / POLICY status): absent credentials on a restricted
/// subscription give 401 with a vapid challenge.
#[tokio::test(flavor = "multi_thread")]
async fn policy_vapid_restricted_no_auth_401() {
    let key = AppServerKey::new();
    let (_server, http, _ua, sub) = restricted(&key).await;
    let r = http.request("POST", &sub.push, &[TTL60], b"x").await;
    assert_eq!(r.status, 401);
    let challenge = r.header("www-authenticate").expect("WWW-Authenticate");
    assert!(
        challenge.to_ascii_lowercase().starts_with("vapid"),
        "{challenge}"
    );
}

/// VAP-08 (MUST): valid credentials are accepted and the message delivered.
#[tokio::test(flavor = "multi_thread")]
async fn vapid_restricted_valid() {
    let key = AppServerKey::new();
    let (_server, http, mut ua, sub) = restricted(&key).await;
    let auth = key.auth(&http.origin, now() + 3600, Some("mailto:ops@example.com"));
    assert_eq!(push_auth(&http, &sub, &auth).await.status, 201);
    assert_eq!(ua.next_notification().await.data(), b"x");
}

/// VAP-08, VAP-09 (MUST): every kind of invalid credential gives 403.
#[tokio::test(flavor = "multi_thread")]
async fn vapid_restricted_invalid_403() {
    let key = AppServerKey::new();
    let (_server, http, _ua, sub) = restricted(&key).await;
    let origin = http.origin.clone();
    let k = key.k_b64();
    let valid = key.token(&origin, now() + 3600, None);

    // Corrupt one signature octet, keeping the encoding well formed.
    let (input, sig) = valid.rsplit_once('.').unwrap();
    let mut sig = unb64(sig);
    sig[10] ^= 0x01;
    let bad_sig = format!("{input}.{}", b64(&sig));

    let claims = serde_json::json!({ "aud": origin, "exp": now() + 3600 }).to_string();
    let hs256 = key.token_raw(r#"{"typ":"JWT","alg":"HS256"}"#, &claims);
    let other = AppServerKey::new();

    let cases = [
        ("bad signature", format!("vapid t={bad_sig}, k={k}")),
        ("expired", key.auth(&origin, now() - 60, None)),
        ("exp > 24h", key.auth(&origin, now() + 86400 + 600, None)),
        (
            "wrong aud",
            key.auth("https://example.com", now() + 3600, None),
        ),
        ("other key", other.auth(&origin, now() + 3600, None)),
        ("t missing", format!("vapid k={k}")),
        ("alg HS256", format!("vapid t={hs256}, k={k}")),
    ];
    for (name, auth) in cases {
        assert_eq!(push_auth(&http, &sub, &auth).await.status, 403, "{name}");
    }
}

/// VAP-04 (MUST): scheme case, `realm`, and unknown params are tolerated.
#[tokio::test(flavor = "multi_thread")]
async fn vapid_params_ignored() {
    let key = AppServerKey::new();
    let (_server, http, _ua, sub) = restricted(&key).await;
    let t = key.token(&http.origin, now() + 3600, None);
    let auth = format!("Vapid realm=\"push\", t={t}, foo=bar, k={}", key.k_b64());
    assert_eq!(push_auth(&http, &sub, &auth).await.status, 201);
}

/// VAP-02 (MUST): `aud` as an array containing the origin.
#[tokio::test(flavor = "multi_thread")]
async fn vapid_aud_array() {
    let key = AppServerKey::new();
    let (_server, http, _ua, sub) = restricted(&key).await;
    let claims =
        serde_json::json!({ "aud": ["https://other.example", http.origin], "exp": now() + 3600 });
    let t = key.token_raw(r#"{"typ":"JWT","alg":"ES256"}"#, &claims.to_string());
    let auth = format!("vapid t={t}, k={}", key.k_b64());
    assert_eq!(push_auth(&http, &sub, &auth).await.status, 201);
}

/// VAP-12 (MAY): valid credentials on an unrestricted subscription.
#[tokio::test(flavor = "multi_thread")]
async fn vapid_unrestricted_valid() {
    let (_server, http, _ua, sub) = unrestricted().await;
    let key = AppServerKey::new();
    let auth = key.auth(&http.origin, now() + 3600, None);
    assert_eq!(push_auth(&http, &sub, &auth).await.status, 201);
}

/// VAP-12 (MAY / POLICY): invalid credentials give 403 even when the
/// subscription is unrestricted.
#[tokio::test(flavor = "multi_thread")]
async fn policy_vapid_unrestricted_invalid_403() {
    let (_server, http, _ua, sub) = unrestricted().await;
    let key = AppServerKey::new();
    let auth = key.auth(&http.origin, now() - 60, None);
    assert_eq!(push_auth(&http, &sub, &auth).await.status, 403);
}

/// VAP-06 (SHOULD): `k` equal to the `aes128gcm` keyid gives 400.
#[tokio::test(flavor = "multi_thread")]
async fn vapid_k_equals_keyid_400() {
    let key = AppServerKey::new();
    let (_server, http, _ua, sub) = restricted(&key).await;
    let auth = key.auth(&http.origin, now() + 3600, None);
    let headers = [
        TTL60,
        ("authorization", &auth),
        ("content-encoding", "aes128gcm"),
    ];
    let body = opaque_aes128gcm(&key.public());
    let r = http.request("POST", &sub.push, &headers, &body).await;
    assert_eq!(r.status, 400);
}
