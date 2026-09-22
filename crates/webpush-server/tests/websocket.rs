//! User agent protocol conformance (`TECH_SPEC.md` §4.5): the WebSocket
//! protocol Firefox speaks to its push server. Messages are sent exactly as
//! Firefox sends them (`dom/push/PushServiceWebSocket.sys.mjs`), and replies
//! are checked for what Firefox checks plus the service's own requirements.
#![allow(clippy::unwrap_used)]

mod common;

use base64::{Engine, engine::general_purpose::URL_SAFE};
use common::*;
use serde_json::json;

/// A server and a user agent that completed `hello`.
async fn connected() -> (TestServer, Ua, String) {
    let server = TestServer::start().await;
    let mut ua = server.ua().await;
    let uaid = ua.hello(None).await;
    (server, ua, uaid)
}

/// FX-01 (COMPAT): the server selects the `push-notification` subprotocol.
#[tokio::test(flavor = "multi_thread")]
async fn subprotocol_selected() {
    let server = TestServer::start().await;
    let ua = server.ua().await;
    assert_eq!(ua.protocol.as_deref(), Some("push-notification"));
}

/// FX-03 (COMPAT): the hello reply contains a 32-character lowercase hex
/// `uaid`, status 200, `use_webpush`, and an empty `broadcasts` object.
#[tokio::test(flavor = "multi_thread")]
async fn hello_reply() {
    let server = TestServer::start().await;
    let mut ua = server.ua().await;
    ua.send(&json!({ "messageType": "hello", "broadcasts": {}, "use_webpush": true }))
        .await;
    let reply = ua.recv().await.expect("hello reply");
    assert_eq!(reply["messageType"], "hello");
    assert_eq!(reply["status"], 200);
    assert_eq!(reply["use_webpush"], true);
    assert_eq!(reply["broadcasts"], json!({}));
    let uaid = reply["uaid"].as_str().expect("uaid is a string");
    assert_eq!(uaid.len(), 32, "{uaid}");
    assert!(
        uaid.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "{uaid}"
    );
}

/// FX-04 (COMPAT): a known `uaid` is kept across sessions. A user agent is
/// known once it has registered a subscription.
#[tokio::test(flavor = "multi_thread")]
async fn hello_known_uaid_kept() {
    let (server, mut ua, uaid) = connected().await;
    ua.register(&channel_id(), None).await;
    drop(ua);
    let mut ua = server.ua().await;
    assert_eq!(ua.hello(Some(&uaid)).await, uaid);
}

/// FX-04 (POLICY): a user agent that never registered is not stored, so
/// clients that connect without subscribing leave nothing behind.
#[tokio::test(flavor = "multi_thread")]
async fn hello_without_register_stores_nothing() {
    let (server, ua, uaid) = connected().await;
    drop(ua);
    let mut ua = server.ua().await;
    assert_ne!(ua.hello(Some(&uaid)).await, uaid);
}

/// FX-04 (COMPAT): an unknown or malformed `uaid` is replaced.
#[tokio::test(flavor = "multi_thread")]
async fn hello_unknown_uaid_replaced() {
    let server = TestServer::start().await;
    for stale in ["0".repeat(32), "not-a-uaid".to_owned()] {
        let mut ua = server.ua().await;
        let uaid = ua.hello(Some(&stale)).await;
        assert_ne!(uaid, stale);
    }
}

/// FX-02 (COMPAT): a session must start with `hello`.
#[tokio::test(flavor = "multi_thread")]
async fn first_message_must_be_hello() {
    let server = TestServer::start().await;
    let mut ua = server.ua().await;
    ua.send(&json!({ "messageType": "register", "channelID": channel_id() }))
        .await;
    assert!(ua.closed().await, "connection stayed open");
}

/// FX-12 (COMPAT): `{}` is answered with `{}`.
#[tokio::test(flavor = "multi_thread")]
async fn ping_short_form() {
    let (_server, mut ua, _) = connected().await;
    ua.send_raw("{}").await;
    assert_eq!(ua.recv().await, Some(json!({})));
}

/// FX-12 (COMPAT): the verbose ping form is answered with `{}`.
#[tokio::test(flavor = "multi_thread")]
async fn ping_verbose_form() {
    let (_server, mut ua, _) = connected().await;
    ua.send(&json!({ "messageType": "ping" })).await;
    assert_eq!(ua.recv().await, Some(json!({})));
}

/// FX-06 (COMPAT): `register` replies with status 200, the same channel id,
/// and an absolute push endpoint on the service origin.
#[tokio::test(flavor = "multi_thread")]
async fn register_reply() {
    let (server, mut ua, _) = connected().await;
    let ch = channel_id();
    let reply = ua.register(&ch, None).await;
    assert_eq!(reply["status"], 200);
    assert_eq!(reply["channelID"], ch.as_str());
    let endpoint = reply["pushEndpoint"].as_str().expect("pushEndpoint");
    assert!(
        endpoint.starts_with(&format!("{}/push/", server.origin)),
        "{endpoint}"
    );
}

/// FX-06 (COMPAT): an application server key is accepted with padding, as
/// Firefox sends it, and without.
#[tokio::test(flavor = "multi_thread")]
async fn register_key_padding_optional() {
    let (_server, mut ua, _) = connected().await;
    let key = AppServerKey::new();
    let padded = URL_SAFE.encode(key.public());
    assert!(padded.ends_with('='));
    assert_eq!(
        ua.register(&channel_id(), Some(&padded)).await["status"],
        200
    );
    assert_eq!(
        ua.register(&channel_id(), Some(&key.k_b64())).await["status"],
        200
    );
}

/// FX-06, VAP-07 (COMPAT, MUST): an invalid key or channel id gives status
/// 400.
#[tokio::test(flavor = "multi_thread")]
async fn register_invalid_400() {
    let (_server, mut ua, _) = connected().await;
    let key = AppServerKey::new();
    let bad_keys = [
        b64(&off_curve(&key.public())),
        b64(&key.public()[1..]),
        "!!!".to_owned(),
    ];
    for bad in &bad_keys {
        let reply = ua.register(&channel_id(), Some(bad)).await;
        assert_eq!(reply["status"], 400, "key {bad}");
    }
    for bad in ["not-a-uuid", "d9b746444f9746aab8fa9393985cd6cd"] {
        assert_eq!(ua.register(bad, None).await["status"], 400, "channel {bad}");
    }
}

/// FX-07 (POLICY): registering a channel again with the same key returns the
/// same endpoint.
#[tokio::test(flavor = "multi_thread")]
async fn policy_register_idempotent() {
    let (_server, mut ua, _) = connected().await;
    let ch = channel_id();
    let first = ua.register(&ch, None).await;
    let again = ua.register(&ch, None).await;
    assert_eq!(again["status"], 200);
    assert_eq!(first["pushEndpoint"], again["pushEndpoint"]);
}

/// FX-07 (POLICY): registering a channel again with a different key gives
/// status 409.
#[tokio::test(flavor = "multi_thread")]
async fn policy_register_conflict_409() {
    let (_server, mut ua, _) = connected().await;
    let ch = channel_id();
    assert_eq!(ua.register(&ch, None).await["status"], 200);
    let key = AppServerKey::new().k_b64();
    assert_eq!(ua.register(&ch, Some(&key)).await["status"], 409);
}

/// FX-08 (COMPAT): `unregister` replies with status 200, also for an unknown
/// channel.
#[tokio::test(flavor = "multi_thread")]
async fn unregister_reply() {
    let (_server, mut ua, _) = connected().await;
    let sub = ua.subscribe(None).await;
    let reply = ua.unregister(&sub.channel_id).await;
    assert_eq!(reply["messageType"], "unregister");
    assert_eq!(reply["channelID"], sub.channel_id.as_str());
    assert_eq!(reply["status"], 200);
    assert_eq!(ua.unregister(&channel_id()).await["status"], 200);
}

/// FX-05 (POLICY): a new session for the same `uaid` closes the previous one
/// and takes over delivery.
#[tokio::test(flavor = "multi_thread")]
async fn policy_second_session_replaces_first() {
    let (server, mut first, uaid) = connected().await;
    let sub = first.subscribe(None).await;
    let mut second = server.ua().await;
    assert_eq!(second.hello(Some(&uaid)).await, uaid);
    assert!(first.closed().await, "first session stayed open");

    let http = server.http().await;
    let r = http
        .request("POST", &sub.push, &[("ttl", "60")], b"x")
        .await;
    assert_eq!(r.status, 201);
    assert_eq!(second.next_notification().await.data(), b"x");
}

/// FX-13 (COMPAT): `nack` and `broadcast_subscribe` are accepted without a
/// reply.
#[tokio::test(flavor = "multi_thread")]
async fn nack_and_broadcast_subscribe_ignored() {
    let (_server, mut ua, _) = connected().await;
    ua.send(&json!({ "messageType": "nack", "version": "x", "code": 301 }))
        .await;
    ua.send(&json!({ "messageType": "broadcast_subscribe", "broadcasts": { "remote-settings/monitor_changes": "v1" } }))
        .await;
    ua.send_raw("{}").await;
    assert_eq!(ua.recv().await, Some(json!({})), "expected only the pong");
}

/// FX-14 (POLICY): text that is not JSON closes the connection.
#[tokio::test(flavor = "multi_thread")]
async fn policy_invalid_json_closes() {
    let (_server, mut ua, _) = connected().await;
    ua.send_raw("not json").await;
    assert!(ua.closed().await);
}

/// FX-14 (POLICY): an unknown `messageType` closes the connection.
#[tokio::test(flavor = "multi_thread")]
async fn policy_unknown_message_type_closes() {
    let (_server, mut ua, _) = connected().await;
    ua.send(&json!({ "messageType": "launch" })).await;
    assert!(ua.closed().await);
}

/// FX-02 (COMPAT): `hello` is only valid as the first message.
#[tokio::test(flavor = "multi_thread")]
async fn duplicate_hello_closes() {
    let (_server, mut ua, uaid) = connected().await;
    ua.send(&json!({ "messageType": "hello", "uaid": uaid, "use_webpush": true }))
        .await;
    assert!(ua.closed().await);
}
