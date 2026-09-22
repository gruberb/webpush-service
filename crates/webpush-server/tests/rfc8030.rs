//! RFC 8030 conformance: the application server interface (push, TTL,
//! Urgency, Topic, receipts, message resource) exercised over HTTPS, with
//! delivery and acknowledgement observed through a Firefox-compatible user
//! agent session. Requirement IDs refer to `TECH_SPEC.md` §4.
//!
//! Black box: every URI is discovered through `pushEndpoint`, `Location`, or
//! `Link`; invalid ids are made by mangling discovered URIs.
#![allow(clippy::unwrap_used)]

mod common;

use std::{collections::HashSet, time::Duration};

use common::*;

/// A TTL long enough that no test sees the message expire.
const TTL60: (&str, &str) = ("ttl", "60");
/// Requests a delivery receipt (RFC 8030 §5.1).
const ASYNC: (&str, &str) = ("prefer", "respond-async");

/// A server, an HTTPS client for the application server, and one
/// subscription of one user agent.
struct Env {
    /// The server under test.
    server: TestServer,
    /// Application server side.
    http: Http,
    /// The user agent id, to reconnect with.
    uaid: String,
    /// The subscription.
    sub: Sub,
}

impl Env {
    /// Reconnect the user agent with its `uaid`.
    async fn connect(&self) -> Ua {
        let mut ua = self.server.ua().await;
        assert_eq!(ua.hello(Some(&self.uaid)).await, self.uaid);
        ua
    }
}

/// A server and a connected user agent with one subscription. Dropping the
/// returned `Ua` takes the user agent offline.
async fn setup() -> (Env, Ua) {
    let server = TestServer::start().await;
    let http = server.http().await;
    let mut ua = server.ua().await;
    let uaid = ua.hello(None).await;
    let sub = ua.subscribe(None).await;
    (
        Env {
            server,
            http,
            uaid,
            sub,
        },
        ua,
    )
}

/// POST to a push resource.
async fn push(http: &Http, push_uri: &str, headers: &[(&str, &str)], body: &[u8]) -> Resp {
    http.request("POST", push_uri, headers, body).await
}

/// Push with TTL 60 and assert it was accepted. Returns the message URI.
async fn send(http: &Http, push_uri: &str, extra: &[(&str, &str)], body: &[u8]) -> String {
    let mut headers = vec![TTL60];
    headers.extend_from_slice(extra);
    let r = push(http, push_uri, &headers, body).await;
    assert!(r.status == 201 || r.status == 202, "push: {r:?}");
    r.location(&http.origin)
}

/// Sleep for `ms` milliseconds.
async fn sleep_ms(ms: u64) {
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

/// The set of delivered bodies, for order-independent comparison.
fn bodies(n: &[Notification]) -> HashSet<Vec<u8>> {
    n.iter().map(Notification::data).collect()
}

/// A set of expected bodies.
fn set_of(items: &[&str]) -> HashSet<Vec<u8>> {
    items.iter().map(|s| s.as_bytes().to_vec()).collect()
}

/// Push one message requesting a receipt. Returns (message URI, receipt
/// subscription URI).
async fn send_with_receipt(http: &Http, push_uri: &str, ttl: &str) -> (String, String) {
    let r = push(http, push_uri, &[("ttl", ttl), ASYNC], b"x").await;
    assert_eq!(r.status, 202, "{r:?}");
    (
        r.location(&http.origin),
        r.links(&http.origin, REL_RECEIPT).remove(0),
    )
}

// ---------------------------------------------------------------------------
// Push, TTL, payload

/// WP-07 (MUST): push gives 201 with `Location`.
#[tokio::test(flavor = "multi_thread")]
async fn push_created() {
    let (env, _ua) = setup().await;
    let r = push(&env.http, &env.sub.push, &[TTL60], b"hello").await;
    assert_eq!(r.status, 201);
    assert!(r.header("location").unwrap().starts_with("https://"));
}

/// WP-11 (MUST): missing TTL gives 400.
#[tokio::test(flavor = "multi_thread")]
async fn ttl_missing_400() {
    let (env, _ua) = setup().await;
    assert_eq!(push(&env.http, &env.sub.push, &[], b"x").await.status, 400);
}

/// WP-12 (MUST / DERIVED): TTL = 1*DIGIT; anything else gives 400.
#[tokio::test(flavor = "multi_thread")]
async fn ttl_grammar_400() {
    let (env, _ua) = setup().await;
    for ttl in ["abc", "-1", "1.5", "", "10, 20"] {
        let r = push(&env.http, &env.sub.push, &[("ttl", ttl)], b"x").await;
        assert_eq!(r.status, 400, "TTL {ttl:?}");
    }
}

/// WP-12 (MUST): values that overflow are treated as 2^31.
#[tokio::test(flavor = "multi_thread")]
async fn ttl_overflow_saturates() {
    let (env, _ua) = setup().await;
    let headers = [("ttl", "99999999999999999999")];
    let r = push(&env.http, &env.sub.push, &headers, b"x").await;
    assert_eq!(r.status, 201);
    let ttl: u64 = r.header("ttl").unwrap().parse().unwrap();
    assert!(ttl <= 2_147_483_648);
}

/// WP-13 (MUST): the response TTL is never greater than requested.
#[tokio::test(flavor = "multi_thread")]
async fn response_ttl_not_greater() {
    let (env, _ua) = setup().await;
    let r = push(&env.http, &env.sub.push, &[TTL60], b"x").await;
    let ttl: u64 = r.header("ttl").unwrap().parse().unwrap();
    assert!(ttl <= 60);
}

/// WP-14, WP-33 (MUST NOT, MUST): an expired message is not delivered when the
/// user agent comes back.
#[tokio::test(flavor = "multi_thread")]
async fn ttl_expired_not_delivered() {
    let (env, ua) = setup().await;
    drop(ua);
    let r = push(&env.http, &env.sub.push, &[("ttl", "1")], b"x").await;
    assert_eq!(r.status, 201);
    sleep_ms(2500).await;
    env.connect().await.expect_no_notification(500).await;
}

/// WP-15 (MUST): TTL 0 while the user agent is offline is never delivered.
#[tokio::test(flavor = "multi_thread")]
async fn ttl_zero_offline_never_delivered() {
    let (env, ua) = setup().await;
    drop(ua);
    let r = push(&env.http, &env.sub.push, &[("ttl", "0")], b"x").await;
    assert_eq!(r.status, 201);
    env.connect().await.expect_no_notification(500).await;
}

/// WP-15 (MUST): TTL 0 while the user agent is connected is delivered.
#[tokio::test(flavor = "multi_thread")]
async fn ttl_zero_online_delivered() {
    let (env, mut ua) = setup().await;
    let r = push(&env.http, &env.sub.push, &[("ttl", "0")], b"now").await;
    assert_eq!(r.status, 201);
    assert_eq!(ua.next_notification().await.data(), b"now");
}

/// WP-34 (MUST): push to an unknown push resource gives 404.
#[tokio::test(flavor = "multi_thread")]
async fn push_unknown_404() {
    let (env, _ua) = setup().await;
    let r = push(&env.http, &mangle(&env.sub.push), &[TTL60], b"x").await;
    assert_eq!(r.status, 404);
}

/// WP-34 (MUST): push after unregister gives 404.
#[tokio::test(flavor = "multi_thread")]
async fn push_after_unregister_404() {
    let (env, mut ua) = setup().await;
    assert_eq!(ua.unregister(&env.sub.channel_id).await["status"], 200);
    let r = push(&env.http, &env.sub.push, &[TTL60], b"x").await;
    assert_eq!(r.status, 404);
}

/// WP-32 (MUST NOT): 4096 octets are never refused with 413.
#[tokio::test(flavor = "multi_thread")]
async fn payload_4096_accepted() {
    let (env, _ua) = setup().await;
    let r = push(&env.http, &env.sub.push, &[TTL60], &[7u8; 4096]).await;
    assert_eq!(r.status, 201);
}

/// WP-32 (MAY / POLICY): bodies above 4096 octets give 413.
#[tokio::test(flavor = "multi_thread")]
async fn policy_payload_4097_413() {
    let (env, _ua) = setup().await;
    let r = push(&env.http, &env.sub.push, &[TTL60], &[7u8; 4097]).await;
    assert_eq!(r.status, 413);
}

/// WP-07, FX-10 (MUST, COMPAT): an empty body is accepted and delivered
/// without `data`.
#[tokio::test(flavor = "multi_thread")]
async fn empty_body_delivered_without_data() {
    let (env, mut ua) = setup().await;
    send(&env.http, &env.sub.push, &[], b"").await;
    let n = ua.next_notification().await;
    assert!(n.0.get("data").is_none(), "{}", n.0);
}

// ---------------------------------------------------------------------------
// Urgency

/// WP-19 (MUST): each defined urgency is accepted.
#[tokio::test(flavor = "multi_thread")]
async fn urgency_values_accepted() {
    let (env, _ua) = setup().await;
    for u in ["very-low", "low", "normal", "high"] {
        let r = push(&env.http, &env.sub.push, &[TTL60, ("urgency", u)], b"x").await;
        assert_eq!(r.status, 201, "urgency {u}");
    }
}

/// WP-19 (DERIVED): a value outside the grammar gives 400.
#[tokio::test(flavor = "multi_thread")]
async fn urgency_invalid_400() {
    let (env, _ua) = setup().await;
    let headers = [TTL60, ("urgency", "urgent")];
    assert_eq!(
        push(&env.http, &env.sub.push, &headers, b"x").await.status,
        400
    );
}

/// WP-19 (MUST): multiple urgency values give 400.
#[tokio::test(flavor = "multi_thread")]
async fn urgency_multiple_400() {
    let (env, _ua) = setup().await;
    let two = [TTL60, ("urgency", "low"), ("urgency", "high")];
    assert_eq!(push(&env.http, &env.sub.push, &two, b"x").await.status, 400);
    let list = [TTL60, ("urgency", "low, high")];
    assert_eq!(
        push(&env.http, &env.sub.push, &list, b"x").await.status,
        400
    );
}

// ---------------------------------------------------------------------------
// Topics

/// WP-20 (MUST): at most 32 characters.
#[tokio::test(flavor = "multi_thread")]
async fn topic_too_long_400() {
    let (env, _ua) = setup().await;
    let (t33, t32) = ("a".repeat(33), "a".repeat(32));
    let r = push(&env.http, &env.sub.push, &[TTL60, ("topic", &t33)], b"x").await;
    assert_eq!(r.status, 400);
    let r = push(&env.http, &env.sub.push, &[TTL60, ("topic", &t32)], b"x").await;
    assert_eq!(r.status, 201);
}

/// WP-20 (MUST): only the base64url alphabet.
#[tokio::test(flavor = "multi_thread")]
async fn topic_bad_alphabet_400() {
    let (env, _ua) = setup().await;
    for t in ["a.b", "a=b", "a/b", "a+b"] {
        let r = push(&env.http, &env.sub.push, &[TTL60, ("topic", t)], b"x").await;
        assert_eq!(r.status, 400, "topic {t}");
    }
}

/// WP-21 (MUST): a topic message replaces the outstanding one.
#[tokio::test(flavor = "multi_thread")]
async fn topic_replaces() {
    let (env, ua) = setup().await;
    drop(ua);
    send(&env.http, &env.sub.push, &[("topic", "t")], b"A").await;
    send(&env.http, &env.sub.push, &[("topic", "t")], b"B").await;
    let got = env.connect().await.drain(500).await;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].data(), b"B");
}

/// WP-21 (MUST): the replacement is a new resource; the old one is gone.
#[tokio::test(flavor = "multi_thread")]
async fn topic_new_location_old_gone() {
    let (env, ua) = setup().await;
    drop(ua);
    let a = send(&env.http, &env.sub.push, &[("topic", "t")], b"A").await;
    let b = send(&env.http, &env.sub.push, &[("topic", "t")], b"B").await;
    assert_ne!(a, b);
    assert_eq!(env.http.request("GET", &a, &[], b"").await.status, 404);
    assert_eq!(env.http.request("GET", &b, &[], b"").await.status, 200);
}

/// WP-21 (MUST): the replacement's TTL applies.
#[tokio::test(flavor = "multi_thread")]
async fn topic_replaces_ttl() {
    let (env, ua) = setup().await;
    drop(ua);
    let a = [("ttl", "600"), ("topic", "t")];
    let b = [("ttl", "1"), ("topic", "t")];
    assert_eq!(push(&env.http, &env.sub.push, &a, b"A").await.status, 201);
    assert_eq!(push(&env.http, &env.sub.push, &b, b"B").await.status, 201);
    sleep_ms(2500).await;
    env.connect().await.expect_no_notification(500).await;
}

/// WP-21 (MUST), WP-22 (SHOULD): the replacement's receipt settings apply,
/// and the replaced message emits no receipt.
#[tokio::test(flavor = "multi_thread")]
async fn topic_replaces_receipt() {
    let (env, ua) = setup().await;
    drop(ua);
    let headers = [TTL60, ASYNC, ("topic", "t")];
    let r = push(&env.http, &env.sub.push, &headers, b"A").await;
    assert_eq!(r.status, 202);
    let rsub = r.links(&env.http.origin, REL_RECEIPT).remove(0);
    send(&env.http, &env.sub.push, &[("topic", "t")], b"B").await;
    let mut receipts = env.server.receipts(&rsub, &[]).await;
    let mut ua = env.connect().await;
    let n = ua.next_notification().await;
    assert_eq!(n.data(), b"B");
    ua.ack(n.channel_id(), n.version(), 100).await;
    receipts.expect_no_receipt(500).await;
}

/// WP-21 (MUST): distinct topics, and messages without a topic, do not
/// replace each other.
#[tokio::test(flavor = "multi_thread")]
async fn topic_distinct_not_replaced() {
    let (env, ua) = setup().await;
    drop(ua);
    send(&env.http, &env.sub.push, &[("topic", "t1")], b"1").await;
    send(&env.http, &env.sub.push, &[("topic", "t2")], b"2").await;
    send(&env.http, &env.sub.push, &[], b"3").await;
    let got = env.connect().await.drain(500).await;
    assert_eq!(bodies(&got), set_of(&["1", "2", "3"]));
}

/// WP-21 (MUST): replacement is scoped to one subscription.
#[tokio::test(flavor = "multi_thread")]
async fn topic_scoped_to_subscription() {
    let (env, mut ua) = setup().await;
    let other = ua.subscribe(None).await;
    drop(ua);
    send(&env.http, &env.sub.push, &[("topic", "t")], b"a").await;
    send(&env.http, &other.push, &[("topic", "t")], b"b").await;
    let got = env.connect().await.drain(500).await;
    assert_eq!(bodies(&got), set_of(&["a", "b"]));
}

// ---------------------------------------------------------------------------
// Delivery

/// FX-10, WP-07 (COMPAT, MUST): a message arrives as a notification with
/// the channel, the message id, and the exact body.
#[tokio::test(flavor = "multi_thread")]
async fn notification_delivered() {
    let (env, mut ua) = setup().await;
    let body: Vec<u8> = (0..=255).collect();
    let msg = send(&env.http, &env.sub.push, &[], &body).await;
    let n = ua.next_notification().await;
    assert_eq!(n.channel_id(), env.sub.channel_id);
    assert_eq!(n.version(), last_segment(&msg));
    assert_eq!(n.data(), body);
}

/// ENC-05 (MUST): `Content-Encoding` reaches the user agent as
/// `headers.encoding`.
#[tokio::test(flavor = "multi_thread")]
async fn content_encoding_forwarded() {
    let (env, mut ua) = setup().await;
    let body = opaque_aes128gcm(&[0x04; 65]);
    let headers = [("content-encoding", "aes128gcm")];
    send(&env.http, &env.sub.push, &headers, &body).await;
    let n = ua.next_notification().await;
    assert_eq!(n.encoding(), Some("aes128gcm"));
    assert_eq!(n.data(), body);
}

/// WP-16, WP-23, VAP-10, FX-10 (MUST NOT): Urgency, Topic, TTL, and VAPID
/// credentials never reach the user agent.
#[tokio::test(flavor = "multi_thread")]
async fn not_forwarded() {
    let (env, mut ua) = setup().await;
    let key = AppServerKey::new();
    let token = key.token(
        &env.http.origin,
        now() + 3600,
        Some("mailto:ops@example.com"),
    );
    let auth = format!("vapid t={token}, k={}", key.k_b64());
    let headers = [
        ("urgency", "high"),
        ("topic", "t"),
        ("authorization", auth.as_str()),
        ("content-encoding", "aes128gcm"),
    ];
    send(
        &env.http,
        &env.sub.push,
        &headers,
        &opaque_aes128gcm(&[0x04; 65]),
    )
    .await;
    let n = ua.next_notification().await;
    let allowed = ["messageType", "channelID", "version", "data", "headers"];
    for field in n.0.as_object().unwrap().keys() {
        assert!(
            allowed.contains(&field.as_str()),
            "{field} forwarded: {}",
            n.0
        );
    }
    let header_fields: Vec<&String> = n.0["headers"].as_object().unwrap().keys().collect();
    assert_eq!(header_fields, ["encoding"]);
    let text = n.0.to_string();
    assert!(
        !text.contains(&token) && !text.contains(&key.k_b64()),
        "credential forwarded"
    );
}

/// FX-09 (COMPAT): one session receives the messages of every subscription of
/// the user agent.
#[tokio::test(flavor = "multi_thread")]
async fn all_subscriptions_on_one_session() {
    let (env, mut ua) = setup().await;
    let other = ua.subscribe(None).await;
    send(&env.http, &env.sub.push, &[], b"a").await;
    send(&env.http, &other.push, &[], b"b").await;
    let got = ua.drain(500).await;
    assert_eq!(bodies(&got), set_of(&["a", "b"]));
    let channels: HashSet<&str> = got.iter().map(Notification::channel_id).collect();
    let expected = HashSet::from([env.sub.channel_id.as_str(), other.channel_id.as_str()]);
    assert_eq!(channels, expected);
}

/// WP-33, FX-09 (MUST, COMPAT): stored messages are delivered when the user
/// agent reconnects, oldest first.
#[tokio::test(flavor = "multi_thread")]
async fn stored_delivered_on_reconnect() {
    let (env, ua) = setup().await;
    drop(ua);
    for b in ["1", "2", "3"] {
        send(&env.http, &env.sub.push, &[], b.as_bytes()).await;
        sleep_ms(5).await;
    }
    let got: Vec<Vec<u8>> = env
        .connect()
        .await
        .drain(500)
        .await
        .iter()
        .map(Notification::data)
        .collect();
    assert_eq!(got, [b"1".to_vec(), b"2".to_vec(), b"3".to_vec()]);
}

/// WP-28 (SHOULD): an unacknowledged message is delivered again on the next
/// session.
#[tokio::test(flavor = "multi_thread")]
async fn unacked_redelivered() {
    let (env, mut ua) = setup().await;
    send(&env.http, &env.sub.push, &[], b"again").await;
    assert_eq!(ua.next_notification().await.data(), b"again");
    drop(ua);
    let mut ua = env.connect().await;
    assert_eq!(ua.next_notification().await.data(), b"again");
}

/// WP-27, FX-11 (MUST, COMPAT): an acknowledged message is not delivered
/// again.
#[tokio::test(flavor = "multi_thread")]
async fn acked_not_redelivered() {
    let (env, mut ua) = setup().await;
    send(&env.http, &env.sub.push, &[], b"x").await;
    let n = ua.next_notification().await;
    ua.ack(n.channel_id(), n.version(), 100).await;
    sleep_ms(200).await;
    drop(ua);
    env.connect().await.expect_no_notification(500).await;
}

/// FX-11 (COMPAT): an acknowledgement naming the wrong channel is ignored.
#[tokio::test(flavor = "multi_thread")]
async fn ack_wrong_channel_ignored() {
    let (env, mut ua) = setup().await;
    send(&env.http, &env.sub.push, &[], b"x").await;
    let n = ua.next_notification().await;
    ua.ack(&channel_id(), n.version(), 100).await;
    sleep_ms(200).await;
    drop(ua);
    let mut ua = env.connect().await;
    assert_eq!(ua.next_notification().await.data(), b"x");
}

/// WP-31 (SHOULD): the message resource returns the body with
/// `Last-Modified`.
#[tokio::test(flavor = "multi_thread")]
async fn message_readable() {
    let (env, _ua) = setup().await;
    let headers = [("content-type", "text/plain")];
    let msg = send(&env.http, &env.sub.push, &headers, b"read me").await;
    let r = env.http.request("GET", &msg, &[], b"").await;
    assert_eq!(r.status, 200);
    assert_eq!(&r.body[..], b"read me");
    assert_eq!(r.header("content-type"), Some("text/plain"));
    let lm = r.header("last-modified").expect("last-modified");
    assert!(httpdate::parse_http_date(lm).is_ok(), "{lm}");
}

/// WP-39 (POLICY): `DELETE` withdraws an undelivered message.
#[tokio::test(flavor = "multi_thread")]
async fn policy_message_withdraw() {
    let (env, ua) = setup().await;
    drop(ua);
    let msg = send(&env.http, &env.sub.push, &[], b"never").await;
    assert_eq!(env.http.request("DELETE", &msg, &[], b"").await.status, 204);
    assert_eq!(env.http.request("DELETE", &msg, &[], b"").await.status, 404);
    assert_eq!(env.http.request("GET", &msg, &[], b"").await.status, 404);
    env.connect().await.expect_no_notification(500).await;
}

/// WP-39 (POLICY): withdrawing an unknown message gives 404.
#[tokio::test(flavor = "multi_thread")]
async fn policy_withdraw_unknown_404() {
    let (env, _ua) = setup().await;
    let msg = send(&env.http, &env.sub.push, &[], b"x").await;
    let r = env.http.request("DELETE", &mangle(&msg), &[], b"").await;
    assert_eq!(r.status, 404);
}

// ---------------------------------------------------------------------------
// Receipts

/// WP-08 (MUST): `Prefer: respond-async` gives 202 with `Location` and a
/// receipt `Link`.
#[tokio::test(flavor = "multi_thread")]
async fn receipt_requested_202() {
    let (env, _ua) = setup().await;
    let r = push(&env.http, &env.sub.push, &[TTL60, ASYNC], b"x").await;
    assert_eq!(r.status, 202);
    assert!(r.header("location").is_some());
    assert_eq!(r.links(&env.http.origin, REL_RECEIPT).len(), 1);
}

/// WP-08 (MUST): `Prefer` is a list (RFC 7240).
#[tokio::test(flavor = "multi_thread")]
async fn prefer_list_parsed() {
    let (env, _ua) = setup().await;
    let headers = [TTL60, ("prefer", "wait=5, respond-async")];
    assert_eq!(
        push(&env.http, &env.sub.push, &headers, b"x").await.status,
        202
    );
}

/// WP-09 (SHOULD): a receipt `Link` returns the same receipt subscription.
#[tokio::test(flavor = "multi_thread")]
async fn receipt_sub_reused() {
    let (env, _ua) = setup().await;
    let (_, rsub) = send_with_receipt(&env.http, &env.sub.push, "60").await;
    let link = link_header(&rsub, REL_RECEIPT);
    let headers = [TTL60, ASYNC, ("link", link.as_str())];
    let r = push(&env.http, &env.sub.push, &headers, b"y").await;
    assert_eq!(r.status, 202);
    assert_eq!(r.links(&env.http.origin, REL_RECEIPT), vec![rsub]);
}

/// WP-10 (MUST): an invalid receipt `Link` gives 400.
#[tokio::test(flavor = "multi_thread")]
async fn receipt_invalid_400() {
    let (env, _ua) = setup().await;
    let (_, rsub) = send_with_receipt(&env.http, &env.sub.push, "60").await;
    let link = link_header(&mangle(&rsub), REL_RECEIPT);
    let headers = [TTL60, ASYNC, ("link", link.as_str())];
    assert_eq!(
        push(&env.http, &env.sub.push, &headers, b"y").await.status,
        400
    );
}

/// WP-30 (MUST): the receipt stream is `text/event-stream`.
#[tokio::test(flavor = "multi_thread")]
async fn receipt_stream_is_event_stream() {
    let (env, _ua) = setup().await;
    let (_, rsub) = send_with_receipt(&env.http, &env.sub.push, "60").await;
    let stream = env.server.receipts(&rsub, &[]).await;
    assert_eq!(stream.status, 200);
    let ct = stream
        .headers
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.starts_with("text/event-stream"), "{ct}");
}

/// WP-27, WP-30, FX-11 (MUST): acknowledgement produces a 204 receipt naming
/// the message URI.
#[tokio::test(flavor = "multi_thread")]
async fn receipt_204_on_ack() {
    let (env, mut ua) = setup().await;
    let (msg, rsub) = send_with_receipt(&env.http, &env.sub.push, "60").await;
    let mut receipts = env.server.receipts(&rsub, &[]).await;
    let n = ua.next_notification().await;
    ua.ack(n.channel_id(), n.version(), 100).await;
    assert_eq!(receipts.next_receipt().await, (msg, 204));
}

/// WP-29, FX-11 (MUST): a user agent that cannot decrypt the message
/// produces a 410 receipt.
#[tokio::test(flavor = "multi_thread")]
async fn receipt_410_on_decryption_failure() {
    let (env, mut ua) = setup().await;
    let (msg, rsub) = send_with_receipt(&env.http, &env.sub.push, "60").await;
    let mut receipts = env.server.receipts(&rsub, &[]).await;
    let n = ua.next_notification().await;
    ua.ack(n.channel_id(), n.version(), 101).await;
    assert_eq!(receipts.next_receipt().await, (msg, 410));
}

/// WP-30 (MUST): a receipt emitted while the application server is offline
/// is delivered when it connects.
#[tokio::test(flavor = "multi_thread")]
async fn receipt_queued_while_offline() {
    let (env, mut ua) = setup().await;
    let (msg, rsub) = send_with_receipt(&env.http, &env.sub.push, "60").await;
    let n = ua.next_notification().await;
    ua.ack(n.channel_id(), n.version(), 100).await;
    sleep_ms(200).await;
    let mut receipts = env.server.receipts(&rsub, &[]).await;
    assert_eq!(receipts.next_receipt().await, (msg, 204));
}

/// WP-29 (MUST): a message that expires undelivered produces a 410 receipt.
#[tokio::test(flavor = "multi_thread")]
async fn receipt_410_on_expiry() {
    let (env, ua) = setup().await;
    drop(ua);
    let (msg, rsub) = send_with_receipt(&env.http, &env.sub.push, "1").await;
    let mut receipts = env.server.receipts(&rsub, &[]).await;
    assert_eq!(receipts.next_receipt().await, (msg, 410));
}

/// WP-29 (MUST): unregistering with a pending message produces a 410
/// receipt.
#[tokio::test(flavor = "multi_thread")]
async fn receipt_410_on_unregister() {
    let (env, mut ua) = setup().await;
    let (msg, rsub) = send_with_receipt(&env.http, &env.sub.push, "60").await;
    let mut receipts = env.server.receipts(&rsub, &[]).await;
    assert_eq!(ua.next_notification().await.version(), last_segment(&msg));
    assert_eq!(ua.unregister(&env.sub.channel_id).await["status"], 200);
    assert_eq!(receipts.next_receipt().await, (msg, 410));
}

/// §5.5 (POLICY): `Prefer: wait=0` with nothing queued gives 204.
#[tokio::test(flavor = "multi_thread")]
async fn policy_receipt_wait0_empty_204() {
    let (env, _ua) = setup().await;
    let (_, rsub) = send_with_receipt(&env.http, &env.sub.push, "60").await;
    let stream = env.server.receipts(&rsub, &[("prefer", "wait=0")]).await;
    assert_eq!(stream.status, 204);
}

/// §5.5 (POLICY): `Prefer: wait=0` sends the queued receipts and ends the
/// stream.
#[tokio::test(flavor = "multi_thread")]
async fn policy_receipt_wait0_backlog_then_end() {
    let (env, mut ua) = setup().await;
    let (msg, rsub) = send_with_receipt(&env.http, &env.sub.push, "60").await;
    let n = ua.next_notification().await;
    ua.ack(n.channel_id(), n.version(), 100).await;
    sleep_ms(200).await;
    let mut stream = env.server.receipts(&rsub, &[("prefer", "wait=0")]).await;
    assert_eq!(stream.status, 200);
    assert_eq!(stream.next_receipt().await, (msg, 204));
    assert!(stream.next_event().await.is_none(), "stream did not end");
}

/// WP-34 (MUST): deleting a receipt subscription ends its stream, and the
/// receipt `Link` becomes invalid.
#[tokio::test(flavor = "multi_thread")]
async fn receipt_sub_delete() {
    let (env, _ua) = setup().await;
    let (_, rsub) = send_with_receipt(&env.http, &env.sub.push, "60").await;
    let mut stream = env.server.receipts(&rsub, &[]).await;
    assert_eq!(
        env.http.request("DELETE", &rsub, &[], b"").await.status,
        204
    );
    assert_eq!(stream.next_event().await.expect("gone event").event, "gone");
    assert!(stream.next_event().await.is_none(), "stream did not end");
    let link = link_header(&rsub, REL_RECEIPT);
    let headers = [TTL60, ASYNC, ("link", link.as_str())];
    assert_eq!(
        push(&env.http, &env.sub.push, &headers, b"x").await.status,
        400
    );
    assert_eq!(
        env.http.request("DELETE", &rsub, &[], b"").await.status,
        404
    );
}

/// WP-34 (MUST): an unknown receipt subscription gives 404.
#[tokio::test(flavor = "multi_thread")]
async fn receipt_unknown_404() {
    let (env, _ua) = setup().await;
    let (_, rsub) = send_with_receipt(&env.http, &env.sub.push, "60").await;
    let stream = env.server.receipts(&mangle(&rsub), &[]).await;
    assert_eq!(stream.status, 404);
}

// ---------------------------------------------------------------------------
// Capability URLs

/// WP-36, WP-37 (MUST, guidance): push endpoints and message URIs contain at
/// least 120 bits, never repeat, and reveal neither the user agent nor the
/// channel.
#[tokio::test(flavor = "multi_thread")]
async fn capability_urls() {
    let (env, mut ua) = setup().await;
    let msg = send(&env.http, &env.sub.push, &[], b"x").await;
    ua.next_notification().await;
    let mut uris = vec![
        (env.sub.push.clone(), env.sub.channel_id.clone()),
        (msg, String::new()),
    ];
    for _ in 0..20 {
        let sub = ua.subscribe(None).await;
        uris.push((sub.push, sub.channel_id));
    }
    let mut seen = HashSet::new();
    for (uri, channel) in uris {
        let seg = last_segment(&uri).to_owned();
        assert!(seg.len() >= 20, "short id {seg}");
        assert!(
            seg.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "non-base64url id {seg}"
        );
        assert!(!uri.contains(&env.uaid), "{uri} reveals the uaid");
        assert!(
            channel.is_empty() || !uri.contains(&channel),
            "{uri} reveals the channel"
        );
        assert!(seen.insert(seg), "repeated id in {uri}");
    }
}

// ---------------------------------------------------------------------------
// Transport

/// WP-01 (MUST): no plaintext HTTP.
#[tokio::test(flavor = "multi_thread")]
async fn tls_required() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let server = TestServer::start().await;
    let mut tcp = tokio::net::TcpStream::connect(server.addr).await.unwrap();
    let _ = tcp
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await;
    let mut buf = [0u8; 5];
    let n = tokio::time::timeout(Duration::from_secs(2), tcp.read(&mut buf))
        .await
        .map_or(0, |r| r.unwrap_or(0));
    assert_ne!(&buf[..n], b"HTTP/");
}

/// RFC 8030 §1.1: the application server interface works over HTTP/1.1.
#[tokio::test(flavor = "multi_thread")]
async fn http1_push_and_read() {
    let (env, _ua) = setup().await;
    let h1 = env.server.h1().await;
    let r = h1
        .request("POST", &env.sub.push, &[TTL60], b"over h1")
        .await;
    assert_eq!(r.status, 201);
    let msg = r.location(&env.server.origin);
    let r = h1.request("GET", &msg, &[], b"").await;
    assert_eq!((r.status, &r.body[..]), (200, &b"over h1"[..]));
}
