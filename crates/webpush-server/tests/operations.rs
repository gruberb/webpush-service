//! Production behaviour: probes and metrics, graceful shutdown, connection
//! limits, server pings, batched backlogs, user agent expiry, and CORS.
#![allow(clippy::unwrap_used)]

mod common;

use std::time::Duration;

use common::*;

/// Start a single node with an internal listener and extra settings.
async fn server(toml: &str) -> TestServer {
    TestServer::start_with(Options {
        toml: toml.to_owned(),
        internal: true,
        ..Options::default()
    })
    .await
}

/// `GET` on the internal listener.
async fn internal_get(server: &TestServer, path: &str) -> reqwest::Response {
    let url = format!("http://{}{path}", server.internal.unwrap());
    reqwest::get(url).await.unwrap()
}

/// A registered user agent that has disconnected: its `uaid` and endpoint.
async fn offline_subscription(server: &TestServer) -> (String, Sub) {
    let mut ua = server.ua().await;
    let uaid = ua.hello(None).await;
    let sub = ua.subscribe(None).await;
    (uaid, sub)
}

/// Health, readiness, version, and metrics answer on the internal listener.
#[tokio::test(flavor = "multi_thread")]
async fn probes_and_metrics() {
    let server = server("").await;
    assert_eq!(internal_get(&server, "/health").await.status(), 200);
    assert_eq!(internal_get(&server, "/ready").await.status(), 200);
    let version: serde_json::Value = internal_get(&server, "/version")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(version["name"], "webpush-server");

    let (_, sub) = offline_subscription(&server).await;
    let http = server.http().await;
    http.request("POST", &sub.push, &[("ttl", "60")], b"x")
        .await;
    let metrics = internal_get(&server, "/metrics")
        .await
        .text()
        .await
        .unwrap();
    assert!(metrics.contains("webpush_http_requests_total"), "{metrics}");
    assert!(
        metrics.contains(r#"route="/push/{id}""#),
        "labelled by route template"
    );
    assert!(
        !metrics.contains(&last_segment(&sub.push).to_owned()),
        "no capability URLs"
    );
}

/// On shutdown, readiness fails first, then sessions close with 1001 and the
/// server finishes.
#[tokio::test(flavor = "multi_thread")]
async fn graceful_shutdown() {
    let server = server("[shutdown]\ndrain_delay = \"300ms\"\ntimeout = \"5s\"\n").await;
    let internal = server.internal.unwrap();
    let mut ua = server.ua().await;
    ua.hello(None).await;

    let done = tokio::spawn(server.shutdown());
    tokio::time::sleep(Duration::from_millis(100)).await;
    let ready = reqwest::get(format!("http://{internal}/ready"))
        .await
        .unwrap();
    assert_eq!(ready.status(), 503, "readiness fails while draining");
    assert_eq!(ua.close_code().await, Some(1001), "going away");
    done.await.unwrap();
}

/// At the connection limit the listener stops accepting until a connection
/// closes; a WebSocket session keeps its connection's place.
#[tokio::test(flavor = "multi_thread")]
async fn connection_limit() {
    let server = server("[public]\nmax_connections = 1\n").await;
    let mut first = server.ua().await;
    first.hello(None).await;
    let blocked = tokio::time::timeout(Duration::from_millis(500), server.ua()).await;
    assert!(
        blocked.is_err(),
        "a second connection was served at the limit"
    );
    drop(first);
    let mut second = tokio::time::timeout(Duration::from_secs(5), server.ua())
        .await
        .expect("served once the first closed");
    second.hello(None).await;
}

/// The server pings idle sessions.
#[tokio::test(flavor = "multi_thread")]
async fn server_pings() {
    let server = server("[websocket]\nping_interval = \"100ms\"\n").await;
    let mut ua = server.ua().await;
    ua.hello(None).await;
    assert!(ua.pinged_within(2000).await);
}

/// A large backlog goes out in batches; each follows the acknowledgement of
/// the previous one.
#[tokio::test(flavor = "multi_thread")]
async fn backlog_in_batches() {
    let server = server("[websocket]\nbacklog_batch = 2\n").await;
    let (uaid, sub) = offline_subscription(&server).await;
    let http = server.http().await;
    for i in 0..5 {
        let body = format!("m{i}");
        http.request("POST", &sub.push, &[("ttl", "60")], body.as_bytes())
            .await;
        // Order is by acceptance time in milliseconds.
        tokio::time::sleep(Duration::from_millis(3)).await;
    }
    let mut ua = server.ua().await;
    ua.hello(Some(&uaid)).await;
    let mut received = Vec::new();
    for expected in [2, 2, 1] {
        let batch = ua.drain(300).await;
        assert_eq!(batch.len(), expected, "batch sizes");
        for n in &batch {
            received.push(n.data());
            ua.ack(n.channel_id(), n.version(), 100).await;
        }
    }
    let want: Vec<Vec<u8>> = (0..5).map(|i| format!("m{i}").into_bytes()).collect();
    assert_eq!(received, want, "oldest first, each once");
}

/// User agents not seen within `expire_after` are deleted with their
/// subscriptions.
#[tokio::test(flavor = "multi_thread")]
async fn user_agents_expire() {
    let server =
        server("[user_agents]\nexpire_after = \"300ms\"\nsweep_interval = \"50ms\"\n").await;
    let (_, sub) = offline_subscription(&server).await;
    let http = server.http().await;
    assert_eq!(
        http.request("POST", &sub.push, &[("ttl", "60")], b"")
            .await
            .status,
        201
    );
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(
        http.request("POST", &sub.push, &[("ttl", "60")], b"")
            .await
            .status,
        404
    );
}

/// With allowed origins configured, browsers may call the push API.
#[tokio::test(flavor = "multi_thread")]
async fn cors_preflight() {
    let server = server("[cors]\nallowed_origins = [\"https://app.example\"]\n").await;
    let (_, sub) = offline_subscription(&server).await;
    let http = server.http().await;
    let r = http
        .request(
            "OPTIONS",
            &sub.push,
            &[
                ("origin", "https://app.example"),
                ("access-control-request-method", "POST"),
                ("access-control-request-headers", "ttl, content-encoding"),
            ],
            b"",
        )
        .await;
    assert_eq!(
        r.header("access-control-allow-origin"),
        Some("https://app.example")
    );
    let r = http
        .request(
            "POST",
            &sub.push,
            &[("ttl", "60"), ("origin", "https://app.example")],
            b"",
        )
        .await;
    assert!(
        r.header("access-control-expose-headers")
            .is_some_and(|h| h.contains("location")),
        "{r:?}"
    );
}

/// With `max_session`, a session ends with 1001 after its (jittered)
/// lifetime, and a message stored meanwhile arrives after reconnecting.
#[tokio::test(flavor = "multi_thread")]
async fn sessions_end_after_max_session() {
    let server = server("[websocket]\nmax_session = \"400ms\"\n").await;
    let mut ua = server.ua().await;
    let uaid = ua.hello(None).await;
    let sub = ua.subscribe(None).await;
    let started = std::time::Instant::now();
    assert_eq!(ua.close_code().await, Some(1001));
    let lived = started.elapsed();
    assert!(
        lived >= Duration::from_millis(250) && lived < Duration::from_secs(2),
        "{lived:?}"
    );
    let http = server.http().await;
    http.request("POST", &sub.push, &[("ttl", "60")], b"while away")
        .await;
    let mut ua = server.ua().await;
    ua.hello(Some(&uaid)).await;
    assert_eq!(ua.next_notification().await.data(), b"while away");
}
