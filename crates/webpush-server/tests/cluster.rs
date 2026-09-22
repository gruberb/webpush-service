//! The service split into endpoint and connection nodes that share one
//! store: delivery across nodes, receipts for acknowledgements made on
//! another node, session takeover, stale routes, and the internal API.
#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use webpush_store::{MemoryStore, Recipient, Store};

/// Shared secret of the test cluster.
const TOKEN: &str = "test-cluster-token-0123456789";

/// One endpoint node and `n` connection nodes over one store.
struct Cluster {
    /// Serves application servers.
    endpoint: TestServer,
    /// Serve user agents.
    connect: Vec<TestServer>,
    /// The shared store, to inspect routes.
    store: MemoryStore,
}

/// Start a cluster with `n` connection nodes.
async fn cluster(n: usize) -> Cluster {
    let store = MemoryStore::new();
    let endpoint = TestServer::start_with(Options {
        role: Some("endpoint"),
        cluster_token: Some(TOKEN.to_owned()),
        store: Some(store.clone()),
        ..Options::default()
    })
    .await;
    let mut connect = Vec::new();
    for _ in 0..n {
        connect.push(
            TestServer::start_with(Options {
                role: Some("connect"),
                origin: Some(endpoint.origin.clone()),
                cluster_token: Some(TOKEN.to_owned()),
                store: Some(store.clone()),
                ..Options::default()
            })
            .await,
        );
    }
    Cluster {
        endpoint,
        connect,
        store,
    }
}

/// A push accepted by the endpoint node.
async fn push(http: &Http, uri: &str, headers: &[(&str, &str)], body: &[u8]) -> Resp {
    let r = http.request("POST", uri, headers, body).await;
    assert!(r.status == 201 || r.status == 202, "push: {r:?}");
    r
}

/// A message pushed on the endpoint node reaches a session on a connection
/// node, and the endpoint is issued on the endpoint node's origin.
#[tokio::test(flavor = "multi_thread")]
async fn push_reaches_session_on_another_node() {
    let c = cluster(1).await;
    let mut ua = c.connect[0].ua().await;
    ua.hello(None).await;
    let sub = ua.subscribe(None).await;
    assert!(sub.push.starts_with(&c.endpoint.origin), "{}", sub.push);

    let http = c.endpoint.http().await;
    push(&http, &sub.push, &[("ttl", "60")], b"across").await;
    assert_eq!(ua.next_notification().await.data(), b"across");
}

/// An acknowledgement on a connection node produces the receipt on the
/// endpoint node's receipt stream.
#[tokio::test(flavor = "multi_thread")]
async fn receipt_crosses_nodes() {
    let c = cluster(1).await;
    let mut ua = c.connect[0].ua().await;
    ua.hello(None).await;
    let sub = ua.subscribe(None).await;
    let http = c.endpoint.http().await;
    let r = push(
        &http,
        &sub.push,
        &[("ttl", "60"), ("prefer", "respond-async")],
        b"x",
    )
    .await;
    let rsub = r.links(&http.origin, REL_RECEIPT).remove(0);
    let mut receipts = c.endpoint.receipts(&rsub, &[]).await;

    let n = ua.next_notification().await;
    ua.ack(n.channel_id(), n.version(), 100).await;
    let (message, status) = receipts.next_receipt().await;
    assert_eq!(status, 204);
    assert_eq!(message, r.location(&http.origin));
}

/// A user agent that reconnects to another node closes its old session
/// there, and messages follow it.
#[tokio::test(flavor = "multi_thread")]
async fn session_moves_between_nodes() {
    let c = cluster(2).await;
    let mut first = c.connect[0].ua().await;
    let uaid = first.hello(None).await;
    let sub = first.subscribe(None).await;

    let mut second = c.connect[1].ua().await;
    assert_eq!(second.hello(Some(&uaid)).await, uaid);
    assert_eq!(first.close_code().await, Some(1000), "old session replaced");

    let http = c.endpoint.http().await;
    push(&http, &sub.push, &[("ttl", "60")], b"moved").await;
    assert_eq!(second.next_notification().await.data(), b"moved");
}

/// A route to a node that cannot be reached is removed, the message stays
/// stored, and it arrives when the user agent connects again.
#[tokio::test(flavor = "multi_thread")]
async fn stale_route_is_removed() {
    let c = cluster(1).await;
    let mut ua = c.connect[0].ua().await;
    let uaid = ua.hello(None).await;
    let sub = ua.subscribe(None).await;
    drop(ua);

    let to = Recipient::UserAgent(uaid.clone());
    let dead = "http://127.0.0.1:9";
    // Wait for the session's own cleanup, then plant a route to nowhere.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    c.store.set_route(&to, dead).await.unwrap();

    let http = c.endpoint.http().await;
    push(&http, &sub.push, &[("ttl", "60")], b"stored").await;
    assert_eq!(
        c.store.route(&to).await.unwrap(),
        None,
        "stale route removed"
    );

    let mut ua = c.connect[0].ua().await;
    ua.hello(Some(&uaid)).await;
    assert_eq!(ua.next_notification().await.data(), b"stored");
}

/// A session's route is removed when it disconnects.
#[tokio::test(flavor = "multi_thread")]
async fn route_removed_on_disconnect() {
    let c = cluster(1).await;
    let mut ua = c.connect[0].ua().await;
    let uaid = ua.hello(None).await;
    ua.subscribe(None).await;
    let to = Recipient::UserAgent(uaid);
    assert!(c.store.route(&to).await.unwrap().is_some());
    drop(ua);
    for _ in 0..50 {
        if c.store.route(&to).await.unwrap().is_none() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("route still present after disconnect");
}

/// The internal delivery endpoint refuses callers without the cluster token.
#[tokio::test(flavor = "multi_thread")]
async fn internal_notify_requires_token() {
    let c = cluster(1).await;
    let url = format!(
        "http://{}/internal/v1/notify",
        c.connect[0].internal.unwrap()
    );
    let body =
        serde_json::json!({ "to": { "user_agent": "0".repeat(32) }, "event": { "type": "gone" } });
    let client = reqwest::Client::new();
    for auth in [None, Some("Bearer wrong-token-0123456789")] {
        let mut req = client.post(&url).json(&body);
        if let Some(auth) = auth {
            req = req.header("authorization", auth);
        }
        assert_eq!(req.send().await.unwrap().status(), 401);
    }
    let ok = client
        .post(&url)
        .bearer_auth(TOKEN)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 404, "authorized, but no such session here");
}

/// Each role serves only its half of the public API.
#[tokio::test(flavor = "multi_thread")]
async fn roles_serve_their_half() {
    let c = cluster(1).await;
    let on_connect = c.connect[0].http().await;
    let r = on_connect
        .request(
            "POST",
            &c.connect[0].url("/push/AAAAAAAAAAAAAAAAAAAAAA"),
            &[("ttl", "0")],
            b"",
        )
        .await;
    assert_eq!(r.status, 404, "connection nodes do not accept pushes");
    let on_endpoint = c.endpoint.h1().await;
    let r = on_endpoint
        .request("GET", &c.endpoint.url("/"), &[], b"")
        .await;
    assert_eq!(r.status, 404, "endpoint nodes do not accept sessions");
}
