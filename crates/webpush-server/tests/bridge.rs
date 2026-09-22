//! Bridged user agents: the registration API, and delivery through a bridge
//! with its failure mapping. A recording bridge stands in for FCM and APNs;
//! the real bridges are tested in their own crates.
#![allow(clippy::unwrap_used)]

mod common;

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use common::*;
use serde_json::{Value, json};
use webpush_bridge::{Address, BoxFuture, Bridge, Error, Notification, Priority};

/// What the fake bridge was asked to deliver.
#[derive(Clone, Debug)]
struct Sent {
    /// Application id.
    app_id: String,
    /// Device token.
    token: String,
    /// `Notification::fields`.
    fields: std::collections::BTreeMap<&'static str, String>,
    /// TTL.
    ttl: Duration,
    /// Priority.
    priority: Priority,
}

/// A bridge that records messages and fails on demand.
#[derive(Default)]
struct Fake {
    /// Every successful send.
    sent: Mutex<Vec<Sent>>,
    /// The error the next send returns, if any.
    fail: Mutex<Option<Error>>,
}

impl Bridge for Fake {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn has_app(&self, app_id: &str) -> bool {
        app_id == "app"
    }

    fn send<'a>(
        &'a self,
        to: Address<'a>,
        n: &'a Notification<'a>,
    ) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            if let Some(e) = self.fail.lock().unwrap().take() {
                return Err(e);
            }
            self.sent.lock().unwrap().push(Sent {
                app_id: to.app_id.to_owned(),
                token: to.token.to_owned(),
                fields: n.fields(),
                ttl: n.ttl,
                priority: n.priority,
            });
            Ok(())
        })
    }
}

/// A server with the fake bridge, and an HTTPS client.
async fn setup() -> (TestServer, Http, Arc<Fake>) {
    let fake = Arc::new(Fake::default());
    let server = TestServer::start_with(Options {
        toml: format!("[registration]\nsecret_keys = [\"{}\"]\n", "k".repeat(32)),
        bridges: vec![fake.clone()],
        ..Options::default()
    })
    .await;
    let http = server.http().await;
    (server, http, fake)
}

/// Send a JSON request with an optional bearer secret.
async fn call(
    http: &Http,
    method: &str,
    uri: &str,
    secret: Option<&str>,
    body: Option<Value>,
) -> Resp {
    let auth = secret.map(|s| format!("Bearer {s}"));
    let mut headers = vec![("content-type", "application/json")];
    if let Some(a) = &auth {
        headers.push(("authorization", a));
    }
    let body = body.map(|b| b.to_string()).unwrap_or_default();
    http.request(method, uri, &headers, body.as_bytes()).await
}

/// JSON body of a response.
fn json_of(r: &Resp) -> Value {
    serde_json::from_slice(&r.body).unwrap_or_else(|_| panic!("JSON body: {r:?}"))
}

/// A registered user agent: its URL and secret.
async fn register(server: &TestServer, http: &Http) -> (String, String) {
    let body = json!({ "bridge": "fake", "appID": "app", "token": "device-token-1" });
    let r = call(
        http,
        "POST",
        &server.url("/v1/user-agents"),
        None,
        Some(body),
    )
    .await;
    assert_eq!(r.status, 201, "{r:?}");
    let v = json_of(&r);
    (
        r.location(&server.origin),
        v["secret"].as_str().unwrap().to_owned(),
    )
}

/// Create a subscription, returning its push endpoint.
async fn subscribe(http: &Http, ua: &str, secret: &str, key: Option<&AppServerKey>) -> String {
    let body = key.map(|k| json!({ "key": k.k_b64() }));
    let uri = format!("{ua}/subscriptions/{}", channel_id());
    let r = call(http, "PUT", &uri, Some(secret), body).await;
    assert_eq!(r.status, 201, "{r:?}");
    json_of(&r)["pushEndpoint"].as_str().unwrap().to_owned()
}

/// Registration checks the bridge, the application, and the token.
#[tokio::test(flavor = "multi_thread")]
async fn registration_validates_input() {
    let (server, http, _) = setup().await;
    let uri = server.url("/v1/user-agents");
    for body in [
        json!({ "bridge": "other", "appID": "app", "token": "t0ken" }),
        json!({ "bridge": "fake", "appID": "unknown", "token": "t0ken" }),
        json!({ "bridge": "fake", "appID": "app", "token": "" }),
        json!({ "bridge": "fake", "appID": "app", "token": "../escape" }),
    ] {
        let r = call(&http, "POST", &uri, None, Some(body.clone())).await;
        assert_eq!(r.status, 400, "{body}");
    }
}

/// Every call after registration needs the secret, and a secret works only
/// for its own user agent.
#[tokio::test(flavor = "multi_thread")]
async fn secret_required() {
    let (server, http, _) = setup().await;
    let (ua, secret) = register(&server, &http).await;
    let (other, other_secret) = register(&server, &http).await;
    for s in [None, Some("bm90LWl0"), Some(other_secret.as_str())] {
        let r = call(&http, "GET", &ua, s, None).await;
        assert_eq!(r.status, 401, "{s:?}");
        assert_eq!(r.header("www-authenticate"), Some("Bearer"));
    }
    assert_eq!(
        call(&http, "GET", &ua, Some(&secret), None).await.status,
        200
    );
    assert_eq!(
        call(&http, "GET", &other, Some(&other_secret), None)
            .await
            .status,
        200
    );
}

/// Subscriptions are idempotent by channel and listed on the user agent.
#[tokio::test(flavor = "multi_thread")]
async fn subscriptions_are_idempotent_and_listed() {
    let (server, http, _) = setup().await;
    let (ua, secret) = register(&server, &http).await;
    let ch = channel_id();
    let uri = format!("{ua}/subscriptions/{ch}");
    let first = call(&http, "PUT", &uri, Some(&secret), None).await;
    assert_eq!(first.status, 201);
    let again = call(&http, "PUT", &uri, Some(&secret), None).await;
    assert_eq!(again.status, 200);
    assert_eq!(
        json_of(&first)["pushEndpoint"],
        json_of(&again)["pushEndpoint"]
    );
    let key = AppServerKey::new();
    let conflict = call(
        &http,
        "PUT",
        &uri,
        Some(&secret),
        Some(json!({ "key": key.k_b64() })),
    )
    .await;
    assert_eq!(conflict.status, 409);

    let listed = json_of(&call(&http, "GET", &ua, Some(&secret), None).await);
    assert_eq!(listed["subscriptions"][0]["channelID"], ch);
    assert_eq!(
        listed["subscriptions"][0]["pushEndpoint"],
        json_of(&first)["pushEndpoint"]
    );

    assert_eq!(
        call(&http, "DELETE", &uri, Some(&secret), None)
            .await
            .status,
        204
    );
    assert_eq!(
        call(&http, "DELETE", &uri, Some(&secret), None)
            .await
            .status,
        404
    );
}

/// A push to a bridged subscription goes to the bridge with the reference
/// payload fields, TTL, and priority, and is not stored.
#[tokio::test(flavor = "multi_thread")]
async fn push_goes_to_bridge() {
    let (server, http, fake) = setup().await;
    let (ua, secret) = register(&server, &http).await;
    let push = subscribe(&http, &ua, &secret, None).await;
    let body = opaque_aes128gcm(b"");
    let r = http
        .request(
            "POST",
            &push,
            &[
                ("ttl", "120"),
                ("urgency", "high"),
                ("content-encoding", "aes128gcm"),
                ("prefer", "respond-async"),
            ],
            &body,
        )
        .await;
    assert_eq!(
        r.status, 201,
        "receipts are not offered for bridged subscriptions"
    );
    assert!(r.links(&server.origin, REL_RECEIPT).is_empty());

    let sent = fake.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    let s = &sent[0];
    assert_eq!(
        (s.app_id.as_str(), s.token.as_str()),
        ("app", "device-token-1")
    );
    assert_eq!(s.fields["data"], b64(&body));
    assert_eq!(s.fields["encoding"], "aes128gcm");
    assert_eq!(
        s.fields["version"],
        last_segment(&r.location(&server.origin))
    );
    assert_eq!(
        (s.ttl, s.priority),
        (Duration::from_secs(120), Priority::High)
    );

    let read = http
        .request("GET", &r.location(&server.origin), &[], b"")
        .await;
    assert_eq!(read.status, 404, "bridged messages are not stored");
}

/// A new device token is used for later messages.
#[tokio::test(flavor = "multi_thread")]
async fn token_update_applies() {
    let (server, http, fake) = setup().await;
    let (ua, secret) = register(&server, &http).await;
    let push = subscribe(&http, &ua, &secret, None).await;
    let r = call(
        &http,
        "PUT",
        &ua,
        Some(&secret),
        Some(json!({ "token": "device-token-2" })),
    )
    .await;
    assert_eq!(r.status, 204);
    http.request("POST", &push, &[("ttl", "0")], b"").await;
    assert_eq!(fake.sent.lock().unwrap()[0].token, "device-token-2");
}

/// Bridge failures map to statuses, and a gone token deletes the user agent.
#[tokio::test(flavor = "multi_thread")]
async fn bridge_failures() {
    let (server, http, fake) = setup().await;
    let (ua, secret) = register(&server, &http).await;
    let push = subscribe(&http, &ua, &secret, None).await;
    let cases = [
        (Error::TooLarge, 413, None),
        (
            Error::Throttled {
                retry_after: Some(Duration::from_secs(30)),
            },
            429,
            Some("30"),
        ),
        (Error::Unavailable("down".into()), 502, None),
        (Error::Rejected("bad".to_owned()), 502, None),
    ];
    for (error, status, retry_after) in cases {
        *fake.fail.lock().unwrap() = Some(error);
        let r = http.request("POST", &push, &[("ttl", "60")], b"").await;
        assert_eq!(r.status, status);
        assert_eq!(r.header("retry-after"), retry_after);
    }

    *fake.fail.lock().unwrap() = Some(Error::TokenGone);
    let r = http.request("POST", &push, &[("ttl", "60")], b"").await;
    assert_eq!(r.status, 410);
    assert_eq!(
        call(&http, "GET", &ua, Some(&secret), None).await.status,
        404
    );
    let r = http.request("POST", &push, &[("ttl", "60")], b"").await;
    assert_eq!(r.status, 404, "the subscription went with the user agent");
}

/// VAPID restrictions apply to bridged subscriptions as to any other.
#[tokio::test(flavor = "multi_thread")]
async fn restricted_bridged_subscription() {
    let (server, http, fake) = setup().await;
    let (ua, secret) = register(&server, &http).await;
    let key = AppServerKey::new();
    let push = subscribe(&http, &ua, &secret, Some(&key)).await;
    let r = http.request("POST", &push, &[("ttl", "60")], b"").await;
    assert_eq!(r.status, 401);
    let auth = key.auth(&server.origin, now() + 3600, Some("mailto:ops@example.com"));
    let r = http
        .request(
            "POST",
            &push,
            &[("ttl", "60"), ("authorization", &auth)],
            b"",
        )
        .await;
    assert_eq!(r.status, 201);
    assert_eq!(fake.sent.lock().unwrap().len(), 1);
}

/// Deleting the user agent deletes its subscriptions.
#[tokio::test(flavor = "multi_thread")]
async fn delete_user_agent() {
    let (server, http, _) = setup().await;
    let (ua, secret) = register(&server, &http).await;
    let push = subscribe(&http, &ua, &secret, None).await;
    assert_eq!(
        call(&http, "DELETE", &ua, Some(&secret), None).await.status,
        204
    );
    assert_eq!(
        http.request("POST", &push, &[("ttl", "60")], b"")
            .await
            .status,
        404
    );
}

/// A bridged user agent's id cannot be used to open a WebSocket session.
#[tokio::test(flavor = "multi_thread")]
async fn bridged_uaid_cannot_open_session() {
    let (server, http, _) = setup().await;
    let (ua, _) = register(&server, &http).await;
    let uaid = last_segment(&ua).to_owned();
    let mut session = server.ua().await;
    assert_ne!(session.hello(Some(&uaid)).await, uaid);
}

/// Without bridges the registration API does not exist.
#[tokio::test(flavor = "multi_thread")]
async fn no_registration_without_bridges() {
    let server = TestServer::start().await;
    let http = server.http().await;
    let body = json!({ "bridge": "fake", "appID": "app", "token": "t0ken" });
    let r = call(
        &http,
        "POST",
        &server.url("/v1/user-agents"),
        None,
        Some(body),
    )
    .await;
    assert_eq!(r.status, 404);
}
