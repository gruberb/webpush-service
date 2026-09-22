//! Tests the APNs bridge against a fake APNs provider API served over
//! HTTP/2 with prior knowledge on a loopback port.
#![allow(clippy::unwrap_used)]

use std::{
    collections::{HashMap, VecDeque},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, Version},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{
    SecretKey,
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
    elliptic_curve::rand_core::OsRng,
    pkcs8::{EncodePrivateKey, LineEnding},
};
use serde_json::{Value, json};
use webpush_apns::{Apns, AppConfig, Config, Environment, PushType};
use webpush_bridge::{Address, Bridge, Error, Notification, Priority};

const TOKEN: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

struct Captured {
    version: Version,
    path: String,
    headers: HeaderMap,
    body: Value,
}

#[derive(Default)]
struct Fake {
    requests: Mutex<Vec<Captured>>,
    /// Responses to return in order; 200 once exhausted.
    responses: Mutex<VecDeque<Response>>,
}

impl Fake {
    fn respond(&self, status: u16, body: &str) {
        let resp = (StatusCode::from_u16(status).unwrap(), body.to_owned()).into_response();
        self.responses.lock().unwrap().push_back(resp);
    }

    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    fn take(&self) -> Vec<Captured> {
        std::mem::take(&mut self.requests.lock().unwrap())
    }
}

async fn handle(State(fake): State<Arc<Fake>>, req: Request) -> Response {
    let version = req.version();
    let path = req.uri().path().to_owned();
    let headers = req.headers().clone();
    let body = to_bytes(req.into_body(), usize::MAX).await.unwrap();
    fake.requests.lock().unwrap().push(Captured {
        version,
        path,
        headers,
        body: serde_json::from_slice(&body).unwrap(),
    });
    let next = fake.responses.lock().unwrap().pop_front();
    next.unwrap_or_else(|| StatusCode::OK.into_response())
}

fn key_file(key: &SecretKey) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "webpush-apns-{}-{}.p8",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, key.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes()).unwrap();
    path
}

fn app(key_file: PathBuf, endpoint: Option<String>) -> AppConfig {
    AppConfig {
        key_file,
        key_id: "ABC123DEFG".into(),
        team_id: "DEF123GHIJ".into(),
        topic: "com.example.app".into(),
        environment: Environment::Production,
        endpoint,
        push_type: PushType::Background,
        aps: None,
    }
}

struct Setup {
    apns: Apns,
    fake: Arc<Fake>,
    key: SecretKey,
}

async fn setup(push_type: PushType, aps: Option<Value>) -> Setup {
    let fake = Arc::new(Fake::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let router = Router::new()
        .route("/3/device/{token}", post(handle))
        .with_state(fake.clone());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let key = SecretKey::random(&mut OsRng);
    let mut cfg = app(key_file(&key), Some(format!("http://127.0.0.1:{port}")));
    cfg.push_type = push_type;
    cfg.aps = aps;
    let bridge = Apns::new(&Config {
        apps: HashMap::from([("example-ios".to_owned(), cfg)]),
        timeout: Duration::from_secs(5),
    })
    .unwrap();
    Setup {
        apns: bridge,
        fake,
        key,
    }
}

fn notification(priority: Priority, ttl: u64) -> Notification<'static> {
    Notification {
        channel_id: "5b8a2f0e-7a4c-4b8e-9d5f-2c1e3a4b5c6d",
        version: "AAAAAAAAAAAAAAAAAAAAAA",
        data: Some(b"\x01\x02\x03"),
        encoding: Some("aes128gcm"),
        ttl: Duration::from_secs(ttl),
        priority,
    }
}

async fn send(apns: &Apns, n: &Notification<'_>) -> Result<(), Error> {
    let to = Address {
        app_id: "example-ios",
        token: TOKEN,
    };
    apns.send(to, n).await
}

fn header<'a>(c: &'a Captured, name: &str) -> &'a str {
    c.headers[name].to_str().unwrap()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

type Check = fn(&Error) -> bool;

/// Verify the provider token and return its header and claims.
fn verify_jwt(c: &Captured, key: &SecretKey) -> (Value, Value) {
    let jwt = header(c, "authorization").strip_prefix("bearer ").unwrap();
    let (input, sig) = jwt.rsplit_once('.').unwrap();
    let sig = Signature::from_slice(&URL_SAFE_NO_PAD.decode(sig).unwrap()).unwrap();
    VerifyingKey::from(key.public_key())
        .verify(input.as_bytes(), &sig)
        .unwrap();
    let (h, claims) = input.split_once('.').unwrap();
    let decode = |s: &str| serde_json::from_slice(&URL_SAFE_NO_PAD.decode(s).unwrap()).unwrap();
    (decode(h), decode(claims))
}

#[tokio::test]
async fn background_request() {
    let s = setup(PushType::Background, None).await;
    let before = now();
    send(&s.apns, &notification(Priority::High, 60))
        .await
        .unwrap();

    let reqs = s.fake.take();
    let c = &reqs[0];
    assert_eq!(c.version, Version::HTTP_2);
    assert_eq!(c.path, format!("/3/device/{TOKEN}"));
    assert_eq!(header(c, "apns-topic"), "com.example.app");
    assert_eq!(header(c, "apns-push-type"), "background");
    assert_eq!(header(c, "apns-priority"), "5", "background is always 5");
    let exp: u64 = header(c, "apns-expiration").parse().unwrap();
    assert!((before + 60..=now() + 60).contains(&exp));
    assert_eq!(
        c.body,
        json!({
            "aps": {"content-available": 1},
            "channelID": "5b8a2f0e-7a4c-4b8e-9d5f-2c1e3a4b5c6d",
            "version": "AAAAAAAAAAAAAAAAAAAAAA",
            "data": "AQID",
            "encoding": "aes128gcm",
        })
    );

    let (h, claims) = verify_jwt(c, &s.key);
    assert_eq!(h, json!({"alg": "ES256", "kid": "ABC123DEFG"}));
    assert_eq!(claims["iss"], "DEF123GHIJ");
    let iat = claims["iat"].as_u64().unwrap();
    assert!((before..=now()).contains(&iat));
}

#[tokio::test]
async fn alert_request() {
    let aps = json!({"alert": {"title": "New message"}, "mutable-content": 1});
    let s = setup(PushType::Alert, Some(aps.clone())).await;
    send(&s.apns, &notification(Priority::High, 0))
        .await
        .unwrap();
    send(&s.apns, &notification(Priority::Normal, 0))
        .await
        .unwrap();

    let reqs = s.fake.take();
    assert_eq!(header(&reqs[0], "apns-push-type"), "alert");
    assert_eq!(header(&reqs[0], "apns-priority"), "10");
    assert_eq!(header(&reqs[1], "apns-priority"), "5");
    assert_eq!(
        header(&reqs[0], "apns-expiration"),
        "0",
        "ttl 0 means do not store"
    );
    assert_eq!(reqs[0].body["aps"], aps);
}

#[tokio::test]
async fn jwt_is_cached() {
    let s = setup(PushType::Background, None).await;
    let n = notification(Priority::Normal, 60);
    send(&s.apns, &n).await.unwrap();
    send(&s.apns, &n).await.unwrap();
    let reqs = s.fake.take();
    assert_eq!(
        header(&reqs[0], "authorization"),
        header(&reqs[1], "authorization")
    );
}

#[tokio::test]
async fn expired_provider_token_signs_a_new_one() {
    let s = setup(PushType::Background, None).await;
    let n = notification(Priority::Normal, 60);
    s.fake.respond(403, r#"{"reason":"ExpiredProviderToken"}"#);
    assert!(matches!(
        send(&s.apns, &n).await,
        Err(Error::Unavailable(_))
    ));
    // ES256 signatures are randomized, so a re-signed token differs even
    // within the same second.
    send(&s.apns, &n).await.unwrap();
    let reqs = s.fake.take();
    assert_ne!(
        header(&reqs[0], "authorization"),
        header(&reqs[1], "authorization")
    );
    verify_jwt(&reqs[1], &s.key);
}

#[tokio::test]
async fn error_mapping() {
    let s = setup(PushType::Background, None).await;
    let n = notification(Priority::Normal, 60);
    let cases: [(u16, &str, Check); 7] = [
        (410, r#"{"reason":"Unregistered"}"#, |e| {
            matches!(e, Error::TokenGone)
        }),
        (400, r#"{"reason":"BadDeviceToken"}"#, |e| {
            matches!(e, Error::TokenGone)
        }),
        (400, r#"{"reason":"DeviceTokenNotForTopic"}"#, |e| {
            matches!(e, Error::TokenGone)
        }),
        (
            400,
            r#"{"reason":"BadExpirationDate"}"#,
            |e| matches!(e, Error::Rejected(r) if r == "BadExpirationDate"),
        ),
        (413, r#"{"reason":"PayloadTooLarge"}"#, |e| {
            matches!(e, Error::TooLarge)
        }),
        (500, "not json", |e| matches!(e, Error::Unavailable(_))),
        (403, r#"{"reason":"BadCertificate"}"#, |e| {
            matches!(e, Error::Unavailable(_))
        }),
    ];
    for (status, body, check) in cases {
        s.fake.respond(status, body);
        let err = send(&s.apns, &n).await.unwrap_err();
        assert!(check(&err), "{status} {body}: {err:?}");
    }
}

#[tokio::test]
async fn throttled_with_retry_after() {
    let s = setup(PushType::Background, None).await;
    let resp = (
        StatusCode::TOO_MANY_REQUESTS,
        [("retry-after", "30")],
        r#"{"reason":"TooManyRequests"}"#,
    )
        .into_response();
    s.fake.responses.lock().unwrap().push_back(resp);
    s.fake.respond(429, "");
    let n = notification(Priority::Normal, 60);
    assert!(matches!(
        send(&s.apns, &n).await,
        Err(Error::Throttled { retry_after: Some(d) }) if d == Duration::from_secs(30)
    ));
    assert!(matches!(
        send(&s.apns, &n).await,
        Err(Error::Throttled { retry_after: None })
    ));
}

#[tokio::test]
async fn too_large_without_request() {
    let s = setup(PushType::Background, None).await;
    let data = vec![0u8; 4096];
    let n = Notification {
        data: Some(&data),
        ..notification(Priority::Normal, 60)
    };
    assert!(matches!(send(&s.apns, &n).await, Err(Error::TooLarge)));
    assert_eq!(s.fake.count(), 0);
}

#[tokio::test]
async fn unknown_app() {
    let s = setup(PushType::Background, None).await;
    let n = notification(Priority::Normal, 60);
    let to = Address {
        app_id: "other",
        token: TOKEN,
    };
    assert!(matches!(s.apns.send(to, &n).await, Err(Error::UnknownApp)));
    assert!(s.apns.has_app("example-ios"));
    assert!(!s.apns.has_app("other"));
    assert_eq!(s.apns.name(), "apns");
}

#[tokio::test]
async fn token_outside_hex_is_gone_without_request() {
    let s = setup(PushType::Background, None).await;
    let n = notification(Priority::Normal, 60);
    let to = Address {
        app_id: "example-ios",
        token: "../../other?x=1",
    };
    assert!(matches!(s.apns.send(to, &n).await, Err(Error::TokenGone)));
    assert_eq!(s.fake.count(), 0);
}

#[test]
fn new_rejects_alert_without_aps() {
    let mut cfg = app(key_file(&SecretKey::random(&mut OsRng)), None);
    cfg.push_type = PushType::Alert;
    let err = Apns::new(&Config {
        apps: HashMap::from([("a".to_owned(), cfg)]),
        timeout: Duration::from_secs(1),
    })
    .err()
    .unwrap();
    assert!(err.to_string().contains("aps"), "{err}");
}

#[test]
fn new_rejects_missing_key_file() {
    let cfg = app("/nonexistent/apns.p8".into(), None);
    assert!(
        Apns::new(&Config {
            apps: HashMap::from([("a".to_owned(), cfg)]),
            timeout: Duration::from_secs(1),
        })
        .is_err()
    );
}
