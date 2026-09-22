//! End-to-end tests for the FCM bridge against a local fake of the Google
//! token endpoint and the FCM v1 `messages:send` API.
#![allow(clippy::unwrap_used)]

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Form, Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::{KeyPair, RSA_PKCS1_2048_8192_SHA256, RsaKeyPair, UnparsedPublicKey};
use rustls_pki_types::{PrivatePkcs8KeyDer, pem::PemObject};
use serde_json::{Value, json};
use webpush_bridge::{Address, Bridge, Error, Notification, Priority};
use webpush_fcm::{AppConfig, Config, Fcm};

// Throwaway RSA key generated for these tests only; it protects nothing.
const TEST_KEY: &str = include_str!("fixtures/test-rsa-key.pem");
const CLIENT_EMAIL: &str = "bridge@example-project.iam.gserviceaccount.com";

/// What the fake saw, and how it answers the next `messages:send`.
#[derive(Default)]
struct Fake {
    assertions: Vec<String>,
    sends: Vec<(Option<String>, Value)>,
    reply: Option<Reply>,
}

/// Status, headers, and body for a canned `messages:send` response.
type Reply = (StatusCode, Vec<(&'static str, String)>, String);

type Shared = Arc<Mutex<Fake>>;

async fn token(State(fake): State<Shared>, Form(form): Form<HashMap<String, String>>) -> Response {
    assert_eq!(
        form["grant_type"],
        "urn:ietf:params:oauth:grant-type:jwt-bearer"
    );
    let mut fake = fake.lock().unwrap();
    fake.assertions.push(form["assertion"].clone());
    let n = fake.assertions.len();
    Json(json!({"access_token": format!("access-{n}"), "expires_in": 3600, "token_type": "Bearer"}))
        .into_response()
}

async fn send(State(fake): State<Shared>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    let auth = headers
        .get("authorization")
        .map(|v| v.to_str().unwrap().to_owned());
    let mut fake = fake.lock().unwrap();
    fake.sends.push((auth, body));
    match fake.reply.take() {
        None => Json(json!({"name": "projects/example-project/messages/1"})).into_response(),
        Some((status, headers, body)) => {
            let mut resp = (status, body).into_response();
            for (k, v) in headers {
                resp.headers_mut().insert(k, v.parse().unwrap());
            }
            resp
        }
    }
}

struct Harness {
    fcm: Fcm,
    fake: Shared,
    token_uri: String,
}

impl Harness {
    async fn start() -> Self {
        let fake = Shared::default();
        let app = Router::new()
            .route("/token", post(token))
            .route("/v1/projects/example-project/messages:send", post(send))
            .with_state(fake.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let token_uri = format!("{base}/token");
        let creds = write_temp(
            &json!({
                "type": "service_account",
                "project_id": "example-project",
                "private_key_id": "unused",
                "private_key": TEST_KEY,
                "client_email": CLIENT_EMAIL,
                "token_uri": token_uri,
            })
            .to_string(),
        );
        let fcm = Fcm::new(&config(creds.clone(), Some(base))).unwrap();
        std::fs::remove_file(creds).unwrap();
        Self {
            fcm,
            fake,
            token_uri,
        }
    }

    fn reply(&self, status: u16, headers: &[(&'static str, &str)], body: &str) {
        self.fake.lock().unwrap().reply = Some((
            StatusCode::from_u16(status).unwrap(),
            headers.iter().map(|(k, v)| (*k, (*v).to_owned())).collect(),
            body.to_owned(),
        ));
    }

    async fn send(&self, n: &Notification<'_>) -> Result<(), Error> {
        let to = Address {
            app_id: "example-android",
            token: "device-token",
        };
        self.fcm.send(to, n).await
    }

    fn counts(&self) -> (usize, usize) {
        let fake = self.fake.lock().unwrap();
        (fake.assertions.len(), fake.sends.len())
    }
}

fn config(credentials_file: PathBuf, endpoint: Option<String>) -> Config {
    Config {
        apps: HashMap::from([(
            "example-android".to_owned(),
            AppConfig {
                credentials_file: Some(credentials_file),
                project_id: None,
                endpoint,
            },
        )]),
        timeout: Duration::from_secs(5),
    }
}

fn write_temp(contents: &str) -> PathBuf {
    let mut name = [0u8; 8];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut name).unwrap();
    let path = std::env::temp_dir().join(format!("fcm-test-{}.json", URL_SAFE_NO_PAD.encode(name)));
    std::fs::write(&path, contents).unwrap();
    path
}

fn notification(data: Option<&[u8]>, ttl: u64, priority: Priority) -> Notification<'_> {
    Notification {
        channel_id: "5b8a2f0e-7a4c-4b8e-9d5f-2c1e3a4b5c6d",
        version: "AAAAAAAAAAAAAAAAAAAAAA",
        data,
        encoding: data.map(|_| "aes128gcm"),
        ttl: Duration::from_secs(ttl),
        priority,
    }
}

fn error_body(status: &str, message: &str, error_code: &str) -> String {
    json!({"error": {"code": 0, "message": message, "status": status, "details": [{
        "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError",
        "errorCode": error_code,
    }]}})
    .to_string()
}

#[tokio::test]
async fn assertion_is_signed_with_the_service_account_key() {
    let h = Harness::start().await;
    h.send(&notification(None, 60, Priority::Normal))
        .await
        .unwrap();

    let jwt = h.fake.lock().unwrap().assertions[0].clone();
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);

    let der = PrivatePkcs8KeyDer::from_pem_slice(TEST_KEY.as_bytes()).unwrap();
    let key = RsaKeyPair::from_pkcs8(der.secret_pkcs8_der()).unwrap();
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key.public_key().as_ref())
        .verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &URL_SAFE_NO_PAD.decode(parts[2]).unwrap(),
        )
        .unwrap();

    let decode =
        |s: &str| -> Value { serde_json::from_slice(&URL_SAFE_NO_PAD.decode(s).unwrap()).unwrap() };
    assert_eq!(decode(parts[0]), json!({"alg": "RS256", "typ": "JWT"}));
    let claims = decode(parts[1]);
    assert_eq!(claims["iss"], CLIENT_EMAIL);
    assert_eq!(
        claims["scope"],
        "https://www.googleapis.com/auth/firebase.messaging"
    );
    assert_eq!(claims["aud"], h.token_uri.as_str());
    assert_eq!(
        claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
        3600
    );
}

#[tokio::test]
async fn access_token_is_sent_and_cached() {
    let h = Harness::start().await;
    let n = notification(None, 60, Priority::Normal);
    h.send(&n).await.unwrap();
    h.send(&n).await.unwrap();

    assert_eq!(h.counts(), (1, 2));
    let fake = h.fake.lock().unwrap();
    for (auth, _) in &fake.sends {
        assert_eq!(auth.as_deref(), Some("Bearer access-1"));
    }
}

#[tokio::test]
async fn body_carries_fields_ttl_and_priority() {
    let h = Harness::start().await;
    h.send(&notification(Some(b"\x01\x02"), 3600, Priority::High))
        .await
        .unwrap();

    let body = h.fake.lock().unwrap().sends[0].1.clone();
    assert_eq!(
        body,
        json!({"message": {
            "token": "device-token",
            "data": {
                "channelID": "5b8a2f0e-7a4c-4b8e-9d5f-2c1e3a4b5c6d",
                "version": "AAAAAAAAAAAAAAAAAAAAAA",
                "data": "AQI",
                "encoding": "aes128gcm",
            },
            "android": {"ttl": "3600s", "priority": "HIGH"},
        }})
    );
}

#[tokio::test]
async fn ttl_is_clamped_to_28_days() {
    let h = Harness::start().await;
    h.send(&notification(None, 90 * 86_400, Priority::Normal))
        .await
        .unwrap();

    let body = h.fake.lock().unwrap().sends[0].1.clone();
    assert_eq!(body["message"]["android"]["ttl"], "2419200s");
    assert_eq!(body["message"]["android"]["priority"], "NORMAL");
}

#[tokio::test]
async fn not_found_and_unregistered_mean_token_gone() {
    let h = Harness::start().await;
    let n = notification(None, 60, Priority::Normal);

    h.reply(
        404,
        &[],
        &error_body(
            "NOT_FOUND",
            "Requested entity was not found.",
            "UNREGISTERED",
        ),
    );
    assert!(matches!(h.send(&n).await, Err(Error::TokenGone)));

    // UNREGISTERED decides even when the status is not 404.
    h.reply(
        400,
        &[],
        &error_body("INVALID_ARGUMENT", "gone", "UNREGISTERED"),
    );
    assert!(matches!(h.send(&n).await, Err(Error::TokenGone)));

    h.reply(
        400,
        &[],
        &error_body(
            "INVALID_ARGUMENT",
            "The registration token is not a valid FCM registration token",
            "INVALID_ARGUMENT",
        ),
    );
    assert!(matches!(h.send(&n).await, Err(Error::TokenGone)));

    h.reply(
        403,
        &[],
        &error_body(
            "PERMISSION_DENIED",
            "SenderId mismatch",
            "SENDER_ID_MISMATCH",
        ),
    );
    assert!(matches!(h.send(&n).await, Err(Error::TokenGone)));
}

#[tokio::test]
async fn too_many_requests_is_throttled_with_retry_after() {
    let h = Harness::start().await;
    h.reply(
        429,
        &[("retry-after", "30")],
        &error_body("RESOURCE_EXHAUSTED", "quota", "QUOTA_EXCEEDED"),
    );
    let err = h.send(&notification(None, 60, Priority::Normal)).await;
    assert!(matches!(
        err,
        Err(Error::Throttled { retry_after: Some(d) }) if d == Duration::from_secs(30)
    ));
}

#[tokio::test]
async fn other_bad_request_is_rejected_with_message() {
    let h = Harness::start().await;
    h.reply(
        400,
        &[],
        &error_body(
            "INVALID_ARGUMENT",
            "Invalid value at 'message.android.ttl'",
            "INVALID_ARGUMENT",
        ),
    );
    match h.send(&notification(None, 60, Priority::Normal)).await {
        Err(Error::Rejected(msg)) => assert_eq!(msg, "Invalid value at 'message.android.ttl'"),
        other => panic!("expected Rejected, got {other:?}"),
    }
}

#[tokio::test]
async fn server_error_and_unparsable_body_are_unavailable() {
    let h = Harness::start().await;
    h.reply(500, &[], "<html>upstream error</html>");
    assert!(matches!(
        h.send(&notification(None, 60, Priority::Normal)).await,
        Err(Error::Unavailable(_))
    ));
}

#[tokio::test]
async fn unauthorized_is_unavailable_and_drops_the_token() {
    let h = Harness::start().await;
    let n = notification(None, 60, Priority::Normal);
    h.reply(
        401,
        &[],
        &error_body(
            "UNAUTHENTICATED",
            "Request had invalid authentication credentials.",
            "THIRD_PARTY_AUTH_ERROR",
        ),
    );
    assert!(matches!(h.send(&n).await, Err(Error::Unavailable(_))));

    h.send(&n).await.unwrap();
    assert_eq!(h.counts(), (2, 2));
    let fake = h.fake.lock().unwrap();
    assert_eq!(fake.sends[1].0.as_deref(), Some("Bearer access-2"));
}

#[tokio::test]
async fn oversized_data_is_too_large_without_a_request() {
    let h = Harness::start().await;
    // 3 KiB of body is 4 KiB once base64url encoded, over the limit with the other fields.
    let big = vec![0u8; 3072];
    assert!(matches!(
        h.send(&notification(Some(&big), 60, Priority::Normal))
            .await,
        Err(Error::TooLarge)
    ));
    assert_eq!(h.counts(), (0, 0));
}

#[tokio::test]
async fn unknown_app_is_rejected() {
    let h = Harness::start().await;
    assert!(h.fcm.has_app("example-android"));
    assert!(!h.fcm.has_app("other"));
    let to = Address {
        app_id: "other",
        token: "device-token",
    };
    let n = notification(None, 60, Priority::Normal);
    assert!(matches!(h.fcm.send(to, &n).await, Err(Error::UnknownApp)));
    assert_eq!(h.counts(), (0, 0));
}

#[test]
fn new_fails_on_missing_or_malformed_credentials() {
    let missing = std::env::temp_dir().join("fcm-test-does-not-exist.json");
    assert!(Fcm::new(&config(missing, None)).is_err());

    let not_json = write_temp("not json");
    assert!(Fcm::new(&config(not_json.clone(), None)).is_err());
    std::fs::remove_file(not_json).unwrap();

    let bad_key = write_temp(
        &json!({
            "project_id": "p",
            "client_email": "e",
            "private_key": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            "token_uri": "http://127.0.0.1/token",
        })
        .to_string(),
    );
    assert!(Fcm::new(&config(bad_key.clone(), None)).is_err());
    std::fs::remove_file(bad_key).unwrap();
}
