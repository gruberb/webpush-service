//! Token sources against a fake token endpoint and metadata server: each
//! credential kind's request, caching, and refusal handling.
#![allow(clippy::unwrap_used)]

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    Form, Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::{KeyPair, RSA_PKCS1_2048_8192_SHA256, RsaKeyPair, UnparsedPublicKey};
use rustls_pki_types::{PrivatePkcs8KeyDer, pem::PemObject};
use serde_json::{Value, json};
use webpush_gcp_auth::{CLOUD_PLATFORM, TokenSource};

/// An HTTP client with the crate's TLS setup.
fn client() -> reqwest::Client {
    webpush_gcp_auth::http_client(std::time::Duration::from_secs(5)).unwrap()
}

/// A throwaway 2048-bit key used only by these tests.
const KEY: &str = include_str!("fixtures/test-rsa-key.pem");

/// What the fake servers saw.
#[derive(Default)]
struct Seen {
    /// Token requests.
    requests: AtomicUsize,
    /// The last form body posted to `/token`.
    form: Mutex<HashMap<String, String>>,
    /// The last metadata request's scopes and flavor header.
    metadata: Mutex<Option<(String, Option<String>)>>,
    /// Answer 401 when set.
    refuse: Mutex<bool>,
}

/// Start the fake servers; returns their base URL.
async fn fake() -> (String, Arc<Seen>) {
    async fn token(
        State(seen): State<Arc<Seen>>,
        Form(form): Form<HashMap<String, String>>,
    ) -> Result<Json<Value>, StatusCode> {
        let n = seen.requests.fetch_add(1, Ordering::SeqCst);
        *seen.form.lock().unwrap() = form;
        if *seen.refuse.lock().unwrap() {
            return Err(StatusCode::UNAUTHORIZED);
        }
        Ok(Json(
            json!({ "access_token": format!("token-{n}"), "expires_in": 3600 }),
        ))
    }
    async fn metadata(
        State(seen): State<Arc<Seen>>,
        Query(q): Query<HashMap<String, String>>,
        headers: HeaderMap,
    ) -> Json<Value> {
        let n = seen.requests.fetch_add(1, Ordering::SeqCst);
        let flavor = headers
            .get("metadata-flavor")
            .map(|v| v.to_str().unwrap().to_owned());
        *seen.metadata.lock().unwrap() = Some((q["scopes"].clone(), flavor));
        Json(json!({ "access_token": format!("meta-{n}"), "expires_in": 3600 }))
    }
    let seen = Arc::new(Seen::default());
    let app = Router::new()
        .route("/token", post(token))
        .route(
            "/computeMetadata/v1/instance/service-accounts/default/token",
            get(metadata),
        )
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), seen)
}

fn service_account(token_uri: &str) -> String {
    json!({
        "type": "service_account",
        "project_id": "test-project",
        "client_email": "bridge@test-project.iam.gserviceaccount.com",
        "private_key": KEY,
        "token_uri": token_uri,
    })
    .to_string()
}

/// A service account signs an RS256 assertion with the requested scopes and
/// gets a token, which is cached.
#[tokio::test]
async fn service_account_assertion_and_cache() {
    let (base, seen) = fake().await;
    let uri = format!("{base}/token");
    let source = TokenSource::from_json(
        &service_account(&uri),
        &[CLOUD_PLATFORM, "https://example/scope"],
        client(),
    )
    .unwrap();
    assert_eq!(source.project_id(), Some("test-project"));
    assert_eq!(source.quota_project(), None);
    assert_eq!(source.token().await.unwrap(), "token-0");
    assert_eq!(source.token().await.unwrap(), "token-0", "cached");
    assert_eq!(seen.requests.load(Ordering::SeqCst), 1);

    let form = seen.form.lock().unwrap().clone();
    assert_eq!(
        form["grant_type"],
        "urn:ietf:params:oauth:grant-type:jwt-bearer"
    );
    let parts: Vec<&str> = form["assertion"].split('.').collect();
    let der = PrivatePkcs8KeyDer::from_pem_slice(KEY.as_bytes()).unwrap();
    let key = RsaKeyPair::from_pkcs8(der.secret_pkcs8_der()).unwrap();
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key.public_key().as_ref())
        .verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &URL_SAFE_NO_PAD.decode(parts[2]).unwrap(),
        )
        .expect("assertion verifies");
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(claims["iss"], "bridge@test-project.iam.gserviceaccount.com");
    assert_eq!(claims["aud"], uri);
    assert_eq!(
        claims["scope"],
        format!("{CLOUD_PLATFORM} https://example/scope")
    );
    assert_eq!(
        claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
        3600
    );

    source.invalidate().await;
    assert_eq!(
        source.token().await.unwrap(),
        "token-1",
        "refetched after invalidate"
    );
}

/// The metadata server is asked with its flavor header and comma-separated
/// scopes.
#[tokio::test]
async fn metadata_server() {
    let (base, seen) = fake().await;
    let source = TokenSource::metadata(&base, &["a", "b"], client());
    assert_eq!(source.project_id(), None);
    assert_eq!(source.token().await.unwrap(), "meta-0");
    let (scopes, flavor) = seen.metadata.lock().unwrap().clone().unwrap();
    assert_eq!(scopes, "a,b");
    assert_eq!(flavor.as_deref(), Some("Google"));
}

/// User credentials parse and report their quota project.
#[test]
fn authorized_user_credentials() {
    let json = json!({
        "type": "authorized_user",
        "client_id": "id",
        "client_secret": "secret",
        "refresh_token": "refresh",
        "quota_project_id": "billing-project",
    })
    .to_string();
    let source = TokenSource::from_json(&json, &[CLOUD_PLATFORM], client()).unwrap();
    assert_eq!(source.quota_project(), Some("billing-project"));
    assert_eq!(source.project_id(), Some("billing-project"));
}

/// A refused token request is an error that names only the status.
#[tokio::test]
async fn refusal_is_an_error() {
    let (base, seen) = fake().await;
    *seen.refuse.lock().unwrap() = true;
    let source = TokenSource::from_json(
        &service_account(&format!("{base}/token")),
        &[CLOUD_PLATFORM],
        client(),
    )
    .unwrap();
    let err = source.token().await.unwrap_err().to_string();
    assert_eq!(err, "token request returned 401 Unauthorized");
}

/// Unusable credentials fail when loaded.
#[test]
fn bad_credentials_rejected() {
    for json in [
        json!({ "type": "external_account" }).to_string(),
        json!({ "type": "service_account", "client_email": "x" }).to_string(),
        json!({ "type": "service_account", "client_email": "x", "private_key": "nope" })
            .to_string(),
        "not json".to_owned(),
    ] {
        assert!(
            TokenSource::from_json(&json, &[CLOUD_PLATFORM], client()).is_err(),
            "{json}"
        );
    }
}
