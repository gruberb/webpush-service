//! A [`Bridge`] to Firebase Cloud Messaging (FCM) through the HTTP v1 API.
//!
//! Each configured application maps the app id user agents register with to
//! a Google service account. Messages go out as FCM data messages, so the
//! application receives them even in the background and decides itself
//! whether to show anything.
//!
//! # Authentication
//!
//! FCM v1 takes an OAuth 2.0 access token. The bridge signs a JWT with the
//! service account's RSA key (RS256, scope
//! `https://www.googleapis.com/auth/firebase.messaging`, audience
//! `token_uri`), exchanges it at `token_uri` using the `jwt-bearer` grant,
//! and caches the resulting token per application until less than a minute
//! of its lifetime remains. Concurrent sends wait for a single refresh
//! instead of each requesting a token.
//!
//! # Payload
//!
//! ```json
//! {"message": {
//!   "token": "<device token>",
//!   "data": {"channelID": "...", "version": "...", "data": "...", "encoding": "aes128gcm"},
//!   "android": {"ttl": "3600s", "priority": "NORMAL"}
//! }}
//! ```
//!
//! `data` is [`Notification::fields`] unchanged. FCM limits it to 4096 bytes
//! of keys and values; larger messages fail with [`Error::TooLarge`] before
//! any request is made. The TTL is capped at FCM's maximum of 28 days.
//!
//! # Error mapping
//!
//! | FCM response                                             | [`Error`]        |
//! |----------------------------------------------------------|------------------|
//! | 404, `UNREGISTERED`, `SENDER_ID_MISMATCH`                | `TokenGone`      |
//! | 400 `INVALID_ARGUMENT` naming the registration token     | `TokenGone`      |
//! | other 400                                                | `Rejected`       |
//! | 429                                                      | `Throttled`      |
//! | 401, 403, 5xx, network or token endpoint failure         | `Unavailable`    |
//!
//! A 401 also discards the cached access token, so the next send fetches a
//! new one.
//!
//! # Configuration
//!
//! ```toml
//! [bridges.fcm.apps.example-android]
//! credentials_file = "/etc/webpush/fcm-example.json"
//! ```
//!
//! `endpoint` overrides the FCM base URL (default
//! `https://fcm.googleapis.com`) and `timeout` the per-request timeout
//! (default `10s`).

use std::{
    collections::HashMap,
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{StatusCode, header};
use ring::{
    rand::SystemRandom,
    signature::{RSA_PKCS1_SHA256, RsaKeyPair},
};
use rustls_pki_types::{PrivatePkcs8KeyDer, pem::PemObject};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex;
use webpush_bridge::{Address, BoxError, BoxFuture, Bridge, Error, Notification, Priority};

const DEFAULT_ENDPOINT: &str = "https://fcm.googleapis.com";
const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const MAX_DATA_BYTES: usize = 4096;
/// 28 days, the longest TTL FCM accepts.
const MAX_TTL_SECS: u64 = 2_419_200;
/// Lifetime requested for the signed assertion; Google caps it at one hour.
const ASSERTION_LIFETIME_SECS: u64 = 3600;
/// Refresh this long before expiry so a token never lapses mid-request.
const REFRESH_MARGIN: Duration = Duration::from_secs(60);

/// Bridge configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Applications by the app id user agents register with.
    #[serde(default)]
    pub apps: HashMap<String, AppConfig>,
    /// Timeout for each HTTP request, token requests included.
    #[serde(default = "default_timeout", with = "humantime_serde")]
    pub timeout: Duration,
}

fn default_timeout() -> Duration {
    Duration::from_secs(10)
}

/// One FCM application.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    /// Path to the Google service account JSON key.
    pub credentials_file: PathBuf,
    /// FCM base URL, `https://fcm.googleapis.com` if unset.
    #[serde(default)]
    pub endpoint: Option<String>,
}

/// The fields of a service account key the bridge needs.
#[derive(Deserialize)]
struct ServiceAccount {
    project_id: String,
    client_email: String,
    private_key: String,
    token_uri: String,
}

struct App {
    client_email: String,
    token_uri: String,
    key: RsaKeyPair,
    send_url: String,
    token: Mutex<Option<AccessToken>>,
}

struct AccessToken {
    value: String,
    expires_at: Instant,
}

/// The FCM bridge. Holds credentials, cached access tokens, and an HTTP
/// client; share one instance between requests.
pub struct Fcm {
    apps: HashMap<String, App>,
    http: reqwest::Client,
    rng: SystemRandom,
}

impl Fcm {
    /// Load every configured application's credentials.
    ///
    /// # Errors
    ///
    /// A credentials file cannot be read, is not a service account key, or
    /// holds a private key that is not PKCS#8 RSA; or the HTTP client
    /// cannot be built. Checking at startup keeps a bad deployment from
    /// surfacing only on the first message.
    pub fn new(cfg: &Config) -> Result<Self, BoxError> {
        let apps = cfg
            .apps
            .iter()
            .map(|(id, app)| {
                load_app(app)
                    .map(|a| (id.clone(), a))
                    .map_err(|e| format!("fcm app {id} ({}): {e}", app.credentials_file.display()))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            apps,
            http: webpush_bridge::http_client(cfg.timeout)?,
            rng: SystemRandom::new(),
        })
    }

    /// A valid access token for `app`, fetching one if the cache is empty or
    /// about to expire. Holding the lock across the fetch makes concurrent
    /// callers share one refresh.
    async fn access_token(&self, app: &App) -> Result<String, Error> {
        let mut cached = app.token.lock().await;
        if let Some(t) = cached.as_ref()
            && t.expires_at.saturating_duration_since(Instant::now()) > REFRESH_MARGIN
        {
            return Ok(t.value.clone());
        }
        let fresh = self.fetch_token(app).await.map_err(Error::Unavailable)?;
        let value = fresh.value.clone();
        *cached = Some(fresh);
        Ok(value)
    }

    async fn fetch_token(&self, app: &App) -> Result<AccessToken, BoxError> {
        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            expires_in: u64,
        }

        let assertion = self.assertion(app)?;
        let requested = Instant::now();
        let resp = self
            .http
            .post(&app.token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &assertion),
            ])
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            // The body may echo the assertion; keep it out of errors and logs.
            return Err(format!("token endpoint returned {status}").into());
        }
        let token: TokenResponse = resp.json().await?;
        Ok(AccessToken {
            value: token.access_token,
            // Measured from before the request, so network delay only makes
            // the cached lifetime shorter, never longer.
            expires_at: requested + Duration::from_secs(token.expires_in),
        })
    }

    /// The signed JWT the token endpoint exchanges for an access token.
    fn assertion(&self, app: &App) -> Result<String, BoxError> {
        let iat = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({
            "iss": app.client_email,
            "scope": SCOPE,
            "aud": app.token_uri,
            "iat": iat,
            "exp": iat + ASSERTION_LIFETIME_SECS,
        }))?);
        let signing_input = format!("{header}.{claims}");
        let mut sig = vec![0; app.key.public().modulus_len()];
        app.key
            .sign(
                &RSA_PKCS1_SHA256,
                &self.rng,
                signing_input.as_bytes(),
                &mut sig,
            )
            .map_err(|_| "RSA signing failed")?;
        Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig)))
    }

    async fn deliver(&self, to: Address<'_>, n: &Notification<'_>) -> Result<(), Error> {
        let app = self.apps.get(to.app_id).ok_or(Error::UnknownApp)?;
        let data = n.fields();
        if data.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>() > MAX_DATA_BYTES {
            return Err(Error::TooLarge);
        }
        let body = json!({"message": {
            "token": to.token,
            "data": data,
            "android": {
                "ttl": format!("{}s", n.ttl.as_secs().min(MAX_TTL_SECS)),
                "priority": match n.priority {
                    Priority::Normal => "NORMAL",
                    Priority::High => "HIGH",
                },
            },
        }});

        let token = self.access_token(app).await?;
        let resp = self
            .http
            .post(&app.send_url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Unavailable(e.into()))?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        if status == StatusCode::UNAUTHORIZED {
            // The token was revoked or the clock drifted; start over next time.
            *app.token.lock().await = None;
        }
        let retry_after = resp
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok()?.trim().parse().ok())
            .map(Duration::from_secs);
        let body = resp.bytes().await.unwrap_or_default();
        let err = classify(status, retry_after, &body);
        tracing::debug!(app = to.app_id, %status, kind = err.kind(), "fcm send failed");
        Err(err)
    }
}

impl Bridge for Fcm {
    fn name(&self) -> &'static str {
        "fcm"
    }

    fn has_app(&self, app_id: &str) -> bool {
        self.apps.contains_key(app_id)
    }

    fn send<'a>(
        &'a self,
        to: Address<'a>,
        notification: &'a Notification<'a>,
    ) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(self.deliver(to, notification))
    }
}

fn load_app(cfg: &AppConfig) -> Result<App, BoxError> {
    let sa: ServiceAccount = serde_json::from_slice(&std::fs::read(&cfg.credentials_file)?)?;
    let der = PrivatePkcs8KeyDer::from_pem_slice(sa.private_key.as_bytes())?;
    let key = RsaKeyPair::from_pkcs8(der.secret_pkcs8_der())
        .map_err(|e| format!("private_key is not a usable RSA key: {e}"))?;
    let endpoint = cfg.endpoint.as_deref().unwrap_or(DEFAULT_ENDPOINT);
    Ok(App {
        client_email: sa.client_email,
        token_uri: sa.token_uri,
        key,
        send_url: format!(
            "{}/v1/projects/{}/messages:send",
            endpoint.trim_end_matches('/'),
            sa.project_id
        ),
        token: Mutex::new(None),
    })
}

/// Map a non-2xx FCM response to a bridge error.
fn classify(status: StatusCode, retry_after: Option<Duration>, body: &[u8]) -> Error {
    #[derive(Deserialize, Default)]
    struct Body {
        #[serde(default)]
        error: Status,
    }
    #[derive(Deserialize, Default)]
    struct Status {
        #[serde(default)]
        message: String,
        #[serde(default)]
        details: Vec<Detail>,
    }
    #[derive(Deserialize)]
    struct Detail {
        #[serde(rename = "errorCode")]
        error_code: Option<String>,
    }

    // Proxies and load balancers answer with HTML or nothing; fall back to
    // the status code alone.
    let Status { message, details } = serde_json::from_slice::<Body>(body)
        .unwrap_or_default()
        .error;
    let code = details.into_iter().find_map(|d| d.error_code);
    let code = code.as_deref();

    if status == StatusCode::NOT_FOUND
        || matches!(code, Some("UNREGISTERED" | "SENDER_ID_MISMATCH"))
    {
        return Error::TokenGone;
    }
    if status == StatusCode::TOO_MANY_REQUESTS {
        return Error::Throttled { retry_after };
    }
    if status == StatusCode::BAD_REQUEST {
        // FCM reports a malformed token as a generic INVALID_ARGUMENT; the
        // message is the only thing that tells it apart from a bad field.
        if code == Some("INVALID_ARGUMENT")
            && message.to_ascii_lowercase().contains("registration token")
        {
            return Error::TokenGone;
        }
        return Error::Rejected(if message.is_empty() {
            status.to_string()
        } else {
            message
        });
    }
    Error::Unavailable(format!("FCM returned {status}: {message}").into())
}
