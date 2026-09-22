//! A [`Bridge`] to the Apple Push Notification service (APNs).
//!
//! Messages go to the APNs HTTP/2 provider API as
//! `POST /3/device/{token}`, one request per message. Each configured
//! application has its own signing key, team, and bundle id, so one push
//! service can serve any number of Apple applications.
//!
//! # Authentication
//!
//! Requests carry a provider token: an ES256 JWT with header
//! `{"alg":"ES256","kid":key_id}` and claims `{"iss":team_id,"iat":now}`,
//! signed with the `.p8` key Apple issues for the team. Apple rejects tokens
//! older than an hour and throttles providers that mint new ones more often
//! than every 20 minutes, so each application reuses its token for 40
//! minutes. A 403 with `ExpiredProviderToken` or `InvalidProviderToken`
//! discards the cached token so the next send signs a fresh one.
//!
//! # Background and alert pushes
//!
//! | `push_type`  | `apns-push-type` | `apns-priority`                         | `aps`                     |
//! |--------------|------------------|-----------------------------------------|---------------------------|
//! | `background` | `background`     | always 5; Apple rejects 10              | `{"content-available": 1}`|
//! | `alert`      | `alert`          | 10 for [`Priority::High`], otherwise 5  | from configuration        |
//!
//! Background pushes wake the application silently, but iOS may delay or
//! drop them. Alert pushes are delivered reliably but must display
//! something; configure `aps` with a placeholder alert and
//! `"mutable-content": 1` so a notification service extension can decrypt
//! the message and replace the content before it is shown.
//!
//! `apns-expiration` is now plus the message TTL in Unix seconds, or `0` for
//! a zero TTL, which tells APNs to attempt delivery once and not store the
//! message.
//!
//! # Payload
//!
//! The body is the `aps` dictionary plus the fields of
//! [`Notification::fields`] at the top level:
//!
//! ```json
//! {
//!   "aps": {"content-available": 1},
//!   "channelID": "5b8a2f0e-7a4c-4b8e-9d5f-2c1e3a4b5c6d",
//!   "version": "AAAAAAAAAAAAAAAAAAAAAA",
//!   "data": "base64url ciphertext",
//!   "encoding": "aes128gcm"
//! }
//! ```
//!
//! Bodies over APNs' 4096 byte limit fail with [`Error::TooLarge`] without a
//! request.
//!
//! # Errors
//!
//! APNs reports failures as a status code and a `{"reason": "..."}` body.
//!
//! | Response                                                   | [`Error`]                   |
//! |------------------------------------------------------------|-----------------------------|
//! | 410, or 400 `BadDeviceToken` / `DeviceTokenNotForTopic`    | `TokenGone`                 |
//! | other 400                                                  | `Rejected(reason)`          |
//! | 413                                                        | `TooLarge`                  |
//! | 429                                                        | `Throttled` (`Retry-After`) |
//! | 403, 5xx, network failure                                  | `Unavailable`               |
//!
//! Device tokens and payloads never appear in errors.
//!
//! # Configuration
//!
//! ```toml
//! [bridges.apns.apps.example-ios]
//! key_file = "/etc/webpush/apns-example.p8"
//! key_id = "ABC123DEFG"
//! team_id = "DEF123GHIJ"
//! topic = "com.example.app"
//! environment = "production"
//! ```

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{StatusCode, header::RETRY_AFTER};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair},
};
use rustls_pki_types::{PrivatePkcs8KeyDer, pem::PemObject};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use webpush_bridge::{Address, BoxError, BoxFuture, Bridge, Error, Notification, Priority};

const PRODUCTION: &str = "https://api.push.apple.com";
const SANDBOX: &str = "https://api.sandbox.push.apple.com";
/// APNs' limit on the request body.
const MAX_PAYLOAD: usize = 4096;
/// Inside Apple's window: older than 20 minutes, younger than an hour.
const TOKEN_LIFETIME: Duration = Duration::from_secs(40 * 60);

/// Bridge configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Applications by the app id user agents register with.
    #[serde(default)]
    pub apps: HashMap<String, AppConfig>,
    /// Per-request timeout. Defaults to 10 seconds.
    #[serde(default = "default_timeout", with = "humantime_serde")]
    pub timeout: Duration,
}

fn default_timeout() -> Duration {
    Duration::from_secs(10)
}

/// One Apple application.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    /// The `.p8` signing key from Apple: a PKCS#8 PEM P-256 key.
    pub key_file: PathBuf,
    /// The signing key's id.
    pub key_id: String,
    /// The Apple developer team id.
    pub team_id: String,
    /// The application's bundle id, sent as `apns-topic`.
    pub topic: String,
    /// Which APNs environment the application's tokens belong to.
    #[serde(default)]
    pub environment: Environment,
    /// Base URL overriding `environment`, for test doubles.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Whether messages are background or alert pushes.
    #[serde(default)]
    pub push_type: PushType,
    /// The `aps` dictionary for alert pushes. Required when `push_type` is
    /// `alert`, and should contain `"mutable-content": 1` so a notification
    /// service extension can decrypt the message.
    #[serde(default)]
    pub aps: Option<Value>,
}

/// APNs environment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    /// `api.push.apple.com`, for App Store and ad hoc builds.
    #[default]
    Production,
    /// `api.sandbox.push.apple.com`, for development builds.
    Sandbox,
}

/// APNs push type.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PushType {
    /// A silent push that wakes the application. Always priority 5.
    #[default]
    Background,
    /// A user-visible push, described by the configured `aps`.
    Alert,
}

/// The APNs bridge.
pub struct Apns {
    apps: HashMap<String, App>,
}

struct App {
    client: reqwest::Client,
    endpoint: String,
    key: EcdsaKeyPair,
    key_id: String,
    team_id: String,
    topic: String,
    push_type: PushType,
    aps: Value,
    jwt: Mutex<Option<(String, Instant)>>,
}

impl Apns {
    /// Load every signing key and validate the configuration.
    ///
    /// # Errors
    ///
    /// A key file is missing or not a PKCS#8 P-256 key, an alert app has no
    /// `aps`, or the HTTP client cannot be built.
    pub fn new(cfg: &Config) -> Result<Self, BoxError> {
        let mut loaded = HashMap::new();
        for (id, app) in &cfg.apps {
            let pem = PrivatePkcs8KeyDer::from_pem_file(&app.key_file)
                .map_err(|e| format!("apns app {id}: {}: {e}", app.key_file.display()))?;
            let key = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                pem.secret_pkcs8_der(),
                &SystemRandom::new(),
            )
            .map_err(|e| format!("apns app {id}: key is not a P-256 PKCS#8 key: {e}"))?;
            let aps = match (app.push_type, &app.aps) {
                (_, Some(aps)) => aps.clone(),
                (PushType::Background, None) => json!({"content-available": 1}),
                (PushType::Alert, None) => {
                    return Err(format!("apns app {id}: push_type = \"alert\" requires aps").into());
                }
            };
            let endpoint = app.endpoint.clone().unwrap_or_else(|| {
                match app.environment {
                    Environment::Production => PRODUCTION,
                    Environment::Sandbox => SANDBOX,
                }
                .to_owned()
            });
            let client =
                webpush_bridge::http2_client(cfg.timeout, endpoint.starts_with("http://"))?;
            loaded.insert(
                id.clone(),
                App {
                    client,
                    endpoint: endpoint.trim_end_matches('/').to_owned(),
                    key,
                    key_id: app.key_id.clone(),
                    team_id: app.team_id.clone(),
                    topic: app.topic.clone(),
                    push_type: app.push_type,
                    aps,
                    jwt: Mutex::new(None),
                },
            );
        }
        Ok(Self { apps: loaded })
    }
}

impl App {
    /// The cached provider token, or a freshly signed one.
    fn jwt(&self) -> Result<String, Error> {
        let mut cached = self
            .jwt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((jwt, at)) = &*cached
            && at.elapsed() < TOKEN_LIFETIME
        {
            return Ok(jwt.clone());
        }
        let header = json!({"alg": "ES256", "kid": self.key_id});
        let claims = json!({"iss": self.team_id, "iat": unix_now()});
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let sig = self
            .key
            .sign(&SystemRandom::new(), input.as_bytes())
            .map_err(|e| Error::Unavailable(format!("signing provider token: {e}").into()))?;
        let jwt = format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()));
        *cached = Some((jwt.clone(), Instant::now()));
        Ok(jwt)
    }

    fn drop_jwt(&self) {
        *self
            .jwt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    async fn send(&self, token: &str, n: &Notification<'_>) -> Result<(), Error> {
        // The token becomes a path segment; anything but the hex Apple issues
        // could redirect the request, and APNs would reject it anyway.
        if token.is_empty() || !token.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(Error::TokenGone);
        }
        let mut body = Map::from_iter([("aps".to_owned(), self.aps.clone())]);
        body.extend(
            n.fields()
                .into_iter()
                .map(|(k, v)| (k.to_owned(), Value::String(v))),
        );
        let body = serde_json::to_vec(&body).map_err(|e| Error::Rejected(e.to_string()))?;
        if body.len() > MAX_PAYLOAD {
            return Err(Error::TooLarge);
        }

        let (push_type, priority) = match (self.push_type, n.priority) {
            (PushType::Background, _) => ("background", "5"),
            (PushType::Alert, Priority::High) => ("alert", "10"),
            (PushType::Alert, Priority::Normal) => ("alert", "5"),
        };
        let expiration = if n.ttl.is_zero() {
            0
        } else {
            unix_now().saturating_add(n.ttl.as_secs())
        };

        let resp = self
            .client
            .post(format!("{}/3/device/{token}", self.endpoint))
            .header("authorization", format!("bearer {}", self.jwt()?))
            .header("apns-topic", &self.topic)
            .header("apns-push-type", push_type)
            .header("apns-priority", priority)
            .header("apns-expiration", expiration.to_string())
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            // Strip the URL, which contains the device token.
            .map_err(|e| Error::Unavailable(e.without_url().into()))?;

        let status = resp.status();
        if status == StatusCode::OK {
            return Ok(());
        }
        let retry_after = resp
            .headers()
            .get(RETRY_AFTER)
            .and_then(|v| v.to_str().ok()?.trim().parse().ok())
            .map(Duration::from_secs);
        // A body that is missing or not the documented JSON still leaves the
        // status to go on.
        let reason = resp
            .bytes()
            .await
            .ok()
            .and_then(|b| serde_json::from_slice::<Reason>(&b).ok())
            .map_or_else(|| format!("HTTP {status}"), |r| r.reason);

        Err(match status.as_u16() {
            410 => Error::TokenGone,
            400 if matches!(reason.as_str(), "BadDeviceToken" | "DeviceTokenNotForTopic") => {
                Error::TokenGone
            }
            400 => Error::Rejected(reason),
            413 => Error::TooLarge,
            429 => Error::Throttled { retry_after },
            403 => {
                if matches!(
                    reason.as_str(),
                    "ExpiredProviderToken" | "InvalidProviderToken"
                ) {
                    self.drop_jwt();
                }
                Error::Unavailable(format!("APNs refused credentials: {reason}").into())
            }
            _ => Error::Unavailable(format!("APNs returned {status}: {reason}").into()),
        })
    }
}

#[derive(Deserialize)]
struct Reason {
    reason: String,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Bridge for Apns {
    fn name(&self) -> &'static str {
        "apns"
    }

    fn has_app(&self, app_id: &str) -> bool {
        self.apps.contains_key(app_id)
    }

    fn send<'a>(
        &'a self,
        to: Address<'a>,
        notification: &'a Notification<'a>,
    ) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            let app = self.apps.get(to.app_id).ok_or(Error::UnknownApp)?;
            app.send(to.token, notification).await
        })
    }
}
