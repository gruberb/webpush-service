//! A [`Bridge`] to Firebase Cloud Messaging (FCM) through the HTTP v1 API.
//!
//! Each configured application maps the app id user agents register with to
//! a Google service account. Messages go out as FCM data messages, so the
//! application receives them even in the background and decides itself
//! whether to show anything.
//!
//! # Authentication
//!
//! FCM v1 takes an OAuth 2.0 access token with the scope
//! `https://www.googleapis.com/auth/firebase.messaging`, obtained through
//! [`webpush_gcp_auth::TokenSource`]:
//!
//! - With `credentials_file`, from that service account key: an RS256 JWT
//!   exchanged at the key's `token_uri`.
//! - Without it, from Application Default Credentials: on Cloud Run or GKE
//!   the workload's own service account through the metadata server, so no
//!   key file is deployed; locally `gcloud auth application-default login`.
//!   `project_id` is then required.
//!
//! Tokens are cached per application until less than a minute of their
//! lifetime remains, and concurrent sends wait for a single refresh.
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
//!
//! # Or, with Application Default Credentials:
//! [bridges.fcm.apps.example-android-adc]
//! project_id = "example-firebase-project"
//! ```
//!
//! `endpoint` overrides the FCM base URL (default
//! `https://fcm.googleapis.com`) and `timeout` the per-request timeout
//! (default `10s`).

use std::{collections::HashMap, path::PathBuf, time::Duration};

use reqwest::{StatusCode, header};
use serde::Deserialize;
use serde_json::json;
use webpush_bridge::{Address, BoxError, BoxFuture, Bridge, Error, Notification, Priority};
use webpush_gcp_auth::TokenSource;

const DEFAULT_ENDPOINT: &str = "https://fcm.googleapis.com";
const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const MAX_DATA_BYTES: usize = 4096;
/// 28 days, the longest TTL FCM accepts.
const MAX_TTL_SECS: u64 = 2_419_200;

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
    /// Path to a Google service account JSON key. Without it the bridge uses
    /// Application Default Credentials.
    #[serde(default)]
    pub credentials_file: Option<PathBuf>,
    /// The Firebase project. Defaults to the service account key's project;
    /// required without `credentials_file`.
    #[serde(default)]
    pub project_id: Option<String>,
    /// FCM base URL, `https://fcm.googleapis.com` if unset.
    #[serde(default)]
    pub endpoint: Option<String>,
}

/// One application's credentials and send URL.
struct App {
    /// Access tokens for the application's project.
    auth: TokenSource,
    /// `.../v1/projects/{project}/messages:send`.
    send_url: String,
    /// Project billed for user credentials, sent as `x-goog-user-project`.
    quota_project: Option<String>,
}

/// The FCM bridge. Holds credentials, cached access tokens, and an HTTP
/// client; share one instance between requests.
pub struct Fcm {
    apps: HashMap<String, App>,
    http: reqwest::Client,
}

impl Fcm {
    /// Load every configured application's credentials.
    ///
    /// # Errors
    ///
    /// A credentials file cannot be read or used, an application has no
    /// project, or the HTTP client cannot be built. Checking at startup keeps a bad deployment from
    /// surfacing only on the first message.
    pub fn new(cfg: &Config) -> Result<Self, BoxError> {
        let http = webpush_bridge::http_client(cfg.timeout)?;
        let apps = cfg
            .apps
            .iter()
            .map(|(id, app)| {
                load_app(app, &http)
                    .map(|a| (id.clone(), a))
                    .map_err(|e| format!("fcm app {id}: {e}"))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { apps, http })
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

        let token = app.auth.token().await.map_err(Error::Unavailable)?;
        let mut request = self.http.post(&app.send_url).bearer_auth(token).json(&body);
        if let Some(project) = &app.quota_project {
            request = request.header("x-goog-user-project", project);
        }
        let resp = request
            .send()
            .await
            .map_err(|e| Error::Unavailable(e.without_url().into()))?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        if status == StatusCode::UNAUTHORIZED {
            // The token was revoked or the clock drifted; start over next time.
            app.auth.invalidate().await;
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

fn load_app(cfg: &AppConfig, http: &reqwest::Client) -> Result<App, BoxError> {
    let auth = match &cfg.credentials_file {
        Some(path) => TokenSource::from_file(path, &[SCOPE], http.clone())?,
        None => TokenSource::discover(&[SCOPE], http.clone())?,
    };
    let project = cfg
        .project_id
        .as_deref()
        .or(auth.project_id())
        .ok_or("project_id is required without a service account key")?;
    let endpoint = cfg.endpoint.as_deref().unwrap_or(DEFAULT_ENDPOINT);
    Ok(App {
        send_url: format!(
            "{}/v1/projects/{project}/messages:send",
            endpoint.trim_end_matches('/')
        ),
        quota_project: auth.quota_project().map(str::to_owned),
        auth,
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
