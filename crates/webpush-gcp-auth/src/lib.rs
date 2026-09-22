//! Google Cloud OAuth 2.0 access tokens.
//!
//! Google APIs (Bigtable, FCM) take a short-lived bearer token. A
//! [`TokenSource`] obtains one from whichever credentials the environment
//! offers, caches it, and refreshes it shortly before it expires.
//!
//! | Credentials | Where they come from | How a token is obtained |
//! |---|---|---|
//! | Service account key | a JSON key file | an RS256-signed JWT exchanged at the key's `token_uri` (RFC 7523) |
//! | User credentials | `gcloud auth application-default login` | the refresh token exchanged at Google's token endpoint |
//! | Metadata server | Cloud Run, GKE Workload Identity, Compute Engine | `GET` on the metadata server, no key material in the process |
//!
//! [`TokenSource::discover`] follows the order Google's own libraries use for
//! Application Default Credentials: `$GOOGLE_APPLICATION_CREDENTIALS`, then
//! gcloud's well-known file, then the metadata server.
//!
//! ```no_run
//! # async fn run() -> Result<(), webpush_gcp_auth::BoxError> {
//! use std::time::Duration;
//! use webpush_gcp_auth::{CLOUD_PLATFORM, TokenSource};
//!
//! let http = webpush_gcp_auth::http_client(Duration::from_secs(10))?;
//! let source = TokenSource::discover(&[CLOUD_PLATFORM], http)?;
//! let token = source.token().await?;
//! # let _ = token;
//! # Ok(())
//! # }
//! ```

use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    rand::SystemRandom,
    signature::{RSA_PKCS1_SHA256, RsaKeyPair},
};
use rustls_pki_types::{PrivatePkcs8KeyDer, pem::PemObject};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex;

/// Boxed error for credential and token failures.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The scope that covers every Google Cloud API the account is allowed to use.
pub const CLOUD_PLATFORM: &str = "https://www.googleapis.com/auth/cloud-platform";

/// Google's token endpoint, used for user credentials.
const GOOGLE_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
/// The metadata server's host inside Google Cloud.
const METADATA_HOST: &str = "metadata.google.internal";
/// Lifetime requested for a signed assertion; Google caps it at one hour.
const ASSERTION_LIFETIME_SECS: u64 = 3600;
/// Refresh this long before expiry so a token never lapses mid-request.
const REFRESH_MARGIN: Duration = Duration::from_secs(60);

/// Where tokens come from.
enum Credentials {
    /// A service account key.
    ServiceAccount {
        /// The account, the JWT issuer.
        client_email: String,
        /// Token endpoint and JWT audience.
        token_uri: String,
        /// The account's private key.
        key: Box<RsaKeyPair>,
        /// The key's project.
        project_id: Option<String>,
    },
    /// A user's refresh token from `gcloud auth application-default login`.
    AuthorizedUser {
        /// OAuth client id.
        client_id: String,
        /// OAuth client secret.
        client_secret: String,
        /// The user's refresh token.
        refresh_token: String,
        /// Project billed for API calls made with the user's credentials.
        quota_project: Option<String>,
    },
    /// The metadata server of the Google Cloud runtime.
    Metadata {
        /// `http://host`, without a trailing slash.
        base: String,
    },
}

/// The fields of a credentials file this crate reads.
#[derive(Deserialize)]
struct CredentialsFile {
    /// `service_account` or `authorized_user`.
    #[serde(rename = "type")]
    kind: String,
    client_email: Option<String>,
    private_key: Option<String>,
    token_uri: Option<String>,
    project_id: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    refresh_token: Option<String>,
    quota_project_id: Option<String>,
}

/// A cached access token.
struct Cached {
    /// The bearer token.
    value: String,
    /// When to stop using it.
    expires_at: Instant,
}

/// Obtains, caches, and refreshes access tokens for a set of scopes. Share
/// one instance; concurrent callers wait for a single refresh.
pub struct TokenSource {
    /// Where tokens come from.
    credentials: Credentials,
    /// Space-separated scopes.
    scopes: String,
    /// HTTP client for token requests.
    http: reqwest::Client,
    /// The current token.
    cached: Mutex<Option<Cached>>,
    /// Randomness for RSA signing.
    rng: SystemRandom,
}

impl TokenSource {
    /// Credentials from the JSON of a service account key or a user
    /// credentials file.
    ///
    /// # Errors
    ///
    /// The JSON is not one of those two kinds, misses a field, or holds a
    /// private key that is not PKCS#8 RSA.
    pub fn from_json(json: &str, scopes: &[&str], http: reqwest::Client) -> Result<Self, BoxError> {
        let file: CredentialsFile = serde_json::from_str(json)?;
        let field =
            |v: Option<String>, name: &str| v.ok_or_else(|| format!("credentials without {name}"));
        let credentials = match file.kind.as_str() {
            "service_account" => {
                let pem = field(file.private_key, "private_key")?;
                let der = PrivatePkcs8KeyDer::from_pem_slice(pem.as_bytes())
                    .map_err(|e| format!("private_key: {e}"))?;
                let key = RsaKeyPair::from_pkcs8(der.secret_pkcs8_der())
                    .map_err(|e| format!("private_key is not an RSA key: {e}"))?;
                Credentials::ServiceAccount {
                    client_email: field(file.client_email, "client_email")?,
                    token_uri: file
                        .token_uri
                        .unwrap_or_else(|| GOOGLE_TOKEN_URI.to_owned()),
                    key: Box::new(key),
                    project_id: file.project_id,
                }
            }
            "authorized_user" => Credentials::AuthorizedUser {
                client_id: field(file.client_id, "client_id")?,
                client_secret: field(file.client_secret, "client_secret")?,
                refresh_token: field(file.refresh_token, "refresh_token")?,
                quota_project: file.quota_project_id,
            },
            other => return Err(format!("unsupported credentials type {other:?}").into()),
        };
        Ok(Self::new(credentials, scopes, http))
    }

    /// Credentials from a file, as [`TokenSource::from_json`].
    ///
    /// # Errors
    ///
    /// The file cannot be read, or as for [`TokenSource::from_json`].
    pub fn from_file(
        path: &Path,
        scopes: &[&str],
        http: reqwest::Client,
    ) -> Result<Self, BoxError> {
        let json = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::from_json(&json, scopes, http).map_err(|e| format!("{}: {e}", path.display()).into())
    }

    /// Tokens from a metadata server at `base`, for example
    /// `http://metadata.google.internal`.
    #[must_use]
    pub fn metadata(base: &str, scopes: &[&str], http: reqwest::Client) -> Self {
        let base = base.trim_end_matches('/').to_owned();
        Self::new(Credentials::Metadata { base }, scopes, http)
    }

    /// Application Default Credentials: the file named by
    /// `$GOOGLE_APPLICATION_CREDENTIALS`, else gcloud's well-known file, else
    /// the metadata server (`$GCE_METADATA_HOST` overrides its host). The
    /// metadata server is not probed here; outside Google Cloud the first
    /// [`TokenSource::token`] call fails.
    ///
    /// # Errors
    ///
    /// A credentials file exists but cannot be used.
    pub fn discover(scopes: &[&str], http: reqwest::Client) -> Result<Self, BoxError> {
        if let Some(path) = std::env::var_os("GOOGLE_APPLICATION_CREDENTIALS") {
            return Self::from_file(Path::new(&path), scopes, http);
        }
        if let Some(path) = well_known_file().filter(|p| p.exists()) {
            return Self::from_file(&path, scopes, http);
        }
        let host = std::env::var("GCE_METADATA_HOST").unwrap_or_else(|_| METADATA_HOST.to_owned());
        Ok(Self::metadata(&format!("http://{host}"), scopes, http))
    }

    /// The project named by the credentials: a service account key's
    /// project, or a user's quota project. The metadata server's project is
    /// not looked up.
    #[must_use]
    pub fn project_id(&self) -> Option<&str> {
        match &self.credentials {
            Credentials::ServiceAccount { project_id, .. } => project_id.as_deref(),
            Credentials::AuthorizedUser { quota_project, .. } => quota_project.as_deref(),
            Credentials::Metadata { .. } => None,
        }
    }

    /// The project to bill, sent as `x-goog-user-project`. Only user
    /// credentials need it; service accounts bill their own project.
    #[must_use]
    pub fn quota_project(&self) -> Option<&str> {
        match &self.credentials {
            Credentials::AuthorizedUser { quota_project, .. } => quota_project.as_deref(),
            _ => None,
        }
    }

    /// A valid access token, fetched if the cached one is missing or close to
    /// expiry. Holding the lock across the fetch makes concurrent callers
    /// share one refresh.
    ///
    /// # Errors
    ///
    /// The token endpoint cannot be reached or refuses the credentials.
    /// Response bodies are left out of errors, since they can echo secrets.
    pub async fn token(&self) -> Result<String, BoxError> {
        let mut cached = self.cached.lock().await;
        if let Some(t) = cached.as_ref()
            && t.expires_at.saturating_duration_since(Instant::now()) > REFRESH_MARGIN
        {
            return Ok(t.value.clone());
        }
        let fresh = self.fetch().await?;
        let value = fresh.value.clone();
        *cached = Some(fresh);
        Ok(value)
    }

    /// Drop the cached token, after an API refused it.
    pub async fn invalidate(&self) {
        *self.cached.lock().await = None;
    }

    /// A token source over `credentials`.
    fn new(credentials: Credentials, scopes: &[&str], http: reqwest::Client) -> Self {
        Self {
            credentials,
            scopes: scopes.join(" "),
            http,
            cached: Mutex::new(None),
            rng: SystemRandom::new(),
        }
    }

    /// Request a new token.
    async fn fetch(&self) -> Result<Cached, BoxError> {
        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            expires_in: u64,
        }

        let request = match &self.credentials {
            Credentials::ServiceAccount { token_uri, .. } => {
                let assertion = self.assertion()?;
                self.http.post(token_uri).form(&[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                    ("assertion", assertion.as_str()),
                ])
            }
            Credentials::AuthorizedUser {
                client_id,
                client_secret,
                refresh_token,
                ..
            } => self.http.post(GOOGLE_TOKEN_URI).form(&[
                ("grant_type", "refresh_token"),
                ("client_id", client_id.as_str()),
                ("client_secret", client_secret.as_str()),
                ("refresh_token", refresh_token.as_str()),
            ]),
            Credentials::Metadata { base } => self
                .http
                .get(format!(
                    "{base}/computeMetadata/v1/instance/service-accounts/default/token"
                ))
                .query(&[("scopes", self.scopes.replace(' ', ","))])
                .header("Metadata-Flavor", "Google"),
        };
        // Measured from before the request, so network delay only makes the
        // cached lifetime shorter, never longer.
        let requested = Instant::now();
        let resp = request.send().await.map_err(reqwest::Error::without_url)?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("token request returned {status}").into());
        }
        let token: TokenResponse = resp.json().await?;
        Ok(Cached {
            value: token.access_token,
            expires_at: requested + Duration::from_secs(token.expires_in),
        })
    }

    /// The signed JWT a service account exchanges for an access token.
    fn assertion(&self) -> Result<String, BoxError> {
        let Credentials::ServiceAccount {
            client_email,
            token_uri,
            key,
            ..
        } = &self.credentials
        else {
            return Err("assertions need a service account".into());
        };
        let iat = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({
            "iss": client_email,
            "scope": self.scopes,
            "aud": token_uri,
            "iat": iat,
            "exp": iat + ASSERTION_LIFETIME_SECS,
        }))?);
        let signing_input = format!("{header}.{claims}");
        let mut sig = vec![0; key.public().modulus_len()];
        key.sign(
            &RSA_PKCS1_SHA256,
            &self.rng,
            signing_input.as_bytes(),
            &mut sig,
        )
        .map_err(|_| "RSA signing failed")?;
        Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig)))
    }
}

/// An HTTP client for token requests and Google APIs: rustls with the `ring`
/// provider, installed as the process default unless the application chose
/// another.
///
/// # Errors
///
/// The client cannot be built.
pub fn http_client(timeout: Duration) -> Result<reqwest::Client, BoxError> {
    // Fails only when a provider is already installed, which is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();
    Ok(reqwest::Client::builder().timeout(timeout).build()?)
}

/// gcloud's Application Default Credentials file.
fn well_known_file() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var_os("APPDATA")
            .map(|d| PathBuf::from(d).join("gcloud/application_default_credentials.json"))
    } else {
        std::env::var_os("HOME")
            .map(|h| PathBuf::from(h).join(".config/gcloud/application_default_credentials.json"))
    }
}
