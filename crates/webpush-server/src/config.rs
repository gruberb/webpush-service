//! Service configuration.
//!
//! Configuration is read from a TOML file and then from environment
//! variables, which take precedence. An environment variable names a setting
//! by its path with `__` between levels, prefixed with `WEBPUSH_`:
//!
//! ```text
//!  webpush.toml                        environment
//!  ------------                        -----------
//!  role = "endpoint"                   WEBPUSH_ROLE=endpoint
//!  [cluster]
//!  token = "..."                       WEBPUSH_CLUSTER__TOKEN=...
//!  [store.bigtable]
//!  table = "push"                      WEBPUSH_STORE__BIGTABLE__TABLE=push
//! ```
//!
//! Every setting except `origin` has a default suited to production, so a
//! minimal single-node file is two lines. `config/webpush.example.toml` in
//! the repository lists every setting with its default.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use figment::{
    Figment,
    providers::{Env, Format, Toml},
};
use serde::Deserialize;

use crate::BoxError;

/// Everything the service reads from its configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Which part of the service this process runs.
    #[serde(default)]
    pub role: Role,
    /// Public origin, for example `https://push.example.net`, without a
    /// trailing slash. It is the base of every push endpoint, `Location`, and
    /// `Link` target, and the value VAPID `aud` claims must match
    /// (RFC 8292 §2).
    pub origin: String,
    /// The listener for user agents and application servers.
    #[serde(default)]
    pub public: Public,
    /// The listener for health checks, metrics, and messages between nodes.
    /// Required when `cluster` is set.
    #[serde(default)]
    pub internal: Option<Internal>,
    /// Membership in a cluster of endpoint and connection nodes. Without it
    /// the process must run `role = "all"`.
    #[serde(default)]
    pub cluster: Option<Cluster>,
    /// Limits on push messages.
    #[serde(default)]
    pub push: Push,
    /// User agent sessions.
    #[serde(default)]
    pub websocket: WebSocket,
    /// Receipt streams.
    #[serde(default)]
    pub receipts: Receipts,
    /// User agent liveness.
    #[serde(default)]
    pub user_agents: UserAgents,
    /// Cross-origin access to the application server API.
    #[serde(default)]
    pub cors: Cors,
    /// The registration API for user agents reached through a bridge.
    #[serde(default)]
    pub registration: Registration,
    /// Platform push services.
    #[serde(default)]
    pub bridges: Bridges,
    /// Where state is kept.
    #[serde(default)]
    pub store: Store,
    /// Log output.
    #[serde(default)]
    pub log: Log,
    /// Behaviour on SIGTERM and SIGINT.
    #[serde(default)]
    pub shutdown: Shutdown,
}

/// The part of the service a process runs.
///
/// ```text
///  role       public listener serves                          background work
///  ---------  ----------------------------------------------  -----------------------
///  all        WebSocket, push, messages, receipts, registration  reaper, expiry
///  endpoint   push, messages, receipts, registration             reaper, expiry
///  connect    WebSocket                                          none
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Everything in one process. The default, and the only role that works
    /// without a cluster.
    #[default]
    All,
    /// The application server API: stateless, scaled by adding replicas.
    Endpoint,
    /// User agent WebSocket sessions: scaled by adding nodes, each holding
    /// its share of the connections.
    Connect,
}

impl Role {
    /// Whether this role holds user agent sessions.
    #[must_use]
    pub fn connects(self) -> bool {
        matches!(self, Self::All | Self::Connect)
    }

    /// Whether this role serves the application server API.
    #[must_use]
    pub fn serves_endpoint(self) -> bool {
        matches!(self, Self::All | Self::Endpoint)
    }
}

/// The public listener.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Public {
    /// Address to listen on.
    pub listen: SocketAddr,
    /// TLS material. Without it the listener speaks plaintext HTTP/1.1 and
    /// HTTP/2, for deployments where a load balancer terminates TLS; RFC 8030
    /// §8 requires TLS on the public path, so something in front must
    /// provide it.
    pub tls: Option<Tls>,
    /// Open connections, WebSocket sessions included. At the limit the
    /// listener stops accepting until a connection closes.
    pub max_connections: usize,
    /// Connections that have not completed the TLS handshake by then are
    /// dropped.
    #[serde(with = "humantime_serde")]
    pub handshake_timeout: Duration,
}

impl Default for Public {
    fn default() -> Self {
        Self {
            listen: ([0, 0, 0, 0], 8443).into(),
            tls: None,
            max_connections: 100_000,
            handshake_timeout: Duration::from_secs(10),
        }
    }
}

/// TLS certificate and key files, PEM encoded.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    /// Certificate chain, leaf first.
    pub cert_file: PathBuf,
    /// Private key of the leaf certificate.
    pub key_file: PathBuf,
}

/// The internal listener: plaintext HTTP, to be reachable only from inside
/// the deployment.
///
/// | Path | Purpose |
/// |---|---|
/// | `GET /health` | Liveness: the process is running |
/// | `GET /ready` | Readiness: the store answers and the process is not shutting down |
/// | `GET /version` | Crate name and version |
/// | `GET /metrics` | Prometheus text format |
/// | `POST /internal/v1/notify` | Delivery from another node; requires the cluster token |
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Internal {
    /// Address to listen on.
    pub listen: SocketAddr,
}

/// Cluster membership.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cluster {
    /// URL other nodes use to reach this node's internal listener, for
    /// example `http://10.0.3.7:8081`. It is recorded in the store as the
    /// route to every connection this node holds, so it must be unique per
    /// node and stable for the life of the process.
    pub node_url: String,
    /// Shared secret every node presents on `POST /internal/v1/notify`.
    /// Prefer setting it through `WEBPUSH_CLUSTER__TOKEN`.
    pub token: String,
    /// How long a node waits for another to accept a delivery.
    #[serde(default = "Cluster::default_notify_timeout", with = "humantime_serde")]
    pub notify_timeout: Duration,
}

impl Cluster {
    /// Default for [`Cluster::notify_timeout`].
    fn default_notify_timeout() -> Duration {
        Duration::from_secs(2)
    }
}

/// Limits on push messages.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Push {
    /// Longest time a message is stored. Requested TTLs above it are
    /// reduced, and the response `TTL` header reports the value used
    /// (RFC 8030 §5.2).
    #[serde(with = "humantime_serde")]
    pub max_ttl: Duration,
    /// Largest accepted push message body, in octets. Larger bodies get 413.
    /// Must be at least 4096 (RFC 8030 §7.2).
    pub max_payload: usize,
    /// How often expired messages that requested receipts are swept, which
    /// is when their 410 receipts go out (RFC 8030 §6.2).
    #[serde(with = "humantime_serde")]
    pub reaper_interval: Duration,
}

impl Default for Push {
    fn default() -> Self {
        Self {
            max_ttl: Duration::from_secs(60 * 24 * 3600),
            max_payload: 4096,
            reaper_interval: Duration::from_secs(1),
        }
    }
}

/// User agent sessions.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct WebSocket {
    /// A client that has not sent `hello` by then is disconnected.
    #[serde(with = "humantime_serde")]
    pub hello_timeout: Duration,
    /// Interval of WebSocket pings from the server. They keep load
    /// balancers from closing idle sessions and detect dead peers.
    #[serde(with = "humantime_serde")]
    pub ping_interval: Duration,
    /// A session that sends nothing, not even a pong, for `ping_interval`
    /// plus this long is closed.
    #[serde(with = "humantime_serde")]
    pub pong_timeout: Duration,
    /// Stored messages sent per batch when a user agent connects. The next
    /// batch follows once the user agent has acknowledged the previous one.
    pub backlog_batch: usize,
    /// Live events buffered per connection. A connection that falls this far
    /// behind is closed; the user agent reconnects and reads the rest from
    /// storage.
    pub queue: usize,
    /// Longest a session stays open. When it ends, the session closes with
    /// 1001 and the client reconnects, possibly to another instance. This
    /// moves clients off instances nothing routes to anymore (a platform
    /// that keeps an old instance alive during a rollout) and spreads
    /// connections after a scale-out. Each session's limit varies by up to
    /// 20% either way, so a node's clients do not reconnect at once. Unset
    /// keeps sessions open indefinitely.
    #[serde(with = "humantime_serde")]
    pub max_session: Option<Duration>,
}

impl Default for WebSocket {
    fn default() -> Self {
        Self {
            hello_timeout: Duration::from_secs(10),
            ping_interval: Duration::from_secs(60),
            pong_timeout: Duration::from_secs(30),
            backlog_batch: 100,
            queue: 128,
            max_session: None,
        }
    }
}

/// Receipt streams.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Receipts {
    /// Interval of comment lines that keep intermediaries from closing an
    /// idle stream.
    #[serde(with = "humantime_serde")]
    pub keepalive: Duration,
}

impl Default for Receipts {
    fn default() -> Self {
        Self {
            keepalive: Duration::from_secs(30),
        }
    }
}

/// User agent liveness.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UserAgents {
    /// User agents not seen for this long are deleted with their
    /// subscriptions. A user agent is seen when it connects, while it stays
    /// connected, and when a bridged user agent calls the registration API.
    /// Unset keeps user agents forever.
    #[serde(with = "humantime_serde")]
    pub expire_after: Option<Duration>,
    /// How often expired user agents are swept.
    #[serde(with = "humantime_serde")]
    pub sweep_interval: Duration,
}

impl Default for UserAgents {
    fn default() -> Self {
        Self {
            expire_after: None,
            sweep_interval: Duration::from_secs(3600),
        }
    }
}

/// Cross-origin access to the application server API (push, message, and
/// receipt resources). Empty disables CORS.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Cors {
    /// Origins allowed to call the API from a browser, or `["*"]` for any.
    pub allowed_origins: Vec<String>,
}

/// The registration API for bridged user agents.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Registration {
    /// Keys that derive the secret each bridged user agent authenticates
    /// with. The first signs new secrets; all of them verify, so a key can
    /// be rotated by prepending its successor. Required when a bridge is
    /// configured. Prefer `WEBPUSH_REGISTRATION__SECRET_KEYS`.
    pub secret_keys: Vec<String>,
}

/// Platform push services. Each is available when the binary is built with
/// the feature of the same name.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Bridges {
    /// Firebase Cloud Messaging.
    #[cfg(feature = "fcm")]
    pub fcm: Option<webpush_fcm::Config>,
    /// Apple Push Notification service.
    #[cfg(feature = "apns")]
    pub apns: Option<webpush_apns::Config>,
}

/// Where state is kept.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "lowercase")]
pub enum Store {
    /// In process memory. State is lost on restart, and nodes cannot share
    /// it, so it only suits `role = "all"`.
    #[default]
    Memory,
    /// Cloud Bigtable. Requires the `bigtable` feature.
    Bigtable(Bigtable),
}

/// Cloud Bigtable settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bigtable {
    /// gRPC endpoint: `https://bigtable.googleapis.com`, or
    /// `http://127.0.0.1:8086` for the emulator.
    pub endpoint: String,
    /// Google Cloud project.
    pub project: String,
    /// Bigtable instance.
    pub instance: String,
    /// Table.
    pub table: String,
    /// Create the table if it does not exist.
    #[serde(default)]
    pub create_table: bool,
    /// Service account key. Without it, Cloud Bigtable is reached with
    /// Application Default Credentials: the workload's service account on
    /// Cloud Run and GKE, `gcloud auth application-default login` locally.
    #[serde(default)]
    pub credentials_file: Option<PathBuf>,
    /// App profile that routes the requests; the instance default if unset.
    #[serde(default)]
    pub app_profile: Option<String>,
}

/// Log output.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Log {
    /// A `tracing` filter directive, for example `info` or
    /// `info,webpush_server=debug`. `RUST_LOG` overrides it when set.
    pub level: String,
    /// Output format.
    pub format: LogFormat,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            level: "info".to_owned(),
            format: LogFormat::Text,
        }
    }
}

/// Log line format.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-readable lines.
    #[default]
    Text,
    /// One JSON object per line, for log collectors.
    Json,
}

/// Behaviour on SIGTERM and SIGINT.
///
/// ```text
///  signal ──> /ready answers 503 ──drain_delay──> stop accepting, close
///             (load balancer moves             sessions with 1001, finish
///              new traffic away)                in-flight requests ──timeout──> exit
/// ```
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Shutdown {
    /// Time between failing readiness and closing listeners, so load
    /// balancers stop routing new connections to this process first.
    #[serde(with = "humantime_serde")]
    pub drain_delay: Duration,
    /// Upper bound on finishing in-flight work after listeners close.
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
}

impl Default for Shutdown {
    fn default() -> Self {
        Self {
            drain_delay: Duration::from_secs(5),
            timeout: Duration::from_secs(30),
        }
    }
}

impl Config {
    /// Read the configuration: the TOML file at `path`, if given, overlaid
    /// with `WEBPUSH_*` environment variables. The result is validated.
    ///
    /// # Errors
    ///
    /// The file cannot be read or parsed, a setting has the wrong type or an
    /// unknown name, or [`Config::validate`] fails.
    pub fn load(path: Option<&std::path::Path>) -> Result<Self, BoxError> {
        let mut figment = Figment::new();
        if let Some(path) = path {
            figment = figment.merge(Toml::file_exact(path));
        }
        let cfg: Self = figment
            // `WEBPUSH_CONFIG` names the file; it is not a setting.
            .merge(Env::prefixed("WEBPUSH_").ignore(&["config"]).split("__"))
            .extract()?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Parse a configuration from TOML text, without environment overrides.
    ///
    /// # Errors
    ///
    /// As for [`Config::load`].
    pub fn from_toml(text: &str) -> Result<Self, BoxError> {
        let cfg: Self = Figment::from(Toml::string(text)).extract()?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Check settings that are valid alone but not together.
    ///
    /// # Errors
    ///
    /// A description of the first problem found.
    pub fn validate(&self) -> Result<(), BoxError> {
        let origin = self.origin.trim_end_matches('/');
        if origin != self.origin || !self.origin.starts_with("https://") {
            return Err("origin must be an https:// URL without a trailing slash".into());
        }
        if self.push.max_payload < 4096 {
            return Err("push.max_payload must be at least 4096 (RFC 8030 §7.2)".into());
        }
        if self.websocket.max_session.is_some_and(|d| d.is_zero()) {
            return Err("websocket.max_session must be positive".into());
        }
        if self.websocket.backlog_batch == 0 || self.websocket.queue == 0 {
            return Err("websocket.backlog_batch and websocket.queue must be positive".into());
        }
        if self.public.max_connections == 0 {
            return Err("public.max_connections must be positive".into());
        }
        match &self.cluster {
            None if self.role != Role::All => {
                return Err("role endpoint and connect require a [cluster] section".into());
            }
            Some(c) => {
                if self.internal.is_none() {
                    return Err("[cluster] requires an [internal] listener".into());
                }
                if c.token.len() < 16 {
                    return Err("cluster.token must be at least 16 characters".into());
                }
                if !c.node_url.starts_with("http://") && !c.node_url.starts_with("https://") {
                    return Err("cluster.node_url must be an http:// or https:// URL".into());
                }
            }
            None => {}
        }
        if self.bridges.any() && self.registration.secret_keys.is_empty() {
            return Err("bridges require registration.secret_keys".into());
        }
        if self.registration.secret_keys.iter().any(|k| k.len() < 32) {
            return Err("registration.secret_keys must be at least 32 characters each".into());
        }
        Ok(())
    }
}

impl Bridges {
    /// Whether any bridge is configured.
    #[must_use]
    pub fn any(&self) -> bool {
        let configured: [bool; 2] = [
            #[cfg(feature = "fcm")]
            self.fcm.is_some(),
            #[cfg(not(feature = "fcm"))]
            false,
            #[cfg(feature = "apns")]
            self.apns.is_some(),
            #[cfg(not(feature = "apns"))]
            false,
        ];
        configured.contains(&true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_config_uses_defaults() {
        let cfg = Config::from_toml(r#"origin = "https://push.example.net""#).unwrap();
        assert_eq!(cfg.role, Role::All);
        assert_eq!(cfg.push.max_payload, 4096);
        assert_eq!(cfg.websocket.ping_interval, Duration::from_secs(60));
        assert!(matches!(cfg.store, Store::Memory));
    }

    #[test]
    fn durations_and_sections_parse() {
        let cfg = Config::from_toml(
            r#"
            role = "connect"
            origin = "https://push.example.net"
            [internal]
            listen = "127.0.0.1:8081"
            [cluster]
            node_url = "http://10.0.0.1:8081"
            token = "0123456789abcdef0123"
            [store.bigtable]
            endpoint = "http://127.0.0.1:8086"
            project = "p"
            instance = "i"
            table = "t"
            [user_agents]
            expire_after = "60days"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.role, Role::Connect);
        assert_eq!(
            cfg.user_agents.expire_after,
            Some(Duration::from_secs(60 * 24 * 3600))
        );
    }

    #[test]
    fn example_file_parses() {
        let cfg = Config::from_toml(include_str!("../../../config/webpush.example.toml")).unwrap();
        let defaults = Config::from_toml(r#"origin = "https://push.example.net""#).unwrap();
        // The example documents the defaults; spot-check that it agrees.
        assert_eq!(cfg.push.max_ttl, defaults.push.max_ttl);
        assert_eq!(cfg.websocket.queue, defaults.websocket.queue);
        assert_eq!(cfg.shutdown.drain_delay, defaults.shutdown.drain_delay);
        assert_eq!(cfg.public.max_connections, defaults.public.max_connections);
    }

    #[test]
    fn inconsistent_settings_are_rejected() {
        let origin = r#"origin = "https://push.example.net""#;
        for bad in [
            r#"origin = "http://push.example.net""#.to_owned(),
            r#"origin = "https://push.example.net/""#.to_owned(),
            format!("{origin}\nrole = \"endpoint\""),
            format!("{origin}\n[push]\nmax_payload = 100"),
            format!("{origin}\nunknown = 1"),
        ] {
            assert!(Config::from_toml(&bad).is_err(), "{bad}");
        }
    }
}
