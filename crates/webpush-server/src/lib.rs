//! A reference implementation of an IETF Web Push service.
//!
//! | Specification | Title | Where |
//! |---|---|---|
//! | [RFC 8030] | Generic Event Delivery Using HTTP Push | push, TTL, Urgency, Topic, receipts |
//! | [RFC 8292] | Voluntary Application Server Identification (VAPID) | restricted subscriptions |
//! | [RFC 8291] | Message Encryption for Web Push | `webpush_crypto::ece::webpush` |
//! | [RFC 8188] | Encrypted Content-Encoding for HTTP | `webpush_crypto::ece` |
//! | Firefox push protocol | WebSocket protocol between Firefox and its push server | user agent sessions |
//!
//! The application server side follows the RFCs. The user agent side of
//! RFC 8030 relies on HTTP/2 server push, which browsers have removed, so
//! user agents connect over the WebSocket protocol Firefox uses instead, and
//! mobile applications register a platform device token through the
//! registration API and receive messages through a bridge (FCM, APNs).
//!
//! # Deployment
//!
//! One binary runs in one of three roles (see [`config::Role`]):
//!
//! ```text
//!                  application servers                user agents
//!                          |                               |
//!                   +------+------+                 +------+------+
//!                   |  endpoint   |  ... replicas   |   connect   |  ... nodes
//!                   +------+------+                 +------+------+
//!                          |    POST /internal/v1/notify   ^
//!                          +-------------------------------+
//!                          |                               |
//!                          +-----------> store <-----------+
//!                               messages, subscriptions,
//!                               routes (which node holds which session)
//! ```
//!
//! `role = "all"` runs both halves in one process; it needs no cluster and
//! suits development and small deployments.
//!
//! # Embedding
//!
//! ```no_run
//! # async fn run() -> Result<(), webpush_server::BoxError> {
//! use webpush_server::{Server, config::Config};
//!
//! let cfg = Config::load(Some("webpush.toml".as_ref()))?;
//! let store = webpush_store::MemoryStore::new();
//! Server::new(cfg, store).run(webpush_server::shutdown::signal()).await
//! # }
//! ```
//!
//! [RFC 8030]: https://www.rfc-editor.org/rfc/rfc8030
//! [RFC 8188]: https://www.rfc-editor.org/rfc/rfc8188
//! [RFC 8291]: https://www.rfc-editor.org/rfc/rfc8291
//! [RFC 8292]: https://www.rfc-editor.org/rfc/rfc8292

pub mod config;
pub mod shutdown;
pub mod telemetry;

mod app;
mod endpoint;
mod error;
mod headers;
mod hub;
mod internal;
mod maintenance;
mod notify;
mod receipts;
mod registration;
mod session;
mod subscription;
mod transport;

use std::{future::Future, sync::Arc};

use axum::{Router, middleware, routing::get};
use tokio::net::TcpListener;
use tower_http::cors::{AllowOrigin, CorsLayer};
use webpush_bridge::SharedBridge;
use webpush_store::Store;

use crate::{
    app::App,
    config::{Config, Cors},
    shutdown::Shutdown,
    transport::Listener,
};

pub use webpush_store::BoxError;

/// A configured push service, ready to run.
pub struct Server<S> {
    /// Settings.
    cfg: Config,
    /// Persistent state.
    store: S,
    /// Platform push services.
    bridges: Vec<SharedBridge>,
    /// Sockets bound by the caller, instead of the configured addresses.
    listeners: Option<(TcpListener, Option<TcpListener>)>,
}

impl<S: Store> Server<S> {
    /// A server for `cfg` backed by `store`, without bridges.
    pub fn new(cfg: Config, store: S) -> Self {
        Self {
            cfg,
            store,
            bridges: Vec::new(),
            listeners: None,
        }
    }

    /// Add a bridge. User agents register with it under
    /// [`Bridge::name`](webpush_bridge::Bridge::name).
    #[must_use]
    pub fn bridge(mut self, bridge: SharedBridge) -> Self {
        self.bridges.push(bridge);
        self
    }

    /// Serve on sockets the caller bound, instead of `public.listen` and
    /// `internal.listen`. Useful for tests and socket activation.
    #[must_use]
    pub fn listeners(mut self, public: TcpListener, internal: Option<TcpListener>) -> Self {
        self.listeners = Some((public, internal));
        self
    }

    /// Run until `signal` resolves, then shut down gracefully (see
    /// [`config::Shutdown`]).
    ///
    /// # Errors
    ///
    /// Returns before serving if the configuration is invalid, TLS material
    /// cannot be loaded, or a listener cannot be bound.
    pub async fn run(self, signal: impl Future<Output = ()> + Send) -> Result<(), BoxError> {
        let cfg = self.cfg;
        cfg.validate()?;
        // reqwest (cluster forwards, bridges) needs a process-wide provider.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (public, internal) = match self.listeners {
            Some(l) => l,
            None => (
                TcpListener::bind(cfg.public.listen).await?,
                match &cfg.internal {
                    Some(i) => Some(TcpListener::bind(i.listen).await?),
                    None => None,
                },
            ),
        };
        let tls = cfg
            .public
            .tls
            .as_ref()
            .map(transport::tls_config)
            .transpose()?;
        if tls.is_none() {
            tracing::warn!("public listener without TLS; a proxy in front must terminate TLS");
        }
        telemetry::prometheus();

        let shutdown = Shutdown::default();
        let app = App::new(cfg, self.store, self.bridges, shutdown.clone())?;
        let public = Listener {
            tcp: public,
            tls,
            max_connections: app.cfg.public.max_connections,
            handshake_timeout: app.cfg.public.handshake_timeout,
            name: "public",
        };
        shutdown.tasks.spawn(transport::serve(
            public,
            public_router(&app),
            shutdown.clone(),
        ));
        if let Some(tcp) = internal {
            let internal = Listener {
                tcp,
                tls: None,
                max_connections: 1024,
                handshake_timeout: app.cfg.public.handshake_timeout,
                name: "internal",
            };
            let router = internal::router(app.clone());
            shutdown
                .tasks
                .spawn(transport::serve(internal, router, shutdown.clone()));
        }
        if app.cfg.role.serves_endpoint() {
            maintenance::spawn(&app);
        }
        tracing::info!(role = ?app.cfg.role, "serving");

        let s = &app.cfg.shutdown;
        shutdown.run(signal, s.drain_delay, s.timeout).await;
        Ok(())
    }
}

/// The public router for the configured role.
fn public_router<S: Store>(app: &Arc<App<S>>) -> Router {
    let mut router = Router::new();
    if app.cfg.role.serves_endpoint() {
        let mut api = endpoint::router(app);
        if let Some(cors) = cors(&app.cfg.cors) {
            api = api.layer(cors);
        }
        router = router.merge(api);
        if !app.bridges.is_empty() {
            router = router.merge(registration::router());
        }
    }
    if app.cfg.role.connects() {
        router = router.route("/", get(session::upgrade::<S>));
    }
    router
        .route_layer(middleware::from_fn(telemetry::observe))
        .with_state(app.clone())
}

/// CORS for the application server API, if any origin is allowed.
fn cors(cfg: &Cors) -> Option<CorsLayer> {
    use axum::http::{HeaderName, HeaderValue, Method, header};
    if cfg.allowed_origins.is_empty() {
        return None;
    }
    let origin = if cfg.allowed_origins.iter().any(|o| o == "*") {
        AllowOrigin::any()
    } else {
        AllowOrigin::list(
            cfg.allowed_origins
                .iter()
                .filter_map(|o| HeaderValue::from_str(o).ok()),
        )
    };
    let name = HeaderName::from_static;
    Some(
        CorsLayer::new()
            .allow_origin(origin)
            .allow_methods([Method::GET, Method::POST, Method::DELETE])
            .allow_headers([
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                header::CONTENT_ENCODING,
                header::LINK,
                name("ttl"),
                name("urgency"),
                name("topic"),
                name("prefer"),
            ])
            .expose_headers([header::LOCATION, header::LINK, name("ttl")]),
    )
}

/// The bridges enabled in `cfg`, built from their settings.
///
/// # Errors
///
/// A bridge's credentials cannot be loaded.
pub fn bridges_from_config(cfg: &Config) -> Result<Vec<SharedBridge>, BoxError> {
    #[allow(unused_mut)]
    let mut out: Vec<SharedBridge> = Vec::new();
    #[cfg(feature = "fcm")]
    if let Some(fcm) = &cfg.bridges.fcm {
        out.push(Arc::new(webpush_fcm::Fcm::new(fcm)?));
    }
    #[cfg(feature = "apns")]
    if let Some(apns) = &cfg.bridges.apns {
        out.push(Arc::new(webpush_apns::Apns::new(apns)?));
    }
    #[cfg(not(any(feature = "fcm", feature = "apns")))]
    let _ = cfg;
    Ok(out)
}
