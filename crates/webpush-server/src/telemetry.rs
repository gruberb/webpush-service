//! Logs and metrics.
//!
//! Logs go through `tracing`; [`init_logging`] installs the subscriber the
//! binary uses. Metrics go through the `metrics` facade into a Prometheus
//! recorder, rendered on the internal listener's `/metrics`.
//!
//! Neither ever contains a capability URL, a message body, or a device
//! token (RFC 8030 §8.5). Request metrics are labelled with the route
//! template (`/push/{id}`), never the path.
//!
//! | Metric | Type | Labels |
//! |---|---|---|
//! | `webpush_http_requests_total` | counter | `method`, `route`, `status` |
//! | `webpush_http_request_duration_seconds` | histogram | `method`, `route` |
//! | `webpush_connections` | gauge | `listener` |
//! | `webpush_sessions` | gauge | |
//! | `webpush_messages_accepted_total` | counter | `via` (`websocket`, or the bridge name) |
//! | `webpush_messages_delivered_total` | counter | `via` (`websocket`, or the bridge name) |
//! | `webpush_bridge_errors_total` | counter | `bridge`, `kind` |
//! | `webpush_receipts_total` | counter | `status` |
//! | `webpush_remote_notify_total` | counter | `outcome` |
//! | `webpush_user_agents_expired_total` | counter | |
//! | `webpush_listener_dropped_total` | counter | |

use std::{sync::OnceLock, time::Instant};

use axum::{
    extract::{MatchedPath, Request},
    middleware::Next,
    response::Response,
};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use crate::config::{Log, LogFormat};

/// Open connections, by listener.
pub const CONNECTIONS: &str = "webpush_connections";
/// Open user agent sessions.
pub const SESSIONS: &str = "webpush_sessions";
/// Push messages accepted from application servers.
pub const ACCEPTED: &str = "webpush_messages_accepted_total";
/// Messages handed to a user agent session or a bridge.
pub const DELIVERED: &str = "webpush_messages_delivered_total";
/// Bridge failures.
pub const BRIDGE_ERRORS: &str = "webpush_bridge_errors_total";
/// Receipts queued.
pub const RECEIPTS: &str = "webpush_receipts_total";
/// Deliveries forwarded to another node.
pub const REMOTE_NOTIFY: &str = "webpush_remote_notify_total";
/// User agents deleted for inactivity.
pub const EXPIRED: &str = "webpush_user_agents_expired_total";
/// Listeners dropped for falling behind.
pub const LISTENER_DROPPED: &str = "webpush_listener_dropped_total";

/// Install the global `tracing` subscriber. `RUST_LOG` overrides
/// [`Log::level`] when set.
///
/// # Errors
///
/// The filter directive does not parse, or a subscriber is already
/// installed.
pub fn init_logging(cfg: &Log) -> Result<(), crate::BoxError> {
    let filter = match std::env::var("RUST_LOG") {
        Ok(env) if !env.is_empty() => EnvFilter::try_new(env)?,
        _ => EnvFilter::try_new(&cfg.level)?,
    };
    let registry = tracing_subscriber::registry().with(filter);
    match cfg.format {
        LogFormat::Text => registry.with(fmt::layer()).try_init()?,
        LogFormat::Json => registry
            .with(fmt::layer().json().flatten_event(true))
            .try_init()?,
    }
    Ok(())
}

/// The process-wide Prometheus recorder, installed on first use. Tests start
/// several servers in one process, and they share it.
pub fn prometheus() -> &'static PrometheusHandle {
    static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();
    HANDLE.get_or_init(|| {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        // Fails only if the embedding application installed its own
        // recorder; `/metrics` is then empty and the application's wins.
        if metrics::set_global_recorder(recorder).is_err() {
            tracing::warn!("a metrics recorder is already installed");
        }
        handle
    })
}

/// Render the metrics in the Prometheus text format.
#[must_use]
pub fn render() -> String {
    let handle = prometheus();
    handle.run_upkeep();
    handle.render()
}

/// Increments a gauge on creation and decrements it on drop.
pub struct Gauge {
    /// The gauge, with its labels.
    gauge: metrics::Gauge,
}

impl Gauge {
    /// Increment `name`, labelled `listener = label` unless `label` is empty.
    #[must_use]
    pub fn new(name: &'static str, label: &'static str) -> Self {
        let gauge = if label.is_empty() {
            metrics::gauge!(name)
        } else {
            metrics::gauge!(name, "listener" => label)
        };
        gauge.increment(1.0);
        Self { gauge }
    }
}

impl Drop for Gauge {
    fn drop(&mut self) {
        self.gauge.decrement(1.0);
    }
}

/// Request log and metrics. Only the method, route template, status, and
/// latency are recorded; paths are capability URLs (RFC 8030 §8.5).
pub async fn observe(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unmatched".to_owned(), |p| p.as_str().to_owned());
    let start = Instant::now();
    let resp = next.run(req).await;
    let elapsed = start.elapsed();
    let status = resp.status().as_u16();
    tracing::info!(
        %method,
        route,
        status,
        latency_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        "request"
    );
    metrics::counter!(
        "webpush_http_requests_total",
        "method" => method.to_string(),
        "route" => route.clone(),
        "status" => status.to_string()
    )
    .increment(1);
    metrics::histogram!(
        "webpush_http_request_duration_seconds",
        "method" => method.to_string(),
        "route" => route
    )
    .record(elapsed.as_secs_f64());
    resp
}
