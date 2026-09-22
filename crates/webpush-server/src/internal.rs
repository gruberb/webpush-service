//! The internal listener: probes, metrics, and delivery between nodes. It
//! speaks plaintext HTTP and must only be reachable from inside the
//! deployment.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use webpush_store::Store;

use crate::{
    app::App,
    hub::Notified,
    notify::{Envelope, NOTIFY_PATH},
    telemetry,
};

/// The internal router.
pub fn router<S: Store>(app: Arc<App<S>>) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/ready", get(ready::<S>))
        .route("/version", get(version))
        .route("/metrics", get(|| async { telemetry::render() }))
        .route(NOTIFY_PATH, post(deliver::<S>))
        .with_state(app)
}

/// Ready when not shutting down and the store answers a read.
async fn ready<S: Store>(State(app): State<Arc<App<S>>>) -> StatusCode {
    if app.shutdown.draining.is_cancelled() {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    // Any read works as a probe; this id is never issued.
    match app.store.user_agent(&"0".repeat(32)).await {
        Ok(_) => StatusCode::OK,
        Err(e) => {
            tracing::warn!(error = %e, "readiness probe");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

/// Crate name and version.
async fn version() -> impl IntoResponse {
    Json(serde_json::json!({
        "name": env!("CARGO_PKG_NAME"),
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// An event forwarded by another node. 200 when a listener on this node took
/// it, 404 when this node holds no such listener (the sender then removes the
/// stale route).
async fn deliver<S: Store>(
    State(app): State<Arc<App<S>>>,
    headers: HeaderMap,
    Json(envelope): Json<Envelope>,
) -> StatusCode {
    let Some(cluster) = &app.cluster else {
        return StatusCode::NOT_FOUND;
    };
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if !token.is_some_and(|t| cluster.authorized(t)) {
        return StatusCode::UNAUTHORIZED;
    }
    let Some((to, event)) = envelope.open() else {
        return StatusCode::BAD_REQUEST;
    };
    match app.hub.notify(&to, event) {
        Notified::Delivered => StatusCode::OK,
        Notified::Dropped => {
            metrics::counter!(telemetry::LISTENER_DROPPED).increment(1);
            StatusCode::OK
        }
        Notified::Absent => StatusCode::NOT_FOUND,
    }
}
