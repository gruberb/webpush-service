//! Registration API for user agents reached through a bridge.
//!
//! A mobile application cannot hold a WebSocket in the background, so it
//! registers the device token its platform issued (FCM, APNs) and manages
//! subscriptions over plain HTTPS. Messages then go to the platform, which
//! delivers them to the application.
//!
//! ```text
//!  POST   /v1/user-agents                                  {bridge, appID, token}
//!           201 {uaid, secret}                             no authentication
//!  GET    /v1/user-agents/{uaid}                           200 {uaid, subscriptions}
//!  PUT    /v1/user-agents/{uaid}                           {token}             204
//!  DELETE /v1/user-agents/{uaid}                                               204
//!  PUT    /v1/user-agents/{uaid}/subscriptions/{channelID} {key?}  201 new, 200 existing
//!  DELETE /v1/user-agents/{uaid}/subscriptions/{channelID}                     204
//! ```
//!
//! Every call after the first sends `Authorization: Bearer {secret}`. The
//! secret is `base64url(HMAC-SHA256(key, uaid))`: the service verifies it
//! without storing it, and a key is rotated by adding its successor in
//! front of it in `registration.secret_keys`.
//!
//! The client names its subscriptions, as it does over the WebSocket, so
//! creating one is an idempotent `PUT`. `GET` and `PUT` on the user agent
//! count as activity for `user_agents.expire_after`; an application should
//! call `GET` periodically, which also lets it compare its subscriptions
//! with the service's.

use std::sync::Arc;

use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{post, put},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::hmac;
use serde::Deserialize;
use serde_json::json;
use webpush_store::{BridgeAddress, Store, UserAgent, is_uaid, new_uaid, now_ms};

use crate::{
    app::App,
    error::{Error, Result},
    subscription::{self, Registered},
};

/// Longest device token accepted. Platform tokens are far shorter.
const MAX_TOKEN: usize = 4096;

/// Keys that derive and verify bridged user agents' secrets.
pub struct Secrets {
    /// Signing key first, then older keys still accepted.
    keys: Vec<hmac::Key>,
}

impl Secrets {
    /// Secrets derived from `keys`, the first of which signs.
    pub fn new(keys: &[String]) -> Self {
        Self {
            keys: keys
                .iter()
                .map(|k| hmac::Key::new(hmac::HMAC_SHA256, k.as_bytes()))
                .collect(),
        }
    }

    /// The secret for `uaid`, or `None` without keys.
    fn issue(&self, uaid: &str) -> Option<String> {
        let tag = hmac::sign(self.keys.first()?, uaid.as_bytes());
        Some(URL_SAFE_NO_PAD.encode(tag.as_ref()))
    }

    /// Whether `secret` was issued for `uaid` by any configured key. The
    /// comparison is constant time.
    fn verify(&self, uaid: &str, secret: &str) -> bool {
        let Ok(tag) = URL_SAFE_NO_PAD.decode(secret) else {
            return false;
        };
        self.keys
            .iter()
            .any(|k| hmac::verify(k, uaid.as_bytes(), &tag).is_ok())
    }
}

/// The registration routes.
pub fn router<S: Store>() -> Router<Arc<App<S>>> {
    Router::new()
        .route("/v1/user-agents", post(create::<S>))
        .route(
            "/v1/user-agents/{uaid}",
            axum::routing::get(read::<S>)
                .put(update_token::<S>)
                .delete(delete::<S>),
        )
        .route(
            "/v1/user-agents/{uaid}/subscriptions/{channel}",
            put(subscribe::<S>).delete(unsubscribe::<S>),
        )
}

/// `POST /v1/user-agents` body.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    /// A configured bridge, for example `fcm`.
    bridge: String,
    /// An application configured for that bridge.
    #[serde(rename = "appID")]
    app_id: String,
    /// The device token.
    token: String,
}

/// `PUT /v1/user-agents/{uaid}` body.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateToken {
    /// The new device token.
    token: String,
}

/// `PUT .../subscriptions/{channelID}` body.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Subscribe {
    /// Application server key to restrict the subscription to
    /// (RFC 8292 §4.1), base64url.
    key: Option<String>,
}

/// Device tokens are opaque, but they end up in URLs and JSON sent to the
/// platform, so only the characters platforms use are accepted.
fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'.'))
}

/// Check the bearer secret for `uaid` and load the user agent.
async fn authorize<S: Store>(app: &App<S>, headers: &HeaderMap, uaid: &str) -> Result<UserAgent> {
    let secret = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if !is_uaid(uaid) || !secret.is_some_and(|s| app.secrets.verify(uaid, s)) {
        return Err(Error::unauthorized("Bearer"));
    }
    match app.store.user_agent(uaid).await? {
        Some(ua) if ua.bridge.is_some() => Ok(ua),
        _ => Err(StatusCode::NOT_FOUND.into()),
    }
}

/// The push endpoint URL of a subscription.
fn endpoint<S>(app: &App<S>, push: &str) -> String {
    format!("{}/push/{push}", app.origin())
}

/// Register a bridged user agent.
async fn create<S: Store>(State(app): State<Arc<App<S>>>, Json(body): Json<Create>) -> Result {
    let known = app
        .bridges
        .get(body.bridge.as_str())
        .is_some_and(|b| b.has_app(&body.app_id));
    if !known || !valid_token(&body.token) {
        return Err(StatusCode::BAD_REQUEST.into());
    }
    let ua = UserAgent {
        uaid: new_uaid(),
        bridge: Some(BridgeAddress {
            bridge: body.bridge,
            app_id: body.app_id,
            token: body.token,
        }),
        last_seen: now_ms(),
    };
    let secret = app
        .secrets
        .issue(&ua.uaid)
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    app.store.create_user_agent(&ua).await?;
    let location = format!("{}/v1/user-agents/{}", app.origin(), ua.uaid);
    Ok((
        StatusCode::CREATED,
        [(header::LOCATION, location)],
        Json(json!({ "uaid": ua.uaid, "secret": secret })),
    )
        .into_response())
}

/// The user agent and its subscriptions. Counts as activity.
async fn read<S: Store>(
    State(app): State<Arc<App<S>>>,
    Path(uaid): Path<String>,
    headers: HeaderMap,
) -> Result {
    authorize(&app, &headers, &uaid).await?;
    app.store.touch_user_agent(&uaid, now_ms()).await?;
    let subs: Vec<_> = app
        .store
        .subscriptions(&uaid)
        .await?
        .iter()
        .map(|s| json!({ "channelID": s.channel_id, "pushEndpoint": endpoint(&app, &s.push) }))
        .collect();
    Ok(Json(json!({ "uaid": uaid, "subscriptions": subs })).into_response())
}

/// Replace the device token, after the platform issued a new one. Counts as
/// activity.
async fn update_token<S: Store>(
    State(app): State<Arc<App<S>>>,
    Path(uaid): Path<String>,
    headers: HeaderMap,
    Json(body): Json<UpdateToken>,
) -> Result<StatusCode> {
    authorize(&app, &headers, &uaid).await?;
    if !valid_token(&body.token) {
        return Err(StatusCode::BAD_REQUEST.into());
    }
    app.store.update_bridge_token(&uaid, &body.token).await?;
    app.store.touch_user_agent(&uaid, now_ms()).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Delete the user agent and all its subscriptions.
async fn delete<S: Store>(
    State(app): State<Arc<App<S>>>,
    Path(uaid): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode> {
    authorize(&app, &headers, &uaid).await?;
    let receipts = app.store.delete_user_agent(&uaid).await?;
    app.notify_receipts(receipts).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Create a subscription, or confirm an identical one.
async fn subscribe<S: Store>(
    State(app): State<Arc<App<S>>>,
    Path((uaid, channel)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result {
    authorize(&app, &headers, &uaid).await?;
    // The body is optional: an unrestricted subscription needs none.
    let body: Subscribe = if body.is_empty() {
        Subscribe::default()
    } else {
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?
    };
    let channel = subscription::channel_id(&channel).ok_or(StatusCode::BAD_REQUEST)?;
    let vapid = match body.key.as_deref().map(subscription::vapid_key) {
        None => None,
        Some(Some(k)) => Some(k),
        Some(None) => return Err(StatusCode::BAD_REQUEST.into()),
    };
    let (status, sub) = match subscription::register(&app.store, &uaid, &channel, vapid).await? {
        Registered::Created(sub) => (StatusCode::CREATED, sub),
        Registered::Existing(sub) => (StatusCode::OK, sub),
        Registered::Conflict => return Err(StatusCode::CONFLICT.into()),
    };
    let reply = json!({ "channelID": sub.channel_id, "pushEndpoint": endpoint(&app, &sub.push) });
    Ok((status, Json(reply)).into_response())
}

/// Delete a subscription. Its undelivered messages owe 410 receipts.
async fn unsubscribe<S: Store>(
    State(app): State<Arc<App<S>>>,
    Path((uaid, channel)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response> {
    authorize(&app, &headers, &uaid).await?;
    let channel = subscription::channel_id(&channel).ok_or(StatusCode::NOT_FOUND)?;
    if app.store.channel(&uaid, &channel).await?.is_none() {
        return Err(StatusCode::NOT_FOUND.into());
    }
    let receipts = app.store.delete_subscription(&uaid, &channel).await?;
    app.notify_receipts(receipts).await;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_verify_across_rotation() {
        let old = Secrets::new(&["k".repeat(32)]);
        let rotated = Secrets::new(&["n".repeat(32), "k".repeat(32)]);
        let uaid = new_uaid();
        let issued = old.issue(&uaid).unwrap();
        assert!(
            rotated.verify(&uaid, &issued),
            "old secrets survive rotation"
        );
        assert!(
            !rotated.verify(&new_uaid(), &issued),
            "secret bound to its uaid"
        );
        assert_ne!(rotated.issue(&uaid).unwrap(), issued, "new key signs");
        assert!(!old.verify(&uaid, "not base64!"));
    }

    #[test]
    fn tokens() {
        assert!(valid_token("dGVzdA:APA91b-x_y.z"));
        assert!(!valid_token(""));
        assert!(!valid_token("a/../b"));
        assert!(!valid_token(&"a".repeat(MAX_TOKEN + 1)));
    }
}
