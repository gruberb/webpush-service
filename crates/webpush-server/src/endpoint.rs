//! The application server API: RFC 8030 push and message resources with
//! RFC 8292 enforcement, and the routes to receipt streams.
//!
//! A push is validated in a fixed order, so each failure maps to exactly one
//! status:
//!
//! ```text
//!  POST /push/{id}
//!    push id unknown ...................................... 404
//!    TTL, Urgency, Topic, receipt Link malformed .......... 400
//!    restricted subscription, no VAPID credentials ........ 401
//!    VAPID invalid, or not the restricting key ............ 403
//!    aes128gcm keyid equals the VAPID key ................. 400
//!    session user agent: store, notify the session ........ 201 / 202
//!    bridged user agent: hand to the bridge ............... 201, or see below
//! ```
//!
//! A message for a bridged user agent is not stored: the platform service
//! holds it until the device is reachable. Bridge failures map to:
//!
//! | Bridge error | Status |
//! |---|---|
//! | device token gone (the user agent is deleted) | 410 |
//! | payload over the platform limit | 413 |
//! | platform rate limiting | 429, with `Retry-After` when known |
//! | anything else | 502 |
//!
//! Bodies over the limit are refused with 413 by the router's body limit
//! before the handler runs. Endpoints and headers are listed in
//! `docs/http-reference.md`.

use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    response::{AppendHeaders, IntoResponse},
    routing::post,
};
use webpush_bridge::{Address, Notification as BridgeMessage, Priority};
use webpush_crypto::{ece, vapid};
use webpush_store::{
    BridgeAddress, Message, Recipient, Store, Subscription, Urgency, new_id, now_ms,
};

use crate::{
    app::App,
    error::{Error, Result},
    headers::{self, Invalid},
    hub::{Event, Notification},
    receipts, telemetry,
};

/// Link relation for a receipt subscription (RFC 8030 §9.1).
pub const REL_RECEIPT: &str = "urn:ietf:params:push:receipt";

/// The application server routes. Push bodies above `push.max_payload`
/// octets are refused with 413 while they are read, before they are
/// buffered.
pub fn router<S: Store>(app: &App<S>) -> Router<Arc<App<S>>> {
    Router::new()
        .route("/push/{id}", post(push::<S>))
        .route(
            "/message/{id}",
            axum::routing::get(read_message::<S>).delete(withdraw_message::<S>),
        )
        .route(
            "/receipt-subscription/{id}",
            axum::routing::get(receipts::stream::<S>).delete(delete_receipt_sub::<S>),
        )
        .layer(DefaultBodyLimit::max(app.cfg.push.max_payload))
}

/// Reject ids this service could not have issued before they reach storage.
pub fn valid(id: String) -> Result<String> {
    if headers::is_id(&id) {
        Ok(id)
    } else {
        Err(StatusCode::NOT_FOUND.into())
    }
}

/// A `Link` header value (RFC 8288).
fn link(target: &str, rel: &str) -> String {
    format!("<{target}>; rel=\"{rel}\"")
}

/// VAPID enforcement (RFC 8292 §4.2). Returns the verified key, if any.
fn check_vapid(
    headers: &HeaderMap,
    restricted: Option<&[u8; 65]>,
    origin: &str,
) -> Result<Option<[u8; 65]>> {
    let forbidden = || Error::from(StatusCode::FORBIDDEN);
    let creds = match headers.get(header::AUTHORIZATION).map(|v| v.to_str()) {
        None => None,
        Some(Err(_)) => return Err(forbidden()),
        // Other schemes are not VAPID credentials; treat them as absent.
        Some(Ok(value)) => match vapid::parse_authorization(value) {
            Err(vapid::Error::NotVapid) => None,
            Err(_) => return Err(forbidden()),
            Ok(c) => Some(c),
        },
    };
    let Some(creds) = creds else {
        return match restricted {
            // The only authentication this API asks for is VAPID.
            Some(_) => Err(Error::unauthorized("vapid")),
            None => Ok(None),
        };
    };
    // Invalid credentials are refused even on unrestricted subscriptions
    // (RFC 8292 §4.2 allows it), and nothing from them is used.
    vapid::verify(&creds, origin, now_ms() / 1000).map_err(|_| forbidden())?;
    if restricted.is_some_and(|k| *k != creds.k) {
        return Err(forbidden());
    }
    Ok(Some(creds.k))
}

/// A validated push request, before delivery.
struct Push {
    /// The subscription it was sent to.
    sub: Subscription,
    /// Effective TTL in seconds.
    ttl: u32,
    /// Delivery urgency.
    urgency: Urgency,
    /// Replacement key.
    topic: Option<String>,
    /// Whether the application server asked for a receipt.
    respond_async: bool,
    /// Receipt subscription named by a `Link`, already checked to exist.
    rsub_link: Option<String>,
    /// `Content-Type`.
    ctype: Option<String>,
    /// `Content-Encoding`.
    cenc: Option<String>,
    /// The encrypted body.
    body: Bytes,
}

/// Send a push message (RFC 8030 §5).
async fn push<S: Store>(
    State(app): State<Arc<App<S>>>,
    Path(push_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result {
    let push_id = valid(push_id)?;
    let sub = app
        .store
        .subscription_by_push(&push_id)
        .await?
        .ok_or(StatusCode::NOT_FOUND)?;

    // The parsed TTL saturates at 2^31, which always fits a u32.
    let max_ttl = u32::try_from(app.cfg.push.max_ttl.as_secs()).unwrap_or(u32::MAX);
    let ttl = u32::try_from(headers::ttl(&headers)?)
        .unwrap_or(u32::MAX)
        .min(max_ttl);
    let urgency = headers::urgency(&headers)?.unwrap_or(Urgency::Normal);
    let topic = headers::topic(&headers)?;
    let respond_async = headers::prefer(&headers).respond_async;
    let rsub_link = match headers::link(&headers, REL_RECEIPT) {
        Some(target) if respond_async => {
            let id = headers::resource_id(&target, app.origin(), "/receipt-subscription/")
                .ok_or(Invalid)?;
            if !app.store.receipt_sub_exists(id).await? {
                return Err(Invalid.into());
            }
            Some(id.to_owned())
        }
        _ => None,
    };

    let key = check_vapid(&headers, sub.vapid.as_ref(), app.origin())?;
    let text = |name| {
        headers
            .get(name)
            .and_then(|v: &HeaderValue| v.to_str().ok())
            .map(str::to_owned)
    };
    let cenc = text(header::CONTENT_ENCODING);
    // The application server key must not double as the message encryption
    // key (RFC 8292 §3.2). Only the header is parsed; the payload stays opaque.
    if let Some(k) = key
        && cenc.as_deref() == Some("aes128gcm")
        && ece::parse_header(&body).is_ok_and(|(h, _)| h.keyid == k)
    {
        return Err(Invalid.into());
    }

    let push = Push {
        sub,
        ttl,
        urgency,
        topic,
        respond_async,
        rsub_link,
        ctype: text(header::CONTENT_TYPE),
        cenc,
        body,
    };
    let ua = app
        .store
        .user_agent(&push.sub.uaid)
        .await?
        .ok_or(StatusCode::NOT_FOUND)?;
    match ua.bridge {
        Some(to) => bridge(&app, push, &to).await,
        None => store_and_notify(&app, push, push_id).await,
    }
}

/// Deliver to a user agent with a session: store the message, then tell the
/// session wherever it is. It reads the message from storage if it is not
/// connected now.
async fn store_and_notify<S: Store>(app: &App<S>, p: Push, push_id: String) -> Result {
    let rsub = match p.rsub_link {
        Some(id) => Some(id),
        None if p.respond_async => Some(app.store.create_receipt_sub().await?),
        None => None,
    };
    let accepted = now_ms();
    let m = Message {
        id: new_id(),
        uaid: p.sub.uaid.clone(),
        channel_id: p.sub.channel_id,
        push: push_id,
        topic: p.topic,
        body: p.body,
        ctype: p.ctype,
        cenc: p.cenc,
        ttl: p.ttl,
        urgency: p.urgency,
        accepted,
        expiry: accepted + u64::from(p.ttl) * 1000,
        rsub,
    };
    app.store.insert_message(&m).await?;
    metrics::counter!(telemetry::ACCEPTED, "via" => "websocket").increment(1);

    let o = app.origin();
    let mut out = vec![
        (header::LOCATION, format!("{o}/message/{}", m.id)),
        (HeaderName::from_static("ttl"), p.ttl.to_string()),
    ];
    if let Some(rsub) = &m.rsub {
        let target = format!("{o}/receipt-subscription/{rsub}");
        out.push((header::LINK, link(&target, REL_RECEIPT)));
    }
    let status = match m.rsub {
        Some(_) => StatusCode::ACCEPTED,
        None => StatusCode::CREATED,
    };
    let event = Event::Message(Arc::new(Notification::from(&m)));
    app.notify(&Recipient::UserAgent(p.sub.uaid), event).await;
    Ok((status, AppendHeaders(out)).into_response())
}

/// Deliver to a bridged user agent: hand the message to the platform. The
/// push service cannot observe acknowledgement through a platform, so no
/// receipt is offered and `Prefer: respond-async` is ignored (RFC 8030 §5.1
/// leaves receipts to the push service's discretion).
async fn bridge<S: Store>(app: &App<S>, p: Push, to: &BridgeAddress) -> Result {
    let Some(bridge) = app.bridges.get(to.bridge.as_str()) else {
        tracing::error!(
            bridge = to.bridge,
            "user agent registered with an unconfigured bridge"
        );
        return Err(StatusCode::BAD_GATEWAY.into());
    };
    let id = new_id();
    let message = BridgeMessage {
        channel_id: &p.sub.channel_id,
        version: &id,
        data: (!p.body.is_empty()).then_some(&p.body[..]),
        encoding: p.cenc.as_deref(),
        ttl: Duration::from_secs(p.ttl.into()),
        priority: match p.urgency {
            Urgency::High => Priority::High,
            _ => Priority::Normal,
        },
    };
    let address = Address {
        app_id: &to.app_id,
        token: &to.token,
    };
    metrics::counter!(telemetry::ACCEPTED, "via" => bridge.name()).increment(1);
    if let Err(e) = bridge.send(address, &message).await {
        metrics::counter!(telemetry::BRIDGE_ERRORS, "bridge" => bridge.name(), "kind" => e.kind())
            .increment(1);
        return Err(bridge_error(app, &p.sub.uaid, e).await);
    }
    metrics::counter!(telemetry::DELIVERED, "via" => bridge.name()).increment(1);
    let out = [
        (header::LOCATION, format!("{}/message/{id}", app.origin())),
        (HeaderName::from_static("ttl"), p.ttl.to_string()),
    ];
    Ok((StatusCode::CREATED, AppendHeaders(out)).into_response())
}

/// Map a bridge failure to the application server's response.
async fn bridge_error<S: Store>(app: &App<S>, uaid: &str, e: webpush_bridge::Error) -> Error {
    use webpush_bridge::Error as E;
    match e {
        E::TokenGone => {
            // The application was uninstalled or the device reset; nothing
            // sent to this user agent can arrive again.
            match app.store.delete_user_agent(uaid).await {
                Ok(receipts) => app.notify_receipts(receipts).await,
                Err(e) => tracing::warn!(error = %e, "delete user agent"),
            }
            StatusCode::GONE.into()
        }
        E::TooLarge => StatusCode::PAYLOAD_TOO_LARGE.into(),
        E::Throttled { retry_after } => {
            Error::retry_after(StatusCode::TOO_MANY_REQUESTS, retry_after)
        }
        e => {
            tracing::warn!(error = %e, "bridge");
            StatusCode::BAD_GATEWAY.into()
        }
    }
}

/// Read an undelivered message (RFC 8030 §8.3). TTL, Urgency, Topic, and
/// VAPID credentials are never returned.
async fn read_message<S: Store>(State(app): State<Arc<App<S>>>, Path(id): Path<String>) -> Result {
    let m = app
        .store
        .message(&valid(id)?)
        .await?
        .filter(|m| m.expiry > now_ms())
        .ok_or(StatusCode::NOT_FOUND)?;
    let mut h = HeaderMap::new();
    let mut put = |name: HeaderName, value: &str| {
        if let Ok(v) = HeaderValue::from_str(value) {
            h.insert(name, v);
        }
    };
    put(header::LAST_MODIFIED, &headers::http_date(m.accepted));
    put(header::CACHE_CONTROL, "private");
    if let Some(ct) = &m.ctype {
        put(header::CONTENT_TYPE, ct);
    }
    if let Some(ce) = &m.cenc {
        put(header::CONTENT_ENCODING, ce);
    }
    Ok((h, m.body).into_response())
}

/// Withdraw an undelivered message. It is not delivered afterwards and owes
/// no receipt, because the application server asked for it.
async fn withdraw_message<S: Store>(
    State(app): State<Arc<App<S>>>,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    app.store
        .delete_message(&valid(id)?, None)
        .await?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Delete a receipt subscription (RFC 8030 §7.3). Open streams end.
async fn delete_receipt_sub<S: Store>(
    State(app): State<Arc<App<S>>>,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    let id = valid(id)?;
    if !app.store.delete_receipt_sub(&id).await? {
        return Err(StatusCode::NOT_FOUND.into());
    }
    app.notify(&Recipient::Receipts(id), Event::Gone).await;
    Ok(StatusCode::NO_CONTENT)
}
