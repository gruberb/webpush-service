//! HTTP API: RFC 8030 push and message resources with RFC 8292 enforcement,
//! plus the routes to the user agent WebSocket and the receipt streams.
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
//!    store, notify the user agent's session ............... 201 / 202
//! ```
//!
//! Bodies over the limit are refused with 413 by the router's body limit
//! before the handler runs. Endpoints and headers are listed in
//! `docs/http-reference.md`.

use std::{sync::Arc, time::Instant};

use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{AppendHeaders, IntoResponse, Response},
    routing::{get, post},
};

use crate::{
    App, BoxError, ece,
    headers::{self, Invalid},
    hub::{Event, Hub, Key},
    new_id, now_ms, receipts,
    store::{Message, Receipt, Store, Urgency},
    vapid, ws,
};

/// Link relation for a receipt subscription (RFC 8030 §9.1).
pub const REL_RECEIPT: &str = "urn:ietf:params:push:receipt";

/// The API router. Push bodies above `max_payload` octets are refused with
/// 413 while they are read, before they are buffered.
pub fn router<S: Store>(app: Arc<App<S>>, max_payload: usize) -> Router {
    Router::new()
        .route("/", get(ws::upgrade::<S>))
        .route("/push/{id}", post(push::<S>))
        .route(
            "/message/{id}",
            get(read_message::<S>).delete(withdraw_message::<S>),
        )
        .route(
            "/receipt-subscription/{id}",
            get(receipts::stream::<S>).delete(delete_receipt_sub::<S>),
        )
        // The limit applies while the body is read, before it is buffered.
        .layer(DefaultBodyLimit::max(max_payload))
        .layer(middleware::from_fn(log))
        .with_state(app)
}

/// Method, status, and latency only. Paths are capability URLs and are never
/// logged (RFC 8030 §8.5).
async fn log(req: Request, next: Next) -> Response {
    let (method, start) = (req.method().clone(), Instant::now());
    let resp = next.run(req).await;
    tracing::info!(
        %method,
        status = resp.status().as_u16(),
        latency_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
        "request"
    );
    resp
}

/// A handler failure: a protocol status, or 500 for a storage error.
pub struct Error(StatusCode);

impl From<StatusCode> for Error {
    fn from(s: StatusCode) -> Self {
        Error(s)
    }
}

impl From<Invalid> for Error {
    fn from(_: Invalid) -> Self {
        Error(StatusCode::BAD_REQUEST)
    }
}

impl From<BoxError> for Error {
    fn from(e: BoxError) -> Self {
        tracing::error!(error = %e, "storage");
        Error(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        // The only authentication this service asks for is VAPID
        // (RFC 8292 §4.2), so every 401 includes its challenge.
        if self.0 == StatusCode::UNAUTHORIZED {
            return (self.0, [(header::WWW_AUTHENTICATE, "vapid")]).into_response();
        }
        self.0.into_response()
    }
}

/// Handler result: a response, or an [`Error`] status.
pub type Result<T = Response> = std::result::Result<T, Error>;

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

/// Notify the receipt streams of queued receipts.
pub fn notify_receipts(hub: &Hub, receipts: Vec<(u64, Receipt)>) {
    for (seq, r) in receipts {
        hub.notify(&Key::Receipt(r.rsub.clone()), &Event::Receipt(seq, r));
    }
}

/// Queue and announce the receipt `m` owes with `status`, if it requested
/// one (RFC 8030 §5.1).
pub async fn owe_receipt<S: Store>(
    app: &App<S>,
    m: &Message,
    status: u16,
) -> std::result::Result<(), BoxError> {
    let Some(rsub) = &m.rsub else { return Ok(()) };
    let r = Receipt {
        rsub: rsub.clone(),
        msg_id: m.id.clone(),
        status,
    };
    if let Some(seq) = app.store.enqueue_receipt(&r).await? {
        notify_receipts(&app.hub, vec![(seq, r)]);
    }
    Ok(())
}

/// VAPID enforcement (RFC 8292 §4.2). Returns the verified key, if any.
fn check_vapid(
    headers: &HeaderMap,
    restricted: Option<&[u8; 65]>,
    origin: &str,
) -> Result<Option<[u8; 65]>> {
    let forbidden = || Error(StatusCode::FORBIDDEN);
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
            Some(_) => Err(Error(StatusCode::UNAUTHORIZED)),
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
    let ttl = u32::try_from(headers::ttl(&headers)?)
        .unwrap_or(u32::MAX)
        .min(app.max_ttl);
    let urgency = headers::urgency(&headers)?.unwrap_or(Urgency::Normal);
    let topic = headers::topic(&headers)?;
    let respond_async = headers::prefer(&headers).respond_async;
    let rsub_link = match headers::link(&headers, REL_RECEIPT) {
        Some(target) if respond_async => {
            let id = headers::resource_id(&target, &app.origin, "/receipt-subscription/")
                .ok_or(Invalid)?;
            if !app.store.receipt_sub_exists(id).await? {
                return Err(Invalid.into());
            }
            Some(id.to_owned())
        }
        _ => None,
    };

    let key = check_vapid(&headers, sub.vapid.as_ref(), &app.origin)?;
    let cenc = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok());
    // The application server key must not double as the message encryption
    // key (RFC 8292 §3.2). Only the header is parsed; the payload stays opaque.
    if let Some(k) = key
        && cenc == Some("aes128gcm")
        && ece::parse_header(&body).is_ok_and(|(h, _)| h.keyid == k)
    {
        return Err(Invalid.into());
    }

    let rsub = match rsub_link {
        Some(id) => Some(id),
        None if respond_async => Some(app.store.create_receipt_sub().await?),
        None => None,
    };
    let accepted = now_ms();
    let text = |name| {
        headers
            .get(name)
            .and_then(|v: &HeaderValue| v.to_str().ok())
            .map(str::to_owned)
    };
    let m = Message {
        id: new_id(),
        uaid: sub.uaid.clone(),
        channel_id: sub.channel_id,
        push: push_id,
        topic,
        body,
        ctype: text(header::CONTENT_TYPE),
        cenc: text(header::CONTENT_ENCODING),
        ttl,
        urgency,
        accepted,
        expiry: accepted + u64::from(ttl) * 1000,
        rsub,
    };
    app.store.insert_message(&m).await?;

    let o = &app.origin;
    let mut out = vec![
        (header::LOCATION, format!("{o}/message/{}", m.id)),
        (HeaderName::from_static("ttl"), ttl.to_string()),
    ];
    if let Some(rsub) = &m.rsub {
        let target = format!("{o}/receipt-subscription/{rsub}");
        out.push((header::LINK, link(&target, REL_RECEIPT)));
    }
    let status = match m.rsub {
        Some(_) => StatusCode::ACCEPTED,
        None => StatusCode::CREATED,
    };
    app.hub
        .notify(&Key::Ua(sub.uaid), &Event::Message(Arc::new(m)));
    Ok((status, AppendHeaders(out)).into_response())
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
    app.hub.notify(&Key::Receipt(id), &Event::Gone);
    Ok(StatusCode::NO_CONTENT)
}
