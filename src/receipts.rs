//! Receipt streams: RFC 8030 receipts delivered as Server-Sent Events.
//!
//! RFC 8030 §6.3 delivers receipts to the application server with HTTP/2
//! server push, which HTTP clients disable and browsers removed. The receipt
//! subscription keeps its RFC 8030 role and URL, but `GET` on it returns a
//! `text/event-stream` (WHATWG HTML, "Server-sent events"):
//!
//! ```text
//!  app server              stream task                 hub        store
//!    | GET rsub               |                         |           |
//!    |----------------------->| register(Receipt) ----->|           |
//!    |                        | exists? queued -------------------->|
//!    | 200 text/event-stream  |                         |           |
//!    |<-----------------------|                         |           |
//!    | event: receipt (queued)| delete from queue ----------------->|
//!    |<-----------------------|                         |           |
//!    | event: receipt (live)  |<------- Receipt --------|  <- ack, expiry,
//!    |<-----------------------|                         |     unregister
//!    | event: gone            |<------- Gone -----------|  <- DELETE rsub
//!    |<-----------------------|                         |           |
//! ```
//!
//! Each receipt leaves the queue once written to the stream, so delivery is
//! at most once per receipt. See `docs/http-reference.md`.

use std::{collections::HashSet, convert::Infallible, sync::Arc, time::Duration};

use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
};
use tokio::sync::mpsc::{self, UnboundedReceiver};
use tokio_stream::wrappers::ReceiverStream;

use crate::{
    App, api, headers,
    hub::{Event, Key},
    store::{Receipt, Store},
};

/// Interval of comment lines that keep intermediaries from closing an idle
/// stream.
const KEEPALIVE: Duration = Duration::from_secs(30);

/// `GET /receipt-subscription/{id}`.
pub async fn stream<S: Store>(
    State(app): State<Arc<App<S>>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> api::Result {
    let rsub = api::valid(id)?;
    let key = Key::Receipt(rsub.clone());
    // Register before reading the queue so a receipt queued in between still
    // arrives, as a live event.
    let rx = app.hub.register(key.clone());
    let setup = async {
        if !app.store.receipt_sub_exists(&rsub).await? {
            return Err(api::Error::from(StatusCode::NOT_FOUND));
        }
        Ok(app.store.queued_receipts(&rsub).await?)
    };
    let backlog = match setup.await {
        Ok(backlog) => backlog,
        Err(e) => {
            drop(rx);
            app.hub.prune(&key);
            return Err(e);
        }
    };
    let wait0 = headers::prefer(&headers).wait == Some(0);
    if wait0 && backlog.is_empty() {
        drop(rx);
        app.hub.prune(&key);
        return Ok(StatusCode::NO_CONTENT.into_response());
    }

    let (tx, body) = mpsc::channel::<Result<Bytes, Infallible>>(16);
    let pump = Pump {
        app,
        rsub,
        tx,
        seen: HashSet::new(),
    };
    tokio::spawn(pump.run(rx, backlog, wait0));
    Ok((
        [
            (header::CONTENT_TYPE, "text/event-stream"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        Body::from_stream(ReceiverStream::new(body)),
    )
        .into_response())
}

/// What the stream loop woke up for.
enum Step {
    /// An event from the hub, or the hub dropping the registration.
    Event(Option<Event>),
    /// Time for a keep-alive comment.
    Keepalive,
    /// The client went away.
    Closed,
}

/// Writes receipts for one open stream.
struct Pump<S> {
    /// Shared service state.
    app: Arc<App<S>>,
    /// The receipt subscription.
    rsub: String,
    /// The response body.
    tx: mpsc::Sender<Result<Bytes, Infallible>>,
    /// Sequence numbers already written, since a receipt can arrive both
    /// from the queue and live.
    seen: HashSet<u64>,
}

impl<S: Store> Pump<S> {
    /// Write the backlog, then live receipts until the subscription is
    /// deleted or the client disconnects.
    async fn run(
        mut self,
        mut rx: UnboundedReceiver<Event>,
        backlog: Vec<(u64, Receipt)>,
        wait0: bool,
    ) {
        let mut open = true;
        for (seq, r) in backlog {
            if open {
                open = self.emit(seq, &r).await;
            }
        }
        let mut keepalive =
            tokio::time::interval_at(tokio::time::Instant::now() + KEEPALIVE, KEEPALIVE);
        while open && !wait0 {
            let step = tokio::select! {
                event = rx.recv() => Step::Event(event),
                _ = keepalive.tick() => Step::Keepalive,
                () = self.tx.closed() => Step::Closed,
            };
            open = match step {
                Step::Event(Some(Event::Receipt(seq, r))) => self.emit(seq, &r).await,
                Step::Event(Some(Event::Gone) | None) => {
                    let _ = self.write("event: gone\ndata: {}\n\n").await;
                    false
                }
                Step::Event(Some(Event::Message(_))) => true,
                Step::Keepalive => self.write(": keepalive\n\n").await,
                Step::Closed => false,
            };
        }
        drop(rx);
        self.app.hub.prune(&Key::Receipt(self.rsub));
    }

    /// Write one receipt and remove it from the queue. Returns whether the
    /// stream is still open.
    async fn emit(&mut self, seq: u64, r: &Receipt) -> bool {
        if !self.seen.insert(seq) {
            return true;
        }
        let data = serde_json::json!({
            "message": format!("{}/message/{}", self.app.origin, r.msg_id),
            "status": r.status,
        });
        if !self
            .write(&format!("event: receipt\nid: {seq}\ndata: {data}\n\n"))
            .await
        {
            return false;
        }
        if let Err(e) = self.app.store.delete_receipt(&r.rsub, seq).await {
            tracing::warn!(error = %e, "delete receipt");
        }
        true
    }

    /// Write raw event-stream text. Returns whether the client is connected.
    async fn write(&self, text: &str) -> bool {
        self.tx
            .send(Ok(Bytes::copy_from_slice(text.as_bytes())))
            .await
            .is_ok()
    }
}
