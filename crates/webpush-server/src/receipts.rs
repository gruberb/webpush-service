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
//!    |----------------------->| listen(Receipts) ------>| (route) ->|
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
//! at most once per receipt. A receipt subscription has one stream at a
//! time: opening another ends the first with `event: gone`. In a cluster the
//! stream's node records a route, so receipts produced on connection nodes
//! (acknowledgements) reach it. See `docs/http-reference.md`.

use std::{collections::HashSet, convert::Infallible, sync::Arc};

use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use webpush_store::{Receipt, Recipient, Store};

use crate::{app::App, endpoint, error::Result, headers, hub::Event, notify::Listener};

/// `GET /receipt-subscription/{id}`.
pub async fn stream<S: Store>(
    State(app): State<Arc<App<S>>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result {
    let rsub = endpoint::valid(id)?;
    let wait0 = headers::prefer(&headers).wait == Some(0);
    // Listen before checking and reading the queue, so a receipt queued or a
    // deletion made in between still arrives as a live event. `wait=0` reads
    // the queue only. The listener cleans up after itself if dropped here.
    let listener = if wait0 {
        None
    } else {
        Some(app.listen(Recipient::Receipts(rsub.clone())).await?)
    };
    if !app.store.receipt_sub_exists(&rsub).await? {
        return Err(StatusCode::NOT_FOUND.into());
    }
    let backlog = app.store.queued_receipts(&rsub).await?;
    if wait0 && backlog.is_empty() {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }

    let (tx, body) = mpsc::channel::<std::result::Result<Bytes, Infallible>>(16);
    let pump = Pump {
        app: app.clone(),
        tx,
        seen: HashSet::new(),
    };
    app.shutdown.tasks.spawn(pump.run(listener, backlog));
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
    /// The response body.
    tx: mpsc::Sender<std::result::Result<Bytes, Infallible>>,
    /// Sequence numbers already written, since a receipt can arrive both
    /// from the queue and live.
    seen: HashSet<u64>,
}

impl<S: Store> Pump<S> {
    /// Write the backlog, then, unless this is a `wait=0` read, live
    /// receipts until the subscription is deleted, the stream is replaced,
    /// the client disconnects, or the service shuts down.
    async fn run(mut self, listener: Option<Listener<S>>, backlog: Vec<(u64, Receipt)>) {
        let mut open = true;
        for (seq, r) in backlog {
            if open {
                open = self.emit(seq, &r).await;
            }
        }
        let Some(mut listener) = listener else { return };
        let period = self.app.cfg.receipts.keepalive;
        let mut keepalive = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        let stopping = self.app.shutdown.stopping.clone();
        while open {
            let step = tokio::select! {
                event = listener.rx.recv() => Step::Event(event),
                _ = keepalive.tick() => Step::Keepalive,
                () = self.tx.closed() => Step::Closed,
                () = stopping.cancelled() => Step::Closed,
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
    }

    /// Write one receipt and remove it from the queue. Returns whether the
    /// stream is still open.
    async fn emit(&mut self, seq: u64, r: &Receipt) -> bool {
        if !self.seen.insert(seq) {
            return true;
        }
        let data = serde_json::json!({
            "message": format!("{}/message/{}", self.app.origin(), r.msg_id),
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
