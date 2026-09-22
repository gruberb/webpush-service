//! In-process fan-out from writers to connected sessions and receipt streams.
//!
//! ```text
//!   push handler   --notify(Ua(uaid), Message)----+
//!   ack, reaper,   --notify(Receipt(r), Receipt)--+--> Hub --> session / stream
//!   unregister                                    |          channels
//!   new session    --notify(Ua(uaid), Gone)-------+   (one per connection)
//!   receipt DELETE --notify(Receipt(r), Gone)-----+
//! ```
//!
//! Storage is the source of truth; the hub only notifies connections that are
//! open now. An event nobody receives is not lost, because the next session
//! or stream finds the data in storage. That is what makes plain in-memory
//! channels safe here, and also why the service is single-node. See
//! `docs/architecture.md` (The hub).

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use crate::store::{Message, Receipt};

/// A resource that connections can wait on.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Key {
    /// A user agent session, by `uaid`. Receives the messages of all its
    /// subscriptions.
    Ua(String),
    /// A receipt subscription stream, by id.
    Receipt(String),
}

/// Something a connection should act on.
#[derive(Clone)]
pub enum Event {
    /// A newly accepted push message.
    Message(Arc<Message>),
    /// A queued receipt and its queue sequence number.
    Receipt(u64, Receipt),
    /// The connection must end: a newer session took over the `uaid`, or the
    /// receipt subscription was deleted.
    Gone,
}

/// Senders for every open connection, by the resource it watches.
type Registry = HashMap<Key, Vec<UnboundedSender<Event>>>;

/// Registry of open connections. Channels are unbounded; see the tradeoffs
/// in `docs/architecture.md`.
#[derive(Default)]
pub struct Hub {
    /// All registrations behind one lock.
    inner: Mutex<Registry>,
}

impl Hub {
    /// Start receiving events for `key`. The connection must call
    /// [`Hub::prune`] once it drops the receiver.
    pub fn register(&self, key: Key) -> UnboundedReceiver<Event> {
        let (tx, rx) = unbounded_channel();
        self.lock().entry(key).or_default().push(tx);
        rx
    }

    /// Send `event` to every connection watching `key`, dropping connections
    /// that have gone away.
    pub fn notify(&self, key: &Key, event: &Event) {
        let mut map = self.lock();
        if let Some(senders) = map.get_mut(key) {
            senders.retain(|tx| tx.send(event.clone()).is_ok());
            if senders.is_empty() {
                map.remove(key);
            }
        }
    }

    /// Drop senders whose connection has gone away. Called when a connection
    /// ends so keys that are never notified again do not accumulate.
    pub fn prune(&self, key: &Key) {
        let mut map = self.lock();
        if let Some(senders) = map.get_mut(key) {
            senders.retain(|tx| !tx.is_closed());
            if senders.is_empty() {
                map.remove(key);
            }
        }
    }

    /// The registry, recovering it if a panicking thread poisoned the lock.
    /// Every operation leaves it consistent, so the data is still valid.
    fn lock(&self) -> MutexGuard<'_, Registry> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
