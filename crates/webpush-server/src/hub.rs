//! In-process fan-out from writers to the connections open on this node.
//!
//! ```text
//!   push handler   --notify(UserAgent, Message)--+
//!   ack, reaper,   --notify(Receipts, Receipt)---+--> Hub --> one bounded channel
//!   unregister                                   |          per open connection
//!   /internal/v1/notify (from other nodes) ------+
//! ```
//!
//! Each recipient has at most one listener: a new session for a user agent,
//! or a new stream for a receipt subscription, replaces the previous one,
//! which receives [`Event::Gone`]. That matches the cluster, where the store
//! holds a single route per recipient.
//!
//! Storage is the source of truth; the hub only notifies connections that are
//! open now. An event nobody receives is not lost, because the next session
//! or stream reads it from storage. The same holds for a connection that
//! falls behind: once its channel is full the hub drops it, the connection
//! closes, and the client reconnects and catches up from storage.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use bytes::Bytes;
use tokio::sync::mpsc::{self, Receiver, Sender, error::TrySendError};
use webpush_store::{Message, Receipt, Recipient};

/// A message as a user agent session needs it: only what is sent on the
/// wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notification {
    /// Message id, sent as `version`.
    pub id: String,
    /// The subscription.
    pub channel_id: String,
    /// The encrypted body.
    pub body: Bytes,
    /// The body's content coding.
    pub encoding: Option<String>,
}

impl From<&Message> for Notification {
    fn from(m: &Message) -> Self {
        Self {
            id: m.id.clone(),
            channel_id: m.channel_id.clone(),
            body: m.body.clone(),
            encoding: m.cenc.clone(),
        }
    }
}

/// Something a connection should act on.
#[derive(Clone, Debug)]
pub enum Event {
    /// A newly accepted push message.
    Message(Arc<Notification>),
    /// A queued receipt and its queue sequence number.
    Receipt(u64, Receipt),
    /// A newer connection took over the recipient, or the receipt
    /// subscription was deleted. The connection must end.
    Gone,
}

/// The listener registered for one recipient.
struct Slot {
    /// Identifies the registration, so a replaced listener cannot remove its
    /// successor.
    id: u64,
    /// Sending half of the listener's channel.
    tx: Sender<Event>,
}

/// Registry of the listeners open on this node.
pub struct Hub {
    /// Listeners by recipient.
    slots: Mutex<HashMap<Recipient, Slot>>,
    /// Source of [`Slot::id`].
    next_id: AtomicU64,
    /// Capacity of each listener's channel.
    capacity: usize,
}

/// Outcome of [`Hub::notify`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notified {
    /// A listener on this node took the event.
    Delivered,
    /// A listener on this node fell behind and was dropped; it will catch up
    /// from storage.
    Dropped,
    /// No listener on this node.
    Absent,
}

impl Hub {
    /// An empty hub whose listeners buffer up to `capacity` events.
    pub fn new(capacity: usize) -> Self {
        Self {
            slots: Mutex::default(),
            next_id: AtomicU64::new(0),
            capacity,
        }
    }

    /// Become the listener for `to`. A previous listener receives
    /// [`Event::Gone`]. Returns the registration id for [`Hub::unregister`].
    pub fn register(&self, to: Recipient) -> (u64, Receiver<Event>) {
        let (tx, rx) = mpsc::channel(self.capacity);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        if let Some(old) = self.lock().insert(to, Slot { id, tx }) {
            // A full channel closes anyway once its sender is dropped here.
            let _ = old.tx.try_send(Event::Gone);
        }
        (id, rx)
    }

    /// Remove registration `id` for `to`, unless a newer listener replaced
    /// it. Returns whether it was still registered.
    pub fn unregister(&self, to: &Recipient, id: u64) -> bool {
        let mut slots = self.lock();
        if slots.get(to).is_some_and(|s| s.id == id) {
            slots.remove(to);
            return true;
        }
        false
    }

    /// Hand `event` to the listener for `to`, if it is on this node.
    pub fn notify(&self, to: &Recipient, event: Event) -> Notified {
        let mut slots = self.lock();
        let Some(slot) = slots.get(to) else {
            return Notified::Absent;
        };
        match slot.tx.try_send(event) {
            Ok(()) => Notified::Delivered,
            Err(TrySendError::Full(_)) => {
                slots.remove(to);
                Notified::Dropped
            }
            Err(TrySendError::Closed(_)) => {
                slots.remove(to);
                Notified::Absent
            }
        }
    }

    /// Listeners currently registered.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// The registry, recovering it if a panicking thread poisoned the lock.
    /// Every operation leaves it consistent, so the data is still valid.
    fn lock(&self) -> MutexGuard<'_, HashMap<Recipient, Slot>> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ua() -> Recipient {
        Recipient::UserAgent("u".to_owned())
    }

    #[test]
    fn newer_listener_replaces_older() {
        let hub = Hub::new(4);
        let (old_id, mut old) = hub.register(ua());
        let (new_id, mut new) = hub.register(ua());
        assert!(matches!(old.try_recv(), Ok(Event::Gone)));
        assert!(
            !hub.unregister(&ua(), old_id),
            "old listener removed its successor"
        );
        assert_eq!(hub.notify(&ua(), Event::Gone), Notified::Delivered);
        assert!(matches!(new.try_recv(), Ok(Event::Gone)));
        assert!(hub.unregister(&ua(), new_id));
        assert_eq!(hub.notify(&ua(), Event::Gone), Notified::Absent);
    }

    #[test]
    fn slow_listener_is_dropped() {
        let hub = Hub::new(1);
        let (_, mut rx) = hub.register(ua());
        assert_eq!(hub.notify(&ua(), Event::Gone), Notified::Delivered);
        assert_eq!(hub.notify(&ua(), Event::Gone), Notified::Dropped);
        assert_eq!(hub.len(), 0);
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err(), "channel closes once dropped");
    }
}
