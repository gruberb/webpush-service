//! In-memory [`Store`]: one mutex over plain maps.
//!
//! Every method takes the lock once and never awaits while holding it, so
//! each call is atomic and the trait's replacement and ownership guarantees
//! hold trivially. Data is lost when the process exits.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex, MutexGuard},
};

use crate::{
    BoxError, Message, Receipt, Recipient, Store, Subscription, UserAgent, new_id, next_seq,
};

/// A [`Store`] that keeps everything in process memory.
///
/// Suitable for development, tests, and single-node deployments that can
/// afford to lose undelivered messages on restart. Clones share the same
/// state, so several services in one process can use one store.
///
/// ```
/// let store = webpush_store::MemoryStore::new();
/// # let _ = store;
/// ```
#[derive(Clone, Default)]
pub struct MemoryStore {
    /// All state behind one lock.
    inner: Arc<Mutex<State>>,
}

/// The maps behind [`MemoryStore`].
#[derive(Default)]
struct State {
    /// User agents by id.
    user_agents: HashMap<String, UserAgent>,
    /// Subscriptions by `(uaid, channel_id)`.
    channels: HashMap<(String, String), Subscription>,
    /// Push resource id to `(uaid, channel_id)`.
    push: HashMap<String, (String, String)>,
    /// Messages by id.
    messages: HashMap<String, Message>,
    /// Topic slot `(uaid, channel_id, topic)` to the id of the message in it.
    topics: HashMap<(String, String, String), String>,
    /// Receipt subscriptions and their queues, ordered by sequence number.
    receipts: HashMap<String, BTreeMap<u64, Receipt>>,
    /// The node holding each routed connection.
    routes: HashMap<Recipient, String>,
}

impl MemoryStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The state, recovering it if a panicking thread poisoned the lock.
    /// Every mutation leaves the maps consistent, so the data is still valid.
    fn state(&self) -> MutexGuard<'_, State> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl State {
    /// Delete a subscription and its messages, returning the 410 receipts
    /// owed.
    fn remove_subscription(&mut self, uaid: &str, channel_id: &str) -> Vec<(u64, Receipt)> {
        let Some(sub) = self
            .channels
            .remove(&(uaid.to_owned(), channel_id.to_owned()))
        else {
            return vec![];
        };
        self.push.remove(&sub.push);
        let ids: Vec<String> = self
            .messages
            .values()
            .filter(|m| m.uaid == uaid && m.channel_id == channel_id)
            .map(|m| m.id.clone())
            .collect();
        let mut receipts = Vec::new();
        for id in ids {
            if let Some(m) = self.remove_message(&id) {
                receipts.extend(self.owe_410(&m));
            }
        }
        receipts
    }

    /// Delete a user agent and everything it owns.
    fn remove_user_agent(&mut self, uaid: &str) -> Vec<(u64, Receipt)> {
        self.user_agents.remove(uaid);
        let channels: Vec<String> = self
            .channels
            .keys()
            .filter(|(u, _)| u == uaid)
            .map(|(_, ch)| ch.clone())
            .collect();
        channels
            .iter()
            .flat_map(|ch| self.remove_subscription(uaid, ch))
            .collect()
    }

    /// Remove a message and its topic slot.
    fn remove_message(&mut self, id: &str) -> Option<Message> {
        let m = self.messages.remove(id)?;
        if let Some(topic) = &m.topic {
            self.topics
                .remove(&(m.uaid.clone(), m.channel_id.clone(), topic.clone()));
        }
        Some(m)
    }

    /// Queue a 410 receipt for `m` if it requested one and the receipt
    /// subscription still exists.
    fn owe_410(&mut self, m: &Message) -> Option<(u64, Receipt)> {
        let rsub = m.rsub.as_ref()?;
        let queue = self.receipts.get_mut(rsub)?;
        let r = Receipt {
            rsub: rsub.clone(),
            msg_id: m.id.clone(),
            status: 410,
        };
        let seq = next_seq();
        queue.insert(seq, r.clone());
        Some((seq, r))
    }
}

impl Store for MemoryStore {
    async fn create_user_agent(&self, ua: &UserAgent) -> Result<(), BoxError> {
        self.state().user_agents.insert(ua.uaid.clone(), ua.clone());
        Ok(())
    }

    async fn user_agent(&self, uaid: &str) -> Result<Option<UserAgent>, BoxError> {
        Ok(self.state().user_agents.get(uaid).cloned())
    }

    async fn touch_user_agent(&self, uaid: &str, now: u64) -> Result<bool, BoxError> {
        let mut s = self.state();
        let Some(ua) = s.user_agents.get_mut(uaid) else {
            return Ok(false);
        };
        ua.last_seen = ua.last_seen.max(now);
        Ok(true)
    }

    async fn update_bridge_token(&self, uaid: &str, token: &str) -> Result<bool, BoxError> {
        let mut s = self.state();
        let Some(bridge) = s
            .user_agents
            .get_mut(uaid)
            .and_then(|ua| ua.bridge.as_mut())
        else {
            return Ok(false);
        };
        token.clone_into(&mut bridge.token);
        Ok(true)
    }

    async fn delete_user_agent(&self, uaid: &str) -> Result<Vec<(u64, Receipt)>, BoxError> {
        Ok(self.state().remove_user_agent(uaid))
    }

    async fn expire_user_agents(
        &self,
        cutoff: u64,
    ) -> Result<(usize, Vec<(u64, Receipt)>), BoxError> {
        let mut s = self.state();
        let stale: Vec<String> = s
            .user_agents
            .values()
            .filter(|ua| ua.last_seen < cutoff)
            .map(|ua| ua.uaid.clone())
            .collect();
        let receipts = stale
            .iter()
            .flat_map(|uaid| s.remove_user_agent(uaid))
            .collect();
        Ok((stale.len(), receipts))
    }

    async fn subscriptions(&self, uaid: &str) -> Result<Vec<Subscription>, BoxError> {
        Ok(self
            .state()
            .channels
            .values()
            .filter(|sub| sub.uaid == uaid)
            .cloned()
            .collect())
    }

    async fn channel(
        &self,
        uaid: &str,
        channel_id: &str,
    ) -> Result<Option<Subscription>, BoxError> {
        let key = (uaid.to_owned(), channel_id.to_owned());
        Ok(self.state().channels.get(&key).cloned())
    }

    async fn create_subscription(
        &self,
        uaid: &str,
        channel_id: &str,
        vapid: Option<[u8; 65]>,
    ) -> Result<Subscription, BoxError> {
        let sub = Subscription {
            uaid: uaid.to_owned(),
            channel_id: channel_id.to_owned(),
            push: new_id(),
            vapid,
        };
        let mut s = self.state();
        let key = (sub.uaid.clone(), sub.channel_id.clone());
        s.push.insert(sub.push.clone(), key.clone());
        s.channels.insert(key, sub.clone());
        Ok(sub)
    }

    async fn subscription_by_push(&self, push: &str) -> Result<Option<Subscription>, BoxError> {
        let s = self.state();
        Ok(s.push
            .get(push)
            .and_then(|key| s.channels.get(key))
            .cloned())
    }

    async fn delete_subscription(
        &self,
        uaid: &str,
        channel_id: &str,
    ) -> Result<Vec<(u64, Receipt)>, BoxError> {
        Ok(self.state().remove_subscription(uaid, channel_id))
    }

    async fn insert_message(&self, m: &Message) -> Result<(), BoxError> {
        let mut s = self.state();
        if let Some(topic) = &m.topic {
            let slot = (m.uaid.clone(), m.channel_id.clone(), topic.clone());
            // The replaced message is dropped without a receipt (RFC 8030 §5.4).
            if let Some(old) = s.topics.insert(slot, m.id.clone()) {
                s.messages.remove(&old);
            }
        }
        s.messages.insert(m.id.clone(), m.clone());
        Ok(())
    }

    async fn pending(&self, uaid: &str, now: u64, limit: usize) -> Result<Vec<Message>, BoxError> {
        let s = self.state();
        let mut out: Vec<Message> = s
            .messages
            .values()
            .filter(|m| m.uaid == uaid && m.expiry > now)
            .cloned()
            .collect();
        out.sort_by(|a, b| (a.accepted, &a.id).cmp(&(b.accepted, &b.id)));
        out.truncate(limit);
        Ok(out)
    }

    async fn message(&self, id: &str) -> Result<Option<Message>, BoxError> {
        Ok(self.state().messages.get(id).cloned())
    }

    async fn delete_message(
        &self,
        id: &str,
        owner: Option<(&str, &str)>,
    ) -> Result<Option<Message>, BoxError> {
        let mut s = self.state();
        let permitted = s
            .messages
            .get(id)
            .is_some_and(|m| owner.is_none_or(|(uaid, ch)| m.uaid == uaid && m.channel_id == ch));
        Ok(if permitted {
            s.remove_message(id)
        } else {
            None
        })
    }

    async fn create_receipt_sub(&self) -> Result<String, BoxError> {
        let rsub = new_id();
        self.state().receipts.insert(rsub.clone(), BTreeMap::new());
        Ok(rsub)
    }

    async fn receipt_sub_exists(&self, rsub: &str) -> Result<bool, BoxError> {
        Ok(self.state().receipts.contains_key(rsub))
    }

    async fn delete_receipt_sub(&self, rsub: &str) -> Result<bool, BoxError> {
        Ok(self.state().receipts.remove(rsub).is_some())
    }

    async fn enqueue_receipt(&self, r: &Receipt) -> Result<Option<u64>, BoxError> {
        let mut s = self.state();
        let Some(queue) = s.receipts.get_mut(&r.rsub) else {
            return Ok(None);
        };
        let seq = next_seq();
        queue.insert(seq, r.clone());
        Ok(Some(seq))
    }

    async fn queued_receipts(&self, rsub: &str) -> Result<Vec<(u64, Receipt)>, BoxError> {
        let s = self.state();
        Ok(s.receipts.get(rsub).map_or_else(Vec::new, |q| {
            q.iter().map(|(seq, r)| (*seq, r.clone())).collect()
        }))
    }

    async fn delete_receipt(&self, rsub: &str, seq: u64) -> Result<(), BoxError> {
        if let Some(q) = self.state().receipts.get_mut(rsub) {
            q.remove(&seq);
        }
        Ok(())
    }

    async fn reap(&self, now: u64) -> Result<Vec<(u64, Receipt)>, BoxError> {
        let mut s = self.state();
        // Expired messages without receipts are dropped here too, since
        // nothing else frees their memory.
        let expired: Vec<String> = s
            .messages
            .values()
            .filter(|m| m.expiry <= now)
            .map(|m| m.id.clone())
            .collect();
        let mut receipts = Vec::new();
        for id in expired {
            if let Some(m) = s.remove_message(&id) {
                receipts.extend(s.owe_410(&m));
            }
        }
        Ok(receipts)
    }

    async fn set_route(&self, to: &Recipient, node: &str) -> Result<Option<String>, BoxError> {
        Ok(self.state().routes.insert(to.clone(), node.to_owned()))
    }

    async fn route(&self, to: &Recipient) -> Result<Option<String>, BoxError> {
        Ok(self.state().routes.get(to).cloned())
    }

    async fn clear_route(&self, to: &Recipient, node: &str) -> Result<bool, BoxError> {
        let mut s = self.state();
        if s.routes.get(to).is_some_and(|n| n == node) {
            s.routes.remove(to);
            return Ok(true);
        }
        Ok(false)
    }
}
