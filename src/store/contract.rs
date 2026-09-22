//! Executable version of the [`Store`] contract.
//!
//! [`check`] exercises every guarantee the push service relies on and panics
//! with a description of the first violation. Run it from a test in the crate
//! that implements an adapter:
//!
//! ```no_run
//! # use webpush_service::store::{MemoryStore, contract};
//! #[tokio::test]
//! async fn my_store_meets_the_contract() {
//!     let store = MemoryStore::new(); // your adapter here
//!     contract::check(&store).await;
//! }
//! ```
//!
//! Every check creates its own user agents, subscriptions, and receipt
//! subscriptions with fresh random ids, so it can run against a shared or
//! persistent database without interfering with existing data.

use bytes::Bytes;

use super::{Message, Store, Urgency};
use crate::{new_id, now_ms};

/// Run every contract check against `store`. Panics on the first violation.
pub async fn check<S: Store>(store: &S) {
    user_agents(store).await;
    subscriptions(store).await;
    pending_order_and_expiry(store).await;
    topic_replacement(store).await;
    delete_message_ownership(store).await;
    receipt_queue(store).await;
    delete_subscription_owes_410(store).await;
    reap_owes_410(store).await;
}

/// A message for `(uaid, channel_id)` accepted at `accepted`, expiring
/// `ttl_ms` later.
fn message(uaid: &str, channel_id: &str, push: &str, accepted: u64, ttl_ms: u64) -> Message {
    Message {
        id: new_id(),
        uaid: uaid.to_owned(),
        channel_id: channel_id.to_owned(),
        push: push.to_owned(),
        topic: None,
        body: Bytes::from_static(b"body"),
        ctype: Some("application/octet-stream".to_owned()),
        cenc: Some("aes128gcm".to_owned()),
        ttl: u32::try_from(ttl_ms / 1000).unwrap_or(u32::MAX),
        urgency: Urgency::Normal,
        accepted,
        expiry: accepted + ttl_ms,
        rsub: None,
    }
}

/// A fresh lowercase UUID, as Firefox generates channel ids.
fn channel_id() -> String {
    use std::fmt::Write;
    let hex = new_id().bytes().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    });
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Unwrap a backend result; backend errors are contract failures too.
fn ok<T>(r: Result<T, crate::BoxError>, what: &str) -> T {
    r.unwrap_or_else(|e| panic!("store contract: {what} failed: {e}"))
}

/// User agents are created with 32 lowercase hex ids and can be found again.
async fn user_agents<S: Store>(store: &S) {
    let uaid = ok(store.create_user_agent().await, "create_user_agent");
    assert!(
        uaid.len() == 32
            && uaid
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "store contract: uaid {uaid:?} is not 32 lowercase hex characters"
    );
    assert!(ok(
        store.user_agent_exists(&uaid).await,
        "user_agent_exists"
    ));
    let other = ok(store.create_user_agent().await, "create_user_agent");
    assert_ne!(uaid, other, "store contract: two user agents share an id");
    assert!(
        !ok(
            store.user_agent_exists(&"0".repeat(32)).await,
            "user_agent_exists"
        ),
        "store contract: an unknown uaid exists"
    );
}

/// Subscriptions can be found by channel and by push id, and push ids are
/// unrelated to the user agent.
async fn subscriptions<S: Store>(store: &S) {
    let uaid = ok(store.create_user_agent().await, "create_user_agent");
    let ch = channel_id();
    let key = [4u8; 65];
    assert!(ok(store.channel(&uaid, &ch).await, "channel").is_none());
    let sub = ok(
        store.create_subscription(&uaid, &ch, Some(key)).await,
        "create_subscription",
    );
    assert_eq!(
        (sub.uaid.as_str(), sub.channel_id.as_str()),
        (uaid.as_str(), ch.as_str())
    );
    assert_eq!(sub.vapid, Some(key), "store contract: VAPID key not kept");
    assert!(
        sub.push.len() >= 22,
        "store contract: push id shorter than 128 bits"
    );
    assert!(
        !sub.push.contains(&uaid) && !sub.push.contains(&ch),
        "store contract: push id reveals the user agent or channel"
    );
    assert_eq!(
        ok(store.channel(&uaid, &ch).await, "channel"),
        Some(sub.clone())
    );
    assert_eq!(
        ok(
            store.subscription_by_push(&sub.push).await,
            "subscription_by_push"
        ),
        Some(sub)
    );
    assert!(
        ok(
            store.subscription_by_push(&new_id()).await,
            "subscription_by_push"
        )
        .is_none()
    );
}

/// `pending` returns only unexpired messages of that user agent, oldest first.
async fn pending_order_and_expiry<S: Store>(store: &S) {
    let now = now_ms();
    let uaid = ok(store.create_user_agent().await, "create_user_agent");
    let (a, b) = (channel_id(), channel_id());
    let sa = ok(
        store.create_subscription(&uaid, &a, None).await,
        "create_subscription",
    );
    let sb = ok(
        store.create_subscription(&uaid, &b, None).await,
        "create_subscription",
    );
    let second = message(&uaid, &b, &sb.push, now - 1000, 60_000);
    let first = message(&uaid, &a, &sa.push, now - 2000, 60_000);
    let expired = message(&uaid, &a, &sa.push, now - 3000, 1000);
    for m in [&second, &first, &expired] {
        ok(store.insert_message(m).await, "insert_message");
    }
    let other = ok(store.create_user_agent().await, "create_user_agent");
    let so = ok(
        store.create_subscription(&other, &a, None).await,
        "create_subscription",
    );
    ok(
        store
            .insert_message(&message(&other, &a, &so.push, now, 60_000))
            .await,
        "insert_message",
    );

    let got = ok(store.pending(&uaid, now).await, "pending");
    assert_eq!(
        got,
        vec![first.clone(), second],
        "store contract: pending must return unexpired messages of the user agent, oldest first"
    );
    assert_eq!(ok(store.message(&first.id).await, "message"), Some(first));
}

/// A topic message replaces the stored message with the same topic on the
/// same subscription, and only there.
async fn topic_replacement<S: Store>(store: &S) {
    let now = now_ms();
    let uaid = ok(store.create_user_agent().await, "create_user_agent");
    let (a, b) = (channel_id(), channel_id());
    let sa = ok(
        store.create_subscription(&uaid, &a, None).await,
        "create_subscription",
    );
    let sb = ok(
        store.create_subscription(&uaid, &b, None).await,
        "create_subscription",
    );
    let rsub = ok(store.create_receipt_sub().await, "create_receipt_sub");

    let mut old = message(&uaid, &a, &sa.push, now - 2000, 60_000);
    old.topic = Some("news".to_owned());
    old.rsub = Some(rsub.clone());
    old.urgency = Urgency::High;
    let mut elsewhere = message(&uaid, &b, &sb.push, now - 1500, 60_000);
    elsewhere.topic = Some("news".to_owned());
    let mut new = message(&uaid, &a, &sa.push, now - 1000, 30_000);
    new.topic = Some("news".to_owned());
    new.urgency = Urgency::VeryLow;
    new.body = Bytes::from_static(b"replacement");
    for m in [&old, &elsewhere, &new] {
        ok(store.insert_message(m).await, "insert_message");
    }

    assert!(
        ok(store.message(&old.id).await, "message").is_none(),
        "store contract: a replaced message is still readable"
    );
    assert_eq!(
        ok(store.message(&new.id).await, "message"),
        Some(new.clone())
    );
    assert_eq!(
        ok(store.pending(&uaid, now).await, "pending"),
        vec![elsewhere, new.clone()],
        "store contract: the same topic on another subscription must not be replaced"
    );
    assert!(
        ok(store.delete_message(&old.id, None).await, "delete_message").is_none(),
        "store contract: deleting a replaced message must not match its replacement"
    );
    // The replacement's own settings apply: it has no receipt subscription,
    // so deleting the subscription owes nothing for the replaced message.
    let receipts = ok(
        store.delete_subscription(&uaid, &a).await,
        "delete_subscription",
    );
    assert!(
        receipts.is_empty(),
        "store contract: a replaced message produced a receipt"
    );
}

/// `delete_message` honours the owner and deletes exactly once.
async fn delete_message_ownership<S: Store>(store: &S) {
    let now = now_ms();
    let uaid = ok(store.create_user_agent().await, "create_user_agent");
    let ch = channel_id();
    let sub = ok(
        store.create_subscription(&uaid, &ch, None).await,
        "create_subscription",
    );
    let m = message(&uaid, &ch, &sub.push, now, 60_000);
    ok(store.insert_message(&m).await, "insert_message");

    let stranger = ok(store.create_user_agent().await, "create_user_agent");
    assert!(
        ok(
            store.delete_message(&m.id, Some((&stranger, &ch))).await,
            "delete_message"
        )
        .is_none(),
        "store contract: another user agent deleted a message"
    );
    assert!(
        ok(
            store
                .delete_message(&m.id, Some((&uaid, &channel_id())))
                .await,
            "delete_message"
        )
        .is_none(),
        "store contract: another channel deleted a message"
    );
    assert_eq!(
        ok(
            store.delete_message(&m.id, Some((&uaid, &ch))).await,
            "delete_message"
        ),
        Some(m.clone())
    );
    assert!(
        ok(store.delete_message(&m.id, None).await, "delete_message").is_none(),
        "store contract: a message was deleted twice"
    );
    assert!(ok(store.message(&m.id).await, "message").is_none());
}

/// Receipts queue in order, leave the queue when deleted, and are dropped
/// once their receipt subscription is gone.
async fn receipt_queue<S: Store>(store: &S) {
    let rsub = ok(store.create_receipt_sub().await, "create_receipt_sub");
    assert!(ok(
        store.receipt_sub_exists(&rsub).await,
        "receipt_sub_exists"
    ));
    let receipt = |msg_id: &str, status| super::Receipt {
        rsub: rsub.clone(),
        msg_id: msg_id.to_owned(),
        status,
    };
    let (r1, r2) = (receipt("m1", 204), receipt("m2", 410));
    let s1 = ok(store.enqueue_receipt(&r1).await, "enqueue_receipt").expect("queued");
    let s2 = ok(store.enqueue_receipt(&r2).await, "enqueue_receipt").expect("queued");
    assert!(
        s2 > s1,
        "store contract: receipt sequence numbers must increase"
    );
    assert_eq!(
        ok(store.queued_receipts(&rsub).await, "queued_receipts"),
        vec![(s1, r1), (s2, r2.clone())]
    );
    ok(store.delete_receipt(&rsub, s1).await, "delete_receipt");
    assert_eq!(
        ok(store.queued_receipts(&rsub).await, "queued_receipts"),
        vec![(s2, r2)]
    );
    assert!(ok(
        store.delete_receipt_sub(&rsub).await,
        "delete_receipt_sub"
    ));
    assert!(!ok(
        store.delete_receipt_sub(&rsub).await,
        "delete_receipt_sub"
    ));
    assert!(!ok(
        store.receipt_sub_exists(&rsub).await,
        "receipt_sub_exists"
    ));
    assert!(
        ok(
            store.enqueue_receipt(&receipt("m3", 204)).await,
            "enqueue_receipt"
        )
        .is_none(),
        "store contract: a receipt was queued for a deleted receipt subscription"
    );
    assert!(ok(store.queued_receipts(&rsub).await, "queued_receipts").is_empty());
}

/// Deleting a subscription deletes its messages and owes a 410 for each one
/// that requested a receipt.
async fn delete_subscription_owes_410<S: Store>(store: &S) {
    let now = now_ms();
    let uaid = ok(store.create_user_agent().await, "create_user_agent");
    let (ch, keep) = (channel_id(), channel_id());
    let sub = ok(
        store.create_subscription(&uaid, &ch, None).await,
        "create_subscription",
    );
    let kept = ok(
        store.create_subscription(&uaid, &keep, None).await,
        "create_subscription",
    );
    let rsub = ok(store.create_receipt_sub().await, "create_receipt_sub");
    let mut with_receipt = message(&uaid, &ch, &sub.push, now, 60_000);
    with_receipt.rsub = Some(rsub.clone());
    let without = message(&uaid, &ch, &sub.push, now, 60_000);
    let unrelated = message(&uaid, &keep, &kept.push, now, 60_000);
    for m in [&with_receipt, &without, &unrelated] {
        ok(store.insert_message(m).await, "insert_message");
    }

    let receipts = ok(
        store.delete_subscription(&uaid, &ch).await,
        "delete_subscription",
    );
    assert_eq!(
        receipts.len(),
        1,
        "store contract: expected one 410 receipt"
    );
    assert_eq!(
        (receipts[0].1.msg_id.as_str(), receipts[0].1.status),
        (with_receipt.id.as_str(), 410)
    );
    assert!(ok(store.channel(&uaid, &ch).await, "channel").is_none());
    assert!(
        ok(
            store.subscription_by_push(&sub.push).await,
            "subscription_by_push"
        )
        .is_none()
    );
    assert_eq!(
        ok(store.pending(&uaid, now).await, "pending"),
        vec![unrelated],
        "store contract: deleting a subscription must delete its messages and only those"
    );
    assert!(
        ok(
            store.delete_subscription(&uaid, &ch).await,
            "delete_subscription"
        )
        .is_empty(),
        "store contract: deleting an unknown subscription produced receipts"
    );
}

/// `reap` deletes expired messages that requested receipts and owes a 410.
async fn reap_owes_410<S: Store>(store: &S) {
    let now = now_ms();
    let uaid = ok(store.create_user_agent().await, "create_user_agent");
    let ch = channel_id();
    let sub = ok(
        store.create_subscription(&uaid, &ch, None).await,
        "create_subscription",
    );
    let rsub = ok(store.create_receipt_sub().await, "create_receipt_sub");
    let mut expired = message(&uaid, &ch, &sub.push, now - 5000, 1000);
    expired.rsub = Some(rsub.clone());
    let mut live = message(&uaid, &ch, &sub.push, now, 60_000);
    live.rsub = Some(rsub.clone());
    for m in [&expired, &live] {
        ok(store.insert_message(m).await, "insert_message");
    }

    let receipts = ok(store.reap(now).await, "reap");
    let ours: Vec<_> = receipts.iter().filter(|(_, r)| r.rsub == rsub).collect();
    assert_eq!(
        ours.len(),
        1,
        "store contract: reap must owe exactly one 410 here"
    );
    assert_eq!(
        (ours[0].1.msg_id.as_str(), ours[0].1.status),
        (expired.id.as_str(), 410)
    );
    assert!(ok(store.message(&expired.id).await, "message").is_none());
    assert_eq!(ok(store.message(&live.id).await, "message"), Some(live));
    assert_eq!(
        ok(store.queued_receipts(&rsub).await, "queued_receipts").len(),
        1,
        "store contract: the 410 must also be queued"
    );
}
