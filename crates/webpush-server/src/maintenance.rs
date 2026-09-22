//! Background work: expiring messages that owe receipts, and deleting user
//! agents that stopped checking in.
//!
//! Both loops run on every endpoint node. That is safe because the store
//! makes each deletion happen once: a message or user agent removed by one
//! node is simply not found by another.

use std::{sync::Arc, time::Duration};

use webpush_store::{Store, now_ms};

use crate::{app::App, telemetry};

/// Start the loops that apply to this configuration.
pub fn spawn<S: Store>(app: &Arc<App<S>>) {
    let tasks = &app.shutdown.tasks;
    tasks.spawn(every(app.clone(), app.cfg.push.reaper_interval, reap));
    if let Some(after) = app.cfg.user_agents.expire_after {
        let interval = app.cfg.user_agents.sweep_interval;
        tasks.spawn(every(app.clone(), interval, move |app| expire(app, after)));
    }
}

/// Run `work` every `interval` until shutdown.
async fn every<S, F, Fut>(app: Arc<App<S>>, interval: Duration, work: F)
where
    S: Store,
    F: Fn(Arc<App<S>>) -> Fut,
    Fut: Future<Output = ()>,
{
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tick.tick() => work(app.clone()).await,
            () = app.shutdown.stopping.cancelled() => return,
        }
    }
}

/// Expire unacknowledged messages that asked for receipts and deliver their
/// 410s (RFC 8030 §6.2).
async fn reap<S: Store>(app: Arc<App<S>>) {
    match app.store.reap(now_ms()).await {
        Ok(receipts) => app.notify_receipts(receipts).await,
        Err(e) => tracing::warn!(error = %e, "reaper"),
    }
}

/// Delete user agents not seen for `after`.
async fn expire<S: Store>(app: Arc<App<S>>, after: Duration) {
    let after_ms = u64::try_from(after.as_millis()).unwrap_or(u64::MAX);
    let cutoff = now_ms().saturating_sub(after_ms);
    match app.store.expire_user_agents(cutoff).await {
        Ok((count, receipts)) => {
            if count > 0 {
                tracing::info!(count, "expired user agents");
            }
            metrics::counter!(telemetry::EXPIRED).increment(count as u64);
            app.notify_receipts(receipts).await;
        }
        Err(e) => tracing::warn!(error = %e, "user agent expiry"),
    }
}
