//! Graceful shutdown.
//!
//! ```text
//!   signal
//!     |
//!   draining.cancel()      /ready answers 503; everything else keeps working
//!     |  drain_delay
//!   stopping.cancel()      accept loops end, HTTP connections finish their
//!     |                    in-flight requests, sessions close with 1001,
//!     |                    receipt streams end, background loops return
//!   tasks.wait()           bounded by shutdown.timeout
//! ```
//!
//! Every connection, session, stream, and background loop is spawned on
//! [`Shutdown::tasks`], so waiting for the tracker waits for all of them.

use std::{future::Future, time::Duration};

use tokio_util::{sync::CancellationToken, task::TaskTracker};

/// Shutdown state shared by every task.
#[derive(Clone, Default)]
pub struct Shutdown {
    /// Cancelled when shutdown starts; readiness fails from then on.
    pub draining: CancellationToken,
    /// Cancelled after the drain delay; long-lived work ends.
    pub stopping: CancellationToken,
    /// Every task that must finish before the process exits.
    pub tasks: TaskTracker,
}

impl Shutdown {
    /// Wait for `signal`, then run the shutdown sequence. Returns once every
    /// tracked task has finished or `timeout` has passed.
    pub async fn run(
        &self,
        signal: impl Future<Output = ()>,
        drain_delay: Duration,
        timeout: Duration,
    ) {
        signal.await;
        tracing::info!(?drain_delay, "shutdown: draining");
        self.draining.cancel();
        tokio::time::sleep(drain_delay).await;
        tracing::info!("shutdown: stopping");
        self.stopping.cancel();
        self.tasks.close();
        if tokio::time::timeout(timeout, self.tasks.wait())
            .await
            .is_err()
        {
            tracing::warn!(
                remaining = self.tasks.len(),
                "shutdown: timed out waiting for tasks"
            );
        }
    }
}

/// Resolves on SIGTERM or SIGINT (Ctrl-C).
pub async fn signal() {
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = term => {}
    }
}
