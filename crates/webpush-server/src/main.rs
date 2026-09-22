//! Push service binary.
//!
//! ```text
//! webpush-server [--config <file>]
//! ```
//!
//! The configuration file defaults to `$WEBPUSH_CONFIG`; without either,
//! settings come from `WEBPUSH_*` environment variables alone. See
//! `webpush_server::config` for every setting.

use std::path::PathBuf;

use webpush_server::{BoxError, Server, bridges_from_config, config, shutdown, telemetry};
use webpush_store::{MemoryStore, Store};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let path = config_path()?;
    let cfg = config::Config::load(path.as_deref())?;
    telemetry::init_logging(&cfg.log)?;
    match cfg.store.clone() {
        config::Store::Memory if cfg.cluster.is_some() => {
            Err("nodes of a cluster cannot share the memory store".into())
        }
        config::Store::Memory => run(cfg, MemoryStore::new()).await,
        #[cfg(feature = "bigtable")]
        config::Store::Bigtable(bt) => {
            use webpush_store::{BigtableConfig, BigtableStore};
            let bt = BigtableConfig {
                endpoint: bt.endpoint,
                project: bt.project,
                instance: bt.instance,
                table: bt.table,
                max_ttl: u32::try_from(cfg.push.max_ttl.as_secs()).unwrap_or(u32::MAX),
            };
            if matches!(&cfg.store, config::Store::Bigtable(b) if b.create_table) {
                BigtableStore::ensure_table(&bt).await?;
            }
            run(cfg, BigtableStore::connect(&bt).await?).await
        }
        #[cfg(not(feature = "bigtable"))]
        config::Store::Bigtable(_) => {
            Err("store.bigtable requires a build with --features bigtable".into())
        }
    }
}

/// Build the bridges and serve until SIGTERM or SIGINT.
async fn run<S: Store>(cfg: config::Config, store: S) -> Result<(), BoxError> {
    let mut server = Server::new(cfg.clone(), store);
    for bridge in bridges_from_config(&cfg)? {
        tracing::info!(bridge = bridge.name(), "bridge enabled");
        server = server.bridge(bridge);
    }
    let result = server.run(shutdown::signal()).await;
    if let Err(e) = &result {
        tracing::error!(error = %e, "exiting");
    }
    result
}

/// `--config <file>`, else `$WEBPUSH_CONFIG`.
fn config_path() -> Result<Option<PathBuf>, BoxError> {
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next()) {
        (Some("--config"), Some(path)) => Ok(Some(path.into())),
        (None, _) => Ok(std::env::var_os("WEBPUSH_CONFIG").map(PathBuf::from)),
        _ => Err("usage: webpush-server [--config <file>]".into()),
    }
}
