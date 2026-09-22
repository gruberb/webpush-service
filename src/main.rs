//! Push service binary. Configuration comes from the environment:
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `PUSH_LISTEN` | `0.0.0.0:8443` | Listen address |
//! | `PUSH_ORIGIN` | `https://localhost:8443` | Public origin, see [`Config::origin`] |
//! | `PUSH_TLS_CERT` | required | Path to the PEM certificate chain |
//! | `PUSH_TLS_KEY` | required | Path to the PEM private key |
//! | `PUSH_STORE` | `memory` | `memory`, or `bigtable` when built with the `bigtable` feature |
//! | `BIGTABLE_ENDPOINT` | `http://127.0.0.1:8086` | Bigtable gRPC endpoint |
//! | `BIGTABLE_PROJECT` | `dev` | Google Cloud project |
//! | `BIGTABLE_INSTANCE` | `dev` | Bigtable instance |
//! | `BIGTABLE_TABLE` | `push` | Bigtable table |

use std::{env, time::Duration};

use webpush_service::{BoxError, Config, store::MemoryStore};

/// Messages are kept for at most 60 days.
const MAX_TTL: u32 = 60 * 24 * 3600;

/// A required environment variable.
fn var(name: &str) -> Result<String, BoxError> {
    env::var(name).map_err(|_| format!("{name} is not set").into())
}

/// An optional environment variable, or `default`.
fn var_or(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_owned())
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing_subscriber::fmt::init();
    let cfg = Config {
        origin: var_or("PUSH_ORIGIN", "https://localhost:8443"),
        tls_cert_pem: std::fs::read_to_string(var("PUSH_TLS_CERT")?)?,
        tls_key_pem: std::fs::read_to_string(var("PUSH_TLS_KEY")?)?,
        max_ttl: MAX_TTL,
        max_payload: 4096,
        reaper_interval: Duration::from_secs(1),
    };
    let listener = tokio::net::TcpListener::bind(var_or("PUSH_LISTEN", "0.0.0.0:8443")).await?;
    match var_or("PUSH_STORE", "memory").as_str() {
        "memory" => webpush_service::serve(listener, cfg, MemoryStore::new()).await,
        #[cfg(feature = "bigtable")]
        "bigtable" => {
            use webpush_service::store::{BigtableConfig, BigtableStore};
            let bt = BigtableConfig {
                endpoint: var_or("BIGTABLE_ENDPOINT", "http://127.0.0.1:8086"),
                project: var_or("BIGTABLE_PROJECT", "dev"),
                instance: var_or("BIGTABLE_INSTANCE", "dev"),
                table: var_or("BIGTABLE_TABLE", "push"),
                max_ttl: MAX_TTL,
            };
            let store = BigtableStore::connect(&bt).await?;
            webpush_service::serve(listener, cfg, store).await
        }
        other => Err(format!(
            "PUSH_STORE={other} is not available; use \"memory\", or build with --features bigtable for \"bigtable\""
        )
        .into()),
    }
}
