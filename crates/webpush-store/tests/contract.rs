//! The `Store` contract, checked against every adapter in this crate.
//! Adapters in other crates run the same checks by calling
//! `webpush_store::contract::check`.
#![allow(clippy::unwrap_used)]

use webpush_store::{MemoryStore, contract};

/// The in-memory adapter meets the contract.
#[tokio::test(flavor = "multi_thread")]
async fn memory_store_meets_contract() {
    contract::check(&MemoryStore::new()).await;
}

/// The Bigtable adapter meets the contract, against a fresh emulator.
#[cfg(feature = "bigtable")]
#[tokio::test(flavor = "multi_thread")]
async fn bigtable_store_meets_contract() {
    let (_emulator, store) = emulator::start(60 * 24 * 3600).await;
    contract::check(&store).await;
}

/// Cloud Bigtable meets the contract. Opt in with `--ignored` and name the
/// table in `BIGTABLE_LIVE`, as `project/instance/table`; credentials come
/// from Application Default Credentials. The checks create their own rows
/// and do not touch existing data.
#[cfg(feature = "bigtable")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a Cloud Bigtable table and credentials"]
async fn live_bigtable_meets_contract() {
    use webpush_store::{BigtableConfig, BigtableStore};
    let spec = std::env::var("BIGTABLE_LIVE").expect("BIGTABLE_LIVE=project/instance/table");
    let [project, instance, table]: [&str; 3] = spec
        .split('/')
        .collect::<Vec<_>>()
        .try_into()
        .expect("BIGTABLE_LIVE=project/instance/table");
    let cfg = BigtableConfig {
        endpoint: "https://bigtable.googleapis.com".to_owned(),
        project: project.to_owned(),
        instance: instance.to_owned(),
        table: table.to_owned(),
        max_ttl: 60 * 24 * 3600,
        credentials_file: None,
        app_profile: None,
    };
    BigtableStore::ensure_table(&cfg).await.unwrap();
    contract::check(&BigtableStore::connect(&cfg).await.unwrap()).await;
}

#[cfg(feature = "bigtable")]
mod emulator;
