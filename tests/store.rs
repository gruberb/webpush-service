//! The `Store` contract (`TECH_SPEC.md` §7.2), checked against every adapter
//! in this crate. Adapters in other crates run the same checks by calling
//! `webpush_service::store::contract::check`.

mod common;

use webpush_service::store::{MemoryStore, contract};

/// §7.2: the in-memory adapter meets the contract.
#[tokio::test(flavor = "multi_thread")]
async fn memory_store_meets_contract() {
    contract::check(&MemoryStore::new()).await;
}

/// §7.2: the Bigtable adapter meets the contract, against a fresh emulator.
#[cfg(feature = "bigtable")]
#[tokio::test(flavor = "multi_thread")]
async fn bigtable_store_meets_contract() {
    let (_emulator, store) = common::bigtable::start(60 * 24 * 3600).await;
    contract::check(&store).await;
}
