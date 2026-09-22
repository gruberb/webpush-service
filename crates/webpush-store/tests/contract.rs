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

#[cfg(feature = "bigtable")]
mod emulator;
