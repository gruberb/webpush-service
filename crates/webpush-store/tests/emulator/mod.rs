//! Starts a Bigtable emulator for tests: `$CBTEMULATOR`, or the copy that
//! ships with the gcloud SDK.
#![allow(dead_code)]

use std::{
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use webpush_store::{BigtableConfig, BigtableStore};

/// A TCP port that was free a moment ago.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Path to the Bigtable emulator: `$CBTEMULATOR`, else the gcloud SDK
/// copy.
fn cbtemulator() -> String {
    if let Ok(p) = std::env::var("CBTEMULATOR") {
        return p;
    }
    let out = Command::new("gcloud")
        .args(["info", "--format=value(installation.sdk_root)"])
        .output()
        .expect("set $CBTEMULATOR or install gcloud with the bigtable emulator");
    let root = String::from_utf8(out.stdout).unwrap();
    format!("{}/platform/bigtable-emulator/cbtemulator", root.trim())
}

/// Start an emulator, create the table, and connect a store to it.
pub async fn start(max_ttl: u32) -> (Emulator, BigtableStore) {
    let port = free_port();
    let emulator = Emulator(
        Command::new(cbtemulator())
            .args(["-host", "127.0.0.1", "-port", &port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn cbtemulator"),
    );
    let cfg = BigtableConfig {
        endpoint: format!("http://127.0.0.1:{port}"),
        project: "test".to_owned(),
        instance: "test".to_owned(),
        table: "push".to_owned(),
        max_ttl,
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match BigtableStore::ensure_table(&cfg).await {
            Ok(()) => break,
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => panic!("ensure_table: {e}"),
        }
    }
    let store = BigtableStore::connect(&cfg).await.expect("connect");
    (emulator, store)
}

/// Kills the emulator on drop, including when `start` panics part way.
pub struct Emulator(std::process::Child);

impl Drop for Emulator {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
