# Storage adapters

The push service stores everything through one trait, `webpush_store::Store`. Any database works once it implements that trait: PostgreSQL, SQLite, Redis, DynamoDB, or something in-house. This guide explains what the trait asks for, how to implement it, and how to prove the implementation correct.

An adapter depends only on the `webpush-store` crate, not on the server.

## What the service needs from storage

The trait speaks in protocol terms, not rows or keys:

| Concept | Operations |
|---|---|
| User agents | `create_user_agent`, `user_agent`, `touch_user_agent`, `update_bridge_token`, `delete_user_agent`, `expire_user_agents`, `subscriptions` |
| Subscriptions | `channel`, `create_subscription`, `subscription_by_push`, `delete_subscription` |
| Messages | `insert_message`, `pending`, `message`, `delete_message` |
| Receipts | `create_receipt_sub`, `receipt_sub_exists`, `delete_receipt_sub`, `enqueue_receipt`, `queued_receipts`, `delete_receipt` |
| Expiry | `reap` |
| Routes | `set_route`, `route`, `clear_route` |

Each method returns `impl Future + Send`, so an implementation can be written with `async fn`. Failures of the backend are errors (`BoxError`); "not found" is `None` or `false`.

The types the methods take and return:

| Type | Fields |
|---|---|
| `UserAgent` | `uaid`, `bridge: Option<BridgeAddress>`, `last_seen` (Unix milliseconds) |
| `BridgeAddress` | `bridge` (for example `fcm`), `app_id`, `token` |
| `Subscription` | `uaid`, `channel_id`, `push`, `vapid` |
| `Message` | `id`, `uaid`, `channel_id`, `push`, `topic`, `body`, `ctype`, `cenc`, `ttl`, `urgency`, `accepted`, `expiry`, `rsub` |
| `Receipt` | `rsub`, `msg_id`, `status` |
| `Recipient` | `UserAgent(uaid)` or `Receipts(rsub)`: whose connection a route points to |

Beyond the signatures, the service relies on a few guarantees. These are where adapters differ in effort:

| Guarantee | Why the service needs it | PostgreSQL / SQLite | Redis |
|---|---|---|---|
| A message with a topic atomically replaces the stored message with the same `(uaid, channel_id, topic)` | RFC 8030 §5.4: body, TTL, urgency, and receipt settings change together | Upsert on a unique index over those columns | `MULTI` or a Lua script |
| `delete_message(id, owner)` deletes only the message currently stored under `id`, optionally only for that owner | A replaced message must never match; a user agent must not delete another's message | `DELETE … WHERE id = $1 AND uaid = $2 AND channel_id = $3 RETURNING *` | Lua script comparing before deleting |
| `pending(uaid, now, limit)` returns up to `limit` unexpired messages, oldest first | Delivery order, TTL (RFC 8030 §5.2), and backlog batches | `WHERE uaid = $1 AND expiry > $2 ORDER BY accepted LIMIT $3` | Sorted set by acceptance time |
| Deleting a subscription or user agent, `reap`, and `expire_user_agents` queue a 410 receipt for each deleted message that requested one | RFC 8030 §6.2 | One transaction | Lua script |
| `enqueue_receipt` returns `None` once the receipt subscription is gone | Receipts for deleted subscriptions are dropped | Foreign key or existence check | Existence check in the script |
| Receipt sequence numbers increase | Receipts are delivered in order | A sequence, or the shared `next_seq` clock | `INCR` |
| `touch_user_agent` and `update_bridge_token` never create a user agent, and the latter only updates bridged ones | Liveness and token refresh must not resurrect deleted user agents | `UPDATE … WHERE uaid = $1` | `SET … XX` |
| `clear_route(to, node)` removes the route only while it still names `node` | A node must never remove a route another node took over | `DELETE … WHERE recipient = $1 AND node = $2` | Lua script, or `WATCH` |
| `set_route` returns the previous node | Closing a superseded session early | `UPDATE … RETURNING` with the old value, or read then write | `SET … GET` |

`set_route` may return a slightly stale previous node if the backend has no atomic swap; the value only speeds up closing an old session.

Adapters that offer conditional writes over versioned cells, as Bigtable does, must evaluate the condition against the latest version only. Older versions stay readable until garbage collection removes them, and a predicate that matches an old version passes when it should fail.

The rustdoc of `Store` documents each method in detail: `cargo doc -p webpush-store --open`.

## Implementing an adapter

An adapter is a type that implements `Store`. The following skeleton shows the shape for a SQL database with `sqlx`; methods with interesting guarantees are filled in, and the rest follow the same pattern:

```rust
use webpush_store::{BoxError, Message, Recipient, Store};

pub struct PgStore {
    pool: sqlx::PgPool,
}

impl Store for PgStore {
    async fn insert_message(&self, m: &Message) -> Result<(), BoxError> {
        // A unique index on (uaid, channel_id, topic) WHERE topic IS NOT NULL
        // makes the replacement atomic. Messages without a topic never conflict.
        sqlx::query(
            "INSERT INTO messages (id, uaid, channel_id, topic, push, body, ctype, cenc,
                                   ttl, urgency, accepted, expiry, rsub)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
             ON CONFLICT (uaid, channel_id, topic) WHERE topic IS NOT NULL
             DO UPDATE SET id = EXCLUDED.id, push = EXCLUDED.push, body = EXCLUDED.body,
                           ctype = EXCLUDED.ctype, cenc = EXCLUDED.cenc, ttl = EXCLUDED.ttl,
                           urgency = EXCLUDED.urgency, accepted = EXCLUDED.accepted,
                           expiry = EXCLUDED.expiry, rsub = EXCLUDED.rsub",
        )
        // .bind(...) for every column
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn clear_route(&self, to: &Recipient, node: &str) -> Result<bool, BoxError> {
        // Conditional on the node, so a stale cleanup never removes a newer route.
        let done = sqlx::query("DELETE FROM routes WHERE recipient = $1 AND node = $2")
            .bind(recipient_key(to))
            .bind(node)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() == 1)
    }

    // The remaining methods follow the same pattern.
}
```

A few details apply to every backend:

- **Ids.** The caller generates user agent ids with `webpush_store::new_uaid` (32 lowercase hexadecimal characters) and passes the whole `UserAgent` to `create_user_agent`. `create_subscription` and `create_receipt_sub` generate random 128-bit ids with `webpush_store::new_id`, 22 base64url characters, unrelated to the user agent or channel. This is what keeps push endpoints unlinkable ([Privacy and security](privacy-and-security.md#unlinkability)).
- **Times.** `accepted`, `expiry`, and `last_seen` are Unix milliseconds. `pending(uaid, now, limit)` excludes messages with `expiry <= now`, and `expire_user_agents(cutoff)` deletes user agents with `last_seen < cutoff`.
- **Expiry.** `reap(now)` must handle messages that requested receipts. It may also free expired messages without receipts, or leave them to the database's own expiry, as the Bigtable adapter leaves them to garbage collection.
- **Several nodes.** In a cluster every node uses the store concurrently. Deletions in `reap` and `expire_user_agents` must happen once, so two nodes running them at the same time never owe the same receipt twice.

## Checking an adapter

`webpush_store::contract::check` runs every guarantee against a store and panics with a description of the first violation. Call it from a test in the crate that implements the adapter:

```rust
use webpush_store::contract;

#[tokio::test]
async fn pg_store_meets_the_contract() {
    let store = PgStore::connect("postgres://localhost/push_test").await.unwrap();
    contract::check(&store).await;
}
```

Each check creates its own user agents, subscriptions, receipt subscriptions, and routes with fresh random ids, so it can run against a shared or persistent database without cleaning up first. The expiry check uses `last_seen` values far in the past, so it only affects the user agents it creates. This repository runs the same checks against both of its adapters in `crates/webpush-store/tests/contract.rs`.

For end-to-end confidence, run the server's conformance suite on your adapter too: `crates/webpush-server/tests/common/mod.rs` starts the server under test in `TestServer::start_with`, and switching the store there puts every protocol test on your backend.

## Using an adapter

Pass the store to `webpush_server::Server`:

```rust
let cfg = webpush_server::config::Config::load(Some("webpush.toml".as_ref()))?;
let store = PgStore::connect(&database_url).await?;
webpush_server::Server::new(cfg, store)
    .run(webpush_server::shutdown::signal())
    .await?;
```

`Server` is generic over the store, so there is no dynamic dispatch and no feature flag required for your adapter. To make it selectable in the bundled binary, add a variant to `config::Store` and a branch in `crates/webpush-server/src/main.rs` next to `memory` and `bigtable`.

`MemoryStore` clones share one state, which lets tests run several servers, such as an endpoint node and connection nodes, over one in-memory store. The binary refuses the memory store when a cluster is configured, because separate processes cannot share it.

## Next steps

- [Architecture](architecture.md#storage) explains how the service uses storage.
- [Running the service](running.md#running-on-bigtable) runs the service on Bigtable.
