# Storage adapters

The push service stores everything through one trait, `webpush_service::store::Store`. Any database works once it implements that trait: PostgreSQL, SQLite, Redis, DynamoDB, or something in-house. This guide explains what the trait asks for, how to implement it, and how to prove the implementation correct.

## What the service needs from storage

The trait speaks in protocol terms, not rows or keys:

| Concept | Operations |
|---|---|
| User agents | `create_user_agent`, `user_agent_exists` |
| Subscriptions | `channel`, `create_subscription`, `subscription_by_push`, `delete_subscription` |
| Messages | `insert_message`, `pending`, `message`, `delete_message` |
| Receipts | `create_receipt_sub`, `receipt_sub_exists`, `delete_receipt_sub`, `enqueue_receipt`, `queued_receipts`, `delete_receipt` |
| Expiry | `reap` |

Each method returns `impl Future + Send`, so an implementation can be written with `async fn`. Failures of the backend are errors (`BoxError`); "not found" is `None` or `false`.

Beyond the signatures, the service relies on a few guarantees. These are where adapters differ in effort:

| Guarantee | Why the service needs it | PostgreSQL / SQLite | Redis |
|---|---|---|---|
| A message with a topic atomically replaces the stored message with the same `(uaid, channel_id, topic)` | RFC 8030 §5.4: body, TTL, urgency, and receipt settings change together | Upsert on a unique index over those columns | `MULTI` or a Lua script |
| `delete_message(id, owner)` deletes only the message currently stored under `id`, optionally only for that owner | A replaced message must never match; a user agent must not delete another's message | `DELETE … WHERE id = $1 AND uaid = $2 AND channel_id = $3 RETURNING *` | Lua script comparing before deleting |
| `pending` returns unexpired messages oldest first | Delivery order and TTL (RFC 8030 §5.2) | `WHERE uaid = $1 AND expiry > $2 ORDER BY accepted` | Sorted set by acceptance time |
| `delete_subscription` and `reap` queue a 410 receipt for each deleted message that requested one | RFC 8030 §6.2 | One transaction | Lua script |
| `enqueue_receipt` returns `None` once the receipt subscription is gone | Receipts for deleted subscriptions are dropped | Foreign key or existence check | Existence check in the script |
| Receipt sequence numbers increase | Receipts are delivered in order | A sequence, or the shared `next_seq` clock | `INCR` |

The rustdoc of `Store` documents each method in detail: `cargo doc --open`, then `store::Store`.

## Implementing an adapter

An adapter is a type that implements `Store`. The following skeleton shows the shape for a SQL database with `sqlx`; the two methods with the interesting guarantees are filled in, and the rest follow the same pattern:

```rust
use webpush_service::{BoxError, store::{Message, Receipt, Store, Subscription}};

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

    async fn delete_message(
        &self,
        id: &str,
        owner: Option<(&str, &str)>,
    ) -> Result<Option<Message>, BoxError> {
        // One statement: the row is deleted only if it is still the message
        // with this id and belongs to the owner, and is returned if it was.
        let row = sqlx::query(
            "DELETE FROM messages
             WHERE id = $1 AND ($2::text IS NULL OR (uaid = $2 AND channel_id = $3))
             RETURNING *",
        )
        .bind(id)
        .bind(owner.map(|(uaid, _)| uaid))
        .bind(owner.map(|(_, ch)| ch))
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(message_from_row))
    }

    // create_user_agent, channel, pending, reap, and the receipt methods
    // follow the same pattern.
}
```

A few details apply to every backend:

- **Ids.** `create_user_agent` returns 32 lowercase hexadecimal characters. `create_subscription` and `create_receipt_sub` generate random 128-bit ids, 22 base64url characters, unrelated to the user agent or channel. This is what keeps push endpoints unlinkable ([Privacy and security](privacy-and-security.md#unlinkability)).
- **Times.** `accepted` and `expiry` are Unix milliseconds. `pending(uaid, now)` excludes messages with `expiry <= now`.
- **Expiry.** `reap(now)` must handle messages that requested receipts. It may also free expired messages without receipts, or leave them to the database's own expiry, as the Bigtable adapter leaves them to garbage collection.

## Checking an adapter

`webpush_service::store::contract::check` runs every guarantee against a store and panics with a description of the first violation. Call it from a test in the crate that implements the adapter:

```rust
use webpush_service::store::contract;

#[tokio::test]
async fn pg_store_meets_the_contract() {
    let store = PgStore::connect("postgres://localhost/push_test").await.unwrap();
    contract::check(&store).await;
}
```

Each check creates its own user agents, subscriptions, and receipt subscriptions with fresh random ids, so it can run against a shared or persistent database without cleaning up first. This repository runs the same checks against both of its adapters in `tests/store.rs`.

For end-to-end confidence, run the conformance suite on your adapter too: `tests/common/mod.rs` starts the server under test in `TestServer::start`, and switching the store there puts every protocol test on your backend.

## Using an adapter

Pass the store to `serve`:

```rust
let store = PgStore::connect(&database_url).await?;
webpush_service::serve(listener, cfg, store).await?;
```

`serve` is generic over the store, so there is no dynamic dispatch and no feature flag required for your adapter. To make it selectable in the bundled binary, add a branch for it in `src/main.rs` next to `memory` and `bigtable`.

## Next steps

- [Architecture](architecture.md#storage) explains how the service uses storage.
- [Running the service](running.md) covers the memory and Bigtable adapters.
