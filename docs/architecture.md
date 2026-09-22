# Architecture

This page describes how the push service is built: its crates, the roles a process can run, how a request moves through them, how nodes cooperate, how state is stored, and which tradeoffs the design makes. Read [Web Push concepts](concepts.md) first if the protocol itself is new to you.

## Goals and scope

The service implements the application server side of RFC 8030 and RFC 8292, speaks Firefox's WebSocket protocol to user agents, delivers to mobile apps through FCM and APNs, and includes RFC 8188 and RFC 8291 as a library. Its goals, in order:

1. Follow the RFC text wherever it is deployed. Where an RFC leaves a choice open, the choice is documented and covered by a test whose name starts with `policy_`.
2. Work with real clients: Firefox with one preference changed, and mobile apps through their platform's push service.
3. Scale out by adding processes, with storage behind a small, tested contract.
4. Stay small enough to read in a few sittings. Implementation details are configuration, not forks.

It deliberately does not do rate limiting. See [Tradeoffs](#tradeoffs).

## Why the user agent side is a WebSocket

RFC 8030 §6 delivers messages to user agents, and §6.3 delivers receipts to application servers, with HTTP/2 server push. That part of the RFC has no users left:

- Chrome 106 (2022) disabled HTTP/2 server push, Firefox 132 (2024) removed it, and nginx dropped it in 1.25.1. HTTP clients that still implement it usually disable it.
- No browser ever used RFC 8030 for Web Push delivery. Firefox holds a WebSocket to its push service, Chrome uses FCM, Edge uses WNS, and Safari uses APNs.
- The W3C Push API leaves the user agent protocol unspecified.

Firefox is the only browser whose push protocol is open and whose push server can be changed, so implementing that protocol makes the service usable by a real browser. Receipts keep their RFC 8030 role and URL, but are delivered as a Server-Sent Events stream, which any HTTP client can read.

Mobile operating systems do not let an app keep its own connection open in the background. Mobile apps therefore register a platform device token over HTTPS and receive messages through a bridge ([Mobile bridges](mobile-bridges.md)).

## Crates

The workspace splits along dependency lines, so an application server can use the cryptography without a server, and a storage or bridge implementation depends only on its small interface crate:

```text
                         webpush-server  (binary + library)
                  /        |          \            \
      webpush-crypto  webpush-store  webpush-bridge  webpush-fcm, webpush-apns
                                           ^                 |
                                           +-----------------+
```

| Crate | Responsibility | Depends on |
|---|---|---|
| `webpush-crypto` | RFC 8188 and RFC 8291 encryption, RFC 8292 VAPID verification. No I/O, no runtime | nothing in the workspace |
| `webpush-store` | The `Store` trait, its executable contract, the memory adapter, and the Bigtable adapter (feature `bigtable`) | nothing in the workspace |
| `webpush-bridge` | The `Bridge` trait, the notification fields every bridge delivers, and the error kinds | nothing in the workspace |
| `webpush-fcm` | FCM HTTP v1 bridge with OAuth 2.0 service account authentication | `webpush-bridge` |
| `webpush-apns` | APNs provider API bridge with ES256 provider tokens | `webpush-bridge` |
| `webpush-server` | Configuration, transport, the endpoint and connection roles, clustering, telemetry, and shutdown | all of the above; the bridges behind features `fcm` and `apns` (on by default) |

Inside `webpush-server`:

| Module | Responsibility |
|---|---|
| `lib.rs` | `Server` builder, role-dependent router assembly, CORS |
| `config.rs` | Settings, loading from TOML and `WEBPUSH_*`, validation |
| `transport.rs` | Accept loop, connection limit, TLS, handing each connection to hyper. Knows nothing about Web Push |
| `endpoint.rs` | Push and message resources, VAPID enforcement, bridged delivery |
| `receipts.rs` | Receipt streams as Server-Sent Events |
| `registration.rs` | Registration API for bridged user agents |
| `session.rs` | The Firefox-compatible user agent protocol |
| `hub.rs` | In-process fan-out to connections open on this node |
| `notify.rs` | Delivery to a connection on any node: routes and forwarding |
| `internal.rs` | Internal listener: probes, metrics, delivery from other nodes |
| `maintenance.rs` | Receipt reaper and user agent expiry |
| `shutdown.rs`, `telemetry.rs` | Graceful shutdown; logs and metrics |

## Roles

One binary runs in one of three roles, set by `role`:

| Role | Public listener serves | Background work |
|---|---|---|
| `all` (default) | WebSocket, push, messages, receipts, registration | reaper, expiry |
| `endpoint` | push, messages, receipts, registration | reaper, expiry |
| `connect` | WebSocket | none |

`all` runs everything in one process and needs no cluster. `endpoint` and `connect` together form a cluster over a shared store; [Deployment](deployment.md) shows how to run one. Endpoint nodes are stateless and scale by replicas. Connection nodes each hold their share of the WebSocket sessions.

## Handling a push

The router validates a push in a fixed order, so every error maps to one status:

```text
POST /push/{id}
  push id unknown ...................................... 404
  TTL, Urgency, Topic, receipt Link malformed .......... 400
  restricted subscription, no VAPID credentials ........ 401 + WWW-Authenticate: vapid
  VAPID invalid, or not the restricting key ............ 403
  aes128gcm keyid equals the VAPID key ................. 400
  session user agent: store, notify the session ........ 201, or 202 with receipt
  bridged user agent: hand to the bridge ............... 201, 410, 413, 429, 502
```

Bodies over `push.max_payload` (default 4096 octets) are rejected with `413` by the router's body limit while they are read, before the handler runs. A message for a bridged user agent is not stored: once the bridge accepts it, the platform service holds it until the device is reachable.

## Delivery across nodes

A single node delivers through the hub alone. In a cluster, the node that holds a connection records itself in the store as that connection's route, and other nodes forward events to it:

```text
 endpoint node                     store                  connection node
 -------------                     -----                  ---------------
                                                  hello:  set_route(ua, me)
                                                          read backlog
 POST /push/{id}
   insert_message --------------->  message
   hub: no local session
   route(ua) -------------------->  node URL
   POST {node}/internal/v1/notify ----------------------> hub.notify(ua)
                                                            200 delivered
                                                            404 not here
   clear_route(ua, node) -------->  removed only if it
                                    still names node
```

Why this never loses a message:

- **Store before routing.** The endpoint stores the message before it looks up the route. The connection node sets its route before it reads the backlog. So either the endpoint sees the new route and forwards the message, or the message was stored before the route existed and is in the backlog. A failed forward loses nothing either: the next session reads the message from storage.
- **Conditional cleanup.** A node removes its route when the connection ends. Any node that finds a route stale (the target answers `404` or refuses the connection) removes it too. `Store::clear_route` only removes a route that still names the node in question, so a stale cleanup never removes a newer route.
- **One listener per recipient.** When a user agent reconnects to another node, that node receives the previous route from `set_route` and forwards `Gone` to it, closing the older session.

Receipts use the same mechanism in the other direction. A receipt stream on an endpoint node records a route, and an acknowledgement on a connection node forwards the receipt to it.

The internal call is `POST /internal/v1/notify` on the target's internal listener, authenticated with the shared `cluster.token`. The listener compares SHA-256 digests of the presented and configured tokens, so the comparison time reveals nothing about the token.

## The hub

The hub maps each recipient (a `uaid`, or a receipt subscription) on this node to at most one listener. A new listener for the same recipient replaces the previous one, which receives `Gone`; that matches the single route per recipient in the store.

Each listener has a bounded queue of `websocket.queue` events (default 128). A connection that falls that far behind is dropped from the hub and closed: sessions with WebSocket code 1013, receipt streams by ending. The client reconnects and reads what it missed from storage.

Storage is the source of truth. The hub only notifies connections that are open now, and any event a connection misses is found in storage on the next connection. That is why dropping a slow listener, or losing a forward, never loses data.

## User agent sessions

A session is one WebSocket from one user agent, identified by its `uaid`:

```text
 client                         session task          hub / route          store
   | hello {uaid?}                  |                      |                  |
   |------------------------------->| known uaid? ----------------------------->|
   |                                | listen(ua) --------->| set_route -----> |
   | hello {uaid}                   |                      |                  |
   |<-------------------------------|                      |                  |
   | notification (first batch)     | pending(batch) ------------------------->|
   |<-------------------------------|                      |                  |
   | register / unregister / ack    |                      |                  |
   |------------------------------->|                      |                  |
   | notification (live)            |<----- Message -------|                  |
   |<-------------------------------|                      |                  |
```

The rules that keep delivery reliable without locks:

- **Listen before reading.** The session registers as the listener (and sets its route) before it reads stored messages. A message accepted in between arrives as a live event instead of being missed. Duplicates from the overlap are dropped by message id.
- **Redeliver on reconnect.** Every new session reads all unacknowledged, unexpired messages. That is the retry RFC 8030 §6.2 asks for, with no retry timers. Firefox discards duplicates by `version`.
- **Batches.** The backlog goes out in batches of `websocket.backlog_batch` (default 100). The next batch is read once every message sent so far is acknowledged, so a large backlog never sits in memory at once.
- **Deferred creation.** A `hello` without a known `uaid` gets a fresh one, but nothing is stored until the first `register`. Clients that connect and never subscribe leave no state.
- **Pings.** The server sends a WebSocket ping every `websocket.ping_interval` (default 60 seconds), which keeps load balancers from closing idle sessions. A session that sends nothing for `ping_interval` plus `pong_timeout` is closed.
- **Live events skip the expiry check.** A message with TTL 0 is stored already expired, so reads of stored messages never return it, but a connected session receives it as a live event.

A connected user agent refreshes its `last_seen` on `hello` and every six hours while connected, so `user_agents.expire_after` never removes an active session.

## Receipt streams

`GET` on a receipt subscription opens a Server-Sent Events stream. The stream listens (and, in a cluster, sets its route), checks that the subscription exists, reads the queued receipts, writes them, and then writes live receipts as acknowledgements, expiries, and unsubscribes produce them. Each receipt is deleted from the queue once written, so delivery is at most once per receipt. A receipt subscription has one stream at a time; opening a second ends the first with `event: gone`, as does deleting the subscription.

## Bridges

A bridge hands one message to a platform push service. The server holds the configured bridges by name (`fcm`, `apns`), and a bridged user agent stores its bridge name, app id, and device token. On a push, the endpoint builds the notification fields (`channelID`, `version`, `data`, `encoding`, the same names as the WebSocket `notification`), maps urgency `high` to high priority and everything else to normal, and passes the TTL. Bridge failures map to statuses:

| Bridge error | Status | Side effect |
|---|---|---|
| Device token gone | `410` | The user agent and its subscriptions are deleted |
| Payload over the platform limit | `413` | |
| Platform rate limiting | `429`, with `Retry-After` when known | |
| Anything else | `502` | Logged |

The platform owns delivery once it accepts a message, so the service cannot observe acknowledgement and offers no receipts for bridged subscriptions. [Mobile bridges](mobile-bridges.md) covers the client side and configuration.

## Graceful shutdown

Every connection, session, stream, and background loop runs on one task tracker. On SIGTERM or SIGINT:

```text
signal --> /ready answers 503 --drain_delay--> stop accepting; sessions close
           (load balancer moves               with 1001; streams end; hyper
            new traffic away)                 finishes in-flight requests
                                              --timeout--> exit
```

Sessions and streams release their routes as they close, so other nodes stop forwarding to this one.

## Storage

All state goes through the `Store` trait in `webpush-store`. It is written in terms of the protocol (user agents, subscriptions, messages, receipts, routes), not rows or keys, so each backend can use its own consistency tools. `webpush_store::contract::check` verifies the guarantees against any implementation. [Storage adapters](storage-adapters.md) shows how to write one.

| Adapter | Feature | Use |
|---|---|---|
| `MemoryStore` | default | Development, tests, and single-node deployments that can lose undelivered messages on restart. Clones share state |
| `BigtableStore` | `bigtable` | Cloud Bigtable over gRPC: TLS and OAuth tokens (from `webpush-gcp-auth`) for `https` endpoints, plaintext for the emulator |

### Bigtable layout

One table with two column families:

| Family | Garbage collection | Holds |
|---|---|---|
| `d` | 1 version | User agents, subscriptions, receipt subscriptions, receipt queues, routes, indexes |
| `m` | 1 version, and at most `max_ttl` + 1 day old | Messages and the message index |

| Row key | Family | Columns | Purpose |
|---|---|---|---|
| `ua#{uaid}` | d | `seen`, and `bridge`, `app`, `token` for bridged user agents | User agent |
| `ch#{uaid}#{channelID}` | d | `push`, `vapid` | Subscription |
| `push#{push}` | d | `uaid`, `ch` | Push endpoint to subscription |
| `msg#{uaid}#{slot}` | m | `id`, `ch`, `push`, `body`, `ctype`, `cenc`, `ttl`, `expiry`, `urgency`, `accepted`, `rsub` | Message |
| `mid#{id}` | m | `row` | Message id to message row |
| `rsub#{rsub}` | d | `c` | Receipt subscription exists |
| `rq#{rsub}#{seq}` | d | `msg`, `status` | Queued receipts, oldest first |
| `rexp#{expiry}#{id}` | d | `row` | Expiry index for messages that requested receipts |
| `route#u:{uaid}`, `route#r:{rsub}` | d | `node` | Node holding the session or receipt stream |

`slot` is `t:{channelID}:{topic}` for messages with a topic, and `{accepted}{id}` otherwise, so all messages of a user agent are one prefix scan. Numbers in keys are fixed-width hexadecimal so lexical order matches numeric order.

Bigtable makes single-row writes atomic and nothing more, so the layout is built around that:

- **Topic replacement is one row write.** A topic message always lands in the same row. The write clears the row and sets every column in one atomic mutation.
- **Conditional writes check the latest value.** Message deletion, route cleanup, `touch_user_agent`, and `update_bridge_token` use `CheckAndMutateRow`. The predicates limit the check to the latest cell version, because older versions stay readable until garbage collection runs; without that, a node could remove a route another node had since taken over.
- **Index rows are written last and deleted last.** A reader can find an index row that points at nothing, which it ignores. It never finds data that is only half written.
- **`set_route` is a read followed by a write.** The previous node it returns can be slightly stale under a race; it is only used to close a superseded session early.

### Background work

Endpoint nodes run two loops. The reaper calls `Store::reap` every `push.reaper_interval` and announces the `410` receipts for messages that expired unacknowledged. When `user_agents.expire_after` is set, the expiry sweep calls `Store::expire_user_agents` every `user_agents.sweep_interval`. Both are safe on several nodes at once, because the store makes each deletion happen once. On Bigtable, the expiry sweep scans every user agent row, so run it rarely.

## Tradeoffs

| Decision | Gained | Given up | Revisit when |
|---|---|---|---|
| Firefox WebSocket protocol for user agents | A real browser can use the service; one code path for all HTTP | Literal conformance with RFC 8030 §4 and §6 | An open, standardized user agent protocol appears |
| Receipts over Server-Sent Events | Receipts work with any HTTP client | Literal conformance with RFC 8030 §6.3 | Same as above |
| Always store, then notify | One delivery path; a failed forward loses nothing | A store write and a route read on every push, even when the session is connected | Store write volume becomes the bottleneck |
| Routes in the application store | No coordination service | A route write per connect and a route read per push | Route traffic dominates the store; move routes to a dedicated low-latency store |
| Plaintext internal listener with a shared token | No certificate management inside the deployment | Relies on network isolation for confidentiality | The internal network is not trusted; put the internal listener behind mutual TLS |
| No receipts for bridged subscriptions | Honest semantics: platforms report acceptance, not delivery | Receipts for mobile apps | Platforms expose delivery acknowledgements |
| Redelivery only on reconnect | No timers or retry state | A connected client that ignores a message does not see it again until it reconnects | Clients need in-session retries |
| Receipt sequence numbers from the process clock | No shared counter | Strict ordering across nodes | Receipt order across nodes matters; add a node id or a store sequence |
| No rate limiting | Less code in the request path | Protection against a leaked push endpoint used for flooding | Deploy behind infrastructure that limits requests per push endpoint, or add a limiter layer |

## Next steps

- [Deployment](deployment.md) runs the roles in production.
- [WebSocket protocol reference](websocket-protocol.md) lists every user agent message.
- [HTTP reference](http-reference.md) lists every endpoint the service serves.
- [Storage adapters](storage-adapters.md) shows how to add a database.
