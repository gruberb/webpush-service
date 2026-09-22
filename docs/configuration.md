# Configuration reference

Every setting the service reads, with its default. The service loads a TOML file (`--config <file>`, or the file named by `WEBPUSH_CONFIG`) and then applies `WEBPUSH_*` environment variables on top. [Running the service](running.md#overriding-settings-from-the-environment) explains the variable names. `config/webpush.example.toml` in the repository lists the same settings as a commented file.

Durations are written as `"30s"`, `"5m"`, `"60days"`, and so on. Unknown settings are errors, so a typo stops the service at startup instead of being ignored.

## Top level

| Key | Default | Meaning |
|---|---|---|
| `role` | `"all"` | `all`, `endpoint`, or `connect`. See [Architecture](architecture.md#roles) |
| `origin` | required | Public origin, for example `https://push.example.net`: `https://`, no trailing slash. Base of every URL the service issues, and the value VAPID `aud` claims must match |

## `[public]`: user agents and application servers

| Key | Default | Meaning |
|---|---|---|
| `listen` | `"0.0.0.0:8443"` | Address to listen on |
| `max_connections` | `100000` | Open connections, WebSocket sessions included. At the limit the listener stops accepting until one closes |
| `handshake_timeout` | `"10s"` | Connections that have not finished the TLS handshake by then are dropped |
| `tls.cert_file` | none | PEM certificate chain, leaf first |
| `tls.key_file` | none | PEM private key of the leaf certificate |

Without `[public.tls]` the listener speaks plaintext HTTP/1.1 and HTTP/2. Only do that behind a proxy that terminates TLS.

## `[internal]`: probes, metrics, and delivery between nodes

| Key | Default | Meaning |
|---|---|---|
| `listen` | none | Address of the internal listener. Without `[internal]` there is no internal listener. Required with `[cluster]` |

The internal listener accepts up to 1024 connections. Its endpoints are listed in the [HTTP reference](http-reference.md#internal-listener).

## `[cluster]`: membership in a cluster

| Key | Default | Meaning |
|---|---|---|
| `node_url` | required | URL other nodes use to reach this node's internal listener, for example `http://10.0.3.7:8081`. Unique per node, stable for the life of the process |
| `token` | required | Shared secret, at least 16 characters, presented on every delivery between nodes. Set it with `WEBPUSH_CLUSTER__TOKEN` |
| `notify_timeout` | `"2s"` | How long a node waits for another to accept a delivery |

Without `[cluster]`, `role` must be `all`.

## `[push]`: push messages

| Key | Default | Meaning |
|---|---|---|
| `max_ttl` | `"60days"` | Longest time a message is stored. Longer requested TTLs are reduced, and the response `TTL` reports the value used |
| `max_payload` | `4096` | Largest accepted body in octets; larger bodies get `413`. At least 4096, as RFC 8030 §7.2 requires |
| `reaper_interval` | `"1s"` | How often expired messages that requested receipts are swept, which is when their `410` receipts go out |

## `[websocket]`: user agent sessions

| Key | Default | Meaning |
|---|---|---|
| `hello_timeout` | `"10s"` | A client that has not sent `hello` by then is disconnected |
| `ping_interval` | `"60s"` | Interval of WebSocket pings from the server |
| `pong_timeout` | `"30s"` | A session silent for `ping_interval` plus this long is closed |
| `backlog_batch` | `100` | Stored messages sent per batch on connect. The next batch follows the acknowledgement of the previous one |
| `queue` | `128` | Live events buffered per connection. A connection that falls this far behind is closed and catches up from storage |

## `[receipts]`: receipt streams

| Key | Default | Meaning |
|---|---|---|
| `keepalive` | `"30s"` | Interval of comment lines on an idle receipt stream |

## `[user_agents]`: liveness

| Key | Default | Meaning |
|---|---|---|
| `expire_after` | unset | Delete user agents, with their subscriptions, not seen for this long. Unset keeps them forever |
| `sweep_interval` | `"1h"` | How often expired user agents are swept |

A user agent is seen when it connects, every six hours while it stays connected, and when a bridged user agent calls `GET` or `PUT` on the registration API.

## `[cors]`: browser access to the application server API

| Key | Default | Meaning |
|---|---|---|
| `allowed_origins` | `[]` | Origins allowed to call the push, message, and receipt endpoints from a browser, or `["*"]` for any. Empty disables CORS |

## `[registration]`: bridged user agents

| Key | Default | Meaning |
|---|---|---|
| `secret_keys` | `[]` | Keys that derive the secret each bridged user agent authenticates with, at least 32 characters each. The first signs; all verify. Required when a bridge is configured. Set it with `WEBPUSH_REGISTRATION__SECRET_KEYS` |

## `[bridges.fcm]`: Firebase Cloud Messaging

Available when the binary is built with the `fcm` feature (on by default).

| Key | Default | Meaning |
|---|---|---|
| `timeout` | `"10s"` | Per-request timeout |
| `apps.<app id>.credentials_file` | required | Google service account JSON for the Firebase project |
| `apps.<app id>.endpoint` | `"https://fcm.googleapis.com"` | FCM base URL |

## `[bridges.apns]`: Apple Push Notification service

Available when the binary is built with the `apns` feature (on by default).

| Key | Default | Meaning |
|---|---|---|
| `timeout` | `"10s"` | Per-request timeout |
| `apps.<app id>.key_file` | required | The `.p8` signing key from Apple |
| `apps.<app id>.key_id` | required | Id of that key |
| `apps.<app id>.team_id` | required | Apple developer team id |
| `apps.<app id>.topic` | required | The app's bundle id |
| `apps.<app id>.environment` | `"production"` | `production` or `sandbox` |
| `apps.<app id>.endpoint` | by environment | Overrides the APNs base URL |
| `apps.<app id>.push_type` | `"background"` | `background` or `alert` |
| `apps.<app id>.aps` | `{"content-available": 1}` for background | The `aps` dictionary. Required for `alert` |

[Mobile bridges](mobile-bridges.md) explains how to choose between background and alert pushes.

## `[store]`: where state is kept

The default is the in-memory store. To use Bigtable, build with the `bigtable` feature and configure `[store.bigtable]`:

| Key | Default | Meaning |
|---|---|---|
| `endpoint` | required | gRPC endpoint, for example `http://127.0.0.1:8086` for the emulator |
| `project` | required | Google Cloud project |
| `instance` | required | Bigtable instance |
| `table` | required | Table |
| `create_table` | `false` | Create the table if it does not exist. For development only |

A cluster cannot use the memory store, because separate processes cannot share it.

## `[log]`: log output

| Key | Default | Meaning |
|---|---|---|
| `level` | `"info"` | A `tracing` filter directive, for example `info,webpush_server=debug`. `RUST_LOG` overrides it when set |
| `format` | `"text"` | `text` or `json` |

## `[shutdown]`: behaviour on SIGTERM and SIGINT

| Key | Default | Meaning |
|---|---|---|
| `drain_delay` | `"5s"` | Time between failing readiness and closing listeners, so load balancers stop sending new connections first |
| `timeout` | `"30s"` | Upper bound on finishing in-flight work after listeners close |

## Validation

The service refuses to start when settings contradict each other:

- `origin` is not `https://` or ends in `/`.
- `push.max_payload` is below 4096, or `websocket.backlog_batch`, `websocket.queue`, or `public.max_connections` is zero.
- `role` is `endpoint` or `connect` without `[cluster]`.
- `[cluster]` without `[internal]`, a `cluster.token` shorter than 16 characters, or a `node_url` that is not `http://` or `https://`.
- A bridge is configured without `registration.secret_keys`, or a secret key is shorter than 32 characters.
- A cluster with the memory store.
