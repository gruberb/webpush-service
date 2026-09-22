# Running the service

This guide runs the push service locally, verifies it, connects Firefox to it, and runs the test suite. At the end you have a push service on `https://localhost:8443` that the other guides use. [Deployment](deployment.md) covers production and multi-node setups.

## Prerequisites

- Rust 1.88 or later with Cargo. The workspace uses the 2024 edition.
- OpenSSL, to create a development certificate.
- `curl`, to verify the service.
- Optional: the Google Cloud SDK with the Bigtable emulator (`gcloud components install bigtable`), to run on Bigtable instead of in memory.

## Creating a development certificate

To create a self-signed P-256 certificate for `localhost`, valid for 30 days:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" \
  -keyout key.pem -out cert.pem
```

Clients must trust this certificate, or skip verification during development (`curl -k`).

## Writing a configuration file

The service reads a TOML file. The only required setting is `origin`; everything else has a production default, listed in the [configuration reference](configuration.md). For local development, create `webpush.toml` next to the certificate:

```toml
origin = "https://localhost:8443"

[public.tls]
cert_file = "cert.pem"
key_file = "key.pem"

[internal]
listen = "127.0.0.1:8081"

[shutdown]
drain_delay = "0s"
```

This serves user agents and application servers on `0.0.0.0:8443` over TLS, opens the internal listener for probes and metrics on port 8081, and skips the shutdown drain delay, which only matters behind a load balancer. `config/webpush.example.toml` in the repository lists every setting with its default.

## Starting the service

From the repository root, start the binary with the file:

```bash
cargo run --release -p webpush-server -- --config webpush.toml
```

Without `--config`, the binary reads the file named by `WEBPUSH_CONFIG`. With neither, it takes every setting from the environment.

The service keeps its state in memory and logs one line per request with the method, route template, status, and latency. Stopping it discards all subscriptions and messages.

### Overriding settings from the environment

Every setting can be set or overridden with an environment variable: `WEBPUSH_` followed by the setting's path, with `__` between levels. Environment variables take precedence over the file:

| Setting | Variable |
|---|---|
| `role` | `WEBPUSH_ROLE=endpoint` |
| `origin` | `WEBPUSH_ORIGIN=https://push.example.net` |
| `cluster.token` | `WEBPUSH_CLUSTER__TOKEN=...` |
| `store.bigtable.table` | `WEBPUSH_STORE__BIGTABLE__TABLE=push` |

Keep secrets (`cluster.token`, `registration.secret_keys`) in the environment rather than in the file.

## Verifying the service

With the internal listener configured, check liveness and readiness:

```bash
curl -s http://127.0.0.1:8081/health
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8081/ready
```

```text
ok
200
```

`/ready` answers `200` once the store responds, and `503` from the moment shutdown starts. `/version` returns the crate name and version, and `/metrics` returns Prometheus text; [Deployment](deployment.md#metrics) lists the metrics.

A subscription needs a user agent session, which `curl` cannot open. To exercise the full flow, connect Firefox as described next, or run the test suite.

## Connecting Firefox

1. Import `cert.pem` into Firefox under **Settings > Privacy & Security > Certificates > View Certificates > Authorities**, and trust it for websites.
2. In `about:config`, set `dom.push.serverURL` to `wss://localhost:8443/`.
3. Restart Firefox.

Subscriptions created by any page now have endpoints on `https://localhost:8443/push/`. [Connecting a client](connecting-a-client.md#using-firefox) shows a subscription from JavaScript, and [Sending a message](sending-a-message.md) sends one to it. To switch back to Firefox's default service, reset `dom.push.serverURL`.

## Logs

Logs go to standard output. Two settings control them:

| Setting | Values | Default |
|---|---|---|
| `log.level` | A `tracing` filter, for example `info` or `info,webpush_server=debug` | `info` |
| `log.format` | `text` for people, `json` for log collectors | `text` |

`RUST_LOG`, when set, replaces `log.level`. Logs never contain capability URLs, message bodies, or device tokens: request lines record the route template (`/push/{id}`), not the path.

## Stopping the service

On SIGTERM or SIGINT the service shuts down in stages:

1. `/ready` starts answering `503`.
2. After `shutdown.drain_delay` (default 5 seconds), listeners stop accepting, sessions close with WebSocket code 1001, receipt streams end, and in-flight requests finish.
3. The process exits once everything has finished, or after `shutdown.timeout` (default 30 seconds).

Firefox reconnects after a 1001 close, so a rolling restart loses no messages: undelivered messages stay in the store and arrive on the next session.

## Running on Bigtable

The Bigtable adapter keeps state across restarts and lets several nodes share it. The binary includes it when built with the `bigtable` feature. The endpoint's scheme decides how it connects:

| Endpoint | Transport | Authentication |
|---|---|---|
| `http://127.0.0.1:8086` (emulator) | plaintext | none |
| `https://bigtable.googleapis.com` | TLS | OAuth 2.0 token on every call |

### Against the emulator

To start the emulator on port 8086, run this in its own terminal:

```bash
gcloud beta emulators bigtable start --host-port=127.0.0.1:8086
```

Then add the store to `webpush.toml`. `create_table` creates the table and its column families if they do not exist, which is convenient against the emulator; keep it off for production tables provisioned ahead of time:

```toml
[store.bigtable]
endpoint = "http://127.0.0.1:8086"
project = "dev"
instance = "dev"
table = "push"
create_table = true
```

Start the service with the feature enabled:

```bash
cargo run --release -p webpush-server --features bigtable -- --config webpush.toml
```

### Against Cloud Bigtable

Point the endpoint at Google and name your instance and table:

```toml
[store.bigtable]
endpoint = "https://bigtable.googleapis.com"
project = "your-project"
instance = "your-instance"
table = "push"
create_table = true
```

Tokens come from `credentials_file`, a service account key, when set. Otherwise the service uses Application Default Credentials: on Cloud Run and GKE the workload's service account through the metadata server, so no key file is deployed; on a workstation the credentials from `gcloud auth application-default login`. The account needs `roles/bigtable.user`, and `roles/bigtable.admin` as well while `create_table` is on.

To check a table and your credentials before deploying, run the store contract against it. It writes its own rows and leaves existing data alone:

```bash
BIGTABLE_LIVE=your-project/your-instance/push \
  cargo test -p webpush-store --features bigtable --test contract -- --ignored
```

The message column family's maximum age is `push.max_ttl` plus one day, so Bigtable discards expired messages on its own. [Architecture](architecture.md#bigtable-layout) describes the layout.

## Running in a container

The repository's `Dockerfile` builds the binary with both bridges and the Bigtable adapter into a distroless image that runs as a non-root user:

```bash
docker build -t webpush-server .
docker run -p 8443:8443 -p 8081:8081 \
  -v "$PWD/webpush.toml:/etc/webpush/webpush.toml:ro" \
  -e WEBPUSH_CONFIG=/etc/webpush/webpush.toml webpush-server
```

Without a mounted file, `WEBPUSH_*` environment variables alone configure the service. Platforms such as Cloud Run expect the listener on `$PORT`; set `WEBPUSH_PUBLIC__LISTEN=0.0.0.0:8080` accordingly and leave `[public.tls]` unset, since the platform terminates TLS.

## Running the tests

The whole suite runs against the in-memory store and needs nothing else:

```bash
cargo test --workspace
```

It covers the RFC test vectors, the application server interface, the user agent WebSocket protocol, the registration API and bridge delivery, clusters of endpoint and connection nodes, shutdown, limits, and the storage contract. The FCM and APNs bridges are tested against local fakes of the platform APIs. Test names cite the requirement they check; tests whose names start with `policy_` cover choices the specifications leave open.

To check the Bigtable adapter against its contract, and to run every server test on Bigtable, enable the feature. Each test starts its own emulator, found through `$CBTEMULATOR` or the gcloud installation:

```bash
cargo test -p webpush-store --features bigtable
PUSH_TEST_STORE=bigtable cargo test -p webpush-server --features bigtable
```

The lint gate is clippy with the workspace's pedantic settings:

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## Next steps

- [Connecting a client](connecting-a-client.md) subscribes and receives messages.
- [Connecting a publisher](connecting-a-publisher.md) prepares an application server.
- [Deployment](deployment.md) scales the service out.
