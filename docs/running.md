# Running the service

This guide runs the push service locally, verifies it, connects Firefox to it, and runs the test suite. At the end you have a push service on `https://localhost:8443` that the other guides use.

## Prerequisites

- Rust 1.97 or later with Cargo. The project uses the 2024 edition.
- OpenSSL, to create a development certificate.
- `curl`, to verify the service.
- Optional: the Google Cloud SDK with the Bigtable emulator (`gcloud components install bigtable cbt`), to run on Bigtable instead of in memory.

## Creating a development certificate

The service only speaks TLS. To create a self-signed P-256 certificate for `localhost`, valid for 30 days:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" \
  -keyout key.pem -out cert.pem
```

Clients must trust this certificate, or skip verification during development (`curl -k`).

## Starting the service

From the repository root, start the service with the certificate paths:

```bash
PUSH_TLS_CERT=cert.pem PUSH_TLS_KEY=key.pem cargo run --release
```

The service listens on `0.0.0.0:8443`, keeps its state in memory, and logs one line per request with the method, status, and latency. Stopping it discards all subscriptions and messages.

## Verifying the service

A subscription needs a user agent session, which `curl` cannot open, but you can confirm the WebSocket endpoint answers. A plain HTTP/1.1 request without a WebSocket upgrade is refused:

```bash
curl -k -i --http1.1 https://localhost:8443/
```

```text
HTTP/1.1 400 Bad Request
```

The `400` comes from the WebSocket endpoint on `/`, which means the service is up. To exercise the full flow, connect Firefox as described next, or run the test suite, which subscribes, pushes, and receives over real connections.

## Connecting Firefox

1. Import `cert.pem` into Firefox under **Settings > Privacy & Security > Certificates > View Certificates > Authorities**, and trust it for websites.
2. In `about:config`, set `dom.push.serverURL` to `wss://localhost:8443/`.
3. Restart Firefox.

Subscriptions created by any page now have endpoints on `https://localhost:8443/push/`. [Connecting a client](connecting-a-client.md#using-firefox) shows a subscription from JavaScript, and [Sending a message](sending-a-message.md) sends one to it. To switch back to Mozilla's service, reset `dom.push.serverURL`.

## Configuration

The binary reads its configuration from environment variables:

| Variable | Default | Description |
|---|---|---|
| `PUSH_LISTEN` | `0.0.0.0:8443` | Listen address |
| `PUSH_ORIGIN` | `https://localhost:8443` | Public origin. Base of every push endpoint and URL the service issues, and the value VAPID `aud` claims must match. Set it to the address clients use |
| `PUSH_TLS_CERT` | required | Path to the PEM certificate chain, leaf first |
| `PUSH_TLS_KEY` | required | Path to the PEM private key |
| `PUSH_STORE` | `memory` | `memory`, or `bigtable` when built with `--features bigtable` |
| `BIGTABLE_ENDPOINT` | `http://127.0.0.1:8086` | Bigtable gRPC endpoint |
| `BIGTABLE_PROJECT` | `dev` | Google Cloud project |
| `BIGTABLE_INSTANCE` | `dev` | Bigtable instance |
| `BIGTABLE_TABLE` | `push` | Table name |

The following limits are fixed in the binary. Embedding applications set them through `webpush_service::Config`:

| Setting | Value | Why |
|---|---|---|
| Maximum TTL | 60 days | Longer requests are reduced, and the response `TTL` reports the value used |
| Maximum body | 4096 octets | The minimum RFC 8030 requires every push service to accept |
| Reaper interval | 1 second | How quickly `410` receipts follow expiry |

`PUSH_ORIGIN` must match what clients see. If the service runs behind a load balancer on `https://push.example.net`, set `PUSH_ORIGIN=https://push.example.net`, or VAPID tokens from application servers fail with `403`.

## Running on Bigtable

The Bigtable adapter keeps state across restarts. It currently supports the emulator; production Bigtable needs TLS and Google Cloud authentication on the gRPC channel, which is not implemented yet.

To start the emulator on port 8086, run this in its own terminal:

```bash
gcloud beta emulators bigtable start --host-port=127.0.0.1:8086
```

In a second terminal, create the table with its two column families. [Architecture](architecture.md#bigtable-layout) explains what each holds:

```bash
export BIGTABLE_EMULATOR_HOST=127.0.0.1:8086
cbt -project dev -instance dev createtable push
cbt -project dev -instance dev createfamily push d
cbt -project dev -instance dev createfamily push m
cbt -project dev -instance dev setgcpolicy push d maxversions=1
cbt -project dev -instance dev setgcpolicy push m "maxversions=1 or maxage=61d"
```

The `m` family's maximum age is the 60-day TTL limit plus one day, so Bigtable discards expired messages on its own. Then start the service with the adapter:

```bash
PUSH_STORE=bigtable PUSH_TLS_CERT=cert.pem PUSH_TLS_KEY=key.pem cargo run --release --features bigtable
```

Embedding applications can call `BigtableStore::ensure_table` instead of using `cbt`; it creates the same schema.

## Running the tests

The whole suite runs against the in-memory store and needs nothing else:

```bash
cargo test
```

It covers the RFC test vectors, the application server interface, the user agent WebSocket protocol, and the storage contract. Test names cite the requirement they check; tests whose names start with `policy_` cover choices the specifications leave open.

To also check the Bigtable adapter against its contract, and to run every conformance test on Bigtable, enable the feature. Each test starts its own emulator, found through `$CBTEMULATOR` or the gcloud installation:

```bash
cargo test --features bigtable
PUSH_TEST_STORE=bigtable cargo test --features bigtable
```

## Next steps

- [Connecting a client](connecting-a-client.md) subscribes and receives messages.
- [Connecting a publisher](connecting-a-publisher.md) prepares an application server.
- [Storage adapters](storage-adapters.md) adds a database of your choice.
