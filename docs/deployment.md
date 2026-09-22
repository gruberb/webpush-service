# Deployment

This guide runs the push service in production: as one process, or as a cluster of endpoint and connection nodes that scale independently. It assumes you have run the service locally ([Running the service](running.md)).

## Choosing a topology

| Topology | Roles | Store | Use when |
|---|---|---|---|
| Single node | one `all` process | memory or Bigtable | Development, small deployments, one machine is enough |
| Cluster | `endpoint` replicas and `connect` nodes | Bigtable, or another shared adapter | Sessions or push traffic outgrow one machine, or you need rolling restarts without a single point of failure |

The memory store keeps state in one process, so a cluster needs a shared store. Use the Bigtable adapter; see [Running on Bigtable](running.md#running-on-bigtable). The repository's `Dockerfile` builds an image with every feature; see [Running in a container](running.md#running-in-a-container).

## Cluster layout

```text
               application servers                  browsers
                       |                               |
              HTTPS load balancer            WebSocket load balancer
                       |                               |
          +------------+------------+     +------------+------------+
          |  endpoint  |  endpoint  |     |  connect   |  connect   |
          +------------+------------+     +------------+------------+
                 |   internal: POST /internal/v1/notify   ^
                 +----------------------------------------+
                 |                                        |
                 +----------------> store <---------------+
                           messages, subscriptions, routes
```

- **Endpoint nodes** serve the application server API and the registration API, run the reaper and user agent expiry, and hold receipt streams. They keep no per-client state, so add replicas freely.
- **Connection nodes** hold WebSocket sessions. Each session records its node in the store as a route; endpoint nodes use it to forward messages. [Architecture](architecture.md#delivery-across-nodes) explains why this loses no messages.
- **Every node** exposes an internal listener that the other nodes must reach.

Both roles serve the same `origin`: connection nodes issue push endpoints on it, and the load balancer sends those URLs to endpoint nodes.

## Configuring the roles

The two roles share most settings. An endpoint node:

```toml
role = "endpoint"
origin = "https://push.example.net"

[public]
listen = "0.0.0.0:8443"

[internal]
listen = "0.0.0.0:8081"

[cluster]
node_url = "http://10.0.3.7:8081"   # this node's own internal address

[store.bigtable]
endpoint = "http://bigtable:8086"
project = "prod"
instance = "push"
table = "push"

[log]
format = "json"
```

A connection node uses the same file with `role = "connect"` and its own `node_url`. Set the shared secret on every node through the environment:

```bash
WEBPUSH_CLUSTER__TOKEN="$(cat /run/secrets/cluster-token)"
```

This example leaves out `[public.tls]` because the load balancer terminates TLS. Without a TLS-terminating proxy in front, configure `[public.tls]` on every node.

`node_url` must be unique per node and reachable from every other node. In Kubernetes, derive it from the pod IP, for example `WEBPUSH_CLUSTER__NODE_URL=http://$(POD_IP):8081`.

## Load balancers

- **Endpoint traffic** is plain request and response HTTP. Any HTTP load balancer works; the receipt streams are long-lived `text/event-stream` responses, so allow long response times on `/receipt-subscription/`.
- **WebSocket traffic** needs a load balancer that supports upgrades and keeps connections open. Its idle timeout must be longer than `websocket.ping_interval` (default 60 seconds), or it closes quiet sessions. Lower `ping_interval` if the load balancer's idle timeout is shorter, for example to 25 seconds for a 30-second timeout.
- **Registration** (`POST /v1/user-agents`) needs no credentials. Rate-limit it at the load balancer if the service is public.

## Health checks and shutdown

Point probes at the internal listener:

| Probe | Path | Meaning |
|---|---|---|
| Liveness | `GET /health` | The process runs |
| Readiness | `GET /ready` | The store answers a read, and the process is not shutting down |

On SIGTERM, `/ready` fails immediately, and the listeners close after `shutdown.drain_delay`. Set the drain delay to at least the time your load balancer needs to notice a failing readiness probe, and the platform's grace period above the sum of both shutdown settings:

```text
terminationGracePeriodSeconds  >  shutdown.drain_delay + shutdown.timeout
                  45           >          5s          +       30s
```

Connection nodes close their sessions with WebSocket code 1001 when they stop. Firefox reconnects, the load balancer sends it to another node, and the new session receives every undelivered message from the store.

Some platforms do not stop an old instance while it holds WebSockets. Cloud Run, for example, keeps a replaced revision's instance running until its open requests end or reach the request timeout, and sends no SIGTERM meanwhile. A single `role = "all"` instance on such a platform keeps its sessions after a rollout, while new pushes arrive at the new instance, so those sessions miss them until they reconnect. Set `websocket.max_session`, for example to `"10m"`, to bound that window: sessions end with 1001, clients reconnect to the current instance, and messages stored meanwhile arrive with the backlog.

## Metrics

`GET /metrics` on the internal listener returns the Prometheus text format. Labels never contain capability URLs or tokens; request metrics use the route template.

| Metric | Type | Labels |
|---|---|---|
| `webpush_http_requests_total` | counter | `method`, `route`, `status` |
| `webpush_http_request_duration_seconds` | histogram | `method`, `route` |
| `webpush_connections` | gauge | `listener` (`public`, `internal`) |
| `webpush_sessions` | gauge | |
| `webpush_messages_accepted_total` | counter | `via` (`websocket`, or the bridge name) |
| `webpush_messages_delivered_total` | counter | `via` (`websocket`, or the bridge name) |
| `webpush_bridge_errors_total` | counter | `bridge`, `kind` |
| `webpush_receipts_total` | counter | `status` |
| `webpush_remote_notify_total` | counter | `outcome` (`delivered`, `stale`, `unreachable`, `failed`) |
| `webpush_user_agents_expired_total` | counter | |
| `webpush_listener_dropped_total` | counter | |

Useful signals: a rising `outcome="failed"` rate means nodes cannot reach each other's internal listeners; `webpush_listener_dropped_total` means clients read too slowly for `websocket.queue`; `webpush_bridge_errors_total{kind="unavailable"}` points at platform credentials or outages.

## Capacity

| Setting | Default | Effect |
|---|---|---|
| `public.max_connections` | 100000 | Upper bound on open connections per node, WebSocket sessions included. Excess connections wait in the kernel accept queue. Size it together with the process file descriptor limit |
| `websocket.queue` | 128 | Live events buffered per session. Higher values tolerate slower clients at the cost of memory |
| `websocket.backlog_batch` | 100 | Stored messages read and sent at once on connect. Lower values reduce memory and store reads per batch for user agents with long backlogs |
| `websocket.max_session` | unset | Session lifetime before a 1001 close and reconnect. On Kubernetes, one to a few hours rebalances connections after a scale-out; see below for platforms that keep old instances alive |
| `websocket.ping_interval` | 60s | One small frame per session per interval. Shorter intervals keep load balancers happy at the cost of traffic |
| `user_agents.sweep_interval` | 1h | On Bigtable the sweep scans every user agent row; keep it infrequent |

## Next steps

- [Configuration reference](configuration.md) lists every setting.
- [Privacy and security](privacy-and-security.md#clusters-and-the-internal-listener) covers the internal listener and cluster token.
- [Mobile bridges](mobile-bridges.md) adds FCM and APNs.
