# HTTP reference

Every HTTP request this push service accepts, with its headers, bodies, and status codes. Browsers use the WebSocket on `/`, described in the [WebSocket protocol reference](websocket-protocol.md). Mobile apps use the [registration API](#registration-api). Application servers use the push, message, and receipt endpoints, and discover all of them from `pushEndpoint`, `Location`, and `Link`; they never construct a path.

All targets in `Location` and `Link` are absolute URLs built from the configured `origin`. Every `{id}` is 22 base64url characters. An id of any other shape gets `404` without a storage lookup. Every endpoint works over HTTP/1.1 and HTTP/2.

Which endpoints a process serves depends on its role: `connect` serves only the WebSocket, `endpoint` serves everything else, and `all` serves both. Requests for a route the role does not serve get `404`.

## Summary

| Method | Path | Operation | Success |
|---|---|---|---|
| `GET` (WebSocket upgrade) | `/` | [User agent session](websocket-protocol.md) | `101` |
| `POST` | `/push/{id}` | [Send a message](#send-a-message) | `201`, `202` |
| `GET` | `/message/{id}` | [Read a message](#read-a-message) | `200` |
| `DELETE` | `/message/{id}` | [Withdraw a message](#withdraw-a-message) | `204` |
| `GET` | `/receipt-subscription/{id}` | [Receive receipts](#receive-receipts) | `200` stream, or `204` |
| `DELETE` | `/receipt-subscription/{id}` | [Delete a receipt subscription](#delete-a-receipt-subscription) | `204` |
| `POST` | `/v1/user-agents` | [Register a bridged user agent](#register-a-bridged-user-agent) | `201` |
| `GET` | `/v1/user-agents/{uaid}` | [Read a bridged user agent](#read-a-bridged-user-agent) | `200` |
| `PUT` | `/v1/user-agents/{uaid}` | [Replace the device token](#replace-the-device-token) | `204` |
| `DELETE` | `/v1/user-agents/{uaid}` | [Delete a bridged user agent](#delete-a-bridged-user-agent) | `204` |
| `PUT` | `/v1/user-agents/{uaid}/subscriptions/{channelID}` | [Create a bridged subscription](#create-a-bridged-subscription) | `201`, `200` |
| `DELETE` | `/v1/user-agents/{uaid}/subscriptions/{channelID}` | [Delete a bridged subscription](#delete-a-bridged-subscription) | `204` |

The [internal listener](#internal-listener) serves probes, metrics, and delivery between nodes on a separate port.

## Send a message

`POST /push/{id}` ([RFC 8030 §5](https://www.rfc-editor.org/rfc/rfc8030#section-5), [RFC 8292 §4.2](https://www.rfc-editor.org/rfc/rfc8292#section-4.2))

### Request

| Header | Required | Description |
|---|---|---|
| `TTL` | Yes | Seconds to keep the message: one or more digits, sent once. Values above the service maximum are reduced; values beyond 2^31 are treated as 2^31 |
| `Urgency` | No | One of `very-low`, `low`, `normal`, `high`. Default `normal` |
| `Topic` | No | 1 to 32 characters of `A-Z a-z 0-9 - _`. Replaces an undelivered message with the same topic on this subscription |
| `Prefer` | No | `respond-async` requests a delivery receipt. Parsed as a comma-separated list, so `wait=5, respond-async` also works |
| `Link` with `rel="urn:ietf:params:push:receipt"` | No | With `respond-async`, deliver the receipt to this existing receipt subscription instead of a new one |
| `Authorization` | Restricted subscriptions | `vapid t=<JWT>, k=<public key>` ([RFC 8292 §3](https://www.rfc-editor.org/rfc/rfc8292#section-3)) |
| `Content-Encoding` | No | Forwarded to the user agent as `headers.encoding`. Web Push payloads use `aes128gcm` |
| `Content-Type` | No | Kept for [message reads](#read-a-message). Not forwarded to the user agent |

The body is forwarded unchanged. At most `push.max_payload` octets (default 4096). An empty body is allowed.

### Responses

| Status | Meaning |
|---|---|
| `201 Created` | Stored, or accepted by the bridge for a bridged subscription. `Location` is the message, `TTL` the lifetime granted |
| `202 Accepted` | Stored, receipt requested. Also includes a `Link` with `rel="urn:ietf:params:push:receipt"`. Never returned for bridged subscriptions |
| `400 Bad Request` | `TTL` missing or malformed; `Urgency` or `Topic` invalid or repeated; receipt `Link` unknown; VAPID `k` equals the `aes128gcm` key id |
| `401 Unauthorized` | The subscription is restricted and the request has no VAPID credentials. Includes `WWW-Authenticate: vapid` |
| `403 Forbidden` | VAPID credentials present but invalid: malformed, not ES256, bad signature, expired, expiring more than 24 hours ahead, wrong `aud`, or signed by a key other than the one the subscription is restricted to |
| `404 Not Found` | The push endpoint does not exist or its subscription was deleted |
| `410 Gone` | Bridged subscription only: the platform reports the device token as no longer valid. The user agent and all its subscriptions are deleted; later pushes get `404` |
| `413 Payload Too Large` | Body over `push.max_payload`, or, for a bridged subscription, over the platform's limit |
| `429 Too Many Requests` | Bridged subscription only: the platform is rate limiting. `Retry-After` is included when the platform sent one |
| `502 Bad Gateway` | Bridged subscription only: the platform could not be reached, rejected the request, or refused the credentials |

### Bridged subscriptions

A push to a subscription of a [bridged user agent](mobile-bridges.md) goes to the platform push service instead of the store. Validation is identical up to that point, VAPID restrictions included. Then:

- The message is not stored. `Location` names a message id, but [reading](#read-a-message) or [withdrawing](#withdraw-a-message) it gets `404`.
- `Prefer: respond-async` is ignored and the response is `201` without a receipt `Link`. The platform reports acceptance, not delivery, so the service has no acknowledgement to report.
- `Topic` is not forwarded, so a later message does not replace an earlier one at the platform.
- `Urgency: high` asks the platform for high priority; every other urgency is normal priority.

```text
HTTP/2 202
location: https://push.example.net/message/gSKXfdV8jcmZ0HKx2r5--A
ttl: 60
link: <https://push.example.net/receipt-subscription/vfqjHA-BlQmJsjiEjDSOYg>; rel="urn:ietf:params:push:receipt"
```

## Read a message

`GET /message/{id}` ([RFC 8030 §8.3](https://www.rfc-editor.org/rfc/rfc8030#section-8.3))

Returns an undelivered, unexpired message.

| Field | Value |
|---|---|
| `content-type`, `content-encoding` | As sent, if present |
| `last-modified` | When the push service accepted the message |
| `cache-control` | `private` |
| body | The body exactly as sent |

| Status | Meaning |
|---|---|
| `200 OK` | The message |
| `404 Not Found` | Unknown, acknowledged, withdrawn, expired, or replaced |

## Withdraw a message

`DELETE /message/{id}`

Deletes an undelivered message. It is not delivered afterwards and produces no receipt. RFC 8030 assigns `DELETE` on the message to the user agent's acknowledgement; here the user agent acknowledges over the WebSocket, so `DELETE` is the application server's way to take a message back.

| Status | Meaning |
|---|---|
| `204 No Content` | Withdrawn |
| `404 Not Found` | Unknown, acknowledged, already withdrawn, expired, or replaced |

## Receive receipts

`GET /receipt-subscription/{id}` ([RFC 8030 §5.1](https://www.rfc-editor.org/rfc/rfc8030#section-5.1); delivery replaces §6.3)

Returns a `text/event-stream` (WHATWG HTML, "Server-sent events"). Queued receipts come first, oldest first, then new receipts as they occur. Each receipt leaves the queue once written.

### Request

| Header | Required | Description |
|---|---|---|
| `Prefer: wait=0` | No | Send the queued receipts, then end the stream. With nothing queued, the response is `204` |

### Events

```text
event: receipt
id: 1758561234000000
data: {"message":"https://push.example.net/message/QVUEoVnQK-l6vV-5Y95_7A","status":204}

```

| Event | Data | Meaning |
|---|---|---|
| `receipt` | `{"message": <message URL>, "status": 204}` | The user agent acknowledged the message |
| `receipt` | `{"message": <message URL>, "status": 410}` | Not delivered: the message expired, its subscription was deleted, or the user agent reported it could not decrypt or show it |
| `gone` | `{}` | The receipt subscription was deleted. The stream ends |

A comment line, `: keepalive`, is sent every `receipts.keepalive` (default 30 seconds) while the stream is idle. A receipt subscription has one open stream at a time: opening a second ends the first with `event: gone`.

| Status | Meaning |
|---|---|
| `200 OK` | The stream |
| `204 No Content` | `Prefer: wait=0` and nothing queued |
| `404 Not Found` | Unknown receipt subscription |

## Delete a receipt subscription

`DELETE /receipt-subscription/{id}` ([RFC 8030 §7.3](https://www.rfc-editor.org/rfc/rfc8030#section-7.3))

Deletes the receipt subscription and its queued receipts. Open streams end with an `event: gone`, receipts owed to it are dropped, and later pushes that name it get `400`.

| Status | Meaning |
|---|---|
| `204 No Content` | Deleted |
| `404 Not Found` | Unknown |

## Registration API

Mobile apps cannot hold a WebSocket in the background. They register the device token their platform issued and manage subscriptions over these endpoints; [Mobile bridges](mobile-bridges.md) walks through the flow. The API exists only when at least one bridge is configured; otherwise every path below gets `404`.

Request bodies are JSON with `Content-Type: application/json`. A request without that content type gets `415`, a body that is not JSON gets `400`, and a body with missing or unknown fields gets `422`. The optional body of [Create a bridged subscription](#create-a-bridged-subscription) is the exception: it needs no content type, and any malformed body gets `400`.

### Authentication

`POST /v1/user-agents` needs no credentials. It returns a `secret`, and every other request for that user agent must send it:

```text
Authorization: Bearer {secret}
```

| Problem | Status |
|---|---|
| No `Authorization`, another scheme, or a secret not issued for this `uaid` | `401` with `WWW-Authenticate: Bearer` |
| Valid secret, but the user agent was deleted or expired | `404` |

### Register a bridged user agent

`POST /v1/user-agents`

```json
{"bridge": "fcm", "appID": "example-android", "token": "dGVzdA:APA91b..."}
```

| Field | Meaning |
|---|---|
| `bridge` | A configured bridge: `fcm` or `apns` |
| `appID` | An application configured for that bridge |
| `token` | The device token the platform issued: 1 to 4096 characters of `A-Z a-z 0-9 - _ : .` |

| Status | Meaning |
|---|---|
| `201 Created` | Registered. `Location` is the user agent URL; the body is `{"uaid": "...", "secret": "..."}` |
| `400 Bad Request` | Unknown bridge, unknown app id, or invalid token |

### Read a bridged user agent

`GET /v1/user-agents/{uaid}`

Returns the user agent and its subscriptions, and counts as activity for `user_agents.expire_after`.

```json
{"uaid": "5f1a9c0e2b7d4e8f9a6b3c2d1e0f7a8b",
 "subscriptions": [{"channelID": "d9b74644-4f97-46aa-b8fa-9393985cd6cd",
                    "pushEndpoint": "https://push.example.net/push/FLhiBWT0-e7Hd6w8KEn1Qw"}]}
```

| Status | Meaning |
|---|---|
| `200 OK` | The user agent |
| `401`, `404` | See [Authentication](#authentication) |

### Replace the device token

`PUT /v1/user-agents/{uaid}` with `{"token": "..."}`. Later messages go to the new token. Counts as activity.

| Status | Meaning |
|---|---|
| `204 No Content` | Replaced |
| `400 Bad Request` | Invalid token |
| `401`, `404` | See [Authentication](#authentication) |

### Delete a bridged user agent

`DELETE /v1/user-agents/{uaid}`. Deletes the user agent and all its subscriptions. Their push endpoints return `404` from then on.

| Status | Meaning |
|---|---|
| `204 No Content` | Deleted |
| `401`, `404` | See [Authentication](#authentication) |

### Create a bridged subscription

`PUT /v1/user-agents/{uaid}/subscriptions/{channelID}`

The client names the subscription with a UUID, as it does over the WebSocket, so the request is idempotent. The body is optional:

```json
{"key": "BA1Hxzyi..."}
```

`key` restricts the subscription to an application server key (RFC 8292 §4.1), base64url, with or without padding. The response body is `{"channelID": "...", "pushEndpoint": "..."}`.

| Status | Meaning |
|---|---|
| `201 Created` | Created |
| `200 OK` | Already exists with the same key; same `pushEndpoint` |
| `400 Bad Request` | `channelID` is not a UUID, or `key` is not a P-256 public key |
| `409 Conflict` | Already exists with a different key |
| `401`, `404` | See [Authentication](#authentication) |

### Delete a bridged subscription

`DELETE /v1/user-agents/{uaid}/subscriptions/{channelID}`

| Status | Meaning |
|---|---|
| `204 No Content` | Deleted |
| `404 Not Found` | Unknown subscription, or see [Authentication](#authentication) |
| `401` | See [Authentication](#authentication) |

## Internal listener

With `[internal]` configured, a second listener serves plaintext HTTP on `internal.listen`. It must only be reachable from inside the deployment.

| Method | Path | Response |
|---|---|---|
| `GET` | `/health` | `200 ok` while the process runs |
| `GET` | `/ready` | `200` when the store answers a read, `503` when it does not or once shutdown has started |
| `GET` | `/version` | `{"name": "webpush-server", "version": "..."}` |
| `GET` | `/metrics` | Prometheus text format. [Deployment](deployment.md#metrics) lists the metrics |
| `POST` | `/internal/v1/notify` | Delivery from another node. `Authorization: Bearer {cluster.token}` is required: `401` without it, `200` when a connection on this node took the event, `404` when this node holds no such connection |
