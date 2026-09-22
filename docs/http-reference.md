# HTTP reference

Every HTTP request this push service accepts, with its headers, bodies, and status codes. User agents use the WebSocket on `/`, described in the [WebSocket protocol reference](websocket-protocol.md). Application servers use the endpoints below, and discover all of them from `pushEndpoint`, `Location`, and `Link`; they never construct a path.

All targets in `Location` and `Link` are absolute URLs built from the configured origin. Every `{id}` is 22 base64url characters. An id of any other shape gets `404` without a storage lookup. Every endpoint works over HTTP/1.1 and HTTP/2.

## Summary

| Method | Path | Operation | Success |
|---|---|---|---|
| `GET` (WebSocket upgrade) | `/` | [User agent session](websocket-protocol.md) | `101` |
| `POST` | `/push/{id}` | [Send a message](#send-a-message) | `201`, `202` |
| `GET` | `/message/{id}` | [Read a message](#read-a-message) | `200` |
| `DELETE` | `/message/{id}` | [Withdraw a message](#withdraw-a-message) | `204` |
| `GET` | `/receipt-subscription/{id}` | [Receive receipts](#receive-receipts) | `200` stream, or `204` |
| `DELETE` | `/receipt-subscription/{id}` | [Delete a receipt subscription](#delete-a-receipt-subscription) | `204` |

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

The body is forwarded unchanged. At most 4096 octets. An empty body is allowed.

### Responses

| Status | Meaning |
|---|---|
| `201 Created` | Stored. `Location` is the message, `TTL` the lifetime granted |
| `202 Accepted` | Stored, receipt requested. Also includes a `Link` with `rel="urn:ietf:params:push:receipt"` |
| `400 Bad Request` | `TTL` missing or malformed; `Urgency` or `Topic` invalid or repeated; receipt `Link` unknown; VAPID `k` equals the `aes128gcm` key id |
| `401 Unauthorized` | The subscription is restricted and the request has no VAPID credentials. Includes `WWW-Authenticate: vapid` |
| `403 Forbidden` | VAPID credentials present but invalid: malformed, not ES256, bad signature, expired, expiring more than 24 hours ahead, wrong `aud`, or signed by a key other than the one the subscription is restricted to |
| `404 Not Found` | The push endpoint does not exist or its subscription was deleted |
| `413 Payload Too Large` | Body over 4096 octets |

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

A comment line, `: keepalive`, is sent every 30 seconds while the stream is idle.

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
