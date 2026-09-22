# WebSocket protocol reference

Browsers talk to this service over one WebSocket, using the protocol Firefox speaks to its push service. This page lists every message. The field names, values, and behaviors match what Firefox sends and checks (`dom/push/PushServiceWebSocket.sys.mjs`), so a stock Firefox works against this service with `dom.push.serverURL` set to it.

For a walkthrough, see [Connecting a client](connecting-a-client.md).

## Connection

| Property | Value |
|---|---|
| URL | `wss://{origin}/` |
| Subprotocol | `push-notification`. The server selects it when offered |
| Frames | Text frames, each one JSON object. Binary frames close the connection |
| Largest client message | 64 KiB |
| First message | Must be `hello`, within `websocket.hello_timeout` (default 10 seconds) |
| Sessions | One per `uaid`, across all connection nodes. A new `hello` for a `uaid` closes the older connection |
| Server pings | A WebSocket ping every `websocket.ping_interval` (default 60 seconds) |
| Idle limit | A session that sends nothing, not even a pong, for `ping_interval` plus `websocket.pong_timeout` (default 30 seconds) is closed |

Every message is an object with a `messageType` field, except the short ping form `{}`. Unknown fields are ignored. Text that is not JSON, or an unknown `messageType`, closes the connection.

### Close codes

| Code | Sent when |
|---|---|
| `1000` | A newer session for the same `uaid` replaced this one (reason `replaced`) |
| `1001` | The service is shutting down, or the session was idle past the limit |
| `1002` | Protocol error: first message not `hello`, a second `hello`, or an invalid message |
| `1003` | The client sent a binary frame |
| `1013` | The session fell more than `websocket.queue` events behind. Reconnect; the missed messages are in storage |

Clients should reconnect with backoff after any close. Undelivered messages stay stored and arrive on the next session.

## Messages from the client

### `hello`

Starts the session. Sent once, as the first message.

```json
{"messageType": "hello", "uaid": "5f1a9c0e2b7d4e8f9a6b3c2d1e0f7a8b", "use_webpush": true, "broadcasts": {}}
```

| Field | Required | Meaning |
|---|---|---|
| `uaid` | No | The id from a previous session. Omit it to get a new one |
| `use_webpush` | No | Firefox sends `true`. Accepted and ignored |
| `broadcasts` | No | Broadcast subscriptions. This service offers no broadcasts; accepted and ignored |

### `register`

Creates a subscription.

```json
{"messageType": "register", "channelID": "d9b74644-4f97-46aa-b8fa-9393985cd6cd", "key": "BA1Hxzyi…="}
```

| Field | Required | Meaning |
|---|---|---|
| `channelID` | Yes | A UUID chosen by the client, hyphenated. Compared case-insensitively |
| `key` | No | Application server public key (RFC 8292 §4.1), base64url, with or without padding. Restricts the subscription to pushes signed by this key |

### `unregister`

Deletes a subscription. Its push endpoint returns `404` from then on, and messages that requested receipts produce `410` receipts.

```json
{"messageType": "unregister", "channelID": "d9b74644-4f97-46aa-b8fa-9393985cd6cd", "code": 200}
```

`code` is the reason Firefox reports: `200` manual, `201` quota exceeded, `202` permission revoked. It is informational.

### `ack`

Acknowledges delivered messages.

```json
{"messageType": "ack", "updates": [{"channelID": "d9b74644-4f97-46aa-b8fa-9393985cd6cd", "version": "QVUEoVnQK-l6vV-5Y95_7A", "code": 100}]}
```

| `code` | Meaning | Effect on the message | Receipt |
|---|---|---|---|
| `100` or absent | Delivered | Deleted | `204` |
| `101` | Decryption failed | Deleted | `410` |
| `102` | Not delivered | Deleted | `410` |
| anything else | | Unchanged | none |

Updates naming an unknown message, a message replaced by a newer topic message, or another subscription's message are ignored. No reply is sent.

### `nack`

Firefox reports that a message reached the device but its service worker failed. Accepted and ignored: delivery already happened, and the `ack` that Firefox sends decides the outcome.

```json
{"messageType": "nack", "version": "QVUEoVnQK-l6vV-5Y95_7A", "code": 301}
```

### `broadcast_subscribe`

Broadcast subscriptions. Broadcasts are not part of Web Push and this service offers none, so the message is accepted and ignored, and the `broadcasts` field of the server's `hello` is always `{}`.

### Ping

`{}` or `{"messageType": "ping"}`. The server answers `{}`.

## Messages from the server

### `hello`

```json
{"messageType": "hello", "uaid": "5f1a9c0e2b7d4e8f9a6b3c2d1e0f7a8b", "status": 200, "use_webpush": true, "broadcasts": {}}
```

`uaid` is 32 lowercase hexadecimal characters. It equals the client's `uaid` when the service knows it, and is new otherwise. A client that receives a different `uaid` must drop its stored subscriptions, as Firefox does.

A new `uaid` is not stored until the client's first `register`. A client that reconnects with a `uaid` it never registered anything under therefore gets a different one. The `uaid` of a bridged user agent is never accepted here and also gets a new one.

After `hello`, the server sends the stored, unexpired messages for the `uaid`, oldest first, in batches of `websocket.backlog_batch` (default 100). The next batch follows once every message sent so far has been acknowledged. A client that never acknowledges a message receives the rest of the backlog on its next session.

### `register`

```json
{"messageType": "register", "channelID": "d9b74644-4f97-46aa-b8fa-9393985cd6cd", "status": 200, "pushEndpoint": "https://push.example.net/push/FLhiBWT0-e7Hd6w8KEn1Qw"}
```

| `status` | Meaning |
|---|---|
| `200` | Registered, or already registered with the same key. `pushEndpoint` is present |
| `400` | Invalid `channelID` or `key` |
| `409` | Already registered with a different key |

`channelID` echoes the request. `pushEndpoint` is random and does not reveal the `uaid` or `channelID`.

### `unregister`

```json
{"messageType": "unregister", "channelID": "d9b74644-4f97-46aa-b8fa-9393985cd6cd", "status": 200}
```

Always status `200`, including for unknown channels.

### `notification`

```json
{"messageType": "notification", "channelID": "d9b74644-4f97-46aa-b8fa-9393985cd6cd", "version": "QVUEoVnQK-l6vV-5Y95_7A", "data": "DGv6ra1n…", "headers": {"encoding": "aes128gcm"}}
```

| Field | Present | Meaning |
|---|---|---|
| `channelID` | Always | The subscription |
| `version` | Always | The message id: the last path segment of the `Location` the application server received |
| `data` | Non-empty bodies | The body exactly as the application server sent it, base64url without padding |
| `headers.encoding` | When the push included `Content-Encoding` | The content coding, `aes128gcm` for Web Push |

Nothing else is sent: no TTL, urgency, topic, or VAPID data. A message is sent again on every new session until it is acknowledged, so clients must discard duplicates by `version`.

### Ping reply

`{}`.

## Choices this service makes

The protocol leaves some behavior to the server. This service:

| Behavior | Choice |
|---|---|
| Push endpoint | A random id, unrelated to the `uaid` and `channelID` |
| Delivery receipts | Supported (RFC 8030 §5.1) |
| Broadcasts | Not offered |
| Bodies without `Content-Encoding` | Accepted, as RFC 8030 allows |
| User agent expiry | Optional: `user_agents.expire_after` deletes user agents not seen for that long. A connected session counts as seen |
