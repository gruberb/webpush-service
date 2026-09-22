# Mobile bridges

Android and iOS do not let an app keep its own network connection open in the background. Messages for mobile apps go through the platform's push service instead: Firebase Cloud Messaging (FCM) on Android, the Apple Push Notification service (APNs) on Apple platforms. This push service hands those messages over through a bridge. Application servers see no difference: they push to the same kind of endpoint, with the same encryption and VAPID rules.

```text
 mobile app                       push service                    platform
 ----------                       ------------                    --------
 get device token from FCM/APNs
 POST /v1/user-agents  ---------> store user agent + token
 PUT .../subscriptions/{ch} ----> pushEndpoint
 hand pushEndpoint + keys to the application server

                  application server: POST pushEndpoint
                                  bridge.send ------------------> FCM / APNs
 app receives {channelID, version, data, encoding} <------------------+
 decrypt data with the subscription's keys
```

## Registering an app

The [registration API](http-reference.md#registration-api) exists when at least one bridge is configured. An app uses it in five steps.

### 1. Register the device

Get a device token from the platform SDK, then register it with the bridge name and your app id as configured on the server:

```bash
curl -s https://push.example.net/v1/user-agents \
  -H 'content-type: application/json' \
  -d '{"bridge": "fcm", "appID": "example-android", "token": "dGVzdA:APA91b..."}'
```

```json
{"uaid": "5f1a9c0e2b7d4e8f9a6b3c2d1e0f7a8b", "secret": "Qm9w..."}
```

Store both in the app's private storage. Every later call sends `Authorization: Bearer {secret}`.

### 2. Create subscriptions

Choose a UUID for each subscription, generate its P-256 key pair and authentication secret as a browser would, and create it. The request is idempotent, so it is safe to retry:

```bash
curl -s -X PUT https://push.example.net/v1/user-agents/$UAID/subscriptions/$CHANNEL \
  -H "authorization: Bearer $SECRET" \
  -H 'content-type: application/json' \
  -d '{"key": "BA1Hxzyi..."}'
```

```json
{"channelID": "d9b74644-4f97-46aa-b8fa-9393985cd6cd", "pushEndpoint": "https://push.example.net/push/FLhiBWT0-e7Hd6w8KEn1Qw"}
```

`key` is optional; it restricts the subscription to one application server's VAPID key. Hand `pushEndpoint` and the subscription's public key and authentication secret to the application server, as a browser does with `PushSubscription`.

### 3. Check in regularly

Call `GET /v1/user-agents/{uaid}` periodically, for example once a day when the app starts:

- It marks the user agent as seen. With `user_agents.expire_after` set, user agents that stop checking in are deleted with their subscriptions.
- It returns the subscriptions the service holds, so the app can detect and repair differences with its own list.

A `404` means the user agent is gone, for example because it expired or the platform reported its token invalid. Register again from step 1 and give the application servers the new endpoints.

### 4. Refresh the token

Platforms rotate device tokens. When the SDK reports a new one, send it:

```bash
curl -s -X PUT https://push.example.net/v1/user-agents/$UAID \
  -H "authorization: Bearer $SECRET" \
  -H 'content-type: application/json' \
  -d '{"token": "new-device-token"}'
```

### 5. Clean up

`DELETE /v1/user-agents/{uaid}/subscriptions/{channelID}` removes one subscription; `DELETE /v1/user-agents/{uaid}` removes the user agent and all its subscriptions. Their push endpoints return `404` from then on.

## Receiving messages

Every bridge delivers the same fields, with the same names as the WebSocket `notification` message, so an app can share its decoding with a WebSocket client:

| Field | Present | Meaning |
|---|---|---|
| `channelID` | Always | The subscription |
| `version` | Always | The message id |
| `data` | Messages with a body | The encrypted body, base64url without padding |
| `encoding` | Messages with a body and a `Content-Encoding` | The content coding, `aes128gcm` for Web Push |

On Android the fields arrive as the FCM data message's key-value pairs. On iOS they arrive at the top level of the notification payload, next to `aps`. Look up the subscription's keys by `channelID` and decrypt `data` with RFC 8291, for example with `webpush_crypto::ece::webpush::decrypt`.

## Configuring the bridges

Configure each platform under `[bridges]`, keyed by the app id apps register with, and set the registration secret keys. Both bridges use token-based authentication; neither needs client certificates.

### FCM

FCM's HTTP v1 API takes OAuth 2.0 access tokens, cached until shortly before they expire. With a service account key, the bridge signs a JWT with its RSA key and exchanges it at Google's token endpoint:

```toml
[bridges.fcm.apps.example-android]
credentials_file = "/etc/webpush/fcm-example.json"
```

On Cloud Run or GKE, leave the key out and name the project; the bridge then uses the workload's service account through the metadata server, which needs the Firebase Cloud Messaging API enabled and `roles/firebasecloudmessaging.admin`:

```toml
[bridges.fcm.apps.example-android]
project_id = "your-firebase-project"
```

Messages go out as data messages, so the app decides what to show. The TTL is capped at FCM's maximum of 28 days, and urgency `high` maps to high priority.

### APNs

APNs authenticates providers with an ES256 JWT, the provider token, signed with a `.p8` key from the Apple developer account. The bridge signs one per app and reuses it for 40 minutes, within Apple's limits:

```toml
[bridges.apns.apps.example-ios]
key_file = "/etc/webpush/apns-example.p8"
key_id = "ABC123DEFG"
team_id = "DEF123GHIJ"
topic = "com.example.app"
environment = "production"
```

Choose the push type with `push_type`:

| `push_type` | Delivery | Configure |
|---|---|---|
| `background` (default) | Wakes the app silently. iOS may delay or drop these | Nothing more; `aps` defaults to `{"content-available": 1}` |
| `alert` | Reliable, but iOS shows a notification | `aps` with a placeholder alert and `"mutable-content": 1`, so a notification service extension can decrypt the message and replace the text before it is shown |

```toml
[bridges.apns.apps.example-ios]
# ...
push_type = "alert"
aps = { alert = { title = "New message" }, "mutable-content" = 1 }
```

### Secrets

```bash
WEBPUSH_REGISTRATION__SECRET_KEYS='["a-random-key-of-at-least-32-characters"]'
```

To rotate a key, put the new key first; secrets issued under the old key keep working until you remove it.

The `webpush-fcm` and `webpush-apns` crate documentation (`cargo doc -p webpush-fcm -p webpush-apns --open`) details authentication, payloads, and the platform error mapping.

## What is not supported

| Feature | Why |
|---|---|
| Delivery receipts | The platform reports acceptance, not delivery to the device, so the service has no acknowledgement to report. Pushes that ask for a receipt get `201` without one |
| Topic replacement | Topics are not forwarded to the platform, so they are not disclosed to it. Each message is delivered separately |
| Reading or withdrawing a message | Bridged messages are not stored; the platform holds them |
| Bodies near 4096 octets | Both platforms limit the payload to 4096 bytes after base64url encoding and field names, so bridged bodies are limited to roughly 3000 octets. Larger pushes get `413` |

When the platform reports a device token as invalid, the push that found out gets `410`, and the user agent is deleted with all its subscriptions. The app registers again on its next check-in.

## Next steps

- [HTTP reference](http-reference.md#registration-api) lists every registration endpoint and status.
- [Privacy and security](privacy-and-security.md#bridged-user-agents) covers what the platform can see.
- [Configuration reference](configuration.md) lists every bridge setting.
