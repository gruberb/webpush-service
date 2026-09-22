# Documentation

These pages explain how Web Push works and how to run and use this push service. Start with the concepts, then read the guide for the side you are building.

## Reading order

| If you want to | Read |
|---|---|
| Understand the protocol and its vocabulary | [Web Push concepts](concepts.md) |
| Run the service locally | [Running the service](running.md) |
| Look up a configuration setting | [Configuration reference](configuration.md) |
| Run it in production, on several nodes | [Deployment](deployment.md) |
| Connect Firefox, or build a client that receives messages | [Connecting a client](connecting-a-client.md) |
| Deliver to a mobile app through FCM or APNs | [Mobile bridges](mobile-bridges.md) |
| Build an application server that sends messages | [Connecting a publisher](connecting-a-publisher.md) |
| Follow one message end to end | [Sending a message](sending-a-message.md) |
| Know what the push service can and cannot learn | [Privacy and security](privacy-and-security.md) |
| Store state in your own database | [Storage adapters](storage-adapters.md) |
| Change or review the implementation | [Architecture](architecture.md) |
| Look up a user agent message | [WebSocket protocol reference](websocket-protocol.md) |
| Look up an endpoint, header, or status code | [HTTP reference](http-reference.md) |
| Check a requirement ID cited by a test (`WP-`, `FX-`, `VAP-`, …) | [Design spec](../TECH_SPEC.md) |

## Terminology

The RFCs and these docs use the following names:

| Term | Also called | Meaning |
|---|---|---|
| User agent | client, UA | The software on the device that subscribes and receives messages, usually a browser or a mobile app |
| Application server | publisher, AS | The backend that sends messages to user agents |
| Push service | | The relay between them: this project |
| Session | | A user agent's WebSocket connection to the push service |
| `uaid` | user agent id | The user agent's identity at the push service |
| `channelID` | | The user agent's name for one subscription |
| Push endpoint | push resource | The URL an application server POSTs messages to |
| VAPID | | Voluntary Application Server Identification: a signed token that identifies the application server |
| Bridge | | A platform push service the push service hands messages to: Firebase Cloud Messaging (FCM) or the Apple Push Notification service (APNs) |
| Bridged user agent | | A user agent reached through a bridge instead of a session, typically a mobile app. It registers over HTTPS with a device token |
| Role | | The part of the service one process runs: `all`, `endpoint`, or `connect` |
| Node | | One running process in a cluster, reachable by other nodes on its internal listener |
| Route | | A store record naming the node that holds a session or receipt stream, so other nodes can forward events to it |

## Specifications

- [RFC 8030](https://www.rfc-editor.org/rfc/rfc8030): Generic Event Delivery Using HTTP Push
- [RFC 8291](https://www.rfc-editor.org/rfc/rfc8291): Message Encryption for Web Push
- [RFC 8188](https://www.rfc-editor.org/rfc/rfc8188): Encrypted Content-Encoding for HTTP
- [RFC 8292](https://www.rfc-editor.org/rfc/rfc8292): Voluntary Application Server Identification (VAPID) for Web Push
- [Firefox push client](https://firefox-source-docs.mozilla.org/dom/push/): the WebSocket protocol this service speaks to user agents
- [FCM HTTP v1 API](https://firebase.google.com/docs/reference/fcm/rest/v1/projects.messages) and [APNs provider API](https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns): the platform services behind the bridges

API documentation for every crate in the workspace is available with `cargo doc --workspace --open`.
