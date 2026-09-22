# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 - 2026-09-22

### Added

- Push service implementing the application server side of RFC 8030: push,
  TTL, urgency, topic replacement, message resources (read and withdraw), and
  delivery receipts (204 on acknowledgement, 410 on expiry, unsubscribe, or a
  decryption failure reported by the user agent).
- User agent sessions over WebSocket, compatible with Firefox's push client:
  `hello`, `register` (including restricted subscriptions), `unregister`,
  `notification`, `ack`, and pings. Firefox uses the service after setting
  `dom.push.serverURL`.
- Receipt streams as Server-Sent Events on the RFC 8030 receipt subscription.
- RFC 8292 VAPID enforcement: restricted subscriptions, 401 without
  credentials, 403 for invalid credentials, and rejection of a VAPID key
  reused as the encryption key id.
- `ece` library module: RFC 8188 `aes128gcm` encryption and decryption, and
  RFC 8291 Web Push message encryption for application servers and user
  agents.
- `vapid` library module: RFC 8292 `Authorization` parsing and ES256 token
  verification.
- Storage behind the public `store::Store` trait, with an executable contract
  (`store::contract::check`), an in-memory adapter (default), and a Cloud
  Bigtable adapter behind the `bigtable` feature.
- TLS-only transport serving HTTP/1.1, HTTP/2, and WebSocket upgrades through
  one router.
- Conformance suites for the application server interface, the user agent
  protocol, VAPID, and end-to-end encryption; RFC test-vector suites for
  RFC 8188, RFC 8291, and RFC 8292; and the storage contract run against every
  adapter. Every conformance test can also run on the Bigtable emulator.
- Documentation in `docs/`: concepts, running the service, connecting a
  client, connecting a publisher, sending a message, privacy and security,
  storage adapters, architecture, and the WebSocket and HTTP references.

### Deviations from RFC 8030

- The user agent side (§4 subscribe, §6 delivery with HTTP/2 server push,
  §6.1 subscription sets, §6.2 acknowledgement by `DELETE`) is replaced by the
  Firefox WebSocket protocol, because browsers removed HTTP/2 server push and
  never used RFC 8030 for delivery.
- Receipts (§6.3) are delivered as Server-Sent Events instead of server
  pushes.

### Known limitations

- Single node: open sessions are tracked in process memory.
- The Bigtable adapter supports the emulator only (no TLS or Google
  authentication on the gRPC channel yet).
- No rate limiting, and no automatic subscription or user agent expiry.
