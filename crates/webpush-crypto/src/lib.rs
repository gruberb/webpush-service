//! Cryptography for Web Push, usable by application servers, user agents,
//! and push services alike.
//!
//! | Specification | Title | Module |
//! |---|---|---|
//! | [RFC 8188] | Encrypted Content-Encoding for HTTP | [`ece`] |
//! | [RFC 8291] | Message Encryption for Web Push | [`ece::webpush`] |
//! | [RFC 8292] | Voluntary Application Server Identification (VAPID) | [`vapid`] |
//!
//! The crate has no I/O and no async runtime dependency.
//!
//! [RFC 8188]: https://www.rfc-editor.org/rfc/rfc8188
//! [RFC 8291]: https://www.rfc-editor.org/rfc/rfc8291
//! [RFC 8292]: https://www.rfc-editor.org/rfc/rfc8292

pub mod ece;
pub mod vapid;
