//! RFC 8291 end to end: the test acts as application server and user agent,
//! using the library module on both ends, with the push service in between.

mod common;

use common::*;
use p256::{
    SecretKey,
    elliptic_curve::{rand_core::OsRng, sec1::ToEncodedPoint},
};
use webpush_service::ece::webpush;

/// A user agent's subscription keys (RFC 8291 §2).
struct UserAgent {
    /// P-256 private key.
    private: [u8; 32],
    /// P-256 public key, uncompressed.
    public: [u8; 65],
    /// Authentication secret (RFC 8291 §3.2).
    auth: [u8; 16],
}

impl UserAgent {
    /// Fresh random keys.
    fn new() -> Self {
        let sk = SecretKey::random(&mut OsRng);
        UserAgent {
            private: sk.to_bytes().into(),
            public: sk
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .try_into()
                .unwrap(),
            auth: random(),
        }
    }
}

/// Encrypt `plaintext` to a fresh user agent, push it through the service,
/// and decrypt what arrives over the user agent's session.
async fn roundtrip(plaintext: &[u8]) -> Vec<u8> {
    let server = TestServer::start().await;
    let http = server.http().await;
    let mut session = server.ua().await;
    session.hello(None).await;
    let sub = session.subscribe(None).await;

    let ua = UserAgent::new();
    let as_private: [u8; 32] = SecretKey::random(&mut OsRng).to_bytes().into();
    let body = webpush::encrypt(&ua.public, &ua.auth, &as_private, &random(), plaintext).unwrap();
    // 86-octet header, delimiter, 16-octet tag.
    assert_eq!(body.len(), 86 + plaintext.len() + 17);

    let headers = [("ttl", "60"), ("content-encoding", "aes128gcm")];
    let r = http.request("POST", &sub.push, &headers, &body).await;
    assert_eq!(r.status, 201, "{r:?}");

    let n = session.next_notification().await;
    assert_eq!(n.encoding(), Some("aes128gcm"));
    assert_eq!(n.data(), body);
    webpush::decrypt(&ua.private, &ua.auth, &n.data()).unwrap()
}

/// ENC-01..05 (MUST): an encrypted message survives the push service intact.
#[tokio::test(flavor = "multi_thread")]
async fn e2e_encrypted_roundtrip() {
    let pt = b"When I grow up, I want to be a watermelon";
    assert_eq!(roundtrip(pt).await, pt);
}

/// ENC-08, WP-32 (DERIVED, MUST NOT): 3993 octets of plaintext make a
/// 4096-octet body, which is accepted and delivered intact.
#[tokio::test(flavor = "multi_thread")]
async fn e2e_max_plaintext() {
    let pt = vec![0x5a; 3993];
    assert_eq!(roundtrip(&pt).await, pt);
}
