//! Independent oracles for the Web Push RFCs: base64url helpers, an ES256
//! VAPID signer, and `aes128gcm` record builders. None of it uses the code
//! under test, so a bug in the implementation cannot validate itself. Shared
//! by the crypto and server test suites.
#![allow(dead_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::{Aes128Gcm, KeyInit, aead::Aead};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::rand_core::{OsRng, RngCore},
};

/// Base64url without padding, the encoding every Web Push RFC uses.
pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode base64url without padding. Panics on invalid input.
pub fn unb64(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s).expect("base64url")
}

/// Current time in seconds since the Unix epoch.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// `N` random octets from the OS CSPRNG.
pub fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

// ---------------------------------------------------------------------------
// VAPID oracle: an ES256 JWT signer independent of `webpush_crypto::vapid`

/// An application server's VAPID signing key (RFC 8292 §2).
pub struct AppServerKey {
    /// The private key.
    key: SigningKey,
}

impl AppServerKey {
    /// A fresh random P-256 key.
    pub fn new() -> Self {
        AppServerKey {
            key: SigningKey::random(&mut OsRng),
        }
    }

    /// Uncompressed public key, 65 octets.
    pub fn public(&self) -> [u8; 65] {
        let point = self.key.verifying_key().to_encoded_point(false);
        point.as_bytes().try_into().unwrap()
    }

    /// The public key as the `k` parameter expects it (RFC 8292 §3.2).
    pub fn k_b64(&self) -> String {
        b64(&self.public())
    }

    /// ES256 signature over `data`.
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.key.sign(data)
    }

    /// `b64(header).b64(claims).b64(raw r||s signature)`.
    pub fn token_raw(&self, header_json: &str, claims_json: &str) -> String {
        let input = format!(
            "{}.{}",
            b64(header_json.as_bytes()),
            b64(claims_json.as_bytes())
        );
        let sig = self.sign(input.as_bytes());
        format!("{input}.{}", b64(&sig.to_bytes()))
    }

    /// A signed VAPID JWT with the given claims and an ES256 header.
    pub fn token(&self, aud: &str, exp: u64, sub: Option<&str>) -> String {
        let mut claims = serde_json::json!({ "aud": aud, "exp": exp });
        if let Some(sub) = sub {
            claims["sub"] = sub.into();
        }
        self.token_raw(r#"{"typ":"JWT","alg":"ES256"}"#, &claims.to_string())
    }

    /// A complete `Authorization` header value.
    pub fn auth(&self, aud: &str, exp: u64, sub: Option<&str>) -> String {
        format!("vapid t={}, k={}", self.token(aud, exp, sub), self.k_b64())
    }
}

/// Flip the y coordinate of an uncompressed point by one, which takes it off
/// the curve.
pub fn off_curve(point: &[u8; 65]) -> [u8; 65] {
    let mut p = *point;
    for b in p[33..].iter_mut().rev() {
        let (v, carry) = b.overflowing_add(1);
        *b = v;
        if !carry {
            break;
        }
    }
    p
}

// ---------------------------------------------------------------------------
// aes128gcm oracle: record builders independent of `webpush_crypto::ece`

/// `salt || rs || idlen || keyid`.
pub fn ece_header(salt: &[u8; 16], rs: u32, keyid: &[u8]) -> Vec<u8> {
    let mut h = salt.to_vec();
    h.extend_from_slice(&rs.to_be_bytes());
    h.push(u8::try_from(keyid.len()).expect("keyid fits the one-octet idlen"));
    h.extend_from_slice(keyid);
    h
}

/// Seal one record whose plaintext (data, delimiter, padding) is `plaintext`,
/// using a given CEK and base nonce at sequence number `seq`.
pub fn ece_record(cek: &[u8; 16], nonce: &[u8; 12], seq: u64, plaintext: &[u8]) -> Vec<u8> {
    let mut n = *nonce;
    for (b, s) in n[4..].iter_mut().zip(seq.to_be_bytes()) {
        *b ^= s;
    }
    Aes128Gcm::new(cek.into())
        .encrypt(&n.into(), plaintext)
        .unwrap()
}

/// A syntactically valid `aes128gcm` body with random salt and ciphertext.
/// The push service only inspects the header, so this needs no real keys.
pub fn opaque_aes128gcm(keyid: &[u8]) -> Vec<u8> {
    let mut body = ece_header(&random(), 4096, keyid);
    body.extend_from_slice(&random::<48>());
    body
}
