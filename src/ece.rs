//! Encrypted Content-Encoding for HTTP ([RFC 8188]) and Message Encryption
//! for Web Push ([RFC 8291]).
//!
//! The top-level functions implement the generic `aes128gcm` content coding.
//! [`webpush`] adds the Web Push key agreement on top. The push service itself
//! only uses [`parse_header`]; the rest is for application servers and user
//! agents.
//!
//! # Example
//!
//! Decrypting the example from [RFC 8188 §3.1]:
//!
//! ```
//! use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
//! use webpush_service::ece;
//!
//! let ikm = B64.decode("yqdlZ-tYemfogSmv7Ws5PQ")?;
//! let body = B64.decode(
//!     "I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-ly8Thjg",
//! )?;
//! assert_eq!(ece::decrypt(&ikm, &body)?, b"I am the walrus");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! [RFC 8188]: https://www.rfc-editor.org/rfc/rfc8188
//! [RFC 8291]: https://www.rfc-editor.org/rfc/rfc8291
//! [RFC 8188 §3.1]: https://www.rfc-editor.org/rfc/rfc8188#section-3.1

use std::fmt;

use aes_gcm::{Aes128Gcm, KeyInit, aead::Aead};
use hkdf::Hkdf;
use sha2::Sha256;

/// Why a body could not be parsed, encrypted, or decrypted.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The body ends inside the header, or before its final record
    /// (RFC 8188 §2.1, §4.2).
    Truncated,
    /// The header's record size is below the minimum of 18 (RFC 8188 §2.1).
    InvalidRecordSize,
    /// A record failed AEAD authentication: wrong key, or tampered data.
    Decrypt,
    /// A record has no delimiter, or the wrong one for its position
    /// (RFC 8188 §2; RFC 8291 §4).
    InvalidPadding,
    /// The key id is not a 65-octet uncompressed P-256 point, or does not fit
    /// the one-octet length field (RFC 8291 §4).
    InvalidKeyId,
    /// A public key is not a point on P-256 (RFC 8291 §7).
    InvalidPublicKey,
    /// The plaintext does not fit a single record of the requested size.
    TooLarge,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Truncated => "aes128gcm body is truncated",
            Error::InvalidRecordSize => "aes128gcm record size is below 18",
            Error::Decrypt => "aes128gcm record failed authentication",
            Error::InvalidPadding => "aes128gcm record has an invalid padding delimiter",
            Error::InvalidKeyId => "key id is not an uncompressed P-256 public key",
            Error::InvalidPublicKey => "public key is not a point on P-256",
            Error::TooLarge => "plaintext does not fit a single record",
        })
    }
}

impl std::error::Error for Error {}

/// The `aes128gcm` header (RFC 8188 §2.1).
///
/// ```text
/// +-----------+--------+-----------+---------------+
/// | salt (16) | rs (4) | idlen (1) | keyid (idlen) |
/// +-----------+--------+-----------+---------------+
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct Header<'a> {
    /// Random salt; with the input keying material it determines the content
    /// encryption key and nonce.
    pub salt: [u8; 16],
    /// Record size in octets, including the 16-octet authentication tag.
    pub rs: u32,
    /// Key identifier. For Web Push, the application server's uncompressed
    /// public key.
    pub keyid: &'a [u8],
}

/// Smallest valid record size: the 16-octet tag, a delimiter, and at least
/// one octet of data (RFC 8188 §2.1).
const MIN_RS: u32 = 18;
/// Length of the AES-GCM authentication tag appended to every record.
const TAG_LEN: usize = 16;

/// Split `body` into its header and the record data that follows it.
///
/// ```
/// use webpush_service::ece;
///
/// let mut body = vec![0u8; 16];                   // salt
/// body.extend_from_slice(&4096u32.to_be_bytes()); // rs
/// body.extend_from_slice(&[2, b'a', b'1']);       // idlen, keyid
/// body.extend_from_slice(b"records...");
///
/// let (header, records) = ece::parse_header(&body)?;
/// assert_eq!(header.rs, 4096);
/// assert_eq!(header.keyid, b"a1");
/// assert_eq!(records, b"records...");
/// # Ok::<(), ece::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::Truncated`] if the header or key id runs past the end of `body`,
/// [`Error::InvalidRecordSize`] if `rs` is below 18.
pub fn parse_header(body: &[u8]) -> Result<(Header<'_>, &[u8]), Error> {
    let (salt, rest) = body.split_first_chunk::<16>().ok_or(Error::Truncated)?;
    let (rs, rest) = rest.split_first_chunk::<4>().ok_or(Error::Truncated)?;
    let (&idlen, rest) = rest.split_first().ok_or(Error::Truncated)?;
    let (keyid, data) = rest
        .split_at_checked(idlen.into())
        .ok_or(Error::Truncated)?;
    let rs = u32::from_be_bytes(*rs);
    if rs < MIN_RS {
        return Err(Error::InvalidRecordSize);
    }
    let header = Header {
        salt: *salt,
        rs,
        keyid,
    };
    Ok((header, data))
}

/// Derive the content encryption key and base nonce from the input keying
/// material and salt (RFC 8188 §2.2, §2.3).
///
/// ```text
/// PRK   = HMAC-SHA-256(salt, IKM)
/// CEK   = HMAC-SHA-256(PRK, "Content-Encoding: aes128gcm" || 0x00 || 0x01)[..16]
/// NONCE = HMAC-SHA-256(PRK, "Content-Encoding: nonce"     || 0x00 || 0x01)[..12]
/// ```
///
/// Each record's nonce is `NONCE` XOR its 96-bit sequence number.
///
/// ```
/// use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
/// use webpush_service::ece;
///
/// // RFC 8188 §3.1
/// let ikm = B64.decode("yqdlZ-tYemfogSmv7Ws5PQ")?;
/// let salt: [u8; 16] = B64.decode("I1BsxtFttlv3u_Oo94xnmw")?.try_into().unwrap();
/// let (cek, nonce) = ece::derive_cek_nonce(&ikm, &salt);
/// assert_eq!(B64.encode(cek), "_wniytB-ofscZDh4tbSjHw");
/// assert_eq!(B64.encode(nonce), "Bcs8gkIRKLI8GeI8");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[must_use]
#[allow(
    clippy::missing_panics_doc,
    reason = "fixed HKDF output lengths of at most 32 octets cannot fail"
)]
pub fn derive_cek_nonce(ikm: &[u8], salt: &[u8; 16]) -> ([u8; 16], [u8; 12]) {
    // With L <= HashLen, HKDF-Expand is a single HMAC(PRK, info || 0x01),
    // which is exactly the derivation the RFC spells out.
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut cek = [0u8; 16];
    let mut nonce = [0u8; 12];
    hk.expand(b"Content-Encoding: aes128gcm\0", &mut cek)
        .expect("16 octets is a valid HKDF-SHA256 length");
    hk.expand(b"Content-Encoding: nonce\0", &mut nonce)
        .expect("12 octets is a valid HKDF-SHA256 length");
    (cek, nonce)
}

/// Per-record nonce: the base nonce XOR the 96-bit big-endian sequence number.
fn record_nonce(nonce: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut n = *nonce;
    for (b, s) in n[4..].iter_mut().zip(seq.to_be_bytes()) {
        *b ^= s;
    }
    n
}

/// Decrypt one record and strip its padding. Returns the data and the
/// delimiter octet, which the caller checks against the record's position.
fn open_record(
    cipher: &Aes128Gcm,
    nonce: &[u8; 12],
    seq: u64,
    record: &[u8],
) -> Result<(Vec<u8>, u8), Error> {
    let mut pt = cipher
        .decrypt(&record_nonce(nonce, seq).into(), record)
        .map_err(|_| Error::Decrypt)?;
    let pos = pt
        .iter()
        .rposition(|&b| b != 0)
        .ok_or(Error::InvalidPadding)?;
    let delimiter = pt[pos];
    pt.truncate(pos);
    Ok((pt, delimiter))
}

/// Decrypt a complete `aes128gcm` body with any number of records.
///
/// Every record but the last must be exactly `rs` octets and end in the
/// delimiter 0x01; the last record ends in 0x02. A body that stops after a
/// 0x01 record was cut short and is rejected rather than returned as a
/// shorter message (RFC 8188 §4.2). See the [module example](self).
///
/// # Errors
///
/// Header errors as for [`parse_header`]; [`Error::Decrypt`] if a record
/// fails authentication; [`Error::InvalidPadding`] for a missing or misplaced
/// delimiter; [`Error::Truncated`] if the body ends before its last record.
pub fn decrypt(ikm: &[u8], body: &[u8]) -> Result<Vec<u8>, Error> {
    let (header, mut data) = parse_header(body)?;
    let (cek, nonce) = derive_cek_nonce(ikm, &header.salt);
    let cipher = Aes128Gcm::new(&cek.into());
    let rs = header.rs as usize;
    let mut out = Vec::new();
    let mut seq = 0;
    loop {
        // Running out of data before a record with delimiter 2 means the
        // message was cut off between two records (RFC 8188 §4.2).
        if data.is_empty() {
            return Err(Error::Truncated);
        }
        let (record, rest) = data.split_at(data.len().min(rs));
        let (pt, delimiter) = open_record(&cipher, &nonce, seq, record)?;
        out.extend_from_slice(&pt);
        match (delimiter, rest.is_empty()) {
            (2, true) => return Ok(out),
            (1, false) => data = rest,
            _ => return Err(Error::InvalidPadding),
        }
        seq += 1;
    }
}

/// Encrypt `plaintext` as a single record with delimiter 0x02 and no padding.
///
/// Callers must use a fresh random `salt` for every message; reusing a salt
/// with the same keying material reuses the AES-GCM key and nonce.
///
/// ```
/// use webpush_service::ece;
///
/// let ikm = [7u8; 16];
/// let salt = [1u8; 16];
/// let body = ece::encrypt(&ikm, &salt, 4096, b"", b"hello")?;
/// assert_eq!(ece::decrypt(&ikm, &body)?, b"hello");
/// # Ok::<(), ece::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::TooLarge`] if `plaintext.len() + 17 > rs`,
/// [`Error::InvalidRecordSize`] if `rs` is below 18, [`Error::InvalidKeyId`]
/// if `keyid` is longer than 255 octets.
pub fn encrypt(
    ikm: &[u8],
    salt: &[u8; 16],
    rs: u32,
    keyid: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    if rs < MIN_RS {
        return Err(Error::InvalidRecordSize);
    }
    let idlen = u8::try_from(keyid.len()).map_err(|_| Error::InvalidKeyId)?;
    if plaintext.len() + 1 + TAG_LEN > rs as usize {
        return Err(Error::TooLarge);
    }
    let (cek, nonce) = derive_cek_nonce(ikm, salt);
    let mut record = plaintext.to_vec();
    record.push(2);
    let sealed = Aes128Gcm::new(&cek.into())
        .encrypt(&nonce.into(), &record[..])
        .map_err(|_| Error::TooLarge)?;

    let mut body = Vec::with_capacity(21 + keyid.len() + sealed.len());
    body.extend_from_slice(salt);
    body.extend_from_slice(&rs.to_be_bytes());
    body.push(idlen);
    body.extend_from_slice(keyid);
    body.extend_from_slice(&sealed);
    Ok(body)
}

/// Message Encryption for Web Push ([RFC 8291]).
///
/// The user agent publishes a P-256 public key and a 16-octet authentication
/// secret with its subscription. For each message the application server
/// generates an ephemeral P-256 key pair, performs ECDH with the user agent's
/// key, and derives the `aes128gcm` input keying material from the shared
/// secret, the authentication secret, and both public keys. The ephemeral
/// public key is sent in the `keyid` header field, so the body is
/// self-contained.
///
/// A message is always a single record. Its plaintext is limited to
/// 3993 octets so the body fits the 4096 octets a push service must accept
/// (RFC 8030 §7.2).
///
/// # Example
///
/// ```
/// use p256::{SecretKey, elliptic_curve::{rand_core::OsRng, sec1::ToEncodedPoint}};
/// use webpush_service::ece::webpush;
///
/// // User agent: subscription keys.
/// let ua = SecretKey::random(&mut OsRng);
/// let ua_public: [u8; 65] = ua.public_key().to_encoded_point(false).as_bytes().try_into()?;
/// let auth_secret = [0x42; 16];
///
/// // Application server: a fresh key pair and salt per message.
/// let as_private: [u8; 32] = SecretKey::random(&mut OsRng).to_bytes().into();
/// let salt = [0x17; 16];
/// let body = webpush::encrypt(&ua_public, &auth_secret, &as_private, &salt, b"hi")?;
///
/// // User agent: decrypt what the push service delivered.
/// let ua_private: [u8; 32] = ua.to_bytes().into();
/// assert_eq!(webpush::decrypt(&ua_private, &auth_secret, &body)?, b"hi");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// [RFC 8291]: https://www.rfc-editor.org/rfc/rfc8291
pub mod webpush {
    use aes_gcm::{Aes128Gcm, KeyInit};
    use hkdf::Hkdf;
    use p256::{PublicKey, SecretKey, ecdh::diffie_hellman, elliptic_curve::sec1::ToEncodedPoint};
    use sha2::Sha256;

    use super::{Error, derive_cek_nonce, open_record, parse_header};

    /// Record size used for every message this module produces (RFC 8291 §4).
    const RS: u32 = 4096;

    /// Derive the `aes128gcm` input keying material (RFC 8291 §3.3):
    ///
    /// ```text
    /// IKM = HKDF-SHA-256(salt = auth_secret, ikm = ecdh_secret,
    ///                    info = "WebPush: info" || 0x00 || ua_public || as_public,
    ///                    L = 32)
    /// ```
    ///
    /// ```
    /// use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
    /// use webpush_service::ece::webpush;
    ///
    /// // RFC 8291 Appendix A
    /// let ecdh = B64.decode("kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs")?;
    /// let auth: [u8; 16] = B64.decode("BTBZMqHH6r4Tts7J_aSIgg")?.try_into().unwrap();
    /// let ua: [u8; 65] = B64.decode(
    ///     "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
    /// )?.try_into().unwrap();
    /// let r#as: [u8; 65] = B64.decode(
    ///     "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8",
    /// )?.try_into().unwrap();
    /// let ikm = webpush::ikm(&ecdh, &auth, &ua, &r#as);
    /// assert_eq!(B64.encode(ikm), "S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg");
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    #[allow(
        clippy::missing_panics_doc,
        reason = "fixed HKDF output lengths of at most 32 octets cannot fail"
    )]
    pub fn ikm(
        ecdh_secret: &[u8],
        auth_secret: &[u8; 16],
        ua_public: &[u8; 65],
        as_public: &[u8; 65],
    ) -> [u8; 32] {
        let mut info = Vec::with_capacity(14 + 130);
        info.extend_from_slice(b"WebPush: info\0");
        info.extend_from_slice(ua_public);
        info.extend_from_slice(as_public);
        let mut out = [0u8; 32];
        Hkdf::<Sha256>::new(Some(auth_secret), ecdh_secret)
            .expand(&info, &mut out)
            .expect("32 octets is a valid HKDF-SHA256 length");
        out
    }

    /// SEC1 uncompressed encoding: 0x04 followed by the x and y coordinates.
    fn uncompressed(key: &PublicKey) -> [u8; 65] {
        key.to_encoded_point(false)
            .as_bytes()
            .try_into()
            .expect("uncompressed P-256 points are 65 octets")
    }

    /// The raw x coordinate of the ECDH shared point (RFC 8291 §3.1).
    fn ecdh(private: &SecretKey, public: &PublicKey) -> [u8; 32] {
        let shared = diffie_hellman(private.to_nonzero_scalar(), public.as_affine());
        (*shared.raw_secret_bytes()).into()
    }

    /// Encrypt `plaintext` for a subscription, as an application server.
    ///
    /// `as_private` and `salt` must be fresh for every message. The result
    /// uses `rs = 4096` and puts the application server's public key in
    /// `keyid` (RFC 8291 §4). See the [module example](self).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPublicKey`] if `ua_public` is not a P-256 point,
    /// [`Error::InvalidKeyId`] if `as_private` is not a valid scalar,
    /// [`Error::TooLarge`] if the plaintext exceeds 3993 octets.
    pub fn encrypt(
        ua_public: &[u8; 65],
        auth_secret: &[u8; 16],
        as_private: &[u8; 32],
        salt: &[u8; 16],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let ua = PublicKey::from_sec1_bytes(ua_public).map_err(|_| Error::InvalidPublicKey)?;
        // The keyid is derived from this key, so an unusable scalar is
        // reported as a bad keyid.
        let sk = SecretKey::from_bytes(as_private.into()).map_err(|_| Error::InvalidKeyId)?;
        let as_public = uncompressed(&sk.public_key());
        let ikm = ikm(&ecdh(&sk, &ua), auth_secret, ua_public, &as_public);
        super::encrypt(&ikm, salt, RS, &as_public, plaintext)
    }

    /// Decrypt a pushed message body, as a user agent.
    ///
    /// The application server's public key is read from `keyid` and
    /// validated as a P-256 point before use (RFC 8291 §7). A message whose
    /// delimiter is not 0x02 is discarded (RFC 8291 §4). See the
    /// [module example](self).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKeyId`] unless `keyid` is a 65-octet uncompressed
    /// point, [`Error::InvalidPublicKey`] if it is off the curve,
    /// [`Error::Decrypt`] for a wrong key or authentication secret,
    /// [`Error::InvalidPadding`] for a delimiter other than 0x02, and the
    /// header errors of [`parse_header`].
    pub fn decrypt(
        ua_private: &[u8; 32],
        auth_secret: &[u8; 16],
        body: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let (header, record) = parse_header(body)?;
        let as_public: &[u8; 65] = match <&[u8; 65]>::try_from(header.keyid) {
            Ok(k @ [0x04, ..]) => k,
            _ => return Err(Error::InvalidKeyId),
        };
        let peer = PublicKey::from_sec1_bytes(as_public).map_err(|_| Error::InvalidPublicKey)?;
        let sk = SecretKey::from_bytes(ua_private.into()).map_err(|_| Error::Decrypt)?;
        let ikm = ikm(
            &ecdh(&sk, &peer),
            auth_secret,
            &uncompressed(&sk.public_key()),
            as_public,
        );

        // Web Push messages are exactly one record, so rs is not needed to
        // split the body (RFC 8291 §4).
        let (cek, nonce) = derive_cek_nonce(&ikm, &header.salt);
        let (pt, delimiter) = open_record(&Aes128Gcm::new(&cek.into()), &nonce, 0, record)?;
        if delimiter != 2 {
            return Err(Error::InvalidPadding);
        }
        Ok(pt)
    }
}
