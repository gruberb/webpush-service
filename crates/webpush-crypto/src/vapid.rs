//! Voluntary Application Server Identification for Web Push ([RFC 8292]).
//!
//! An application server identifies itself to a push service with a JWT
//! signed by a long-lived P-256 key, sent together with the public key:
//!
//! ```text
//! Authorization: vapid t=<JWS compact serialization>, k=<base64url public key>
//! ```
//!
//! [`parse_authorization`] extracts the credentials, [`verify`] checks the
//! token against the key, the push resource origin, and the clock.
//!
//! # Example
//!
//! Verifying the token from [RFC 8292 §2.4] an hour before it expires:
//!
//! ```
//! use webpush_crypto::vapid;
//!
//! let header = "vapid \
//!     t=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3B1c2guZXhhbXBsZS5uZXQiLCJl\
//!     eHAiOjE0NTM1MjM3NjgsInN1YiI6Im1haWx0bzpwdXNoQGV4YW1wbGUuY29tIn0.i3CYb7t4xfxCDquptFOepC9GAu_H\
//!     LGkMlMuCGSK2rpiUfnK9ojFwDXb1JrErtmysazNjjvW2L9OkSSHzvoD1oA, \
//!     k=BA1Hxzyi1RUM1b5wjxsn7nGxAszw2u61m164i3MrAIxHF6YK5h4SDYic-dRuU_RCPCfA5aq9ojSwk5Y2EmClBPs";
//!
//! let creds = vapid::parse_authorization(header)?;
//! let claims = vapid::verify(&creds, "https://push.example.net", 1_453_523_768 - 3600)?;
//! assert_eq!(claims.sub.as_deref(), Some("mailto:push@example.com"));
//! # Ok::<(), vapid::Error>(())
//! ```
//!
//! [RFC 8292]: https://www.rfc-editor.org/rfc/rfc8292
//! [RFC 8292 §2.4]: https://www.rfc-editor.org/rfc/rfc8292#section-2.4

use std::fmt;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde_json::Value;

/// Why VAPID credentials were rejected.
///
/// A push service answers every variant except [`Error::NotVapid`] with
/// 403 (RFC 8292 §4.2). `NotVapid` means the request had no VAPID
/// credentials at all, which a restricted subscription answers with 401.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The `Authorization` scheme is not `vapid`.
    NotVapid,
    /// The `t` or `k` parameter is absent (RFC 8292 §3).
    MissingParam,
    /// `k` is not a base64url-encoded uncompressed P-256 point (RFC 8292 §3.2).
    InvalidKey,
    /// The parameter list, JWS structure, or claims set does not parse, or
    /// `exp` is missing.
    Malformed,
    /// The JWS `alg` is not `ES256` (RFC 8292 §2).
    UnsupportedAlgorithm,
    /// The signature is not a valid 64-octet ES256 signature by `k`.
    BadSignature,
    /// The current time is past `exp`.
    Expired,
    /// `exp` is more than 24 hours in the future (RFC 8292 §2).
    ExpiryTooFar,
    /// `aud` does not contain the push resource origin (RFC 8292 §2).
    AudienceMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::NotVapid => "authorization scheme is not vapid",
            Error::MissingParam => "vapid credentials lack the t or k parameter",
            Error::InvalidKey => "vapid key is not an uncompressed P-256 point",
            Error::Malformed => "vapid token is malformed",
            Error::UnsupportedAlgorithm => "vapid token is not signed with ES256",
            Error::BadSignature => "vapid token signature does not verify",
            Error::Expired => "vapid token has expired",
            Error::ExpiryTooFar => "vapid token expires more than 24 hours ahead",
            Error::AudienceMismatch => "vapid token audience does not match the push service",
        })
    }
}

impl std::error::Error for Error {}

/// The parameters of an `Authorization: vapid` header (RFC 8292 §3).
///
/// Nothing in here is trustworthy until [`verify`] succeeds.
#[derive(Debug)]
pub struct Credentials {
    /// The JWT, in JWS compact serialization.
    pub t: String,
    /// The application server's public key: an uncompressed P-256 point.
    pub k: [u8; 65],
}

/// Longest accepted distance between now and `exp` (RFC 8292 §2).
const MAX_EXP_AHEAD: u64 = 24 * 3600;

/// Parse an `Authorization` header value (RFC 8292 §3).
///
/// The scheme is case-insensitive. Parameters follow the `auth-param` grammar
/// of RFC 7235 §2.1: any order, token or quoted-string values, optional
/// whitespace around `=` and `,`. Unknown parameters, including `realm`, are
/// ignored. The key is checked for length and encoding only; [`verify`]
/// checks that it is a curve point.
///
/// ```
/// use webpush_crypto::vapid::{self, Error};
///
/// let creds = vapid::parse_authorization(
///     "Vapid realm=\"push\", k=\"BA1Hxzyi1RUM1b5wjxsn7nGxAszw2u61m164i3MrAIxHF6YK5h4SDYic-dRuU_RCPCfA5aq9ojSwk5Y2EmClBPs\", t=a.b.c",
/// )?;
/// assert_eq!(creds.t, "a.b.c");
/// assert_eq!(creds.k[0], 0x04);
///
/// assert_eq!(vapid::parse_authorization("Bearer abc").unwrap_err(), Error::NotVapid);
/// # Ok::<(), Error>(())
/// ```
///
/// # Errors
///
/// [`Error::NotVapid`] for another scheme, [`Error::MissingParam`] without
/// both `t` and `k`, [`Error::InvalidKey`] if `k` is not 65 octets of
/// base64url, [`Error::Malformed`] if the parameter list does not parse.
pub fn parse_authorization(value: &str) -> Result<Credentials, Error> {
    let value = value.trim();
    let (scheme, mut rest) = value
        .split_once(|c: char| c.is_ascii_whitespace())
        .unwrap_or((value, ""));
    if !scheme.eq_ignore_ascii_case("vapid") {
        return Err(Error::NotVapid);
    }

    // auth-param = token BWS "=" BWS ( token / quoted-string ), comma
    // separated (RFC 7235 §2.1). Unknown params, including `realm`, are
    // skipped.
    let (mut t, mut k) = (None, None);
    loop {
        rest = rest.trim_start_matches(|c: char| c == ',' || c.is_ascii_whitespace());
        if rest.is_empty() {
            break;
        }
        let end = rest
            .find(|c: char| c == '=' || c == ',' || c.is_ascii_whitespace())
            .unwrap_or(rest.len());
        let name = &rest[..end];
        let after_eq = rest[end..]
            .trim_start()
            .strip_prefix('=')
            .ok_or(Error::Malformed)?;
        let (param, tail) = param_value(after_eq.trim_start())?;
        rest = tail;
        if name.eq_ignore_ascii_case("t") {
            t = Some(param);
        } else if name.eq_ignore_ascii_case("k") {
            k = Some(param);
        }
    }

    let (Some(t), Some(k)) = (t, k) else {
        return Err(Error::MissingParam);
    };
    // Padding can only appear inside a quoted-string; accept it there.
    let k = URL_SAFE_NO_PAD
        .decode(k.trim_end_matches('='))
        .map_err(|_| Error::InvalidKey)?
        .try_into()
        .map_err(|_| Error::InvalidKey)?;
    Ok(Credentials { t, k })
}

/// Read a token or quoted-string at the start of `s`. Returns the unescaped
/// value and the remaining input.
fn param_value(s: &str) -> Result<(String, &str), Error> {
    let Some(quoted) = s.strip_prefix('"') else {
        let end = s
            .find(|c: char| c == ',' || c.is_ascii_whitespace())
            .unwrap_or(s.len());
        return Ok((s[..end].to_owned(), &s[end..]));
    };
    let mut out = String::new();
    let mut chars = quoted.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Ok((out, &quoted[i + 1..])),
            '\\' => out.push(chars.next().ok_or(Error::Malformed)?.1),
            c => out.push(c),
        }
    }
    Err(Error::Malformed)
}

/// Claims from a verified token.
#[derive(Debug)]
pub struct Claims {
    /// Expiry, in seconds since the Unix epoch.
    pub exp: u64,
    /// Contact for the application server operator, a `mailto:` or `https:`
    /// URI (RFC 8292 §2.1). Optional, and informational only.
    pub sub: Option<String>,
}

/// Decode one base64url JWS segment as JSON.
fn decode_json(segment: &str) -> Result<Value, Error> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| Error::Malformed)?;
    serde_json::from_slice(&bytes).map_err(|_| Error::Malformed)
}

/// Verify the JWT in `creds` against `k`, the push resource `origin`, and the
/// current time (RFC 8292 §2, §4.2).
///
/// `origin` is the Unicode serialization of the push resource origin, for
/// example `https://push.example.net`. `aud` may be that string or an array
/// containing it. The token is valid while `now_unix <= exp <= now_unix +
/// 86400`. Claims are only read after the signature verifies, so nothing from
/// an invalid token is ever used (RFC 8292 §2). See the
/// [module example](self).
///
/// # Errors
///
/// The first failing check, in this order: [`Error::InvalidKey`],
/// [`Error::UnsupportedAlgorithm`], [`Error::BadSignature`],
/// [`Error::Malformed`], [`Error::Expired`], [`Error::ExpiryTooFar`],
/// [`Error::AudienceMismatch`]. A token that is not three dot-separated
/// segments is [`Error::Malformed`].
pub fn verify(creds: &Credentials, origin: &str, now_unix: u64) -> Result<Claims, Error> {
    let key = VerifyingKey::from_sec1_bytes(&creds.k).map_err(|_| Error::InvalidKey)?;

    let mut parts = creds.t.split('.');
    let (Some(header), Some(payload), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::Malformed);
    };

    if decode_json(header)?["alg"] != "ES256" {
        return Err(Error::UnsupportedAlgorithm);
    }

    // JWS ES256 is the raw 64-octet r || s (RFC 7518 §3.4). `from_slice`
    // rejects any other length, which rules out DER.
    let sig = URL_SAFE_NO_PAD
        .decode(sig)
        .ok()
        .and_then(|s| Signature::from_slice(&s).ok())
        .ok_or(Error::BadSignature)?;
    let signing_input = &creds.t[..header.len() + 1 + payload.len()];
    key.verify(signing_input.as_bytes(), &sig)
        .map_err(|_| Error::BadSignature)?;

    // Claims are only read once the signature has verified (RFC 8292 §2).
    let claims = decode_json(payload)?;
    let exp = claims["exp"].as_u64().ok_or(Error::Malformed)?;
    if now_unix > exp {
        return Err(Error::Expired);
    }
    if exp - now_unix > MAX_EXP_AHEAD {
        return Err(Error::ExpiryTooFar);
    }
    let aud_ok = match &claims["aud"] {
        Value::String(a) => a == origin,
        Value::Array(list) => list.iter().any(|a| a == origin),
        _ => false,
    };
    if !aud_ok {
        return Err(Error::AudienceMismatch);
    }
    Ok(Claims {
        exp,
        sub: claims["sub"].as_str().map(str::to_owned),
    })
}
