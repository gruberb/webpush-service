//! RFC 8292 VAPID parsing and verification. Uses the §2.4 vector and tokens
//! signed by the harness oracle. No emulator needed.
#![allow(clippy::unwrap_used)]

mod oracle;

use oracle::{AppServerKey, b64, now, off_curve, unb64};
use webpush_crypto::vapid::{self, Credentials, Error};

/// RFC 8292 §2.4: the example JWT.
const T: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3B1c2guZXhhbXBsZS5uZXQiLCJleHAiOjE0NTM1MjM3NjgsInN1YiI6Im1haWx0bzpwdXNoQGV4YW1wbGUuY29tIn0.i3CYb7t4xfxCDquptFOepC9GAu_HLGkMlMuCGSK2rpiUfnK9ojFwDXb1JrErtmysazNjjvW2L9OkSSHzvoD1oA";
/// RFC 8292 §2.4: the key that signed [`T`].
const K: &str =
    "BA1Hxzyi1RUM1b5wjxsn7nGxAszw2u61m164i3MrAIxHF6YK5h4SDYic-dRuU_RCPCfA5aq9ojSwk5Y2EmClBPs";
/// RFC 8292 §2.4: `exp` of [`T`].
const EXP: u64 = 1_453_523_768;
/// RFC 8292 §2.4: `aud` of [`T`].
const ORIGIN: &str = "https://push.example.net";
/// A valid P-256 key that did not sign [`T`] (RFC 8291 Appendix A).
const RFC8291_AS_PUBLIC: &str =
    "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
/// A JWS header for ES256.
const ES256: &str = r#"{"typ":"JWT","alg":"ES256"}"#;

/// Credentials from the RFC 8292 §2.4 example.
fn rfc_creds() -> Credentials {
    vapid::parse_authorization(&format!("vapid t={T}, k={K}")).unwrap()
}

/// Credentials parsed from a `t` and `k` pair.
fn creds(t: &str, k: &str) -> Credentials {
    vapid::parse_authorization(&format!("vapid t={t}, k={k}")).unwrap()
}

/// VAP-01..05 (MUST): the RFC example verifies an hour before it expires.
#[test]
fn rfc_example_verifies() {
    let claims = vapid::verify(&rfc_creds(), ORIGIN, EXP - 3600).unwrap();
    assert_eq!(claims.exp, EXP);
    assert_eq!(claims.sub.as_deref(), Some("mailto:push@example.com"));
}

/// VAP-03 (MUST): invalid once now is past exp.
#[test]
fn expired() {
    assert_eq!(
        vapid::verify(&rfc_creds(), ORIGIN, EXP + 1).unwrap_err(),
        Error::Expired
    );
}

/// VAP-03 (MUST): exp more than 24 hours out is invalid; exactly 24 hours is
/// accepted.
#[test]
fn expiry_more_than_24h() {
    assert_eq!(
        vapid::verify(&rfc_creds(), ORIGIN, EXP - 86401).unwrap_err(),
        Error::ExpiryTooFar
    );
    assert!(vapid::verify(&rfc_creds(), ORIGIN, EXP - 86400).is_ok());
}

/// VAP-02 (MUST): aud must match the push resource origin.
#[test]
fn audience_mismatch() {
    assert_eq!(
        vapid::verify(&rfc_creds(), "https://push.example.com", EXP - 3600).unwrap_err(),
        Error::AudienceMismatch
    );
}

/// VAP-02 (MUST): aud may be an array that includes the origin.
#[test]
fn aud_array_containing_origin() {
    let key = AppServerKey::new();
    let exp = now() + 3600;
    let claims = serde_json::json!({ "aud": ["https://other.example", ORIGIN], "exp": exp });
    let t = key.token_raw(ES256, &claims.to_string());
    let claims = vapid::verify(&creds(&t, &key.k_b64()), ORIGIN, now()).unwrap();
    assert_eq!(claims.exp, exp);
    assert_eq!(claims.sub, None);
}

/// VAP-01 (MUST): changing the claims breaks the signature.
#[test]
fn tampered_claims() {
    let parts: Vec<&str> = T.split('.').collect();
    let claims = format!(
        r#"{{"aud":"{ORIGIN}","exp":{},"sub":"mailto:push@example.com"}}"#,
        EXP + 1
    );
    let t = format!("{}.{}.{}", parts[0], b64(claims.as_bytes()), parts[2]);
    assert_eq!(
        vapid::verify(&creds(&t, K), ORIGIN, EXP - 3600).unwrap_err(),
        Error::BadSignature
    );
}

/// VAP-01 (MUST): the signature must verify against `k`, not merely against
/// some valid key.
#[test]
fn other_valid_key() {
    assert_eq!(
        vapid::verify(&creds(T, RFC8291_AS_PUBLIC), ORIGIN, EXP - 3600).unwrap_err(),
        Error::BadSignature
    );
}

/// VAP-01 (MUST): JWS ES256 signatures are raw r||s; DER is rejected.
#[test]
fn der_signature_rejected() {
    let key = AppServerKey::new();
    let claims = serde_json::json!({ "aud": ORIGIN, "exp": now() + 3600 });
    let input = format!(
        "{}.{}",
        b64(ES256.as_bytes()),
        b64(claims.to_string().as_bytes())
    );
    let der = key.sign(input.as_bytes()).to_der();
    let t = format!("{input}.{}", b64(der.as_bytes()));
    assert_eq!(
        vapid::verify(&creds(&t, &key.k_b64()), ORIGIN, now()).unwrap_err(),
        Error::BadSignature
    );
}

/// VAP-01 (MUST): any alg other than ES256 is invalid.
#[test]
fn alg_not_es256() {
    let key = AppServerKey::new();
    let claims = serde_json::json!({ "aud": ORIGIN, "exp": now() + 3600 }).to_string();
    for alg in ["HS256", "none"] {
        let t = key.token_raw(&format!(r#"{{"typ":"JWT","alg":"{alg}"}}"#), &claims);
        assert_eq!(
            vapid::verify(&creds(&t, &key.k_b64()), ORIGIN, now()).unwrap_err(),
            Error::UnsupportedAlgorithm,
            "alg {alg}"
        );
    }
}

/// VAP-03 (MUST): exp is required.
#[test]
fn missing_exp() {
    let key = AppServerKey::new();
    let t = key.token_raw(ES256, &serde_json::json!({ "aud": ORIGIN }).to_string());
    assert_eq!(
        vapid::verify(&creds(&t, &key.k_b64()), ORIGIN, now()).unwrap_err(),
        Error::Malformed
    );
}

/// VAP-05 (MUST): `k` must be a base64url uncompressed P-256 point.
#[test]
fn k_invalid() {
    let err = |k: &str| match vapid::parse_authorization(&format!("vapid t={T}, k={k}")) {
        Err(e) => e,
        Ok(c) => vapid::verify(&c, ORIGIN, EXP - 3600).unwrap_err(),
    };
    let point: [u8; 65] = unb64(K).try_into().unwrap();
    assert_eq!(
        err(&b64(&off_curve(&point))),
        Error::InvalidKey,
        "off curve"
    );
    assert_eq!(err(&b64(&point[1..])), Error::InvalidKey, "64 octets");
    assert_eq!(err("!!!!"), Error::InvalidKey, "bad base64");
}

/// VAP-04 (MUST): case-insensitive scheme, any param order, quoted values,
/// `realm` and unknown params ignored, whitespace around `,` and `=`.
#[test]
fn parse_lenient_grammar() {
    let variants = [
        format!("VAPID t={T}, k={K}"),
        format!("vapid k={K}, t={T}"),
        format!("vapid t=\"{T}\", k=\"{K}\""),
        format!("vapid realm=\"push\", t={T}, foo=bar, k={K}"),
        format!("vapid   t = {T} ,k= {K}"),
    ];
    let k = unb64(K);
    for v in &variants {
        let c = vapid::parse_authorization(v).unwrap_or_else(|e| panic!("{v}: {e:?}"));
        assert_eq!(c.t, T, "{v}");
        assert_eq!(c.k.to_vec(), k, "{v}");
        assert!(vapid::verify(&c, ORIGIN, EXP - 3600).is_ok(), "{v}");
    }
}

/// VAP-04, VAP-09 (MUST): `t` and `k` are required; other schemes are not
/// VAPID.
#[test]
fn parse_missing_params() {
    let parse = |v: &str| vapid::parse_authorization(v).unwrap_err();
    assert_eq!(parse(&format!("vapid k={K}")), Error::MissingParam);
    assert_eq!(parse(&format!("vapid t={T}")), Error::MissingParam);
    assert_eq!(parse("Bearer abc"), Error::NotVapid);
}
