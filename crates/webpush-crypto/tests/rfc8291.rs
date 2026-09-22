//! RFC 8291 vectors from §5 and Appendix A. Malformed bodies are sealed by the
//! harness oracle with the Appendix A CEK and NONCE. No emulator needed.
#![allow(clippy::unwrap_used)]

mod oracle;

use oracle::{ece_header, ece_record, off_curve, unb64};
use webpush_crypto::ece::{self, Error, webpush};

/// RFC 8291 §5: user agent authentication secret.
const AUTH_SECRET: &str = "BTBZMqHH6r4Tts7J_aSIgg";
/// RFC 8291 Appendix A: user agent private key.
const UA_PRIVATE: &str = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94";
/// RFC 8291 Appendix A: user agent public key.
const UA_PUBLIC: &str =
    "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
/// RFC 8291 Appendix A: application server private key.
const AS_PRIVATE: &str = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
/// RFC 8291 Appendix A: application server public key.
const AS_PUBLIC: &str =
    "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
/// RFC 8291 §5: salt.
const SALT: &str = "DGv6ra1nlYgDCS1FRnbzlw";
/// RFC 8291 Appendix A: ECDH shared secret.
const ECDH_SECRET: &str = "kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs";
/// RFC 8291 Appendix A: input keying material.
const IKM: &str = "S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg";
/// RFC 8291 Appendix A: content encryption key.
const CEK: &str = "oIhVW04MRdy2XN9CiKLxTg";
/// RFC 8291 Appendix A: base nonce.
const NONCE: &str = "4h_95klXJ5E_qnoN";
/// RFC 8291 §5: plaintext.
const PLAINTEXT: &[u8] = b"When I grow up, I want to be a watermelon";
/// RFC 8291 §5: encrypted body, 144 octets.
const BODY: &str = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN";

/// Decode base64url into a fixed-size array.
fn arr<const N: usize>(s: &str) -> [u8; N] {
    unb64(s).try_into().unwrap()
}

/// Swap the keyid of the §5 body for `keyid`, keeping salt, rs, and record.
fn with_keyid(keyid: &[u8]) -> Vec<u8> {
    let body = unb64(BODY);
    let mut out = ece_header(&arr(SALT), 4096, keyid);
    out.extend_from_slice(&body[86..]);
    out
}

/// ENC-01 (MUST): IKM derivation matches Appendix A.
#[test]
fn ikm_matches_appendix_a() {
    let ikm = webpush::ikm(
        &unb64(ECDH_SECRET),
        &arr(AUTH_SECRET),
        &arr(UA_PUBLIC),
        &arr(AS_PUBLIC),
    );
    assert_eq!(ikm.to_vec(), unb64(IKM));
}

/// ECE-02 (MUST): CEK and NONCE from the Appendix A IKM and salt.
#[test]
fn cek_nonce_match_appendix_a() {
    let (cek, nonce) = ece::derive_cek_nonce(&unb64(IKM), &arr(SALT));
    assert_eq!(cek.to_vec(), unb64(CEK));
    assert_eq!(nonce.to_vec(), unb64(NONCE));
}

/// ENC-01..04 (MUST): encryption reproduces the §5 body. The body is 144
/// octets; the RFC text says `Content-Length: 145` (erratum).
#[test]
fn encrypt_matches_section_5() {
    let body = webpush::encrypt(
        &arr(UA_PUBLIC),
        &arr(AUTH_SECRET),
        &arr(AS_PRIVATE),
        &arr(SALT),
        PLAINTEXT,
    )
    .unwrap();
    assert_eq!(body.len(), 144);
    assert_eq!(body, unb64(BODY));
}

/// ENC-04 (MUST): 86-octet header, rs 4096, keyid is the 65-octet
/// uncompressed application server key.
#[test]
fn header_is_86_octets() {
    let body = unb64(BODY);
    let (header, rest) = ece::parse_header(&body).unwrap();
    assert_eq!(body.len() - rest.len(), 86);
    assert_eq!(header.rs, 4096);
    assert_eq!(header.keyid.len(), 65);
    assert_eq!(header.keyid[0], 0x04);
    assert_eq!(header.keyid, unb64(AS_PUBLIC));
}

/// ENC-01 (MUST): the user agent decrypts the §5 body.
#[test]
fn decrypt_section_5() {
    let pt = webpush::decrypt(&arr(UA_PRIVATE), &arr(AUTH_SECRET), &unb64(BODY)).unwrap();
    assert_eq!(pt, PLAINTEXT);
}

/// ENC-06 (MUST): a padding delimiter other than 0x02 means the message is
/// discarded.
#[test]
fn delimiter_other_than_2_discarded() {
    let mut body = ece_header(&arr(SALT), 4096, &unb64(AS_PUBLIC));
    let mut pt = PLAINTEXT.to_vec();
    pt.push(0x01);
    body.extend(ece_record(&arr(CEK), &arr(NONCE), 0, &pt));
    assert_eq!(
        webpush::decrypt(&arr(UA_PRIVATE), &arr(AUTH_SECRET), &body).unwrap_err(),
        Error::InvalidPadding
    );
}

/// ENC-07 (MUST): a keyid that is not a P-256 point is rejected.
#[test]
fn keyid_not_on_curve() {
    let body = with_keyid(&off_curve(&arr(AS_PUBLIC)));
    assert_eq!(
        webpush::decrypt(&arr(UA_PRIVATE), &arr(AUTH_SECRET), &body).unwrap_err(),
        Error::InvalidPublicKey
    );
}

/// ENC-04 (MUST): keyid must be 65 octets in uncompressed form.
#[test]
fn keyid_wrong_form() {
    let key = unb64(AS_PUBLIC);
    let mut compressed = vec![0x02 | (key[64] & 1)];
    compressed.extend_from_slice(&key[1..33]);
    for keyid in [&key[1..], &compressed[..]] {
        assert_eq!(
            webpush::decrypt(&arr(UA_PRIVATE), &arr(AUTH_SECRET), &with_keyid(keyid)).unwrap_err(),
            Error::InvalidKeyId,
            "keyid of {} octets",
            keyid.len()
        );
    }
}

/// ENC-07 (MUST): encrypting to an off-curve user agent key fails.
#[test]
fn encrypt_rejects_off_curve_ua_key() {
    let err = webpush::encrypt(
        &off_curve(&arr(UA_PUBLIC)),
        &arr(AUTH_SECRET),
        &arr(AS_PRIVATE),
        &arr(SALT),
        PLAINTEXT,
    )
    .unwrap_err();
    assert_eq!(err, Error::InvalidPublicKey);
}

/// ENC-02 (MUST): the auth secret is part of the key; a wrong one fails.
#[test]
fn wrong_auth_secret() {
    let mut auth: [u8; 16] = arr(AUTH_SECRET);
    auth[0] ^= 0x01;
    assert_eq!(
        webpush::decrypt(&arr(UA_PRIVATE), &auth, &unb64(BODY)).unwrap_err(),
        Error::Decrypt
    );
}

/// ENC-03, ENC-08 (MUST, DERIVED): 3993 octets of plaintext produce a
/// 4096-octet body (86 header + 3993 + 1 delimiter + 16 tag) that decrypts back to the original.
#[test]
fn max_plaintext_3993_fits_4096() {
    let pt = vec![0x61; 3993];
    let body = webpush::encrypt(
        &arr(UA_PUBLIC),
        &arr(AUTH_SECRET),
        &arr(AS_PRIVATE),
        &arr(SALT),
        &pt,
    )
    .unwrap();
    assert_eq!(body.len(), 4096);
    assert_eq!(
        webpush::decrypt(&arr(UA_PRIVATE), &arr(AUTH_SECRET), &body).unwrap(),
        pt
    );
}
