//! RFC 8188 `aes128gcm` vectors and malformed-record cases. Malformed records
//! are sealed by the harness oracle with the §3.1 CEK and NONCE, not by
//! `src/ece.rs`. No emulator needed.
#![allow(clippy::unwrap_used)]

mod oracle;

use oracle::{ece_header, ece_record, unb64};
use webpush_crypto::ece::{self, Error};

/// RFC 8188 §3.1: input keying material.
const S31_IKM: &str = "yqdlZ-tYemfogSmv7Ws5PQ";
/// RFC 8188 §3.1: encrypted body, one record, rs 4096, empty key id.
const S31_BODY: &str = "I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-ly8Thjg";
/// RFC 8188 §3.1: content encryption key.
const S31_CEK: &str = "_wniytB-ofscZDh4tbSjHw";
/// RFC 8188 §3.1: base nonce.
const S31_NONCE: &str = "Bcs8gkIRKLI8GeI8";
/// RFC 8188 §3.2: input keying material.
const S32_IKM: &str = "BO3ZVPxUlnLORbVGMpbT1Q";
/// RFC 8188 §3.2: encrypted body, two records, rs 25, key id "a1".
const S32_BODY: &str = "uNCkWiNYzKTnBN9ji3-qWAAAABkCYTHOG8chz_gnvgOqdGYovxyjuqRyJFjEDyoF1Fvkj6hQPdPHI51OEUKEpgz3SsLWIqS_uA";
/// Plaintext of both RFC 8188 examples.
const WALRUS: &[u8] = b"I am the walrus";

/// The salt from the §3.1 header.
fn s31_salt() -> [u8; 16] {
    unb64(S31_BODY)[..16].try_into().unwrap()
}

/// Seal a body under the §3.1 key: header with `rs`, then one record per
/// entry of `records`.
fn oracle_body(rs: u32, records: &[&[u8]]) -> Vec<u8> {
    let cek: [u8; 16] = unb64(S31_CEK).try_into().unwrap();
    let nonce: [u8; 12] = unb64(S31_NONCE).try_into().unwrap();
    let mut body = ece_header(&s31_salt(), rs, b"");
    for (seq, pt) in records.iter().enumerate() {
        body.extend(ece_record(&cek, &nonce, seq as u64, pt));
    }
    body
}

/// ECE-01..04 (MUST): RFC 8188 §3.1 decrypts. The body is 53 octets; the RFC
/// text says 54 (erratum).
#[test]
fn s3_1_decrypt() {
    let body = unb64(S31_BODY);
    assert_eq!(body.len(), 53);
    assert_eq!(ece::decrypt(&unb64(S31_IKM), &body).unwrap(), WALRUS);
}

/// ECE-02 (MUST): CEK and NONCE derivation matches §3.1.
#[test]
fn s3_1_cek_nonce() {
    let (cek, nonce) = ece::derive_cek_nonce(&unb64(S31_IKM), &s31_salt());
    assert_eq!(cek.to_vec(), unb64(S31_CEK));
    assert_eq!(nonce.to_vec(), unb64(S31_NONCE));
}

/// ECE-01..04 (MUST): encrypting the §3.1 inputs reproduces the body exactly.
#[test]
fn s3_1_encrypt_exact() {
    let body = ece::encrypt(&unb64(S31_IKM), &s31_salt(), 4096, b"", WALRUS).unwrap();
    assert_eq!(body, unb64(S31_BODY));
}

/// ECE-02, ECE-03 (MUST): the §3.2 two-record body with rs 25 and keyid "a1".
#[test]
fn s3_2_multi_record() {
    let body = unb64(S32_BODY);
    let (header, _) = ece::parse_header(&body).unwrap();
    assert_eq!(header.rs, 25);
    assert_eq!(header.keyid, b"a1");
    assert_eq!(ece::decrypt(&unb64(S32_IKM), &body).unwrap(), WALRUS);
}

/// ECE-01 (MUST): rs below 18 is invalid.
#[test]
fn rs_below_18_invalid() {
    let mut body = unb64(S31_BODY);
    body[16..20].copy_from_slice(&17u32.to_be_bytes());
    assert_eq!(
        ece::parse_header(&body).unwrap_err(),
        Error::InvalidRecordSize
    );
    assert_eq!(
        ece::decrypt(&unb64(S31_IKM), &body).unwrap_err(),
        Error::InvalidRecordSize
    );
}

/// ECE-01 (MUST): a header shorter than 21 octets, or a keyid running past the
/// end, is truncated.
#[test]
fn truncated_header() {
    let body = unb64(S31_BODY);
    assert_eq!(
        ece::parse_header(&body[..20]).unwrap_err(),
        Error::Truncated
    );
    let mut short_keyid = body[..20].to_vec();
    short_keyid.extend_from_slice(&[5, b'a', b'b']);
    assert_eq!(
        ece::parse_header(&short_keyid).unwrap_err(),
        Error::Truncated
    );
}

/// ECE-02 (MUST): a flipped ciphertext bit fails authentication.
#[test]
fn tampered_ciphertext() {
    let mut body = unb64(S31_BODY);
    body[30] ^= 0x01;
    assert_eq!(
        ece::decrypt(&unb64(S31_IKM), &body).unwrap_err(),
        Error::Decrypt
    );
}

/// ECE-03 (MUST): a record with no non-zero octet has no delimiter.
#[test]
fn no_delimiter_fails() {
    let body = oracle_body(4096, &[&[0u8; 16]]);
    assert_eq!(
        ece::decrypt(&unb64(S31_IKM), &body).unwrap_err(),
        Error::InvalidPadding
    );
}

/// ECE-03 (MUST): the last record's delimiter must be 0x02.
#[test]
fn last_record_delimiter_must_be_2() {
    let body = oracle_body(4096, &[b"hello\x01"]);
    assert_eq!(
        ece::decrypt(&unb64(S31_IKM), &body).unwrap_err(),
        Error::InvalidPadding
    );
}

/// ECE-03 (MUST): a non-last record's delimiter must be 0x01.
#[test]
fn non_last_delimiter_must_be_1() {
    // rs 24: the first record is full size (8 octets plaintext + 16 tag).
    let body = oracle_body(24, &[b"abcdefg\x02", b"hi\x02"]);
    assert_eq!(
        ece::decrypt(&unb64(S31_IKM), &body).unwrap_err(),
        Error::InvalidPadding
    );
}

/// ECE-05 (MUST): removing the last record is detected, not accepted as a
/// shorter message.
#[test]
fn truncation_detected() {
    let body = unb64(S32_BODY);
    // 23-octet header plus two 25-octet records.
    assert_eq!(body.len(), 73);
    assert!(ece::decrypt(&unb64(S32_IKM), &body[..48]).is_err());
}
