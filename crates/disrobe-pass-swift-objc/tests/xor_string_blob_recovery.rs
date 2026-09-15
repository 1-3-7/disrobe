#![allow(clippy::expect_used)]

use disrobe_pass_swift_objc::swift::{self, XorBlobDecodeResult};

const EXPLICIT_KEY: u8 = 0x55;

const PROVENANCE: &str = "The ciphertext in these cases is produced by this test by xoring each byte of a chosen plaintext with a chosen key. It is a model of a single-byte XOR string blob, not output from SwiftConfidential or evidence about that tool.";

const API_ENDPOINT_CIPHERTEXT: &[u8] = &[
    0x34, 0x25, 0x3c, 0x0a, 0x3e, 0x30, 0x2c, 0x0a, 0x33, 0x3a, 0x27, 0x0a, 0x23, 0x64, 0x0a, 0x25,
    0x27, 0x3a, 0x31, 0x0a, 0x20, 0x26, 0x30, 0x55,
];

const BEARER_TOKEN_CIPHERTEXT: &[u8] = &[
    0x37, 0x30, 0x34, 0x27, 0x30, 0x27, 0x0a, 0x34, 0x36, 0x36, 0x30, 0x26, 0x26, 0x0a, 0x32, 0x27,
    0x34, 0x3b, 0x21, 0x0a, 0x2d, 0x55,
];

const EXPECTED_API_PLAINTEXT: &str = "api_key_for_v1_prod_use";
const EXPECTED_TOKEN_PLAINTEXT: &str = "bearer_access_grant_x";

fn model_xor(plaintext: &str) -> Vec<u8> {
    plaintext
        .bytes()
        .map(|byte: u8| byte ^ EXPLICIT_KEY)
        .collect()
}

#[test]
fn explicit_key_decodes_the_model_api_blob() {
    let result: XorBlobDecodeResult =
        swift::xor_decode_printable_strings(API_ENDPOINT_CIPHERTEXT, EXPLICIT_KEY);
    assert!(
        result
            .recovered
            .iter()
            .any(|plaintext: &String| plaintext == EXPECTED_API_PLAINTEXT),
        "{PROVENANCE}"
    );
    assert_eq!(result.key, EXPLICIT_KEY);
    assert_eq!(result.bytes_scanned, API_ENDPOINT_CIPHERTEXT.len());
}

#[test]
fn explicit_key_decodes_each_concatenated_model_blob() {
    let mut combined: Vec<u8> = Vec::new();
    combined.extend_from_slice(API_ENDPOINT_CIPHERTEXT);
    combined.push(EXPLICIT_KEY);
    combined.extend_from_slice(BEARER_TOKEN_CIPHERTEXT);
    let result: XorBlobDecodeResult = swift::xor_decode_printable_strings(&combined, EXPLICIT_KEY);
    assert!(
        result
            .recovered
            .iter()
            .any(|plaintext: &String| plaintext == EXPECTED_API_PLAINTEXT)
    );
    assert!(
        result
            .recovered
            .iter()
            .any(|plaintext: &String| plaintext == EXPECTED_TOKEN_PLAINTEXT)
    );
}

#[test]
fn wrong_explicit_key_does_not_recover_the_model_plaintext() {
    let result: XorBlobDecodeResult =
        swift::xor_decode_printable_strings(API_ENDPOINT_CIPHERTEXT, EXPLICIT_KEY ^ 0x01);
    assert!(
        !result
            .recovered
            .iter()
            .any(|plaintext: &String| plaintext == EXPECTED_API_PLAINTEXT),
        "the explicit key must affect decoding"
    );
}

#[test]
fn model_encoder_and_explicit_decoder_agree_for_an_unrelated_literal() {
    let plaintext: &str = "unrelated model literal";
    let ciphertext: Vec<u8> = model_xor(plaintext);
    let result: XorBlobDecodeResult =
        swift::xor_decode_printable_strings(&ciphertext, EXPLICIT_KEY);
    assert_eq!(result.recovered, vec![plaintext.to_owned()]);
}
