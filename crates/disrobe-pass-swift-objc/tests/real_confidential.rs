#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/macho_corpus.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod macho_corpus;

use std::collections::BTreeSet;

use disrobe_pass_swift_objc::macho::{self, ParsedSlice};
use disrobe_pass_swift_objc::swift::{
    self, ConfidentialDecryptResult, ConfidentialKeyRecovery, MIN_RECOVERABLE_CIPHERTEXT_LEN,
};

use macho_corpus::{CONFIDENTIAL_APP, CONFIDENTIAL_EDGE_BEFORE, read_host_sourced};

const TRUE_KEY: u8 = 0x55;

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

#[test]
fn confidential_pass_recovers_key_and_plaintext_for_api_endpoint() {
    let recovery: ConfidentialKeyRecovery =
        swift::confidential_recover_key(API_ENDPOINT_CIPHERTEXT).expect("recovery");
    assert_eq!(
        recovery.key, TRUE_KEY,
        "pass must DERIVE the key from the ciphertext, recovered {:#04x}",
        recovery.key
    );
    assert_eq!(recovery.keys_tried, 256);
    let plaintext: String = recovery
        .recovered
        .iter()
        .find(|s: &&String| s.contains("api_key"))
        .cloned()
        .unwrap_or_default();
    assert_eq!(plaintext, EXPECTED_API_PLAINTEXT);
}

#[test]
fn confidential_pass_recovers_key_and_plaintext_for_bearer_token() {
    let recovery: ConfidentialKeyRecovery =
        swift::confidential_recover_key(BEARER_TOKEN_CIPHERTEXT).expect("recovery");
    assert_eq!(
        recovery.key, TRUE_KEY,
        "pass must DERIVE the key from the ciphertext, recovered {:#04x}",
        recovery.key
    );
    let plaintext: String = recovery
        .recovered
        .iter()
        .find(|s: &&String| s.contains("bearer"))
        .cloned()
        .unwrap_or_default();
    assert_eq!(plaintext, EXPECTED_TOKEN_PLAINTEXT);
}

#[test]
fn confidential_pass_recovers_both_literals_from_concatenated_ciphertext() {
    let combined: Vec<u8> = {
        let mut buf: Vec<u8> =
            Vec::with_capacity(API_ENDPOINT_CIPHERTEXT.len() + BEARER_TOKEN_CIPHERTEXT.len());
        buf.extend_from_slice(API_ENDPOINT_CIPHERTEXT);
        buf.extend_from_slice(BEARER_TOKEN_CIPHERTEXT);
        buf
    };
    let result: ConfidentialDecryptResult =
        swift::confidential_recover(&combined).expect("recover");
    assert_eq!(
        result.key, TRUE_KEY,
        "key must be recovered, not supplied; got {:#04x}",
        result.key
    );
    assert!(
        result
            .recovered
            .iter()
            .any(|s: &String| s == EXPECTED_API_PLAINTEXT),
        "missing api endpoint literal in {:?}",
        result.recovered
    );
    assert!(
        result
            .recovered
            .iter()
            .any(|s: &String| s == EXPECTED_TOKEN_PLAINTEXT),
        "missing bearer token literal in {:?}",
        result.recovered
    );
    assert_eq!(result.candidates_scanned, combined.len());
}

const EDGE_EXPECTED_LITERALS: &[&str] = &[
    "key",
    "id",
    "tok",
    "api",
    "go",
    "api_key_short",
    "session_id_x42",
    "https://api.example.com/v1/auth/login",
    "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.tk",
    "refresh_token_abcdef1234567890abcdef1234567890",
    "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua ut enim ad minim",
    "Hello, World!",
    "Cafe con leche grande",
    "alpha-beta-gamma-2026",
    "konnichiwa-token-xyz",
    "key-icon-secret",
    "user=alice&pwd=p@ssw0rd!",
    "x-api-key: REDACTED",
    "/etc/passwd:0:0:root",
    "DROP TABLE users; -- comment",
];

fn embed_literal(plaintext: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(plaintext.len() + 1);
    bytes.extend(plaintext.bytes().map(|b: u8| b ^ TRUE_KEY));
    bytes.push(TRUE_KEY);
    bytes
}

#[test]
fn confidential_pass_recovers_key_for_every_sufficiently_long_edge_literal() {
    let mut wrong_key: Vec<(&'static str, u8)> = Vec::new();
    let mut checked: usize = 0;
    for plaintext in EDGE_EXPECTED_LITERALS {
        let ciphertext: Vec<u8> = embed_literal(plaintext);
        if ciphertext.len() < MIN_RECOVERABLE_CIPHERTEXT_LEN {
            continue;
        }
        checked += 1;
        let recovery: ConfidentialKeyRecovery =
            swift::confidential_recover_key(&ciphertext).expect("recovery");
        assert!(
            recovery.unambiguous,
            "{plaintext:?} is above the minimum length and must report unambiguous recovery"
        );
        if recovery.key != TRUE_KEY {
            wrong_key.push((plaintext, recovery.key));
        }
    }
    assert!(
        checked >= 14,
        "expected most edge literals to clear the length threshold, only {checked} did"
    );
    assert!(
        wrong_key.is_empty(),
        "pass recovered the wrong key for {wrong_key:?} (true key {TRUE_KEY:#04x})"
    );
}

#[test]
fn confidential_short_isolated_literals_are_flagged_ambiguous_not_silently_wrong() {
    for plaintext in ["id", "go", "key", "tok", "api"] {
        let ciphertext: Vec<u8> = embed_literal(plaintext);
        assert!(
            ciphertext.len() < MIN_RECOVERABLE_CIPHERTEXT_LEN,
            "{plaintext:?} should be below the recovery threshold"
        );
        let recovery: ConfidentialKeyRecovery =
            swift::confidential_recover_key(&ciphertext).expect("recovery");
        assert!(
            !recovery.unambiguous,
            "{plaintext:?} ciphertext is too short to claim an unambiguous key"
        );
    }
}

#[test]
fn confidential_pass_recovers_every_edge_plaintext_via_recovered_key() {
    let combined: Vec<u8> = EDGE_EXPECTED_LITERALS
        .iter()
        .flat_map(|p: &&str| embed_literal(p))
        .collect();
    let result: ConfidentialDecryptResult =
        swift::confidential_recover(&combined).expect("recover");
    assert_eq!(
        result.key, TRUE_KEY,
        "key must be recovered from the concatenated ciphertext, got {:#04x}",
        result.key
    );

    let recovered_concat: String = result.recovered.join("\n");
    let mut missing: Vec<&'static str> = Vec::new();
    for plaintext in EDGE_EXPECTED_LITERALS {
        if !recovered_concat.contains(*plaintext) {
            missing.push(plaintext);
        }
    }
    assert!(
        missing.is_empty(),
        "pass missed plaintext(s) {missing:?} after recovering key {:#04x}; runs={}",
        result.key,
        result.recovered.len()
    );
}

#[test]
fn confidential_recovered_runs_are_distinct() {
    let combined: Vec<u8> = EDGE_EXPECTED_LITERALS
        .iter()
        .flat_map(|p: &&str| embed_literal(p))
        .collect();
    let result: ConfidentialDecryptResult =
        swift::confidential_recover(&combined).expect("recover");
    let unique: BTreeSet<&String> = result.recovered.iter().collect();
    assert!(
        unique.len() > 5,
        "expected many distinct recovered runs, got {}",
        unique.len()
    );
}

#[test]
fn confidential_real_binary_recovers_key_when_fixture_present() {
    let Some(bytes): Option<Vec<u8>> = read_host_sourced(CONFIDENTIAL_APP) else {
        return;
    };
    let parsed: ParsedSlice = macho::parse_slice(&bytes).expect("parse confidential binary");
    assert!(
        !parsed.segments.is_empty(),
        "ConfidentialApp.bin produced no segments"
    );
    let api_window: Option<usize> = bytes
        .windows(API_ENDPOINT_CIPHERTEXT.len())
        .position(|w: &[u8]| w == API_ENDPOINT_CIPHERTEXT);
    let start: usize = api_window.unwrap_or_else(|| {
        panic!(
            "{} is present but does not embed the ciphertext window this case grades against; a \
             fixture that is here and carries nothing to recover is never a skip, because that is \
             how a rebuilt sample silently stops grading",
            CONFIDENTIAL_APP.relative()
        )
    });
    let isolated: &[u8] = &bytes[start..start + API_ENDPOINT_CIPHERTEXT.len()];
    let recovery: ConfidentialKeyRecovery =
        swift::confidential_recover_key(isolated).expect("recovery");
    assert_eq!(recovery.key, TRUE_KEY);
    assert!(
        recovery
            .recovered
            .iter()
            .any(|s: &String| s == EXPECTED_API_PLAINTEXT)
    );
}

#[test]
fn confidential_edge_before_binary_contains_every_plaintext_literal() {
    let Some(bytes): Option<Vec<u8>> = read_host_sourced(CONFIDENTIAL_EDGE_BEFORE) else {
        return;
    };
    let mut missing: Vec<&'static str> = Vec::new();
    for plaintext in EDGE_EXPECTED_LITERALS {
        let needle: &[u8] = plaintext.as_bytes();
        if !bytes.windows(needle.len()).any(|w: &[u8]| w == needle) {
            missing.push(plaintext);
        }
    }
    assert!(
        missing.is_empty(),
        "before.bin missing expected plaintext literal(s) {missing:?}"
    );
}
