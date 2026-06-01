#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use disrobe_pass_swift_objc::macho::{self, ParsedSlice};
use disrobe_pass_swift_objc::swift::{self, ConfidentialDecryptResult};

const XOR_KEY: u8 = 0x55;

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

fn corpus_root() -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &Path = manifest_dir
        .ancestors()
        .nth(2)
        .expect("workspace root above crate");
    workspace_root
        .join("corpus")
        .join("mobile")
        .join("macho-mac")
}

fn legacy_root() -> PathBuf {
    corpus_root()
}

fn edge_root() -> PathBuf {
    corpus_root().join("confidential-edgecases")
}

fn load_at(root: &Path, name: &str) -> Option<Vec<u8>> {
    let path: PathBuf = root.join(name);
    fs::read(&path).ok()
}

#[test]
fn confidential_xor_decrypts_isolated_api_endpoint_literal() {
    let decrypted: Vec<u8> = swift::confidential_xor_decrypt(API_ENDPOINT_CIPHERTEXT, XOR_KEY);
    let recovered: String = String::from_utf8_lossy(&decrypted)
        .trim_end_matches('\0')
        .to_owned();
    assert_eq!(recovered, EXPECTED_API_PLAINTEXT);
}

#[test]
fn confidential_xor_decrypts_isolated_bearer_token_literal() {
    let decrypted: Vec<u8> = swift::confidential_xor_decrypt(BEARER_TOKEN_CIPHERTEXT, XOR_KEY);
    let recovered: String = String::from_utf8_lossy(&decrypted)
        .trim_end_matches('\0')
        .to_owned();
    assert_eq!(recovered, EXPECTED_TOKEN_PLAINTEXT);
}

#[test]
fn confidential_recover_strings_splits_both_literals_with_terminator() {
    let combined: Vec<u8> = {
        let mut buf: Vec<u8> =
            Vec::with_capacity(API_ENDPOINT_CIPHERTEXT.len() + BEARER_TOKEN_CIPHERTEXT.len());
        buf.extend_from_slice(API_ENDPOINT_CIPHERTEXT);
        buf.extend_from_slice(BEARER_TOKEN_CIPHERTEXT);
        buf
    };
    let result: ConfidentialDecryptResult = swift::confidential_recover_strings(&combined, XOR_KEY);
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
    assert_eq!(result.key, XOR_KEY);
    assert_eq!(result.candidates_scanned, combined.len());
}

#[test]
fn confidential_real_binary_yields_ciphertext_when_scanned_for_xor_recovery() {
    let Some(bytes): Option<Vec<u8>> = load_at(&legacy_root(), "ConfidentialApp.bin") else {
        eprintln!("skip: macho-mac/ConfidentialApp.bin fixture absent");
        return;
    };
    let parsed: ParsedSlice = macho::parse_slice(&bytes).expect("parse confidential binary");
    assert!(
        !parsed.segments.is_empty(),
        "ConfidentialApp.bin produced no segments"
    );
    let mut found_api: bool = false;
    let mut found_token: bool = false;
    let api_needle: Vec<u8> = API_ENDPOINT_CIPHERTEXT.to_vec();
    let token_needle: Vec<u8> = BEARER_TOKEN_CIPHERTEXT.to_vec();
    for window in bytes.windows(api_needle.len()) {
        if window == api_needle.as_slice() {
            found_api = true;
            break;
        }
    }
    for window in bytes.windows(token_needle.len()) {
        if window == token_needle.as_slice() {
            found_token = true;
            break;
        }
    }
    assert!(
        found_api,
        "ConfidentialApp.bin missing api endpoint ciphertext (compiler may have inlined literal differently)"
    );
    assert!(
        found_token,
        "ConfidentialApp.bin missing bearer token ciphertext"
    );

    let whole_decrypted: Vec<u8> = swift::confidential_xor_decrypt(&bytes, XOR_KEY);
    let api_bytes: &[u8] = EXPECTED_API_PLAINTEXT.as_bytes();
    let token_bytes: &[u8] = EXPECTED_TOKEN_PLAINTEXT.as_bytes();
    let api_found_after_xor: bool = whole_decrypted
        .windows(api_bytes.len())
        .any(|w: &[u8]| w == api_bytes);
    let token_found_after_xor: bool = whole_decrypted
        .windows(token_bytes.len())
        .any(|w: &[u8]| w == token_bytes);
    assert!(
        api_found_after_xor,
        "XOR-decrypted binary missing api endpoint plaintext bytes"
    );
    assert!(
        token_found_after_xor,
        "XOR-decrypted binary missing bearer token plaintext bytes"
    );
    let result: ConfidentialDecryptResult = swift::confidential_recover_strings(&bytes, XOR_KEY);
    assert_eq!(result.key, XOR_KEY);
    assert_eq!(result.candidates_scanned, bytes.len());
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

#[test]
fn confidential_edge_after_binary_yields_every_known_ciphertext_window() {
    let Some(bytes): Option<Vec<u8>> = load_at(&edge_root(), "ConfidentialEdgeCases.after.bin")
    else {
        eprintln!("skip: confidential-edgecases/ConfidentialEdgeCases.after.bin fixture absent");
        return;
    };
    let parsed: ParsedSlice = macho::parse_slice(&bytes).expect("parse edge after.bin");
    assert!(!parsed.segments.is_empty(), "after.bin has no segments");

    let mut missing: Vec<&'static str> = Vec::new();
    for plaintext in EDGE_EXPECTED_LITERALS {
        let cipher: Vec<u8> = plaintext
            .as_bytes()
            .iter()
            .map(|b: &u8| b ^ XOR_KEY)
            .collect();
        let mut found: bool = false;
        for window in bytes.windows(cipher.len()) {
            if window == cipher.as_slice() {
                found = true;
                break;
            }
        }
        if !found {
            missing.push(plaintext);
        }
    }
    assert!(
        missing.is_empty(),
        "after.bin missing ciphertext window(s) for {missing:?}"
    );
}

#[test]
fn confidential_edge_after_binary_does_not_contain_plain_secrets() {
    let Some(bytes): Option<Vec<u8>> = load_at(&edge_root(), "ConfidentialEdgeCases.after.bin")
    else {
        eprintln!("skip: confidential-edgecases/ConfidentialEdgeCases.after.bin fixture absent");
        return;
    };

    let always_unique: &[&str] = &[
        "api_key_short",
        "session_id_x42",
        "https://api.example.com/v1/auth/login",
        "refresh_token_abcdef1234567890abcdef1234567890",
        "x-api-key: REDACTED",
    ];
    for plaintext in always_unique {
        let needle: &[u8] = plaintext.as_bytes();
        let mut found: bool = false;
        for window in bytes.windows(needle.len()) {
            if window == needle {
                found = true;
                break;
            }
        }
        assert!(
            !found,
            "after.bin must not contain plaintext secret {plaintext:?} before XOR"
        );
    }
}

#[test]
fn confidential_edge_before_binary_contains_every_plaintext_literal() {
    let Some(bytes): Option<Vec<u8>> = load_at(&edge_root(), "ConfidentialEdgeCases.before.bin")
    else {
        eprintln!("skip: confidential-edgecases/ConfidentialEdgeCases.before.bin fixture absent");
        return;
    };
    let mut missing: Vec<&'static str> = Vec::new();
    for plaintext in EDGE_EXPECTED_LITERALS {
        let needle: &[u8] = plaintext.as_bytes();
        let mut found: bool = false;
        for window in bytes.windows(needle.len()) {
            if window == needle {
                found = true;
                break;
            }
        }
        if !found {
            missing.push(plaintext);
        }
    }
    assert!(
        missing.is_empty(),
        "before.bin missing expected plaintext literal(s) {missing:?}"
    );
}

#[test]
fn confidential_edge_recover_strings_surfaces_all_twenty_plaintexts_as_substrings() {
    let Some(bytes): Option<Vec<u8>> = load_at(&edge_root(), "ConfidentialEdgeCases.after.bin")
    else {
        eprintln!("skip: confidential-edgecases/ConfidentialEdgeCases.after.bin fixture absent");
        return;
    };
    let result: ConfidentialDecryptResult = swift::confidential_recover_strings(&bytes, XOR_KEY);
    assert_eq!(result.key, XOR_KEY);
    assert_eq!(result.candidates_scanned, bytes.len());
    assert!(
        !result.recovered.is_empty(),
        "recover returned zero printable runs"
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
        "confidential_recover_strings missed plaintext(s) {missing:?}; total runs={} (largest={})",
        result.recovered.len(),
        result.recovered.iter().map(String::len).max().unwrap_or(0)
    );
}

#[test]
fn confidential_edge_recover_strings_returns_distinct_runs() {
    let Some(bytes): Option<Vec<u8>> = load_at(&edge_root(), "ConfidentialEdgeCases.after.bin")
    else {
        eprintln!("skip: confidential-edgecases/ConfidentialEdgeCases.after.bin fixture absent");
        return;
    };
    let result: ConfidentialDecryptResult = swift::confidential_recover_strings(&bytes, XOR_KEY);
    let unique: BTreeSet<&String> = result.recovered.iter().collect();
    assert!(
        unique.len() > 5,
        "expected many distinct printable runs in XOR-decoded binary, got {}",
        unique.len()
    );
}

#[test]
fn confidential_edge_whole_binary_xor_pass_exposes_every_plaintext_window() {
    let Some(bytes): Option<Vec<u8>> = load_at(&edge_root(), "ConfidentialEdgeCases.after.bin")
    else {
        eprintln!("skip: confidential-edgecases/ConfidentialEdgeCases.after.bin fixture absent");
        return;
    };
    let decrypted: Vec<u8> = swift::confidential_xor_decrypt(&bytes, XOR_KEY);
    let mut missing: Vec<&'static str> = Vec::new();
    for plaintext in EDGE_EXPECTED_LITERALS {
        let needle: &[u8] = plaintext.as_bytes();
        let mut found: bool = false;
        for window in decrypted.windows(needle.len()) {
            if window == needle {
                found = true;
                break;
            }
        }
        if !found {
            missing.push(plaintext);
        }
    }
    assert!(
        missing.is_empty(),
        "whole-binary XOR pass missing plaintext window(s) {missing:?}"
    );
}
