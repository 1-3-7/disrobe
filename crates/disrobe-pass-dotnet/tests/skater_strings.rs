#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation
)]

mod common;

use disrobe_pass_dotnet::peel::skater::peel_skater;
use disrobe_pass_dotnet::peel::skater_strings::{SkaterStrings, recover_skater_strings};
use disrobe_pass_dotnet::peel::{PeelReport, PeelStrategy};

use crate::common::protector_pe::{DotnetPeSpec, build_dotnet_pe, ldc_i4_store_cctor};

const KEY: u8 = 0x6B;

const EXPECTED: &[&str] = &[
    "Activation=https://license.rustemsoft.example/validate",
    "ProductKey=ACME-PRO-2026-XYZ",
];

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out: String = String::new();
    for chunk in data.chunks(3) {
        let b: [u8; 3] = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n: u32 = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 0x3F] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3F] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 0x3F] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 0x3F] as char
        } else {
            '='
        });
    }
    out
}

fn forward_encode(plain: &str, key: u8) -> Vec<u16> {
    let cipher_bytes: Vec<u8> = plain.bytes().map(|b: u8| b ^ key).collect();
    let b64: String = base64_encode(&cipher_bytes);
    b64.encode_utf16().collect()
}

fn build_sample() -> Vec<u8> {
    let mut spec: DotnetPeSpec = DotnetPeSpec::new(&["RustemSoft.Skater", "SkaterObfuscator"]);
    spec.cctor_body = Some(ldc_i4_store_cctor(u32::from(KEY), 0x0400_0001));
    spec.us_entries = EXPECTED
        .iter()
        .map(|p: &&str| forward_encode(p, KEY))
        .collect();
    build_dotnet_pe(&spec)
}

#[test]
fn base64_xor_recovery_grades_against_expected_vector() {
    let image: Vec<u8> = build_sample();
    let recovery: SkaterStrings = recover_skater_strings(&image).expect("recover");
    assert_eq!(
        recovery.key,
        Some(KEY),
        "the single-byte XOR key must come from the static ldc.i4 constant"
    );
    let texts: Vec<String> = recovery.recovered.iter().map(|r| r.text.clone()).collect();
    for expected in EXPECTED {
        assert!(
            texts.iter().any(|t: &String| t == expected),
            "expected {expected:?} must be recovered; got {texts:?}"
        );
    }
}

#[test]
fn peel_promotes_strategy_on_recovery() {
    let image: Vec<u8> = build_sample();
    let report: PeelReport = peel_skater(&image).expect("peel");
    assert_eq!(report.strategy, PeelStrategy::EncryptedResourceExtracted);
    assert_eq!(report.recovered_strings.len(), EXPECTED.len());
}
