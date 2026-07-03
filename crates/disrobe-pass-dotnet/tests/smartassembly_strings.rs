#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation
)]

mod common;

use disrobe_pass_dotnet::peel::smartassembly::peel_smartassembly;
use disrobe_pass_dotnet::peel::smartassembly_strings::{
    SmartAssemblyStrings, recover_smartassembly_strings,
};
use disrobe_pass_dotnet::peel::{PeelReport, PeelStrategy};

use crate::common::protector_pe::{DotnetPeSpec, build_dotnet_pe, ldc_i4_store_cctor};

const KEY: u32 = 0x5A3C_71E9;

const EXPECTED_PLAINTEXTS: &[&str] = &[
    "Data Source=prod-sql;Initial Catalog=billing;User Id=svc;Password=Sup3rSecret!",
    "https://internal.api.example.com/v2/charge",
    "AKIA5EXAMPLEKEYID1234",
];

fn forward_encrypt(plain: &str, key: u32) -> Vec<u16> {
    let key_bytes: [u8; 4] = key.to_le_bytes();
    plain
        .encode_utf16()
        .enumerate()
        .map(|(i, u): (usize, u16)| {
            let lo: u8 = (u & 0xFF) as u8 ^ key_bytes[(2 * i) % 4];
            let hi: u8 = (u >> 8) as u8 ^ key_bytes[(2 * i + 1) % 4];
            u16::from(lo) | (u16::from(hi) << 8)
        })
        .collect()
}

fn build_sample() -> Vec<u8> {
    let mut spec: DotnetPeSpec =
        DotnetPeSpec::new(&["SmartAssembly.Attributes", "PoweredByAttribute"]);
    spec.cctor_body = Some(ldc_i4_store_cctor(KEY, 0x0400_0001));
    spec.us_entries = EXPECTED_PLAINTEXTS
        .iter()
        .map(|p: &&str| forward_encrypt(p, KEY))
        .collect();
    build_dotnet_pe(&spec)
}

#[test]
fn cctor_key_drives_byte_exact_string_recovery_against_expected_vector() {
    let image: Vec<u8> = build_sample();
    let recovery: SmartAssemblyStrings = recover_smartassembly_strings(&image).expect("recover");
    assert_eq!(
        recovery.key,
        Some(KEY),
        "the 32-bit XOR key must be folded out of the static .cctor ldc.i4 constant, not guessed"
    );
    let recovered: Vec<String> = recovery.recovered.iter().map(|r| r.text.clone()).collect();
    for expected in EXPECTED_PLAINTEXTS {
        assert!(
            recovered.iter().any(|t: &String| t == expected),
            "expected plaintext {expected:?} must be recovered exactly; got {recovered:?}"
        );
    }
}

#[test]
fn on_disk_us_heap_holds_only_ciphertext_never_plaintext() {
    let image: Vec<u8> = build_sample();
    for expected in EXPECTED_PLAINTEXTS {
        let plain_le: Vec<u8> = expected
            .encode_utf16()
            .flat_map(|u: u16| u.to_le_bytes())
            .collect();
        assert!(
            image
                .windows(plain_le.len())
                .all(|w: &[u8]| w != plain_le.as_slice()),
            "the assembly must not contain the plaintext UTF-16 of {expected:?} on disk"
        );
    }
}

#[test]
fn peel_reports_recovered_strings_and_promotes_strategy() {
    let image: Vec<u8> = build_sample();
    let report: PeelReport = peel_smartassembly(&image).expect("peel");
    assert_eq!(report.strategy, PeelStrategy::EncryptedResourceExtracted);
    assert_eq!(report.recovered_strings.len(), EXPECTED_PLAINTEXTS.len());
}

#[test]
fn wrong_cctor_key_yields_no_false_recovery() {
    let mut spec: DotnetPeSpec = DotnetPeSpec::new(&["SmartAssembly.Attributes"]);
    spec.cctor_body = Some(ldc_i4_store_cctor(KEY ^ 0x00FF_0000, 0x0400_0001));
    spec.us_entries = vec![forward_encrypt(EXPECTED_PLAINTEXTS[0], KEY)];
    let image: Vec<u8> = build_dotnet_pe(&spec);
    let recovery: SmartAssemblyStrings = recover_smartassembly_strings(&image).expect("recover");
    assert!(
        recovery.recovered.is_empty(),
        "a wrong static key must not produce a readable false positive"
    );
}
