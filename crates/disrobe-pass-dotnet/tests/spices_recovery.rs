#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation
)]

mod common;

use disrobe_pass_dotnet::peel::spices_net::peel_spices_net;
use disrobe_pass_dotnet::peel::spices_strings::{
    SpicesRecovery, recover_spices, unmap_homoglyph_name,
};
use disrobe_pass_dotnet::peel::{PeelReport, PeelStrategy};

use crate::common::protector_pe::{DotnetPeSpec, build_dotnet_pe, ldc_i4_store_cctor};

const SHIFT: u16 = 17;

const EXPECTED: &[&str] = &[
    "config/connection.json",
    "HKEY_LOCAL_MACHINE\\Software\\Spices",
];

fn forward_rot(plain: &str, shift: u16) -> Vec<u16> {
    plain
        .encode_utf16()
        .map(|u: u16| u.wrapping_add(shift))
        .collect()
}

fn build_sample() -> Vec<u8> {
    let mut spec: DotnetPeSpec = DotnetPeSpec::new(&["9rays.Net", "Spices.Net"]);
    spec.cctor_body = Some(ldc_i4_store_cctor(u32::from(SHIFT), 0x0400_0001));
    spec.us_entries = EXPECTED
        .iter()
        .map(|p: &&str| forward_rot(p, SHIFT))
        .collect();
    build_dotnet_pe(&spec)
}

#[test]
fn rot_n_recovery_grades_against_expected_vector() {
    let image: Vec<u8> = build_sample();
    let recovery: SpicesRecovery = recover_spices(&image).expect("recover");
    assert_eq!(
        recovery.rot_shift,
        Some(u32::from(SHIFT)),
        "the ROT-N shift must be recovered from the static ldc.i4 constant, not brute-forced"
    );
    let texts: Vec<String> = recovery
        .recovered_strings
        .iter()
        .map(|r| r.text.clone())
        .collect();
    for expected in EXPECTED {
        assert!(
            texts.iter().any(|t: &String| t == expected),
            "expected {expected:?} must be recovered; got {texts:?}"
        );
    }
}

#[test]
fn peel_promotes_strategy_on_rot_recovery() {
    let image: Vec<u8> = build_sample();
    let report: PeelReport = peel_spices_net(&image).expect("peel");
    assert_eq!(report.strategy, PeelStrategy::EncryptedResourceExtracted);
    let texts: Vec<&str> = report
        .recovered_strings
        .iter()
        .map(|r| r.text.as_str())
        .collect();
    for expected in EXPECTED {
        assert!(
            texts.iter().any(|t: &&str| t == expected),
            "the promoted peel must surface the recovered string {expected:?}; got {texts:?}"
        );
    }
    assert_eq!(
        report.recovered_strings.len(),
        EXPECTED.len(),
        "the peel must recover exactly the ROT-N decoded strings, no more and no fewer"
    );
}

#[test]
fn homoglyph_table_unmaps_cyrillic_lookalikes() {
    assert_eq!(
        unmap_homoglyph_name("\u{0421}\u{043E}nfig").as_deref(),
        Some("Config")
    );
    assert_eq!(unmap_homoglyph_name("RealAsciiName"), None);
}
