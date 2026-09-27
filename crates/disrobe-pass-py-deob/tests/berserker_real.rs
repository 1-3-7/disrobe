#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::berserker::BerserkerPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, Obfuscator, PeelOutcome, Quality};

const OBF: &str = "berserker";

const SLOTS: &[&str] = &[
    "hello",
    "edge_recursive",
    "edge_class_decorator",
    "edge_async_fn",
    "edge_generator",
    "edge_lambda_in_listcomp",
    "edge_walrus_operator",
    "edge_match_statement",
    "edge_structural_pattern",
    "edge_typing_generic",
];

fn original_source(slot: &str) -> &'static str {
    if slot == "hello" {
        return common::edge_case_source("hello_world");
    }
    common::edge_case_source(slot)
}

#[test]
fn berserker_real_sparkle_fixtures_recover_full_source() {
    for slot in SLOTS {
        let fixture: Vec<u8> = common::require_real_fixture(OBF, slot);
        let detect: DetectReport = BerserkerPass.detect(&fixture);
        assert_eq!(detect.obfuscator, Obfuscator::Berserker);
        assert!(
            detect.matched,
            "berserker slot {slot} not detected: {detect:?}"
        );
        let peel: PeelOutcome = BerserkerPass
            .peel(&fixture)
            .unwrap_or_else(|e| panic!("berserker slot {slot} peel: {e:?}"));
        assert_eq!(
            peel.quality,
            Quality::Full,
            "berserker slot {slot} must fully recover (got {:?}); diagnostics={:?}",
            peel.quality,
            peel.diagnostics
        );
        assert_eq!(
            peel.recovered_source,
            original_source(slot),
            "berserker slot {slot}: the sparkle payload must decode byte-exact to the original"
        );
    }
}

#[test]
fn berserker_real_large_application_fixture_recovers() {
    let fixture: Vec<u8> = common::require_real_fixture(OBF, "application");
    let peel: PeelOutcome = BerserkerPass
        .peel(&fixture)
        .unwrap_or_else(|e| panic!("berserker application peel: {e:?}"));
    assert_eq!(peel.quality, Quality::Full);
    assert!(
        peel.recovered_source.len() > 1000,
        "application fixture should recover a substantial program, got {} bytes",
        peel.recovered_source.len()
    );
    assert!(
        ruff_python_parser::parse(
            &peel.recovered_source,
            ruff_python_parser::ParseOptions::from(ruff_python_parser::Mode::Module)
        )
        .is_ok(),
        "the recovered application must parse as Python; first 300 chars: {:?}",
        peel.recovered_source.chars().take(300).collect::<String>()
    );
    assert!(
        !BerserkerPass
            .detect(peel.recovered_source.as_bytes())
            .matched,
        "the recovered application still carries the berserker wrapper"
    );
}
