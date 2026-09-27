#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::plusobf::PlusObfPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome, Quality};

const EDGE_SLOTS: &[&str] = &[
    "edge_hello_world",
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

fn peel_full(slot: &str) -> PeelOutcome {
    let fixture: Vec<u8> = common::require_real_fixture("plusobf", slot);
    let det: DetectReport = PlusObfPass.detect(&fixture);
    assert!(det.matched, "plusobf slot {slot} not detected: {det:?}");
    let peel: PeelOutcome = PlusObfPass
        .peel(&fixture)
        .unwrap_or_else(|e| panic!("plusobf slot {slot} peel: {e:?}"));
    assert_eq!(
        peel.quality,
        Quality::Full,
        "plusobf slot {slot} should fully recover: {:?}",
        peel.quality
    );
    peel
}

#[test]
fn plusobf_real_fixtures_detect_and_peel() {
    for slot in EDGE_SLOTS {
        assert_eq!(
            peel_full(slot).recovered_source,
            common::edge_case_source(slot),
            "plusobf slot {slot}: chr(len) decoding must reproduce the original byte-exact"
        );
    }
    let plus: PeelOutcome = peel_full("edge_cases_3_8_plus");
    let hash: PeelOutcome = peel_full("edge_cases_3_8_hash");
    assert!(
        plus.recovered_source.contains("Python 3.8+ edge cases"),
        "plusobf edge_cases_3_8_plus: recovered source missing its docstring; got first 160: {:?}",
        &plus.recovered_source.chars().take(160).collect::<String>()
    );
    assert_eq!(
        plus.recovered_source, hash.recovered_source,
        "the + and # plusobf encodings of one module must decode to the same source"
    );
}
