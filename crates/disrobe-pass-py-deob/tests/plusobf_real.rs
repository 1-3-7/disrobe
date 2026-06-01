#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::plusobf::PlusObfPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome, Quality};

const SLOTS: &[&str] = &[
    "edge_cases_3_8_plus",
    "edge_cases_3_8_hash",
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

#[test]
fn plusobf_real_fixtures_detect_and_peel() {
    let mut tested: usize = 0;
    for slot in SLOTS {
        let Some(fixture): Option<Vec<u8>> = common::load_real_fixture("plusobf", slot) else {
            continue;
        };
        tested += 1;
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
        assert!(
            !peel.recovered_source.is_empty(),
            "plusobf slot {slot} produced empty recovered source"
        );
    }
    if tested == 0 {
        common::skip_absent_corpus("plusobf_real_fixtures_detect_and_peel", "plusobf");
    }
}
