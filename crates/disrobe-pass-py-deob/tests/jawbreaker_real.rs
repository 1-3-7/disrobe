#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::jawbreaker::JawbreakerPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome};

const SLOTS: &[&str] = &[
    "edge_cases_3_8",
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
fn jawbreaker_real_fixtures_detect_and_peel() {
    let mut tested: usize = 0;
    for slot in SLOTS {
        let Some(fixture): Option<Vec<u8>> = common::load_real_fixture("jawbreaker", slot) else {
            continue;
        };
        tested += 1;
        let det: DetectReport = JawbreakerPass.detect(&fixture);
        assert!(det.matched, "jawbreaker slot {slot} not detected: {det:?}");
        let peel: PeelOutcome = JawbreakerPass
            .peel(&fixture)
            .unwrap_or_else(|e| panic!("jawbreaker slot {slot} peel: {e:?}"));
        let _ = peel.quality;
    }
    assert!(tested > 0, "no jawbreaker real fixtures found");
}
