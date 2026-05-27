#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::manglify::ManglifyPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome, Quality};

const SLOTS: &[&str] = &[
    "edge_cases_3_8",
    "edge_hello_world",
    "edge_async_fn",
    "edge_lambda_in_listcomp",
    "edge_typing_generic",
    "edge_walrus_operator",
];

#[test]
fn manglify_real_fixtures_detect_and_peel() {
    let mut tested: usize = 0;
    let mut full_count: usize = 0;
    for slot in SLOTS {
        let Some(fixture): Option<Vec<u8>> = common::load_real_fixture("manglify", slot) else {
            continue;
        };
        tested += 1;
        let det: DetectReport = ManglifyPass.detect(&fixture);
        assert!(det.matched, "manglify slot {slot} not detected: {det:?}");
        let peel: PeelOutcome = ManglifyPass
            .peel(&fixture)
            .unwrap_or_else(|e| panic!("manglify slot {slot} peel: {e:?}"));
        if matches!(peel.quality, Quality::Full) {
            full_count += 1;
        }
    }
    assert!(tested > 0, "no manglify real fixtures found");
    assert!(
        full_count >= 1,
        "expected at least one manglify fixture to upgrade to Quality::Full via AST eval, got {full_count}"
    );
}
