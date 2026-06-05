#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::blankobf::BlankObfPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome, Quality};

const SLOTS: &[&str] = &[
    "edge_cases_3_8_r1",
    "edge_cases_3_8_r1_imports",
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
fn blankobf_real_fixtures_detect_and_peel() {
    let mut tested: usize = 0;
    let mut full_count: usize = 0;
    for slot in SLOTS {
        let Some(fixture): Option<Vec<u8>> = common::load_real_fixture("blankobf", slot) else {
            continue;
        };
        tested += 1;
        let det: DetectReport = BlankObfPass.detect(&fixture);
        assert!(det.matched, "blankobf slot {slot} not detected: {det:?}");
        let peel: PeelOutcome = BlankObfPass
            .peel(&fixture)
            .unwrap_or_else(|e| panic!("blankobf slot {slot} peel: {e:?}"));
        assert!(
            matches!(peel.quality, Quality::Full | Quality::Partial),
            "blankobf slot {slot} unexpected quality: {:?}",
            peel.quality
        );
        if matches!(peel.quality, Quality::Full) {
            full_count += 1;
            let original: &str = std::str::from_utf8(&fixture).unwrap_or("");
            let folded: usize = peel
                .diagnostics
                .get("ast_exprs_folded")
                .and_then(|v: &String| v.parse::<usize>().ok())
                .unwrap_or(0);
            assert!(
                folded > 0,
                "blankobf slot {slot}: Quality::Full must reflect real AST folding, got ast_exprs_folded={folded}; diagnostics={:?}",
                peel.diagnostics
            );
            assert_ne!(
                peel.recovered_source, original,
                "blankobf slot {slot}: Quality::Full claims recovery but output is identical to the obfuscated input"
            );
        }
    }
    if tested == 0 {
        common::skip_absent_corpus("blankobf_real_fixtures_detect_and_peel", "blankobf");
        return;
    }
    assert!(
        full_count >= 1,
        "expected at least one blankobf fixture to upgrade to Quality::Full via AST eval, got {full_count}"
    );
}
