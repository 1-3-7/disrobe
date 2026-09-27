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
    for slot in SLOTS {
        let fixture: Vec<u8> = common::require_real_fixture("blankobf", slot);
        let det: DetectReport = BlankObfPass.detect(&fixture);
        assert!(det.matched, "blankobf slot {slot} not detected: {det:?}");
        let peel: PeelOutcome = BlankObfPass
            .peel(&fixture)
            .unwrap_or_else(|e| panic!("blankobf slot {slot} peel: {e:?}"));
        assert_eq!(
            peel.quality,
            Quality::Full,
            "blankobf slot {slot}: every committed v2 fixture reaches Full through AST eval; \
             diagnostics={:?}",
            peel.diagnostics
        );
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
