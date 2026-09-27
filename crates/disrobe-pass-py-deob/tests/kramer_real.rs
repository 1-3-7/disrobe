#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::kramer::KramerPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome, Quality};

const EXACT_SLOTS: &[&str] = &[
    "edge_hello_world",
    "edge_recursive",
    "edge_class_decorator",
    "edge_async_fn",
    "edge_generator",
    "edge_lambda_in_listcomp",
    "edge_match_statement",
    "edge_structural_pattern",
];

const UNRECORDED_ORIGINAL_SLOTS: &[(&str, &str)] = &[
    ("edge_walrus_operator", "while (n :="),
    ("edge_typing_generic", "from typing import Generic, TypeVar"),
    ("edge_cases_3_8", "Python 3.8+ edge cases"),
];

fn peel_full(slot: &str) -> PeelOutcome {
    let fixture: Vec<u8> = common::require_real_fixture("kramer", slot);
    let det: DetectReport = KramerPass.detect(&fixture);
    assert!(det.matched, "kramer slot {slot} not detected: {det:?}");
    let peel: PeelOutcome = KramerPass
        .peel(&fixture)
        .unwrap_or_else(|e| panic!("kramer slot {slot} peel: {e:?}"));
    assert_eq!(
        peel.quality,
        Quality::Full,
        "kramer slot {slot} must fully recover (got {:?}); diagnostics={:?}",
        peel.quality,
        peel.diagnostics
    );
    peel
}

#[test]
fn kramer_real_fixtures_recover_full_source() {
    for slot in EXACT_SLOTS {
        let peel: PeelOutcome = peel_full(slot);
        assert_eq!(
            peel.recovered_source,
            common::edge_case_source(slot),
            "kramer slot {slot}: the payload must decode byte-exact to the original"
        );
    }
    for (slot, needle) in UNRECORDED_ORIGINAL_SLOTS {
        let peel: PeelOutcome = peel_full(slot);
        assert!(
            peel.recovered_source.contains(needle),
            "kramer slot {slot}: recovered source missing {needle:?}; got first 120 bytes: {:?}",
            &peel.recovered_source.chars().take(120).collect::<String>()
        );
    }
}
