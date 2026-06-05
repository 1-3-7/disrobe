#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::kramer::KramerPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome, Quality};

/// (slot, substring that MUST appear in the recovered source).
const SLOTS: &[(&str, &str)] = &[
    ("edge_hello_world", "print('hello world')"),
    ("edge_recursive", "def fact(n):"),
    ("edge_class_decorator", "class Box:"),
    ("edge_async_fn", "async def fetch():"),
    ("edge_generator", "def gen():"),
    ("edge_lambda_in_listcomp", "lambda y: y + 1"),
    ("edge_walrus_operator", "while (n :="),
    ("edge_match_statement", "match s:"),
    ("edge_structural_pattern", "case {'type': t"),
    ("edge_typing_generic", "from typing import Generic, TypeVar"),
    ("edge_cases_3_8", "Python 3.8+ edge cases"),
];

#[test]
fn kramer_real_pyc_fixtures_recover_full_source() {
    let mut tested: usize = 0;
    for (slot, needle) in SLOTS {
        let Some(fixture): Option<Vec<u8>> = common::load_real_fixture("kramer", slot) else {
            continue;
        };
        tested += 1;
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
        assert!(
            peel.recovered_source.contains(needle),
            "kramer slot {slot}: recovered source missing {needle:?}; got first 120 bytes: {:?}",
            &peel.recovered_source.chars().take(120).collect::<String>()
        );
    }
    if tested == 0 {
        common::skip_absent_corpus("kramer_real_pyc_fixtures_recover_full_source", "kramer");
        return;
    }
    assert!(
        tested >= 10,
        "expected 10+ kramer real fixtures, got {tested}"
    );
}
