#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::berserker::BerserkerPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, Obfuscator, PeelOutcome, Quality};

const OBF: &str = "berserker";

/// (slot, substring that MUST appear in the recovered source).
const SLOTS: &[(&str, &str)] = &[
    ("hello", "print('hello world')"),
    ("edge_recursive", "def fact(n):"),
    ("edge_class_decorator", "class Box:"),
    ("edge_async_fn", "async def fetch():"),
    ("edge_generator", "def gen():"),
    ("edge_lambda_in_listcomp", "lambda y: y + 1"),
    ("edge_walrus_operator", "while (n :="),
    ("edge_match_statement", "match s:"),
    ("edge_structural_pattern", "case {'type': t"),
    ("edge_typing_generic", "from typing import Generic, TypeVar"),
];

#[test]
fn berserker_real_sparkle_fixtures_recover_full_source() {
    let mut tested: usize = 0;
    for (slot, needle) in SLOTS {
        let Some(fixture): Option<Vec<u8>> = common::load_real_fixture(OBF, slot) else {
            continue;
        };
        tested += 1;
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
        assert!(
            peel.recovered_source.contains(needle),
            "berserker slot {slot}: recovered source missing {needle:?}; got first 120: {:?}",
            &peel.recovered_source.chars().take(120).collect::<String>()
        );
    }
    if tested == 0 {
        common::skip_absent_corpus("berserker_real_sparkle_fixtures_recover_full_source", OBF);
        return;
    }
    assert!(
        tested >= 10,
        "expected 10+ berserker real fixtures, got {tested}"
    );
}

#[test]
fn berserker_real_large_application_fixture_recovers() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture(OBF, "application") else {
        common::skip_absent_corpus("berserker_real_large_application_fixture_recovers", OBF);
        return;
    };
    let peel: PeelOutcome = BerserkerPass
        .peel(&fixture)
        .unwrap_or_else(|e| panic!("berserker application peel: {e:?}"));
    assert_eq!(peel.quality, Quality::Full);
    assert!(
        peel.recovered_source.len() > 1000,
        "application fixture should recover a substantial program, got {} bytes",
        peel.recovered_source.len()
    );
}
