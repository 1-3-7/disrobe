#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::plusobf::PlusObfPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome, Quality};

const SLOTS: &[(&str, &str)] = &[
    ("edge_cases_3_8_plus", "Python 3.8+ edge cases"),
    ("edge_cases_3_8_hash", "Python 3.8+ edge cases"),
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
];

#[test]
fn plusobf_real_fixtures_detect_and_peel() {
    let mut tested: usize = 0;
    for (slot, needle) in SLOTS {
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
            peel.recovered_source.contains(needle),
            "plusobf slot {slot}: recovered source missing {needle:?}; got first 160: {:?}",
            &peel.recovered_source.chars().take(160).collect::<String>()
        );
    }
    if tested == 0 {
        common::skip_absent_corpus("plusobf_real_fixtures_detect_and_peel", "plusobf");
    }
}
