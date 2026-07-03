#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::kramer::KramerPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome, Quality};

#[test]
fn kramer_real_hello_world_decodes_to_exact_source() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture("kramer", "edge_hello_world")
    else {
        common::skip_absent_corpus("kramer_real_hello_world_decodes_to_exact_source", "kramer");
        return;
    };
    let det: DetectReport = KramerPass.detect(&fixture);
    assert!(det.matched, "real kramer hello_world not detected: {det:?}");
    let peel: PeelOutcome = KramerPass
        .peel(&fixture)
        .unwrap_or_else(|e| panic!("real kramer hello_world peel: {e:?}"));
    assert_eq!(
        peel.quality,
        Quality::Full,
        "real kramer hello_world must reach Full; diagnostics={:?}",
        peel.diagnostics
    );
    assert_eq!(
        peel.recovered_source, "print('hello world')\n",
        "real kramer _sparkle must decode byte-exact to the original source"
    );
    assert_eq!(
        peel.diagnostics.get("ord_shift").map(String::as_str),
        Some("42"),
        "the per-build ord-shift must be recovered from the real sample, not assumed: {:?}",
        peel.diagnostics
    );
}

const REAL_SLOTS: &[(&str, &str)] = &[
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
fn kramer_real_sparkle_recovers_recognizable_source() {
    let mut tested: usize = 0;
    for (slot, needle) in REAL_SLOTS {
        let Some(fixture): Option<Vec<u8>> = common::load_real_fixture("kramer", slot) else {
            continue;
        };
        tested += 1;
        let peel: PeelOutcome = KramerPass
            .peel(&fixture)
            .unwrap_or_else(|e| panic!("real kramer slot {slot} peel: {e:?}"));
        assert_eq!(
            peel.quality,
            Quality::Full,
            "real kramer slot {slot} must reach Full; diagnostics={:?}",
            peel.diagnostics
        );
        assert!(
            peel.recovered_source.contains(needle),
            "real kramer slot {slot}: recovered source missing {needle:?}; got first 160 bytes: {:?}",
            &peel.recovered_source.chars().take(160).collect::<String>()
        );
    }
    if tested == 0 {
        common::skip_absent_corpus("kramer_real_sparkle_recovers_recognizable_source", "kramer");
        return;
    }
    assert!(
        tested >= 5,
        "expected 5+ real kramer fixtures, got {tested}"
    );
}
