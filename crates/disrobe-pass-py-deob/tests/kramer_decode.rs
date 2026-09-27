#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::kramer::KramerPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome, Quality};

#[test]
fn kramer_real_hello_world_decodes_to_exact_source() {
    let fixture: Vec<u8> = common::require_real_fixture("kramer", "edge_hello_world");
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

const REAL_SLOTS: &[(&str, Option<&str>)] = &[
    ("edge_recursive", None),
    ("edge_class_decorator", None),
    ("edge_async_fn", None),
    ("edge_generator", None),
    ("edge_lambda_in_listcomp", None),
    ("edge_walrus_operator", Some("while (n :=")),
    ("edge_match_statement", None),
    ("edge_structural_pattern", None),
    (
        "edge_typing_generic",
        Some("from typing import Generic, TypeVar"),
    ),
];

#[test]
fn kramer_real_sparkle_recovers_recognizable_source() {
    for (slot, unrecorded_needle) in REAL_SLOTS {
        let fixture: Vec<u8> = common::require_real_fixture("kramer", slot);
        let peel: PeelOutcome = KramerPass
            .peel(&fixture)
            .unwrap_or_else(|e| panic!("real kramer slot {slot} peel: {e:?}"));
        assert_eq!(
            peel.quality,
            Quality::Full,
            "real kramer slot {slot} must reach Full; diagnostics={:?}",
            peel.diagnostics
        );
        match unrecorded_needle {
            None => assert_eq!(
                peel.recovered_source,
                common::edge_case_source(slot),
                "real kramer slot {slot} must decode byte-exact to the original"
            ),
            Some(needle) => assert!(
                peel.recovered_source.contains(needle),
                "real kramer slot {slot}: recovered source missing {needle:?}; got first 160 bytes: {:?}",
                &peel.recovered_source.chars().take(160).collect::<String>()
            ),
        }
    }
}
