#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::online_family::{OnlineFamilyPass, bake};

/// Self-consistency smoke test: `bake()` is THIS crate's synthetic re-implementation of the
/// online-family (pyobfuscator.com) zlib+base64+reverse pipeline, so this round-trip proves only
/// that `peel()` inverts `bake()`. It is NOT evidence of real-tool recovery accuracy; the
/// independent committed captures are exercised by the detector in `online_family_real.rs`.
#[test]
fn online_family_model_self_consistency_detect_and_peel() {
    let original: &str = "x: int = 1\ny: int = 2\nprint(x + y)\n";
    let obf: String = bake(original);
    assert!(OnlineFamilyPass.detect(obf.as_bytes()).matched);
    let out = OnlineFamilyPass.peel(obf.as_bytes()).expect("peel");
    assert_eq!(out.recovered_source, original);
}

/// Self-consistency smoke test over the shared synthetic edge-case corpus. Validates the
/// `bake()` -> `peel()` model round-trip only, NOT real-tool recovery (see `online_family_real.rs`).
#[test]
fn online_family_model_self_consistency_edge_cases() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        OnlineFamilyPass
            .peel(obf)
            .is_ok_and(|o| !o.recovered_source.is_empty())
    });
    assert!(count >= 5);
}
