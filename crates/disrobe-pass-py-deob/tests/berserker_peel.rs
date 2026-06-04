#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::berserker::{BerserkerPass, bake};

/// Self-consistency smoke test: `bake()` is THIS crate's synthetic re-implementation of the
/// `Berserker` transform, so this round-trip proves only that `peel()` inverts `bake()`. It is NOT
/// evidence of real-tool recovery accuracy; that claim is gated by the independent committed
/// fixtures in `berserker_real.rs`.
#[test]
fn berserker_model_self_consistency_roundtrips_source() {
    let original: &str = "def add(a: int, b: int) -> int:\n    return a + b\n";
    let obf: String = bake(original);
    assert!(BerserkerPass.detect(obf.as_bytes()).matched);
    let out = BerserkerPass.peel(obf.as_bytes()).expect("peel");
    assert_eq!(out.recovered_source, original);
}

/// Self-consistency smoke test over the shared synthetic edge-case corpus. Validates the
/// `bake()` -> `peel()` model round-trip only, NOT real-tool recovery (see `berserker_real.rs`).
#[test]
fn berserker_model_self_consistency_edge_cases() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        BerserkerPass
            .peel(obf)
            .is_ok_and(|o| !o.recovered_source.is_empty())
    });
    assert!(count >= 5);
}
