#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::plusobf::{PlusObfPass, bake};

/// Self-consistency smoke test: `bake()` is THIS crate's synthetic re-implementation of the
/// `PlusObf` transform, so this round-trip proves only that `peel()` inverts `bake()`. It is NOT
/// evidence of real-tool recovery accuracy; that claim is gated by the independent committed
/// fixtures in `plusobf_real.rs`.
#[test]
fn plusobf_model_self_consistency_recovers_source() {
    let original: &str = "x = [i*i for i in range(5)]\nprint(x)\n";
    let obf: String = bake(original);
    assert!(PlusObfPass.detect(obf.as_bytes()).matched);
    let out = PlusObfPass.peel(obf.as_bytes()).expect("peel");
    assert_eq!(out.recovered_source, original);
}

/// Self-consistency smoke test over the shared synthetic edge-case corpus. Validates the
/// `bake()` -> `peel()` model round-trip only, NOT real-tool recovery (see `plusobf_real.rs`).
#[test]
fn plusobf_model_self_consistency_edge_cases() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        PlusObfPass
            .peel(obf)
            .is_ok_and(|o| !o.recovered_source.is_empty())
    });
    assert!(count >= 5);
}
