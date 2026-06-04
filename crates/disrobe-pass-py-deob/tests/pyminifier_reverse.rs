#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::pyminifier::{PyminifierPass, bake};

/// Self-consistency smoke test: `bake()` is THIS crate's synthetic re-implementation of the
/// pyminifier transform, so this round-trip proves only that `peel()` inverts `bake()`. It is NOT
/// evidence of real-tool recovery accuracy; that claim is gated by the independent committed
/// pyminifier 2.1 fixtures in `pyminifier_real.rs`.
#[test]
fn pyminifier_model_self_consistency_reverse() {
    let original: &str = "def long_function_name(parameter_value):\n    return parameter_value\n";
    let obf: String = bake(original);
    assert!(PyminifierPass.detect(obf.as_bytes()).matched);
    let out = PyminifierPass.peel(obf.as_bytes()).expect("peel");
    assert!(out.recovered_source.contains("def long_function_name"));
}

/// Self-consistency smoke test over the shared synthetic edge-case corpus. Validates the
/// `bake()` -> `peel()` model round-trip only, NOT real-tool recovery (see `pyminifier_real.rs`).
#[test]
fn pyminifier_model_self_consistency_edge_cases() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        PyminifierPass
            .peel(obf)
            .is_ok_and(|o| !o.recovered_source.is_empty())
    });
    assert!(count >= 5);
}
