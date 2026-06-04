#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::py_mauricelambert::{PyObfuscatorMauricelambertPass, bake};

/// Self-consistency smoke test: `bake()` is THIS crate's synthetic re-implementation of the
/// `PyObfuscator` (`Mauricelambert`) transform, so this round-trip proves only that `peel()`
/// inverts `bake()`. It is NOT evidence of real-tool recovery accuracy; the real artifact is a
/// gzip+`chr()`-arithmetic layering gated as honest `Partial` in
/// `pyobfuscator_mauricelambert_real.rs`.
#[test]
fn pyobfuscator_mauricelambert_model_self_consistency_peel() {
    let original: &str = "def g(): yield from range(3)\n";
    let obf: String = bake(original);
    assert!(
        PyObfuscatorMauricelambertPass
            .detect(obf.as_bytes())
            .matched
    );
    let out = PyObfuscatorMauricelambertPass
        .peel(obf.as_bytes())
        .expect("peel");
    assert_eq!(out.recovered_source, original);
}

/// Self-consistency smoke test over the shared synthetic edge-case corpus. Validates the
/// `bake()` -> `peel()` model round-trip only, NOT real-tool recovery (see
/// `pyobfuscator_mauricelambert_real.rs`).
#[test]
fn pyobfuscator_mauricelambert_model_self_consistency_edge_cases() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        PyObfuscatorMauricelambertPass
            .peel(obf)
            .is_ok_and(|o| !o.recovered_source.is_empty())
    });
    assert!(count >= 5);
}
