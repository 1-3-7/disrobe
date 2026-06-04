#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::pyobfuscate_com::{PyobfuscateComPass, bake};

/// Self-consistency smoke test: `bake()` is THIS crate's synthetic re-implementation of the
/// legacy pyobfuscate.com zlib+base64 dropper, so this round-trip proves only that `peel()`
/// inverts `bake()`. It is NOT evidence of real-tool recovery accuracy; the live service pivoted
/// to an XOR/lambda format that no longer matches this pass (documented in `pyobfuscate_com_real.rs`).
#[test]
fn pyobfuscate_com_model_self_consistency_peel() {
    let original: &str = "from math import sqrt\nprint(sqrt(2))\n";
    let obf: String = bake(original);
    assert!(PyobfuscateComPass.detect(obf.as_bytes()).matched);
    let out = PyobfuscateComPass.peel(obf.as_bytes()).expect("peel");
    assert_eq!(out.recovered_source, original);
}

/// Self-consistency smoke test over the shared synthetic edge-case corpus. Validates the
/// `bake()` -> `peel()` model round-trip only, NOT real-tool recovery (see `pyobfuscate_com_real.rs`).
#[test]
fn pyobfuscate_com_model_self_consistency_edge_cases() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        PyobfuscateComPass
            .peel(obf)
            .is_ok_and(|o| !o.recovered_source.is_empty())
    });
    assert!(count >= 5);
}
