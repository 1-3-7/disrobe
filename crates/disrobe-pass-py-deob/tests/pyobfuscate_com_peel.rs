#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::pyobfuscate_com::{PyobfuscateComPass, bake};

/// Proves `peel()` inverts the synthetic `bake()` model; not real-tool recovery evidence.
#[test]
fn pyobfuscate_com_model_self_consistency_peel() {
    let original: &str = "from math import sqrt\nprint(sqrt(2))\n";
    let obf: String = bake(original);
    assert!(PyobfuscateComPass.detect(obf.as_bytes()).matched);
    let out = PyobfuscateComPass.peel(obf.as_bytes()).expect("peel");
    assert_eq!(out.recovered_source, original);
}

/// Validates the `bake()` -> `peel()` model round-trip over the shared edge-case corpus.
#[test]
fn pyobfuscate_com_model_self_consistency_edge_cases() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        PyobfuscateComPass
            .peel(obf)
            .is_ok_and(|o| !o.recovered_source.is_empty())
    });
    assert!(count >= 5);
}
