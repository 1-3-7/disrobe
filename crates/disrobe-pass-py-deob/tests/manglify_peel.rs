#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::manglify::{ManglifyPass, bake};

#[test]
fn manglify_model_self_consistency_peel() {
    let original: &str =
        "def calculate(x):\n    return x * 2\n\ndef double(y):\n    return calculate(y)\n";
    let obf: String = bake(original);
    assert!(ManglifyPass.detect(obf.as_bytes()).matched);
    let out = ManglifyPass.peel(obf.as_bytes()).expect("peel");
    assert!(out.recovered_source.contains("def calculate"));
    assert!(out.recovered_source.contains("def double"));
}

#[test]
fn manglify_model_self_consistency_edge_cases() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        ManglifyPass
            .peel(obf)
            .is_ok_and(|o| !o.recovered_source.is_empty())
    });
    assert!(count >= 5);
}
