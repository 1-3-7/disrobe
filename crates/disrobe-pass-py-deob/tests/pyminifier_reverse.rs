#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::pyminifier::{PyminifierPass, bake};

#[test]
fn pyminifier_reverse() {
    let original: &str = "def long_function_name(parameter_value):\n    return parameter_value\n";
    let obf: String = bake(original);
    assert!(PyminifierPass.detect(obf.as_bytes()).matched);
    let out = PyminifierPass.peel(obf.as_bytes()).expect("peel");
    assert!(out.recovered_source.contains("def long_function_name"));
}

#[test]
fn pyminifier_edge_cases() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        PyminifierPass
            .peel(obf)
            .is_ok_and(|o| !o.recovered_source.is_empty())
    });
    assert!(count >= 5);
}
