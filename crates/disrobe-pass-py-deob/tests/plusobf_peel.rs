#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::plusobf::{PlusObfPass, bake};

#[test]
fn plusobf_model_self_consistency_recovers_source() {
    let original: &str = "x = [i*i for i in range(5)]\nprint(x)\n";
    let obf: String = bake(original);
    assert!(PlusObfPass.detect(obf.as_bytes()).matched);
    let out = PlusObfPass.peel(obf.as_bytes()).expect("peel");
    assert_eq!(out.recovered_source, original);
}

#[test]
fn plusobf_model_self_consistency_edge_cases() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        PlusObfPass
            .peel(obf)
            .is_ok_and(|o| !o.recovered_source.is_empty())
    });
    assert!(count >= 5);
}
