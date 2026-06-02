#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::online_family::{OnlineFamilyPass, bake};

#[test]
fn online_family_detect_and_peel() {
    let original: &str = "x: int = 1\ny: int = 2\nprint(x + y)\n";
    let obf: String = bake(original);
    assert!(OnlineFamilyPass.detect(obf.as_bytes()).matched);
    let out = OnlineFamilyPass.peel(obf.as_bytes()).expect("peel");
    assert_eq!(out.recovered_source, original);
}

#[test]
fn online_family_edge_cases() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        OnlineFamilyPass
            .peel(obf)
            .is_ok_and(|o| !o.recovered_source.is_empty())
    });
    assert!(count >= 5);
}
