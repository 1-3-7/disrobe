#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::blankobf::{BlankObfPass, bake};

#[test]
fn blankobf_recovers_source() {
    let original: &str = "print('blankobf-target')\n";
    let obf: String = bake(original);
    assert!(BlankObfPass.detect(obf.as_bytes()).matched);
    let out = BlankObfPass.peel(obf.as_bytes()).expect("peel");
    assert_eq!(out.recovered_source, original);
}

#[test]
fn blankobf_edge_cases() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        BlankObfPass
            .peel(obf)
            .is_ok_and(|o| !o.recovered_source.is_empty())
    });
    assert!(count >= 5);
}
