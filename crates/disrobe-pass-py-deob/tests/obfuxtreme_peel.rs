#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::obfuxtreme::{ObfuXtremePass, bake};

#[test]
fn obfuxtreme_peel_via_sidecar() {
    let original: &str =
        "match x:\n    case 1:\n        print('one')\n    case _:\n        print('?')\n";
    let obf: String = bake(original);
    assert!(ObfuXtremePass.detect(obf.as_bytes()).matched);
    let out = ObfuXtremePass.peel(obf.as_bytes()).expect("peel");
    assert_eq!(out.recovered_source, original);
}

#[test]
fn obfuxtreme_edge_cases() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        ObfuXtremePass
            .peel(obf)
            .is_ok_and(|o| !o.recovered_source.is_empty())
    });
    assert!(count >= 5);
}
