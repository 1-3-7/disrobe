#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::jawbreaker::{JawbreakerPass, bake};

#[test]
fn jawbreaker_peel_recovers_class() {
    let original: &str = "class Foo:\n    def bar(self):\n        return 42\n";
    let obf: String = bake(original);
    assert!(JawbreakerPass.detect(obf.as_bytes()).matched);
    let out = JawbreakerPass.peel(obf.as_bytes()).expect("peel");
    assert_eq!(out.recovered_source, original);
}

#[test]
fn jawbreaker_edge_cases_full_peel() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        JawbreakerPass
            .peel(obf)
            .is_ok_and(|o| !o.recovered_source.is_empty())
    });
    assert!(count >= 5);
}
