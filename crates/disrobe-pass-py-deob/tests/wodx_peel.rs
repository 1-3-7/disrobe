#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::wodx::{WodxPass, bake};

#[test]
fn wodx_recovers_source() {
    let original: &str = "async def main():\n    return 1\n";
    let obf: String = bake(original);
    assert!(WodxPass.detect(obf.as_bytes()).matched);
    let out = WodxPass.peel(obf.as_bytes()).expect("peel");
    assert_eq!(out.recovered_source, original);
}

#[test]
fn wodx_edge_cases() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        WodxPass
            .peel(obf)
            .is_ok_and(|o| !o.recovered_source.is_empty())
    });
    assert!(count >= 5);
}
