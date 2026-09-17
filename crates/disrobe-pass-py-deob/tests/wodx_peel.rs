#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::wodx::{WodxPass, bake};

#[test]
fn wodx_model_self_consistency_recovers_source() {
    let original: &str = "async def main():\n    return 1\n";
    let obf: String = bake(original);
    assert!(WodxPass.detect(obf.as_bytes()).matched);
    let out = WodxPass.peel(obf.as_bytes()).expect("peel");
    assert_eq!(out.recovered_source, original);
}

#[test]
fn wodx_model_self_consistency_edge_cases() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        WodxPass
            .peel(obf)
            .is_ok_and(|o| !o.recovered_source.is_empty())
    });
    assert!(count >= 5);
}

#[test]
fn wodx_real_corpus_sourcing_blocked() {
    let real_fixture: Option<Vec<u8>> = common::load_real_fixture("wodx", "hello");
    assert!(
        real_fixture.is_none(),
        "an independent WodX real fixture now exists; remove this sourcing-blocked marker and un-ignore the gating real test in wodx_real.rs"
    );
}
