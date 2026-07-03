#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::oxyry::{OxyryPass, bake};

#[test]
fn oxyry_model_self_consistency_unminify_via_hints() {
    let original: &str =
        "def compute(value):\n    return value * 3\n\ndef triple(x):\n    return compute(x)\n";
    let obf: String = bake(original);
    assert!(OxyryPass.detect(obf.as_bytes()).matched);
    let out = OxyryPass.peel(obf.as_bytes()).expect("peel");
    assert!(out.recovered_source.contains("def compute"));
    assert!(out.recovered_source.contains("def triple"));
}

#[test]
fn oxyry_model_self_consistency_edge_cases() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        OxyryPass
            .peel(obf)
            .is_ok_and(|o| !o.recovered_source.is_empty())
    });
    assert!(count >= 5);
}

#[test]
fn oxyry_real_corpus_sourcing_blocked() {
    let real_fixture: Option<Vec<u8>> = common::load_real_fixture("oxyry", "hello");
    assert!(
        real_fixture.is_none(),
        "an independent Oxyry real fixture now exists; remove this sourcing-blocked marker and un-ignore the gating real test in oxyry_real.rs"
    );
}
