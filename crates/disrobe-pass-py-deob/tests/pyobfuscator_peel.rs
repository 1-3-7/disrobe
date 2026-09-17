#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::py_mauricelambert::{PyObfuscatorMauricelambertPass, bake};

#[test]
fn pyobfuscator_mauricelambert_model_self_consistency_peel() {
    let original: &str = "def g(): yield from range(3)\n";
    let obf: String = bake(original);
    assert!(
        PyObfuscatorMauricelambertPass
            .detect(obf.as_bytes())
            .matched
    );
    let out = PyObfuscatorMauricelambertPass
        .peel(obf.as_bytes())
        .expect("peel");
    assert_eq!(out.recovered_source, original);
}

#[test]
fn pyobfuscator_mauricelambert_model_self_consistency_edge_cases() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        PyObfuscatorMauricelambertPass
            .peel(obf)
            .is_ok_and(|o| !o.recovered_source.is_empty())
    });
    assert!(count >= 5);
}
