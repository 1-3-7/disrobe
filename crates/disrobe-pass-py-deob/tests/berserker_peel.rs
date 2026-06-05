#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::berserker::{BerserkerPass, bake};

/// Proves `peel()` inverts the synthetic `bake()` model; not real-tool recovery evidence.
#[test]
fn berserker_model_self_consistency_roundtrips_source() {
    let original: &str = "def add(a: int, b: int) -> int:\n    return a + b\n";
    let obf: String = bake(original);
    assert!(BerserkerPass.detect(obf.as_bytes()).matched);
    let out = BerserkerPass.peel(obf.as_bytes()).expect("peel");
    assert_eq!(out.recovered_source, original);
}

/// Validates the `bake()` -> `peel()` model round-trip over the shared edge-case corpus.
#[test]
fn berserker_model_self_consistency_edge_cases() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        BerserkerPass
            .peel(obf)
            .is_ok_and(|o| !o.recovered_source.is_empty())
    });
    assert!(count >= 5);
}
