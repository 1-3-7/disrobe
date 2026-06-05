#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::jawbreaker::{JawbreakerPass, bake};

/// Proves `peel()` inverts the synthetic `bake()` model; not real-tool recovery evidence.
#[test]
fn jawbreaker_model_self_consistency_recovers_class() {
    let original: &str = "class Foo:\n    def bar(self):\n        return 42\n";
    let obf: String = bake(original);
    assert!(JawbreakerPass.detect(obf.as_bytes()).matched);
    let out = JawbreakerPass.peel(obf.as_bytes()).expect("peel");
    assert_eq!(out.recovered_source, original);
}

/// Validates the `bake()` -> `peel()` model round-trip over the shared edge-case corpus.
#[test]
fn jawbreaker_model_self_consistency_edge_cases() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        JawbreakerPass
            .peel(obf)
            .is_ok_and(|o| !o.recovered_source.is_empty())
    });
    assert!(count >= 5);
}
