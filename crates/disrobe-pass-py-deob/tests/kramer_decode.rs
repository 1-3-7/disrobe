#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::kramer::{KramerPass, bake};

#[test]
fn kramer_decode_full_pipeline() {
    let original: &str = "def f(x):\n    return x + 1\n";
    let obf: String = bake(original);
    let det = KramerPass.detect(obf.as_bytes());
    assert!(det.matched, "{det:?}");
    let out = KramerPass.peel(obf.as_bytes()).expect("peel");
    assert!(!out.stages_applied.is_empty());
}

#[test]
fn kramer_edge_cases_all_decode() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        let det = KramerPass.detect(obf);
        if !det.matched {
            return false;
        }
        KramerPass.peel(obf).is_ok()
    });
    assert!(count >= 5, "expected 5+ edge cases, got {count}");
}
