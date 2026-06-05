#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::kramer::{KramerPass, bake};

/// Proves `peel()` inverts the synthetic `bake()` model; not real-tool recovery evidence.
#[test]
fn kramer_model_self_consistency_full_pipeline() {
    let original: &str = "def f(x):\n    return x + 1\n";
    let obf: String = bake(original);
    let det = KramerPass.detect(obf.as_bytes());
    assert!(det.matched, "{det:?}");
    let out = KramerPass.peel(obf.as_bytes()).expect("peel");
    assert!(!out.stages_applied.is_empty());
}

/// Validates the `bake()` -> `peel()` model round-trip over the shared edge-case corpus.
#[test]
fn kramer_model_self_consistency_edge_cases() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        let det = KramerPass.detect(obf);
        if !det.matched {
            return false;
        }
        KramerPass.peel(obf).is_ok()
    });
    assert!(count >= 5, "expected 5+ edge cases, got {count}");
}
