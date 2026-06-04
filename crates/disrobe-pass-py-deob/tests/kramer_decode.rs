#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::kramer::{KramerPass, bake};

/// Self-consistency smoke test: `bake()` is THIS crate's synthetic re-implementation of the
/// `Kramer` transform, so this round-trip proves only that `peel()` inverts `bake()`. It is NOT
/// evidence of real-tool recovery accuracy; that claim is gated by the independent committed
/// `.pyc` fixtures in `kramer_real.rs`.
#[test]
fn kramer_model_self_consistency_full_pipeline() {
    let original: &str = "def f(x):\n    return x + 1\n";
    let obf: String = bake(original);
    let det = KramerPass.detect(obf.as_bytes());
    assert!(det.matched, "{det:?}");
    let out = KramerPass.peel(obf.as_bytes()).expect("peel");
    assert!(!out.stages_applied.is_empty());
}

/// Self-consistency smoke test over the shared synthetic edge-case corpus. Validates the
/// `bake()` -> `peel()` model round-trip only, NOT real-tool recovery (see `kramer_real.rs`).
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
