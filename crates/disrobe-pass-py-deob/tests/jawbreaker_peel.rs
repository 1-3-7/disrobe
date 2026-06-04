#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::jawbreaker::{JawbreakerPass, bake};

/// Self-consistency smoke test: `bake()` is THIS crate's synthetic re-implementation of the
/// `Jawbreaker` transform, so this round-trip proves only that `peel()` inverts `bake()`. It is NOT
/// evidence of real-tool recovery accuracy; the real `Jawbreaker` artifact is a remote-fetch loader
/// with no embedded source, gated as honest `DetectOnly` in `jawbreaker_real.rs`.
#[test]
fn jawbreaker_model_self_consistency_recovers_class() {
    let original: &str = "class Foo:\n    def bar(self):\n        return 42\n";
    let obf: String = bake(original);
    assert!(JawbreakerPass.detect(obf.as_bytes()).matched);
    let out = JawbreakerPass.peel(obf.as_bytes()).expect("peel");
    assert_eq!(out.recovered_source, original);
}

/// Self-consistency smoke test over the shared synthetic edge-case corpus. Validates the
/// `bake()` -> `peel()` model round-trip only, NOT real-tool recovery (see `jawbreaker_real.rs`).
#[test]
fn jawbreaker_model_self_consistency_edge_cases() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        JawbreakerPass
            .peel(obf)
            .is_ok_and(|o| !o.recovered_source.is_empty())
    });
    assert!(count >= 5);
}
