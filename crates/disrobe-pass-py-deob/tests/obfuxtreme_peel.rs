#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::obfuxtreme::{ObfuXtremePass, bake};

/// Self-consistency smoke test: `bake()` is THIS crate's synthetic re-implementation of the
/// `ObfuXtreme` transform (with a recovery sidecar), so this round-trip proves only that `peel()`
/// inverts `bake()`. It is NOT evidence of real-tool recovery accuracy; the real `ObfuXtreme` v4
/// artifact is AES+zlib+marshal, gated as honest `Partial` in `obfuxtreme_real.rs`.
#[test]
fn obfuxtreme_model_self_consistency_via_sidecar() {
    let original: &str =
        "match x:\n    case 1:\n        print('one')\n    case _:\n        print('?')\n";
    let obf: String = bake(original);
    assert!(ObfuXtremePass.detect(obf.as_bytes()).matched);
    let out = ObfuXtremePass.peel(obf.as_bytes()).expect("peel");
    assert_eq!(out.recovered_source, original);
}

/// Self-consistency smoke test over the shared synthetic edge-case corpus. Validates the
/// `bake()` -> `peel()` model round-trip only, NOT real-tool recovery (see `obfuxtreme_real.rs`).
#[test]
fn obfuxtreme_model_self_consistency_edge_cases() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        ObfuXtremePass
            .peel(obf)
            .is_ok_and(|o| !o.recovered_source.is_empty())
    });
    assert!(count >= 5);
}
