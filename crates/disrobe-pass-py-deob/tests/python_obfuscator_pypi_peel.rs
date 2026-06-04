#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::python_obfuscator_pypi::{PythonObfuscatorPypiPass, bake};

/// Self-consistency smoke test: `bake()` is THIS crate's synthetic re-implementation of the
/// `python-obfuscator` (`PyPI`) transform, so this round-trip proves only that `peel()` inverts
/// `bake()`. It is NOT evidence of real-tool recovery accuracy; that claim is gated by the
/// independent committed fixtures in `python_obfuscator_pypi_real.rs`.
#[test]
fn python_obfuscator_pypi_model_self_consistency_peel() {
    let original: &str = "def alpha(x):\n    return x\n\ndef beta(y):\n    return alpha(y) + 1\n";
    let obf: String = bake(original);
    assert!(PythonObfuscatorPypiPass.detect(obf.as_bytes()).matched);
    let out = PythonObfuscatorPypiPass.peel(obf.as_bytes()).expect("peel");
    assert!(out.recovered_source.contains("def alpha"));
    assert!(out.recovered_source.contains("def beta"));
    assert!(out.recovered_source.contains("alpha(y)"));
}

/// Self-consistency smoke test over the shared synthetic edge-case corpus. Validates the
/// `bake()` -> `peel()` model round-trip only, NOT real-tool recovery (see
/// `python_obfuscator_pypi_real.rs`).
#[test]
fn python_obfuscator_pypi_model_self_consistency_edge_cases() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        PythonObfuscatorPypiPass
            .peel(obf)
            .is_ok_and(|o| !o.recovered_source.is_empty())
    });
    assert!(count >= 5);
}
