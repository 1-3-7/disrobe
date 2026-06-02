#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::python_obfuscator_pypi::{PythonObfuscatorPypiPass, bake};

#[test]
fn python_obfuscator_pypi_peel() {
    let original: &str = "def alpha(x):\n    return x\n\ndef beta(y):\n    return alpha(y) + 1\n";
    let obf: String = bake(original);
    assert!(PythonObfuscatorPypiPass.detect(obf.as_bytes()).matched);
    let out = PythonObfuscatorPypiPass.peel(obf.as_bytes()).expect("peel");
    assert!(out.recovered_source.contains("def alpha"));
    assert!(out.recovered_source.contains("def beta"));
    assert!(out.recovered_source.contains("alpha(y)"));
}

#[test]
fn python_obfuscator_pypi_edge_cases() {
    let count: usize = common::run_edge_cases(bake, |obf: &[u8]| {
        PythonObfuscatorPypiPass
            .peel(obf)
            .is_ok_and(|o| !o.recovered_source.is_empty())
    });
    assert!(count >= 5);
}
