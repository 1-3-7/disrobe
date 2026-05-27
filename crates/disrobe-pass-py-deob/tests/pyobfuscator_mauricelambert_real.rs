#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::py_mauricelambert::PyObfuscatorMauricelambertPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, Obfuscator, PeelOutcome};

const OBF: &str = "pyobfuscator_mauricelambert";

#[test]
fn pyobfuscator_mauricelambert_real_hello_loads_without_panic() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture(OBF, "hello") else {
        panic!("missing real fixture: corpus/python/obfuscators/{OBF}/real_hello.py");
    };
    let detect: DetectReport = PyObfuscatorMauricelambertPass.detect(&fixture);
    assert_eq!(detect.obfuscator, Obfuscator::PyObfuscatorMauricelambert);
    let _peel: disrobe_pass_py_deob::Result<PeelOutcome> =
        PyObfuscatorMauricelambertPass.peel(&fixture);
}

#[test]
fn pyobfuscator_mauricelambert_real_edge_recursive_loads_without_panic() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture(OBF, "edge_recursive") else {
        panic!("missing real fixture");
    };
    let _detect: DetectReport = PyObfuscatorMauricelambertPass.detect(&fixture);
    let _peel: disrobe_pass_py_deob::Result<PeelOutcome> =
        PyObfuscatorMauricelambertPass.peel(&fixture);
}

#[test]
#[ignore = "upstream-pyobfuscator-mauricelambert-incompatible-with-py3.14-ast-unparse-on-modern-fstrings"]
fn pyobfuscator_mauricelambert_real_sample_loads_without_panic() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture(OBF, "sample") else {
        return;
    };
    let _detect: DetectReport = PyObfuscatorMauricelambertPass.detect(&fixture);
    let _peel: disrobe_pass_py_deob::Result<PeelOutcome> =
        PyObfuscatorMauricelambertPass.peel(&fixture);
}

#[test]
fn pyobfuscator_mauricelambert_real_detector_should_match() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture(OBF, "hello") else {
        return;
    };
    let detect: DetectReport = PyObfuscatorMauricelambertPass.detect(&fixture);
    assert!(detect.matched);
}
