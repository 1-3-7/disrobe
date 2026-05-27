#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::python_obfuscator_pypi::PythonObfuscatorPypiPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, Obfuscator, PeelOutcome};

const OBF: &str = "python_obfuscator_pypi";

#[test]
fn python_obfuscator_pypi_real_hello_loads_and_contains_hello_world() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture(OBF, "hello") else {
        panic!("missing real fixture: corpus/python/obfuscators/{OBF}/real_hello.py");
    };
    let text: &str = std::str::from_utf8(&fixture).expect("utf8");
    assert!(
        text.contains("68656c6c6f20776f726c64"),
        "real fixture should embed hello world hex literal"
    );
    let detect: DetectReport = PythonObfuscatorPypiPass.detect(&fixture);
    assert_eq!(detect.obfuscator, Obfuscator::PythonObfuscatorPypi);
    let _peel: disrobe_pass_py_deob::Result<PeelOutcome> = PythonObfuscatorPypiPass.peel(&fixture);
}

#[test]
fn python_obfuscator_pypi_real_sample_loads_without_panic() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture(OBF, "sample") else {
        panic!("missing real fixture");
    };
    let _detect: DetectReport = PythonObfuscatorPypiPass.detect(&fixture);
    let _peel: disrobe_pass_py_deob::Result<PeelOutcome> = PythonObfuscatorPypiPass.peel(&fixture);
}

#[test]
fn python_obfuscator_pypi_real_application_loads_without_panic() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture(OBF, "application") else {
        panic!("missing real fixture");
    };
    let _detect: DetectReport = PythonObfuscatorPypiPass.detect(&fixture);
    let _peel: disrobe_pass_py_deob::Result<PeelOutcome> = PythonObfuscatorPypiPass.peel(&fixture);
}

#[test]
fn python_obfuscator_pypi_real_detector_should_match() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture(OBF, "hello") else {
        return;
    };
    let detect: DetectReport = PythonObfuscatorPypiPass.detect(&fixture);
    assert!(detect.matched);
}
