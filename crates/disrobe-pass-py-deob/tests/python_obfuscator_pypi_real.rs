#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::python_obfuscator_pypi::PythonObfuscatorPypiPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, Obfuscator, PeelOutcome, Quality};

const OBF: &str = "python_obfuscator_pypi";

#[test]
fn python_obfuscator_pypi_real_hello_unwraps_exec_to_inner_source() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture(OBF, "hello") else {
        common::skip_absent_corpus(
            "python_obfuscator_pypi_real_hello_unwraps_exec_to_inner_source",
            OBF,
        );
        return;
    };
    let text: &str = std::str::from_utf8(&fixture).expect("utf8");
    assert!(
        text.contains("68656c6c6f20776f726c64"),
        "real fixture should embed hello-world hex literal"
    );
    let detect: DetectReport = PythonObfuscatorPypiPass.detect(&fixture);
    assert_eq!(detect.obfuscator, Obfuscator::PythonObfuscatorPypi);
    assert!(detect.matched, "real fixture must be detected: {detect:?}");
    let peel: PeelOutcome = PythonObfuscatorPypiPass
        .peel(&fixture)
        .unwrap_or_else(|e| panic!("peel: {e:?}"));
    assert_eq!(
        peel.quality,
        Quality::Partial,
        "exec-unwrap is an honest Partial (junk vars remain), got {:?}",
        peel.quality
    );
    assert!(
        peel.stages_applied
            .iter()
            .any(|s: &String| s == "exec-unwrap"),
        "expected exec-unwrap stage, got {:?}",
        peel.stages_applied
    );
    assert!(
        peel.recovered_source
            .contains("print(bytes.fromhex('68656c6c6f20776f726c64').decode('utf-8'))"),
        "recovered inner source must contain the unwrapped print statement; got first 200: {:?}",
        &peel.recovered_source.chars().take(200).collect::<String>()
    );
    assert!(
        !peel.recovered_source.trim_start().starts_with("exec("),
        "recovered source must be the inner program, not the exec() wrapper"
    );
}

#[test]
fn python_obfuscator_pypi_real_sample_unwraps_inner_source() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture(OBF, "sample") else {
        common::skip_absent_corpus(
            "python_obfuscator_pypi_real_sample_unwraps_inner_source",
            OBF,
        );
        return;
    };
    let detect: DetectReport = PythonObfuscatorPypiPass.detect(&fixture);
    assert!(detect.matched);
    let peel: PeelOutcome = PythonObfuscatorPypiPass
        .peel(&fixture)
        .unwrap_or_else(|e| panic!("sample peel: {e:?}"));
    assert_eq!(peel.quality, Quality::Partial);
    assert!(
        peel.stages_applied
            .iter()
            .any(|s: &String| s == "exec-unwrap"),
        "expected exec-unwrap stage, got {:?}",
        peel.stages_applied
    );
    assert!(
        !peel.recovered_source.is_empty()
            && !peel.recovered_source.trim_start().starts_with("exec("),
        "sample recovery must unwrap the exec wrapper"
    );
}

#[test]
fn python_obfuscator_pypi_real_application_unwraps_inner_source() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture(OBF, "application") else {
        common::skip_absent_corpus(
            "python_obfuscator_pypi_real_application_unwraps_inner_source",
            OBF,
        );
        return;
    };
    let detect: DetectReport = PythonObfuscatorPypiPass.detect(&fixture);
    assert!(detect.matched);
    let peel: PeelOutcome = PythonObfuscatorPypiPass
        .peel(&fixture)
        .unwrap_or_else(|e| panic!("application peel: {e:?}"));
    assert!(
        peel.recovered_source.len() > 100
            && !peel.recovered_source.trim_start().starts_with("exec("),
        "application recovery must unwrap to substantial inner source"
    );
}

#[test]
fn python_obfuscator_pypi_real_detector_matches() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture(OBF, "hello") else {
        common::skip_absent_corpus("python_obfuscator_pypi_real_detector_matches", OBF);
        return;
    };
    let detect: DetectReport = PythonObfuscatorPypiPass.detect(&fixture);
    assert!(detect.matched);
}
