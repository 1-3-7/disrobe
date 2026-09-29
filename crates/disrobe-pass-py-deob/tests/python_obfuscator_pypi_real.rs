#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::python_obfuscator_pypi::PythonObfuscatorPypiPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, Obfuscator, PeelOutcome, Quality};

const OBF: &str = "python_obfuscator_pypi";

fn assert_parses(slot: &str, source: &str) {
    assert!(
        ruff_python_parser::parse(
            source,
            ruff_python_parser::ParseOptions::from(ruff_python_parser::Mode::Module)
        )
        .is_ok(),
        "python_obfuscator_pypi {slot}: the unwrapped inner program must parse as Python; first \
         200: {:?}",
        source.chars().take(200).collect::<String>()
    );
}

#[test]
fn python_obfuscator_pypi_real_hello_unwraps_exec_to_inner_source() {
    let fixture: Vec<u8> = common::require_real_fixture(OBF, "hello");
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
    assert_parses("hello", &peel.recovered_source);
}

#[test]
fn python_obfuscator_pypi_real_sample_unwraps_inner_source() {
    let fixture: Vec<u8> = common::require_real_fixture(OBF, "sample");
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
    assert_parses("sample", &peel.recovered_source);
}

#[test]
fn python_obfuscator_pypi_real_application_unwraps_inner_source() {
    let fixture: Vec<u8> = common::require_real_fixture(OBF, "application");
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
    assert_eq!(peel.quality, Quality::Partial);
}

#[test]
fn python_obfuscator_pypi_real_detector_matches() {
    let fixture: Vec<u8> = common::require_real_fixture(OBF, "hello");
    let detect: DetectReport = PythonObfuscatorPypiPass.detect(&fixture);
    assert!(detect.matched);
}

#[test]
fn python_obfuscator_pypi_detector_matches_every_real_edge_case_without_hex_strings() {
    let edges: [&str; 9] = [
        "edge_async_fn",
        "edge_class_decorator",
        "edge_generator",
        "edge_lambda_in_listcomp",
        "edge_match_statement",
        "edge_recursive",
        "edge_structural_pattern",
        "edge_typing_generic",
        "edge_walrus_operator",
    ];
    let mut missed: Vec<&str> = Vec::new();
    for slot in edges {
        let fixture: Vec<u8> = common::require_real_fixture(OBF, slot);
        let detect: DetectReport = PythonObfuscatorPypiPass.detect(&fixture);
        if !detect.matched || detect.confidence < 0.5 {
            missed.push(slot);
        }
    }
    assert!(
        missed.is_empty(),
        "the python-obfuscator exec wrapper must be detected on every real edge case, including \
         the ones with no string literal to hex-encode; missed {missed:?}"
    );
}
