#![cfg(feature = "alt-ironpython")]
#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_pass_py_disasm::alt_runtimes::ironpython::{
    DotnetAnalysis, IronPythonModule, analyze, detect, parse,
};

fn synth_pe_with_marker(marker: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(2048);
    bytes.extend_from_slice(b"MZ");
    bytes.extend_from_slice(&[0u8; 58]);
    bytes.extend_from_slice(&[0u8; 4]);
    bytes.extend_from_slice(marker.as_bytes());
    bytes.resize(1024, 0u8);
    bytes
}

const GREET_IP: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/ironpython/greet_ip.dll");

#[test]
fn detect_finds_ironpython_runtime_marker() {
    assert!(detect(GREET_IP));
}

#[test]
fn detect_finds_ironpython_modules_marker() {
    let runtime: &[u8] = b"IronPython.Runtime";
    let at: usize = GREET_IP
        .windows(runtime.len())
        .position(|w: &[u8]| w == runtime)
        .expect("the fixture references IronPython.Runtime");
    let mut bytes: Vec<u8> = GREET_IP.to_vec();
    bytes[at..at + runtime.len()].copy_from_slice(b"IronPython.Modules");
    assert!(!bytes.windows(runtime.len()).any(|w: &[u8]| w == runtime));
    assert!(detect(&bytes));
}

#[test]
fn a_native_pe_naming_the_runtime_is_not_ironpython() {
    assert!(!detect(&synth_pe_with_marker("IronPython.Runtime")));
    assert!(!detect(&synth_pe_with_marker("IronPython.Modules")));
}

#[test]
fn detect_rejects_non_pe() {
    let bytes: [u8; 64] = [0u8; 64];
    assert!(!detect(&bytes));
}

#[test]
fn detect_rejects_pe_without_ironpython_marker() {
    let bytes: Vec<u8> = synth_pe_with_marker("System.Runtime");
    assert!(!detect(&bytes));
}

#[test]
fn parse_on_synthetic_pe_returns_delegation_failure() {
    let bytes: Vec<u8> = synth_pe_with_marker("IronPython.Runtime");
    let result: Result<IronPythonModule, _> = parse(&bytes);
    let err: disrobe_pass_py_disasm::AltRuntimeError = result.expect_err("synthetic PE invalid");
    assert!(matches!(
        err,
        disrobe_pass_py_disasm::AltRuntimeError::DelegationFailed { .. }
    ));
}

#[test]
fn analyze_on_synthetic_pe_returns_delegation_failure() {
    let bytes: Vec<u8> = synth_pe_with_marker("IronPython.Runtime");
    let result: Result<DotnetAnalysis, disrobe_pass_py_disasm::AltRuntimeError> = analyze(&bytes);
    assert!(
        matches!(
            result,
            Err(disrobe_pass_py_disasm::AltRuntimeError::DelegationFailed {
                target: "dotnet.pe",
                ..
            })
        ),
        "a synthetic PE must fail dotnet delegation, not parse; got {result:?}"
    );
}

#[test]
fn analyze_on_real_dotnet_pe_works() {
    let analysis: DotnetAnalysis = analyze(GREET_IP).expect("analyze real dll");
    assert!(analysis.is_ironpython);
    assert!(analysis.markers.contains(&"IronPython.Runtime".to_owned()));
}
