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

#[test]
fn detect_finds_ironpython_runtime_marker() {
    let bytes: Vec<u8> = synth_pe_with_marker("IronPython.Runtime");
    assert!(detect(&bytes));
}

#[test]
fn detect_finds_ironpython_modules_marker() {
    let bytes: Vec<u8> = synth_pe_with_marker("IronPython.Modules");
    assert!(detect(&bytes));
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
#[ignore = "requires the uncommitted corpus/python/alt_runtimes/ironpython/hello.dll fixture; run with --ignored once present"]
fn analyze_on_real_dotnet_pe_works() {
    const CORPUS: &str = "../../corpus/python/alt_runtimes/ironpython/hello.dll";
    let path: std::path::PathBuf = std::env::current_dir().expect("cwd").join(CORPUS);
    assert!(
        path.exists(),
        "missing ironpython corpus fixture: {}",
        path.display()
    );
    let bytes: Vec<u8> = std::fs::read(&path).expect("read corpus");
    let analysis: DotnetAnalysis = analyze(&bytes).expect("analyze real dll");
    assert!(analysis.is_ironpython);
}
