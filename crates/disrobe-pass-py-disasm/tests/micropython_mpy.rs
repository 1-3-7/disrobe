#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_py_disasm::alt_runtimes::micropython::{MicroPythonModule, detect, parse};

const MPY_MAGIC: u8 = b'M';

fn header(version: u8) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(8);
    bytes.push(MPY_MAGIC);
    bytes.push(version);
    bytes.push(0u8);
    bytes.push(31u8);
    if version >= 5 {
        bytes.extend_from_slice(&[12u8, 0u8]);
    }
    bytes
}

#[test]
fn parses_mpy_v0_through_v6() {
    for v in 0u8..=6u8 {
        let mut bytes: Vec<u8> = header(v);
        bytes.extend_from_slice(&[10u8, 20u8, 30u8]);
        let module: MicroPythonModule = parse(&bytes).expect("parse mpy");
        assert_eq!(module.version.raw(), v);
        assert_eq!(module.raw_code, vec![10u8, 20u8, 30u8]);
    }
}

#[test]
fn opcode_histogram_counts_bytes() {
    let mut bytes: Vec<u8> = header(3);
    bytes.extend_from_slice(&[5u8, 5u8, 5u8, 7u8]);
    let module: MicroPythonModule = parse(&bytes).expect("parse");
    assert_eq!(module.opcode_histogram.get(&5u8).copied(), Some(3u32));
    assert_eq!(module.opcode_histogram.get(&7u8).copied(), Some(1u32));
}

#[test]
fn detect_accepts_v0_through_v6() {
    for v in 0u8..=6u8 {
        let bytes: Vec<u8> = header(v);
        assert!(detect(&bytes), "should detect v{v}");
    }
}

#[test]
fn detect_rejects_v7_unsupported() {
    let bytes: Vec<u8> = vec![MPY_MAGIC, 7u8, 0u8, 31u8];
    assert!(!detect(&bytes));
}

#[test]
fn parse_rejects_truncated_v5_header() {
    let bytes: [u8; 4] = [MPY_MAGIC, 5u8, 0u8, 31u8];
    let err: disrobe_pass_py_disasm::AltRuntimeError = parse(&bytes).expect_err("truncated");
    assert!(matches!(
        err,
        disrobe_pass_py_disasm::AltRuntimeError::Truncated { .. }
    ));
}

#[test]
fn version_supports_native_only_v3_plus() {
    use disrobe_pass_py_disasm::alt_runtimes::micropython::MpyVersion;
    assert!(!MpyVersion(2).supports_native());
    assert!(MpyVersion(3).supports_native());
    assert!(MpyVersion(6).supports_native());
}

#[test]
#[ignore = "requires the uncommitted corpus/python/alt_runtimes/micropython/hello.mpy fixture; run with --ignored once present"]
fn parses_real_baked_v6_fixture() {
    const FIXTURE: &str = "../../corpus/python/alt_runtimes/micropython/hello.mpy";
    let path: std::path::PathBuf = std::env::current_dir().expect("cwd").join(FIXTURE);
    assert!(
        path.exists(),
        "missing micropython v6 fixture: {}",
        path.display()
    );
    let bytes: Vec<u8> = std::fs::read(&path).expect("read");
    let module: MicroPythonModule = parse(&bytes).expect("parse real v6 mpy");
    assert_eq!(module.version.raw(), 6);
    assert!(!module.raw_code.is_empty());
}
