#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stderr,
    clippy::panic
)]

use std::path::PathBuf;

use disrobe_pass_pyarmor::{Detection, ProtectionKind, PyarmorVersion, detect_from_wrapper};

fn samples_root() -> PathBuf {
    let here: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    here.parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("corpus")
        .join("generated")
        .join("pyarmor")
}

fn try_read_wrapper(sample: &str) -> Option<(String, PathBuf)> {
    let path: PathBuf = samples_root().join(sample).join("hello.py");
    if !path.is_file() {
        return None;
    }
    let text: String = std::fs::read_to_string(&path).ok()?;
    Some((text, path))
}

#[test]
fn detect_v9_default_sample() {
    let Some((text, _)): Option<(String, PathBuf)> = try_read_wrapper("v9-default") else {
        eprintln!(
            "skipped: v9-default sample not present (corpus/generated/pyarmor/v9-default/hello.py)"
        );
        return;
    };
    let (det, payload): (Detection, Vec<u8>) =
        detect_from_wrapper(&text).expect("must detect v9 wrapper");
    assert_eq!(det.version, PyarmorVersion::V9);
    assert_eq!(det.protection, ProtectionKind::Standard);
    assert_eq!(det.serial.as_deref(), Some("000000"));
    assert_eq!(det.python_major, Some(3));
    assert_eq!(det.python_minor, Some(14));
    assert!(&payload[..2] == b"PY");
    assert!(payload.len() > 256);
}

#[test]
fn detect_v8_default_sample() {
    let Some((text, _)): Option<(String, PathBuf)> = try_read_wrapper("v8-default") else {
        eprintln!("skipped: v8-default sample not present");
        return;
    };
    let (det, payload): (Detection, Vec<u8>) =
        detect_from_wrapper(&text).expect("must detect v8 wrapper");
    assert!(matches!(
        det.version,
        PyarmorVersion::V8 | PyarmorVersion::V9
    ));
    assert_eq!(det.python_major, Some(3));
    assert!(payload.len() > 256);
}

#[test]
fn detect_v7_default_sample() {
    let Some((text, _)): Option<(String, PathBuf)> = try_read_wrapper("v7-default") else {
        eprintln!("skipped: v7-default sample not present");
        return;
    };
    let (det, payload): (Detection, Vec<u8>) =
        detect_from_wrapper(&text).expect("must detect v7 wrapper");
    assert!(matches!(
        det.version,
        PyarmorVersion::V6 | PyarmorVersion::V7
    ));
    assert!(payload.starts_with(b"PYARMOR\0"));
    assert!(payload.len() > 128);
}

#[test]
fn detect_v6_default_sample() {
    let Some((text, _)): Option<(String, PathBuf)> = try_read_wrapper("v6-default") else {
        eprintln!("skipped: v6-default sample not present");
        return;
    };
    let (det, payload): (Detection, Vec<u8>) =
        detect_from_wrapper(&text).expect("must detect v6 wrapper");
    assert!(matches!(
        det.version,
        PyarmorVersion::V6 | PyarmorVersion::V7
    ));
    assert!(payload.starts_with(b"PYARMOR\0"));
}

#[test]
fn detect_v9_no_wrap_sample() {
    let Some((text, _)): Option<(String, PathBuf)> = try_read_wrapper("v9-no-wrap") else {
        eprintln!("skipped: v9-no-wrap sample not present");
        return;
    };
    let (det, payload): (Detection, Vec<u8>) =
        detect_from_wrapper(&text).expect("must detect v9 no-wrap");
    assert_eq!(det.version, PyarmorVersion::V9);
    assert_eq!(det.protection, ProtectionKind::Standard);
    assert!(payload.len() > 256);
}
