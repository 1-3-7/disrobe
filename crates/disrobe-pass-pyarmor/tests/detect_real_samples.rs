#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use disrobe_pass_pyarmor::{Detection, ProtectionKind, PyarmorVersion, detect_from_wrapper};

fn samples_root() -> PathBuf {
    let here: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    here.parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("corpus")
        .join("python")
        .join("pyarmor")
}

fn read_wrapper(relative: &str) -> String {
    let path: PathBuf = samples_root().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "committed PyArmor wrapper missing or unreadable: {}: {error}",
            path.display()
        )
    })
}

#[test]
fn detect_v9_default_sample() {
    let text: String = read_wrapper("v9_latest_925/default/known_plaintext.py");
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
    let text: String = read_wrapper(
        "v8/basic/chunk_00_try_except_basic_try_except_else/chunk_00_try_except_basic_try_except_else.py",
    );
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
fn detect_v9_no_wrap_sample() {
    let text: String = read_wrapper("v9_latest_925/nowrap/known_plaintext.py");
    let (det, payload): (Detection, Vec<u8>) =
        detect_from_wrapper(&text).expect("must detect v9 no-wrap");
    assert_eq!(det.version, PyarmorVersion::V9);
    assert_eq!(det.protection, ProtectionKind::Standard);
    assert!(payload.len() > 256);
}
