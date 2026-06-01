#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use disrobe_pass_pyarmor::{
    StaticUnpackConfig, StaticUnpackOutput, WrapperMagic, unpack_static, unpack_static_with_config,
};

#[test]
fn rejects_zero_bytes() {
    let err: bool = unpack_static(&[]).is_err();
    assert!(err);
}

#[test]
fn rejects_garbage_bytes() {
    let err: bool = unpack_static(&[0xffu8; 64]).is_err();
    assert!(err);
}

#[test]
fn detect_only_v8_without_runtime() {
    let mut bytes: Vec<u8> = vec![0u8; 64];
    bytes[..8].copy_from_slice(b"PY008106");
    bytes[9] = 3;
    bytes[10] = 11;
    bytes[20] = 0x08;
    let output: StaticUnpackOutput =
        unpack_static(&bytes).expect("v8 detect-only succeeds with no runtime");
    assert_eq!(output.header_metadata.magic, WrapperMagic::Py8Or9);
    assert_eq!(output.header_metadata.serial.as_deref(), Some("008106"));
    assert_eq!(output.python_version, Some((3, 11)));
}

#[test]
fn detect_only_v9_bcc_without_runtime() {
    let mut bytes: Vec<u8> = vec![0u8; 64];
    bytes[..8].copy_from_slice(b"PY009070");
    bytes[9] = 3;
    bytes[10] = 13;
    bytes[20] = 0x09;
    let output: StaticUnpackOutput = unpack_static(&bytes).expect("v9 detect-only");
    assert_eq!(output.header_metadata.protection_type, Some(0x09));
}

#[test]
fn corpus_pyc_smoke_does_not_panic() {
    let corpus_dir: PathBuf = workspace_root().join("corpus/python/pyarmor");
    if !corpus_dir.is_dir() {
        return;
    }
    walk_files(&corpus_dir, &mut |path: &Path| {
        if path.extension().and_then(std::ffi::OsStr::to_str) != Some("pyc") {
            return;
        }
        if let Ok(bytes) = std::fs::read(path) {
            let cfg: StaticUnpackConfig = StaticUnpackConfig {
                emit_llm_metadata: true,
                ..StaticUnpackConfig::default()
            };
            let _ = unpack_static_with_config(&bytes, &cfg);
        }
    });
}

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn walk_files(dir: &Path, visitor: &mut dyn FnMut(&Path)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path: PathBuf = entry.path();
        if path.is_dir() {
            walk_files(&path, visitor);
        } else {
            visitor(&path);
        }
    }
}
