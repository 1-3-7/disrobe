#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::{ExtractionResult, extract_to};

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn temp_dir(name: &str) -> PathBuf {
    let seq: u64 = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "disrobe-realdisk-{}-{name}-{seq}",
        std::process::id()
    ));
    if dir.exists() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn expected_payload() -> Vec<u8> {
    let path: PathBuf = common::corpus_binfmt_root()
        .join("disk")
        .join("expected")
        .join("HELLO.TXT");
    std::fs::read(&path).expect("read ground-truth disk/expected/HELLO.TXT")
}

fn find_recovered(out: &std::path::Path, leaf: &str) -> Option<Vec<u8>> {
    for entry in walkdir(out) {
        if entry
            .file_name()
            .and_then(|n: &std::ffi::OsStr| n.to_str())
            .is_some_and(|n: &str| n.eq_ignore_ascii_case(leaf))
        {
            return std::fs::read(&entry).ok();
        }
    }
    None
}

fn walkdir(root: &std::path::Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let path: PathBuf = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out
}

fn assert_image_recovers_payload(format_dir: &str, fixture: &str, kind: ContainerKind, tag: &str) {
    let Some(bytes): Option<Vec<u8>> = common::load_fixture(format_dir, fixture) else {
        panic!(
            "missing committed fixture corpus/binfmt/{format_dir}/{fixture} - see corpus/binfmt/MANIFEST.toml"
        );
    };
    assert_eq!(
        detect_container(&bytes),
        Some(kind),
        "{fixture} must be detected as {kind:?}"
    );
    let out: PathBuf = temp_dir(tag);
    let result: ExtractionResult = extract_to(kind, &bytes, &out).expect("extract disk image");
    assert_eq!(result.kind, kind);

    let payload: Vec<u8> = expected_payload();
    let hello: Vec<u8> = find_recovered(&out, "HELLO.TXT").unwrap_or_else(|| {
        panic!(
            "HELLO.TXT not recovered from {fixture}; violations: {:?}",
            result.integrity_violations
        )
    });
    assert_eq!(
        hello, payload,
        "HELLO.TXT recovered from {fixture} must be byte-identical to the file written into the volume"
    );
    let notes: Vec<u8> = find_recovered(&out, "NOTES.TXT").unwrap_or_else(|| {
        panic!(
            "DOCS/NOTES.TXT not recovered from {fixture}; violations: {:?}",
            result.integrity_violations
        )
    });
    assert_eq!(
        notes, payload,
        "DOCS/NOTES.TXT recovered from {fixture} must be byte-identical to the authored payload"
    );
}

#[test]
fn vhd_fixed_fat_recovers_known_file_byte_exact() {
    assert_image_recovers_payload("disk", "fat-fixed.vhd", ContainerKind::Vhd, "vhd-fixed");
}

#[test]
fn vhd_dynamic_fat_recovers_known_file_byte_exact() {
    assert_image_recovers_payload("disk", "fat-dynamic.vhd", ContainerKind::Vhd, "vhd-dynamic");
}

#[test]
fn vhdx_fat_recovers_known_file_byte_exact() {
    assert_image_recovers_payload("disk", "fat.vhdx", ContainerKind::Vhdx, "vhdx");
}
