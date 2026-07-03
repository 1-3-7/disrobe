#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::rar::{RarArchive, parse_rar};
use disrobe_binfmt::{ExtractionResult, extract_to};

const EXPECTED: [(&str, &str); 3] = [
    ("hello.txt", "hello.txt"),
    ("lorem.txt", "lorem.txt"),
    ("docs/notes.txt", "docs/notes.txt"),
];

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn temp_dir(name: &str) -> PathBuf {
    let seq: u64 = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "disrobe-realrar-{}-{name}-{seq}",
        std::process::id()
    ));
    if dir.exists() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn expected_bytes(rel: &str) -> Vec<u8> {
    let path: PathBuf = common::corpus_binfmt_root()
        .join("rar")
        .join("expected")
        .join(rel);
    std::fs::read(&path).unwrap_or_else(|_| panic!("read ground-truth rar/expected/{rel}"))
}

fn assert_store_archive_recovers(fixture: &str, version: u8, tag: &str) {
    let Some(bytes): Option<Vec<u8>> = common::load_fixture("rar", fixture) else {
        panic!(
            "missing committed fixture corpus/binfmt/rar/{fixture} - see corpus/binfmt/MANIFEST.toml"
        );
    };
    assert_eq!(detect_container(&bytes), Some(ContainerKind::Rar));
    let archive: RarArchive = parse_rar(&bytes).expect("parse rar");
    assert_eq!(archive.version, version, "{fixture} version");

    let out: PathBuf = temp_dir(tag);
    let result: ExtractionResult =
        extract_to(ContainerKind::Rar, &bytes, &out).expect("extract rar");
    assert_eq!(result.kind, ContainerKind::Rar);

    for (member, on_disk) in EXPECTED {
        let want: Vec<u8> = expected_bytes(member);
        let got: Vec<u8> = std::fs::read(out.join(on_disk)).unwrap_or_else(|_| {
            panic!(
                "member {member} not recovered from {fixture}; violations: {:?}",
                result.integrity_violations
            )
        });
        assert_eq!(
            got, want,
            "{member} recovered from {fixture} must be byte-identical to the source file"
        );
    }
}

fn assert_single_member_recovers(fixture: &str, member: &str, original: &str, tag: &str) {
    let Some(bytes): Option<Vec<u8>> = common::load_fixture("rar", fixture) else {
        panic!("missing committed fixture corpus/binfmt/rar/{fixture}");
    };
    assert_eq!(detect_container(&bytes), Some(ContainerKind::Rar));
    let archive: RarArchive = parse_rar(&bytes).expect("parse rar5");
    assert_eq!(archive.version, 5, "{fixture} version");

    let out: PathBuf = temp_dir(tag);
    let result: ExtractionResult =
        extract_to(ContainerKind::Rar, &bytes, &out).expect("extract rar5");
    assert!(
        result.integrity_violations.is_empty(),
        "{fixture} extraction reported violations: {:?}",
        result.integrity_violations
    );
    let want: Vec<u8> = expected_bytes(original);
    let got: Vec<u8> = std::fs::read(out.join(member)).unwrap_or_else(|_| {
        panic!(
            "member {member} not recovered from {fixture}; violations: {:?}",
            result.integrity_violations
        )
    });
    assert_eq!(
        got, want,
        "{member} recovered from {fixture} must be byte-identical to the source file"
    );
}

#[test]
fn rar4_store_recovers_members_byte_exact() {
    assert_store_archive_recovers("store-rar4.rar", 4, "store-rar4");
}

#[test]
fn rar5_store_recovers_members_byte_exact() {
    assert_store_archive_recovers("store-rar5.rar", 5, "store-rar5");
}

#[test]
fn rar5_normal_decompresses_members_byte_exact() {
    assert_store_archive_recovers("normal-rar5.rar", 5, "normal-rar5");
}

#[test]
fn rar4_normal_decompresses_members_byte_exact() {
    assert_store_archive_recovers("normal-rar4.rar", 4, "normal-rar4");
}

#[test]
fn rar4_ppmd_decompresses_members_byte_exact() {
    assert_store_archive_recovers("ppmd-rar4.rar", 4, "ppmd-rar4");
}

#[test]
fn rar5_e8e9_filter_decodes_member_byte_exact() {
    assert_single_member_recovers(
        "filter-e8e9-rar5.rar",
        "x86code.bin",
        "x86code.bin",
        "filter-e8e9",
    );
}

#[test]
fn rar5_delta_filter_decodes_member_byte_exact() {
    assert_single_member_recovers(
        "filter-delta-rar5.rar",
        "delta.bin",
        "delta.bin",
        "filter-delta",
    );
}

#[test]
fn rar5_multiblock_lz_decodes_member_byte_exact() {
    assert_single_member_recovers(
        "multiblock-rar5.rar",
        "multiblock.bin",
        "multiblock.bin",
        "multiblock",
    );
}
