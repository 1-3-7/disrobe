#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::squashfs::{
    SquashfsCompression, SquashfsSuperblock, parse_squashfs_superblock,
};
use disrobe_binfmt::{ExtractionResult, extract_to};

const FORMAT_DIR: &str = "squashfs-lzo";
const FIXTURE_NAME: &str = "hello-lzo.squashfs";

fn temp_dir(name: &str) -> PathBuf {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe-squashlzo-{}-{name}", std::process::id()));
    if dir.exists() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn expected_bytes(rel: &str) -> Vec<u8> {
    let path: PathBuf = common::corpus_binfmt_root()
        .join(FORMAT_DIR)
        .join("expected")
        .join(rel);
    std::fs::read(&path).unwrap_or_else(|_| panic!("read ground-truth {FORMAT_DIR}/expected/{rel}"))
}

#[test]
fn lzo_squashfs_superblock_reports_lzo_compressor() {
    let bytes: Vec<u8> = common::load_fixture(FORMAT_DIR, FIXTURE_NAME).unwrap_or_else(|| {
        panic!("missing committed fixture corpus/binfmt/{FORMAT_DIR}/{FIXTURE_NAME}")
    });
    let sb: SquashfsSuperblock =
        parse_squashfs_superblock(&bytes, 0).expect("parse lzo squashfs superblock");
    assert_eq!(sb.version_major, 4);
    assert!(sb.little_endian);
    assert!(
        matches!(sb.compression, SquashfsCompression::Lzo),
        "fixture must use the lzo compressor, got {:?}",
        sb.compression
    );
}

#[test]
fn lzo_squashfs_recovers_members_byte_exact() {
    let bytes: Vec<u8> = common::load_fixture(FORMAT_DIR, FIXTURE_NAME).unwrap_or_else(|| {
        panic!("missing committed fixture corpus/binfmt/{FORMAT_DIR}/{FIXTURE_NAME}")
    });
    assert_eq!(detect_container(&bytes), Some(ContainerKind::Squashfs));

    let out: PathBuf = temp_dir("extract");
    let result: ExtractionResult =
        extract_to(ContainerKind::Squashfs, &bytes, &out).expect("extract lzo squashfs");
    assert_eq!(result.kind, ContainerKind::Squashfs);
    assert!(
        result.integrity_violations.is_empty(),
        "extraction reported violations: {:?}",
        result.integrity_violations
    );

    for member in ["hello.txt", "docs/notes.txt"] {
        let want: Vec<u8> = expected_bytes(member);
        let got: Vec<u8> = std::fs::read(out.join(member)).unwrap_or_else(|_| {
            panic!(
                "member {member} not recovered from {FIXTURE_NAME}; violations: {:?}",
                result.integrity_violations
            )
        });
        assert_eq!(
            got, want,
            "{member} recovered from lzo squashfs must be byte-identical to the source file"
        );
    }
}
