#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::xar::{XarArchive, parse_xar};
use disrobe_binfmt::quota::ExtractionQuota;
use disrobe_binfmt::{ExtractionResult, extract_to_with_quota};

const MEMBERS: [&str; 4] = [
    "Distribution",
    "PackageInfo",
    "Payload.bin",
    "Scripts/preinstall",
];

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn temp_dir(name: &str) -> PathBuf {
    let seq: u64 = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "disrobe-realxar-{}-{name}-{seq}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn expected_bytes(rel: &str) -> Vec<u8> {
    let path: PathBuf = common::corpus_binfmt_root()
        .join("pkg")
        .join("expected")
        .join(rel);
    std::fs::read(&path).unwrap_or_else(|_| panic!("read ground-truth pkg/expected/{rel}"))
}

fn assert_pkg_recovers(fixture: &str, tag: &str) {
    let Some(bytes): Option<Vec<u8>> = common::load_fixture("pkg", fixture) else {
        panic!(
            "missing committed fixture corpus/binfmt/pkg/{fixture} - see corpus/binfmt/MANIFEST.toml"
        );
    };
    assert_eq!(detect_container(&bytes), Some(ContainerKind::Pkg));

    let archive: XarArchive = parse_xar(&bytes).expect("parse xar");
    assert!(
        archive.files.iter().any(|f| f.path == "Scripts/preinstall"),
        "xar toc must carry the nested Scripts/preinstall member"
    );

    let out: PathBuf = temp_dir(tag);
    let result: ExtractionResult = extract_to_with_quota(
        ContainerKind::Pkg,
        &bytes,
        &out,
        ExtractionQuota::unrestricted(),
    )
    .expect("extract xar");
    assert_eq!(result.kind, ContainerKind::Pkg);
    assert!(
        result.integrity_violations.is_empty(),
        "{fixture} extraction reported violations: {:?}",
        result.integrity_violations
    );

    for member in MEMBERS {
        let want: Vec<u8> = expected_bytes(member);
        let got: Vec<u8> = std::fs::read(out.join(member)).unwrap_or_else(|_| {
            panic!(
                "member {member} not recovered from {fixture}; entries={:?}",
                result.entries.iter().map(|e| &e.name).collect::<Vec<_>>()
            )
        });
        assert_eq!(
            got, want,
            "{member} recovered from {fixture} must be byte-identical to the source file"
        );
    }
}

#[test]
fn real_xar_gzip_recovers_members_byte_exact() {
    assert_pkg_recovers("gzip.pkg", "gzip");
}

#[test]
fn real_xar_uncompressed_recovers_members_byte_exact() {
    assert_pkg_recovers("none.pkg", "none");
}

#[test]
fn real_xar_bzip2_recovers_members_byte_exact() {
    assert_pkg_recovers("bzip2.pkg", "bzip2");
}

#[test]
fn real_xar_xz_recovers_members_byte_exact() {
    assert_pkg_recovers("xz.pkg", "xz");
}

#[test]
fn real_xar_lzma_recovers_members_byte_exact() {
    assert_pkg_recovers("lzma.pkg", "lzma");
}
