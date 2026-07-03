#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::io::Read as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::fat::{FatKind, FatVolume, walk_fat};
use disrobe_binfmt::{ExtractionResult, extract_to};

const FORMAT_DIR: &str = "fat";

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn temp_dir(name: &str) -> PathBuf {
    let seq: u64 = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "disrobe-realfat-{}-{name}-{seq}",
        std::process::id()
    ));
    if dir.exists() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn load_image(name: &str) -> Vec<u8> {
    let gz: Vec<u8> =
        common::load_fixture(FORMAT_DIR, &format!("{name}.img.gz")).unwrap_or_else(|| {
            panic!("missing committed fixture corpus/binfmt/{FORMAT_DIR}/{name}.img.gz")
        });
    let mut decoder: flate2::read::GzDecoder<&[u8]> = flate2::read::GzDecoder::new(&gz[..]);
    let mut out: Vec<u8> = Vec::new();
    decoder.read_to_end(&mut out).expect("inflate fixture");
    out
}

fn expected_bytes(rel: &str) -> Vec<u8> {
    let path: PathBuf = common::corpus_binfmt_root()
        .join(FORMAT_DIR)
        .join("expected")
        .join(rel);
    std::fs::read(&path).unwrap_or_else(|_| panic!("read ground-truth {FORMAT_DIR}/expected/{rel}"))
}

fn assert_fat_recovers_members(name: &str, want_kind: FatKind) {
    let image: Vec<u8> = load_image(name);

    let volume: FatVolume = walk_fat(&image, 1 << 30).expect("walk fat volume");
    assert_eq!(volume.bpb.kind, want_kind, "{name} must be {want_kind:?}");
    assert_eq!(
        volume.volume_label.as_deref(),
        Some("DISROBEVOL"),
        "{name} volume label must round-trip"
    );

    assert_eq!(
        detect_container(&image),
        Some(ContainerKind::Fat),
        "{name} must be detected as a top-level FAT container"
    );

    let out: PathBuf = temp_dir(name);
    let result: ExtractionResult =
        extract_to(ContainerKind::Fat, &image, &out).expect("extract fat volume");
    assert_eq!(result.kind, ContainerKind::Fat);
    assert!(
        result.integrity_violations.is_empty(),
        "{name} extraction reported violations: {:?}",
        result.integrity_violations
    );

    for member in ["HELLO.TXT", "DATA.BIN"] {
        let want: Vec<u8> = expected_bytes(member);
        let got: Vec<u8> = std::fs::read(out.join(member)).unwrap_or_else(|_| {
            panic!(
                "member {member} not recovered from {name}; violations: {:?}",
                result.integrity_violations
            )
        });
        assert_eq!(
            got, want,
            "{member} recovered from {name} must be byte-identical to the encoder input"
        );
    }
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn fat16_recovers_members_byte_exact() {
    assert_fat_recovers_members("fat16", FatKind::Fat16);
}

#[test]
fn fat12_recovers_members_byte_exact() {
    assert_fat_recovers_members("fat12", FatKind::Fat12);
}
