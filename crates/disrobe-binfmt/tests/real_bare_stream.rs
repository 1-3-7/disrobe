#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::path::{Path, PathBuf};

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::{ExtractionQuota, ExtractionResult, extract_to, extract_to_with_quota};

const FORMAT_DIR: &str = "bare-stream";

fn temp_dir(name: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-barestream-{name}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

fn expected_payload() -> Vec<u8> {
    let path: PathBuf = common::corpus_binfmt_root()
        .join(FORMAT_DIR)
        .join("expected")
        .join("payload.bin");
    std::fs::read(&path).expect("read ground-truth payload.bin")
}

fn load(name: &str) -> Vec<u8> {
    common::load_fixture(FORMAT_DIR, name)
        .unwrap_or_else(|| panic!("missing fixture corpus/binfmt/{FORMAT_DIR}/{name}"))
}

fn single_output(result: &ExtractionResult, out: &Path) -> Vec<u8> {
    assert!(
        result.integrity_violations.is_empty(),
        "violations: {:?}",
        result.integrity_violations
    );
    assert_eq!(
        result.entries.len(),
        1,
        "expected exactly one output member"
    );
    let entry: &disrobe_binfmt::ExtractedEntry = &result.entries[0];
    std::fs::read(out.join(&entry.name)).expect("read recovered output")
}

#[test]
fn zlib_stream_round_trips_byte_exact() {
    let bytes: Vec<u8> = load("payload.zlib");
    assert_eq!(detect_container(&bytes), Some(ContainerKind::Zlib));
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("zlib");
    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult =
        extract_to(ContainerKind::Zlib, &bytes, &out).expect("extract zlib");
    assert_eq!(single_output(&result, &out), expected_payload());
}

#[test]
fn lzip_stream_round_trips_byte_exact() {
    let bytes: Vec<u8> = load("payload.lz");
    assert_eq!(detect_container(&bytes), Some(ContainerKind::Lzip));
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("lzip");
    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult =
        extract_to(ContainerKind::Lzip, &bytes, &out).expect("extract lzip");
    assert_eq!(single_output(&result, &out), expected_payload());
}

#[test]
fn lz4_frame_round_trips_byte_exact() {
    let bytes: Vec<u8> = load("payload.lz4");
    assert_eq!(detect_container(&bytes), Some(ContainerKind::Lz4));
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("lz4");
    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult =
        extract_to(ContainerKind::Lz4, &bytes, &out).expect("extract lz4");
    assert_eq!(single_output(&result, &out), expected_payload());
}

#[test]
fn lz4_skippable_frame_round_trips_byte_exact() {
    let bytes: Vec<u8> = load("payload-skippable.lz4");
    assert_eq!(detect_container(&bytes), Some(ContainerKind::Lz4));
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("lz4skip");
    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult =
        extract_to(ContainerKind::Lz4, &bytes, &out).expect("extract lz4 skippable");
    assert_eq!(single_output(&result, &out), expected_payload());
}

#[test]
fn lz4_legacy_frame_round_trips_byte_exact() {
    let bytes: Vec<u8> = load("payload-legacy.lz4");
    assert_eq!(detect_container(&bytes), Some(ContainerKind::Lz4));
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("lz4legacy");
    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult =
        extract_to(ContainerKind::Lz4, &bytes, &out).expect("extract lz4 legacy");
    assert_eq!(single_output(&result, &out), expected_payload());
}

#[test]
fn bare_gzip_round_trips_byte_exact() {
    let bytes: Vec<u8> = load("payload.gz");
    assert_eq!(detect_container(&bytes), Some(ContainerKind::Gzip));
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("gz");
    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult =
        extract_to(ContainerKind::Gzip, &bytes, &out).expect("extract gz");
    assert_eq!(single_output(&result, &out), expected_payload());
}

#[test]
fn bare_gzip_emits_embedded_original_filename() {
    let bytes: Vec<u8> = load("payload-named.gz");
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("gznamed");
    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult =
        extract_to(ContainerKind::Gzip, &bytes, &out).expect("extract named gz");
    assert!(
        result.entries.iter().any(|e| e.name == "payload.bin"),
        "expected the embedded original filename payload.bin, got {:?}",
        result.entries.iter().map(|e| &e.name).collect::<Vec<_>>()
    );
    let got: Vec<u8> = std::fs::read(out.join("payload.bin")).expect("read named output");
    assert_eq!(got, expected_payload());
}

#[test]
fn bare_gzip_concatenated_members_all_recovered() {
    let bytes: Vec<u8> = load("payload-multi.gz");
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("gzmulti");
    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult =
        extract_to(ContainerKind::Gzip, &bytes, &out).expect("extract multi gz");
    assert_eq!(result.entries.len(), 2, "expected two concatenated members");
    let mut combined: Vec<u8> = Vec::new();
    for entry in &result.entries {
        combined.extend(std::fs::read(out.join(&entry.name)).expect("read member"));
    }
    assert_eq!(combined, expected_payload());
}

#[test]
fn bare_bzip2_round_trips_byte_exact() {
    let bytes: Vec<u8> = load("payload.bz2");
    assert_eq!(detect_container(&bytes), Some(ContainerKind::Bzip2));
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("bz2");
    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult =
        extract_to(ContainerKind::Bzip2, &bytes, &out).expect("extract bz2");
    assert_eq!(single_output(&result, &out), expected_payload());
}

#[test]
fn bare_zstd_round_trips_byte_exact() {
    let bytes: Vec<u8> = load("payload.zst");
    assert_eq!(detect_container(&bytes), Some(ContainerKind::Zstd));
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("zst");
    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult =
        extract_to(ContainerKind::Zstd, &bytes, &out).expect("extract zst");
    assert_eq!(single_output(&result, &out), expected_payload());
}

#[test]
fn bare_lzma_alone_round_trips_byte_exact() {
    let bytes: Vec<u8> = load("payload.lzma");
    let hinted: Option<ContainerKind> = disrobe_binfmt::detect_container_with_hint(
        &bytes,
        Some(std::path::Path::new("payload.lzma")),
    );
    assert_eq!(hinted, Some(ContainerKind::Lzma));
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("lzma");
    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult =
        extract_to(ContainerKind::Lzma, &bytes, &out).expect("extract lzma");
    assert_eq!(single_output(&result, &out), expected_payload());
}

#[test]
fn unix_compress_round_trips_byte_exact() {
    let bytes: Vec<u8> = load("payload.Z");
    assert_eq!(detect_container(&bytes), Some(ContainerKind::UnixCompress));
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("compress");
    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult =
        extract_to(ContainerKind::UnixCompress, &bytes, &out).expect("extract .Z");
    assert_eq!(single_output(&result, &out), expected_payload());
}

const fn tiny_cap_quota() -> ExtractionQuota {
    ExtractionQuota {
        max_total_uncompressed: 256,
        ..ExtractionQuota::default_safe()
    }
}

#[test]
fn bomb_caps_reject_oversized_decode_per_format() {
    let cases: [(ContainerKind, &str); 8] = [
        (ContainerKind::Zlib, "payload.zlib"),
        (ContainerKind::Lzip, "payload.lz"),
        (ContainerKind::Lz4, "payload.lz4"),
        (ContainerKind::Gzip, "payload.gz"),
        (ContainerKind::Bzip2, "payload.bz2"),
        (ContainerKind::Zstd, "payload.zst"),
        (ContainerKind::Lzma, "payload.lzma"),
        (ContainerKind::UnixCompress, "payload.Z"),
    ];
    for (kind, fixture) in cases {
        let bytes: Vec<u8> = load(fixture);
        let scratch: disrobe_core::scratch::ScratchDir =
            temp_dir(&format!("bomb-{}", kind.label()));
        let out: PathBuf = scratch.path().to_path_buf();
        let result: Result<ExtractionResult, disrobe_binfmt::Error> =
            extract_to_with_quota(kind, &bytes, &out, tiny_cap_quota());
        assert!(
            result.is_err(),
            "{kind:?} decode of {fixture} (22112 uncompressed bytes) must be rejected by the 256-byte bomb cap"
        );
    }
}
