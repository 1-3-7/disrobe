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

const fn text_ratio_quota() -> ExtractionQuota {
    ExtractionQuota {
        max_aggregate_ratio: 1000,
        max_per_entry_ratio: 1000,
        ..ExtractionQuota::default_safe()
    }
}

fn xz_stream(plain: &[u8]) -> Vec<u8> {
    let mut encoder: liblzma::write::XzEncoder<Vec<u8>> =
        liblzma::write::XzEncoder::new(Vec::new(), 6);
    std::io::Write::write_all(&mut encoder, plain).expect("xz encode");
    encoder.finish().expect("xz finish")
}

fn bzip2_stream(plain: &[u8]) -> Vec<u8> {
    let mut encoder: bzip2::write::BzEncoder<Vec<u8>> =
        bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::best());
    std::io::Write::write_all(&mut encoder, plain).expect("bzip2 encode");
    encoder.finish().expect("bzip2 finish")
}

fn gzip_member(plain: &[u8]) -> Vec<u8> {
    let mut encoder: flate2::write::GzEncoder<Vec<u8>> =
        flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    std::io::Write::write_all(&mut encoder, plain).expect("gzip encode");
    encoder.finish().expect("gzip finish")
}

fn concatenated(first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut joined: Vec<u8> = first.to_vec();
    joined.extend_from_slice(second);
    joined
}

#[test]
fn concatenated_lzip_members_all_decode() {
    let single: Vec<u8> = load("payload.lz");
    let bytes: Vec<u8> = concatenated(&single, &single);
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("lzip-multi");
    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult =
        extract_to(ContainerKind::Lzip, &bytes, &out).expect("extract concatenated lzip");
    let payload: Vec<u8> = expected_payload();
    assert_eq!(
        single_output(&result, &out),
        concatenated(&payload, &payload)
    );
}

#[test]
fn concatenated_bzip2_streams_all_decode() {
    let payload: Vec<u8> = expected_payload();
    let tail: &[u8] = b"a second bzip2 stream written by another encoder run\n";
    let bytes: Vec<u8> = concatenated(&load("payload.bz2"), &bzip2_stream(tail));
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("bz2-multi");
    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult =
        extract_to(ContainerKind::Bzip2, &bytes, &out).expect("extract concatenated bz2");
    assert_eq!(single_output(&result, &out), concatenated(&payload, tail));
}

#[test]
fn concatenated_xz_streams_all_decode() {
    let payload: Vec<u8> = expected_payload();
    let (head, tail): (&[u8], &[u8]) = payload.split_at(payload.len() / 3);
    let bytes: Vec<u8> = concatenated(&xz_stream(head), &xz_stream(tail));
    assert_eq!(detect_container(&bytes), Some(ContainerKind::Xz));
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("xz-multi");
    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult =
        extract_to_with_quota(ContainerKind::Xz, &bytes, &out, text_ratio_quota())
            .expect("extract concatenated xz");
    assert_eq!(single_output(&result, &out), payload);
}

fn two_member_tar() -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
    let payload: Vec<u8> = expected_payload();
    let members: Vec<(String, Vec<u8>)> = vec![
        ("head.bin".to_owned(), payload),
        (
            "tail.txt".to_owned(),
            b"the member stored after the split point\n".repeat(40),
        ),
    ];
    let mut builder: tar::Builder<Vec<u8>> = tar::Builder::new(Vec::new());
    for (name, body) in &members {
        let mut header: tar::Header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, name, body.as_slice())
            .expect("append tar member");
    }
    (builder.into_inner().expect("finish tar"), members)
}

#[test]
fn compressed_tar_split_across_concatenated_streams_extracts_every_member() {
    let (tar_bytes, members): (Vec<u8>, Vec<(String, Vec<u8>)>) = two_member_tar();
    let (head, tail): (&[u8], &[u8]) = tar_bytes.split_at(tar_bytes.len() / 2);
    let cases: [(ContainerKind, Vec<u8>); 3] = [
        (
            ContainerKind::TarGz,
            concatenated(&gzip_member(head), &gzip_member(tail)),
        ),
        (
            ContainerKind::TarBz2,
            concatenated(&bzip2_stream(head), &bzip2_stream(tail)),
        ),
        (
            ContainerKind::TarXz,
            concatenated(&xz_stream(head), &xz_stream(tail)),
        ),
    ];
    for (kind, bytes) in cases {
        let scratch: disrobe_core::scratch::ScratchDir =
            temp_dir(&format!("split-{}", kind.label()));
        let out: PathBuf = scratch.path().to_path_buf();
        let result: ExtractionResult = extract_to(kind, &bytes, &out)
            .unwrap_or_else(|e: disrobe_binfmt::Error| panic!("{kind:?}: {e}"));
        for (name, body) in &members {
            let got: Vec<u8> = std::fs::read(out.join(name))
                .unwrap_or_else(|e: std::io::Error| panic!("{kind:?}: read {name}: {e}"));
            assert_eq!(
                &got, body,
                "{kind:?}: {name} differs from the archived bytes"
            );
        }
        assert_eq!(result.entries.len(), members.len(), "{kind:?}");
    }
}
