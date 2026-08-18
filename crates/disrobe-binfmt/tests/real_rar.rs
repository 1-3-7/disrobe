#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::rar::{
    RarArchive, RarEntry, entry_bytes as rar_entry_bytes, parse_rar,
};
use disrobe_binfmt::{ExtractionResult, extract_to};

const EXPECTED: [(&str, &str); 3] = [
    ("hello.txt", "hello.txt"),
    ("lorem.txt", "lorem.txt"),
    ("docs/notes.txt", "docs/notes.txt"),
];

fn temp_dir(name: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-realrar-{name}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
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

    let scratch: disrobe_core::scratch::ScratchDir = temp_dir(tag);

    let out: PathBuf = scratch.path().to_path_buf();
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

    let scratch: disrobe_core::scratch::ScratchDir = temp_dir(tag);

    let out: PathBuf = scratch.path().to_path_buf();
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

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(bytes))
}

fn fixture(name: &str) -> Vec<u8> {
    let Some(bytes): Option<Vec<u8>> = common::load_fixture("rar", name) else {
        panic!(
            "missing committed fixture corpus/binfmt/rar/{name} - see corpus/binfmt/MANIFEST.toml"
        );
    };
    bytes
}

fn only_member(bytes: &[u8], fixture_name: &str) -> RarEntry {
    let archive: RarArchive = parse_rar(bytes).expect("parse rar");
    assert_eq!(archive.version, 4, "{fixture_name} is a rar4 container");
    let mut files: Vec<RarEntry> = archive
        .entries
        .into_iter()
        .filter(|entry: &RarEntry| !entry.is_dir)
        .collect();
    assert_eq!(files.len(), 1, "{fixture_name} holds exactly one member");
    files.remove(0)
}

fn assert_rar3_member_matches_reference(
    fixture_name: &str,
    member: &str,
    size: usize,
    sha256: &str,
    version: u8,
) {
    let bytes: Vec<u8> = fixture(fixture_name);
    assert_eq!(detect_container(&bytes), Some(ContainerKind::Rar));
    let entry: RarEntry = only_member(&bytes, fixture_name);
    assert_eq!(entry.name, member, "{fixture_name} member name");
    assert_eq!(
        entry.compression_version, version,
        "{fixture_name} unpack version"
    );
    let recovered: Vec<u8> = rar_entry_bytes(&bytes, &entry, 512 * 1024 * 1024)
        .unwrap_or_else(|e| panic!("recover {member} from {fixture_name}: {e}"));
    assert_eq!(recovered.len(), size, "{member} recovered length");
    assert_eq!(
        sha256_hex(&recovered),
        sha256,
        "{member} recovered from {fixture_name} must match the bytes 7-Zip 25.01 extracts from the same archive"
    );
}

#[test]
fn rar3_canonical_filter_member_matches_the_independent_extraction() {
    assert_rar3_member_matches_reference(
        "filter-e8-rar3.rar",
        "bsdcat.exe",
        204_288,
        "a961532b3a196e0b2c0126ad6f35d511c9fdfeadacbe78a1b15dc221251ad9a2",
        29,
    );
}

#[test]
fn rar3_mixed_ppmd_and_lz_member_matches_the_independent_extraction() {
    assert_rar3_member_matches_reference(
        "mixed-ppmd-lz-rar3.rar",
        "ppmd_lzss_conversion_test.txt",
        241_647_978,
        "a0b8a5130c56577e61620f3f51ae29478a4c5251f1ed575cec73455fc9b485ea",
        29,
    );
}

#[test]
fn rar3_multiblock_lz_member_matches_the_independent_extraction() {
    assert_rar3_member_matches_reference(
        "multiblock-lz-rar3.rar",
        "multi_lzss_blocks_test.txt",
        20_131_111,
        "49a84a381599f749f93beaf486f3d661883d45659d9f46bfde9d34f72644f208",
        29,
    );
}

#[test]
fn rar3_low_distance_repeat_state_resets_with_each_table() {
    assert_rar3_member_matches_reference(
        "lowdist-reset-rar3.rar",
        "lowdist-reset.bin",
        64,
        "353d5f7a0789034186922e5834f666f36fa1f98e18f53fb4140b336ba090a923",
        29,
    );
}

#[test]
fn rar3_filter_member_reaches_disk_through_container_extraction() {
    let bytes: Vec<u8> = fixture("filter-e8-rar3.rar");
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("filter-e8-rar3");
    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult =
        extract_to(ContainerKind::Rar, &bytes, &out).expect("extract rar3 filter archive");
    assert!(
        result.integrity_violations.is_empty(),
        "filter-e8-rar3.rar extraction reported violations: {:?}",
        result.integrity_violations
    );
    let written: Vec<u8> =
        std::fs::read(out.join("bsdcat.exe")).expect("read recovered bsdcat.exe");
    assert_eq!(
        sha256_hex(&written),
        "a961532b3a196e0b2c0126ad6f35d511c9fdfeadacbe78a1b15dc221251ad9a2"
    );
}

#[test]
fn a_flipped_byte_in_a_stored_member_is_refused_by_its_declared_crc() {
    let mut bytes: Vec<u8> = fixture("store-rar4.rar");
    let archive: RarArchive = parse_rar(&bytes).expect("parse store-rar4");
    let entry: RarEntry = archive
        .entries
        .into_iter()
        .find(|candidate: &RarEntry| candidate.name == "lorem.txt")
        .expect("store-rar4 holds lorem.txt");
    let clean: Vec<u8> =
        rar_entry_bytes(&bytes, &entry, 64 * 1024 * 1024).expect("recover the intact member");
    assert_eq!(clean.len() as u64, entry.unpacked_size);

    let target: usize = entry.data_offset as usize + 16;
    bytes[target] ^= 0x40;
    let error: String = rar_entry_bytes(&bytes, &entry, 64 * 1024 * 1024)
        .expect_err("a flipped payload byte must be refused")
        .to_string();
    assert!(
        error.contains("crc32") && error.contains("archive header declares"),
        "the refusal must name the crc mismatch: {error}"
    );
}

#[test]
fn a_flipped_byte_in_the_rar3_filter_stream_is_refused_rather_than_published() {
    let mut bytes: Vec<u8> = fixture("filter-e8-rar3.rar");
    let entry: RarEntry = only_member(&bytes, "filter-e8-rar3.rar");
    let target: usize = entry.data_offset as usize + 4_096;
    bytes[target] ^= 0x01;
    let outcome: Result<Vec<u8>, disrobe_binfmt::Error> =
        rar_entry_bytes(&bytes, &entry, 512 * 1024 * 1024);
    assert!(
        outcome.is_err(),
        "a flipped byte inside the filtered lz stream must not produce a published member"
    );
}
