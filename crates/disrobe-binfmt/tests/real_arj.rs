#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::{ArjArchive, ArjEntry, arj_entry_bytes, parse_arj};
use disrobe_binfmt::quota::ExtractionQuota;
use disrobe_binfmt::{ExtractionResult, extract_to, extract_to_with_quota};
use disrobe_core::codec::crc32_ieee;
use sha2::{Digest, Sha256};

const MEMBERS: [&str; 5] = [
    "empty.dat",
    "hello.txt",
    "readme.txt",
    "tiers.bin",
    "sub/nested.txt",
];

const MEMBER_SHA256: [(&str, &str); 5] = [
    (
        "empty.dat",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "hello.txt",
        "a0e085fe8606ece4101eddbfa1ee15dc9d63bac2475031cf868d5198ab26c5e8",
    ),
    (
        "readme.txt",
        "1999813e129a943062d59d8bdce0e906bb0da5bf272d11b095e90adb657edfd2",
    ),
    (
        "sub/nested.txt",
        "bd7245820c5d5a8478f8fa113d21bedb3bbe4cc1bb14427afbc70062f61a3776",
    ),
    (
        "tiers.bin",
        "d5d4dff0fde7b22913c963dc826194a5405c5016a14b2833d55c606705f8b201",
    ),
];

const MEMBER_CRC32: [(&str, u32); 5] = [
    ("empty.dat", 0x0000_0000),
    ("hello.txt", 0x3F82_C735),
    ("readme.txt", 0x539B_72B0),
    ("sub/nested.txt", 0x12AC_4CF8),
    ("tiers.bin", 0x46B5_7FA3),
];

const MEMBER_COMPRESSED: [[u32; 5]; 5] = [
    [0, 26, 2088, 27_744, 552],
    [0, 26, 228, 21_527, 54],
    [0, 26, 228, 21_527, 54],
    [0, 26, 229, 21_527, 54],
    [0, 26, 301, 24_752, 53],
];

const MEMBER_ORIGINAL_SIZE: [(&str, u32); 5] = [
    ("empty.dat", 0),
    ("hello.txt", 26),
    ("readme.txt", 2088),
    ("sub/nested.txt", 552),
    ("tiers.bin", 27_744),
];

fn fixture(name: &str) -> Vec<u8> {
    common::load_fixture("arj", name)
        .unwrap_or_else(|| panic!("missing fixture corpus/binfmt/arj/{name}"))
}

fn expected(member: &str) -> Vec<u8> {
    let path: PathBuf = common::corpus_binfmt_root()
        .join("arj")
        .join("expected")
        .join(member);
    std::fs::read(&path).unwrap_or_else(|_| panic!("read corpus/binfmt/arj/expected/{member}"))
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    digest
        .iter()
        .fold(String::new(), |mut acc: String, b: &u8| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

fn lookup<T: Copy>(table: &[(&str, T)], member: &str) -> T {
    table
        .iter()
        .find(|(name, _): &&(&str, T)| *name == member)
        .map_or_else(
            || panic!("no table row for {member}"),
            |(_, value): &(&str, T)| *value,
        )
}

fn method_of(member: &str, declared: u8) -> u8 {
    if member == "empty.dat" || member == "hello.txt" {
        0
    } else {
        declared
    }
}

#[test]
fn real_arj_methods_zero_through_four_recover_committed_plaintext() {
    for declared in 0u8..=4 {
        let name: String = format!("method{declared}.arj");
        let bytes: Vec<u8> = fixture(&name);
        assert_eq!(
            detect_container(&bytes),
            Some(ContainerKind::Arj),
            "{name} must detect as ARJ"
        );
        let archive: ArjArchive = parse_arj(&bytes).unwrap_or_else(|e| panic!("parse {name}: {e}"));
        assert_eq!(archive.archiver_version, 11, "{name} archiver version");
        assert_eq!(archive.min_version, 1, "{name} minimum extract version");
        assert_eq!(archive.host_os, 2, "{name} host os must be UNIX");
        assert!(!archive.multivolume, "{name} must be single volume");
        let names: Vec<&str> = archive
            .entries
            .iter()
            .map(|entry: &ArjEntry| entry.name.as_str())
            .collect();
        assert_eq!(names, MEMBERS, "{name} member order and stored names");
        for (index, entry) in archive.entries.iter().enumerate() {
            let member: &str = entry.name.as_str();
            assert_eq!(
                entry.compressed_size,
                MEMBER_COMPRESSED[usize::from(declared)][index],
                "{name}: {member} compressed size"
            );
            assert_eq!(
                entry.method,
                method_of(member, declared),
                "{name}: member {member} method"
            );
            assert_eq!(entry.archiver_version, 11, "{name}: {member} version");
            assert_eq!(entry.min_version, 1, "{name}: {member} minimum version");
            assert_eq!(
                entry.original_size,
                lookup(&MEMBER_ORIGINAL_SIZE, member),
                "{name}: {member} original size"
            );
            assert_eq!(
                entry.crc32,
                lookup(&MEMBER_CRC32, member),
                "{name}: {member} stored crc32"
            );
            assert!(!entry.encrypted, "{name}: {member} must not be garbled");
            assert!(!entry.split, "{name}: {member} must not be split");
            assert!(!entry.is_directory, "{name}: {member} must be a file entry");
            let data: Vec<u8> = arj_entry_bytes(&bytes, entry, u64::MAX)
                .unwrap_or_else(|e| panic!("{name}: decode {member}: {e}"));
            assert_eq!(
                data,
                expected(member),
                "{name}: {member} must match the committed plaintext byte for byte"
            );
            assert_eq!(
                hex_sha256(&data),
                lookup(&MEMBER_SHA256, member),
                "{name}: {member} sha-256"
            );
        }
    }
}

#[test]
fn real_arj_stored_and_compressed_members_reach_disk_extraction() {
    for declared in 0u8..=4 {
        let name: String = format!("method{declared}.arj");
        let bytes: Vec<u8> = fixture(&name);
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create(&format!("disrobe-arj-{declared}"))
                .expect("create scratch directory");
        let out: PathBuf = scratch.path().to_path_buf();
        let result: ExtractionResult = extract_to(ContainerKind::Arj, &bytes, &out)
            .unwrap_or_else(|e| panic!("extract {name}: {e}"));
        assert!(
            result.integrity_violations.is_empty(),
            "{name} violations: {:?}",
            result.integrity_violations
        );
        for member in MEMBERS {
            let got: Vec<u8> = std::fs::read(out.join(member))
                .unwrap_or_else(|_| panic!("{name}: member {member} not written"));
            assert_eq!(got, expected(member), "{name}: {member} on disk");
        }
    }
}

#[test]
fn real_arj_directory_entries_are_typed_and_created() {
    let bytes: Vec<u8> = fixture("directories.arj");
    let archive: ArjArchive = parse_arj(&bytes).expect("parse directories.arj");
    let directories: Vec<&str> = archive
        .entries
        .iter()
        .filter(|entry: &&ArjEntry| entry.is_directory)
        .map(|entry: &ArjEntry| entry.name.as_str())
        .collect();
    assert_eq!(
        directories,
        vec!["emptydir", "sub"],
        "ARJ directory members must be typed as directories"
    );
    for entry in archive
        .entries
        .iter()
        .filter(|e: &&ArjEntry| e.is_directory)
    {
        assert_eq!(entry.file_type, 3, "directory file type");
        assert_eq!(entry.original_size, 0, "directory original size");
    }
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-arj-dirs")
            .expect("create scratch directory");
    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult =
        extract_to(ContainerKind::Arj, &bytes, &out).expect("extract directories.arj");
    assert!(
        result.integrity_violations.is_empty(),
        "violations: {:?}",
        result.integrity_violations
    );
    assert!(out.join("emptydir").is_dir(), "emptydir must be created");
    assert_eq!(
        std::fs::read(out.join("sub/nested.txt")).expect("nested member"),
        expected("sub/nested.txt")
    );
}

#[test]
fn real_arj_garbled_member_names_the_missing_key() {
    let bytes: Vec<u8> = fixture("garbled.arj");
    let archive: ArjArchive = parse_arj(&bytes).expect("parse garbled.arj");
    assert_eq!(archive.entries.len(), 1);
    let entry: &ArjEntry = &archive.entries[0];
    assert!(entry.encrypted, "garbled member must report encryption");
    assert_eq!(entry.method, 4);
    let error: String = arj_entry_bytes(&bytes, entry, u64::MAX)
        .expect_err("garbled member must not decode")
        .to_string();
    assert!(
        error.contains("password-garbled") && error.contains("no key"),
        "unexpected error: {error}"
    );
}

#[test]
fn real_arj_rejects_header_corruption_truncation_and_body_mutation() {
    let original: Vec<u8> = fixture("method4.arj");
    let archive: ArjArchive = parse_arj(&original).expect("parse method4.arj");

    let mut main_header: Vec<u8> = original.clone();
    main_header[4 + 3] ^= 0x40;
    let main_error: String = parse_arj(&main_header)
        .expect_err("corrupt main header must fail")
        .to_string();
    assert!(
        main_error.contains("basic header crc32 mismatch"),
        "unexpected main header error: {main_error}"
    );

    let local_offset: usize = usize::from(u16::from_le_bytes([original[2], original[3]])) + 10;
    let mut local_header: Vec<u8> = original.clone();
    local_header[local_offset + 5] = 7;
    let local_error: String = parse_arj(&local_header)
        .expect_err("corrupt local header must fail")
        .to_string();
    assert!(
        local_error.contains("basic header crc32 mismatch"),
        "unexpected local header error: {local_error}"
    );

    let truncated: &[u8] = &original[..original.len() - 1];
    assert!(
        parse_arj(truncated).is_err(),
        "an archive missing its last byte must not parse"
    );

    let tiers: &ArjEntry = archive
        .entries
        .iter()
        .find(|entry: &&ArjEntry| entry.name == "tiers.bin")
        .expect("tiers.bin member");
    let mut flipped: Vec<u8> = original.clone();
    flipped[tiers.data_offset + 64] ^= 0x01;
    let flipped_archive: ArjArchive = parse_arj(&flipped).expect("parse mutated body");
    let flipped_entry: &ArjEntry = flipped_archive
        .entries
        .iter()
        .find(|entry: &&ArjEntry| entry.name == "tiers.bin")
        .expect("mutated tiers.bin member");
    let body_error: String = arj_entry_bytes(&flipped, flipped_entry, u64::MAX)
        .expect_err("a mutated method 4 body must not publish bytes")
        .to_string();
    assert!(
        body_error.contains("crc32 mismatch")
            || body_error.contains("method 4")
            || body_error.contains("decoded to"),
        "unexpected body error: {body_error}"
    );

    let cap_error: String = arj_entry_bytes(&original, tiers, 1024)
        .expect_err("a member above the per-entry cap must be refused")
        .to_string();
    assert!(
        cap_error.contains("exceeding the per-entry extraction cap"),
        "unexpected cap error: {cap_error}"
    );
}

fn first_local_header(bytes: &[u8]) -> usize {
    let main_basic: usize = usize::from(u16::from_le_bytes([bytes[2], bytes[3]]));
    4 + main_basic + 4 + 2
}

fn reseal_block(bytes: &mut [u8], header_at: usize) {
    let basic: usize = usize::from(u16::from_le_bytes([
        bytes[header_at + 2],
        bytes[header_at + 3],
    ]));
    let block_start: usize = header_at + 4;
    let block_end: usize = block_start + basic;
    let crc: u32 = crc32_ieee(&bytes[block_start..block_end]);
    bytes[block_end..block_end + 4].copy_from_slice(&crc.to_le_bytes());
}

#[test]
fn real_arj_split_member_names_the_missing_volume() {
    let mut bytes: Vec<u8> = fixture("method1.arj");
    let header_at: usize = first_local_header(&bytes);
    bytes[header_at + 4 + 4] |= 0x08;
    reseal_block(&mut bytes, header_at);
    let archive: ArjArchive = parse_arj(&bytes).expect("parse resealed archive");
    let entry: &ArjEntry = &archive.entries[0];
    assert!(
        entry.split,
        "the EXTFILE flag must surface as a split member"
    );
    let error: String = arj_entry_bytes(&bytes, entry, u64::MAX)
        .expect_err("a split member must not publish bytes")
        .to_string();
    assert!(
        error.contains("continues across volumes"),
        "unexpected error: {error}"
    );
}

#[test]
fn real_arj_member_count_over_the_entry_cap_is_refused() {
    let bytes: Vec<u8> = fixture("method1.arj");
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-arj-entry-cap")
            .expect("create scratch directory");
    let refusal: Result<ExtractionResult, disrobe_binfmt::Error> = extract_to_with_quota(
        ContainerKind::Arj,
        &bytes,
        scratch.path(),
        ExtractionQuota {
            max_entries: 2,
            max_total_uncompressed: 1 << 20,
            max_per_entry_uncompressed: 1 << 20,
            max_per_entry_ratio: 1 << 10,
            max_aggregate_ratio: 1 << 10,
        },
    );
    let message: String = match refusal {
        Ok(result) => panic!(
            "a five-member archive must not extract under a two-entry cap: {:?}",
            result.integrity_violations
        ),
        Err(error) => error.to_string(),
    };
    assert!(
        message.contains("entry") && message.contains('2'),
        "the refusal must name the entry cap it enforced: {message}"
    );
}

#[test]
fn real_arj_expansion_ratio_is_enforced() {
    let bytes: Vec<u8> = fixture("method1.arj");
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-arj-ratio")
            .expect("create scratch directory");
    let result: ExtractionResult = extract_to_with_quota(
        ContainerKind::Arj,
        &bytes,
        scratch.path(),
        ExtractionQuota {
            max_entries: 64,
            max_total_uncompressed: 1 << 20,
            max_per_entry_uncompressed: 1 << 20,
            max_per_entry_ratio: 2,
            max_aggregate_ratio: 2,
        },
    )
    .expect("extract under a tight ratio quota");
    assert!(
        result
            .integrity_violations
            .iter()
            .any(|violation: &String| violation.starts_with("arj-quota `readme.txt`")),
        "the tight expansion ratio must refuse readme.txt: {:?}",
        result.integrity_violations
    );
    assert!(
        !scratch.path().join("readme.txt").exists(),
        "a quota-refused member must not reach disk"
    );
}

#[test]
fn real_arj_stored_member_sizes_must_agree() {
    let original: Vec<u8> = fixture("method0.arj");
    let archive: ArjArchive = parse_arj(&original).expect("parse method0.arj");
    let readme: &ArjEntry = archive
        .entries
        .iter()
        .find(|entry: &&ArjEntry| entry.name == "readme.txt")
        .expect("readme member");
    let mut forged: ArjEntry = readme.clone();
    forged.original_size = readme.original_size - 1;
    let error: String = arj_entry_bytes(&original, &forged, u64::MAX)
        .expect_err("a stored member with mismatched sizes must be refused")
        .to_string();
    assert!(
        error.contains("compressed and") && error.contains("original bytes"),
        "unexpected error: {error}"
    );
}
