#![allow(clippy::expect_used)]

use std::io::Read;
use std::path::PathBuf;

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::parse_lzh;
use disrobe_binfmt::{ExtractionQuota, ExtractionResult, extract_to, extract_to_with_quota};

const LEVEL3_LONG_NAME: &[u8] = include_bytes!("fixtures/lzh/level3/h3_lfn.lzh");
const LEVEL3_LH0: &[u8] = include_bytes!("fixtures/lzh/level3/h3_lh0.lzh");
const LEVEL3_LH5: &[u8] = include_bytes!("fixtures/lzh/level3/h3_lh5.lzh");
const LEVEL3_SUBDIRECTORY: &[u8] = include_bytes!("fixtures/lzh/level3/h3_subdir.lzh");
const UTF16_NAMES: &[u8] = include_bytes!("fixtures/lzh/encoding/filename_utf16.lzh");
const CP932_NAMES: &[u8] = include_bytes!("fixtures/lzh/encoding/filename_cp932.lzh");
const HEADER_LEVEL1: &[u8] = include_bytes!("fixtures/lzh/levels/h1_lh0.lzh");

const METHOD_FIXTURES: [(&[u8], &str, u64, u32); 9] = [
    (
        include_bytes!("fixtures/lzh/methods/lh1.lzh"),
        "-lh1-",
        18_092,
        0x4e46_f4a1,
    ),
    (
        include_bytes!("fixtures/lzh/methods/lh4.lzh"),
        "-lh4-",
        18_092,
        0x4e46_f4a1,
    ),
    (
        include_bytes!("fixtures/lzh/methods/lh6.lzh"),
        "-lh6-",
        18_092,
        0x4e46_f4a1,
    ),
    (
        include_bytes!("fixtures/lzh/methods/lh7.lzh"),
        "-lh7-",
        18_092,
        0x4e46_f4a1,
    ),
    (
        include_bytes!("fixtures/lzh/methods/lhx.lzh"),
        "-lhx-",
        18_092,
        0x4e46_f4a1,
    ),
    (
        include_bytes!("fixtures/lzh/methods/lz4.lzs"),
        "-lz4-",
        6_829,
        0xe469_0583,
    ),
    (
        include_bytes!("fixtures/lzh/methods/lz5.lzs"),
        "-lz5-",
        18_092,
        0x4e46_f4a1,
    ),
    (
        include_bytes!("fixtures/lzh/methods/lzs.lzs"),
        "-lzs-",
        18_092,
        0x4e46_f4a1,
    ),
    (
        include_bytes!("fixtures/lzh/methods/pm0.pma"),
        "-pm0-",
        6_912,
        0x549d_935a,
    ),
];

fn extract(bytes: &[u8], tag: &str) -> (disrobe_core::scratch::ScratchDir, ExtractionResult) {
    assert_eq!(detect_container(bytes), Some(ContainerKind::Lzh));
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(tag).expect("create scratch directory");
    let result: ExtractionResult =
        extract_to(ContainerKind::Lzh, bytes, scratch.path()).expect("extract level-3 LZH archive");
    assert!(result.integrity_violations.is_empty());
    (scratch, result)
}

fn lha_crc16(data: &[u8]) -> u16 {
    data.iter().fold(0u16, |mut crc: u16, byte: &u8| {
        crc ^= u16::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ 0xa001
            };
        }
        crc
    })
}

fn level2_member_with_mode(archive: &[u8], name: [u8; 5], mode: u16, method: [u8; 5]) -> Vec<u8> {
    let mut member: Vec<u8> = archive.to_vec();
    let header_end: usize = usize::from(u16::from_le_bytes([member[0], member[1]]));
    let mut cursor: usize = 26;
    let mut length: usize = usize::from(u16::from_le_bytes([member[24], member[25]]));
    let mut common_crc_at: Option<usize> = None;
    let mut last_link_at: Option<usize> = None;
    let mut name_at: Option<usize> = None;
    while length != 0 {
        let kind: u8 = member[cursor];
        if kind == 0x00 {
            common_crc_at = Some(cursor + 1);
        }
        if kind == 0x01 && length == 8 {
            name_at = Some(cursor + 1);
        }
        let link_at: usize = cursor + length - 2;
        let next: usize = usize::from(u16::from_le_bytes([member[link_at], member[link_at + 1]]));
        if next == 0 {
            last_link_at = Some(link_at);
        }
        cursor += length;
        length = next;
    }
    let common_crc_at: usize = common_crc_at.expect("level-2 common CRC header");
    let last_link_at: usize = last_link_at.expect("level-2 final extended-header link");
    let name_at: usize = name_at.expect("level-2 filename header");
    member[2..7].copy_from_slice(&method);
    member[name_at..name_at + name.len()].copy_from_slice(&name);
    member[last_link_at..last_link_at + 2].copy_from_slice(&5u16.to_le_bytes());
    let mode_bytes: [u8; 2] = mode.to_le_bytes();
    member.splice(
        header_end..header_end,
        [0x50, mode_bytes[0], mode_bytes[1], 0, 0],
    );
    let new_header_end: usize = header_end + 5;
    member[0..2].copy_from_slice(
        &u16::try_from(new_header_end)
            .expect("bounded level-2 header")
            .to_le_bytes(),
    );
    member[common_crc_at..common_crc_at + 2].fill(0);
    let common_crc: [u8; 2] = lha_crc16(&member[..new_header_end]).to_le_bytes();
    member[common_crc_at..common_crc_at + 2].copy_from_slice(&common_crc);
    member
}

fn concatenate_members(first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut archive: Vec<u8> = first[..first.len() - 1].to_vec();
    archive.extend_from_slice(second);
    archive
}

#[test]
fn level3_long_name_extracts_through_the_public_caller() {
    let (scratch, result): (disrobe_core::scratch::ScratchDir, ExtractionResult) =
        extract(LEVEL3_LONG_NAME, "disrobe-lzh-level3-long-name");
    let output: PathBuf = scratch.path().to_path_buf();
    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.entries[0].name, "Long Filename.txt");
    assert_eq!(result.entries[0].uncompressed_size, 14);
    assert_eq!(
        std::fs::read(output.join("Long Filename.txt")).expect("read extracted member"),
        b"hello world!\r\n"
    );
}

#[test]
fn level3_lh5_matches_the_reference_stored_member() {
    let (stored_scratch, stored_result): (disrobe_core::scratch::ScratchDir, ExtractionResult) =
        extract(LEVEL3_LH0, "disrobe-lzh-level3-lh0");
    let (compressed_scratch, compressed_result): (
        disrobe_core::scratch::ScratchDir,
        ExtractionResult,
    ) = extract(LEVEL3_LH5, "disrobe-lzh-level3-lh5");
    assert_eq!(stored_result.entries.len(), 1);
    assert_eq!(compressed_result.entries.len(), 1);
    assert_eq!(stored_result.entries[0].name, "GPL-2.gz");
    assert_eq!(compressed_result.entries[0].name, "GPL-2");
    let stored: Vec<u8> =
        std::fs::read(stored_scratch.path().join("GPL-2.gz")).expect("read stored member");
    let mut reference: Vec<u8> = Vec::new();
    let _: usize = flate2::read::GzDecoder::new(stored.as_slice())
        .read_to_end(&mut reference)
        .expect("decode independent gzip member");
    assert_eq!(
        reference,
        std::fs::read(compressed_scratch.path().join("GPL-2")).expect("read compressed member")
    );
}

#[test]
fn level3_directories_reconstruct_the_nested_member_path() {
    let (scratch, result): (disrobe_core::scratch::ScratchDir, ExtractionResult) =
        extract(LEVEL3_SUBDIRECTORY, "disrobe-lzh-level3-subdirectory");
    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.entries[0].name, "subdir/subdir2/HELLO.TXT");
    assert_eq!(
        std::fs::read(scratch.path().join("subdir/subdir2/HELLO.TXT")).expect("read nested member"),
        b"hello world!\r\n"
    );
}

#[test]
fn level3_common_crc_corruption_is_rejected() {
    let mut damaged: Vec<u8> = LEVEL3_LONG_NAME.to_vec();
    damaged[33] ^= 0x01;
    let error: disrobe_binfmt::Error =
        parse_lzh(&damaged, 1024).expect_err("reject invalid common-header CRC");
    assert!(error.to_string().contains("header CRC-16"));
}

#[test]
fn level0_and_level1_header_sum_corruption_is_rejected() {
    for archive in [METHOD_FIXTURES[5].0, HEADER_LEVEL1] {
        let mut damaged: Vec<u8> = archive.to_vec();
        damaged[1] ^= 0x01;
        let error: disrobe_binfmt::Error =
            parse_lzh(&damaged, 16 * 1024).expect_err("reject invalid header sum");
        assert!(
            error.to_string().contains("header level checksum"),
            "unexpected header-sum error: {error}"
        );
    }
}

#[test]
fn level1_extended_header_size_underflow_is_rejected() {
    let mut damaged: Vec<u8> = HEADER_LEVEL1.to_vec();
    damaged[7..11].copy_from_slice(&4u32.to_le_bytes());
    damaged[33..35].copy_from_slice(&5u16.to_le_bytes());
    damaged.splice(35..35, [0x01, 0, 0, 0, 0]);
    damaged[1] = damaged[2..35]
        .iter()
        .fold(0u8, |sum: u8, byte: &u8| sum.wrapping_add(*byte));
    let error: disrobe_binfmt::Error =
        parse_lzh(&damaged, 16 * 1024).expect_err("reject level-1 size underflow");
    assert!(
        error.to_string().contains("wrong header size"),
        "unexpected level-1 underflow error: {error}"
    );
}

#[test]
fn level3_header_extent_is_bounded_before_dependency_parsing() {
    let mut oversized: Vec<u8> = LEVEL3_LONG_NAME.to_vec();
    oversized[24..28].copy_from_slice(&1_048_577u32.to_le_bytes());
    let error: disrobe_binfmt::Error =
        parse_lzh(&oversized, 1024).expect_err("reject oversized level-3 header");
    assert!(
        error
            .to_string()
            .contains("header extent 1048577 exceeds cap 1048576")
    );
}

#[test]
fn level3_truncated_header_is_rejected() {
    let error: disrobe_binfmt::Error =
        parse_lzh(&LEVEL3_LONG_NAME[..81], 1024).expect_err("reject truncated level-3 header");
    assert!(error.to_string().contains("header runs past end"));
}

#[test]
fn level3_truncated_body_and_corrupt_member_crc_are_rejected() {
    let truncated: &[u8] = &LEVEL3_LONG_NAME[..LEVEL3_LONG_NAME.len() - 2];
    let error: disrobe_binfmt::Error =
        parse_lzh(truncated, 1024).expect_err("reject truncated member body");
    assert!(error.to_string().contains("member body runs past end"));

    let mut damaged: Vec<u8> = LEVEL3_LONG_NAME.to_vec();
    damaged[82] ^= 0x01;
    let error: disrobe_binfmt::Error =
        parse_lzh(&damaged, 1024).expect_err("reject corrupt member body CRC");
    assert!(
        error.to_string().contains("crc16 mismatch"),
        "unexpected member CRC error: {error}"
    );
}

#[test]
fn level3_member_quota_refuses_before_output_creation() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-lzh-level3-quota")
            .expect("create quota output directory");
    let error: disrobe_binfmt::Error = extract_to_with_quota(
        ContainerKind::Lzh,
        LEVEL3_LONG_NAME,
        scratch.path(),
        ExtractionQuota {
            max_entries: 8,
            max_total_uncompressed: 13,
            max_per_entry_uncompressed: 13,
            max_per_entry_ratio: 100,
            max_aggregate_ratio: 100,
        },
    )
    .expect_err("reject member beyond caller quota");
    assert!(
        error.to_string().contains("per-entry cap 13"),
        "unexpected quota error: {error}"
    );
    assert_eq!(
        std::fs::read_dir(scratch.path())
            .expect("read quota output directory")
            .count(),
        0
    );
}

#[test]
fn level3_expansion_ratio_refuses_before_output_creation() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-lzh-level3-ratio")
            .expect("create ratio output directory");
    let error: disrobe_binfmt::Error = extract_to_with_quota(
        ContainerKind::Lzh,
        LEVEL3_LH5,
        scratch.path(),
        ExtractionQuota {
            max_entries: 8,
            max_total_uncompressed: 1 << 20,
            max_per_entry_uncompressed: 1 << 20,
            max_per_entry_ratio: 1,
            max_aggregate_ratio: 1,
        },
    )
    .expect_err("reject expansion ratio");
    assert!(
        error
            .to_string()
            .contains("per-entry expansion ratio 2 exceeds cap 1"),
        "unexpected ratio error: {error}"
    );
    assert_eq!(
        std::fs::read_dir(scratch.path())
            .expect("read ratio output directory")
            .count(),
        0
    );
}

#[test]
fn hostile_and_colliding_paths_refuse_before_output_creation() {
    let mut hostile: Vec<u8> = METHOD_FIXTURES[5].0.to_vec();
    hostile[22..30].copy_from_slice(b"../a.txt");
    hostile[1] = hostile[2..32]
        .iter()
        .fold(0u8, |sum: u8, byte: &u8| sum.wrapping_add(*byte));
    let hostile_output: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-lzh-hostile-path")
            .expect("create hostile-path output");
    let result: ExtractionResult = extract_to(ContainerKind::Lzh, &hostile, hostile_output.path())
        .expect("report hostile LZH path without partial output");
    assert!(result.entries.is_empty());
    assert!(
        result.integrity_violations.len() == 1
            && result.integrity_violations[0].contains("lzh-slip")
            && result.integrity_violations[0].contains("escapes container root"),
        "{:?}",
        result.integrity_violations
    );
    assert_eq!(
        std::fs::read_dir(hostile_output.path())
            .expect("read hostile-path output")
            .count(),
        0
    );

    let lower: Vec<u8> =
        level2_member_with_mode(METHOD_FIXTURES[2].0, *b"case1", 0o100_644, *b"-lh6-");
    let upper: Vec<u8> =
        level2_member_with_mode(METHOD_FIXTURES[2].0, *b"CASE1", 0o100_644, *b"-lh6-");
    let mut duplicate: Vec<u8> = concatenate_members(&lower, &upper);
    let first_body: usize = usize::from(u16::from_le_bytes([duplicate[0], duplicate[1]]));
    duplicate[first_body] ^= 0xff;
    let duplicate_output: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-lzh-duplicate-path")
            .expect("create duplicate-path output");
    let error: disrobe_binfmt::Error =
        extract_to(ContainerKind::Lzh, &duplicate, duplicate_output.path())
            .expect_err("reject duplicate LZH path");
    assert!(
        error
            .to_string()
            .contains("duplicate normalized output path"),
        "{error}"
    );
    assert_eq!(
        std::fs::read_dir(duplicate_output.path())
            .expect("read duplicate-path output")
            .count(),
        0
    );
}

#[test]
fn unix_modes_reach_the_public_executable_flag() {
    let executable: Vec<u8> =
        level2_member_with_mode(METHOD_FIXTURES[2].0, *b"runme", 0o100_755, *b"-lh6-");
    let ordinary: Vec<u8> =
        level2_member_with_mode(METHOD_FIXTURES[2].0, *b"data1", 0o100_644, *b"-lh6-");
    let archive: Vec<u8> = concatenate_members(&executable, &ordinary);
    let (_, result): (disrobe_core::scratch::ScratchDir, ExtractionResult) =
        extract(&archive, "disrobe-lzh-unix-mode");
    assert_eq!(result.entries.len(), 2);
    assert_eq!(result.entries[0].name, "runme");
    assert!(result.entries[0].is_executable);
    assert_eq!(result.entries[1].name, "data1");
    assert!(!result.entries[1].is_executable);
}

#[test]
fn symlink_shaped_lhd_member_refuses_before_output_creation() {
    let symlink: Vec<u8> =
        level2_member_with_mode(METHOD_FIXTURES[2].0, *b"link1", 0o120_777, *b"-lhd-");
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-lzh-symlink")
            .expect("create symlink output");
    let error: disrobe_binfmt::Error = extract_to(ContainerKind::Lzh, &symlink, scratch.path())
        .expect_err("refuse symbolic-link LHD member");
    assert!(error.to_string().contains("symbolic link"), "{error}");
    assert_eq!(
        std::fs::read_dir(scratch.path())
            .expect("read symlink output")
            .count(),
        0
    );
}

#[test]
fn a_mislabelled_pm1_or_pm2_member_is_refused_without_partial_output() {
    let expected: [(&[u8; 5], &str); 2] = [
        (
            b"-pm1-",
            "-pm1- copy distance 14 exceeds the 10 byte(s) produced",
        ),
        (b"-pm2-", "decoded CRC 34c1 differs from declared CRC b6d5"),
    ];
    for (method, message) in expected {
        let mut archive: Vec<u8> = METHOD_FIXTURES[5].0.to_vec();
        archive[2..7].copy_from_slice(method);
        let header_end: usize = usize::from(archive[0]) + 2;
        archive[1] = archive[2..header_end]
            .iter()
            .fold(0u8, |sum: u8, byte: &u8| sum.wrapping_add(*byte));
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("disrobe-lzh-pm-mislabelled")
                .expect("create PM output");
        let error: disrobe_binfmt::Error = extract_to(ContainerKind::Lzh, &archive, scratch.path())
            .expect_err("refuse a member whose body is not a PMarc stream");
        assert!(error.to_string().contains(message), "{error}");
        assert_eq!(
            std::fs::read_dir(scratch.path())
                .expect("read PM output")
                .count(),
            0
        );
    }
}

#[test]
fn every_declared_method_matches_the_lhasa_reference_output()
-> Result<(), Box<dyn std::error::Error>> {
    for (archive, expected_method, expected_size, expected_crc32) in METHOD_FIXTURES {
        let parsed: disrobe_binfmt::containers::lzh::LzhArchive =
            disrobe_binfmt::containers::lzh::parse_lzh(archive, 1 << 20)?;
        let file: &disrobe_binfmt::containers::lzh::LzhFile = parsed
            .files
            .iter()
            .find(|file| !file.is_directory)
            .ok_or_else(|| std::io::Error::other(format!("{expected_method}: missing file")))?;
        assert_eq!(file.method, expected_method);
        assert!(file.decoder_supported, "{expected_method}");
        assert_eq!(file.original_size, expected_size, "{expected_method}");
        assert_eq!(file.data.len() as u64, expected_size, "{expected_method}");
        assert_eq!(
            crc32fast::hash(&file.data),
            expected_crc32,
            "{expected_method}"
        );
    }
    Ok(())
}

#[test]
fn real_archives_grade_every_declared_header_level() -> Result<(), Box<dyn std::error::Error>> {
    let archives: [(&[u8], u8); 4] = [
        (METHOD_FIXTURES[0].0, 0),
        (HEADER_LEVEL1, 1),
        (METHOD_FIXTURES[2].0, 2),
        (LEVEL3_LONG_NAME, 3),
    ];
    for (archive, expected_level) in archives {
        let parsed: disrobe_binfmt::containers::lzh::LzhArchive = parse_lzh(archive, 1 << 20)?;
        let file: &disrobe_binfmt::containers::lzh::LzhFile = parsed
            .files
            .iter()
            .find(|file| !file.is_directory)
            .ok_or_else(|| {
                std::io::Error::other(format!("level {expected_level}: missing file"))
            })?;
        assert_eq!(file.header_level, expected_level);
    }
    let level1: disrobe_binfmt::containers::lzh::LzhArchive = parse_lzh(HEADER_LEVEL1, 1 << 20)?;
    let file: &disrobe_binfmt::containers::lzh::LzhFile = level1
        .files
        .first()
        .ok_or("level-1 fixture contained no files")?;
    assert_eq!(file.path, "gpl-2.gz");
    assert_eq!(file.original_size, 6_829);
    assert_eq!(crc32fast::hash(&file.data), 0xe469_0583);
    Ok(())
}

#[test]
fn unicode_name_extensions_reconstruct_the_reference_paths()
-> Result<(), Box<dyn std::error::Error>> {
    let archive: disrobe_binfmt::containers::lzh::LzhArchive = parse_lzh(UTF16_NAMES, 1 << 20)?;
    let paths: Vec<(&str, u64, bool)> = archive
        .files
        .iter()
        .map(|file| (file.path.as_str(), file.original_size, file.is_directory))
        .collect();
    assert_eq!(
        paths,
        vec![
            ("ÜÖÄüöä/äöüÄÖÜ.txt", 12, false),
            ("ÜÖÄüöä", 0, true),
            ("ÜÖÄüöä/テスト.txt", 25, false),
            ("テスト/äöüÄÖÜ.txt", 12, false),
            ("テスト", 0, true),
            ("äöüÄÖÜ.txt", 12, false),
        ]
    );
    assert!(
        archive
            .files
            .iter()
            .all(|file| file.is_directory || file.decoder_supported)
    );
    let (scratch, result): (disrobe_core::scratch::ScratchDir, ExtractionResult) =
        extract(UTF16_NAMES, "disrobe-lzh-utf16-names");
    assert_eq!(result.entries.len(), 4);
    assert_eq!(
        std::fs::read(scratch.path().join("テスト/äöüÄÖÜ.txt"))?.len(),
        12
    );
    Ok(())
}

#[test]
fn declared_cp932_names_decode_without_splitting_trail_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let archive: disrobe_binfmt::containers::lzh::LzhArchive = parse_lzh(CP932_NAMES, 1 << 20)?;
    let paths: Vec<(&str, u64)> = archive
        .files
        .iter()
        .map(|file| (file.path.as_str(), file.original_size))
        .collect();
    assert_eq!(paths, vec![("漢字.txt", 8), ("表.txt", 4)]);
    assert!(archive.files.iter().all(|file| file.decoder_supported));
    let (scratch, result): (disrobe_core::scratch::ScratchDir, ExtractionResult) =
        extract(CP932_NAMES, "disrobe-lzh-cp932-names");
    assert_eq!(result.entries.len(), 2);
    assert_eq!(std::fs::read(scratch.path().join("表.txt"))?.len(), 4);
    Ok(())
}
