#![allow(clippy::expect_used, clippy::panic)]

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::lzh::{LzhArchive, LzhFile, parse_lzh};
use disrobe_binfmt::containers::pmarc::{PmDecoded, PmMethod, decode_bounded};
use disrobe_binfmt::{ExtractionResult, extract_to};
use sha2::{Digest as _, Sha256};

const PMARC124_PM1: &[u8] = include_bytes!("../../../corpus/binfmt/lzh/pmarc/pmarc124_pm1.pma");
const PMARC124_PM1_LONG: &[u8] =
    include_bytes!("../../../corpus/binfmt/lzh/pmarc/pmarc124_pm1_long.pma");
const PMARC124_MTCD: &[u8] = include_bytes!("../../../corpus/binfmt/lzh/pmarc/pmarc124_mtcd.pma");
const GENERATED_PM1: &[u8] = include_bytes!("../../../corpus/binfmt/lzh/pmarc/generated_pm1.pma");
const PMARC2_PM2: &[u8] = include_bytes!("../../../corpus/binfmt/lzh/pmarc/pmarc2_pm2.pma");
const PMARC2_COMMENT: &[u8] = include_bytes!("../../../corpus/binfmt/lzh/pmarc/pmarc2_comment.pma");
const PMARC2_LONG: &[u8] = include_bytes!("../../../corpus/binfmt/lzh/pmarc/pmarc2_long.pma");
const EVIL_PM2: &[u8] = include_bytes!("../../../corpus/binfmt/lzh/pmarc/evil_pm2.lzh");

const LONG_TXT_DIGEST: &str = "fab4ae956d48bbbc45b21b07af5746a5b03cb0903501f836a1070186051065c4";
const LONG_TXT_SIZE: u64 = 1_241_659;

const GENERATED_PM1_DIGESTS: [&str; 32] = [
    "da55b9a1943bf46aa5e3089e3c1c29c793c21d8f58b2ebbc74cadddbeb4327d3",
    "9045d8ed2e34aa35e9ba255740f66fa447c743da878da9ecb34544be525ffdaf",
    "485e085c3d105024d7e4e3d71a7b8271c303ab0fdaf837a1ce4df8e5df2c5c1b",
    "79814af0c8994a697138e37aad9b853e06168bee597d59feda7b8c82bef64708",
    "bdc44602c0860a4426ad522d446868aea746cb90a4aea4bd62ea2dbc7353341f",
    "8688bc1d9163852597a99310c67723e6715a24faea9aed7b91546bc908600c3d",
    "0b2e604994225fa4e0336aec7f1f2055ad796aad92040db92f195456f154e20e",
    "8c300fcf798f7d56382767d141a022d4d8e6e6537e60d4a9dcf86e68824a83f9",
    "4d42f97169efba8a4f6601dac779dbd9fe903e1a0c21965ce904db21b9c9b4f4",
    "3b8974ffea5fb2c5e693aa4e8b1e01ff1c9f677144528f1c0aa398d0a7150c03",
    "9af9f22eaa1dac9bf635c58827b9212ad355a3fa2080ad57cd751905fc1039a8",
    "596027a8cfb3807da1e9ea670c3734f701725bcee11b467675893ac9db54d45f",
    "04efec9de2034c70538d39e638ed80aae9f10550d703d004bdf02c7a3aac3cf9",
    "56a411f3157635fce7e3ecbcda21bd2a73c4a67b7839edef71ddf24c067a9e1d",
    "150aae37b6aa9d1b39a6398e92a00bf2a7f01da6c667f02ec7556ed2b9d4dbdd",
    "11e81aa6fb4d2163f0a52a9baaa26a5a34a17ea098274bd22a3c8f4c9f71d854",
    "5e6af70b56107643e15125feb22735a7bd029d67af7befd63a0dd64e6a000863",
    "cee938c69cee72697b7e29f264a907a91e3f3edbb339b95121b37e98e61e521a",
    "fddb61476fcc1c70dabeb0fedb9690d7c6e95e27ab05b8d83f849d621e4239aa",
    "089c1c088c5e6af0a61c41a246f10902bd535b4fa228db30aa410fac3f1cbf9c",
    "e743605918ad0459b15d2807b94869dcb583b5ff0d49e3223b69a4649a2bba37",
    "600057b7d02855ccfbfb5f19c2f7b04427ac8026e06e9240a5504058ca9da377",
    "b870e40bcf6e4facba2d9838081657aa1f7573afd0980ba388d9f931dbe813a3",
    "d0cbe7e5d886002018fb5c131e275a1018102d6d4c1bdee7747a8c7d98f24278",
    "486bdd25bdfc8615172c8009768247bf49350c2ab316456886233dff10d31377",
    "5c314ddd874b49ab153521554421fa4eea3eab8ce86ebe41222b2757d4c5474e",
    "9c9612cf1883a14c3ea7151fae6b8b7b8238b043e9e573868ef03406473092a2",
    "42566399a306df95499c29df41a0b54e85d42b5a44dcb993f4e808de7425cf87",
    "625a8183fcb8e8dd75c899f933bcbb657f41afe7a3b2a3386890a75b015a0509",
    "272c924848810b85d827d241b077afef0c6f2170372d39d22980cddc8230517c",
    "24012e445e67d9c8fb8cd8c106dcddcaf7caccd7fdf64b43d6b5e98a86d18b80",
    "d1eb71841f698f594451ed014aade5b4de8cc73d5a85ec5248025280b7c2a4b7",
];

const QUOTA: u64 = 64 * 1024 * 1024;

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn parse(archive: &[u8], label: &str) -> LzhArchive {
    parse_lzh(archive, QUOTA)
        .unwrap_or_else(|error: disrobe_binfmt::Error| panic!("parse {label}: {error}"))
}

fn member_body(archive: &[u8]) -> &[u8] {
    let header_end: usize = usize::from(archive[0]) + 2;
    let compressed: usize =
        u32::from_le_bytes([archive[7], archive[8], archive[9], archive[10]]) as usize;
    &archive[header_end..header_end + compressed]
}

fn crc16_arc(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xA001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

#[test]
fn pmarc124_pm1_member_matches_the_reference_extraction() {
    let parsed: LzhArchive = parse(PMARC124_PM1, "pmarc124 pm1");
    assert!(parsed.notes.is_empty(), "{:?}", parsed.notes);
    let file: &LzhFile = parsed.files.first().expect("one -pm1- member");
    assert_eq!(file.path, "COPYING.TXT");
    assert_eq!(file.method, "-pm1-");
    assert_eq!(file.header_level, 0);
    assert!(file.decoder_supported);
    assert_eq!(file.original_size, 25_284);
    assert_eq!(file.data.len() as u64, file.original_size);
    assert_eq!(
        digest(&file.data),
        "66875d5ccf1f362902a3a14fad934fcb69522cc2a2b4f5a84978fe2569c33e45"
    );
    assert!(
        file.data
            .starts_with(b"\t\t  GNU LIBRARY GENERAL PUBLIC LICENSE"),
        "recovered member is not the archived licence text"
    );
}

#[test]
fn pmarc124_pm1_multi_member_archive_matches_the_reference_extraction() {
    let parsed: LzhArchive = parse(PMARC124_MTCD, "pmarc124 mtcd");
    assert!(parsed.notes.is_empty(), "{:?}", parsed.notes);
    assert_eq!(parsed.files.len(), 2);
    let expected: [(&str, u64, &str); 2] = [
        (
            "MTCD.DOC",
            1_403,
            "3916cd29631f259044ce5063edc0c6ea3c9c00afcd55a335430c27441367f8d5",
        ),
        (
            "CD.MTC",
            256,
            "f03b85f1706d12de59bdde738af6c9340caff87357501743b1992421d0e84a2f",
        ),
    ];
    for (file, (path, size, sha)) in parsed.files.iter().zip(expected) {
        assert_eq!(file.path, path);
        assert_eq!(file.method, "-pm1-");
        assert!(file.decoder_supported);
        assert_eq!(file.original_size, size);
        assert_eq!(digest(&file.data), sha);
    }
    assert_eq!(parsed.files[0].data.last(), Some(&0x1a));
}

#[test]
fn pm1_and_pm2_recover_the_same_long_member_from_different_archivers() {
    let pm1: LzhArchive = parse(PMARC124_PM1_LONG, "pmarc124 pm1_long");
    let pm2: LzhArchive = parse(PMARC2_LONG, "pmarc2 long");
    let pm1_file: &LzhFile = pm1.files.first().expect("one -pm1- member");
    let pm2_file: &LzhFile = pm2.files.first().expect("one -pm2- member");
    assert_eq!(pm1_file.method, "-pm1-");
    assert_eq!(pm2_file.method, "-pm2-");
    assert_eq!(pm1_file.original_size, LONG_TXT_SIZE);
    assert_eq!(pm2_file.original_size, LONG_TXT_SIZE);
    assert_eq!(digest(&pm1_file.data), LONG_TXT_DIGEST);
    assert_eq!(digest(&pm2_file.data), LONG_TXT_DIGEST);
    assert_eq!(pm1_file.data, pm2_file.data);
    assert!(
        pm1_file
            .data
            .starts_with(b"Project Gutenberg Etext of Hamlet")
    );
}

#[test]
fn every_pm1_start_tree_recovers_its_reference_member() {
    let parsed: LzhArchive = parse(GENERATED_PM1, "generated pm1");
    assert_eq!(parsed.files.len(), 32);
    assert_eq!(parsed.notes.len(), 32);
    assert!(
        parsed.notes[0]
            .contains("-pm1- member declares 24576 compressed byte(s) but the decoder consumed"),
        "{}",
        parsed.notes[0]
    );
    for (index, file) in parsed.files.iter().enumerate() {
        assert_eq!(file.path, format!("DATA_{index:02}.BIN"));
        assert_eq!(file.method, "-pm1-");
        assert!(file.decoder_supported);
        assert_eq!(file.original_size, 32_768);
        assert_eq!(
            digest(&file.data),
            GENERATED_PM1_DIGESTS[index],
            "start tree {index}"
        );
    }
}

#[test]
fn pmarc2_pm2_member_matches_the_reference_extraction() {
    let parsed: LzhArchive = parse(PMARC2_COMMENT, "pmarc2 comment");
    assert!(parsed.notes.is_empty(), "{:?}", parsed.notes);
    let file: &LzhFile = parsed.files.first().expect("one -pm2- member");
    assert_eq!(file.path, "HELLO.TXT");
    assert_eq!(file.method, "-pm2-");
    assert!(file.decoder_supported);
    assert_eq!(file.compressed_size, 22);
    assert_eq!(file.original_size, 128);
    assert_eq!(
        digest(&file.data),
        "481cc3b501c83a210c1840b9ec898a90c529de8fe3555c720656b620b56cea72"
    );
    assert_eq!(&file.data[..12], b"hello world\n");
    assert!(file.data[12..].iter().all(|byte: &u8| *byte == 0));
}

#[test]
fn pm2_member_behind_a_refused_path_still_decodes_through_the_codec() {
    let parsed: LzhArchive = parse(PMARC2_PM2, "pmarc2 pm2");
    assert!(parsed.files.is_empty());
    assert_eq!(parsed.notes.len(), 1);
    assert!(
        parsed.notes[0].contains("archive entry path escapes container root: GPL-2."),
        "{}",
        parsed.notes[0]
    );
    let decoded: PmDecoded = decode_bounded(PmMethod::Pm2, member_body(PMARC2_PM2), 18_176, QUOTA)
        .expect("decode the -pm2- member body");
    assert_eq!(decoded.data.len(), 18_176);
    assert!(decoded.unread_bits < 8, "{}", decoded.unread_bits);
    assert_eq!(
        digest(&decoded.data),
        "891ff81846fa2544373b4eec884593050069973c9be6771ed279959721aee739"
    );
    assert!(
        decoded
            .data
            .starts_with(b"                    GNU GENERAL PUBLIC LICENSE"),
        "recovered member is not the archived licence text"
    );
    assert_eq!(
        crc16_arc(&decoded.data),
        0x83cd,
        "recovered member must match the CRC-16 the archiver stored"
    );
}

#[test]
fn pm1_and_pm2_members_reach_the_dedicated_extraction_surface() {
    for (archive, label, method) in [
        (PMARC124_MTCD, "disrobe-pmarc-pm1", "-pm1-"),
        (PMARC2_COMMENT, "disrobe-pmarc-pm2", "-pm2-"),
    ] {
        assert_eq!(detect_container(archive), Some(ContainerKind::Lzh));
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create(label).expect("create PMarc output");
        let result: ExtractionResult =
            extract_to(ContainerKind::Lzh, archive, scratch.path()).expect("extract PMarc archive");
        assert!(result.integrity_violations.is_empty());
        let parsed: LzhArchive = parse(archive, method);
        assert_eq!(result.entries.len(), parsed.files.len());
        for (entry, file) in result.entries.iter().zip(&parsed.files) {
            let written: Vec<u8> =
                std::fs::read(scratch.path().join(&entry.name)).expect("read extracted member");
            assert_eq!(written, file.data, "{} bytes differ", entry.name);
        }
    }
}

#[test]
fn pm2_code_tree_above_the_declared_ceiling_is_refused() {
    let parsed: LzhArchive =
        parse_lzh(EVIL_PM2, QUOTA).expect("record the oversized -pm2- code tree");
    assert!(
        parsed.files.is_empty()
            && parsed.notes.len() == 1
            && parsed.notes[0].contains("-pm2- code tree declares 31 codes above the 29 ceiling"),
        "{:?}",
        parsed.notes
    );
}

#[test]
fn truncated_pm1_and_pm2_bodies_fail_without_partial_output() {
    let pm1_body: &[u8] = member_body(PMARC124_PM1);
    let pm2_body: &[u8] = member_body(PMARC2_COMMENT);
    let pm1_error: disrobe_binfmt::Error = decode_bounded(
        PmMethod::Pm1,
        &pm1_body[..pm1_body.len() / 2],
        25_284,
        QUOTA,
    )
    .expect_err("refuse a halved -pm1- body");
    assert!(
        pm1_error
            .to_string()
            .contains("-pm1- stream read 72 bit(s) past the compressed body"),
        "{pm1_error}"
    );
    let pm2_error: disrobe_binfmt::Error =
        decode_bounded(PmMethod::Pm2, &pm2_body[..pm2_body.len() / 2], 128, QUOTA)
            .expect_err("refuse a halved -pm2- body");
    assert!(
        pm2_error
            .to_string()
            .contains("compressed body ended before the decoded stream"),
        "{pm2_error}"
    );
    let absent: [(PmMethod, &str); 2] = [
        (
            PmMethod::Pm1,
            "-pm1- copy distance 0 exceeds the 0 byte(s) produced",
        ),
        (
            PmMethod::Pm2,
            "-pm2- compressed body ended before the decoded stream",
        ),
    ];
    for (method, message) in absent {
        let error: disrobe_binfmt::Error =
            decode_bounded(method, &[], 16, QUOTA).expect_err("refuse an absent body");
        assert!(error.to_string().contains(message), "{error}");
    }
}

#[test]
fn declared_output_above_the_caller_limit_is_refused_before_decoding() {
    for method in [PmMethod::Pm1, PmMethod::Pm2] {
        let error: disrobe_binfmt::Error =
            decode_bounded(method, member_body(PMARC124_PM1), 25_284, 1_024)
                .expect_err("refuse output above the caller limit");
        assert!(
            error
                .to_string()
                .contains("declared output exceeds 1024-byte limit"),
            "{error}"
        );
    }
    for method in [PmMethod::Pm1, PmMethod::Pm2] {
        let empty: PmDecoded = decode_bounded(method, &[], 0, QUOTA).expect("empty member");
        assert!(empty.data.is_empty());
        assert_eq!(empty.unread_bits, 0);
    }
}

#[test]
fn a_single_flipped_bit_in_a_pm1_or_pm2_body_fails_the_stored_crc16() {
    let cases: [(&[u8], usize, &str); 2] = [
        (
            PMARC124_PM1,
            37,
            "lzh `COPYING.TXT`: decoded CRC 01db differs from declared CRC e582",
        ),
        (
            PMARC2_LONG,
            48,
            "lzh `LONG.TXT`: decoded CRC 8e6e differs from declared CRC 2aea",
        ),
    ];
    for (archive, position, message) in cases {
        let mut mutated: Vec<u8> = archive.to_vec();
        mutated[position] ^= 0x01;
        let parsed: LzhArchive =
            parse_lzh(&mutated, QUOTA).expect("record a corrupted PMarc member");
        assert!(
            parsed.files.is_empty()
                && parsed
                    .notes
                    .iter()
                    .any(|refusal: &String| refusal.contains(message)),
            "{:?}",
            parsed.notes
        );
    }
}

#[test]
fn a_bit_the_pm1_format_never_reads_still_recovers_the_reference_member() {
    let mut mutated: Vec<u8> = PMARC124_PM1.to_vec();
    mutated[293] ^= 0x01;
    let parsed: LzhArchive = parse(&mutated, "pmarc124 pm1 with an unread bit flipped");
    let file: &LzhFile = parsed.files.first().expect("one -pm1- member");
    assert_eq!(
        digest(&file.data),
        "66875d5ccf1f362902a3a14fad934fcb69522cc2a2b4f5a84978fe2569c33e45"
    );
}

#[test]
fn a_pm2_code_tree_declaring_no_codes_is_refused() {
    let error: disrobe_binfmt::Error = decode_bounded(PmMethod::Pm2, &[0x00, 0x00], 16, QUOTA)
        .expect_err("refuse an empty -pm2- code tree");
    assert!(
        error
            .to_string()
            .contains("-pm2- code tree declares no codes"),
        "{error}"
    );
}

#[test]
fn a_pm1_stream_running_entirely_on_zero_fill_is_refused_by_the_pad_ceiling() {
    let error: disrobe_binfmt::Error = decode_bounded(PmMethod::Pm1, &[0xff, 0xff], 1 << 20, QUOTA)
        .expect_err("refuse a -pm1- stream that runs on zero fill");
    assert!(
        error.to_string().contains("past the compressed body"),
        "{error}"
    );
}
