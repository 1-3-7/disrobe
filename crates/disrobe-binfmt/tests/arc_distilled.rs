#![allow(clippy::expect_used, clippy::panic)]

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::arc::{ArcArchive, ArcEntry, entry_bytes, parse_arc};
use sha2::{Digest as _, Sha256};

const DISTILLED: &[u8] = include_bytes!("../../../corpus/binfmt/arc/pak/pak11_distilled.pak");
const CAP: u64 = 8 * 1024 * 1024;

const MEMBERS: [(&str, usize, &str); 10] = [
    (
        "AREAFIX.HLP",
        1_960,
        "a293520ae049bdbf517bb7f91fb3bfa80c826adbca17e98dbd643859f96aa960",
    ),
    (
        "IEINFO.DOC",
        11_527,
        "f3fa28baf32bed15414403b14db0e259e01ffa0ff4ef98d6ef006f41be4e42f1",
    ),
    (
        "IEMANUAL.DOC",
        68_329,
        "3f872991f2a403cb5437209137e8636b12ff117579c3f781a5f4198650335e4e",
    ),
    (
        "IENEW.DOC",
        45_745,
        "11026d43509340daee131ba4787fb92f8089731bc4176224090aa64268dc5397",
    ),
    (
        "IESETUP.EXE",
        297_528,
        "d811ccd14c52e44c79406a79d60bfb87f724c3b264a566f886e254f8ab65e46a",
    ),
    (
        "IESETUP.HLP",
        92_022,
        "d9c79a081f2daa1ddada6c50d7c9208cabf2328f1766640a4dca9034061caf4e",
    ),
    (
        "INTRECHO.EXE",
        384_939,
        "3a4e3bb48070dae3a4ec030ff3b928bc2bace35b440f61c397994fa2109e8742",
    ),
    (
        "LICENSE.DOC",
        1_742,
        "be4e47b1841de3c307e509fa3a0a4c7a5e9cb8d749a1d4d49c18f76b39ce028a",
    ),
    (
        "ORDER.USA",
        2_670,
        "342dfb2dc1546a53bf18f3a0af0bea6b7e7d47fc87642730485854f141a77600",
    ),
    (
        "PRICE.DOC",
        12_169,
        "0ed78c95e8c4d4aa6b44f6ca97220ff41be7e76b11bddb4673538e7c4400fa6e",
    ),
];

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn member<'a>(archive: &'a ArcArchive, name: &str) -> &'a ArcEntry {
    archive
        .entries
        .iter()
        .find(|entry: &&ArcEntry| entry.name == name)
        .unwrap_or_else(|| panic!("member {name} is absent"))
}

fn distilled_archive(body: &[u8], original_size: u32) -> Vec<u8> {
    let mut archive: Vec<u8> = vec![0x1a, 11];
    let mut name: [u8; 13] = [0; 13];
    name[..8].copy_from_slice(b"bad.bin\0");
    archive.extend_from_slice(&name);
    archive.extend_from_slice(&(body.len() as u32).to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(&original_size.to_le_bytes());
    archive.extend_from_slice(body);
    archive.extend_from_slice(&[0x1a, 0]);
    archive
}

#[test]
fn every_distilled_member_recovers_against_the_archiver_crc() {
    let archive: ArcArchive = parse_arc(DISTILLED).expect("parse distilled archive");
    assert_eq!(archive.entries.len(), MEMBERS.len());
    for (entry, (name, size, sha256)) in archive.entries.iter().zip(MEMBERS) {
        assert_eq!(entry.name, name);
        assert_eq!(entry.method, 11);
        assert_eq!(entry.original_size as usize, size);
        let decoded: Vec<u8> = entry_bytes(DISTILLED, entry, CAP)
            .unwrap_or_else(|error| panic!("decode {name}: {error}"));
        assert_eq!(decoded.len(), size, "{name}");
        assert_eq!(digest(&decoded), sha256, "{name}");
    }
}

#[test]
fn the_recovered_distilled_licence_member_is_the_archived_document() {
    let archive: ArcArchive = parse_arc(DISTILLED).expect("parse distilled archive");
    let decoded: Vec<u8> =
        entry_bytes(DISTILLED, member(&archive, "LICENSE.DOC"), CAP).expect("decode LICENSE.DOC");
    let text: String = String::from_utf8_lossy(&decoded).into_owned();
    assert!(
        text.starts_with("InterMail Software Inc."),
        "recovered member is not the archived licence"
    );
    assert!(
        text.contains("allowed and encouraged to distribute the demo file archive"),
        "recovered member lost its redistribution clause"
    );
    assert_eq!(decoded.last(), Some(&0x1a));
}

#[test]
fn the_recovered_distilled_executables_carry_their_dos_headers() {
    let archive: ArcArchive = parse_arc(DISTILLED).expect("parse distilled archive");
    for name in ["IESETUP.EXE", "INTRECHO.EXE"] {
        let decoded: Vec<u8> =
            entry_bytes(DISTILLED, member(&archive, name), CAP).expect("decode executable");
        assert_eq!(&decoded[..2], b"MZ", "{name} lost its DOS header");
    }
}

#[test]
fn a_distilled_archive_reaches_the_extraction_surface_with_identical_bytes() {
    assert_eq!(detect_container(DISTILLED), Some(ContainerKind::Arc));
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-arc-distilled")
            .expect("create distilled output");
    let result: disrobe_binfmt::ExtractionResult =
        disrobe_binfmt::extract_to(ContainerKind::Arc, DISTILLED, scratch.path())
            .expect("extract distilled archive");
    assert!(result.integrity_violations.is_empty());
    assert_eq!(result.entries.len(), MEMBERS.len());
    for (name, size, sha256) in MEMBERS {
        let written: Vec<u8> =
            std::fs::read(scratch.path().join(name)).expect("read extracted member");
        assert_eq!(written.len(), size, "{name}");
        assert_eq!(digest(&written), sha256, "{name}");
    }
}

#[test]
fn a_corrupted_distilled_body_fails_the_archiver_crc() {
    let archive: ArcArchive = parse_arc(DISTILLED).expect("parse distilled archive");
    let entry: &ArcEntry = member(&archive, "AREAFIX.HLP");
    let mut mutated: Vec<u8> = DISTILLED.to_vec();
    let flip: usize = entry.data_offset + entry.compressed_size as usize - 2;
    mutated[flip] ^= 0x01;
    let error: disrobe_binfmt::Error =
        entry_bytes(&mutated, entry, CAP).expect_err("refuse a corrupted distilled member");
    let rendered: String = error.to_string();
    assert!(
        rendered.contains("CRC mismatch") || rendered.contains("distilled"),
        "{rendered}"
    );
}

#[test]
fn distilled_members_refuse_truncation_and_output_caps() {
    let archive: ArcArchive = parse_arc(DISTILLED).expect("parse distilled archive");
    let entry: &ArcEntry = member(&archive, "IEINFO.DOC");
    let body: &[u8] =
        &DISTILLED[entry.data_offset..entry.data_offset + entry.compressed_size as usize];
    let truncated: Vec<u8> = distilled_archive(&body[..body.len() / 2], entry.original_size);
    let parsed: ArcArchive = parse_arc(&truncated).expect("parse truncated distilled member");
    let error: disrobe_binfmt::Error = entry_bytes(&truncated, &parsed.entries[0], CAP)
        .expect_err("refuse truncated distilled member");
    assert!(error.to_string().contains("distilled"), "{error}");

    let error: disrobe_binfmt::Error =
        entry_bytes(DISTILLED, entry, 0).expect_err("refuse output above cap");
    assert!(error.to_string().contains("output exceeds cap"), "{error}");
}

#[test]
fn distilled_members_refuse_malformed_node_tables_without_output() {
    for body in [
        &[0x03, 0x00, 0x0a][..],
        &[0x00, 0x08, 0x0a][..],
        &[0x02, 0x00, 0x00][..],
    ] {
        let malformed: Vec<u8> = distilled_archive(body, 16);
        let parsed: ArcArchive = parse_arc(&malformed).expect("parse malformed distilled member");
        let error: disrobe_binfmt::Error = entry_bytes(&malformed, &parsed.entries[0], CAP)
            .expect_err("refuse malformed node table");
        assert!(error.to_string().contains("distilled"), "{error}");
    }
}
