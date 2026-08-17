#![allow(clippy::expect_used, clippy::panic)]

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::{IsoImage, parse_iso};
use disrobe_binfmt::{ExtractionResult, extract_to};

const SECTOR_SIZE: usize = 2_048;

fn put_both_endian_u16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    bytes[at + 2..at + 4].copy_from_slice(&value.to_be_bytes());
}

fn put_both_endian_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    bytes[at + 4..at + 8].copy_from_slice(&value.to_be_bytes());
}

fn directory_record(
    name: &[u8],
    lba: u32,
    size: u32,
    directory: bool,
    system_use: &[u8],
) -> Vec<u8> {
    let record_len: usize =
        33 + name.len() + usize::from(name.len().is_multiple_of(2)) + system_use.len();
    let mut record: Vec<u8> = vec![0; record_len];
    record[0] = record_len as u8;
    put_both_endian_u32(&mut record, 2, lba);
    put_both_endian_u32(&mut record, 10, size);
    record[25] = if directory { 2 } else { 0 };
    put_both_endian_u16(&mut record, 28, 1);
    record[32] = name.len() as u8;
    record[33..33 + name.len()].copy_from_slice(name);
    let system_use_at: usize = 33 + name.len() + usize::from(name.len().is_multiple_of(2));
    record[system_use_at..].copy_from_slice(system_use);
    record
}

fn root_system_use(identifier: &[u8; 10]) -> Vec<u8> {
    let mut entries: Vec<u8> = vec![b'S', b'P', 7, 1, 0xbe, 0xef, 0];
    entries.extend_from_slice(&[b'E', b'R', 18, 1, 10, 0, 0, 1]);
    entries.extend_from_slice(identifier);
    entries.extend_from_slice(&[b'S', b'T', 4, 1]);
    entries
}

fn name_system_use(name: &[u8]) -> Vec<u8> {
    let mut entries: Vec<u8> = vec![b'N', b'M', (5 + name.len()) as u8, 1, 0];
    entries.extend_from_slice(name);
    entries.extend_from_slice(&[b'S', b'T', 4, 1]);
    entries
}

fn regular_system_use(name: &[u8], mode: u32) -> Vec<u8> {
    let mut entries: Vec<u8> = name_system_use(name);
    entries.truncate(entries.len() - 4);
    let mut px: Vec<u8> = vec![b'P', b'X', 44, 1];
    for value in [mode, 1, 0, 0, 1] {
        let at: usize = px.len();
        px.resize(at + 8, 0);
        put_both_endian_u32(&mut px, at, value);
    }
    entries.extend_from_slice(&px);
    entries.extend_from_slice(&[b'S', b'T', 4, 1]);
    entries
}

fn symlink_system_use(name: &[u8], target: &[u8]) -> Vec<u8> {
    let mut entries: Vec<u8> = vec![b'N', b'M', (5 + name.len()) as u8, 1, 0];
    entries.extend_from_slice(name);
    let mut px: Vec<u8> = vec![b'P', b'X', 44, 1];
    for value in [0o120_777, 1, 0, 0, 7] {
        let at: usize = px.len();
        px.resize(at + 8, 0);
        put_both_endian_u32(&mut px, at, value);
    }
    entries.extend_from_slice(&px);
    entries.extend_from_slice(&[
        b'S',
        b'L',
        (7 + target.len()) as u8,
        1,
        0,
        0,
        target.len() as u8,
    ]);
    entries.extend_from_slice(target);
    entries.extend_from_slice(&[b'S', b'T', 4, 1]);
    entries
}

fn type1_image_with(marker: bool, rrip_identifier: &[u8; 10], app_run_mode: u32) -> Vec<u8> {
    let sectors: u32 = 24;
    let root_lba: u32 = 20;
    let file_lba: u32 = 21;
    let body: &[u8] = b"#!/bin/sh\nprintf type1\n";
    let mut image: Vec<u8> = vec![0; sectors as usize * SECTOR_SIZE];
    let image_len: u64 = image.len() as u64;
    image[0..4].copy_from_slice(b"\x7fELF");
    image[4] = 2;
    image[5] = 1;
    image[6] = 1;
    if marker {
        image[8..11].copy_from_slice(b"AI\x01");
    }
    image[16..18].copy_from_slice(&2u16.to_le_bytes());
    image[18..20].copy_from_slice(&62u16.to_le_bytes());
    image[20..24].copy_from_slice(&1u32.to_le_bytes());
    image[24..32].copy_from_slice(&0x40_0000u64.to_le_bytes());
    image[32..40].copy_from_slice(&64u64.to_le_bytes());
    image[52..54].copy_from_slice(&64u16.to_le_bytes());
    image[54..56].copy_from_slice(&56u16.to_le_bytes());
    image[56..58].copy_from_slice(&1u16.to_le_bytes());
    image[64..68].copy_from_slice(&1u32.to_le_bytes());
    image[68..72].copy_from_slice(&5u32.to_le_bytes());
    image[72..80].copy_from_slice(&0u64.to_le_bytes());
    image[80..88].copy_from_slice(&0x40_0000u64.to_le_bytes());
    image[88..96].copy_from_slice(&0x40_0000u64.to_le_bytes());
    image[96..104].copy_from_slice(&image_len.to_le_bytes());
    image[104..112].copy_from_slice(&image_len.to_le_bytes());
    image[112..120].copy_from_slice(&0x1000u64.to_le_bytes());

    let pvd_at: usize = 16 * SECTOR_SIZE;
    image[pvd_at] = 1;
    image[pvd_at + 1..pvd_at + 6].copy_from_slice(b"CD001");
    image[pvd_at + 6] = 1;
    put_both_endian_u32(&mut image, pvd_at + 80, sectors);
    put_both_endian_u16(&mut image, pvd_at + 120, 1);
    put_both_endian_u16(&mut image, pvd_at + 124, 1);
    put_both_endian_u16(&mut image, pvd_at + 128, SECTOR_SIZE as u16);
    let root: Vec<u8> = directory_record(&[0], root_lba, SECTOR_SIZE as u32, true, &[]);
    image[pvd_at + 156..pvd_at + 156 + root.len()].copy_from_slice(&root);

    let terminator_at: usize = 17 * SECTOR_SIZE;
    image[terminator_at] = 255;
    image[terminator_at + 1..terminator_at + 6].copy_from_slice(b"CD001");
    image[terminator_at + 6] = 1;

    let root_at: usize = root_lba as usize * SECTOR_SIZE;
    let current: Vec<u8> = directory_record(
        &[0],
        root_lba,
        SECTOR_SIZE as u32,
        true,
        &root_system_use(rrip_identifier),
    );
    let parent: Vec<u8> = directory_record(&[1], root_lba, SECTOR_SIZE as u32, true, &[]);
    let app_run: Vec<u8> = directory_record(
        b"APPRUN.;1",
        file_lba,
        body.len() as u32,
        false,
        &regular_system_use(b"AppRun", app_run_mode),
    );
    let mut cursor: usize = root_at;
    for record in [&current, &parent, &app_run] {
        image[cursor..cursor + record.len()].copy_from_slice(record);
        cursor += record.len();
    }
    let file_at: usize = file_lba as usize * SECTOR_SIZE;
    image[file_at..file_at + body.len()].copy_from_slice(body);
    image
}

fn type1_image(marker: bool) -> Vec<u8> {
    type1_image_with(marker, b"RRIP_1991A", 0o100_755)
}

fn with_joliet_fallback_tree(mut image: Vec<u8>) -> Vec<u8> {
    let supplementary_at: usize = 17 * SECTOR_SIZE;
    let terminator_at: usize = 18 * SECTOR_SIZE;
    image[supplementary_at..terminator_at + SECTOR_SIZE].fill(0);
    image[supplementary_at] = 2;
    image[supplementary_at + 1..supplementary_at + 6].copy_from_slice(b"CD001");
    image[supplementary_at + 6] = 1;
    image[supplementary_at + 88..supplementary_at + 91].copy_from_slice(b"%/E");
    put_both_endian_u32(&mut image, supplementary_at + 80, 24);
    put_both_endian_u16(&mut image, supplementary_at + 120, 1);
    put_both_endian_u16(&mut image, supplementary_at + 124, 1);
    put_both_endian_u16(&mut image, supplementary_at + 128, SECTOR_SIZE as u16);
    let root: Vec<u8> = directory_record(&[0], 22, SECTOR_SIZE as u32, true, &[]);
    image[supplementary_at + 156..supplementary_at + 156 + root.len()].copy_from_slice(&root);
    image[terminator_at] = 255;
    image[terminator_at + 1..terminator_at + 6].copy_from_slice(b"CD001");
    image[terminator_at + 6] = 1;

    let root_at: usize = 22 * SECTOR_SIZE;
    let current: Vec<u8> = directory_record(&[0], 22, SECTOR_SIZE as u32, true, &[]);
    let parent: Vec<u8> = directory_record(&[1], 22, SECTOR_SIZE as u32, true, &[]);
    let joliet_name: Vec<u8> = "Fallback"
        .encode_utf16()
        .flat_map(u16::to_be_bytes)
        .collect();
    let file: Vec<u8> = directory_record(&joliet_name, 23, 1, false, &[]);
    let mut cursor: usize = root_at;
    for record in [&current, &parent, &file] {
        image[cursor..cursor + record.len()].copy_from_slice(record);
        cursor += record.len();
    }
    image[23 * SECTOR_SIZE] = b'x';
    image
}

fn append_root_file(image: &mut [u8], iso_name: &[u8], rr_name: &[u8], lba: u32) {
    let root_at: usize = 20 * SECTOR_SIZE;
    let mut cursor: usize = root_at;
    while image[cursor] != 0 {
        cursor += usize::from(image[cursor]);
    }
    let record: Vec<u8> = directory_record(iso_name, lba, 1, false, &name_system_use(rr_name));
    image[cursor..cursor + record.len()].copy_from_slice(&record);
    image[lba as usize * SECTOR_SIZE] = b'x';
}

fn append_root_symlink(image: &mut [u8], iso_name: &[u8], rr_name: &[u8], target: &[u8]) {
    let root_at: usize = 20 * SECTOR_SIZE;
    let mut cursor: usize = root_at;
    while image[cursor] != 0 {
        cursor += usize::from(image[cursor]);
    }
    let record: Vec<u8> =
        directory_record(iso_name, 0, 0, false, &symlink_system_use(rr_name, target));
    image[cursor..cursor + record.len()].copy_from_slice(&record);
}

#[test]
fn type1_marker_preempts_generic_iso_detection() {
    let image: Vec<u8> = type1_image(true);
    assert_eq!(detect_container(&image), Some(ContainerKind::AppImage));

    for marker in [*b"AI\x00", *b"AI\x03", *b"AI\xff"] {
        let mut forged: Vec<u8> = image.clone();
        forged[8..11].copy_from_slice(&marker);
        assert_eq!(detect_container(&forged), Some(ContainerKind::Iso));
    }
}

#[test]
fn no_marker_type1_requires_the_apprun_root_entry() {
    let image: Vec<u8> = type1_image(false);
    assert_eq!(detect_container(&image), Some(ContainerKind::AppImage));

    let mut without_app_run: Vec<u8> = image;
    let name_at: usize = without_app_run
        .windows(b"APPRUN.;1".len())
        .position(|window: &[u8]| window == b"APPRUN.;1")
        .expect("AppRun ISO directory record");
    let app_run_at: usize = name_at - 33;
    without_app_run[app_run_at] = 0;
    assert_eq!(detect_container(&without_app_run), Some(ContainerKind::Iso));

    let mut invalid_elf: Vec<u8> = type1_image(true);
    invalid_elf[18..20].fill(0);
    assert_eq!(detect_container(&invalid_elf), Some(ContainerKind::Iso));
}

#[test]
fn rrip_1_12_identifier_preserves_type1_detection() {
    let image: Vec<u8> = type1_image_with(false, b"IEEE_P1282", 0o100_755);
    let parsed: IsoImage = parse_iso(&image).expect("parse RRIP 1.12 image");
    assert!(parsed.rock_ridge);
    assert_eq!(detect_container(&image), Some(ContainerKind::AppImage));
}

#[test]
fn type1_requires_an_executable_load_segment_containing_the_entry() {
    let image: Vec<u8> = type1_image(false);
    for mutation in [
        (20usize, 4usize, 0u64),
        (24, 8, 0),
        (24, 8, 0x80_0000),
        (56, 2, 0),
        (68, 4, 4),
    ] {
        let mut malformed: Vec<u8> = image.clone();
        malformed[mutation.0..mutation.0 + mutation.1]
            .copy_from_slice(&mutation.2.to_le_bytes()[..mutation.1]);
        assert_eq!(
            detect_container(&malformed),
            Some(ContainerKind::Iso),
            "mutation {mutation:?}"
        );
    }

    let mut out_of_bounds_table: Vec<u8> = image;
    let phoff: u64 = out_of_bounds_table.len() as u64 - 8;
    out_of_bounds_table[32..40].copy_from_slice(&phoff.to_le_bytes());
    assert_eq!(
        detect_container(&out_of_bounds_table),
        Some(ContainerKind::Iso)
    );
}

#[test]
fn type1_requires_an_executable_regular_root_apprun() {
    for marker in [false, true] {
        let image: Vec<u8> = type1_image_with(marker, b"RRIP_1991A", 0o100_644);
        assert_eq!(detect_container(&image), Some(ContainerKind::Iso));
    }

    let mut symlink_app_run: Vec<u8> = type1_image(false);
    let name_at: usize = symlink_app_run
        .windows(b"APPRUN.;1".len())
        .position(|window: &[u8]| window == b"APPRUN.;1")
        .expect("AppRun ISO directory record");
    symlink_app_run[name_at - 33] = 0;
    append_root_symlink(&mut symlink_app_run, b"APPRUN.;1", b"AppRun", b"payload");
    assert_eq!(detect_container(&symlink_app_run), Some(ContainerKind::Iso));
}

#[test]
fn rock_ridge_primary_tree_precedes_a_joliet_fallback_tree() {
    let image: Vec<u8> = with_joliet_fallback_tree(type1_image(false));
    let parsed: IsoImage = parse_iso(&image).expect("parse dual-tree image");
    assert!(parsed.rock_ridge);
    assert!(!parsed.joliet);
    assert!(parsed.files.iter().any(|entry| entry.path == "AppRun"));
    assert_eq!(detect_container(&image), Some(ContainerKind::AppImage));
}

#[test]
fn type1_extraction_uses_the_iso_payload_at_offset_zero() {
    let image: Vec<u8> = type1_image(true);
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("binfmt-appimage-type1")
            .expect("create scratch directory");
    let result: ExtractionResult = extract_to(ContainerKind::AppImage, &image, scratch.path())
        .expect("extract type 1 appimage");
    assert_eq!(result.kind, ContainerKind::AppImage);
    assert!(result.integrity_violations.is_empty());
    assert_eq!(
        std::fs::read(scratch.path().join("AppRun")).expect("read extracted AppRun"),
        b"#!/bin/sh\nprintf type1\n"
    );
    assert!(
        scratch
            .path()
            .join(".disrobe-appimage-layout.json")
            .is_file()
    );
}

#[test]
fn symlinks_are_described_without_materializing_a_host_link() {
    let mut image: Vec<u8> = type1_image(true);
    append_root_symlink(&mut image, b"LINK.;1", b"link", b"outside");
    let parsed: IsoImage = parse_iso(&image).expect("parse type 1 symlink image");
    let link: &disrobe_binfmt::containers::IsoEntry = parsed
        .files
        .iter()
        .find(|entry| entry.path == "link")
        .expect("find parsed symlink");
    assert_eq!(link.kind, disrobe_binfmt::containers::IsoEntryKind::Symlink);
    assert_eq!(link.symlink_target.as_deref(), Some("outside"));

    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("binfmt-appimage-type1-symlink")
            .expect("create symlink scratch directory");
    extract_to(ContainerKind::AppImage, &image, scratch.path()).expect("extract type 1 image");
    assert!(!scratch.path().join("link").exists());
    let layout: String = std::fs::read_to_string(scratch.path().join(".disrobe-iso-layout.json"))
        .expect("read ISO layout");
    assert!(layout.contains("\"kind\": \"Symlink\""));
    assert!(layout.contains("\"symlink_target\": \"outside\""));
}

#[test]
fn hostile_and_colliding_rrip_paths_refuse_before_output_creation() {
    for (iso_name, rr_name) in [
        (b"ESCAPE.;1".as_slice(), b"../escape".as_slice()),
        (b"DUP.;1".as_slice(), b"AppRun".as_slice()),
        (
            b"SIDECAR.;1".as_slice(),
            b".disrobe-appimage-layout.json".as_slice(),
        ),
    ] {
        let mut image: Vec<u8> = type1_image(true);
        append_root_file(&mut image, iso_name, rr_name, 22);
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("binfmt-appimage-type1-refuse")
                .expect("create refusal scratch directory");
        assert!(extract_to(ContainerKind::AppImage, &image, scratch.path()).is_err());
        assert_eq!(
            std::fs::read_dir(scratch.path())
                .expect("read refusal output")
                .count(),
            0
        );
    }

    for entries in [
        [(b"A.;1".as_slice(), b"a".as_slice()), (b"AB.;1", b"a/b")],
        [(b"AB.;1".as_slice(), b"a/b".as_slice()), (b"A.;1", b"a")],
    ] {
        let mut image: Vec<u8> = type1_image(true);
        append_root_file(&mut image, entries[0].0, entries[0].1, 22);
        append_root_file(&mut image, entries[1].0, entries[1].1, 23);
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("binfmt-appimage-type1-prefix-refuse")
                .expect("create prefix refusal scratch directory");
        assert!(extract_to(ContainerKind::AppImage, &image, scratch.path()).is_err());
        assert_eq!(
            std::fs::read_dir(scratch.path())
                .expect("read prefix refusal output")
                .count(),
            0
        );
    }
}
