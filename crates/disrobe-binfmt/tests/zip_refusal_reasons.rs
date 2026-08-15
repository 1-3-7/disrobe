#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::io::{Cursor, Write};
use std::path::PathBuf;

use disrobe_binfmt::{ContainerKind, ExtractionResult, extract_to};
use disrobe_core::scratch::ScratchDir;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

fn eocd(entries: u16, directory_offset: u32, directory_size: u32) -> Vec<u8> {
    let mut record: Vec<u8> = Vec::with_capacity(22);
    record.extend_from_slice(&[b'P', b'K', 0x05, 0x06]);
    record.extend_from_slice(&0u16.to_le_bytes());
    record.extend_from_slice(&0u16.to_le_bytes());
    record.extend_from_slice(&entries.to_le_bytes());
    record.extend_from_slice(&entries.to_le_bytes());
    record.extend_from_slice(&directory_size.to_le_bytes());
    record.extend_from_slice(&directory_offset.to_le_bytes());
    record.extend_from_slice(&0u16.to_le_bytes());
    record
}

fn central_directory_entry(name: &[u8]) -> Vec<u8> {
    let name_len: u16 = u16::try_from(name.len()).expect("bounded test name");
    let mut record: Vec<u8> = vec![0u8; 46];
    record[0..4].copy_from_slice(&[b'P', b'K', 0x01, 0x02]);
    record[28..30].copy_from_slice(&name_len.to_le_bytes());
    record.extend_from_slice(name);
    record
}

fn refusal_reason(image: &[u8]) -> String {
    let scratch: ScratchDir = ScratchDir::create("zip-refusal").expect("scratch dir");
    let out: PathBuf = scratch.path().join("out");
    let error: disrobe_binfmt::Error = extract_to(ContainerKind::Zip, image, &out)
        .expect_err("every image in this test is malformed and must be refused");
    error.to_string()
}

fn stored_zip() -> Vec<u8> {
    let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    let mut writer: ZipWriter<Cursor<Vec<u8>>> = ZipWriter::new(cursor);
    writer
        .start_file("payload.bin", SimpleFileOptions::default())
        .expect("start bounded stored entry");
    writer.write_all(b"payload").expect("write stored body");
    writer.finish().expect("finish stored zip").into_inner()
}

fn zip64_stored_zip() -> Vec<u8> {
    let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    let mut writer: ZipWriter<Cursor<Vec<u8>>> = ZipWriter::new(cursor);
    writer.set_zip64_comment(Some(""));
    writer
        .start_file("payload.bin", SimpleFileOptions::default())
        .expect("start bounded ZIP64 entry");
    writer
        .write_all(b"payload")
        .expect("write ZIP64 stored body");
    let mut image: Vec<u8> = writer.finish().expect("finish ZIP64 zip").into_inner();
    let eocd_offset: usize = image
        .windows(4)
        .rposition(|window: &[u8]| window == [b'P', b'K', 0x05, 0x06])
        .expect("ZIP64 zip has classic EOCD");
    image[eocd_offset + 8..eocd_offset + 12].copy_from_slice(&u32::MAX.to_le_bytes());
    image
}

fn signature_offset(image: &[u8], signature: [u8; 4]) -> usize {
    image
        .windows(signature.len())
        .rposition(|window: &[u8]| window == signature)
        .expect("fixture contains required zip signature")
}

fn force_zip64_count_mismatch(image: &mut [u8]) {
    let eocd64_offset: usize = signature_offset(image, [b'P', b'K', 0x06, 0x06]);
    image[eocd64_offset + 24..eocd64_offset + 40]
        .chunks_exact_mut(8)
        .for_each(|field: &mut [u8]| field.copy_from_slice(&2u64.to_le_bytes()));
}

fn zip64_local_offset_archive() -> Vec<u8> {
    let mut image: Vec<u8> = zip64_stored_zip();
    let central: usize = signature_offset(&image, [b'P', b'K', 0x01, 0x02]);
    let name_len: usize = usize::from(u16::from_le_bytes([
        image[central + 28],
        image[central + 29],
    ]));
    let extra_offset: usize = central + 46 + name_len;
    image[central + 30..central + 32].copy_from_slice(&12u16.to_le_bytes());
    image[central + 42..central + 46].copy_from_slice(&u32::MAX.to_le_bytes());
    let mut extra: Vec<u8> = Vec::with_capacity(12);
    extra.extend_from_slice(&1u16.to_le_bytes());
    extra.extend_from_slice(&8u16.to_le_bytes());
    extra.extend_from_slice(&0u64.to_le_bytes());
    image.splice(extra_offset..extra_offset, extra);

    let eocd64: usize = signature_offset(&image, [b'P', b'K', 0x06, 0x06]);
    let locator: usize = signature_offset(&image, [b'P', b'K', 0x06, 0x07]);
    let eocd: usize = signature_offset(&image, [b'P', b'K', 0x05, 0x06]);
    let directory_size: u64 = u64::from_le_bytes(
        image[eocd64 + 40..eocd64 + 48]
            .try_into()
            .expect("ZIP64 directory size field"),
    ) + 12;
    image[eocd64 + 40..eocd64 + 48].copy_from_slice(&directory_size.to_le_bytes());
    image[locator + 8..locator + 16].copy_from_slice(
        &u64::try_from(eocd64)
            .expect("bounded ZIP64 EOCD offset")
            .to_le_bytes(),
    );
    image[eocd + 12..eocd + 16].copy_from_slice(
        &u32::try_from(directory_size)
            .expect("bounded ZIP64 directory size")
            .to_le_bytes(),
    );
    image
}

fn zip64_all_selected_entry_fields_archive() -> Vec<u8> {
    let mut image: Vec<u8> = zip64_local_offset_archive();
    let central: usize = signature_offset(&image, [b'P', b'K', 0x01, 0x02]);
    let name_len: usize = usize::from(u16::from_le_bytes([
        image[central + 28],
        image[central + 29],
    ]));
    let compressed_size: u64 = u64::from(u32::from_le_bytes(
        image[central + 20..central + 24]
            .try_into()
            .expect("central compressed size"),
    ));
    let uncompressed_size: u64 = u64::from(u32::from_le_bytes(
        image[central + 24..central + 28]
            .try_into()
            .expect("central uncompressed size"),
    ));
    let extra: usize = central + 46 + name_len;
    image[central + 20..central + 28]
        .chunks_exact_mut(4)
        .for_each(|field: &mut [u8]| field.copy_from_slice(&u32::MAX.to_le_bytes()));
    image[central + 34..central + 36].copy_from_slice(&u16::MAX.to_le_bytes());
    image[central + 30..central + 32].copy_from_slice(&32u16.to_le_bytes());
    image[extra + 2..extra + 4].copy_from_slice(&28u16.to_le_bytes());
    let mut sizes: Vec<u8> = Vec::with_capacity(16);
    sizes.extend_from_slice(&uncompressed_size.to_le_bytes());
    sizes.extend_from_slice(&compressed_size.to_le_bytes());
    image.splice(extra + 4..extra + 4, sizes);
    image.splice(extra + 28..extra + 28, 0u32.to_le_bytes());

    let eocd64: usize = signature_offset(&image, [b'P', b'K', 0x06, 0x06]);
    let locator: usize = signature_offset(&image, [b'P', b'K', 0x06, 0x07]);
    let eocd: usize = signature_offset(&image, [b'P', b'K', 0x05, 0x06]);
    let directory_size: u64 = u64::from_le_bytes(
        image[eocd64 + 40..eocd64 + 48]
            .try_into()
            .expect("ZIP64 directory size field"),
    ) + 20;
    image[eocd64 + 40..eocd64 + 48].copy_from_slice(&directory_size.to_le_bytes());
    image[locator + 8..locator + 16].copy_from_slice(
        &u64::try_from(eocd64)
            .expect("bounded ZIP64 EOCD offset")
            .to_le_bytes(),
    );
    image[eocd + 12..eocd + 16].copy_from_slice(
        &u32::try_from(directory_size)
            .expect("bounded ZIP64 directory size")
            .to_le_bytes(),
    );
    image
}

fn zip64_size_only_archive() -> Vec<u8> {
    let mut image: Vec<u8> = zip64_stored_zip();
    let eocd: usize = signature_offset(&image, [b'P', b'K', 0x05, 0x06]);
    image[eocd + 8..eocd + 12]
        .chunks_exact_mut(2)
        .for_each(|field: &mut [u8]| field.copy_from_slice(&1u16.to_le_bytes()));
    image[eocd + 12..eocd + 16].copy_from_slice(&u32::MAX.to_le_bytes());
    image
}

fn zip64_offset_only_archive() -> Vec<u8> {
    let mut image: Vec<u8> = zip64_stored_zip();
    let eocd: usize = signature_offset(&image, [b'P', b'K', 0x05, 0x06]);
    image[eocd + 8..eocd + 12]
        .chunks_exact_mut(2)
        .for_each(|field: &mut [u8]| field.copy_from_slice(&1u16.to_le_bytes()));
    image[eocd + 16..eocd + 20].copy_from_slice(&u32::MAX.to_le_bytes());
    image
}

fn insert_false_zip64_end_signature(image: &mut Vec<u8>) {
    let eocd64: usize = signature_offset(image.as_slice(), [b'P', b'K', 0x06, 0x06]);
    let locator: usize = signature_offset(image.as_slice(), [b'P', b'K', 0x06, 0x07]);
    let mut block: Vec<u8> = Vec::with_capacity(80);
    block.extend_from_slice(&0x4321u16.to_le_bytes());
    block.extend_from_slice(&74u32.to_le_bytes());
    block.extend_from_slice(&[b'P', b'K', 0x06, 0x06]);
    block.extend_from_slice(&62u64.to_le_bytes());
    block.resize(80, 0x5a);
    image[eocd64 + 4..eocd64 + 12].copy_from_slice(&124u64.to_le_bytes());
    image.splice(locator..locator, block);
}

fn zip64_size_only_archive_with_false_end_signature() -> Vec<u8> {
    let mut image: Vec<u8> = zip64_size_only_archive();
    insert_false_zip64_end_signature(&mut image);
    image
}

fn zip64_sfx_with_pre_record_decoy() -> Vec<u8> {
    let mut archive: Vec<u8> = zip64_stored_zip();
    force_zip64_count_mismatch(&mut archive);
    let locator: usize = signature_offset(&archive, [b'P', b'K', 0x06, 0x07]);
    let logical_eocd: usize = usize::try_from(u64::from_le_bytes(
        archive[locator + 8..locator + 16]
            .try_into()
            .expect("ZIP64 locator offset"),
    ))
    .expect("bounded logical ZIP64 offset");
    let prefix_len: usize = logical_eocd + 96;
    let mut image: Vec<u8> = vec![0x41; prefix_len];
    let decoy: usize = logical_eocd + 8;
    let physical_locator: usize = prefix_len + locator;
    let decoy_size: u64 =
        u64::try_from(physical_locator - decoy - 12).expect("bounded decoy ZIP64 record size");
    image[decoy..decoy + 4].copy_from_slice(&[b'P', b'K', 0x06, 0x06]);
    image[decoy + 4..decoy + 12].copy_from_slice(&decoy_size.to_le_bytes());
    image.extend_from_slice(&archive);
    image
}

#[test]
fn an_empty_file_says_it_is_empty_rather_than_blaming_a_missing_directory() {
    let reason: String = refusal_reason(&[]);
    assert_eq!(
        reason,
        "DR-BINFMT-0003: zip parse failed: the input is empty, so it holds no archive"
    );
}

#[test]
fn a_body_that_is_not_an_archive_says_no_directory_record_exists() {
    let mut image: Vec<u8> = vec![b'P', b'K', 0x03, 0x04];
    image.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
    image.resize(512, 0);
    let reason: String = refusal_reason(&image);
    assert_eq!(
        reason,
        "DR-BINFMT-0003: zip parse failed: no end-of-central-directory record in the last 512 byte(s), so this is not a zip archive whatever its leading bytes say"
    );
}

#[test]
fn a_directory_pointing_past_the_file_names_the_offset_and_the_size() {
    let mut image: Vec<u8> = vec![0u8; 64];
    image.extend_from_slice(&eocd(1, 0x00FF_FFFF, 0x40));
    let reason: String = refusal_reason(&image);
    assert!(
        reason.contains("ends past the"),
        "an out-of-range central directory must say so; saw: {reason}"
    );
}

#[test]
fn a_declared_count_the_archive_cannot_satisfy_says_that_and_not_that_the_record_is_missing() {
    let mut image: Vec<u8> = vec![0u8; 64];
    image.extend_from_slice(&eocd(2, 0, 0));
    let reason: String = refusal_reason(&image);
    assert_eq!(
        reason,
        "DR-BINFMT-0003: zip parse failed: the end-of-central-directory record declares 2 entries, but the central directory contains 0"
    );
}

#[test]
fn a_truncated_central_directory_record_names_the_required_and_available_bytes() {
    let mut directory: Vec<u8> = central_directory_entry(b"entry.bin");
    directory.truncate(48);
    let directory_len: u32 = u32::try_from(directory.len()).expect("bounded directory");
    let mut image: Vec<u8> = directory;
    image.extend_from_slice(&eocd(1, 0, directory_len));
    let reason: String = refusal_reason(&image);
    assert_eq!(
        reason,
        "DR-BINFMT-0003: zip parse failed: central-directory entry 0 declares 55 byte(s), but only 48 remain"
    );
}

#[test]
fn a_signature_inside_the_comment_does_not_hide_the_real_directory_record() {
    let mut image: Vec<u8> = eocd(1, 0, 0);
    image[20..22].copy_from_slice(&22u16.to_le_bytes());
    image.extend_from_slice(&eocd(2, 0, 0));
    let reason: String = refusal_reason(&image);
    assert_eq!(
        reason,
        "DR-BINFMT-0003: zip parse failed: the end-of-central-directory record declares 1 entry, but the central directory contains 0"
    );
}

#[test]
fn a_self_extracting_prefix_does_not_turn_relative_directory_offsets_into_a_refusal() {
    let mut image: Vec<u8> = b"MZ\x90\0self-extracting-prefix".to_vec();
    image.extend_from_slice(&stored_zip());
    let scratch: ScratchDir = ScratchDir::create("zip-sfx").expect("scratch dir");
    let out: PathBuf = scratch.path().join("out");
    let result: ExtractionResult =
        extract_to(ContainerKind::Zip, &image, &out).expect("SFX zip extracts");
    assert_eq!(result.entries.len(), 1);
    assert_eq!(
        std::fs::read(out.join("payload.bin")).expect("read extracted entry"),
        b"payload"
    );
}

#[test]
fn a_malformed_self_extracting_zip_counts_its_relative_directory() {
    let mut image: Vec<u8> = b"MZ\x90\0self-extracting-prefix".to_vec();
    image.extend_from_slice(&stored_zip());
    let eocd_offset: usize = image
        .windows(4)
        .rposition(|window: &[u8]| window == [b'P', b'K', 0x05, 0x06])
        .expect("stored zip has EOCD");
    image[eocd_offset + 8..eocd_offset + 12]
        .chunks_exact_mut(2)
        .for_each(|field: &mut [u8]| field.copy_from_slice(&2u16.to_le_bytes()));
    let reason: String = refusal_reason(&image);
    assert_eq!(
        reason,
        "DR-BINFMT-0003: zip parse failed: the end-of-central-directory record declares 2 entries, but the central directory contains 1"
    );
}

#[test]
fn a_directory_offset_into_a_local_record_names_the_bad_local_mapping() {
    let mut image: Vec<u8> = stored_zip();
    let eocd_offset: usize = image
        .windows(4)
        .rposition(|window: &[u8]| window == [b'P', b'K', 0x05, 0x06])
        .expect("stored zip has EOCD");
    image[eocd_offset + 16..eocd_offset + 20].copy_from_slice(&0u32.to_le_bytes());
    let reason: String = refusal_reason(&image);
    assert_eq!(
        reason,
        "DR-BINFMT-0003: zip parse failed: central-directory entry 0 points to local-header offset 0, which does not identify a local file record"
    );
}

#[test]
fn central_entries_on_another_classic_disk_are_refused_for_one_input_file() {
    let mut classic: Vec<u8> = stored_zip();
    let classic_central: usize = signature_offset(&classic, [b'P', b'K', 0x01, 0x02]);
    classic[classic_central + 34..classic_central + 36].copy_from_slice(&1u16.to_le_bytes());
    let classic_eocd: usize = signature_offset(&classic, [b'P', b'K', 0x05, 0x06]);
    classic[classic_eocd + 8..classic_eocd + 12]
        .chunks_exact_mut(2)
        .for_each(|field: &mut [u8]| field.copy_from_slice(&2u16.to_le_bytes()));

    let mut zip64: Vec<u8> = zip64_local_offset_archive();
    let zip64_central: usize = signature_offset(&zip64, [b'P', b'K', 0x01, 0x02]);
    zip64[zip64_central + 34..zip64_central + 36].copy_from_slice(&1u16.to_le_bytes());
    force_zip64_count_mismatch(&mut zip64);

    for image in [&classic, &zip64] {
        let reason: String = refusal_reason(image);
        assert_eq!(
            reason,
            "DR-BINFMT-0003: zip parse failed: central-directory entry 0 starts on disk 1, but only one input file was provided"
        );
    }
}

#[test]
fn a_valid_zip64_locator_and_directory_are_extracted_in_process() {
    let image: Vec<u8> = zip64_stored_zip();
    let scratch: ScratchDir = ScratchDir::create("zip64-valid").expect("scratch dir");
    let out: PathBuf = scratch.path().join("out");
    let result: ExtractionResult =
        extract_to(ContainerKind::Zip, &image, &out).expect("ZIP64 zip extracts");
    assert_eq!(result.entries.len(), 1);
    assert_eq!(
        std::fs::read(out.join("payload.bin")).expect("read ZIP64 entry"),
        b"payload"
    );
}

#[test]
fn a_size_only_zip64_sentinel_extracts_without_being_misdiagnosed() {
    let image: Vec<u8> = zip64_size_only_archive();
    let upstream: zip::ZipArchive<Cursor<&[u8]>> =
        zip::ZipArchive::new(Cursor::new(image.as_slice())).expect("size-only ZIP64 parses");
    assert_eq!(upstream.len(), 1);
    let scratch: ScratchDir = ScratchDir::create("zip64-size-only").expect("scratch dir");
    let out: PathBuf = scratch.path().join("out");
    let result: ExtractionResult =
        extract_to(ContainerKind::Zip, &image, &out).expect("size-only ZIP64 extracts");
    assert_eq!(result.entries.len(), 1);
    assert_eq!(
        std::fs::read(out.join("payload.bin")).expect("read size-only ZIP64 entry"),
        b"payload"
    );
}

#[test]
fn a_size_only_zip64_sentinel_with_an_sfx_prefix_extracts() {
    let mut image: Vec<u8> = b"MZ\x90\0size-only-zip64-prefix".to_vec();
    image.extend_from_slice(&zip64_size_only_archive());
    let scratch: ScratchDir = ScratchDir::create("zip64-size-only-sfx").expect("scratch dir");
    let out: PathBuf = scratch.path().join("out");
    let result: ExtractionResult =
        extract_to(ContainerKind::Zip, &image, &out).expect("size-only ZIP64 SFX extracts");
    assert_eq!(result.entries.len(), 1);
    assert_eq!(
        std::fs::read(out.join("payload.bin")).expect("read size-only ZIP64 SFX entry"),
        b"payload"
    );
}

#[test]
fn an_offset_only_zip64_sentinel_extracts_with_and_without_an_sfx_prefix() {
    let plain: Vec<u8> = zip64_offset_only_archive();
    let mut sfx: Vec<u8> = b"MZ\x90\0offset-only-zip64-prefix".to_vec();
    sfx.extend_from_slice(&plain);
    for (name, image) in [("plain", plain), ("sfx", sfx)] {
        let scratch: ScratchDir =
            ScratchDir::create(&format!("zip64-offset-only-{name}")).expect("scratch dir");
        let out: PathBuf = scratch.path().join("out");
        let result: ExtractionResult =
            extract_to(ContainerKind::Zip, &image, &out).expect("offset-only ZIP64 extracts");
        assert_eq!(result.entries.len(), 1);
        assert_eq!(
            std::fs::read(out.join("payload.bin")).expect("read offset-only ZIP64 entry"),
            b"payload"
        );
    }
}

#[test]
fn a_false_zip64_end_signature_inside_extensible_data_cannot_hide_the_real_record() {
    let image: Vec<u8> = zip64_size_only_archive_with_false_end_signature();
    let scratch: ScratchDir = ScratchDir::create("zip64-false-end-signature").expect("scratch dir");
    let out: PathBuf = scratch.path().join("out");
    let result: ExtractionResult = extract_to(ContainerKind::Zip, &image, &out)
        .expect("the real ZIP64 end record remains authoritative");
    assert_eq!(result.entries.len(), 1);
    assert_eq!(
        std::fs::read(out.join("payload.bin")).expect("read false-signature ZIP64 entry"),
        b"payload"
    );
}

#[test]
fn zip64_diagnostics_ignore_a_false_end_signature_inside_extensible_data() {
    let mut image: Vec<u8> = zip64_stored_zip();
    force_zip64_count_mismatch(&mut image);
    insert_false_zip64_end_signature(&mut image);
    let reason: String = refusal_reason(&image);
    assert_eq!(
        reason,
        "DR-BINFMT-0003: zip parse failed: the ZIP64 end-of-central-directory record declares 2 entries, but the central directory contains 1"
    );
}

#[test]
fn zip64_diagnostics_reject_a_pre_record_sfx_decoy_before_selecting_the_real_record() {
    let image: Vec<u8> = zip64_sfx_with_pre_record_decoy();
    let reason: String = refusal_reason(&image);
    assert_eq!(
        reason,
        "DR-BINFMT-0003: zip parse failed: the ZIP64 end-of-central-directory record declares 2 entries, but the central directory contains 1"
    );
}

#[test]
fn a_valid_zip64_archive_with_a_self_extracting_prefix_is_extracted_in_process() {
    let mut image: Vec<u8> = b"MZ\x90\0zip64-self-extracting-prefix".to_vec();
    image.extend_from_slice(&zip64_stored_zip());
    let scratch: ScratchDir = ScratchDir::create("zip64-sfx-valid").expect("scratch dir");
    let out: PathBuf = scratch.path().join("out");
    let result: ExtractionResult =
        extract_to(ContainerKind::Zip, &image, &out).expect("ZIP64 SFX extracts");
    assert_eq!(result.entries.len(), 1);
    assert_eq!(
        std::fs::read(out.join("payload.bin")).expect("read ZIP64 SFX entry"),
        b"payload"
    );
}

#[test]
fn a_zip64_central_entry_resolves_its_local_offset_from_extra_data() {
    let image: Vec<u8> = zip64_local_offset_archive();
    let scratch: ScratchDir = ScratchDir::create("zip64-local-offset").expect("scratch dir");
    let out: PathBuf = scratch.path().join("out");
    let result: ExtractionResult =
        extract_to(ContainerKind::Zip, &image, &out).expect("ZIP64 local offset resolves");
    assert_eq!(result.entries.len(), 1);
    assert_eq!(
        std::fs::read(out.join("payload.bin")).expect("read ZIP64 offset entry"),
        b"payload"
    );
}

#[test]
fn zip64_diagnostics_resolve_a_valid_extra_field_before_counting() {
    let mut image: Vec<u8> = zip64_local_offset_archive();
    force_zip64_count_mismatch(&mut image);
    let reason: String = refusal_reason(&image);
    assert_eq!(
        reason,
        "DR-BINFMT-0003: zip parse failed: the ZIP64 end-of-central-directory record declares 2 entries, but the central directory contains 1"
    );
}

#[test]
fn zip64_entry_fields_follow_the_selected_size_offset_and_disk_order() {
    let image: Vec<u8> = zip64_all_selected_entry_fields_archive();
    let scratch: ScratchDir = ScratchDir::create("zip64-all-entry-fields").expect("scratch dir");
    let out: PathBuf = scratch.path().join("out");
    let result: ExtractionResult = extract_to(ContainerKind::Zip, &image, &out)
        .expect("all selected ZIP64 entry fields resolve");
    assert_eq!(result.entries.len(), 1);
    assert_eq!(
        std::fs::read(out.join("payload.bin")).expect("read all-field ZIP64 entry"),
        b"payload"
    );

    let mut malformed: Vec<u8> = image;
    force_zip64_count_mismatch(&mut malformed);
    let reason: String = refusal_reason(&malformed);
    assert_eq!(
        reason,
        "DR-BINFMT-0003: zip parse failed: the ZIP64 end-of-central-directory record declares 2 entries, but the central directory contains 1"
    );
}

#[test]
fn a_zip64_directory_count_mismatch_uses_the_locator_metadata() {
    let mut image: Vec<u8> = zip64_stored_zip();
    force_zip64_count_mismatch(&mut image);
    let reason: String = refusal_reason(&image);
    assert_eq!(
        reason,
        "DR-BINFMT-0003: zip parse failed: the ZIP64 end-of-central-directory record declares 2 entries, but the central directory contains 1"
    );
}

#[test]
fn a_zip64_sfx_count_mismatch_uses_archive_relative_offsets() {
    let mut image: Vec<u8> = b"MZ\x90\0zip64-self-extracting-prefix".to_vec();
    image.extend_from_slice(&zip64_stored_zip());
    force_zip64_count_mismatch(&mut image);
    let reason: String = refusal_reason(&image);
    assert_eq!(
        reason,
        "DR-BINFMT-0003: zip parse failed: the ZIP64 end-of-central-directory record declares 2 entries, but the central directory contains 1"
    );
}

#[test]
fn zip64_multi_disk_metadata_is_refused_as_an_unsupported_layout() {
    let mut image: Vec<u8> = zip64_stored_zip();
    let locator: usize = signature_offset(&image, [b'P', b'K', 0x06, 0x07]);
    image[locator + 16..locator + 20].copy_from_slice(&2u32.to_le_bytes());
    let reason: String = refusal_reason(&image);
    assert_eq!(
        reason,
        "DR-BINFMT-0003: zip parse failed: the ZIP64 multi-disk layout is unsupported for one input file: end_record_disk=0, total_disks=2"
    );
}

#[test]
fn invalid_zip64_locator_disk_metadata_is_reported_before_entry_scanning() {
    let mut zero_disks: Vec<u8> = zip64_stored_zip();
    let zero_locator: usize = signature_offset(&zero_disks, [b'P', b'K', 0x06, 0x07]);
    zero_disks[zero_locator + 16..zero_locator + 20].copy_from_slice(&0u32.to_le_bytes());
    force_zip64_count_mismatch(&mut zero_disks);

    let mut second_disk: Vec<u8> = zip64_stored_zip();
    let second_locator: usize = signature_offset(&second_disk, [b'P', b'K', 0x06, 0x07]);
    second_disk[second_locator + 4..second_locator + 8].copy_from_slice(&1u32.to_le_bytes());
    force_zip64_count_mismatch(&mut second_disk);

    let zero_reason: String = refusal_reason(&zero_disks);
    let second_reason: String = refusal_reason(&second_disk);
    assert_eq!(
        zero_reason,
        "DR-BINFMT-0003: zip parse failed: the ZIP64 multi-disk layout is unsupported for one input file: end_record_disk=0, total_disks=0"
    );
    assert_eq!(
        second_reason,
        "DR-BINFMT-0003: zip parse failed: the ZIP64 multi-disk layout is unsupported for one input file: end_record_disk=1, total_disks=1"
    );
}

#[test]
fn a_zip64_locator_offset_at_the_locator_is_rejected_without_scanning_past_it() {
    let mut image: Vec<u8> = zip64_stored_zip();
    let locator: usize = signature_offset(&image, [b'P', b'K', 0x06, 0x07]);
    image[locator + 8..locator + 16].copy_from_slice(&(locator as u64).to_le_bytes());
    force_zip64_count_mismatch(&mut image);
    let reason: String = refusal_reason(&image);
    assert_eq!(
        reason,
        format!(
            "DR-BINFMT-0003: zip parse failed: the ZIP64 locator points to end record offset {locator}, which is not before the locator at {locator}"
        )
    );
}

#[test]
fn a_truncated_zip64_extensible_block_is_named_exactly() {
    let mut image: Vec<u8> = zip64_stored_zip();
    force_zip64_count_mismatch(&mut image);
    let eocd64: usize = signature_offset(&image, [b'P', b'K', 0x06, 0x06]);
    let locator: usize = signature_offset(&image, [b'P', b'K', 0x06, 0x07]);
    image[eocd64 + 4..eocd64 + 12].copy_from_slice(&47u64.to_le_bytes());
    image.splice(locator..locator, [0x01, 0x00, 0x00]);
    let reason: String = refusal_reason(&image);
    assert_eq!(
        reason,
        "DR-BINFMT-0003: zip parse failed: the ZIP64 extensible sector ends with a truncated block header"
    );
}

#[test]
fn a_zip64_end_record_below_its_fixed_minimum_is_named_exactly() {
    let mut image: Vec<u8> = zip64_stored_zip();
    force_zip64_count_mismatch(&mut image);
    let eocd64: usize = signature_offset(&image, [b'P', b'K', 0x06, 0x06]);
    let locator: usize = signature_offset(&image, [b'P', b'K', 0x06, 0x07]);
    image[eocd64 + 4..eocd64 + 12].copy_from_slice(&43u64.to_le_bytes());
    image.remove(locator - 1);
    let reason: String = refusal_reason(&image);
    assert_eq!(
        reason,
        "DR-BINFMT-0003: zip parse failed: the ZIP64 end record declares 43 byte(s) after its size field, below the 44-byte fixed minimum"
    );
}

#[test]
fn classic_and_zip64_non_sentinel_fields_must_agree() {
    let mut image: Vec<u8> = zip64_stored_zip();
    force_zip64_count_mismatch(&mut image);
    let eocd: usize = signature_offset(&image, [b'P', b'K', 0x05, 0x06]);
    let classic_size: u32 = u32::from_le_bytes(
        image[eocd + 12..eocd + 16]
            .try_into()
            .expect("classic directory size"),
    );
    image[eocd + 12..eocd + 16].copy_from_slice(
        &classic_size
            .checked_add(1)
            .expect("bounded classic directory size")
            .to_le_bytes(),
    );
    let reason: String = refusal_reason(&image);
    assert_eq!(
        reason,
        "DR-BINFMT-0003: zip parse failed: the classic and ZIP64 end-of-central-directory records disagree"
    );
}

#[test]
fn a_zip64_extensible_payload_cannot_cross_into_the_locator() {
    let mut image: Vec<u8> = zip64_stored_zip();
    force_zip64_count_mismatch(&mut image);
    let eocd64: usize = signature_offset(&image, [b'P', b'K', 0x06, 0x06]);
    let locator: usize = signature_offset(&image, [b'P', b'K', 0x06, 0x07]);
    image[eocd64 + 4..eocd64 + 12].copy_from_slice(&52u64.to_le_bytes());
    image.splice(
        locator..locator,
        [0x01, 0x00, 0x05, 0x00, 0x00, 0x00, 0xaa, 0xbb],
    );
    let reason: String = refusal_reason(&image);
    assert_eq!(
        reason,
        "DR-BINFMT-0003: zip parse failed: a ZIP64 extensible-sector block extends past the ZIP64 end record"
    );
}

#[test]
fn bounded_unknown_zip64_extensible_blocks_are_skipped() {
    let mut image: Vec<u8> = zip64_stored_zip();
    force_zip64_count_mismatch(&mut image);
    let eocd64: usize = signature_offset(&image, [b'P', b'K', 0x06, 0x06]);
    let locator: usize = signature_offset(&image, [b'P', b'K', 0x06, 0x07]);
    let blocks: [u8; 15] = [
        0x34, 0x12, 0x02, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0x78, 0x56, 0x01, 0x00, 0x00, 0x00, 0xcc,
    ];
    image[eocd64 + 4..eocd64 + 12].copy_from_slice(&59u64.to_le_bytes());
    image.splice(locator..locator, blocks);
    let reason: String = refusal_reason(&image);
    assert_eq!(
        reason,
        "DR-BINFMT-0003: zip parse failed: the ZIP64 end-of-central-directory record declares 2 entries, but the central directory contains 1"
    );
}

#[test]
fn a_truncated_zip64_local_offset_field_is_named_exactly() {
    let mut image: Vec<u8> = zip64_local_offset_archive();
    let central: usize = signature_offset(&image, [b'P', b'K', 0x01, 0x02]);
    let name_len: usize = usize::from(u16::from_le_bytes([
        image[central + 28],
        image[central + 29],
    ]));
    let extra_offset: usize = central + 46 + name_len;
    image[extra_offset + 2..extra_offset + 4].copy_from_slice(&4u16.to_le_bytes());
    force_zip64_count_mismatch(&mut image);
    let reason: String = refusal_reason(&image);
    assert_eq!(
        reason,
        "DR-BINFMT-0003: zip parse failed: central-directory entry 0 omits its ZIP64 local-header offset"
    );
}

#[test]
fn the_zip64_sentinel_is_reported_as_a_sentinel_and_not_as_an_impossible_count() {
    let mut disk_number_sentinel: Vec<u8> = eocd(1, 0, 0);
    disk_number_sentinel[4..6].copy_from_slice(&u16::MAX.to_le_bytes());
    let mut directory_disk_sentinel: Vec<u8> = eocd(1, 0, 0);
    directory_disk_sentinel[6..8].copy_from_slice(&u16::MAX.to_le_bytes());
    let mut count_sentinel: Vec<u8> = eocd(1, 0, 0);
    count_sentinel[8..10].copy_from_slice(&u16::MAX.to_le_bytes());
    let size_sentinel: Vec<u8> = eocd(1, 0, u32::MAX);
    let offset_sentinel: Vec<u8> = eocd(1, u32::MAX, 0);
    for image in [
        &disk_number_sentinel,
        &directory_disk_sentinel,
        &count_sentinel,
        &eocd(u16::MAX, 0, 0),
        &size_sentinel,
        &offset_sentinel,
    ] {
        let reason: String = refusal_reason(image);
        assert_eq!(
            reason,
            "DR-BINFMT-0003: zip parse failed: the end-of-central-directory record uses a reserved ZIP64 sentinel, but the 20-byte ZIP64 locator immediately before it is absent"
        );
    }
}

#[test]
fn four_different_malformations_never_render_as_one_message() {
    let mut not_an_archive: Vec<u8> = vec![b'P', b'K', 0x03, 0x04];
    not_an_archive.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
    not_an_archive.resize(512, 0);

    let mut out_of_range: Vec<u8> = vec![0u8; 64];
    out_of_range.extend_from_slice(&eocd(1, 0x00FF_FFFF, 0x40));

    let mut unsatisfiable: Vec<u8> = vec![0u8; 64];
    unsatisfiable.extend_from_slice(&eocd(2, 0, 0));

    let reasons: Vec<String> = vec![
        refusal_reason(&[]),
        refusal_reason(&not_an_archive),
        refusal_reason(&out_of_range),
        refusal_reason(&unsatisfiable),
    ];
    let distinct: BTreeSet<&String> = reasons.iter().collect();
    assert_eq!(
        distinct.len(),
        reasons.len(),
        "four different malformations collapsed onto fewer messages, which is the defect this test exists for: {reasons:#?}"
    );
}
