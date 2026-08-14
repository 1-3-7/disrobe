#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_binfmt::{ContainerKind, extract_to};
use disrobe_core::scratch::ScratchDir;

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

fn refusal_reason(image: &[u8]) -> String {
    let scratch: ScratchDir = ScratchDir::create("zip-refusal").expect("scratch dir");
    let out: PathBuf = scratch.path().join("out");
    let error: disrobe_binfmt::Error = extract_to(ContainerKind::Zip, image, &out)
        .expect_err("every image in this test is malformed and must be refused");
    error.to_string()
}

#[test]
fn an_empty_file_says_it_is_empty_rather_than_blaming_a_missing_directory() {
    let reason: String = refusal_reason(&[]);
    assert!(
        reason.contains("empty"),
        "an empty input must say so; saw: {reason}"
    );
}

#[test]
fn a_body_that_is_not_an_archive_says_no_directory_record_exists() {
    let mut image: Vec<u8> = vec![b'P', b'K', 0x03, 0x04];
    image.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
    image.resize(512, 0);
    let reason: String = refusal_reason(&image);
    assert!(
        reason.contains("no end-of-central-directory record"),
        "a file whose magic lies must be told apart from a real archive; saw: {reason}"
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
    assert!(
        reason.contains("does not satisfy"),
        "an unsatisfiable entry count must be named; saw: {reason}"
    );
}

#[test]
fn the_zip64_sentinel_is_reported_as_a_sentinel_and_not_as_an_impossible_count() {
    let mut image: Vec<u8> = vec![0u8; 64];
    image.extend_from_slice(&eocd(0xFFFF, 0, 0));
    let reason: String = refusal_reason(&image);
    assert!(
        reason.contains("zip64"),
        "0xFFFF is the zip64 sentinel, not a count; saw: {reason}"
    );
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
