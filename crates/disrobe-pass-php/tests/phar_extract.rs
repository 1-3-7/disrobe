#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    unreachable_pub,
    dead_code,
    clippy::print_stdout,
    clippy::redundant_pub_crate,
    clippy::std_instead_of_alloc,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo
)]

mod common;

use disrobe_pass_php::{Error, PharArchive, PharEntry, extract_phar_entry, parse_phar};

#[test]
fn parses_tiny_phar_with_one_file() {
    let phar = common::build_tiny_phar(
        &common::default_phar_stub(),
        &[("hello.php", b"<?php echo 'hi';")],
    );
    let archive = parse_phar(&phar).expect("parse");
    assert_eq!(archive.entries.len(), 1);
    let entry = archive.entries.get("hello.php").expect("entry");
    assert_eq!(entry.uncompressed_size, 16);
    assert_eq!(entry.stored_size, 16);
}

#[test]
fn extracts_uncompressed_payload_byte_perfect() {
    let body: &[u8] = b"<?php return 42;";
    let phar = common::build_tiny_phar(&common::default_phar_stub(), &[("r.php", body)]);
    let archive = parse_phar(&phar).expect("parse");
    let extracted = extract_phar_entry(&archive, &phar, "r.php").expect("extract");
    assert_eq!(extracted, body);
}

#[test]
fn extract_from_post_parse_truncated_buffer_returns_payload_error() {
    let body: &[u8] = b"<?php echo 'safe';";
    let phar: Vec<u8> =
        common::build_tiny_phar(&common::default_phar_stub(), &[("late.php", body)]);
    let archive: PharArchive = parse_phar(&phar).expect("parse");
    let entry: &PharEntry = archive.entries.get("late.php").expect("entry");
    let kept_payload: usize = usize::try_from(entry.stored_size / 2).expect("stored size");
    let truncated_len: usize = entry
        .data_offset
        .checked_add(kept_payload)
        .expect("truncate length");
    let truncated: &[u8] = &phar[..truncated_len];
    let err: Error =
        extract_phar_entry(&archive, truncated, "late.php").expect_err("truncated payload");
    let msg: String = format!("{err}");
    assert!(msg.contains("DR-PHP-0025"), "got: {msg}");
    let payload_error: Option<(String, u32, usize)> = match err {
        Error::PharEntryPayloadTruncated { name, need, got } => Some((name, need, got)),
        _ => None,
    };
    let (name, need, got): (String, u32, usize) =
        payload_error.expect("payload truncation variant");
    assert_eq!(name, "late.php");
    assert_eq!(need, entry.stored_size);
    assert_eq!(got, kept_payload);
}

#[test]
fn parses_multi_entry_phar_sorted_btree() {
    let phar = common::build_tiny_phar(
        &common::default_phar_stub(),
        &[
            ("zeta.php", b"<?php //z"),
            ("alpha.php", b"<?php //a"),
            ("mu.php", b"<?php //m"),
        ],
    );
    let archive = parse_phar(&phar).expect("parse");
    let names: Vec<&str> = archive.entries.keys().map(String::as_str).collect();
    assert_eq!(names, ["alpha.php", "mu.php", "zeta.php"]);
}

#[test]
fn rejects_phar_without_halt_sentinel() {
    let err = parse_phar(b"<?php echo 1;").expect_err("must fail");
    let msg = format!("{err}");
    assert!(msg.contains("DR-PHP-0021"), "got: {msg}");
}

#[test]
fn rejects_too_small_input() {
    let err = parse_phar(b"ab").expect_err("must fail");
    let msg = format!("{err}");
    assert!(msg.contains("DR-PHP-0020"), "got: {msg}");
}

#[test]
fn rejects_truncated_manifest_after_halt_sentinel() {
    let truncated: &[u8] = b"<?php __HALT_COMPILER(); ?>\n\x10\x00";
    let err = parse_phar(truncated).expect_err("truncated manifest must fail cleanly");
    let msg = format!("{err}");
    assert!(msg.contains("DR-PHP-0022"), "got: {msg}");
}

#[test]
fn rejects_entry_metadata_outside_declared_manifest() {
    let mut phar: Vec<u8> =
        common::build_tiny_phar(&common::default_phar_stub(), &[("empty.php", b"")]);
    let manifest_offset: usize = common::default_phar_stub().len() + 1;
    phar[manifest_offset..manifest_offset + 4].copy_from_slice(&14u32.to_le_bytes());
    let err: Error = parse_phar(&phar).expect_err("metadata past manifest must fail");
    let msg: String = format!("{err}");
    assert!(msg.contains("DR-PHP-0022"), "got: {msg}");
}

#[test]
fn rejects_absurd_entry_count_without_allocating() {
    let mut blob: Vec<u8> = b"<?php __HALT_COMPILER(); ?>\n".to_vec();
    blob.extend_from_slice(&64u32.to_le_bytes());
    blob.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    blob.extend_from_slice(&0x0011u16.to_be_bytes());
    blob.extend(std::iter::repeat_n(0u8, 32));
    let err = parse_phar(&blob).expect_err("absurd entry count must be rejected");
    let msg = format!("{err}");
    assert!(msg.contains("DR-PHP-0023"), "got: {msg}");
}

#[test]
fn malformed_phar_never_panics_on_random_bytes() {
    for seed in 0u8..32 {
        let mut bytes: Vec<u8> = b"<?php __HALT_COMPILER(); ?>\nGBMB".to_vec();
        bytes
            .extend((0..200u16).map(|i: u16| (i.wrapping_mul(31).wrapping_add(seed.into())) as u8));
        let _ = parse_phar(&bytes);
    }
}
