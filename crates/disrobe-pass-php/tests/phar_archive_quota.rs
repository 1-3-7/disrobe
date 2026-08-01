#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo
)]

mod common;

use common::{PHAR_FLAG_DEFLATE, PharFixtureEntry};
use disrobe_pass_php::{Error, PHAR_DECOMPRESS_CAP, extract_phar_entry, parse_phar};

const ENTRY_OUTPUT_BYTES: usize = 64 * 1024;
const QUOTA_ENTRY_COUNT: usize = PHAR_DECOMPRESS_CAP / ENTRY_OUTPUT_BYTES;

fn build_quota_archive(entry_count: usize) -> Vec<u8> {
    let payload: Vec<u8> = vec![b'Q'; ENTRY_OUTPUT_BYTES];
    let compressed: Vec<u8> = common::deflate(&payload);
    let names: Vec<String> = (0..entry_count)
        .map(|index: usize| format!("members/{index:05}.php"))
        .collect();
    let entries: Vec<PharFixtureEntry<'_>> = names
        .iter()
        .map(|name: &String| PharFixtureEntry {
            name,
            stored: &compressed,
            declared_uncompressed: u32::try_from(ENTRY_OUTPUT_BYTES).expect("entry size fits"),
            crc32: 0,
            flags: PHAR_FLAG_DEFLATE,
        })
        .collect();
    common::build_phar_with_entries(&common::default_phar_stub(), &entries)
}

#[test]
fn individually_valid_members_at_the_archive_quota_remain_extractable() {
    let phar: Vec<u8> = build_quota_archive(QUOTA_ENTRY_COUNT);
    let archive = parse_phar(&phar).expect("archive at quota parses");
    assert_eq!(archive.entries.len(), QUOTA_ENTRY_COUNT);
    let extracted: Vec<u8> =
        extract_phar_entry(&archive, &phar, "members/00000.php").expect("entry extracts");
    assert_eq!(extracted, vec![b'Q'; ENTRY_OUTPUT_BYTES]);
}

#[test]
fn added_member_past_archive_quota_fails_closed() {
    let phar: Vec<u8> = build_quota_archive(QUOTA_ENTRY_COUNT + 1);
    let error: Error =
        parse_phar(&phar).expect_err("archive past quota must refuse during parsing");
    match error {
        Error::PharArchiveQuotaExceeded { declared, cap } => {
            assert_eq!(declared, PHAR_DECOMPRESS_CAP + ENTRY_OUTPUT_BYTES);
            assert_eq!(cap, PHAR_DECOMPRESS_CAP);
        }
        other => panic!("expected archive quota refusal, got {other:?}"),
    }
}
