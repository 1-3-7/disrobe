#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::missing_const_for_fn
)]

#[path = "support/php_toolchain.rs"]
#[allow(
    dead_code,
    clippy::redundant_pub_crate,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod php_toolchain;

use disrobe_pass_php::{PharArchive, PharCompression, extract_phar_entry, parse_phar};
use php_toolchain::required_corpus;

const HELLO_PHAR_ENTRIES: usize = 2;
const EDGE_CASES_PHAR_ENTRIES: usize = 3;
const BZIP2_PHAR_ENTRIES: usize = 3;

const EDGE_CASES_MEMBER_LEN: usize = 20_760;

fn phar_bz2_src(rel: &str) -> Vec<u8> {
    required_corpus(&format!("phar-bz2/src/{rel}"))
}

#[test]
fn parses_real_hello_phar_lists_entries() {
    let bytes: Vec<u8> = required_corpus("phar/hello.phar");
    let archive: PharArchive = parse_phar(&bytes).expect("parse hello.phar");
    assert_eq!(
        archive.entries.len(),
        HELLO_PHAR_ENTRIES,
        "hello.phar bundles index.php and helper.php, so the entry count is pinned rather than \
         bounded below; a reader that stops after one member must fail here, got {:?}",
        archive.entries.keys().collect::<Vec<&String>>()
    );
    let names: Vec<&str> = archive.entries.keys().map(String::as_str).collect();
    assert!(names.iter().any(|n: &&str| n.ends_with("index.php")));
    assert!(names.iter().any(|n: &&str| n.ends_with("helper.php")));
}

#[test]
fn extracts_real_hello_phar_entries_to_bytes() {
    let bytes: Vec<u8> = required_corpus("phar/hello.phar");
    let archive: PharArchive = parse_phar(&bytes).expect("parse hello.phar");
    let key: &str = archive
        .entries
        .keys()
        .find(|k: &&String| k.ends_with("index.php"))
        .map(String::as_str)
        .expect("index.php entry");
    let extracted: Vec<u8> = extract_phar_entry(&archive, &bytes, key).expect("extract");
    assert!(!extracted.is_empty(), "index.php payload empty");
    let text: String = String::from_utf8_lossy(&extracted).into_owned();
    assert!(
        text.contains("phar hello world"),
        "expected literal payload, got: {text}"
    );
}

#[test]
fn parses_real_edge_cases_phar_lists_entries() {
    let bytes: Vec<u8> = required_corpus("phar/edge_cases.phar");
    let archive: PharArchive = parse_phar(&bytes).expect("parse edge_cases.phar");
    assert_eq!(
        archive.entries.len(),
        EDGE_CASES_PHAR_ENTRIES,
        "edge_cases.phar bundles three files and the count is pinned rather than bounded below, so \
         a member that stops being listed fails here, got {:?}",
        archive.entries.keys().collect::<Vec<&String>>()
    );
    let names: Vec<&str> = archive.entries.keys().map(String::as_str).collect();
    for expected in ["edge_cases.php", "hello.php", "pre80_edge_cases.php"] {
        assert!(
            names.iter().any(|n: &&str| n.ends_with(expected)),
            "edge_cases.phar must list {expected}, got {names:?}"
        );
    }
}

fn extract_member(archive: &PharArchive, bytes: &[u8], suffix: &str) -> Vec<u8> {
    let key: &str = archive
        .entries
        .keys()
        .find(|k: &&String| k.ends_with(suffix))
        .map(String::as_str)
        .unwrap_or_else(|| panic!("member {suffix} not in archive"));
    extract_phar_entry(archive, bytes, key).expect("extract member")
}

#[test]
fn extracts_real_edge_cases_phar_members_byte_identical_to_their_committed_sources() {
    let bytes: Vec<u8> = required_corpus("phar/edge_cases.phar");
    let archive: PharArchive = parse_phar(&bytes).expect("parse edge_cases.phar");
    let mut graded: usize = 0;
    for (suffix, source_rel) in [
        ("hello.php", "baseline/hello.php"),
        ("pre80_edge_cases.php", "megafile/pre80_edge_cases.php"),
    ] {
        let extracted: Vec<u8> = extract_member(&archive, &bytes, suffix);
        let source: Vec<u8> = required_corpus(source_rel);
        assert_eq!(
            extracted, source,
            "the {suffix} member must decompress byte-identical to corpus/php/{source_rel}; a \
             preamble substring would still match after a truncated extraction"
        );
        graded += 1;
    }
    assert_eq!(
        graded, 2,
        "both members with a committed source must be compared against it"
    );
}

#[test]
fn the_edge_cases_phar_member_with_no_committed_source_is_graded_by_size_and_shape() {
    let bytes: Vec<u8> = required_corpus("phar/edge_cases.phar");
    let archive: PharArchive = parse_phar(&bytes).expect("parse edge_cases.phar");
    let extracted: Vec<u8> = extract_member(&archive, &bytes, "edge_cases.php");
    let committed: Vec<u8> = required_corpus("megafile/edge_cases.php");
    assert_ne!(
        extracted,
        committed,
        "the edge_cases.php member of this phar is {EDGE_CASES_MEMBER_LEN} bytes while \
         corpus/php/megafile/edge_cases.php is {} bytes, so the archive was built from a revision \
         that is no longer committed. If they now match, rebuild this case as a byte-identical \
         comparison, which is the stronger grade.",
        committed.len()
    );
    assert_eq!(
        extracted.len(),
        EDGE_CASES_MEMBER_LEN,
        "with no committed source to compare against, the extracted length is pinned so a \
         truncated or over-read extraction cannot pass on a substring match alone"
    );
    let text: String = String::from_utf8_lossy(&extracted).into_owned();
    for marker in [
        "declare(strict_types=1)",
        "namespace App\\EdgeCases",
        "readonly class",
    ] {
        assert!(
            text.contains(marker),
            "the extracted php 8 member must carry `{marker}`"
        );
    }
    assert!(
        text.trim_end().ends_with('}') || text.trim_end().ends_with(';'),
        "the extracted member must end on a complete statement, which a truncated read would not; \
         it ends with {:?}",
        text.chars().rev().take(20).collect::<String>()
    );
}

#[test]
fn real_bzip2_phar_members_are_flagged_bzip2() {
    let bytes: Vec<u8> = required_corpus("phar/bzip2.phar");
    let archive: PharArchive = parse_phar(&bytes).expect("parse bzip2.phar");
    assert_eq!(
        archive.entries.len(),
        BZIP2_PHAR_ENTRIES,
        "bzip2.phar bundles three members and the count is pinned, got {:?}",
        archive.entries.keys().collect::<Vec<&String>>()
    );
    for (name, entry) in &archive.entries {
        assert_eq!(
            entry.compression,
            PharCompression::Bzip2,
            "member {name} should be bzip2-compressed, got {:?}",
            entry.compression
        );
        assert!(
            entry.stored_size != entry.uncompressed_size || entry.uncompressed_size == 0,
            "member {name} compressed size {} equals uncompressed {}",
            entry.stored_size,
            entry.uncompressed_size
        );
    }
}

#[test]
fn real_bzip2_phar_members_decompress_byte_identical_to_source() {
    let bytes: Vec<u8> = required_corpus("phar/bzip2.phar");
    let archive: PharArchive = parse_phar(&bytes).expect("parse bzip2.phar");

    let expectations: [(&str, &str); BZIP2_PHAR_ENTRIES] = [
        ("index.php", "index.php"),
        ("lib/greeter.php", "lib/greeter.php"),
        ("lib/math.php", "lib/math.php"),
    ];
    let mut graded: usize = 0;
    for (member_suffix, source_rel) in expectations {
        let source: Vec<u8> = phar_bz2_src(source_rel);
        let key: &str = archive
            .entries
            .keys()
            .find(|k: &&String| k.ends_with(member_suffix))
            .map(String::as_str)
            .unwrap_or_else(|| panic!("member {member_suffix} not in archive"));
        let extracted: Vec<u8> =
            extract_phar_entry(&archive, &bytes, key).expect("extract bzip2 member");
        assert_eq!(
            extracted, source,
            "bzip2 member {member_suffix} did not round-trip byte-identical to {source_rel}"
        );
        graded += 1;
    }
    assert_eq!(
        graded, BZIP2_PHAR_ENTRIES,
        "every member of the archive must be compared against its source, not just the ones a run \
         happened to reach"
    );
}
