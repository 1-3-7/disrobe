#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::missing_const_for_fn
)]

mod common;

use disrobe_pass_php::{PharArchive, PharCompression, extract_phar_entry, parse_phar};
use std::path::PathBuf;

fn phar_bz2_src(rel: &str) -> Option<Vec<u8>> {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut root: PathBuf = manifest;
    root.pop();
    root.pop();
    root.push("corpus");
    root.push("php");
    root.push("phar-bz2");
    root.push("src");
    root.push(rel);
    std::fs::read(root).ok()
}

#[test]
fn parses_real_hello_phar_lists_entries() {
    let Some(bytes): Option<Vec<u8>> = common::load_php_fixture("phar/hello.phar") else {
        eprintln!("skip: phar/hello.phar fixture absent");
        return;
    };
    let archive: PharArchive = parse_phar(&bytes).expect("parse hello.phar");
    assert!(
        archive.entries.len() >= 2,
        "expected hello.phar to contain index.php + helper.php, got {} entries",
        archive.entries.len()
    );
    let names: Vec<&str> = archive.entries.keys().map(String::as_str).collect();
    assert!(names.iter().any(|n: &&str| n.ends_with("index.php")));
    assert!(names.iter().any(|n: &&str| n.ends_with("helper.php")));
}

#[test]
fn extracts_real_hello_phar_entries_to_bytes() {
    let Some(bytes): Option<Vec<u8>> = common::load_php_fixture("phar/hello.phar") else {
        eprintln!("skip: phar/hello.phar fixture absent");
        return;
    };
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
    let Some(bytes): Option<Vec<u8>> = common::load_php_fixture("phar/edge_cases.phar") else {
        eprintln!("skip: phar/edge_cases.phar fixture absent");
        return;
    };
    let archive: PharArchive = parse_phar(&bytes).expect("parse edge_cases.phar");
    assert!(
        archive.entries.len() >= 2,
        "expected edge_cases.phar to bundle 2 files, got {}",
        archive.entries.len()
    );
    let names: Vec<&str> = archive.entries.keys().map(String::as_str).collect();
    assert!(names.iter().any(|n: &&str| n.ends_with("edge_cases.php")));
    assert!(names.iter().any(|n: &&str| n.ends_with("hello.php")));
}

#[test]
fn extracts_real_edge_cases_phar_payload_matches_source() {
    let Some(bytes): Option<Vec<u8>> = common::load_php_fixture("phar/edge_cases.phar") else {
        eprintln!("skip: phar/edge_cases.phar fixture absent");
        return;
    };
    let archive: PharArchive = parse_phar(&bytes).expect("parse edge_cases.phar");
    let key: &str = archive
        .entries
        .keys()
        .find(|k: &&String| k.ends_with("edge_cases.php"))
        .map(String::as_str)
        .expect("edge_cases.php entry");
    let extracted: Vec<u8> = extract_phar_entry(&archive, &bytes, key).expect("extract");
    assert!(!extracted.is_empty());
    let text: String = String::from_utf8_lossy(&extracted).into_owned();
    assert!(
        text.contains("declare(strict_types=1)") || text.contains("namespace App\\EdgeCases"),
        "expected PHP 8 megafile preamble"
    );
}

#[test]
fn real_bzip2_phar_members_are_flagged_bzip2() {
    let Some(bytes): Option<Vec<u8>> = common::load_php_fixture("phar/bzip2.phar") else {
        eprintln!("skip: phar/bzip2.phar fixture absent");
        return;
    };
    let archive: PharArchive = parse_phar(&bytes).expect("parse bzip2.phar");
    assert!(
        archive.entries.len() >= 3,
        "expected 3 members, got {}",
        archive.entries.len()
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
    let Some(bytes): Option<Vec<u8>> = common::load_php_fixture("phar/bzip2.phar") else {
        eprintln!("skip: phar/bzip2.phar fixture absent");
        return;
    };
    let archive: PharArchive = parse_phar(&bytes).expect("parse bzip2.phar");

    let expectations: [(&str, &str); 3] = [
        ("index.php", "index.php"),
        ("lib/greeter.php", "lib/greeter.php"),
        ("lib/math.php", "lib/math.php"),
    ];
    for (member_suffix, source_rel) in expectations {
        let Some(source): Option<Vec<u8>> = phar_bz2_src(source_rel) else {
            eprintln!("skip: phar-bz2 source {source_rel} absent");
            return;
        };
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
    }
}
