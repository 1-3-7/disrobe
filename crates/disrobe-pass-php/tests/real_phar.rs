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

use disrobe_pass_php::{PharArchive, extract_phar_entry, parse_phar};

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
