#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::missing_const_for_fn
)]

use std::path::PathBuf;

use disrobe_pass_php::{PharArchive, extract_phar_entry, parse_phar};

fn corpus_root() -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .expect("crates parent")
        .parent()
        .expect("workspace root")
        .join("corpus")
        .join("php")
}

fn read_fixture(rel: &str) -> Vec<u8> {
    let path: PathBuf = corpus_root().join(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", path.display()))
}

#[test]
fn parses_real_hello_phar_lists_entries() {
    let bytes: Vec<u8> = read_fixture("phar/hello.phar");
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
    let bytes: Vec<u8> = read_fixture("phar/hello.phar");
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
    let bytes: Vec<u8> = read_fixture("phar/edge_cases.phar");
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
    let bytes: Vec<u8> = read_fixture("phar/edge_cases.phar");
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
