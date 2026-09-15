#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::{ExtractionResult, extract_to};
use sha2::{Digest as _, Sha256};

const FIXTURE: &[u8] = include_bytes!("fixtures/stuffit/stuffit45-method13.sit");
const MANIFEST: &str = include_str!("fixtures/stuffit/MANIFEST.tsv");

#[test]
fn stuffit45_method13_forks_match_the_unar_manifest() {
    assert_eq!(FIXTURE.len(), 2_804);
    assert_eq!(
        format!("{:x}", Sha256::digest(FIXTURE)),
        "a0ef9c2f0a1f34be4cfd60da3b54af7fa16357544c009eb8241554670ec74755"
    );
    assert_eq!(detect_container(FIXTURE), Some(ContainerKind::StuffIt));

    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("binfmt-stuffit-method13")
            .expect("create scratch directory");
    let result: ExtractionResult = extract_to(ContainerKind::StuffIt, FIXTURE, scratch.path())
        .expect("extract StuffIt 4.5 fixture");
    let rows: Vec<&str> = MANIFEST.lines().skip(1).collect();
    assert_eq!(rows.len(), 9);
    assert_eq!(result.entries.len(), rows.len());
    assert!(result.integrity_violations.is_empty());

    let mut expected_paths: BTreeSet<&str> = BTreeSet::new();
    for row in rows {
        let fields: Vec<&str> = row.split('\t').collect();
        assert_eq!(fields.len(), 7, "manifest row: {row}");
        let path: &str = fields[0];
        let logical_size: usize = fields[3].parse().expect("manifest logical size");
        let expected_hash: &str = fields[5];
        assert!(
            expected_paths.insert(path),
            "duplicate manifest path {path}"
        );
        let recovered: Vec<u8> = std::fs::read(scratch.path().join(path))
            .unwrap_or_else(|error: std::io::Error| panic!("read {path}: {error}"));
        assert_eq!(recovered.len(), logical_size, "size for {path}");
        assert_eq!(
            format!("{:x}", Sha256::digest(&recovered)),
            expected_hash,
            "hash for {path}"
        );
        let extracted: &disrobe_binfmt::ExtractedEntry = result
            .entries
            .iter()
            .find(|entry: &&disrobe_binfmt::ExtractedEntry| entry.name == path)
            .expect("manifest member in extraction result");
        assert_eq!(extracted.is_executable.to_string(), fields[6]);
    }

    let actual_paths: BTreeSet<&str> = result
        .entries
        .iter()
        .map(|entry: &disrobe_binfmt::ExtractedEntry| entry.name.as_str())
        .collect();
    assert_eq!(actual_paths, expected_paths);
}

#[test]
fn method13_integrity_failure_refuses_the_named_fork_and_keeps_siblings() {
    let mut corrupted: Vec<u8> = FIXTURE.to_vec();
    corrupted[22 + 112 + 17] ^= 0x40;
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("binfmt-stuffit-rollback")
            .expect("create rollback directory");
    let result: ExtractionResult = extract_to(ContainerKind::StuffIt, &corrupted, scratch.path())
        .expect("retain recoverable StuffIt forks");
    assert_eq!(result.entries.len(), 8);
    assert_eq!(result.integrity_violations.len(), 1);
    assert_eq!(
        result.integrity_violations[0],
        "stuffit-decode `Test Image.rsrc`: DR-BINFMT-0063: stuffit archive parse failed: stuffit: method 13 stream is incomplete: invalid Huffman code lengths"
    );
    assert!(
        result
            .entries
            .iter()
            .all(|entry: &disrobe_binfmt::ExtractedEntry| entry.name != "Test Image.rsrc")
    );
    assert!(scratch.path().join("Test Text").is_file());
    assert!(scratch.path().join("testfile.txt.rsrc").is_file());
}
