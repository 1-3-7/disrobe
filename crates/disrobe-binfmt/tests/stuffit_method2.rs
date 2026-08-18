#![allow(clippy::expect_used)]

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::{ExtractionResult, extract_to};
use sha2::{Digest as _, Sha256};

const FIXTURE: &[u8] = include_bytes!("fixtures/stuffit/stuffit-method2.sit");
const EXPECTED: &[u8] = include_bytes!("fixtures/stuffit/stuffit-method2-input.txt");
const MANIFEST: &str = include_str!("fixtures/stuffit/MANIFEST_METHOD2.tsv");

#[test]
fn stuffit_method2_matches_the_unar_reference() {
    assert_eq!(FIXTURE.len(), 757);
    assert_eq!(
        format!("{:x}", Sha256::digest(FIXTURE)),
        "e7ebc350a2c7741cd0df19f4c0d5ad0759d81e909847af5548e3a4b03e218f50"
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(EXPECTED)),
        "0da63e2bd4778b7180e2bed8b80c300ebea7d044c248e1025bd6b369acbf18a2"
    );
    assert_eq!(detect_container(FIXTURE), Some(ContainerKind::StuffIt));
    let fields: Vec<&str> = MANIFEST
        .lines()
        .nth(1)
        .expect("method 2 manifest row")
        .split('\t')
        .collect();
    assert_eq!(fields.len(), 7);
    assert_eq!(fields[0], "method2_input.txt");
    assert_eq!(fields[2], "2");
    assert_eq!(fields[3], "1184");
    assert_eq!(fields[4], "34318");
    assert_eq!(
        fields[5],
        "0da63e2bd4778b7180e2bed8b80c300ebea7d044c248e1025bd6b369acbf18a2"
    );

    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("binfmt-stuffit-method2")
            .expect("create method 2 scratch directory");
    let result: ExtractionResult = extract_to(ContainerKind::StuffIt, FIXTURE, scratch.path())
        .expect("extract StuffIt method 2 fixture");
    assert!(result.integrity_violations.is_empty());
    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.entries[0].name, "method2_input.txt");
    assert!(!result.entries[0].is_executable);
    assert_eq!(
        std::fs::read(scratch.path().join("method2_input.txt"))
            .expect("read recovered method 2 data fork"),
        EXPECTED
    );
}
