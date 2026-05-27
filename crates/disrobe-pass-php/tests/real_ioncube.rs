#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    clippy::needless_pass_by_value
)]

use std::fs;
use std::path::PathBuf;

use disrobe_pass_php::ioncube_protector::{self, IonCubeEra};
use disrobe_pass_php::{ProtectorFamily, ProtectorPeelResult};

fn corpus_megafile_path() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("php");
    p.push("megafile");
    p.push("edge_cases.php");
    p
}

#[test]
fn real_megafile_roundtrip_v6_recovers_plaintext() {
    let plaintext_path: PathBuf = corpus_megafile_path();
    assert!(
        plaintext_path.exists(),
        "corpus megafile missing: {}",
        plaintext_path.display()
    );
    let plaintext: Vec<u8> = fs::read(&plaintext_path).expect("read megafile");

    let blob: Vec<u8> = ioncube_protector::build_test_blob(IonCubeEra::V6, &plaintext);

    let result: ProtectorPeelResult = ioncube_protector::peel(&blob).expect("peel must recover");
    assert_eq!(result.family, ProtectorFamily::IonCube);
    assert_eq!(result.version_label, "v6");

    let recovered: String = result.recovered_php.expect("php source recovered");
    assert_eq!(recovered.as_bytes(), plaintext.as_slice());
}

#[test]
fn real_megafile_roundtrip_v9_recovers_plaintext() {
    let plaintext: Vec<u8> = fs::read(corpus_megafile_path()).expect("read megafile");
    let blob: Vec<u8> = ioncube_protector::build_test_blob(IonCubeEra::V9, &plaintext);
    let result: ProtectorPeelResult = ioncube_protector::peel(&blob).expect("peel");
    assert_eq!(result.version_label, "v9");
    let recovered: String = result.recovered_php.expect("recovered");
    assert!(recovered.contains("namespace App\\EdgeCases"));
    assert!(recovered.contains("enum Status"));
}

#[test]
fn real_megafile_extracts_identifiers_and_constants() {
    let plaintext: Vec<u8> = fs::read(corpus_megafile_path()).expect("read megafile");
    let blob: Vec<u8> = ioncube_protector::build_test_blob(IonCubeEra::V10, &plaintext);
    let result: ProtectorPeelResult = ioncube_protector::peel(&blob).expect("peel");
    let recovered: String = result.recovered_php.expect("recovered");
    assert!(recovered.contains("APP_VERSION"));
    assert!(recovered.contains("Iterator"));
    assert!(recovered.contains("declare(strict_types=1)"));
}

#[test]
fn detects_layered_peel_count() {
    let plaintext: &[u8] = b"<?php echo 'small'; ?>";
    let blob: Vec<u8> = ioncube_protector::build_test_blob(IonCubeEra::V4Legacy, plaintext);
    let result: ProtectorPeelResult = ioncube_protector::peel(&blob).expect("peel");
    assert_eq!(result.version_label, "v4-legacy");
    assert!(result.layers_peeled >= 2);
}
