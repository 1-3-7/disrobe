#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    clippy::needless_pass_by_value
)]

use std::fs;
use std::path::PathBuf;

use disrobe_pass_php::sourceguardian_protector::{self, SourceGuardianEra};
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
fn real_megafile_roundtrip_legacy_recovers_plaintext() {
    let plaintext: Vec<u8> = fs::read(corpus_megafile_path()).expect("read megafile");
    let blob: Vec<u8> =
        sourceguardian_protector::build_test_blob(SourceGuardianEra::Legacy, &plaintext);
    let result: ProtectorPeelResult = sourceguardian_protector::peel(&blob).expect("peel");
    assert_eq!(result.family, ProtectorFamily::SourceGuardian);
    assert_eq!(result.version_label, "sg-legacy");
    let recovered: String = result.recovered_php.expect("recovered");
    assert_eq!(recovered.as_bytes(), plaintext.as_slice());
}

#[test]
fn real_megafile_roundtrip_modern_recovers_plaintext() {
    let plaintext: Vec<u8> = fs::read(corpus_megafile_path()).expect("read megafile");
    let blob: Vec<u8> =
        sourceguardian_protector::build_test_blob(SourceGuardianEra::Modern, &plaintext);
    let result: ProtectorPeelResult = sourceguardian_protector::peel(&blob).expect("peel");
    assert_eq!(result.version_label, "sg-modern");
    let recovered: String = result.recovered_php.expect("recovered");
    assert!(recovered.contains("declare(strict_types=1)"));
    assert!(recovered.contains("enum Priority"));
}

#[test]
fn real_megafile_layers_peeled_is_three() {
    let plaintext: Vec<u8> = fs::read(corpus_megafile_path()).expect("read megafile");
    let blob: Vec<u8> =
        sourceguardian_protector::build_test_blob(SourceGuardianEra::Legacy, &plaintext);
    let result: ProtectorPeelResult = sourceguardian_protector::peel(&blob).expect("peel");
    assert_eq!(result.layers_peeled, 3);
}
