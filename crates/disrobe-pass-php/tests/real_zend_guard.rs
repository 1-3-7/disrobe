#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    clippy::needless_pass_by_value
)]

use std::fs;
use std::path::PathBuf;

use disrobe_pass_php::zend_guard_protector::{self, FLAG_XOR_STREAM, ZendGuardEra};
use disrobe_pass_php::{ProtectorFamily, ProtectorPeelResult};

fn pre80_megafile_path() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("php");
    p.push("megafile");
    p.push("pre80_edge_cases.php");
    p
}

#[test]
fn real_pre80_megafile_roundtrip_zend3_xor() {
    let plaintext: Vec<u8> = fs::read(pre80_megafile_path()).expect("read megafile");
    let blob: Vec<u8> = zend_guard_protector::build_test_blob(
        ZendGuardEra::Zend3,
        &plaintext,
        FLAG_XOR_STREAM,
        0xFEED_BACE,
    );
    let frame: zend_guard_protector::ZendGuardFrame =
        zend_guard_protector::parse_frame(&blob).expect("parse");
    assert_eq!(frame.era, ZendGuardEra::Zend3);
    let recovered: Vec<u8> = zend_guard_protector::decode_frame(&frame).expect("decode");
    assert_eq!(recovered, plaintext);
}

#[test]
fn real_pre80_megafile_peel_emits_strings_and_summary() {
    let plaintext: Vec<u8> = fs::read(pre80_megafile_path()).expect("read megafile");
    let blob: Vec<u8> = zend_guard_protector::build_test_blob(
        ZendGuardEra::Zend4,
        &plaintext,
        FLAG_XOR_STREAM,
        0x1234_5678,
    );
    let result: ProtectorPeelResult = zend_guard_protector::peel(&blob).expect("peel");
    assert_eq!(result.family, ProtectorFamily::ZendGuard);
    assert!(result.version_label.starts_with("zend-4"));
    assert!(!result.recovered_strings.is_empty());
    let joined: String = result.recovered_strings.join("\n");
    assert!(joined.contains("class") || joined.contains("function") || joined.contains("PHP"));
}
