//! Detect-only coverage for the Zend Guard protector against synthetic envelopes.
//!
//! These envelopes carry the real `@Zend;` era marker bytes but opaque filler in
//! place of the Zend Optimizer/Guard loader's encrypted opcode stream. There is no
//! real Zend Guard sample and no source recovery here; the verdict is detect-only
//! plus a structural payload boundary, never plaintext.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    clippy::needless_pass_by_value
)]

use disrobe_pass_php::zend_guard_protector::{self, ZendGuardEra};
use disrobe_pass_php::{ProtectorDetection, ProtectorFamily};

#[test]
fn detects_zend3_marker_layout() {
    let mut blob: Vec<u8> = b"<?php @Zend;\n3".to_vec();
    blob.extend_from_slice(b"0150\nopaque-encrypted-opcode-stream");
    let (era, _idx, _len): (ZendGuardEra, usize, usize) =
        zend_guard_protector::detect(&blob).expect("era");
    assert_eq!(era, ZendGuardEra::Zend3);
}

#[test]
fn analyze_is_honest_detect_only() {
    let mut blob: Vec<u8> = b"<?php @Zend;\n4".to_vec();
    blob.extend_from_slice(b"0030EncryptedZendOpcodeStreamBehindZendOptimizerLoader");
    let detection: ProtectorDetection = zend_guard_protector::analyze(&blob).expect("analyze");
    assert_eq!(detection.family, ProtectorFamily::ZendGuard);
    assert_eq!(detection.version_label, "zend-4");
    assert!(detection.payload_offset.is_some());
    assert!(
        detection.wall_reason.contains("Zend Optimizer"),
        "wall cites Zend Optimizer/Guard Loader: {}",
        detection.wall_reason
    );
}

#[test]
fn loader_banner_only_is_low_confidence() {
    let blob: &[u8] = b"<?php /* needs Zend Guard Loader */";
    let detection: ProtectorDetection = zend_guard_protector::analyze(blob).expect("analyze");
    assert!(!detection.confident);
}

#[test]
fn clean_php_is_not_misdetected() {
    assert!(zend_guard_protector::analyze(b"<?php echo 'clean';").is_err());
}
