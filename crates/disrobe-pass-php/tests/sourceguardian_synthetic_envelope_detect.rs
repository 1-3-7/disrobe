#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    clippy::needless_pass_by_value
)]

use disrobe_pass_php::sourceguardian_protector::{self, SourceGuardianEra};
use disrobe_pass_php::{ProtectorDetection, ProtectorFamily};

#[test]
fn detects_legacy_sgv_banner_layout() {
    let mut blob: Vec<u8> = b"<?php //SGV2\n".to_vec();
    blob.extend_from_slice(b"opaque encrypted opcode payload");
    let (era, _off): (SourceGuardianEra, usize) =
        sourceguardian_protector::detect(&blob).expect("era");
    assert_eq!(era, SourceGuardianEra::Legacy);
}

#[test]
fn analyze_modern_is_honest_detect_only() {
    let mut blob: Vec<u8> = b"<?php @SourceGuardian;\n".to_vec();
    blob.extend_from_slice(b"ixedLoaderEncryptedZendOpcodeStreamNotRecoverableFromEnvelope");
    let detection: ProtectorDetection = sourceguardian_protector::analyze(&blob).expect("analyze");
    assert_eq!(detection.family, ProtectorFamily::SourceGuardian);
    assert_eq!(detection.version_label, "sg-modern");
    assert!(detection.payload_offset.is_some());
    assert!(
        detection.wall_reason.contains("ixed"),
        "wall cites the ixed native loader: {}",
        detection.wall_reason
    );
}

#[test]
fn sg_load_call_is_detected() {
    let blob: &[u8] = b"<?php sg_load('0123456789abcdef');";
    let detection: ProtectorDetection = sourceguardian_protector::analyze(blob).expect("analyze");
    assert_eq!(detection.family, ProtectorFamily::SourceGuardian);
}

#[test]
fn clean_php_is_not_misdetected() {
    assert!(sourceguardian_protector::analyze(b"<?php echo 'clean';").is_err());
}
