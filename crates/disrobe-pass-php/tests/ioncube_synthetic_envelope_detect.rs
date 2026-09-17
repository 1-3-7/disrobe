#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    clippy::needless_pass_by_value
)]

use disrobe_pass_php::ioncube_protector::{self, IonCubeEra};
use disrobe_pass_php::{ProtectorDetection, ProtectorFamily, build_ioncube_container};

const HELLO_DZOA: &[u8] = include_bytes!("fixtures/protector_oparray/hello.dzoa");

fn ioncube_v6_envelope() -> Vec<u8> {
    let mut blob: Vec<u8> = b"<?php //0046\n".to_vec();
    blob.extend_from_slice(b"@dlx_loader_check();\n");
    blob.extend_from_slice(
        b"HR+cP9fencryptedZendOpcodeArrayBytesBehindNativeLoader0123456789ABCDEF",
    );
    blob
}

#[test]
fn detects_v6_era_from_real_marker_layout() {
    let blob: Vec<u8> = ioncube_v6_envelope();
    let (era, off): (IonCubeEra, usize) = ioncube_protector::detect(&blob).expect("era marker");
    assert_eq!(era, IonCubeEra::V6);
    assert_eq!(off, 6);
}

#[test]
fn analyze_is_honest_detect_only_recovers_no_php_source() {
    let blob: Vec<u8> = ioncube_v6_envelope();
    let detection: ProtectorDetection = ioncube_protector::analyze(&blob).expect("analyze");
    assert_eq!(detection.family, ProtectorFamily::IonCube);
    assert_eq!(detection.version_label, "v6");
    assert!(detection.confident);
    assert!(
        detection.payload_offset.is_some(),
        "structural payload boundary located"
    );
    assert!(
        detection.payload_len > 0,
        "ciphertext payload length reported"
    );
    assert!(
        detection.wall_reason.contains("native loader"),
        "honest wall reason documented: {}",
        detection.wall_reason
    );
}

#[test]
fn all_era_markers_are_recognized() {
    for (marker, want) in [
        (&b"<?php //00400\n"[..], "v4-legacy"),
        (&b"<?php //0046\n"[..], "v6"),
        (&b"<?php //004F\n"[..], "v9"),
        (&b"<?php //0080\n"[..], "v10"),
    ] {
        let mut blob: Vec<u8> = marker.to_vec();
        blob.extend_from_slice(b"opaque-encrypted-opcode-bytes");
        let detection: ProtectorDetection = ioncube_protector::analyze(&blob).expect("analyze era");
        assert_eq!(detection.version_label, want, "marker {marker:?}");
    }
}

#[test]
fn clean_php_is_not_misdetected_as_ioncube() {
    let clean: &[u8] = b"<?php declare(strict_types=1); echo 'hello';";
    assert!(
        ioncube_protector::analyze(clean).is_err(),
        "clean PHP must not be flagged as ionCube"
    );
}

#[test]
fn analyze_reverses_container_and_lifts_static_opcode_stream() {
    let envelope: Vec<u8> =
        build_ioncube_container(b"<?php //004F", 9, 0, HELLO_DZOA, false).expect("build");
    let detection: ProtectorDetection = ioncube_protector::analyze(&envelope).expect("analyze");
    assert_eq!(detection.family, ProtectorFamily::IonCube);
    assert!(detection.container_parsed, "container framing was parsed");
    assert!(
        detection
            .static_layers_stripped
            .iter()
            .any(|l: &String| l == "base64"),
        "base64 transport stripped: {:?}",
        detection.static_layers_stripped
    );
    assert!(detection.source_reconstructed, "opcode stream lifted");
    let src: &str = detection
        .recovered_source
        .as_deref()
        .expect("recovered source");
    assert!(
        src.contains("echo 'hello from ioncube container';"),
        "recovered: {src}"
    );
}

#[test]
fn analyze_walls_when_opcode_body_not_statically_present() {
    let blob: Vec<u8> = ioncube_v6_envelope();
    let detection: ProtectorDetection = ioncube_protector::analyze(&blob).expect("analyze");
    assert!(
        !detection.source_reconstructed,
        "an opaque non-container body must not fabricate source"
    );
    assert!(detection.recovered_source.is_none());
    assert!(detection.wall_reason.contains("native loader"));
}
