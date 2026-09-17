#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::fs;
use std::path::{Path, PathBuf};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_pyarmor::{
    Detection, DetectionConfidence, ModeOverride, ProtectionKind, PyarmorVersion, TargetPyVersion,
    UnpackOptions, UnpackOutput, detect_from_wrapper, unpack_wrapper_text_with_options,
};

fn make_scratch_dir(name: &str) -> ScratchDir {
    ScratchDir::create(&format!("pyarmor-{name}")).expect("scratch dir")
}

fn escape_bytes(payload: &[u8]) -> String {
    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
    let mut escaped: String = String::with_capacity(payload.len() * 4);
    for byte in payload.iter().copied() {
        escaped.push('\\');
        escaped.push('x');
        escaped.push(char::from(HEX_LOWER[usize::from(byte >> 4)]));
        escaped.push(char::from(HEX_LOWER[usize::from(byte & 0x0f)]));
    }
    escaped
}

#[test]
fn legacy_v3_v4_v5_detection_round_trip() {
    let cases: [(u8, PyarmorVersion); 3] = [
        (0x01u8, PyarmorVersion::V3),
        (0x02u8, PyarmorVersion::V4),
        (0x05u8, PyarmorVersion::V5),
    ];
    for &(mode_byte, expected) in &cases {
        let mut payload: Vec<u8> = vec![0u8; 64];
        payload[0] = mode_byte;
        let text: String = format!(
            "from pytransform import __pyarmor__\n__pyarmor__(__name__, __file__, b'{}')\n",
            escape_bytes(&payload)
        );
        let (det, _): (Detection, Vec<u8>) =
            detect_from_wrapper(&text).expect("legacy wrapper detects");
        assert_eq!(det.version, expected);
        assert_eq!(det.confidence, DetectionConfidence::Low);
        assert!(!det.diagnostics.is_empty());
    }
}

#[test]
fn legacy_unpack_returns_detection_only_output_not_error() {
    let mut payload: Vec<u8> = vec![0u8; 64];
    payload[0] = 0x05u8;
    let escaped: String = escape_bytes(&payload);
    let text: String = format!(
        "from pytransform import __pyarmor__\n__pyarmor__(__name__, __file__, b'{escaped}')\n"
    );

    let scratch: ScratchDir = make_scratch_dir("legacy-detect-only");
    let tmp: &Path = scratch.path();
    let wrapper: PathBuf = tmp.join("hello.py");
    fs::write(&wrapper, &text).expect("write wrapper");

    let result: UnpackOutput =
        unpack_wrapper_text_with_options(&text, &wrapper, &UnpackOptions::default())
            .expect("legacy detection-only succeeds (does not error)");
    assert_eq!(result.detection.version, PyarmorVersion::V5);
    assert!(result.pyc.is_none());
    assert!(result.fallback_reason.is_some());
}

#[test]
fn legacy_unpack_with_strict_returns_error() {
    let mut payload: Vec<u8> = vec![0u8; 64];
    payload[0] = 0x05u8;
    let text: String = format!(
        "from pytransform import __pyarmor__\n__pyarmor__(__name__, __file__, b'{}')\n",
        escape_bytes(&payload)
    );
    let scratch: ScratchDir = make_scratch_dir("legacy-strict");
    let tmp: &Path = scratch.path();
    let wrapper: PathBuf = tmp.join("hello.py");
    fs::write(&wrapper, &text).expect("write wrapper");

    let options: UnpackOptions = UnpackOptions {
        strict: true,
        ..UnpackOptions::default()
    };
    let err: Result<UnpackOutput, _> = unpack_wrapper_text_with_options(&text, &wrapper, &options);
    assert!(
        err.is_err(),
        "strict mode must fail-fast on legacy detect-only"
    );
}

#[test]
fn mode_override_parses_all_three() {
    assert_eq!(ModeOverride::parse("auto"), Some(ModeOverride::Auto));
    assert_eq!(
        ModeOverride::parse("STANDARD"),
        Some(ModeOverride::Standard)
    );
    assert_eq!(ModeOverride::parse("super"), Some(ModeOverride::Super));
    assert_eq!(ModeOverride::parse("not-a-mode"), None);
}

#[test]
fn target_pyver_parses_and_maps_to_magic() {
    let v: TargetPyVersion = TargetPyVersion::parse("3.11").expect("parses");
    assert_eq!(v.major, 3);
    assert_eq!(v.minor, 11);
    assert_eq!(v.pyc_magic_u16(), Some(3495));
    let v2: TargetPyVersion = TargetPyVersion::parse("3.14").expect("parses");
    assert_eq!(v2.pyc_magic_u16(), Some(3627));
    assert!(TargetPyVersion::parse("abc").is_none());
    assert!(TargetPyVersion::parse("3").is_none());
    assert!(TargetPyVersion::parse("3.11.0").is_none());
}

#[test]
fn target_pyver_unknown_minor_returns_none_for_magic() {
    let v: TargetPyVersion = TargetPyVersion {
        major: 3,
        minor: 99,
    };
    assert!(v.pyc_magic_u16().is_none());
}

#[test]
fn unpack_options_extended_fields_default_to_false_auto_none() {
    let opts: UnpackOptions = UnpackOptions::default();
    assert!(!opts.allow_bcc);
    assert!(!opts.all_emits);
    assert!(!opts.strict);
    assert!(!opts.no_cextract);
    assert!(!opts.cextract_only);
    assert!(opts.target_pyver.is_none());
    assert!(opts.descriptor_cache_dir.is_none());
    assert_eq!(opts.mode_override, ModeOverride::Auto);
}

#[test]
fn legacy_v3_v4_v5_protection_default_is_standard_unless_super_invocation() {
    let mut payload: Vec<u8> = vec![0u8; 64];
    payload[0] = 0x01u8;
    let text: String = format!(
        "from pytransform import __pyarmor__\n__pyarmor__(__name__, __file__, b'{}')\n",
        escape_bytes(&payload)
    );
    let (det, _): (Detection, Vec<u8>) = detect_from_wrapper(&text).expect("detects");
    assert_eq!(det.protection, ProtectionKind::Standard);
}
