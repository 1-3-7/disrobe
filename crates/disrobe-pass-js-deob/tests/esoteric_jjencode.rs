#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{
    EsotericFamily, JjEncodeDecode, JjEncodeDetection, classify_esoteric, decode_jjencode,
    detect_jjencode,
};

const BASIC: &str = include_str!("../corpus/esoteric/jjencode-basic.jjencode.js");
const ALT: &str = include_str!("../corpus/esoteric/jjencode-alt-global.jjencode.js");

#[test]
fn detects_jjencode_signature() {
    let det: JjEncodeDetection = detect_jjencode(BASIC);
    assert!(det.matched, "expected jjencode signature: {det:?}");
    assert_eq!(det.global_var.as_deref(), Some("$"));
    assert!(det.signature_hits >= 2);
    assert!(det.charset_size >= 6);
}

#[test]
fn detects_alt_global_var() {
    let det: JjEncodeDetection = detect_jjencode(ALT);
    assert!(det.matched);
    assert_eq!(det.global_var.as_deref(), Some("_"));
}

#[test]
fn classify_routes_jjencode() {
    let classification = classify_esoteric(BASIC);
    assert_eq!(classification.family, EsotericFamily::JjEncode);
}

#[test]
fn decode_returns_some_capture_or_detection_only() {
    let decode: JjEncodeDecode = decode_jjencode(BASIC);
    assert!(decode.detection.matched);
}

#[test]
fn rejects_normal_javascript() {
    let det: JjEncodeDetection = detect_jjencode("var x = 1; function y(){return x;}");
    assert!(!det.matched);
}
