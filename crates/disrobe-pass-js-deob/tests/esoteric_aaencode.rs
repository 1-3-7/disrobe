#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_js_deob::{
    AaEncodeDecode, AaEncodeDetection, EsotericFamily, classify_esoteric, decode_aaencode,
    detect_aaencode,
};

const BANNER: &str = include_str!("../corpus/esoteric/aaencode-banner.aaencode.js");
const BIGGER: &str = include_str!("../corpus/esoteric/aaencode-bigger.aaencode.js");

#[test]
fn detects_banner_fixture() {
    let det: AaEncodeDetection = detect_aaencode(BANNER);
    assert!(det.matched, "banner fixture must match: {det:?}");
    assert!(det.banner_hits >= 1);
    assert!(det.kaomoji_density >= 0.05);
}

#[test]
fn classify_routes_aaencode() {
    let classification = classify_esoteric(BIGGER);
    assert_eq!(classification.family, EsotericFamily::AaEncode);
}

#[test]
fn decode_returns_detection_envelope() {
    let decode: AaEncodeDecode = decode_aaencode(BANNER);
    assert!(decode.detection.matched);
}

#[test]
fn rejects_normal_javascript() {
    let det: AaEncodeDetection = detect_aaencode("function foo(){return 42;}");
    assert!(!det.matched);
}
