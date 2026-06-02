#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_js_deob::{
    EsotericFamily, JsFuckDecode, JsFuckDetection, classify_esoteric, decode_jsfuck, detect_jsfuck,
};

const BASIC: &str = include_str!("../corpus/esoteric/jsfuck-basic.fuck.js");
const ATOMS: &str = include_str!("../corpus/esoteric/jsfuck-atoms.fuck.js");
const TRUE_LIT: &str = include_str!("../corpus/esoteric/jsfuck-bool-true.fuck.js");
const FALSE_LIT: &str = include_str!("../corpus/esoteric/jsfuck-bool-false.fuck.js");

#[test]
fn detects_basic_jsfuck_fixture() {
    let det: JsFuckDetection = detect_jsfuck(BASIC);
    assert!(
        det.matched,
        "basic fixture must classify as JSFuck: {det:?}"
    );
    assert!(det.purity_ratio >= 0.95);
    assert!(det.symbolic_atoms_recognized >= 1);
}

#[test]
fn classify_routes_jsfuck() {
    let classification = classify_esoteric(BASIC);
    assert_eq!(classification.family, EsotericFamily::JsFuck);
    assert!(classification.confidence >= 0.9);
}

#[test]
fn evaluates_basic_payload_returns_string() {
    let decode: JsFuckDecode = decode_jsfuck(BASIC);
    assert!(decode.detection.matched);
    let Some(recovered): Option<String> = decode.recovered else {
        panic!("expected boa to evaluate the basic payload");
    };
    assert!(
        !recovered.is_empty(),
        "expected non-empty recovered string; got {recovered:?}",
    );
}

#[test]
fn atoms_payload_decodes() {
    let decode: JsFuckDecode = decode_jsfuck(ATOMS);
    assert!(decode.detection.matched);
    assert!(decode.recovered.is_some());
}

#[test]
fn short_atoms_are_not_misclassified() {
    let det_true: JsFuckDetection = detect_jsfuck(TRUE_LIT);
    let det_false: JsFuckDetection = detect_jsfuck(FALSE_LIT);
    assert!(!det_true.matched, "4-char atom should not match");
    assert!(!det_false.matched, "3-char atom should not match");
}

#[test]
fn normal_javascript_is_ignored() {
    let src: &str = "function add(a, b) { return a + b; }";
    let det: JsFuckDetection = detect_jsfuck(src);
    assert!(!det.matched);
}
