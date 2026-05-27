#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_js_deob::{
    EsotericFamily, JsFireTruckDetection, classify_esoteric, detect_jsfiretruck,
};

const SYNTH: &str = include_str!("../corpus/esoteric/jsfiretruck-synth.firetruck.js");

#[test]
fn detects_synthetic_firetruck_payload() {
    let det: JsFireTruckDetection = detect_jsfiretruck(SYNTH);
    assert!(det.matched, "synth firetruck must match: {det:?}");
    assert!(det.dot_slash_density > 0.005);
    assert!(det.purity_ratio >= 0.9);
}

#[test]
fn classify_routes_firetruck() {
    let classification = classify_esoteric(SYNTH);
    assert_eq!(classification.family, EsotericFamily::JsFireTruck);
}

#[test]
fn pure_jsfuck_does_not_match_firetruck() {
    let src: &str = "[][(![]+[])[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]]";
    let det: JsFireTruckDetection = detect_jsfiretruck(src);
    assert!(!det.matched);
}
