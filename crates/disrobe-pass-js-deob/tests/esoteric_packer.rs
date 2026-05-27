#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_js_deob::{
    EsotericFamily, PackerDecode, PackerDetection, classify_esoteric, detect_packer, unpack_packer,
};

const SMALL: &str = include_str!("../corpus/esoteric/packer-small.packed.js");

#[test]
fn detects_packer_signature() {
    let det: PackerDetection = detect_packer(SMALL);
    assert!(det.matched, "must detect packer: {det:?}");
    assert_eq!(det.base, 6);
    assert_eq!(det.word_count, 6);
}

#[test]
fn classify_routes_dean_edwards_packer() {
    let classification = classify_esoteric(SMALL);
    assert_eq!(classification.family, EsotericFamily::DeanEdwardsPacker);
}

#[test]
fn unpacks_to_expected_word_stream() {
    let decode: PackerDecode = unpack_packer(SMALL);
    assert!(decode.detection.matched);
    let Some(recovered): Option<String> = decode.recovered else {
        panic!("must recover packed payload");
    };
    assert!(
        recovered.contains("console"),
        "missing console: {recovered}"
    );
    assert!(recovered.contains("log"), "missing log: {recovered}");
    assert!(recovered.contains("hello"));
    assert!(recovered.contains("world"));
    assert!(recovered.contains("disrobe"));
    assert!(recovered.contains("fixture"));
}

#[test]
fn ignores_non_packer_source() {
    let det: PackerDetection = detect_packer("function foo(){return 1;}");
    assert!(!det.matched);
}
