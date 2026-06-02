#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

use disrobe_pass_js_deob::{
    AaEncodeDetection, EsotericClassification, EsotericFamily, JjEncodeDetection, JsFuckDetection,
    PackerDetection, classify_esoteric, detect_aaencode, detect_jjencode, detect_jsfuck,
    detect_packer,
};

fn corpus_path(rel: &str) -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("..")
        .join("..")
        .join("corpus")
        .join("js")
        .join(rel)
}

fn load(rel: &str) -> Option<String> {
    let p: PathBuf = corpus_path(rel);
    if !p.exists() {
        return None;
    }
    fs::read_to_string(&p).ok()
}

#[test]
fn real_jsfuck_megafile_detects_as_jsfuck() {
    let Some(src): Option<String> = load("jsfuck/obfuscated.megafile.js") else {
        return;
    };
    let det: JsFuckDetection = detect_jsfuck(&src);
    assert!(det.matched, "real jsfuck megafile must match: {det:?}");
    assert!(det.purity_ratio >= 0.95);
}

#[test]
fn real_jsfuck_classification_routes_to_jsfuck_family() {
    let Some(src): Option<String> = load("jsfuck/obfuscated.megafile.js") else {
        return;
    };
    let classification: EsotericClassification = classify_esoteric(&src);
    assert_eq!(classification.family, EsotericFamily::JsFuck);
    assert!(classification.confidence >= 0.9);
}

#[test]
fn real_aaencode_megafile_detects_as_aaencode() {
    let Some(src): Option<String> = load("aaencode/obfuscated.megafile.js") else {
        return;
    };
    let det: AaEncodeDetection = detect_aaencode(&src);
    assert!(det.matched, "real aaencode megafile must match: {det:?}");
    assert!(det.banner_hits >= 1);
}

#[test]
fn real_aaencode_classification_routes_to_aaencode_family() {
    let Some(src): Option<String> = load("aaencode/obfuscated.megafile.js") else {
        return;
    };
    let classification: EsotericClassification = classify_esoteric(&src);
    assert_eq!(classification.family, EsotericFamily::AaEncode);
}

#[test]
fn real_jjencode_megafile_detects_as_jjencode() {
    let Some(src): Option<String> = load("jjencode/obfuscated.megafile.js") else {
        return;
    };
    let det: JjEncodeDetection = detect_jjencode(&src);
    assert!(det.matched, "real jjencode megafile must match: {det:?}");
    assert_eq!(det.global_var.as_deref(), Some("$"));
    assert!(det.signature_hits >= 2);
}

#[test]
fn real_jjencode_classification_routes_to_jjencode_family() {
    let Some(src): Option<String> = load("jjencode/obfuscated.megafile.js") else {
        return;
    };
    let classification: EsotericClassification = classify_esoteric(&src);
    assert_eq!(classification.family, EsotericFamily::JjEncode);
}

#[test]
fn real_packer_megafile_detects_as_dean_edwards_packer() {
    let Some(src): Option<String> = load("packer/obfuscated.megafile.js") else {
        return;
    };
    let det: PackerDetection = detect_packer(&src);
    assert!(det.matched, "real packer megafile must match: {det:?}");
    assert!(det.base >= 36, "expected base>=36, got {}", det.base);
    assert!(det.word_count >= 1);
}

#[test]
fn real_packer_classification_routes_to_packer_family() {
    let Some(src): Option<String> = load("packer/obfuscated.megafile.js") else {
        return;
    };
    let classification: EsotericClassification = classify_esoteric(&src);
    assert_eq!(classification.family, EsotericFamily::DeanEdwardsPacker);
}
