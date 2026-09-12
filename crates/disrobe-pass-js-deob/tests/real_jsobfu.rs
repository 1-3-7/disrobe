#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::PathBuf;

use disrobe_pass_js_deob::{
    JsObfuDetection, JsObfuRewriteStats, detect_jsobfu, rewrite_bracket_access,
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
fn real_jsobfu_es5_output_detects() {
    let Some(src): Option<String> = load("jsobfu/obfuscated.js") else {
        return;
    };
    let det: JsObfuDetection = detect_jsobfu(&src);
    assert!(det.matched, "real jsobfu ES5 output must match: {det:?}");
    assert!(det.confidence >= 0.5, "confidence floor: {det:?}");
}

#[test]
fn real_jsobfu_rewrite_runs_without_panic() {
    let Some(src): Option<String> = load("jsobfu/obfuscated.js") else {
        return;
    };
    let (out, stats): (String, JsObfuRewriteStats) = rewrite_bracket_access(&src);
    assert!(!out.is_empty(), "rewrite must emit non-empty output");
    let _ = stats;
}
