#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

use disrobe_pass_js_deob::{ObfuscatorIoDetection, obfuscator_io_detect};

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
fn real_javascript_obfuscator_megafile_detects() {
    let Some(src): Option<String> = load("javascript-obfuscator/obfuscated.megafile.js") else {
        return;
    };
    let det: ObfuscatorIoDetection = obfuscator_io_detect(&src);
    assert!(
        det.matched || !det.controls.is_empty(),
        "real javascript-obfuscator megafile output must show controls; got {det:?}",
    );
}

#[test]
fn real_javascript_obfuscator_hello_world_detects() {
    let Some(src): Option<String> = load("javascript-obfuscator/obfuscated.js") else {
        return;
    };
    let det: ObfuscatorIoDetection = obfuscator_io_detect(&src);
    assert!(
        det.matched || !det.controls.is_empty(),
        "real javascript-obfuscator hello-world output must show controls; got {det:?}",
    );
}

#[test]
fn real_javascript_obfuscator_megafile_is_distinct_from_input() {
    let Some(obf): Option<String> = load("javascript-obfuscator/obfuscated.megafile.js") else {
        return;
    };
    let Some(input): Option<String> = load("javascript-obfuscator/edge_cases.js") else {
        return;
    };
    assert_ne!(obf, input);
    assert!(obf.len() > input.len() / 2);
}
