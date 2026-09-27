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

fn load(rel: &str) -> String {
    let p: PathBuf = corpus_path(rel);
    fs::read_to_string(&p).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "tracked corpus fixture {} is required: {error}",
            p.display()
        )
    })
}

#[test]
fn real_javascript_obfuscator_megafile_detects() {
    let src: String = load("javascript-obfuscator/obfuscated.megafile.js");
    let det: ObfuscatorIoDetection = obfuscator_io_detect(&src);
    assert!(
        det.matched,
        "real javascript-obfuscator megafile output must be detected; got {det:?}",
    );
}

#[test]
fn real_javascript_obfuscator_hello_world_detects() {
    let src: String = load("javascript-obfuscator/obfuscated.js");
    let det: ObfuscatorIoDetection = obfuscator_io_detect(&src);
    assert!(
        det.matched,
        "real javascript-obfuscator hello-world output must be detected; got {det:?}",
    );
}

#[test]
fn real_javascript_obfuscator_megafile_is_distinct_from_input() {
    let obf: String = load("javascript-obfuscator/obfuscated.megafile.js");
    let input: String = load("javascript-obfuscator/edge_cases.js");
    assert_ne!(obf, input);
    assert!(obf.len() > input.len() / 2);
}
