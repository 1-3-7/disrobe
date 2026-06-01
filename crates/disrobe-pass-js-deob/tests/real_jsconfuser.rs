#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

use disrobe_pass_js_deob::{DeobOptions, DeobOutput, deobfuscate_all};

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
fn real_jsconfuser_low_runs_without_panic() {
    let Some(src): Option<String> = load("jsconfuser/obfuscated.megafile.low.js") else {
        return;
    };
    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput = deobfuscate_all(&src, &opts);
    assert!(
        !out.source.is_empty(),
        "low preset output must be non-empty"
    );
}

#[test]
fn real_jsconfuser_medium_runs_without_panic() {
    let Some(src): Option<String> = load("jsconfuser/obfuscated.megafile.medium.js") else {
        return;
    };
    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput = deobfuscate_all(&src, &opts);
    assert!(
        !out.source.is_empty(),
        "medium preset output must be non-empty"
    );
}

#[test]
fn real_jsconfuser_high_runs_without_panic() {
    let Some(src): Option<String> = load("jsconfuser/obfuscated.megafile.high.js") else {
        return;
    };
    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput = deobfuscate_all(&src, &opts);
    assert!(
        !out.source.is_empty(),
        "high preset output must be non-empty"
    );
}

#[test]
fn real_jsconfuser_outputs_are_distinct_from_input() {
    let Some(input): Option<String> = load("jsconfuser/edge_cases.js") else {
        return;
    };
    for rel in [
        "jsconfuser/obfuscated.megafile.low.js",
        "jsconfuser/obfuscated.megafile.medium.js",
        "jsconfuser/obfuscated.megafile.high.js",
    ] {
        let Some(obf): Option<String> = load(rel) else {
            continue;
        };
        assert_ne!(obf, input, "{rel} must not equal input");
        assert!(
            obf.len() > input.len() / 2,
            "{rel} should not collapse to nothing"
        );
    }
}
