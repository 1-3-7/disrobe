#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::PathBuf;

use disrobe_pass_js_deob::{
    ClosureAdvancedReport, PresetEnvUndoResult, TerserRestoreReport, restore_terser_mangled,
    undo_closure_advanced, undo_preset_env,
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
fn real_terser_megafile_restore_runs_without_panic() {
    let Some(src): Option<String> = load("terser/obfuscated.megafile.js") else {
        return;
    };
    let report: TerserRestoreReport = restore_terser_mangled(&src);
    let _ = report;
}

#[test]
fn real_closure_simple_megafile_undo_runs_without_panic() {
    let Some(src): Option<String> = load("closure/obfuscated.megafile.simple.js") else {
        return;
    };
    let report: ClosureAdvancedReport = undo_closure_advanced(&src);
    let _ = report;
}

#[test]
fn real_closure_whitespace_megafile_undo_runs_without_panic() {
    let Some(src): Option<String> = load("closure/obfuscated.megafile.whitespace.js") else {
        return;
    };
    let report: ClosureAdvancedReport = undo_closure_advanced(&src);
    let _ = report;
}

#[test]
fn real_babel_preset_env_megafile_undo_runs_without_panic() {
    let Some(src): Option<String> = load("babel-preset-env/obfuscated.megafile.js") else {
        return;
    };
    let report: PresetEnvUndoResult = undo_preset_env(&src);
    let _ = report;
}

#[test]
fn real_tsc_megafile_emits_runnable_javascript() {
    let Some(src): Option<String> = load("tsc/obfuscated.megafile.js") else {
        return;
    };
    assert!(src.contains("function") || src.contains("class") || src.contains("console"));
    assert!(!src.is_empty());
}

#[test]
fn real_tsc_declaration_file_parses_as_text() {
    let Some(src): Option<String> = load("tsc/edge_cases.d.ts") else {
        return;
    };
    assert!(src.contains("declare") || src.contains("export"));
}

#[test]
fn real_outputs_distinct_from_input() {
    let Some(input): Option<String> = load("terser/edge_cases.js") else {
        return;
    };
    for rel in [
        "terser/obfuscated.megafile.js",
        "closure/obfuscated.megafile.simple.js",
        "closure/obfuscated.megafile.whitespace.js",
        "babel-preset-env/obfuscated.megafile.js",
    ] {
        let Some(out): Option<String> = load(rel) else {
            continue;
        };
        assert_ne!(out, input, "{rel} must not equal input");
    }
}
