#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::PathBuf;

use disrobe_pass_js_deob::{ObfuscatorIoOptions, ObfuscatorIoOutput, obfuscator_io_deobfuscate};

const SELF_DEFENDING_REGEX: &str = "(((.+)+)+)+$";

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

fn deobfuscate_full(source: &str) -> ObfuscatorIoOutput {
    let opts: ObfuscatorIoOptions = ObfuscatorIoOptions::all();
    obfuscator_io_deobfuscate(source, &opts).expect("obfuscator.io full pipeline must not error")
}

#[test]
fn real_hello_world_recovers_readable_source() {
    let Some(src): Option<String> = load("javascript-obfuscator/obfuscated.js") else {
        return;
    };
    assert!(
        src.contains(SELF_DEFENDING_REGEX),
        "fixture precondition: input must carry the self-defending regex marker",
    );
    assert!(
        src.contains("a0_0x292a") || src.contains("a0_0x203f"),
        "fixture precondition: input must carry the hex string-array accessor",
    );

    let out: ObfuscatorIoOutput = deobfuscate_full(&src);
    let recovered: &str = &out.source;

    assert!(
        !recovered.contains(SELF_DEFENDING_REGEX),
        "self-defending checker regex must be stripped; got:\n{recovered}",
    );
    assert!(
        out.unminify_stats.self_defending_checkers_removed >= 1,
        "stats must record the removed self-defending checker; got {:?}",
        out.unminify_stats,
    );
    assert!(
        !recovered.contains("_0x"),
        "all hex identifiers must be renamed away; got:\n{recovered}",
    );
    assert!(
        recovered.contains("function greet"),
        "the greet function must survive recovery; got:\n{recovered}",
    );
    assert!(
        recovered.contains("console.log") && recovered.contains("greet("),
        "the original call shape must be recovered; got:\n{recovered}",
    );
    assert!(
        recovered.contains("'hello '") || recovered.contains("\"hello \""),
        "string-array contents must be decoded and inlined; got:\n{recovered}",
    );
    assert!(
        recovered.contains("'world'") || recovered.contains("\"world\""),
        "the greet argument literal must be recovered; got:\n{recovered}",
    );
    assert!(
        recovered.len() * 2 < src.len(),
        "recovered source should be far smaller than the obfuscated input ({} vs {})",
        recovered.len(),
        src.len(),
    );
}

#[test]
fn real_megafile_strips_self_defending_and_recovers_symbols() {
    let Some(src): Option<String> = load("javascript-obfuscator/obfuscated.megafile.js") else {
        return;
    };
    assert!(
        src.contains("_0x") && !src.contains("function greet("),
        "fixture precondition: megafile input must be obfuscated (hex idents, greet not yet visible)",
    );

    let out: ObfuscatorIoOutput = deobfuscate_full(&src);
    let recovered: &str = &out.source;

    assert!(
        !recovered.contains(SELF_DEFENDING_REGEX),
        "self-defending checker regex must be stripped from megafile after string-array inlining; head:\n{}",
        &recovered.chars().take(400).collect::<String>(),
    );
    assert!(
        out.unminify_stats.self_defending_checkers_removed >= 1,
        "megafile stats must record the removed self-defending checker; got {:?}",
        out.unminify_stats,
    );
    assert!(
        out.string_array_call_sites_inlined >= 1,
        "megafile string-array call sites must be inlined; got {out:?}",
    );
    assert!(
        recovered.contains("'use strict'") || recovered.contains("\"use strict\""),
        "the program prologue must surface once the obfuscation preamble is gone; head:\n{}",
        &recovered.chars().take(200).collect::<String>(),
    );
    assert!(
        recovered.contains("greet") && recovered.contains("console"),
        "recognizable program symbols must remain after recovery; head:\n{}",
        &recovered.chars().take(400).collect::<String>(),
    );
}

#[test]
fn real_string_array_wrapper_is_gone() {
    let Some(src): Option<String> = load("javascript-obfuscator/obfuscated.js") else {
        return;
    };
    let out: ObfuscatorIoOutput = deobfuscate_full(&src);
    let recovered: &str = &out.source;

    assert!(
        !recovered.contains("['push']") && !recovered.contains("['shift']"),
        "the array-rotation IIFE (push/shift) must be removed; got:\n{recovered}",
    );
    assert!(
        !recovered.contains("function a0_0x292a") && !recovered.contains("function a0_0x203f"),
        "the string-array provider and accessor functions must be gone; got:\n{recovered}",
    );
    assert!(
        out.idents_renamed >= 1,
        "hex identifiers must be renamed; got {out:?}",
    );
}
