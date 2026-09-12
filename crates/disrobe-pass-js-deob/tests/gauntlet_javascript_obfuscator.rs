#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::PathBuf;

use disrobe_pass_js_deob::{
    ObfuscatorIoDetection, ObfuscatorIoOptions, ObfuscatorIoOutput, RenameStats,
    obfuscator_io_deobfuscate, obfuscator_io_detect, rename_hex_idents,
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

fn load_fixture(rel: &str) -> String {
    let p: PathBuf = corpus_path(rel);
    fs::read_to_string(&p)
        .unwrap_or_else(|e: std::io::Error| panic!("failed to read fixture {}: {e}", p.display()))
}

#[test]
fn gauntlet_fixture_is_distinct_from_source() {
    let source: String = load_fixture("javascript-obfuscator/gauntlet-source.js");
    let obfuscated: String = load_fixture("javascript-obfuscator/gauntlet-obfuscated.js");
    assert_ne!(
        source, obfuscated,
        "obfuscated fixture must differ from ground-truth source"
    );
    assert!(
        obfuscated.len() > source.len(),
        "obfuscated output must be larger than the source (obf={}, src={})",
        obfuscated.len(),
        source.len()
    );
    assert!(
        obfuscated.contains("a0_0x4b36"),
        "fixture must contain the real javascript-obfuscator string-array accessor"
    );
    assert!(
        obfuscated.contains("a0_0x9b6d"),
        "fixture must contain the real string-array provider function"
    );
}

#[test]
fn gauntlet_obfuscated_detects_as_obfuscator_io() {
    let src: String = load_fixture("javascript-obfuscator/gauntlet-obfuscated.js");
    let det: ObfuscatorIoDetection = obfuscator_io_detect(&src);
    assert!(
        det.matched || !det.controls.is_empty(),
        "real javascript-obfuscator 5.4.3 output must be detected; got {det:?}"
    );
}

#[test]
fn gauntlet_full_pipeline_inlines_string_array() {
    let src: String = load_fixture("javascript-obfuscator/gauntlet-obfuscated.js");
    let opts: ObfuscatorIoOptions = ObfuscatorIoOptions::all();
    let out: ObfuscatorIoOutput =
        obfuscator_io_deobfuscate(&src, &opts).expect("full pipeline must not error");

    assert!(
        out.string_array_call_sites_inlined >= 40,
        "at least 40 string-array call sites must be inlined; got {}",
        out.string_array_call_sites_inlined
    );
    assert!(
        out.idents_renamed >= 23,
        "at least 23 hex identifiers must be renamed; got {}",
        out.idents_renamed
    );
    assert!(
        out.passes_run >= 1,
        "pipeline must run at least one pass; got {}",
        out.passes_run
    );
}

#[test]
fn gauntlet_proxy_objects_resolved() {
    let src: String = load_fixture("javascript-obfuscator/gauntlet-obfuscated.js");
    let opts: ObfuscatorIoOptions = ObfuscatorIoOptions::all();
    let out: ObfuscatorIoOutput =
        obfuscator_io_deobfuscate(&src, &opts).expect("full pipeline must not error");

    assert!(
        out.control_flow_objects_merged >= 4,
        "at least 4 control-flow dispatch proxy objects must be resolved; got {}",
        out.control_flow_objects_merged
    );
}

#[test]
fn gauntlet_dead_branches_removed() {
    let src: String = load_fixture("javascript-obfuscator/gauntlet-obfuscated.js");
    let opts: ObfuscatorIoOptions = ObfuscatorIoOptions::all();
    let out: ObfuscatorIoOutput =
        obfuscator_io_deobfuscate(&src, &opts).expect("full pipeline must not error");

    assert!(
        out.opaque_predicates_folded >= 2,
        "at least 2 dead-code injection guards must be folded; got {}",
        out.opaque_predicates_folded
    );

    let (recovered, _): (String, RenameStats) = rename_hex_idents(&out.source);
    assert!(
        !recovered.contains("'IoYFb'==='IoYFb'") && !recovered.contains("\"IoYFb\"===\"IoYFb\""),
        "always-true dead-code guard must be removed; recovered:\n{recovered}"
    );
}

#[test]
fn gauntlet_recovered_source_contains_original_strings() {
    let src: String = load_fixture("javascript-obfuscator/gauntlet-obfuscated.js");
    let opts: ObfuscatorIoOptions = ObfuscatorIoOptions::all();
    let out: ObfuscatorIoOutput =
        obfuscator_io_deobfuscate(&src, &opts).expect("full pipeline must not error");

    let (recovered, _stats): (String, RenameStats) = rename_hex_idents(&out.source);

    assert!(
        recovered.contains("the quick brown fox jumps over the lazy dog"),
        "first SAMPLES string must be inlined into the recovered output"
    );
    assert!(
        recovered.contains("pack my box with five dozen liquor jugs"),
        "second SAMPLES string must be inlined into the recovered output"
    );
    assert!(
        recovered.contains("how vexingly quick daft zebras jump"),
        "third SAMPLES string must be inlined into the recovered output"
    );
    assert!(
        recovered.contains("histogram"),
        "the 'histogram' label string must be inlined into the recovered output"
    );
    assert!(
        recovered.contains("console"),
        "the 'console' identifier must be present in the recovered output"
    );
}

#[test]
fn gauntlet_recovered_source_preserves_function_names() {
    let src: String = load_fixture("javascript-obfuscator/gauntlet-obfuscated.js");
    let opts: ObfuscatorIoOptions = ObfuscatorIoOptions::all();
    let out: ObfuscatorIoOutput =
        obfuscator_io_deobfuscate(&src, &opts).expect("full pipeline must not error");

    assert!(
        out.source.contains("TokenCounter"),
        "the class name TokenCounter must survive recovery"
    );
    assert!(
        out.source.contains("tokenize"),
        "the function name 'tokenize' must survive recovery"
    );
    assert!(
        out.source.contains("buildHistogram"),
        "the function name 'buildHistogram' must survive recovery"
    );
    assert!(
        out.source.contains("pipeline"),
        "the function name 'pipeline' must survive recovery"
    );
    assert!(
        out.source.contains("SAMPLES"),
        "the constant name SAMPLES must survive recovery"
    );
}

#[test]
fn gauntlet_recovered_is_smaller_than_obfuscated() {
    let src: String = load_fixture("javascript-obfuscator/gauntlet-obfuscated.js");
    let opts: ObfuscatorIoOptions = ObfuscatorIoOptions::all();
    let out: ObfuscatorIoOutput =
        obfuscator_io_deobfuscate(&src, &opts).expect("full pipeline must not error");
    let (recovered, _stats): (String, RenameStats) = rename_hex_idents(&out.source);

    let reduction_pct: usize = 100 - recovered.len() * 100 / src.len();
    assert!(
        recovered.len() < src.len() / 2,
        "recovered source ({} bytes) must be less than half the obfuscated input ({} bytes); reduction={}%",
        recovered.len(),
        src.len(),
        reduction_pct
    );
}
