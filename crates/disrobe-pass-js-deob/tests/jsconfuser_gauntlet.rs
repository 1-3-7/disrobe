#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::PathBuf;

use disrobe_pass_js_deob::{
    DeobOptions, DeobOutput, Detection, JsObfuscator, RenameStats, deobfuscate_all, detect,
    rename_hex_idents,
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

fn obfuscated() -> String {
    load_fixture("jsconfuser/gauntlet-obfuscated.js")
}

fn recover() -> (DeobOutput, String) {
    let src: String = obfuscated();
    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput = deobfuscate_all(&src, &opts);
    let (recovered, _stats): (String, RenameStats) = rename_hex_idents(&out.source);
    (out, recovered)
}

#[test]
fn gauntlet_fixture_is_distinct_from_source() {
    let source: String = load_fixture("jsconfuser/gauntlet-source.js");
    let obf: String = obfuscated();
    assert_ne!(
        source, obf,
        "obfuscated fixture must differ from ground-truth source"
    );
    assert!(
        obf.len() > source.len() * 20,
        "real JSConfuser output must dwarf the source (obf={}, src={})",
        obf.len(),
        source.len()
    );
    for original_token in [
        "buildHistogram",
        "classifyCharacter",
        "the quick brown fox",
        "vowelRatio",
    ] {
        assert!(
            !obf.contains(original_token),
            "JSConfuser must hide the original token {original_token:?}"
        );
    }
    assert!(
        obf.contains("with("),
        "fixture must contain JSConfuser control-flow-flattening with-statements"
    );
    assert!(
        obf.contains("function*"),
        "fixture must contain JSConfuser state-machine generator functions"
    );
}

#[test]
fn gauntlet_obfuscated_detects_as_jsconfuser() {
    let det: Detection = detect(obfuscated().as_bytes());
    assert_eq!(
        det.family,
        JsObfuscator::JsConfuser,
        "real JSConfuser 2.0.1 output must classify as JsConfuser; got {det:?}"
    );
    assert!(
        det.confidence >= 0.85,
        "detection confidence must be high; got {}",
        det.confidence
    );
    assert!(
        det.markers
            .iter()
            .any(|m: &String| m == "state-sum-control-flow"),
        "control-flow-flattening state machine must be a detection marker; got {:?}",
        det.markers
    );
}

#[test]
fn gauntlet_full_pipeline_decodes_string_layer() {
    let (out, _recovered): (DeobOutput, String) = recover();
    assert!(
        out.string_literals_decoded >= 1000,
        "JSConfuser stringEncoding must decode at least 1000 literals; got {}",
        out.string_literals_decoded
    );
    assert!(
        !out.string_conceal_runtime_keyed,
        "this fixture has no runtime-keyed concealing wall; got runtime_keyed=true"
    );
}

#[test]
fn gauntlet_recovered_source_contains_original_strings() {
    let (_out, recovered): (DeobOutput, String) = recover();
    for original_string in [
        "the quick brown fox jumps over the lazy dog",
        "pack my box with five dozen liquor jugs",
        "how vexingly quick daft zebras jump",
    ] {
        assert!(
            recovered.contains(original_string),
            "the original SAMPLES string {original_string:?} must reappear after recovery"
        );
    }
}

#[test]
fn gauntlet_recovered_source_contains_original_identifiers_and_labels() {
    let (_out, recovered): (DeobOutput, String) = recover();
    for token in ["histogram", "console", "vowel", "consonant"] {
        assert!(
            recovered.contains(token),
            "the original token {token:?} must be statically recovered from the encoded layer"
        );
    }
}

#[test]
fn gauntlet_recovered_is_smaller_than_obfuscated() {
    let src: String = obfuscated();
    let (_out, recovered): (DeobOutput, String) = recover();
    let reduction_pct: usize = 100 - recovered.len() * 100 / src.len();
    assert!(
        recovered.len() < src.len(),
        "recovered source ({} bytes) must be smaller than the obfuscated input ({} bytes); reduction={}%",
        recovered.len(),
        src.len(),
        reduction_pct
    );
    assert!(
        reduction_pct >= 20,
        "recovery must remove at least 20% of the obfuscated bulk; got {reduction_pct}%"
    );
}

#[test]
fn gauntlet_recovery_is_idempotent_and_panic_free() {
    let src: String = obfuscated();
    let opts: DeobOptions = DeobOptions::all();
    let first: DeobOutput = deobfuscate_all(&src, &opts);
    let second: DeobOutput = deobfuscate_all(&first.source, &opts);
    assert!(
        !second.source.is_empty(),
        "re-running recovery on already-recovered output must not collapse to empty"
    );
    assert!(
        second.source.len() <= first.source.len(),
        "second pass must not grow the source (first={}, second={})",
        first.source.len(),
        second.source.len()
    );
}
