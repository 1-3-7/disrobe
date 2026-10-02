#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::PathBuf;

use std::time::Duration;

use disrobe_pass_js_deob::{
    AaEncodeDetection, EsotericClassification, EsotericFamily, JjEncodeDetection, JsFuckDecode,
    JsFuckDetection, PackerDecode, PackerDetection, classify_esoteric, decode_jsfuck,
    detect_aaencode, detect_jjencode, detect_jsfuck, detect_packer, unpack_packer,
};
use disrobe_testkit::{CommandSpec, ToolOutput, tool_output};

const NODE_TIMEOUT: Duration = Duration::from_mins(1);

const JSFUCK_PAIRS: [(&str, &str); 1] = [("jsfuck/obfuscated.js", "jsfuck/hello.js")];

const PACKER_PAIRS: [(&str, &str); 4] = [
    (
        "packer/real/single-layer.packed.js",
        "packer/real/ground-truth.js",
    ),
    (
        "packer/real/double-layer.packed.js",
        "packer/real/ground-truth.js",
    ),
    (
        "packer/real/triple-layer.packed.js",
        "packer/real/ground-truth.js",
    ),
    ("packer/obfuscated.megafile.js", "packer/edge_cases.js"),
];

fn node_stdout(program: &str) -> String {
    let output: ToolOutput = tool_output(
        CommandSpec::new("node", NODE_TIMEOUT)
            .arg("-")
            .stdin(program.as_bytes().to_vec()),
    )
    .expect("node is required on PATH to run the authored originals and the recoveries");
    assert!(
        output.success && !output.timed_out,
        "node failed:\n{}\n{program}",
        output.stderr_text()
    );
    output.stdout_text()
}

fn assert_recovery_runs_like_the_original(obfuscated: &str, original: &str, recovered: &str) {
    let expected: String = node_stdout(&load(original));
    assert!(
        !expected.trim().is_empty(),
        "{original} prints nothing to compare"
    );
    assert_eq!(
        node_stdout(recovered),
        expected,
        "the recovery of {obfuscated} must print what {original} prints:\n{recovered}"
    );
}

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
fn real_jsfuck_megafile_detects_as_jsfuck() {
    let src: String = load("jsfuck/obfuscated.megafile.js");
    let det: JsFuckDetection = detect_jsfuck(&src);
    assert!(det.matched, "real jsfuck megafile must match: {det:?}");
    assert!(det.purity_ratio >= 0.95);
}

#[test]
fn real_jsfuck_classification_routes_to_jsfuck_family() {
    let src: String = load("jsfuck/obfuscated.megafile.js");
    let classification: EsotericClassification = classify_esoteric(&src);
    assert_eq!(classification.family, EsotericFamily::JsFuck);
    assert!(classification.confidence >= 0.9);
}

#[test]
fn real_aaencode_megafile_detects_as_aaencode() {
    let src: String = load("aaencode/obfuscated.megafile.js");
    let det: AaEncodeDetection = detect_aaencode(&src);
    assert!(det.matched, "real aaencode megafile must match: {det:?}");
    assert!(det.banner_hits >= 1);
}

#[test]
fn real_aaencode_classification_routes_to_aaencode_family() {
    let src: String = load("aaencode/obfuscated.megafile.js");
    let classification: EsotericClassification = classify_esoteric(&src);
    assert_eq!(classification.family, EsotericFamily::AaEncode);
}

#[test]
fn real_jjencode_megafile_detects_as_jjencode() {
    let src: String = load("jjencode/obfuscated.megafile.js");
    let det: JjEncodeDetection = detect_jjencode(&src);
    assert!(det.matched, "real jjencode megafile must match: {det:?}");
    assert_eq!(det.global_var.as_deref(), Some("$"));
    assert!(det.signature_hits >= 2);
}

#[test]
fn real_jjencode_classification_routes_to_jjencode_family() {
    let src: String = load("jjencode/obfuscated.megafile.js");
    let classification: EsotericClassification = classify_esoteric(&src);
    assert_eq!(classification.family, EsotericFamily::JjEncode);
}

#[test]
fn real_packer_megafile_detects_as_dean_edwards_packer() {
    let src: String = load("packer/obfuscated.megafile.js");
    let det: PackerDetection = detect_packer(&src);
    assert!(det.matched, "real packer megafile must match: {det:?}");
    assert!(det.base >= 36, "expected base>=36, got {}", det.base);
    assert!(det.word_count >= 1);
}

#[test]
fn real_packer_classification_routes_to_packer_family() {
    let src: String = load("packer/obfuscated.megafile.js");
    let classification: EsotericClassification = classify_esoteric(&src);
    assert_eq!(classification.family, EsotericFamily::DeanEdwardsPacker);
}

#[test]
fn real_jsfuck_recoveries_run_like_the_authored_originals() {
    for (obfuscated, original) in JSFUCK_PAIRS {
        let decoded: JsFuckDecode = decode_jsfuck(&load(obfuscated));
        let recovered: String = decoded
            .recovered
            .unwrap_or_else(|| panic!("{obfuscated} must decode: {:?}", decoded.refusal));
        assert_recovery_runs_like_the_original(obfuscated, original, &recovered);
    }
}

#[test]
fn real_packer_recoveries_run_like_the_authored_originals() {
    for (obfuscated, original) in PACKER_PAIRS {
        let decoded: PackerDecode = unpack_packer(&load(obfuscated));
        let recovered: String = decoded
            .recovered
            .unwrap_or_else(|| panic!("{obfuscated} must unpack: {:?}", decoded.detection));
        assert_recovery_runs_like_the_original(obfuscated, original, &recovered);
    }
}

#[test]
fn a_recovery_that_changes_one_literal_fails_the_grade() {
    let (obfuscated, original): (&str, &str) = PACKER_PAIRS[0];
    let decoded: PackerDecode = unpack_packer(&load(obfuscated));
    let recovered: String = decoded
        .recovered
        .expect("the single-layer packer fixture unpacks");
    let mutated: String = recovered.replacen("Welcome", "Welcomes", 1);
    assert_ne!(mutated, recovered, "the mutation site must exist");
    assert_ne!(
        node_stdout(&mutated),
        node_stdout(&load(original)),
        "a one-literal change must make the grade fail"
    );
}

#[test]
fn a_real_jsfuck_megafile_beyond_the_evaluator_stack_is_refused_by_name() {
    let decoded: JsFuckDecode = decode_jsfuck(&load("jsfuck/obfuscated.megafile.js"));
    assert!(decoded.recovered.is_none());
    assert!(
        decoded
            .refusal
            .as_deref()
            .is_some_and(|reason: &str| reason.starts_with("DR-JS-0940")),
        "the 7.7 MB JSFuck megafile must be refused by name, not dropped: {:?}",
        decoded.refusal
    );
}
