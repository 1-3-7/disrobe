#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::PathBuf;

use disrobe_pass_js_deob::{
    DeobOptions, DeobOutput, Detection, JsObfuscator, deobfuscate_all, detect,
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

fn load(rel: &str) -> String {
    let p: PathBuf = corpus_path(rel);
    fs::read_to_string(&p).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "tracked corpus fixture {} is required: {error}",
            p.display()
        )
    })
}

fn reparses(source: &str) -> bool {
    let allocator: oxc_allocator::Allocator = oxc_allocator::Allocator::default();
    let source_type: oxc_span::SourceType =
        oxc_span::SourceType::from_path("check.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> =
        oxc_parser::Parser::new(&allocator, source, source_type).parse();
    parsed.errors.is_empty() && !parsed.panicked
}

#[test]
fn every_megafile_preset_is_detected_as_jsconfuser() {
    for rel in [
        "jsconfuser/obfuscated.megafile.low.js",
        "jsconfuser/obfuscated.megafile.medium.js",
        "jsconfuser/obfuscated.megafile.high.js",
    ] {
        let src: String = load(rel);
        let detection: Detection = detect(src.as_bytes());
        assert_eq!(
            detection.family,
            JsObfuscator::JsConfuser,
            "{rel}: {detection:?}"
        );
    }
    for rel in [
        "jsconfuser/obfuscated.megafile.low.js",
        "jsconfuser/obfuscated.megafile.medium.js",
    ] {
        let detection: Detection = detect(load(rel).as_bytes());
        assert!(
            detection
                .markers
                .iter()
                .any(|marker: &String| marker == "base91-string-concealing"),
            "{rel}: {detection:?}"
        );
    }
}

#[test]
fn real_jsconfuser_low_runs_without_panic() {
    let src: String = load("jsconfuser/obfuscated.megafile.low.js");
    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput =
        deobfuscate_all(&src, &opts).expect("jsconfuser deobfuscation must not refuse");
    assert!(
        out.source != src && reparses(&out.source),
        "low preset recovery must rewrite the input into source that parses"
    );
}

#[test]
fn real_jsconfuser_medium_runs_without_panic() {
    let src: String = load("jsconfuser/obfuscated.megafile.medium.js");
    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput =
        deobfuscate_all(&src, &opts).expect("jsconfuser deobfuscation must not refuse");
    assert!(
        out.source != src && reparses(&out.source),
        "medium preset recovery must rewrite the input into source that parses"
    );
}

#[test]
fn real_jsconfuser_high_runs_without_panic() {
    let src: String = load("jsconfuser/obfuscated.megafile.high.js");
    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput =
        deobfuscate_all(&src, &opts).expect("jsconfuser deobfuscation must not refuse");
    assert!(
        out.source != src && reparses(&out.source),
        "high preset recovery must rewrite the input into source that parses"
    );
    assert!(
        out.string_compression_blocks_reversed > 0,
        "high preset should reverse the real stringCompression pool"
    );
    assert!(
        !out.source
            .contains("decompressFromUTF16(F3Gl7_L[C8ten4[0x10]])"),
        "high preset should eliminate the indirect LZString pool call"
    );
}

#[test]
fn real_jsconfuser_outputs_are_distinct_from_input() {
    let input: String = load("jsconfuser/edge_cases.js");
    for rel in [
        "jsconfuser/obfuscated.megafile.low.js",
        "jsconfuser/obfuscated.megafile.medium.js",
        "jsconfuser/obfuscated.megafile.high.js",
    ] {
        let obf: String = load(rel);
        assert_ne!(obf, input, "{rel} must not equal input");
        assert!(
            obf.len() > input.len() / 2,
            "{rel} should not collapse to nothing"
        );
    }
}
