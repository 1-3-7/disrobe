#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::PathBuf;

use disrobe_pass_js_deob::{
    CharFoldStats, JsObfuDetection, JsObfuRewriteStats, detect_jsobfu, fold_char_constructors,
    rewrite_bracket_access,
};
use regex::Regex;

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

fn string_bracket_accesses(source: &str) -> usize {
    Regex::new(r#"\[\s*["'][A-Za-z_$][\w$]*["']\s*\]"#)
        .expect("bracket access pattern")
        .find_iter(source)
        .count()
}

#[test]
fn real_jsobfu_es5_output_detects() {
    let src: String = load("jsobfu/obfuscated.js");
    let det: JsObfuDetection = detect_jsobfu(&src);
    assert!(det.matched, "real jsobfu ES5 output must match: {det:?}");
    assert!(det.confidence >= 0.5, "confidence floor: {det:?}");
}

#[test]
fn real_jsobfu_rewrite_converts_every_string_bracket_access() {
    let src: String = load("jsobfu/obfuscated.js");
    let (folded, _): (String, CharFoldStats) = fold_char_constructors(&src);
    let before: usize = string_bracket_accesses(&folded);
    assert!(
        before > 0,
        "folding the real jsobfu output must expose string bracket accesses"
    );
    let (out, stats): (String, JsObfuRewriteStats) = rewrite_bracket_access(&folded);
    assert!(reparses(&out), "rewritten jsobfu output must parse");
    assert_eq!(
        stats.bracket_to_dot_rewrites, before,
        "every identifier-shaped string bracket access in the input must be rewritten"
    );
    assert_eq!(
        string_bracket_accesses(&out),
        0,
        "no identifier-shaped string bracket access may survive the rewrite"
    );
}
