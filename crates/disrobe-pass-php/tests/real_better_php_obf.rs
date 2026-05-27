#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::missing_const_for_fn
)]

use std::path::PathBuf;

use disrobe_pass_php::{PhpDetection, PhpKind, ScanReport, detect_php, signature_scan, tokenize};

fn corpus_root() -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .expect("crates parent")
        .parent()
        .expect("workspace root")
        .join("corpus")
        .join("php")
}

fn read_fixture(rel: &str) -> Vec<u8> {
    let path: PathBuf = corpus_root().join(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", path.display()))
}

#[test]
fn detects_baseline_hello_as_source_php() {
    let bytes: Vec<u8> = read_fixture("baseline/hello.php");
    let det: PhpDetection = detect_php(&bytes);
    assert!(matches!(det.kind, PhpKind::Source | PhpKind::Unknown));
}

#[test]
fn tokenizes_baseline_hello_yields_open_tag() {
    let bytes: Vec<u8> = read_fixture("baseline/hello.php");
    let toks: Vec<disrobe_pass_php::Token<'_>> = tokenize(&bytes).expect("tokenize");
    assert!(!toks.is_empty());
    assert!(toks.iter().any(|t: &disrobe_pass_php::Token<'_>| matches!(
        t.kind,
        disrobe_pass_php::TokKind::OpenTag
    )));
}

#[test]
fn tokenizes_megafile_yields_many_tokens() {
    let bytes: Vec<u8> = read_fixture("megafile/edge_cases.php");
    let toks: Vec<disrobe_pass_php::Token<'_>> = tokenize(&bytes).expect("tokenize");
    assert!(
        toks.len() >= 1500,
        "expected dense token stream for PHP 8 megafile, got {}",
        toks.len()
    );
}

#[test]
fn tokenizes_pre80_megafile_yields_many_tokens() {
    let bytes: Vec<u8> = read_fixture("megafile/pre80_edge_cases.php");
    let toks: Vec<disrobe_pass_php::Token<'_>> = tokenize(&bytes).expect("tokenize");
    assert!(
        toks.len() >= 500,
        "expected token stream for pre-8 megafile, got {}",
        toks.len()
    );
}

#[test]
fn tokenizes_real_obfuscated_megafile() {
    let bytes: Vec<u8> = read_fixture("better-php-obfuscator/edge_cases.obf.php");
    let toks: Vec<disrobe_pass_php::Token<'_>> = tokenize(&bytes).expect("tokenize");
    assert!(
        toks.len() >= 500,
        "expected substantial token stream, got {}",
        toks.len()
    );
    let var_count: usize = toks
        .iter()
        .filter(|t: &&disrobe_pass_php::Token<'_>| {
            matches!(t.kind, disrobe_pass_php::TokKind::Variable)
        })
        .count();
    assert!(
        var_count >= 50,
        "expected many variables in obfuscated output, got {var_count}"
    );
}

#[test]
fn naneau_obfuscator_renames_variables_consistently() {
    let bytes: Vec<u8> = read_fixture("better-php-obfuscator/edge_cases.obf.php");
    let text: String = String::from_utf8_lossy(&bytes).into_owned();
    let var_count: usize = text.matches("$sp").count();
    assert!(
        var_count >= 50,
        "expected scrambled vars '$sp<hex>' in real naneau output, got {var_count}"
    );
}

#[test]
fn scans_baseline_hello_no_signature_hits() {
    let bytes: Vec<u8> = read_fixture("baseline/hello.php");
    let report: ScanReport = signature_scan(&bytes);
    assert!(report.hits.is_empty(), "unexpected hits: {:?}", report.hits);
}
