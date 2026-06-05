#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::missing_const_for_fn
)]

mod common;

use disrobe_pass_php::{PhpDetection, PhpKind, ScanReport, detect_php, signature_scan, tokenize};

#[test]
fn detects_baseline_hello_as_source_php() {
    let Some(bytes): Option<Vec<u8>> = common::load_php_fixture("baseline/hello.php") else {
        eprintln!("skip: baseline/hello.php fixture absent");
        return;
    };
    let det: PhpDetection = detect_php(&bytes);
    assert!(matches!(det.kind, PhpKind::Source | PhpKind::Unknown));
}

#[test]
fn tokenizes_baseline_hello_yields_open_tag() {
    let Some(bytes): Option<Vec<u8>> = common::load_php_fixture("baseline/hello.php") else {
        eprintln!("skip: baseline/hello.php fixture absent");
        return;
    };
    let toks: Vec<disrobe_pass_php::Token<'_>> = tokenize(&bytes).expect("tokenize");
    assert!(!toks.is_empty());
    assert!(toks.iter().any(|t: &disrobe_pass_php::Token<'_>| matches!(
        t.kind,
        disrobe_pass_php::TokKind::OpenTag
    )));
}

#[test]
fn tokenizes_megafile_yields_many_tokens() {
    let Some(bytes): Option<Vec<u8>> = common::load_php_fixture("megafile/edge_cases.php") else {
        eprintln!("skip: megafile/edge_cases.php fixture absent");
        return;
    };
    let toks: Vec<disrobe_pass_php::Token<'_>> = tokenize(&bytes).expect("tokenize");
    assert!(
        toks.len() >= 1500,
        "expected dense token stream for PHP 8 megafile, got {}",
        toks.len()
    );
}

#[test]
fn tokenizes_pre80_megafile_yields_many_tokens() {
    let Some(bytes): Option<Vec<u8>> = common::load_php_fixture("megafile/pre80_edge_cases.php")
    else {
        eprintln!("skip: megafile/pre80_edge_cases.php fixture absent");
        return;
    };
    let toks: Vec<disrobe_pass_php::Token<'_>> = tokenize(&bytes).expect("tokenize");
    assert!(
        toks.len() >= 500,
        "expected token stream for pre-8 megafile, got {}",
        toks.len()
    );
}

#[test]
fn tokenizes_real_obfuscated_megafile() {
    let Some(bytes): Option<Vec<u8>> =
        common::load_php_fixture("better-php-obfuscator/edge_cases.obf.php")
    else {
        eprintln!("skip: better-php-obfuscator/edge_cases.obf.php fixture absent");
        return;
    };
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
    let Some(bytes): Option<Vec<u8>> =
        common::load_php_fixture("better-php-obfuscator/edge_cases.obf.php")
    else {
        eprintln!("skip: better-php-obfuscator/edge_cases.obf.php fixture absent");
        return;
    };
    let text: String = String::from_utf8_lossy(&bytes).into_owned();
    let var_count: usize = text.matches("$sp").count();
    assert!(
        var_count >= 50,
        "expected scrambled vars '$sp<hex>' in real naneau output, got {var_count}"
    );
}

#[test]
fn scans_baseline_hello_no_signature_hits() {
    let Some(bytes): Option<Vec<u8>> = common::load_php_fixture("baseline/hello.php") else {
        eprintln!("skip: baseline/hello.php fixture absent");
        return;
    };
    let report: ScanReport = signature_scan(&bytes);
    assert!(report.hits.is_empty(), "unexpected hits: {:?}", report.hits);
}
