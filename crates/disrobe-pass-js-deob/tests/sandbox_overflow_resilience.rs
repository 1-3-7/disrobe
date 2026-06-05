#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

//! Pins the bounded-refusal behaviour that stops the `boa` sandbox from native-stack-overflowing on adversarial payloads.

use std::fs;
use std::path::PathBuf;

use disrobe_pass_js_deob::{
    decode_aaencode, decode_jjencode, decode_jsfuck, detect_aaencode, detect_jjencode,
    detect_jsfuck,
};

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
}

fn read_corpus(rel: &str) -> Option<String> {
    let path: PathBuf = corpus_root().join(rel);
    fs::read(&path)
        .ok()
        .map(|b: Vec<u8>| String::from_utf8_lossy(&b).into_owned())
}

#[test]
fn jjencode_megafile_does_not_overflow_process() {
    let Some(src) = read_corpus("js/jjencode/obfuscated.megafile.js") else {
        return;
    };
    assert!(
        detect_jjencode(&src).matched,
        "fixture must classify as jjencode"
    );
    let decoded = decode_jjencode(&src);
    let _ = decoded.recovered;
}

#[test]
fn aaencode_megafile_does_not_overflow_process() {
    let Some(src) = read_corpus("js/aaencode/obfuscated.megafile.js") else {
        return;
    };
    assert!(
        detect_aaencode(&src).matched,
        "fixture must classify as aaencode"
    );
    let decoded = decode_aaencode(&src);
    let _ = decoded.recovered;
}

#[test]
fn jsfuck_megafile_does_not_overflow_process() {
    let Some(src) = read_corpus("js/jsfuck/obfuscated.megafile.js") else {
        return;
    };
    let _ = detect_jsfuck(&src);
    let decoded = decode_jsfuck(&src);
    let _ = decoded.recovered;
}

#[test]
fn adversarial_deep_concat_chain_is_bounded() {
    let payload: String = "(function(){return ".to_owned() + &"'a'+".repeat(50_000) + "'b';})()";
    let decoded = decode_jjencode(&payload);
    let _ = decoded.recovered;
}

#[test]
fn modern_recovery_handles_malformed_provider_without_panic() {
    use disrobe_pass_js_deob::recover_string_array;
    let cases: [&str; 5] = [
        "function p(){const a=['x'",
        "function p(){const a=['x'];p=function(){return a;};return p();",
        "function p(){}function d(i){return p()[i];}",
        "function p(){const a=[];p=function(){return a;};return p();}function d(i){return p()[i];}d(",
        "var _0x=function(){}; _0x(",
    ];
    for case in cases {
        let _ = recover_string_array(case);
    }
}

#[test]
fn modern_recovery_bounded_on_massive_call_site_count() {
    use disrobe_pass_js_deob::recover_string_array;
    let mut src: String = String::from(
        "function p(){const a=['log','x'];p=function(){return a;};return p();}function d(i,_){i=i-0x0;const a=p();return a[i];}",
    );
    for _ in 0..200_000 {
        src.push_str("d(0x0);");
    }
    let started: std::time::Instant = std::time::Instant::now();
    let _ = recover_string_array(&src);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(20),
        "massive call-site input must stay bounded"
    );
}

#[test]
fn modern_recovery_handles_deeply_nested_function_body() {
    use disrobe_pass_js_deob::recover_string_array;
    let nested: String = "{".repeat(5_000) + &"}".repeat(5_000);
    let src: String = format!("function p(){nested}function d(i){{return p()[i];}}d(0x0);");
    let _ = recover_string_array(&src);
}
