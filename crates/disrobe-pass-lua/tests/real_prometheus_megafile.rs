#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

use disrobe_pass_lua::obfuscator::{
    DeobfOptions, LuaObfuscatorKind, ObfuscatorDetection, PeelResult,
};
use disrobe_pass_lua::prometheus;

fn corpus_path(rel: &str) -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    let mut p: PathBuf = PathBuf::from(manifest_dir);
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push("lua");
    for seg in rel.split('/') {
        p.push(seg);
    }
    p
}

fn load(rel: &str) -> Option<Vec<u8>> {
    let path: PathBuf = corpus_path(rel);
    fs::read(&path).ok()
}

#[test]
fn real_prometheus_hello_has_expected_shape() {
    let Some(bytes): Option<Vec<u8>> = load("obfuscators/hello.prometheus.lua") else {
        eprintln!("skip: obfuscators/hello.prometheus.lua fixture absent");
        return;
    };
    let head: &[u8] = &bytes[..bytes.len().min(64)];
    let head_str: &str = std::str::from_utf8(head).expect("utf8 head");
    assert!(
        head_str.starts_with("return(function") || head_str.contains("ipairs"),
        "expected Prometheus return(function...ipairs shape, got: {head_str:?}"
    );
}

#[test]
fn real_prometheus_minify_has_expected_shape() {
    let Some(bytes): Option<Vec<u8>> = load("obfuscators/edge_cases.prometheus_minify.lua") else {
        eprintln!("skip: obfuscators/edge_cases.prometheus_minify.lua fixture absent");
        return;
    };
    assert!(
        bytes.len() > 1000,
        "prometheus minify output should be >1 KB"
    );
}

#[test]
fn real_prometheus_weak_has_expected_shape() {
    let Some(bytes): Option<Vec<u8>> = load("obfuscators/edge_cases.prometheus_weak.lua") else {
        eprintln!("skip: obfuscators/edge_cases.prometheus_weak.lua fixture absent");
        return;
    };
    let head: &[u8] = &bytes[..bytes.len().min(64)];
    let head_str: &str = std::str::from_utf8(head).expect("utf8 head");
    assert!(
        head_str.starts_with("return(function") || head_str.contains("ipairs"),
        "expected Prometheus return(function...ipairs shape"
    );
    assert!(
        bytes.len() > 10_000,
        "prometheus weak megafile should be >10 KB"
    );
}

#[test]
fn real_prometheus_hello_detects() {
    let Some(bytes): Option<Vec<u8>> = load("obfuscators/hello.prometheus.lua") else {
        eprintln!("skip: obfuscators/hello.prometheus.lua fixture absent");
        return;
    };
    let det: ObfuscatorDetection = prometheus::detect(&bytes).expect("detect prometheus");
    assert_eq!(det.kind, LuaObfuscatorKind::Prometheus);
    assert!(det.confidence >= 50);
}

#[test]
fn real_prometheus_minify_megafile_detects() {
    let Some(bytes): Option<Vec<u8>> = load("obfuscators/edge_cases.prometheus_minify.lua") else {
        eprintln!("skip: obfuscators/edge_cases.prometheus_minify.lua fixture absent");
        return;
    };
    let det: ObfuscatorDetection = prometheus::detect(&bytes).expect("detect prometheus minify");
    assert_eq!(det.kind, LuaObfuscatorKind::Prometheus);
}

#[test]
fn real_prometheus_weak_megafile_detects() {
    let Some(bytes): Option<Vec<u8>> = load("obfuscators/edge_cases.prometheus_weak.lua") else {
        eprintln!("skip: obfuscators/edge_cases.prometheus_weak.lua fixture absent");
        return;
    };
    let det: ObfuscatorDetection = prometheus::detect(&bytes).expect("detect prometheus weak");
    assert_eq!(det.kind, LuaObfuscatorKind::Prometheus);
}

#[test]
fn real_prometheus_hello_peel_reports_honestly() {
    let Some(bytes): Option<Vec<u8>> = load("obfuscators/hello.prometheus.lua") else {
        eprintln!("skip: obfuscators/hello.prometheus.lua fixture absent");
        return;
    };
    let opts: DeobfOptions = DeobfOptions::default();
    let out: PeelResult = prometheus::peel(&bytes, &opts).expect("peel prometheus hello");
    assert!(
        !out.fully_recovered,
        "prometheus static peel not implemented; must not claim recovery"
    );
    assert!(!out.residual_markers.is_empty());
}

#[test]
fn real_prometheus_weak_megafile_peel_reports_honestly() {
    let Some(bytes): Option<Vec<u8>> = load("obfuscators/edge_cases.prometheus_weak.lua") else {
        eprintln!("skip: obfuscators/edge_cases.prometheus_weak.lua fixture absent");
        return;
    };
    let opts: DeobfOptions = DeobfOptions::default();
    let out: PeelResult = prometheus::peel(&bytes, &opts).expect("peel prometheus weak megafile");
    assert!(!out.fully_recovered);
    assert!(!out.residual_markers.is_empty());
}
