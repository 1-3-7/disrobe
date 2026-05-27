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

fn load(rel: &str) -> Vec<u8> {
    let path: PathBuf = corpus_path(rel);
    fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!("failed to read corpus fixture {}: {e}", path.display())
    })
}

#[test]
fn real_prometheus_hello_has_expected_shape() {
    let bytes: Vec<u8> = load("obfuscators/hello.prometheus.lua");
    let head: &[u8] = &bytes[..bytes.len().min(64)];
    let head_str: &str = std::str::from_utf8(head).expect("utf8 head");
    assert!(
        head_str.starts_with("return(function") || head_str.contains("ipairs"),
        "expected Prometheus return(function...ipairs shape, got: {head_str:?}"
    );
}

#[test]
fn real_prometheus_minify_has_expected_shape() {
    let bytes: Vec<u8> = load("obfuscators/edge_cases.prometheus_minify.lua");
    assert!(
        bytes.len() > 1000,
        "prometheus minify output should be >1 KB"
    );
}

#[test]
fn real_prometheus_weak_has_expected_shape() {
    let bytes: Vec<u8> = load("obfuscators/edge_cases.prometheus_weak.lua");
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
    let bytes: Vec<u8> = load("obfuscators/hello.prometheus.lua");
    let det: ObfuscatorDetection = prometheus::detect(&bytes).expect("detect prometheus");
    assert_eq!(det.kind, LuaObfuscatorKind::Prometheus);
    assert!(det.confidence >= 50);
}

#[test]
fn real_prometheus_minify_megafile_detects() {
    let bytes: Vec<u8> = load("obfuscators/edge_cases.prometheus_minify.lua");
    let det: ObfuscatorDetection = prometheus::detect(&bytes).expect("detect prometheus minify");
    assert_eq!(det.kind, LuaObfuscatorKind::Prometheus);
}

#[test]
fn real_prometheus_weak_megafile_detects() {
    let bytes: Vec<u8> = load("obfuscators/edge_cases.prometheus_weak.lua");
    let det: ObfuscatorDetection = prometheus::detect(&bytes).expect("detect prometheus weak");
    assert_eq!(det.kind, LuaObfuscatorKind::Prometheus);
}

#[test]
fn real_prometheus_hello_peel_runs_passes() {
    let bytes: Vec<u8> = load("obfuscators/hello.prometheus.lua");
    let opts: DeobfOptions = DeobfOptions::default();
    let out: PeelResult = prometheus::peel(&bytes, &opts).expect("peel prometheus hello");
    assert!(
        !out.passes_run.is_empty(),
        "prometheus peel should run at least one pass"
    );
}

#[test]
fn real_prometheus_weak_megafile_peel_runs_passes() {
    let bytes: Vec<u8> = load("obfuscators/edge_cases.prometheus_weak.lua");
    let opts: DeobfOptions = DeobfOptions::default();
    let out: PeelResult = prometheus::peel(&bytes, &opts).expect("peel prometheus weak megafile");
    assert!(
        !out.passes_run.is_empty(),
        "prometheus peel should run at least one pass"
    );
}
