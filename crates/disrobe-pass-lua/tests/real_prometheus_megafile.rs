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
    fs::read(&path).unwrap_or_else(|e| panic!("missing committed fixture {}: {e}", path.display()))
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
fn real_prometheus_hello_peel_reports_honestly() {
    let bytes: Vec<u8> = load("obfuscators/hello.prometheus.lua");
    let opts: DeobfOptions = DeobfOptions::default();
    let out: PeelResult = prometheus::peel(&bytes, &opts).expect("peel prometheus hello");
    assert!(
        !out.fully_recovered,
        "prometheus opcode/CFG stays VM-virtualized; must not claim full recovery"
    );
    assert!(!out.residual_markers.is_empty());
}

const PROMETHEUS_KNOWN_INTRINSICS: &[&str] = &[
    "string",
    "table",
    "math",
    "tonumber",
    "floor",
    "__gc",
    "__len",
    "__metatable",
];

#[test]
fn real_prometheus_hello_static_string_pool_recovers_known_intrinsics() {
    let bytes: Vec<u8> = load("obfuscators/hello.prometheus.lua");
    let opts: DeobfOptions = DeobfOptions::default();
    let out: PeelResult = prometheus::peel(&bytes, &opts).expect("peel prometheus hello");
    assert!(
        out.passes_run
            .iter()
            .any(|p: &String| p == "prometheus-base64-variant-string-decode"),
        "real sample must trigger the static base64 string decoder, passes={:?} residual={:?}",
        out.passes_run,
        out.residual_markers
    );
    let pool: &[String] = &out.recovered_strings;
    let recovered: usize = PROMETHEUS_KNOWN_INTRINSICS
        .iter()
        .filter(|kw: &&&str| pool.iter().any(|s: &String| s == *kw))
        .count();
    assert!(
        recovered >= 6,
        "expected the Prometheus VM intrinsic symbol table decoded from the real sample; recovered {recovered}/{} of {PROMETHEUS_KNOWN_INTRINSICS:?}, pool={pool:?}",
        PROMETHEUS_KNOWN_INTRINSICS.len()
    );
}

#[test]
fn real_prometheus_weak_static_string_pool_recovers_known_intrinsics() {
    let bytes: Vec<u8> = load("obfuscators/edge_cases.prometheus_weak.lua");
    let opts: DeobfOptions = DeobfOptions::default();
    let out: PeelResult = prometheus::peel(&bytes, &opts).expect("peel prometheus weak");
    assert!(
        out.passes_run
            .iter()
            .any(|p: &String| p == "prometheus-base64-variant-string-decode"),
        "weak megafile must trigger the static base64 string decoder, residual={:?}",
        out.residual_markers
    );
    let pool: &[String] = &out.recovered_strings;
    let known: [&str; 4] = ["concat", "error", "pcall", "tonumber"];
    let recovered: usize = known
        .iter()
        .filter(|kw: &&&str| pool.iter().any(|s: &String| s == *kw))
        .count();
    assert!(
        recovered >= 3,
        "expected stdlib intrinsics from the real weak megafile; recovered {recovered}/4 of {known:?}"
    );
}

#[test]
fn real_prometheus_weak_megafile_peel_reports_honestly() {
    let bytes: Vec<u8> = load("obfuscators/edge_cases.prometheus_weak.lua");
    let opts: DeobfOptions = DeobfOptions::default();
    let out: PeelResult = prometheus::peel(&bytes, &opts).expect("peel prometheus weak megafile");
    assert!(!out.fully_recovered);
    assert!(!out.residual_markers.is_empty());
}

const PROMETHEUS_BASE85_ONLY_INTRINSICS_HELLO: &[&str] = &[
    "print",
    "char",
    "byte",
    "concat",
    "gsub",
    "gmatch",
    "setmetatable",
    "pcall",
    "tostring",
    "unpack",
    "random",
    "remove",
    "error",
];

#[test]
fn real_prometheus_hello_base85_constant_array_decodes_correctly() {
    let bytes: Vec<u8> = load("obfuscators/hello.prometheus.lua");
    let opts: DeobfOptions = DeobfOptions::default();
    let out: PeelResult = prometheus::peel(&bytes, &opts).expect("peel prometheus hello");
    assert!(
        out.passes_run
            .iter()
            .any(|p: &String| p == "prometheus-base85-variant-string-decode"),
        "the real ConstantArray mixed encoding must trigger the base85 decoder, passes={:?}",
        out.passes_run
    );
    let pool: &[String] = &out.recovered_strings;
    let missing: Vec<&&str> = PROMETHEUS_BASE85_ONLY_INTRINSICS_HELLO
        .iter()
        .filter(|kw: &&&str| !pool.iter().any(|s: &String| s == **kw))
        .collect();
    assert!(
        missing.is_empty(),
        "every base85-encoded Lua intrinsic must decode to its exact name; missing {missing:?} from pool={pool:?}"
    );
}

const PROMETHEUS_BASE85_ONLY_INTRINSICS_WEAK: &[&str] = &[
    "print",
    "char",
    "byte",
    "math",
    "string",
    "table",
    "floor",
    "getfenv",
    "ipairs",
    "select",
    "sub",
    "insert",
    "pack",
    "setmetatable",
    "tostring",
    "unpack",
    "random",
    "remove",
];

#[test]
fn real_prometheus_weak_base85_constant_array_decodes_correctly() {
    let bytes: Vec<u8> = load("obfuscators/edge_cases.prometheus_weak.lua");
    let opts: DeobfOptions = DeobfOptions::default();
    let out: PeelResult = prometheus::peel(&bytes, &opts).expect("peel prometheus weak megafile");
    assert!(
        out.passes_run
            .iter()
            .any(|p: &String| p == "prometheus-base85-variant-string-decode"),
        "the weak megafile ConstantArray must trigger the base85 decoder, passes={:?}",
        out.passes_run
    );
    let pool: &[String] = &out.recovered_strings;
    let missing: Vec<&&str> = PROMETHEUS_BASE85_ONLY_INTRINSICS_WEAK
        .iter()
        .filter(|kw: &&&str| !pool.iter().any(|s: &String| s == **kw))
        .collect();
    assert!(
        missing.is_empty(),
        "every base85-encoded Lua intrinsic must decode to its exact name; missing {missing:?}"
    );
    let source_symbols: [&str; 6] = [
        "simple_literals",
        "to_array",
        "shallow_eq",
        "is_prime",
        "range_gen",
        "reduce",
    ];
    let recovered_src: usize = source_symbols
        .iter()
        .filter(|kw: &&&str| pool.iter().any(|s: &String| s == **kw))
        .count();
    assert!(
        recovered_src >= 5,
        "the original program's own identifiers must come back from the constant array; recovered {recovered_src}/6 of {source_symbols:?}"
    );
}
