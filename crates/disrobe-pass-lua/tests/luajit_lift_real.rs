#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::PathBuf;

use disrobe_pass_lua::decompile::{self, DecompiledChunk};
use disrobe_pass_lua::{DetectedFormat, decompile_auto, detect};

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
fn luajit_hello_lifts_to_real_lua_source() {
    let bytes: Vec<u8> = load("luajit/hello.luajit");
    let out: DecompiledChunk = decompile::luajit_lift::decompile(&bytes).expect("lift");
    assert!(
        out.source.contains("luajit 2.1 register lifter"),
        "banner missing: {}",
        out.source
    );
    assert!(
        out.source.contains("print"),
        "expected print global reference, got: {}",
        out.source
    );
    assert!(
        out.source.contains("hello world"),
        "expected hello world literal, got: {}",
        out.source
    );
    assert!(
        out.source.contains("function _main"),
        "expected _main wrapper, got: {}",
        out.source
    );
}

#[test]
fn luajit_hello_stripped_lifts() {
    let bytes: Vec<u8> = load("luajit/hello.stripped.luajit");
    let out: DecompiledChunk = decompile::luajit_lift::decompile(&bytes).expect("lift");
    assert!(out.source.contains("print"));
    assert!(out.source.contains("hello world"));
}

#[test]
fn decompile_auto_routes_luajit_to_real_lifter() {
    let bytes: Vec<u8> = load("luajit/hello.luajit");
    assert_eq!(detect(&bytes), DetectedFormat::LuaJit);
    let out: DecompiledChunk = decompile_auto(&bytes).expect("auto run path lifts luajit");
    assert!(
        out.source.contains("luajit 2.1 register lifter"),
        "run path must reach the real luajit lifter, not the metadata skeleton: {}",
        out.source
    );
    assert!(
        !out.source
            .contains("register lifter for this dialect not yet implemented"),
        "run path must not fall back to the metadata-only skeleton: {}",
        out.source
    );
    assert!(
        out.source.contains("print") && out.source.contains("hello world"),
        "structural recovery of the known `print(\"hello world\")` source failed: {}",
        out.source
    );
}

#[test]
fn decompile_auto_luajit_stripped_recovers_known_source() {
    let bytes: Vec<u8> = load("luajit/hello.stripped.luajit");
    assert_eq!(detect(&bytes), DetectedFormat::LuaJit);
    let out: DecompiledChunk = decompile_auto(&bytes).expect("auto run path lifts stripped luajit");
    assert!(out.source.contains("print"));
    assert!(out.source.contains("hello world"));
}

#[test]
fn decompile_auto_luajit_edge_cases_lifts_nontrivial_body() {
    let bytes: Vec<u8> = load("luajit/edge_cases.luajit");
    let out: DecompiledChunk = decompile_auto(&bytes).expect("auto run path lifts edge_cases");
    assert!(out.source.contains("function _main"));
    assert!(
        out.source.len() > 1000,
        "edge_cases body should lift to a substantial source listing, got {} bytes",
        out.source.len()
    );
    let known_globals: bool = ["print", "string", "table", "math", "pairs", "ipairs"]
        .iter()
        .any(|g: &&str| out.source.contains(*g));
    assert!(
        known_globals,
        "expected at least one recovered stdlib global reference from the real megafile"
    );
}

#[test]
fn luajit_edge_cases_lift_runs() {
    let bytes: Vec<u8> = load("luajit/edge_cases.luajit");
    let out: DecompiledChunk = decompile::luajit_lift::decompile(&bytes).expect("lift");
    assert!(out.source.contains("function _main"));
    assert!(out.source.len() > 200, "expected non-trivial source body");
}

#[test]
fn luajit_edge_cases_stripped_lift_runs() {
    let bytes: Vec<u8> = load("luajit/edge_cases.stripped.luajit");
    let out: DecompiledChunk = decompile::luajit_lift::decompile(&bytes).expect("lift");
    assert!(out.source.contains("function _main"));
}

#[test]
fn lift_mutation_string_constant_propagates_to_source() {
    let bytes: Vec<u8> = load("luajit/hello.luajit");
    let needle: &[u8] = b"hello world";
    let pos: usize = bytes
        .windows(needle.len())
        .position(|w: &[u8]| w == needle)
        .expect("hello world constant present in raw luajit chunk");
    let original: DecompiledChunk = decompile::luajit_lift::decompile(&bytes).expect("orig lift");
    assert!(
        original.source.contains("hello world"),
        "baseline missing constant: {}",
        original.source
    );

    let mut mutated: Vec<u8> = bytes;
    mutated[pos] = b'H';
    mutated[pos + 6] = b'W';
    let modified: DecompiledChunk =
        decompile::luajit_lift::decompile(&mutated).expect("mutated lift");
    assert!(
        modified.source.contains("Hello World"),
        "mutated constant not surfaced: {}",
        modified.source
    );
    assert!(
        !modified.source.contains("hello world"),
        "stale constant still present after mutation: {}",
        modified.source
    );
}
