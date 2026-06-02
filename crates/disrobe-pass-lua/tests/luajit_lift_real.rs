#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

use disrobe_pass_lua::decompile::{self, DecompiledChunk};

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
fn luajit_hello_lifts_to_real_lua_source() {
    let Some(bytes): Option<Vec<u8>> = load("luajit/hello.luajit") else {
        eprintln!("skip: luajit/hello.luajit fixture absent");
        return;
    };
    let out: DecompiledChunk = decompile::luajit_lift::decompile(&bytes).expect("lift");
    assert!(
        out.source.contains("luajit 2.x register lifter"),
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
    let Some(bytes): Option<Vec<u8>> = load("luajit/hello.stripped.luajit") else {
        eprintln!("skip: luajit/hello.stripped.luajit fixture absent");
        return;
    };
    let out: DecompiledChunk = decompile::luajit_lift::decompile(&bytes).expect("lift");
    assert!(out.source.contains("print"));
    assert!(out.source.contains("hello world"));
}

#[test]
fn luajit_edge_cases_lift_runs() {
    let Some(bytes): Option<Vec<u8>> = load("luajit/edge_cases.luajit") else {
        eprintln!("skip: luajit/edge_cases.luajit fixture absent");
        return;
    };
    let out: DecompiledChunk = decompile::luajit_lift::decompile(&bytes).expect("lift");
    assert!(out.source.contains("function _main"));
    assert!(out.source.len() > 200, "expected non-trivial source body");
}

#[test]
fn luajit_edge_cases_stripped_lift_runs() {
    let Some(bytes): Option<Vec<u8>> = load("luajit/edge_cases.stripped.luajit") else {
        eprintln!("skip: luajit/edge_cases.stripped.luajit fixture absent");
        return;
    };
    let out: DecompiledChunk = decompile::luajit_lift::decompile(&bytes).expect("lift");
    assert!(out.source.contains("function _main"));
}

#[test]
fn lift_mutation_string_constant_propagates_to_source() {
    let Some(bytes): Option<Vec<u8>> = load("luajit/hello.luajit") else {
        eprintln!("skip: luajit/hello.luajit fixture absent");
        return;
    };
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
