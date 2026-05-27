#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

use disrobe_pass_lua::reader::common::LuaChunk;
use disrobe_pass_lua::reader::{DetectedFormat, detect, luajit};
use disrobe_pass_lua::{LuaDialect, decompile};

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
fn real_luajit_hello_detects_and_parses() {
    let bytes: Vec<u8> = load("luajit/hello.luajit");
    let kind: DetectedFormat = detect(&bytes);
    assert_eq!(kind, DetectedFormat::LuaJit);
    let chunk: LuaChunk = luajit::read(&bytes).expect("parse luajit hello");
    assert_eq!(chunk.dialect, LuaDialect::LuaJit21);
}

#[test]
fn real_luajit_hello_stripped_detects_and_parses() {
    let bytes: Vec<u8> = load("luajit/hello.stripped.luajit");
    let kind: DetectedFormat = detect(&bytes);
    assert_eq!(kind, DetectedFormat::LuaJit);
    let chunk: LuaChunk = luajit::read(&bytes).expect("parse luajit stripped hello");
    assert_eq!(chunk.dialect, LuaDialect::LuaJit21);
}

#[test]
fn real_luajit_megafile_detects() {
    let bytes: Vec<u8> = load("luajit/edge_cases.luajit");
    let kind: DetectedFormat = detect(&bytes);
    assert_eq!(kind, DetectedFormat::LuaJit);
}

#[test]
fn real_luajit_megafile_stripped_detects() {
    let bytes: Vec<u8> = load("luajit/edge_cases.stripped.luajit");
    let kind: DetectedFormat = detect(&bytes);
    assert_eq!(kind, DetectedFormat::LuaJit);
}

#[test]
fn real_luajit_megafile_parses() {
    let bytes: Vec<u8> = load("luajit/edge_cases.luajit");
    let chunk: LuaChunk = luajit::read(&bytes).expect("parse luajit megafile");
    assert_eq!(chunk.dialect, LuaDialect::LuaJit21);
}

#[test]
fn real_luajit_megafile_stripped_parses() {
    let bytes: Vec<u8> = load("luajit/edge_cases.stripped.luajit");
    let chunk: LuaChunk = luajit::read(&bytes).expect("parse luajit stripped megafile");
    assert_eq!(chunk.dialect, LuaDialect::LuaJit21);
}

#[test]
fn real_luajit_megafile_decompile_stub_runs() {
    let bytes: Vec<u8> = load("luajit/edge_cases.luajit");
    let chunk: LuaChunk = luajit::read(&bytes).expect("parse");
    let dec: decompile::DecompiledChunk =
        decompile::luajit21::decompile(&chunk).expect("decompile");
    assert!(dec.source.contains("luajit-decompiler-v2"));
}
