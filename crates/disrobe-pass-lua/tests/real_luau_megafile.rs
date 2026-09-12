#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::PathBuf;

use disrobe_pass_lua::LuaDialect;
use disrobe_pass_lua::reader::common::LuaChunk;
use disrobe_pass_lua::reader::{DetectedFormat, detect, luau};

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
fn real_luau_hello_first_byte_is_known_version() {
    let bytes: Vec<u8> = load("luau/hello.luau");
    let v: u8 = *bytes.first().expect("non-empty");
    assert!(
        v > 0 && v < 0x20,
        "luau version byte {v:#x} outside plausible range"
    );
}

#[test]
fn real_luau_megafile_first_byte_is_known_version() {
    let bytes: Vec<u8> = load("luau/edge_cases.luau.bin");
    let v: u8 = *bytes.first().expect("non-empty");
    assert!(
        v > 0 && v < 0x20,
        "luau version byte {v:#x} outside plausible range"
    );
}

#[test]
fn real_luau_hello_detects() {
    let bytes: Vec<u8> = load("luau/hello.luau");
    let kind: DetectedFormat = detect(&bytes);
    assert_eq!(kind, DetectedFormat::Luau);
}

#[test]
fn real_luau_hello_parses() {
    let bytes: Vec<u8> = load("luau/hello.luau");
    let chunk: LuaChunk = luau::read(&bytes).expect("parse luau hello");
    assert_eq!(chunk.dialect, LuaDialect::Luau);
}

#[test]
fn real_luau_megafile_detects() {
    let bytes: Vec<u8> = load("luau/edge_cases.luau.bin");
    let kind: DetectedFormat = detect(&bytes);
    assert_eq!(kind, DetectedFormat::Luau);
}

#[test]
fn real_luau_megafile_parses() {
    let bytes: Vec<u8> = load("luau/edge_cases.luau.bin");
    let chunk: LuaChunk = luau::read(&bytes).expect("parse luau megafile");
    assert_eq!(chunk.dialect, LuaDialect::Luau);
}
