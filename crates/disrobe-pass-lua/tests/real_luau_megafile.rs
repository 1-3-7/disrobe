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

fn load(rel: &str) -> Option<Vec<u8>> {
    let path: PathBuf = corpus_path(rel);
    fs::read(&path).ok()
}

#[test]
fn real_luau_hello_first_byte_is_known_version() {
    let Some(bytes): Option<Vec<u8>> = load("luau/hello.luau") else {
        eprintln!("skip: luau/hello.luau fixture absent");
        return;
    };
    let v: u8 = *bytes.first().expect("non-empty");
    assert!(
        v > 0 && v < 0x20,
        "luau version byte {v:#x} outside plausible range"
    );
}

#[test]
fn real_luau_megafile_first_byte_is_known_version() {
    let Some(bytes): Option<Vec<u8>> = load("luau/edge_cases.luau.bin") else {
        eprintln!("skip: luau/edge_cases.luau.bin fixture absent");
        return;
    };
    let v: u8 = *bytes.first().expect("non-empty");
    assert!(
        v > 0 && v < 0x20,
        "luau version byte {v:#x} outside plausible range"
    );
}

#[test]
fn real_luau_hello_detects() {
    let Some(bytes): Option<Vec<u8>> = load("luau/hello.luau") else {
        eprintln!("skip: luau/hello.luau fixture absent");
        return;
    };
    let kind: DetectedFormat = detect(&bytes);
    assert_eq!(kind, DetectedFormat::Luau);
}

#[test]
fn real_luau_hello_parses() {
    let Some(bytes): Option<Vec<u8>> = load("luau/hello.luau") else {
        eprintln!("skip: luau/hello.luau fixture absent");
        return;
    };
    let chunk: LuaChunk = luau::read(&bytes).expect("parse luau hello");
    assert_eq!(chunk.dialect, LuaDialect::Luau);
}

#[test]
fn real_luau_megafile_detects() {
    let Some(bytes): Option<Vec<u8>> = load("luau/edge_cases.luau.bin") else {
        eprintln!("skip: luau/edge_cases.luau.bin fixture absent");
        return;
    };
    let kind: DetectedFormat = detect(&bytes);
    assert_eq!(kind, DetectedFormat::Luau);
}

#[test]
fn real_luau_megafile_parses() {
    let Some(bytes): Option<Vec<u8>> = load("luau/edge_cases.luau.bin") else {
        eprintln!("skip: luau/edge_cases.luau.bin fixture absent");
        return;
    };
    let chunk: LuaChunk = luau::read(&bytes).expect("parse luau megafile");
    assert_eq!(chunk.dialect, LuaDialect::Luau);
}
