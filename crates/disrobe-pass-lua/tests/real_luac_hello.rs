#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::PathBuf;

use disrobe_pass_lua::LuaDialect;
use disrobe_pass_lua::reader::common::{LuaChunk, LuaConstant};
use disrobe_pass_lua::reader::{DetectedFormat, detect, lua51, lua52, lua53, lua54, read_auto};

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
fn real_lua_5_1_hello_detects_and_parses() {
    let bytes: Vec<u8> = load("luac/hello.5_1.luac")
        .unwrap_or_else(|| panic!("fixture must be tracked: luac/hello.5_1.luac"));
    let kind: DetectedFormat = detect(&bytes);
    assert_eq!(kind, DetectedFormat::Lua51);
    let chunk: LuaChunk = lua51::read(&bytes).expect("parse 5.1 luac");
    assert_eq!(chunk.dialect, LuaDialect::Lua51);
    assert_eq!(chunk.version_byte, 0x51);
    let has_hello_world: bool = chunk
        .main
        .constants
        .iter()
        .any(|c: &LuaConstant| matches!(c, LuaConstant::Str(s) if s == "hello world"));
    assert!(
        has_hello_world,
        "expected 'hello world' literal in 5.1 constants"
    );
}

#[test]
fn real_lua_5_2_hello_detects() {
    let bytes: Vec<u8> = load("luac/hello.5_2.luac")
        .unwrap_or_else(|| panic!("fixture must be tracked: luac/hello.5_2.luac"));
    let kind: DetectedFormat = detect(&bytes);
    assert_eq!(kind, DetectedFormat::Lua52);
}

#[test]
fn real_lua_5_2_hello_parses() {
    let bytes: Vec<u8> = load("luac/hello.5_2.luac")
        .unwrap_or_else(|| panic!("fixture must be tracked: luac/hello.5_2.luac"));
    let chunk: LuaChunk = lua52::read(&bytes).expect("parse 5.2 luac");
    assert_eq!(chunk.dialect, LuaDialect::Lua52);
    assert_eq!(chunk.version_byte, 0x52);
}

#[test]
fn real_lua_5_3_hello_detects_and_parses() {
    let bytes: Vec<u8> = load("luac/hello.5_3.luac")
        .unwrap_or_else(|| panic!("fixture must be tracked: luac/hello.5_3.luac"));
    let kind: DetectedFormat = detect(&bytes);
    assert_eq!(kind, DetectedFormat::Lua53);
    let chunk: LuaChunk = lua53::read(&bytes).expect("parse 5.3 luac");
    assert_eq!(chunk.dialect, LuaDialect::Lua53);
    assert_eq!(chunk.version_byte, 0x53);
}

#[test]
fn real_lua_5_4_hello_detects_and_parses() {
    let bytes: Vec<u8> = load("luac/hello.5_4.luac")
        .unwrap_or_else(|| panic!("fixture must be tracked: luac/hello.5_4.luac"));
    let kind: DetectedFormat = detect(&bytes);
    assert_eq!(kind, DetectedFormat::Lua54);
    let chunk: LuaChunk = lua54::read(&bytes).expect("parse 5.4 luac");
    assert_eq!(chunk.dialect, LuaDialect::Lua54);
    assert_eq!(chunk.version_byte, 0x54);
}

#[test]
fn real_lua_hello_round_trip_via_read_auto() {
    for rel in [
        "luac/hello.5_1.luac",
        "luac/hello.5_3.luac",
        "luac/hello.5_4.luac",
    ] {
        let bytes: Vec<u8> = load(rel).unwrap_or_else(|| panic!("fixture must be tracked: {rel}"));
        let chunk: LuaChunk = read_auto(&bytes)
            .unwrap_or_else(|e: disrobe_pass_lua::Error| panic!("read_auto({rel}) failed: {e}"));
        assert!(matches!(
            chunk.dialect,
            LuaDialect::Lua51 | LuaDialect::Lua53 | LuaDialect::Lua54
        ));
    }
}
