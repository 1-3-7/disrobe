#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_lua::reader::common::LuaChunk;
use disrobe_pass_lua::reader::{DetectedFormat, detect, lua54};
use disrobe_pass_lua::{LuaDialect, decompile};

const LUA54_EMPTY_CHUNK: &[u8] = &[
    0x1B, b'L', b'u', b'a', 0x54, 0x00, 0x19, 0x93, b'\r', b'\n', 0x1A, b'\n', 0x04, 0x08, 0x08,
    0x78, 0x56, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x77, 0x40,
    0x00, 0x80, 0x80, 0x80, 0x00, 0x00, 0x00, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
];

#[test]
fn detect_lua54_signature() {
    let kind: DetectedFormat = detect(LUA54_EMPTY_CHUNK);
    assert_eq!(kind, DetectedFormat::Lua54);
}

#[test]
fn read_lua54_empty_chunk() {
    let chunk: LuaChunk = lua54::read(LUA54_EMPTY_CHUNK).expect("must parse minimal lua54 chunk");
    assert_eq!(chunk.dialect, LuaDialect::Lua54);
    assert_eq!(chunk.version_byte, 0x54);
    assert_eq!(chunk.format, 0);
    assert!(chunk.little_endian);
    assert_eq!(chunk.size_of_instruction, 4);
    assert_eq!(chunk.size_of_lua_integer, 8);
    assert_eq!(chunk.size_of_lua_number, 8);
    assert_eq!(chunk.main.num_params, 0);
    assert_eq!(chunk.main.is_vararg, 0);
    assert_eq!(chunk.main.max_stack_size, 0);
    assert!(chunk.main.code.is_empty());
    assert!(chunk.main.constants.is_empty());
    assert!(chunk.main.protos.is_empty());
}

#[test]
fn decompile_lua54_empty_chunk_returns_empty_body() {
    let chunk: LuaChunk = lua54::read(LUA54_EMPTY_CHUNK).expect("parse");
    let dec: decompile::DecompiledChunk =
        decompile::lua51::decompile(&chunk).expect("decompile pipeline tolerant of lua54 metadata");
    assert!(dec.source.contains("function _proto_0"));
    assert!(dec.source.contains("return"));
}

#[test]
fn lua54_rejects_bad_signature() {
    let bad: &[u8] = &[0x1B, b'X', b'X', b'X', 0x54];
    let err: disrobe_pass_lua::Error = lua54::read(bad).unwrap_err();
    assert!(matches!(err, disrobe_pass_lua::Error::BadSignature));
}

#[test]
fn lua54_rejects_wrong_version() {
    let mut bad: Vec<u8> = LUA54_EMPTY_CHUNK.to_vec();
    bad[4] = 0x52;
    let err: disrobe_pass_lua::Error = lua54::read(&bad).unwrap_err();
    assert!(matches!(
        err,
        disrobe_pass_lua::Error::UnsupportedLuaVersion(0x52)
    ));
}
