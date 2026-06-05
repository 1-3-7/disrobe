#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_lua::LuaDialect;
use disrobe_pass_lua::reader::common::LuaChunk;
use disrobe_pass_lua::reader::{DetectedFormat, detect, lua52};

const LUA52_EMPTY_CHUNK: &[u8] = &[
    0x1B, b'L', b'u', b'a', 0x52, 0x00, 0x01, 0x04, 0x04, 0x04, 0x08, 0x00, 0x19, 0x93, b'\r',
    b'\n', 0x1A, b'\n', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[test]
fn detect_lua52_signature() {
    let kind: DetectedFormat = detect(LUA52_EMPTY_CHUNK);
    assert_eq!(kind, DetectedFormat::Lua52);
}

#[test]
fn read_lua52_empty_chunk() {
    let chunk: LuaChunk = lua52::read(LUA52_EMPTY_CHUNK).expect("parse lua52");
    assert_eq!(chunk.dialect, LuaDialect::Lua52);
    assert_eq!(chunk.version_byte, 0x52);
}

#[test]
fn lua52_rejects_truncated_tail() {
    let mut bad: Vec<u8> = LUA52_EMPTY_CHUNK.to_vec();
    bad[12] = 0xFF;
    let err: disrobe_pass_lua::Error = lua52::read(&bad).unwrap_err();
    assert!(matches!(err, disrobe_pass_lua::Error::BadLuacData(_)));
}
