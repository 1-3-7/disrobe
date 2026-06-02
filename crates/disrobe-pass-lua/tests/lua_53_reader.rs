#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_lua::LuaDialect;
use disrobe_pass_lua::reader::common::LuaChunk;
use disrobe_pass_lua::reader::{DetectedFormat, detect, lua53};

const LUA53_EMPTY_CHUNK: &[u8] = &[
    0x1B, b'L', b'u', b'a', 0x53, 0x00, 0x19, 0x93, b'\r', b'\n', 0x1A, b'\n', 0x04, 0x04, 0x04,
    0x08, 0x08, 0x78, 0x56, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28,
    0x77, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[test]
fn detect_lua53_signature() {
    let kind: DetectedFormat = detect(LUA53_EMPTY_CHUNK);
    assert_eq!(kind, DetectedFormat::Lua53);
}

#[test]
fn read_lua53_empty_chunk() {
    let chunk: LuaChunk = lua53::read(LUA53_EMPTY_CHUNK).expect("parse lua53");
    assert_eq!(chunk.dialect, LuaDialect::Lua53);
    assert_eq!(chunk.version_byte, 0x53);
    assert_eq!(chunk.size_of_lua_integer, 8);
    assert!(chunk.main.code.is_empty());
}

#[test]
fn lua53_integer_subtype_supported() {
    let mut bytes: Vec<u8> = LUA53_EMPTY_CHUNK.to_vec();
    let const_count_off: usize = 12 + 5 + 8 + 8 + 1 + 1 + 4 + 4 + 3 + 4;
    bytes[const_count_off..const_count_off + 4].copy_from_slice(&1u32.to_le_bytes());
    bytes.insert(const_count_off + 4, 0x13);
    let int_bytes: [u8; 8] = 42i64.to_le_bytes();
    for (i, b) in int_bytes.iter().enumerate() {
        bytes.insert(const_count_off + 5 + i, *b);
    }
    let chunk: LuaChunk = lua53::read(&bytes).expect("parse with integer constant");
    assert_eq!(chunk.main.constants.len(), 1);
    assert!(matches!(
        chunk.main.constants[0],
        disrobe_pass_lua::LuaConstant::Integer(42)
    ));
}
