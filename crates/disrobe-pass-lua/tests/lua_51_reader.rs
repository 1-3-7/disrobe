#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_lua::LuaDialect;
use disrobe_pass_lua::reader::common::{LuaChunk, LuaConstant};
use disrobe_pass_lua::reader::{DetectedFormat, detect, lua51};

const LUA51_EMPTY_CHUNK: &[u8] = &[
    0x1B, b'L', b'u', b'a', 0x51, 0x00, 0x01, 0x04, 0x04, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

#[test]
fn detect_lua51_signature() {
    let kind: DetectedFormat = detect(LUA51_EMPTY_CHUNK);
    assert_eq!(kind, DetectedFormat::Lua51);
}

#[test]
fn read_lua51_empty_chunk() {
    let chunk: LuaChunk = lua51::read(LUA51_EMPTY_CHUNK).expect("parse lua51");
    assert_eq!(chunk.dialect, LuaDialect::Lua51);
    assert_eq!(chunk.version_byte, 0x51);
    assert_eq!(chunk.size_of_int, 4);
    assert_eq!(chunk.size_of_size_t, 4);
    assert_eq!(chunk.size_of_instruction, 4);
    assert_eq!(chunk.size_of_lua_number, 8);
    assert!(chunk.main.code.is_empty());
    assert!(chunk.main.constants.is_empty());
}

const LUA51_NON_UTF8_STRING_CONST: &[u8] = &[
    0x1B, 0x4C, 0x75, 0x61, 0x51, 0x00, 0x01, 0x04, 0x04, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[test]
fn lua51_recovers_chunk_with_non_utf8_string_constant() {
    let chunk: LuaChunk = lua51::read(LUA51_NON_UTF8_STRING_CONST)
        .expect("non-utf8 lua string constant must not abort the whole chunk");
    assert_eq!(chunk.dialect, LuaDialect::Lua51);
    assert_eq!(chunk.main.constants.len(), 1);
    let LuaConstant::Str(decoded): &LuaConstant = &chunk.main.constants[0] else {
        panic!(
            "expected a string constant, got {:?}",
            chunk.main.constants[0]
        );
    };
    assert_eq!(decoded, "\u{FFFD}");
}

#[test]
fn lua51_rejects_unsupported_format() {
    let mut bad: Vec<u8> = LUA51_EMPTY_CHUNK.to_vec();
    bad[5] = 0xFF;
    let err: disrobe_pass_lua::Error = lua51::read(&bad).unwrap_err();
    assert!(matches!(
        err,
        disrobe_pass_lua::Error::UnsupportedFormat(0xFF)
    ));
}
