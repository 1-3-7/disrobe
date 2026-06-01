#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_lua::LuaDialect;
use disrobe_pass_lua::reader::common::LuaChunk;
use disrobe_pass_lua::reader::{DetectedFormat, detect, luau};

const LUAU_V5_EMPTY: &[u8] = &[
    0x05, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00,
];

#[test]
fn detect_luau_version() {
    let kind: DetectedFormat = detect(LUAU_V5_EMPTY);
    assert_eq!(kind, DetectedFormat::Luau);
}

#[test]
fn read_luau_empty_chunk() {
    let chunk: LuaChunk = luau::read(LUAU_V5_EMPTY).expect("parse luau v5");
    assert_eq!(chunk.dialect, LuaDialect::Luau);
    assert_eq!(chunk.version_byte, 5);
    assert_eq!(chunk.main.num_params, 0);
    assert_eq!(chunk.main.is_vararg, 0);
    assert_eq!(chunk.main.max_stack_size, 0);
    assert!(chunk.main.code.is_empty());
    assert!(chunk.main.constants.is_empty());
}

#[test]
fn luau_rejects_version_zero() {
    let bad: &[u8] = &[0x00];
    let err: disrobe_pass_lua::Error = luau::read(bad).unwrap_err();
    assert!(matches!(err, disrobe_pass_lua::Error::NotLuau));
}

#[test]
fn luau_rejects_unsupported_version() {
    let bad: &[u8] = &[0x12];
    let err: disrobe_pass_lua::Error = luau::read(bad).unwrap_err();
    assert!(matches!(
        err,
        disrobe_pass_lua::Error::UnsupportedLuauVersion(0x12)
    ));
}
