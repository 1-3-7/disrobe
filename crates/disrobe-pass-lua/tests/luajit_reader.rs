#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_lua::reader::common::LuaChunk;
use disrobe_pass_lua::reader::{DetectedFormat, detect, luajit};
use disrobe_pass_lua::{LuaDialect, decompile};

const LUAJIT_21_EMPTY_STRIPPED: &[u8] = &[
    0x1B, b'L', b'J', 0x02, 0x02, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

const LUAJIT_20_EMPTY_STRIPPED: &[u8] = &[
    0x1B, b'L', b'J', 0x01, 0x02, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[test]
fn detect_luajit_signature() {
    let kind: DetectedFormat = detect(LUAJIT_21_EMPTY_STRIPPED);
    assert_eq!(kind, DetectedFormat::LuaJit);
}

#[test]
fn read_luajit_21_empty_stripped_chunk() {
    let chunk: LuaChunk = luajit::read(LUAJIT_21_EMPTY_STRIPPED).expect("parse luajit 2.1");
    assert_eq!(chunk.dialect, LuaDialect::LuaJit21);
    assert_eq!(chunk.version_byte, 2);
    assert!(chunk.main.code.is_empty());
    assert!(chunk.main.constants.is_empty());
    assert_eq!(chunk.main.num_params, 0);
    assert_eq!(chunk.main.max_stack_size, 0);
}

#[test]
fn read_luajit_20_empty_stripped_chunk() {
    let chunk: LuaChunk = luajit::read(LUAJIT_20_EMPTY_STRIPPED).expect("parse luajit 2.0");
    assert_eq!(chunk.dialect, LuaDialect::LuaJit20);
    assert_eq!(chunk.version_byte, 1);
}

#[test]
fn luajit_rejects_unknown_version() {
    let mut bad: Vec<u8> = LUAJIT_21_EMPTY_STRIPPED.to_vec();
    bad[3] = 0x07;
    let err: disrobe_pass_lua::Error = luajit::read(&bad).unwrap_err();
    assert!(matches!(
        err,
        disrobe_pass_lua::Error::UnsupportedLuaJitVersion(0x07)
    ));
}

#[test]
fn luajit_rejects_wrong_signature() {
    let bad: &[u8] = &[0x1B, b'X', b'X', 0x02];
    let err: disrobe_pass_lua::Error = luajit::read(bad).unwrap_err();
    assert!(matches!(err, disrobe_pass_lua::Error::BadLuaJitSignature));
}

#[test]
fn decompile_luajit_21_stripped_produces_stub() {
    let chunk: LuaChunk = luajit::read(LUAJIT_21_EMPTY_STRIPPED).expect("parse");
    let dec: decompile::DecompiledChunk =
        decompile::luajit21::decompile(&chunk).expect("decompile");
    assert!(dec.source.contains("luajit bytecode disassembly"));
    assert!(dec.source.contains("function _ljp_"));
}
