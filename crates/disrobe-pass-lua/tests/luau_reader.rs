#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_lua::LuaDialect;
use disrobe_pass_lua::reader::common::LuaChunk;
use disrobe_pass_lua::reader::{DetectedFormat, detect, luau};

const LUAU_V5_EMPTY: &[u8] = &[
    0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
];

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte: u8 = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

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

#[test]
fn luau_rejects_out_of_range_main_proto_id() {
    let mut bad: Vec<u8> = LUAU_V5_EMPTY.to_vec();
    let main_id: &mut u8 = bad.last_mut().expect("main id byte");
    *main_id = 1;
    let err: disrobe_pass_lua::Error = luau::read(&bad).expect_err("main proto id");
    assert!(matches!(
        err,
        disrobe_pass_lua::Error::LuauMainProtoOutOfRange { index: 1, count: 1 }
    ));
}

#[test]
fn luau_rejects_declared_constants_past_proto_body() {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.push(0x05);
    bytes.push(0x01);
    write_varint(&mut bytes, 0);
    write_varint(&mut bytes, 1);
    bytes.extend_from_slice(&[0, 0, 0, 0, 0]);
    write_varint(&mut bytes, 0);
    write_varint(&mut bytes, 0);
    write_varint(&mut bytes, 10);
    bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    write_varint(&mut bytes, 0);
    let err: disrobe_pass_lua::Error = luau::read(&bytes).expect_err("constant count");
    match err {
        disrobe_pass_lua::Error::LimitExceeded { section, count, .. } => {
            assert_eq!(section, "luau constant");
            assert_eq!(count, 10);
        }
        other => panic!("expected luau constant limit, got {other:?}"),
    }
}
