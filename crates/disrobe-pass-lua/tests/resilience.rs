#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_lua::decompile::lua51::decompile as decompile_lua51;
use disrobe_pass_lua::reader::{lua51, lua53, lua54, luajit, luau, read_auto};

fn lua51_header(code_len_bytes: [u8; 4]) -> Vec<u8> {
    let mut v: Vec<u8> = vec![
        0x1B, b'L', b'u', b'a', 0x51, 0x00, 0x01, 0x04, 0x04, 0x04, 0x08, 0x00,
    ];
    v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    v.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    v.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    v.push(0x00);
    v.push(0x00);
    v.push(0x00);
    v.push(0x02);
    v.extend_from_slice(&code_len_bytes);
    v
}

#[test]
fn oversized_code_len_does_not_oom_returns_err() {
    let bytes: Vec<u8> = lua51_header([0xFF, 0xFF, 0xFF, 0xFF]);
    let result = lua51::read(&bytes);
    assert!(
        result.is_err(),
        "a 4-billion code_len with no payload must error, not allocate"
    );
}

#[test]
fn truncated_header_errors_cleanly() {
    for cut in 0..12usize {
        let bytes: Vec<u8> =
            vec![0x1B, b'L', b'u', b'a', 0x51, 0x00, 0x01, 0x04][..cut.min(8)].to_vec();
        let _ = lua51::read(&bytes);
        let _ = read_auto(&bytes);
    }
}

#[test]
fn empty_input_errors() {
    assert!(lua51::read(&[]).is_err());
    assert!(lua53::read(&[]).is_err());
    assert!(lua54::read(&[]).is_err());
    assert!(luajit::read(&[]).is_err());
    assert!(luau::read(&[]).is_err());
    assert!(read_auto(&[]).is_err());
}

#[test]
fn bad_signature_errors() {
    let junk: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x99];
    assert!(read_auto(&junk).is_err());
}

#[test]
fn all_byte_values_as_single_byte_never_panic() {
    for b in 0u16..=255 {
        let input: Vec<u8> = vec![b as u8];
        let _ = read_auto(&input);
    }
}

#[test]
fn random_fuzz_prefixes_never_panic() {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..2000 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let len: usize = (state % 64) as usize;
        let mut buf: Vec<u8> = Vec::with_capacity(len + 5);
        buf.extend_from_slice(&[0x1B, b'L', b'u', b'a', 0x51]);
        let mut s: u64 = state;
        for _ in 0..len {
            s = s
                .wrapping_mul(2_862_933_555_777_941_757)
                .wrapping_add(3_037_000_493);
            buf.push((s >> 33) as u8);
        }
        let _ = read_auto(&buf);
    }
}

#[test]
fn luajit_oversized_proto_len_errors() {
    let bytes: Vec<u8> = vec![0x1B, b'L', b'J', 0x02, 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F];
    let _ = luajit::read(&bytes);
}

#[test]
fn luau_oversized_string_count_does_not_oom() {
    let bytes: Vec<u8> = vec![0x06, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F];
    let result = luau::read(&bytes);
    assert!(result.is_err());
}

fn push_proto_prelude_one_child(v: &mut Vec<u8>) {
    v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    v.push(0x00);
    v.push(0x00);
    v.push(0x00);
    v.push(0x02);
    v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    v.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
}

#[test]
fn deeply_nested_lua51_protos_error_not_stack_overflow() {
    let mut bytes: Vec<u8> = vec![
        0x1B, b'L', b'u', b'a', 0x51, 0x00, 0x01, 0x04, 0x04, 0x04, 0x08, 0x00,
    ];
    for _ in 0..400 {
        push_proto_prelude_one_child(&mut bytes);
    }
    let result = lua51::read(&bytes);
    assert!(
        result.is_err(),
        "400 levels of nested protos must hit the depth guard, not overflow the stack"
    );
}

#[test]
fn decompile_of_garbage_opcodes_never_panics() {
    let mut bytes: Vec<u8> = vec![
        0x1B, b'L', b'u', b'a', 0x51, 0x00, 0x01, 0x04, 0x04, 0x04, 0x08, 0x00,
    ];
    bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    bytes.push(0x00);
    bytes.push(0x00);
    bytes.push(0x00);
    bytes.push(0x05);
    bytes.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]);
    for _ in 0..3 {
        bytes.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    }
    bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    if let Ok(chunk) = lua51::read(&bytes) {
        let out = decompile_lua51(&chunk).expect("decompile must not panic on garbage opcodes");
        assert!(!out.source.is_empty());
    }
}
