#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_lua::decompile::{self, DecompiledChunk, Fidelity};
use disrobe_pass_lua::reader::{common::LuaChunk, lua51};

const LUA51_EMPTY_CHUNK: &[u8] = &[
    0x1B, b'L', b'u', b'a', 0x51, 0x00, 0x01, 0x04, 0x04, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

#[test]
fn lua51_decompile_empty_produces_function_skeleton() {
    let chunk: LuaChunk = lua51::read(LUA51_EMPTY_CHUNK).expect("parse");
    let out: DecompiledChunk = decompile::lua51::decompile(&chunk).expect("decompile");
    assert!(matches!(
        out.fidelity,
        Fidelity::Lossless | Fidelity::Lossy | Fidelity::BestEffort
    ));
    assert!(out.source.contains("function _main"));
    assert!(out.source.contains("end"));
}
