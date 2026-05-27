#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_lua::decompile::{self, DecompiledChunk, Fidelity};
use disrobe_pass_lua::reader::{common::LuaChunk, luajit};

const LUAJIT_21_EMPTY_STRIPPED: &[u8] = &[
    0x1B, b'L', b'J', 0x02, 0x02, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[test]
fn luajit_21_stripped_decompile_emits_port_banner() {
    let chunk: LuaChunk = luajit::read(LUAJIT_21_EMPTY_STRIPPED).expect("parse");
    let out: DecompiledChunk = decompile::luajit21::decompile(&chunk).expect("decompile");
    assert!(matches!(out.fidelity, Fidelity::BestEffort));
    assert!(out.source.contains("luajit-decompiler-v2"));
    assert!(out.source.contains("function _ljp_"));
}
