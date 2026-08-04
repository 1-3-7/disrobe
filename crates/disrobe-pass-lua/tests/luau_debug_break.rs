#![allow(clippy::expect_used)]

use disrobe_pass_lua::decompile::decompile_chunk;
use disrobe_pass_lua::reader::common::{LuaChunk, LuaProto};
use disrobe_pass_lua::{DecompiledChunk, Fidelity, LuaDialect};

const LOP_BREAK: u32 = 1;

fn debugger_break_chunk() -> LuaChunk {
    LuaChunk {
        dialect: LuaDialect::Luau,
        version_byte: 6,
        format: 0,
        little_endian: true,
        size_of_int: 4,
        size_of_size_t: 8,
        size_of_instruction: 4,
        size_of_lua_integer: 8,
        size_of_lua_number: 8,
        integral_number: false,
        main: LuaProto {
            source: Some("debugger_break".to_owned()),
            line_defined: 0,
            last_line_defined: 0,
            num_params: 0,
            is_vararg: 0,
            max_stack_size: 2,
            code: vec![LOP_BREAK],
            constants: Vec::new(),
            protos: Vec::new(),
            source_lines: vec![1],
            locals: Vec::new(),
            upvalues: Vec::new(),
        },
    }
}

#[test]
fn debugger_break_is_reported_without_emitting_language_break() {
    let chunk: LuaChunk = debugger_break_chunk();
    let decompiled: DecompiledChunk = decompile_chunk(&chunk).expect("decompile debugger break");

    assert!(
        decompiled
            .source
            .lines()
            .all(|line: &str| line.trim() != "break"),
        "debugger instrumentation must not become a language break:\n{}",
        decompiled.source
    );
    assert_eq!(decompiled.fidelity, Fidelity::BestEffort);
    assert_eq!(
        decompiled.warnings,
        ["unresolved luau debugger breakpoint at pc=0"]
    );
}
