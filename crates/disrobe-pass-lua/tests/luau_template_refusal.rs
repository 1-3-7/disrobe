#![allow(clippy::panic)]

use std::sync::Arc;

use disrobe_pass_lua::decompile::decompile_chunk;
use disrobe_pass_lua::error::Error;
use disrobe_pass_lua::reader::common::{LuaChunk, LuaConstant, LuaDialect, LuaProto};

fn chunk(code: Vec<u32>, constant: LuaConstant) -> LuaChunk {
    LuaChunk {
        dialect: LuaDialect::Luau,
        version_byte: 11,
        format: 0,
        little_endian: true,
        size_of_int: 4,
        size_of_size_t: 8,
        size_of_instruction: 4,
        size_of_lua_integer: 8,
        size_of_lua_number: 8,
        integral_number: false,
        main: LuaProto {
            source: None,
            line_defined: 0,
            last_line_defined: 0,
            num_params: 0,
            is_vararg: 0,
            max_stack_size: 2,
            code,
            constants: vec![constant],
            protos: Vec::new(),
            source_lines: Vec::new(),
            locals: Vec::new(),
            upvalues: Vec::new(),
        },
    }
}

fn assert_template_refusal(input: &LuaChunk) {
    match decompile_chunk(input) {
        Err(error @ Error::DecompileUnsupported(_)) => {
            assert!(error.to_string().contains("table template"), "{error}");
        }
        result => panic!("table-template misuse must be a named typed refusal: {result:?}"),
    }
}

#[test]
fn duptable_requires_a_table_template_constant() {
    let cases: [(u32, LuaConstant); 3] = [
        (54, LuaConstant::Nil),
        (
            0x36 | 0xffff_0000,
            LuaConstant::TableTemplate(Arc::from([])),
        ),
        (
            0x36 | (0x1 << 16),
            LuaConstant::TableTemplate(Arc::from([])),
        ),
    ];
    for (instruction, constant) in cases {
        assert_template_refusal(&chunk(vec![instruction, 0x16 | (0x2 << 16)], constant));
    }
}

#[test]
fn shared_template_loads_without_duplication_are_a_named_refusal() {
    for code in [vec![5, 0x16 | (0x2 << 16)], vec![66, 0, 0x16 | (0x2 << 16)]] {
        assert_template_refusal(&chunk(code, LuaConstant::TableTemplate(Arc::from([]))));
    }
}
