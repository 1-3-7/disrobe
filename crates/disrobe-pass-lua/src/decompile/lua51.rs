use crate::decompile::{DecompiledChunk, decompile_chunk};
use crate::error::Result;
use crate::reader::common::LuaChunk;

pub fn decompile(chunk: &LuaChunk) -> Result<DecompiledChunk> {
    decompile_chunk(chunk)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::reader::common::{LuaConstant, LuaDialect, LuaProto};

    fn enc_abc(op: u32, a: u32, b: u32, c: u32) -> u32 {
        op | (a << 6) | (c << 14) | (b << 23)
    }

    fn enc_abx(op: u32, a: u32, bx: u32) -> u32 {
        op | (a << 6) | (bx << 14)
    }

    fn chunk_with(code: Vec<u32>, constants: Vec<LuaConstant>, stack: u8) -> LuaChunk {
        LuaChunk {
            dialect: LuaDialect::Lua51,
            version_byte: 0x51,
            format: 0,
            little_endian: true,
            size_of_int: 4,
            size_of_size_t: 4,
            size_of_instruction: 4,
            size_of_lua_integer: 0,
            size_of_lua_number: 8,
            integral_number: false,
            main: LuaProto {
                source: None,
                line_defined: 0,
                last_line_defined: 0,
                num_params: 0,
                is_vararg: 2,
                max_stack_size: stack,
                code,
                constants,
                protos: Vec::new(),
                source_lines: Vec::new(),
                locals: Vec::new(),
                upvalues: Vec::new(),
            },
        }
    }

    #[test]
    fn decompile_emits_main_function() {
        let c: LuaChunk = chunk_with(vec![0x0000_001E], Vec::new(), 2);
        let out: DecompiledChunk = decompile(&c).expect("decompile");
        assert!(out.source.contains("function _main(...)"));
        assert!(out.source.contains("end"));
    }

    #[test]
    fn decompile_hello_world_pattern() {
        let consts: Vec<LuaConstant> = vec![
            LuaConstant::Str("print".to_owned()),
            LuaConstant::Str("hi".to_owned()),
        ];
        let code: Vec<u32> = vec![
            enc_abx(0x05, 0, 0),
            enc_abx(0x01, 1, 1),
            enc_abc(0x1C, 0, 2, 1),
            enc_abc(0x1E, 0, 1, 0),
        ];
        let c: LuaChunk = chunk_with(code, consts, 3);
        let out: DecompiledChunk = decompile(&c).expect("decompile");
        assert!(
            out.source.contains("print(\"hi\")"),
            "expected print call, got:\n{}",
            out.source
        );
    }
}
