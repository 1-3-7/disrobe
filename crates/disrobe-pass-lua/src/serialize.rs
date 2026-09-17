use crate::error::{Error, Result};
use crate::reader::common::{
    LUA_SIGNATURE, LUAC_DATA_TAIL, LuaChunk, LuaConstant, LuaDialect, LuaProto,
};

const LUAC_INT_5_3: i64 = 0x5678;
const LUAC_NUM_5_3: f64 = 370.5_f64;

const TAG_NIL: u8 = 0x00;
const TAG_BOOL: u8 = 0x01;
const TAG_FLOAT: u8 = 0x03;
const TAG_INT: u8 = 0x13;
const TAG_SHORT_STR: u8 = 0x04;
const TAG_LONG_STR: u8 = 0x14;

#[derive(Debug)]
struct ByteWriter {
    out: Vec<u8>,
    little_endian: bool,
}

impl ByteWriter {
    fn new(little_endian: bool) -> Self {
        Self {
            out: Vec::new(),
            little_endian,
        }
    }

    fn push(&mut self, byte: u8) {
        self.out.push(byte);
    }

    fn extend(&mut self, bytes: &[u8]) {
        self.out.extend_from_slice(bytes);
    }

    fn write_u32(&mut self, value: u32) {
        if self.little_endian {
            self.out.extend_from_slice(&value.to_le_bytes());
        } else {
            self.out.extend_from_slice(&value.to_be_bytes());
        }
    }

    fn write_u64(&mut self, value: u64) {
        if self.little_endian {
            self.out.extend_from_slice(&value.to_le_bytes());
        } else {
            self.out.extend_from_slice(&value.to_be_bytes());
        }
    }

    fn write_size(&mut self, value: u64, size_bytes: u8) -> Result<()> {
        match size_bytes {
            4 => {
                let narrowed: u32 = u32::try_from(value & 0xFFFF_FFFF).unwrap_or(0);
                self.write_u32(narrowed);
                Ok(())
            }
            8 => {
                self.write_u64(value);
                Ok(())
            }
            other => Err(Error::BadIntSize(other)),
        }
    }

    fn write_f64(&mut self, value: f64) {
        self.write_u64(value.to_bits());
    }
}

fn write_string(w: &mut ByteWriter, value: Option<&str>, size_size_t: u8) -> Result<()> {
    let Some(text) = value else {
        w.push(0x00);
        return Ok(());
    };
    let stored_len: u64 = text.len() as u64 + 1;
    if stored_len < 0xFF {
        w.push(stored_len as u8);
    } else {
        w.push(0xFF);
        w.write_size(stored_len, size_size_t)?;
    }
    w.extend(text.as_bytes());
    Ok(())
}

fn write_string_5152(w: &mut ByteWriter, value: Option<&str>, size_size_t: u8) -> Result<()> {
    let Some(text) = value else {
        w.write_size(0, size_size_t)?;
        return Ok(());
    };
    w.write_size(text.len() as u64 + 1, size_size_t)?;
    w.extend(text.as_bytes());
    w.push(0);
    Ok(())
}

pub fn serialize_chunk(chunk: &LuaChunk) -> Result<Vec<u8>> {
    match chunk.dialect {
        LuaDialect::Lua53 => serialize_53(chunk),
        LuaDialect::Lua51 | LuaDialect::Lua52 => serialize_5152(chunk),
        _ => Err(Error::DecompileUnsupported(
            "lua serializer emits Lua 5.1, 5.2 and 5.3 bytecode only",
        )),
    }
}

fn serialize_53(chunk: &LuaChunk) -> Result<Vec<u8>> {
    let mut w: ByteWriter = ByteWriter::new(chunk.little_endian);
    w.extend(&LUA_SIGNATURE);
    w.push(0x53);
    w.push(chunk.format);
    w.extend(&LUAC_DATA_TAIL);
    w.push(chunk.size_of_int);
    w.push(chunk.size_of_size_t);
    w.push(chunk.size_of_instruction);
    w.push(chunk.size_of_lua_integer);
    w.push(chunk.size_of_lua_number);
    w.write_size(LUAC_INT_5_3 as u64, chunk.size_of_lua_integer)?;
    if chunk.size_of_lua_number == 8 {
        w.write_f64(LUAC_NUM_5_3);
    } else {
        let narrowed: f32 = LUAC_NUM_5_3 as f32;
        w.write_u32(narrowed.to_bits());
    }
    w.push(1);
    write_proto_53(&mut w, &chunk.main, chunk)?;
    Ok(w.out)
}

fn serialize_5152(chunk: &LuaChunk) -> Result<Vec<u8>> {
    let mut w: ByteWriter = ByteWriter::new(chunk.little_endian);
    w.extend(&LUA_SIGNATURE);
    w.push(if matches!(chunk.dialect, LuaDialect::Lua52) {
        0x52
    } else {
        0x51
    });
    w.push(chunk.format);
    w.push(u8::from(chunk.little_endian));
    w.push(chunk.size_of_int);
    w.push(chunk.size_of_size_t);
    w.push(chunk.size_of_instruction);
    w.push(chunk.size_of_lua_number);
    w.push(u8::from(chunk.integral_number));
    if matches!(chunk.dialect, LuaDialect::Lua52) {
        w.extend(&LUAC_DATA_TAIL);
        write_proto_52(&mut w, &chunk.main, chunk)?;
    } else {
        write_proto_51(&mut w, &chunk.main, chunk)?;
    }
    Ok(w.out)
}

fn write_proto_53(w: &mut ByteWriter, proto: &LuaProto, chunk: &LuaChunk) -> Result<()> {
    write_string(w, proto.source.as_deref(), chunk.size_of_size_t)?;
    w.write_size(u64::from(proto.line_defined), chunk.size_of_int)?;
    w.write_size(u64::from(proto.last_line_defined), chunk.size_of_int)?;
    w.push(proto.num_params);
    w.push(proto.is_vararg);
    w.push(proto.max_stack_size);

    write_code(w, proto, chunk)?;
    write_constants_53(w, proto, chunk)?;

    w.write_size(proto.upvalues.len() as u64, chunk.size_of_int)?;
    for _ in &proto.upvalues {
        w.push(0);
        w.push(0);
    }

    w.write_size(proto.protos.len() as u64, chunk.size_of_int)?;
    for sub in &proto.protos {
        write_proto_53(w, sub, chunk)?;
    }

    write_lineinfo(w, proto, chunk)?;
    write_locals(w, proto, chunk)?;

    w.write_size(proto.upvalues.len() as u64, chunk.size_of_int)?;
    for upvalue in &proto.upvalues {
        write_string(w, Some(&upvalue.name), chunk.size_of_size_t)?;
    }
    Ok(())
}

fn write_proto_51(w: &mut ByteWriter, proto: &LuaProto, chunk: &LuaChunk) -> Result<()> {
    write_string_5152(w, proto.source.as_deref(), chunk.size_of_size_t)?;
    w.write_size(u64::from(proto.line_defined), chunk.size_of_int)?;
    w.write_size(u64::from(proto.last_line_defined), chunk.size_of_int)?;
    let upvalue_count: u8 =
        u8::try_from(proto.upvalues.len()).map_err(|_| Error::LimitExceeded {
            section: "lua51 upvalues",
            count: proto.upvalues.len() as u64,
            limit: usize::from(u8::MAX),
        })?;
    w.push(upvalue_count);
    w.push(proto.num_params);
    w.push(proto.is_vararg);
    w.push(proto.max_stack_size);

    write_code(w, proto, chunk)?;
    write_constants_5152(w, proto, chunk)?;

    w.write_size(proto.protos.len() as u64, chunk.size_of_int)?;
    for sub in &proto.protos {
        write_proto_51(w, sub, chunk)?;
    }

    write_lineinfo(w, proto, chunk)?;
    write_locals_5152(w, proto, chunk)?;

    w.write_size(proto.upvalues.len() as u64, chunk.size_of_int)?;
    for upvalue in &proto.upvalues {
        write_string_5152(w, Some(&upvalue.name), chunk.size_of_size_t)?;
    }
    Ok(())
}

fn write_proto_52(w: &mut ByteWriter, proto: &LuaProto, chunk: &LuaChunk) -> Result<()> {
    w.write_size(u64::from(proto.line_defined), chunk.size_of_int)?;
    w.write_size(u64::from(proto.last_line_defined), chunk.size_of_int)?;
    w.push(proto.num_params);
    w.push(proto.is_vararg);
    w.push(proto.max_stack_size);

    write_code(w, proto, chunk)?;
    write_constants_5152(w, proto, chunk)?;

    w.write_size(proto.protos.len() as u64, chunk.size_of_int)?;
    for sub in &proto.protos {
        write_proto_52(w, sub, chunk)?;
    }

    w.write_size(proto.upvalues.len() as u64, chunk.size_of_int)?;
    for _ in &proto.upvalues {
        w.push(0);
        w.push(0);
    }

    write_string_5152(w, proto.source.as_deref(), chunk.size_of_size_t)?;
    write_lineinfo(w, proto, chunk)?;
    write_locals_5152(w, proto, chunk)?;

    w.write_size(proto.upvalues.len() as u64, chunk.size_of_int)?;
    for upvalue in &proto.upvalues {
        write_string_5152(w, Some(&upvalue.name), chunk.size_of_size_t)?;
    }
    Ok(())
}

fn write_code(w: &mut ByteWriter, proto: &LuaProto, chunk: &LuaChunk) -> Result<()> {
    w.write_size(proto.code.len() as u64, chunk.size_of_int)?;
    for instruction in &proto.code {
        w.write_size(u64::from(*instruction), chunk.size_of_instruction)?;
    }
    Ok(())
}

fn write_lineinfo(w: &mut ByteWriter, proto: &LuaProto, chunk: &LuaChunk) -> Result<()> {
    w.write_size(proto.source_lines.len() as u64, chunk.size_of_int)?;
    for line in &proto.source_lines {
        w.write_size(u64::from(*line), chunk.size_of_int)?;
    }
    Ok(())
}

fn write_locals(w: &mut ByteWriter, proto: &LuaProto, chunk: &LuaChunk) -> Result<()> {
    w.write_size(proto.locals.len() as u64, chunk.size_of_int)?;
    for local in &proto.locals {
        write_string(w, Some(&local.name), chunk.size_of_size_t)?;
        w.write_size(u64::from(local.start_pc), chunk.size_of_int)?;
        w.write_size(u64::from(local.end_pc), chunk.size_of_int)?;
    }
    Ok(())
}

fn write_locals_5152(w: &mut ByteWriter, proto: &LuaProto, chunk: &LuaChunk) -> Result<()> {
    w.write_size(proto.locals.len() as u64, chunk.size_of_int)?;
    for local in &proto.locals {
        write_string_5152(w, Some(&local.name), chunk.size_of_size_t)?;
        w.write_size(u64::from(local.start_pc), chunk.size_of_int)?;
        w.write_size(u64::from(local.end_pc), chunk.size_of_int)?;
    }
    Ok(())
}

fn write_constants_53(w: &mut ByteWriter, proto: &LuaProto, chunk: &LuaChunk) -> Result<()> {
    w.write_size(proto.constants.len() as u64, chunk.size_of_int)?;
    for constant in &proto.constants {
        write_constant_53(w, constant, chunk)?;
    }
    Ok(())
}

fn write_constants_5152(w: &mut ByteWriter, proto: &LuaProto, chunk: &LuaChunk) -> Result<()> {
    w.write_size(proto.constants.len() as u64, chunk.size_of_int)?;
    for constant in &proto.constants {
        write_constant_5152(w, constant, chunk)?;
    }
    Ok(())
}

fn write_constant_53(w: &mut ByteWriter, constant: &LuaConstant, chunk: &LuaChunk) -> Result<()> {
    match constant {
        LuaConstant::Nil => w.push(TAG_NIL),
        LuaConstant::Bool(value) => {
            w.push(TAG_BOOL);
            w.push(u8::from(*value));
        }
        LuaConstant::Number(value) => {
            w.push(TAG_FLOAT);
            if chunk.size_of_lua_number == 8 {
                w.write_f64(*value);
            } else {
                w.write_u32((*value as f32).to_bits());
            }
        }
        LuaConstant::Integer(value) => {
            w.push(TAG_INT);
            w.write_size(*value as u64, chunk.size_of_lua_integer)?;
        }
        LuaConstant::Str(text) => {
            let tag: u8 = if text.len() + 1 < 0xFF {
                TAG_SHORT_STR
            } else {
                TAG_LONG_STR
            };
            w.push(tag);
            write_string(w, Some(text), chunk.size_of_size_t)?;
        }
        LuaConstant::ClosureRef(_) | LuaConstant::Import(_) | LuaConstant::Vector(_) => {
            return Err(Error::DecompileUnsupported(
                "lua 5.3 serializer: non-5.3 constant kind in chunk",
            ));
        }
    }
    Ok(())
}

fn write_constant_5152(w: &mut ByteWriter, constant: &LuaConstant, chunk: &LuaChunk) -> Result<()> {
    match constant {
        LuaConstant::Nil => w.push(TAG_NIL),
        LuaConstant::Bool(value) => {
            w.push(TAG_BOOL);
            w.push(u8::from(*value));
        }
        LuaConstant::Number(value) => {
            w.push(TAG_FLOAT);
            if chunk.size_of_lua_number == 8 {
                w.write_f64(*value);
            } else {
                w.write_u32((*value as f32).to_bits());
            }
        }
        LuaConstant::Integer(value) => {
            w.push(TAG_FLOAT);
            if chunk.size_of_lua_number == 8 {
                w.write_f64(*value as f64);
            } else {
                w.write_u32((*value as f32).to_bits());
            }
        }
        LuaConstant::Str(text) => {
            w.push(TAG_SHORT_STR);
            write_string_5152(w, Some(text), chunk.size_of_size_t)?;
        }
        LuaConstant::ClosureRef(_) | LuaConstant::Import(_) | LuaConstant::Vector(_) => {
            return Err(Error::DecompileUnsupported(
                "lua 5.1/5.2 serializer: unsupported constant kind in chunk",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::reader::{lua51, lua52, lua53};

    fn canonical_chunk(main: LuaProto) -> LuaChunk {
        LuaChunk {
            dialect: LuaDialect::Lua53,
            version_byte: 0x53,
            format: 0,
            little_endian: true,
            size_of_int: 4,
            size_of_size_t: 8,
            size_of_instruction: 4,
            size_of_lua_integer: 8,
            size_of_lua_number: 8,
            integral_number: false,
            main,
        }
    }

    fn chunk_5152(dialect: LuaDialect, main: LuaProto) -> LuaChunk {
        LuaChunk {
            dialect,
            version_byte: dialect.version_byte().unwrap_or(0x51),
            format: 0,
            little_endian: true,
            size_of_int: 4,
            size_of_size_t: 8,
            size_of_instruction: 4,
            size_of_lua_integer: 0,
            size_of_lua_number: 8,
            integral_number: false,
            main,
        }
    }

    fn sample_proto_5152() -> LuaProto {
        LuaProto {
            source: Some("@sample51.lua".to_owned()),
            line_defined: 0,
            last_line_defined: 0,
            num_params: 0,
            is_vararg: 2,
            max_stack_size: 3,
            code: vec![0x0000_0005, 0x0040_0041, 0x0080_0041, 0x0000_001E],
            constants: vec![
                LuaConstant::Str("print".to_owned()),
                LuaConstant::Number(40.0),
                LuaConstant::Number(2.0),
            ],
            protos: Vec::new(),
            source_lines: vec![1, 1, 1, 1],
            locals: Vec::new(),
            upvalues: Vec::new(),
        }
    }

    fn sample_proto() -> LuaProto {
        LuaProto {
            source: Some("@sample.lua".to_owned()),
            line_defined: 0,
            last_line_defined: 0,
            num_params: 0,
            is_vararg: 1,
            max_stack_size: 2,
            code: vec![0x0000_0024, 0x0100_0024, 0x0080_0067],
            constants: vec![
                LuaConstant::Str("print".to_owned()),
                LuaConstant::Integer(42),
                LuaConstant::Number(2.5),
                LuaConstant::Bool(true),
                LuaConstant::Nil,
            ],
            protos: Vec::new(),
            source_lines: vec![1, 1, 1],
            locals: Vec::new(),
            upvalues: Vec::new(),
        }
    }

    #[test]
    fn serialize_then_read_round_trips() {
        let chunk: LuaChunk = canonical_chunk(sample_proto());
        let bytes: Vec<u8> = serialize_chunk(&chunk).expect("serialize");
        let reparsed: LuaChunk = lua53::read(&bytes).expect("read back");
        assert_eq!(reparsed.main.code, chunk.main.code);
        assert_eq!(reparsed.main.constants, chunk.main.constants);
        assert_eq!(reparsed.main.source_lines, chunk.main.source_lines);
        assert_eq!(reparsed.main.num_params, chunk.main.num_params);
        assert_eq!(reparsed.main.is_vararg, chunk.main.is_vararg);
        assert_eq!(reparsed.main.max_stack_size, chunk.main.max_stack_size);
    }

    #[test]
    fn nested_protos_round_trip() {
        let mut outer: LuaProto = sample_proto();
        outer.protos.push(sample_proto());
        let chunk: LuaChunk = canonical_chunk(outer);
        let bytes: Vec<u8> = serialize_chunk(&chunk).expect("serialize");
        let reparsed: LuaChunk = lua53::read(&bytes).expect("read back");
        assert_eq!(reparsed.main.protos.len(), 1);
        assert_eq!(
            reparsed.main.protos[0].constants,
            chunk.main.protos[0].constants
        );
    }

    #[test]
    fn serialize_51_round_trips_through_reader() {
        let chunk: LuaChunk = chunk_5152(LuaDialect::Lua51, sample_proto_5152());
        let bytes: Vec<u8> = serialize_chunk(&chunk).expect("serialize 5.1");
        let reparsed: LuaChunk = lua51::read(&bytes).expect("read back 5.1");
        assert_eq!(reparsed.dialect, LuaDialect::Lua51);
        assert_eq!(reparsed.main.code, chunk.main.code);
        assert_eq!(reparsed.main.constants, chunk.main.constants);
        assert_eq!(reparsed.main.num_params, chunk.main.num_params);
        assert_eq!(reparsed.main.max_stack_size, chunk.main.max_stack_size);
    }

    #[test]
    fn serialize_52_round_trips_through_reader() {
        let chunk: LuaChunk = chunk_5152(LuaDialect::Lua52, sample_proto_5152());
        let bytes: Vec<u8> = serialize_chunk(&chunk).expect("serialize 5.2");
        let reparsed: LuaChunk = lua52::read(&bytes).expect("read back 5.2");
        assert_eq!(reparsed.dialect, LuaDialect::Lua52);
        assert_eq!(reparsed.main.code, chunk.main.code);
        assert_eq!(reparsed.main.constants, chunk.main.constants);
        assert_eq!(reparsed.main.is_vararg, chunk.main.is_vararg);
    }

    #[test]
    fn serialize_51_nested_protos_round_trip() {
        let mut outer: LuaProto = sample_proto_5152();
        outer.protos.push(sample_proto_5152());
        let chunk: LuaChunk = chunk_5152(LuaDialect::Lua51, outer);
        let bytes: Vec<u8> = serialize_chunk(&chunk).expect("serialize 5.1 nested");
        let reparsed: LuaChunk = lua51::read(&bytes).expect("read back 5.1 nested");
        assert_eq!(reparsed.main.protos.len(), 1);
        assert_eq!(
            reparsed.main.protos[0].constants,
            chunk.main.protos[0].constants
        );
    }

    #[test]
    fn serialize_51_rejects_upvalue_count_over_u8() {
        let mut main: LuaProto = sample_proto_5152();
        main.upvalues = (0..=usize::from(u8::MAX))
            .map(|index: usize| crate::reader::common::LuaUpvalueName {
                name: format!("up{index}"),
            })
            .collect();
        let chunk: LuaChunk = chunk_5152(LuaDialect::Lua51, main);
        let err: Error = serialize_chunk(&chunk).expect_err("overflowing upvalues must fail");
        assert!(matches!(
            err,
            Error::LimitExceeded {
                section: "lua51 upvalues",
                count: 256,
                limit: 255
            }
        ));
    }
}
