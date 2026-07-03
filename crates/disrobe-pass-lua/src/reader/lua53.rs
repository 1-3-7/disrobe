use crate::cursor::{ByteCursor, MAX_PROTO_DEPTH};
use crate::error::{Error, Result};
use crate::reader::common::{
    LUA_SIGNATURE, LUAC_DATA_TAIL, LuaChunk, LuaConstant, LuaDialect, LuaLocal, LuaProto,
    LuaUpvalueName, capped_u32, low_u32,
};

const LUAC_INT_5_3: u64 = 0x5678;
const LUAC_NUM_5_3: f64 = 370.5_f64;

pub fn read(bytes: &[u8]) -> Result<LuaChunk> {
    let mut c: ByteCursor<'_> = ByteCursor::new(bytes);
    let sig: &[u8] = c.read_bytes(4)?;
    if sig != LUA_SIGNATURE {
        return Err(Error::BadSignature);
    }
    let version: u8 = c.read_u8()?;
    if version != 0x53 {
        return Err(Error::UnsupportedLuaVersion(version));
    }
    let format: u8 = c.read_u8()?;
    if format != 0x00 {
        return Err(Error::UnsupportedFormat(format));
    }
    let tail_off: usize = c.position();
    let tail: &[u8] = c.read_bytes(6)?;
    if tail != LUAC_DATA_TAIL {
        return Err(Error::BadLuacData(tail_off));
    }
    let size_int: u8 = c.read_u8()?;
    let size_size_t: u8 = c.read_u8()?;
    let size_instr: u8 = c.read_u8()?;
    let size_lua_integer: u8 = c.read_u8()?;
    let size_lua_number: u8 = c.read_u8()?;
    if size_int != 4 && size_int != 8 {
        return Err(Error::BadIntSize(size_int));
    }
    if size_size_t != 4 && size_size_t != 8 {
        return Err(Error::BadIntSize(size_size_t));
    }
    if size_lua_integer != 4 && size_lua_integer != 8 {
        return Err(Error::BadIntSize(size_lua_integer));
    }
    if size_lua_number != 4 && size_lua_number != 8 {
        return Err(Error::BadNumberSize(size_lua_number));
    }
    let int_check_le: u64 = read_native_size(&mut c, size_lua_integer, true)?;
    let little_endian: bool = if int_check_le == LUAC_INT_5_3 {
        true
    } else {
        let int_check_be: u64 =
            int_check_le.swap_bytes() >> (64u32.saturating_sub(u32::from(size_lua_integer) * 8));
        if int_check_be == LUAC_INT_5_3 {
            false
        } else {
            return Err(Error::EndianMismatch { got: int_check_le });
        }
    };
    c.set_little_endian(little_endian);
    let num_check: f64 = if size_lua_number == 8 {
        c.read_f64()?
    } else {
        let raw: u32 = c.read_u32()?;
        f64::from(f32::from_bits(raw))
    };
    if (num_check - LUAC_NUM_5_3).abs() > 0.001 {
        return Err(Error::FloatMismatch { got: num_check });
    }
    let _upval_size: u8 = c.read_u8()?;
    let main: LuaProto = read_proto(
        &mut c,
        size_int,
        size_size_t,
        size_instr,
        size_lua_integer,
        size_lua_number,
        0,
    )?;
    Ok(LuaChunk {
        dialect: LuaDialect::Lua53,
        version_byte: 0x53,
        format,
        little_endian,
        size_of_int: size_int,
        size_of_size_t: size_size_t,
        size_of_instruction: size_instr,
        size_of_lua_integer: size_lua_integer,
        size_of_lua_number: size_lua_number,
        integral_number: false,
        main,
    })
}

fn read_native_size(c: &mut ByteCursor<'_>, sz: u8, _le: bool) -> Result<u64> {
    c.read_size(sz)
}

fn read_string(c: &mut ByteCursor<'_>, size_size_t: u8) -> Result<Option<String>> {
    let first: u8 = c.read_u8()?;
    let len: u64 = if first == 0xFF {
        c.read_size(size_size_t)?
    } else {
        u64::from(first)
    };
    if len == 0 {
        return Ok(None);
    }
    let raw_len: usize = c.checked_len("lua53 string length", len.saturating_sub(1))?;
    let raw: &[u8] = c.read_bytes(raw_len)?;
    let owned: String = String::from_utf8_lossy(raw).into_owned();
    Ok(Some(owned))
}

fn read_proto(
    c: &mut ByteCursor<'_>,
    size_int: u8,
    size_size_t: u8,
    size_instr: u8,
    size_lua_integer: u8,
    size_lua_number: u8,
    depth: usize,
) -> Result<LuaProto> {
    if depth > MAX_PROTO_DEPTH {
        return Err(Error::ProtoNestingTooDeep(depth));
    }
    let source: Option<String> = read_string(c, size_size_t)?;
    let line_defined: u32 = capped_u32(c.read_size(size_int)?);
    let last_line_defined: u32 = capped_u32(c.read_size(size_int)?);
    let num_params: u8 = c.read_u8()?;
    let is_vararg: u8 = c.read_u8()?;
    let max_stack_size: u8 = c.read_u8()?;

    let code_len: u64 = c.read_size(size_int)?;
    let code_len: usize = c.checked_count::<u32>("lua53 code", code_len, size_instr.into())?;
    let mut code: Vec<u32> = Vec::with_capacity(code_len);
    for _ in 0..code_len {
        let inst: u64 = c.read_size(size_instr)?;
        code.push(low_u32(inst));
    }

    let const_count: u64 = c.read_size(size_int)?;
    let const_count: usize = c.checked_count::<LuaConstant>("lua53 constant", const_count, 1)?;
    let mut constants: Vec<LuaConstant> = Vec::with_capacity(const_count);
    for _ in 0..const_count {
        let tag: u8 = c.read_u8()?;
        let value: LuaConstant = match tag {
            0x00 => LuaConstant::Nil,
            0x01 => LuaConstant::Bool(c.read_u8()? != 0),
            0x03 => {
                if size_lua_number == 8 {
                    LuaConstant::Number(c.read_f64()?)
                } else {
                    let bits: u32 = c.read_u32()?;
                    LuaConstant::Number(f64::from(f32::from_bits(bits)))
                }
            }
            0x13 => {
                let raw: u64 = c.read_size(size_lua_integer)?;
                LuaConstant::Integer(i64::from_le_bytes(raw.to_le_bytes()))
            }
            0x04 | 0x14 => read_string(c, size_size_t)?
                .map_or(LuaConstant::Str(String::new()), LuaConstant::Str),
            other => return Err(Error::BadConstantTag(other, c.position())),
        };
        constants.push(value);
    }

    let upval_count: u64 = c.read_size(size_int)?;
    let upval_count: usize = c.checked_count::<LuaUpvalueName>("lua53 upvalue", upval_count, 2)?;
    let mut upvalues: Vec<LuaUpvalueName> = Vec::with_capacity(upval_count);
    for _ in 0..upval_count {
        let _in_stack: u8 = c.read_u8()?;
        let _idx: u8 = c.read_u8()?;
        upvalues.push(LuaUpvalueName {
            name: String::new(),
        });
    }

    let proto_count: u64 = c.read_size(size_int)?;
    let proto_count: usize = c.checked_count::<LuaProto>("lua53 proto", proto_count, 1)?;
    let mut protos: Vec<LuaProto> = Vec::with_capacity(proto_count);
    for _ in 0..proto_count {
        protos.push(read_proto(
            c,
            size_int,
            size_size_t,
            size_instr,
            size_lua_integer,
            size_lua_number,
            depth + 1,
        )?);
    }

    let line_count: u64 = c.read_size(size_int)?;
    let line_count: usize =
        c.checked_count::<u32>("lua53 line info", line_count, size_int.into())?;
    let mut source_lines: Vec<u32> = Vec::with_capacity(line_count);
    for _ in 0..line_count {
        source_lines.push(capped_u32(c.read_size(size_int)?));
    }

    let local_count: u64 = c.read_size(size_int)?;
    let local_count: usize = c.checked_count::<LuaLocal>("lua53 local", local_count, 1)?;
    let mut locals: Vec<LuaLocal> = Vec::with_capacity(local_count);
    for _ in 0..local_count {
        let name: String = read_string(c, size_size_t)?.unwrap_or_default();
        let start_pc: u32 = capped_u32(c.read_size(size_int)?);
        let end_pc: u32 = capped_u32(c.read_size(size_int)?);
        locals.push(LuaLocal {
            name,
            start_pc,
            end_pc,
        });
    }

    let upval_names: u64 = c.read_size(size_int)?;
    let upval_names: usize = c.checked_count::<u8>("lua53 upvalue name", upval_names, 1)?;
    for idx in 0..upval_names {
        let name: String = read_string(c, size_size_t)?.unwrap_or_default();
        if idx < upvalues.len() {
            upvalues[idx].name = name;
        }
    }

    Ok(LuaProto {
        source,
        line_defined,
        last_line_defined,
        num_params,
        is_vararg,
        max_stack_size,
        code,
        constants,
        protos,
        source_lines,
        locals,
        upvalues,
    })
}
