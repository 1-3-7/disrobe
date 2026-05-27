use crate::cursor::ByteCursor;
use crate::error::{Error, Result};
use crate::reader::common::{
    LUA_SIGNATURE, LUAC_DATA_TAIL, LuaChunk, LuaConstant, LuaDialect, LuaLocal, LuaProto,
    LuaUpvalueName,
};

const LUAC_INT_5_4: u64 = 0x5678;
const LUAC_NUM_5_4: f64 = 370.5_f64;

pub fn read(bytes: &[u8]) -> Result<LuaChunk> {
    let mut c: ByteCursor<'_> = ByteCursor::new(bytes);
    let sig: &[u8] = c.read_bytes(4)?;
    if sig != LUA_SIGNATURE {
        return Err(Error::BadSignature);
    }
    let version: u8 = c.read_u8()?;
    if version != 0x54 {
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
    let size_instr: u8 = c.read_u8()?;
    let size_lua_integer: u8 = c.read_u8()?;
    let size_lua_number: u8 = c.read_u8()?;
    if size_instr != 4 {
        return Err(Error::BadIntSize(size_instr));
    }
    if size_lua_integer != 4 && size_lua_integer != 8 {
        return Err(Error::BadIntSize(size_lua_integer));
    }
    if size_lua_number != 4 && size_lua_number != 8 {
        return Err(Error::BadNumberSize(size_lua_number));
    }
    let int_check: u64 = c.read_size(size_lua_integer)?;
    if int_check != LUAC_INT_5_4 {
        return Err(Error::EndianMismatch { got: int_check });
    }
    let num_check: f64 = if size_lua_number == 8 {
        c.read_f64()?
    } else {
        let raw: u32 = c.read_u32()?;
        f64::from(f32::from_bits(raw))
    };
    if (num_check - LUAC_NUM_5_4).abs() > 0.001 {
        return Err(Error::FloatMismatch { got: num_check });
    }
    let _num_upvals_main: u8 = c.read_u8()?;
    let main: LuaProto = read_proto(&mut c, size_instr, size_lua_integer, size_lua_number)?;
    Ok(LuaChunk {
        dialect: LuaDialect::Lua54,
        version_byte: 0x54,
        format,
        little_endian: true,
        size_of_int: 0,
        size_of_size_t: 0,
        size_of_instruction: size_instr,
        size_of_lua_integer: size_lua_integer,
        size_of_lua_number: size_lua_number,
        integral_number: false,
        main,
    })
}

fn read_lua54_size(c: &mut ByteCursor<'_>) -> Result<u64> {
    let mut result: u64 = 0;
    loop {
        let byte: u8 = c.read_u8()?;
        result = result
            .checked_shl(7)
            .ok_or(Error::BadUleb128(c.position()))?
            | u64::from(byte & 0x7F);
        if byte & 0x80 != 0 {
            break;
        }
    }
    Ok(result)
}

fn read_string(c: &mut ByteCursor<'_>) -> Result<Option<String>> {
    let len: u64 = read_lua54_size(c)?;
    if len == 0 {
        return Ok(None);
    }
    let raw_len: usize = usize::try_from(len.saturating_sub(1)).unwrap_or(0);
    let raw: &[u8] = c.read_bytes(raw_len)?;
    let off: usize = c.position().saturating_sub(raw.len());
    let owned: String = std::str::from_utf8(raw)
        .map_err(|_| Error::BadUtf8(off))?
        .to_owned();
    Ok(Some(owned))
}

fn read_proto(
    c: &mut ByteCursor<'_>,
    size_instr: u8,
    size_lua_integer: u8,
    size_lua_number: u8,
) -> Result<LuaProto> {
    let source: Option<String> = read_string(c)?;
    let line_defined: u32 = u32::try_from(read_lua54_size(c)?).unwrap_or(0);
    let last_line_defined: u32 = u32::try_from(read_lua54_size(c)?).unwrap_or(0);
    let num_params: u8 = c.read_u8()?;
    let is_vararg: u8 = c.read_u8()?;
    let max_stack_size: u8 = c.read_u8()?;

    let code_len: u64 = read_lua54_size(c)?;
    let mut code: Vec<u32> = Vec::with_capacity(usize::try_from(code_len).unwrap_or(0));
    for _ in 0..code_len {
        let inst: u64 = c.read_size(size_instr)?;
        code.push(u32::try_from(inst & 0xFFFF_FFFF).unwrap_or(0));
    }

    let const_count: u64 = read_lua54_size(c)?;
    let mut constants: Vec<LuaConstant> =
        Vec::with_capacity(usize::try_from(const_count).unwrap_or(0));
    for _ in 0..const_count {
        let tag: u8 = c.read_u8()?;
        let value: LuaConstant = match tag {
            0x00 => LuaConstant::Nil,
            0x01 => LuaConstant::Bool(false),
            0x11 => LuaConstant::Bool(true),
            0x03 => {
                if size_lua_number == 8 {
                    LuaConstant::Number(c.read_f64()?)
                } else {
                    let raw: u32 = c.read_u32()?;
                    LuaConstant::Number(f64::from(f32::from_bits(raw)))
                }
            }
            0x13 => {
                let raw: u64 = c.read_size(size_lua_integer)?;
                LuaConstant::Integer(raw as i64)
            }
            0x04 | 0x14 => {
                read_string(c)?.map_or(LuaConstant::Str(String::new()), LuaConstant::Str)
            }
            other => return Err(Error::BadConstantTag(other, c.position())),
        };
        constants.push(value);
    }

    let upval_count: u64 = read_lua54_size(c)?;
    let mut upvalues: Vec<LuaUpvalueName> =
        Vec::with_capacity(usize::try_from(upval_count).unwrap_or(0));
    for _ in 0..upval_count {
        let _in_stack: u8 = c.read_u8()?;
        let _idx: u8 = c.read_u8()?;
        let _kind: u8 = c.read_u8()?;
        upvalues.push(LuaUpvalueName {
            name: String::new(),
        });
    }

    let proto_count: u64 = read_lua54_size(c)?;
    let mut protos: Vec<LuaProto> = Vec::with_capacity(usize::try_from(proto_count).unwrap_or(0));
    for _ in 0..proto_count {
        protos.push(read_proto(
            c,
            size_instr,
            size_lua_integer,
            size_lua_number,
        )?);
    }

    let line_info_count: u64 = read_lua54_size(c)?;
    let mut source_lines: Vec<u32> =
        Vec::with_capacity(usize::try_from(line_info_count).unwrap_or(0));
    for _ in 0..line_info_count {
        let _: u8 = c.read_u8()?;
    }
    let abs_line_count: u64 = read_lua54_size(c)?;
    for _ in 0..abs_line_count {
        let _pc: u64 = read_lua54_size(c)?;
        let line: u64 = read_lua54_size(c)?;
        source_lines.push(u32::try_from(line).unwrap_or(0));
    }

    let local_count: u64 = read_lua54_size(c)?;
    let mut locals: Vec<LuaLocal> = Vec::with_capacity(usize::try_from(local_count).unwrap_or(0));
    for _ in 0..local_count {
        let name: String = read_string(c)?.unwrap_or_default();
        let start_pc: u32 = u32::try_from(read_lua54_size(c)?).unwrap_or(0);
        let end_pc: u32 = u32::try_from(read_lua54_size(c)?).unwrap_or(0);
        locals.push(LuaLocal {
            name,
            start_pc,
            end_pc,
        });
    }

    let upval_names: u64 = read_lua54_size(c)?;
    for i in 0..upval_names {
        let idx: usize = usize::try_from(i).unwrap_or(0);
        let name: String = read_string(c)?.unwrap_or_default();
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
