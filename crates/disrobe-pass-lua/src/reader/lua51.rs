use crate::cursor::ByteCursor;
use crate::error::{Error, Result};
use crate::reader::common::{
    LUA_SIGNATURE, LuaChunk, LuaConstant, LuaDialect, LuaLocal, LuaProto, LuaUpvalueName,
};

pub fn read(bytes: &[u8]) -> Result<LuaChunk> {
    let mut c: ByteCursor<'_> = ByteCursor::new(bytes);
    let sig: &[u8] = c.read_bytes(4)?;
    if sig != LUA_SIGNATURE {
        return Err(Error::BadSignature);
    }
    let version: u8 = c.read_u8()?;
    if version != 0x51 {
        return Err(Error::UnsupportedLuaVersion(version));
    }
    let format: u8 = c.read_u8()?;
    if format != 0x00 {
        return Err(Error::UnsupportedFormat(format));
    }
    let endian: u8 = c.read_u8()?;
    c.set_little_endian(endian == 1);
    let size_int: u8 = c.read_u8()?;
    let size_size_t: u8 = c.read_u8()?;
    let size_instr: u8 = c.read_u8()?;
    let size_number: u8 = c.read_u8()?;
    let integral_flag: u8 = c.read_u8()?;
    if size_int != 4 && size_int != 8 {
        return Err(Error::BadIntSize(size_int));
    }
    if size_size_t != 4 && size_size_t != 8 {
        return Err(Error::BadIntSize(size_size_t));
    }
    if size_number != 4 && size_number != 8 {
        return Err(Error::BadNumberSize(size_number));
    }
    let integral: bool = integral_flag != 0;
    let main: LuaProto = read_proto(&mut c, size_int, size_size_t, size_instr, size_number)?;
    Ok(LuaChunk {
        dialect: LuaDialect::Lua51,
        version_byte: 0x51,
        format,
        little_endian: c.is_little_endian(),
        size_of_int: size_int,
        size_of_size_t: size_size_t,
        size_of_instruction: size_instr,
        size_of_lua_integer: 0,
        size_of_lua_number: size_number,
        integral_number: integral,
        main,
    })
}

fn read_string(c: &mut ByteCursor<'_>, size_size_t: u8) -> Result<Option<String>> {
    let len: u64 = c.read_size(size_size_t)?;
    if len == 0 {
        return Ok(None);
    }
    let raw: &[u8] = c.read_bytes(usize::try_from(len).map_err(|_| Error::Truncated {
        offset: c.position(),
        needed: 0,
        had: 0,
    })?)?;
    let trimmed: &[u8] = raw.strip_suffix(b"\0").unwrap_or(raw);
    let offset: usize = c.position().saturating_sub(raw.len());
    let owned: String = std::str::from_utf8(trimmed)
        .map_err(|_| Error::BadUtf8(offset))?
        .to_owned();
    Ok(Some(owned))
}

fn read_proto(
    c: &mut ByteCursor<'_>,
    size_int: u8,
    size_size_t: u8,
    size_instr: u8,
    size_number: u8,
) -> Result<LuaProto> {
    let source: Option<String> = read_string(c, size_size_t)?;
    let line_defined: u32 = u32::try_from(c.read_size(size_int)?).unwrap_or(u32::MAX);
    let last_line_defined: u32 = u32::try_from(c.read_size(size_int)?).unwrap_or(u32::MAX);
    let nups: u8 = c.read_u8()?;
    let num_params: u8 = c.read_u8()?;
    let is_vararg: u8 = c.read_u8()?;
    let max_stack_size: u8 = c.read_u8()?;

    let code_len: u64 = c.read_size(size_int)?;
    let mut code: Vec<u32> = Vec::with_capacity(usize::try_from(code_len).unwrap_or(0));
    for _ in 0..code_len {
        let inst: u64 = c.read_size(size_instr)?;
        code.push(u32::try_from(inst & 0xFFFF_FFFF).unwrap_or(0));
    }

    let const_count: u64 = c.read_size(size_int)?;
    let mut constants: Vec<LuaConstant> =
        Vec::with_capacity(usize::try_from(const_count).unwrap_or(0));
    for _ in 0..const_count {
        let tag: u8 = c.read_u8()?;
        let value: LuaConstant = match tag {
            0 => LuaConstant::Nil,
            1 => LuaConstant::Bool(c.read_u8()? != 0),
            3 => {
                if size_number == 8 {
                    LuaConstant::Number(c.read_f64()?)
                } else {
                    let bits: u32 = c.read_u32()?;
                    LuaConstant::Number(f64::from(f32::from_bits(bits)))
                }
            }
            4 => match read_string(c, size_size_t)? {
                Some(s) => LuaConstant::Str(s),
                None => LuaConstant::Str(String::new()),
            },
            other => return Err(Error::BadConstantTag(other, c.position())),
        };
        constants.push(value);
    }

    let proto_count: u64 = c.read_size(size_int)?;
    let mut protos: Vec<LuaProto> = Vec::with_capacity(usize::try_from(proto_count).unwrap_or(0));
    for _ in 0..proto_count {
        protos.push(read_proto(
            c,
            size_int,
            size_size_t,
            size_instr,
            size_number,
        )?);
    }

    let line_count: u64 = c.read_size(size_int)?;
    let mut source_lines: Vec<u32> = Vec::with_capacity(usize::try_from(line_count).unwrap_or(0));
    for _ in 0..line_count {
        source_lines.push(u32::try_from(c.read_size(size_int)?).unwrap_or(0));
    }

    let local_count: u64 = c.read_size(size_int)?;
    let mut locals: Vec<LuaLocal> = Vec::with_capacity(usize::try_from(local_count).unwrap_or(0));
    for _ in 0..local_count {
        let name: String = read_string(c, size_size_t)?.unwrap_or_default();
        let start_pc: u32 = u32::try_from(c.read_size(size_int)?).unwrap_or(0);
        let end_pc: u32 = u32::try_from(c.read_size(size_int)?).unwrap_or(0);
        locals.push(LuaLocal {
            name,
            start_pc,
            end_pc,
        });
    }

    let upval_count: u64 = c.read_size(size_int)?;
    let mut upvalues: Vec<LuaUpvalueName> =
        Vec::with_capacity(usize::try_from(upval_count).unwrap_or(0));
    for _ in 0..upval_count {
        let name: String = read_string(c, size_size_t)?.unwrap_or_default();
        upvalues.push(LuaUpvalueName { name });
    }
    let _: u8 = nups;

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
