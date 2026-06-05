use crate::cursor::ByteCursor;
use crate::error::{Error, Result};
use crate::reader::common::{LuaChunk, LuaConstant, LuaDialect, LuaProto, LuaUpvalueName};

const LUAU_SUPPORTED_MIN: u8 = 1;
const LUAU_SUPPORTED_MAX: u8 = 11;

pub fn read(bytes: &[u8]) -> Result<LuaChunk> {
    let mut c: ByteCursor<'_> = ByteCursor::new(bytes);
    let version: u8 = c.read_u8()?;
    if version == 0 {
        return Err(Error::NotLuau);
    }
    if !(LUAU_SUPPORTED_MIN..=LUAU_SUPPORTED_MAX).contains(&version) {
        return Err(Error::UnsupportedLuauVersion(version));
    }
    let types_version: u8 = if version >= 4 { c.read_u8()? } else { 0 };

    let string_count: u64 = read_varint(&mut c)?;
    let strings_cap: usize = usize::try_from(string_count)
        .ok()
        .filter(|n: &usize| *n <= c.remaining())
        .unwrap_or(0);
    let mut strings: Vec<String> = Vec::with_capacity(strings_cap);
    for _ in 0..string_count {
        let len: u64 = read_varint(&mut c)?;
        let raw: &[u8] = c.read_bytes(usize::try_from(len).unwrap_or(0))?;
        let s: String = String::from_utf8_lossy(raw).into_owned();
        strings.push(s);
    }

    if types_version == 3 {
        loop {
            let idx: u8 = c.read_u8()?;
            if idx == 0 {
                break;
            }
            let name_len: u64 = read_varint(&mut c)?;
            let _name: &[u8] = c.read_bytes(usize::try_from(name_len).unwrap_or(0))?;
        }
    }

    let proto_count: u64 = read_varint(&mut c)?;
    let mut last_proto: LuaProto = empty_proto();
    for _ in 0..proto_count {
        last_proto = read_proto(&mut c, &strings, version, types_version)?;
    }
    let _main_proto_id: u64 = read_varint(&mut c)?;
    Ok(LuaChunk {
        dialect: LuaDialect::Luau,
        version_byte: version,
        format: 0,
        little_endian: true,
        size_of_int: 4,
        size_of_size_t: 4,
        size_of_instruction: 4,
        size_of_lua_integer: 0,
        size_of_lua_number: 8,
        integral_number: false,
        main: last_proto,
    })
}

fn empty_proto() -> LuaProto {
    LuaProto {
        source: None,
        line_defined: 0,
        last_line_defined: 0,
        num_params: 0,
        is_vararg: 0,
        max_stack_size: 0,
        code: Vec::new(),
        constants: Vec::new(),
        protos: Vec::new(),
        source_lines: Vec::new(),
        locals: Vec::new(),
        upvalues: Vec::new(),
    }
}

fn read_varint(c: &mut ByteCursor<'_>) -> Result<u64> {
    let start: usize = c.position();
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        let byte: u8 = c.read_u8()?;
        let chunk: u64 = u64::from(byte & 0x7F);
        let shifted: u64 = chunk.checked_shl(shift).ok_or(Error::BadUleb128(start))?;
        result |= shifted;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return Err(Error::BadUleb128(start));
        }
    }
    Ok(result)
}

const LUAU_K_NIL: u8 = 0;
const LUAU_K_BOOL: u8 = 1;
const LUAU_K_NUMBER: u8 = 2;
const LUAU_K_STRING: u8 = 3;
const LUAU_K_IMPORT: u8 = 4;
const LUAU_K_TABLE: u8 = 5;
const LUAU_K_CLOSURE: u8 = 6;
const LUAU_K_VECTOR: u8 = 7;
const LUAU_K_TABLE_WITH_CONSTANTS: u8 = 8;
const LUAU_K_INTEGER: u8 = 9;
const LUAU_K_CLASS_SHAPE: u8 = 10;

fn read_proto(
    c: &mut ByteCursor<'_>,
    strings: &[String],
    version: u8,
    types_version: u8,
) -> Result<LuaProto> {
    let max_stack_size: u8 = c.read_u8()?;
    let num_params: u8 = c.read_u8()?;
    let nups: u8 = c.read_u8()?;
    let is_vararg: u8 = c.read_u8()?;
    if version >= 4 {
        let _flags: u8 = c.read_u8()?;
        if types_version == 1 || types_version == 2 || types_version == 3 {
            let types_size: u64 = read_varint(c)?;
            if types_size > 0 {
                let _types: &[u8] = c.read_bytes(usize::try_from(types_size).unwrap_or(0))?;
            }
        }
    }
    let code_size: u64 = read_varint(c)?;
    let code_cap: usize = usize::try_from(code_size)
        .ok()
        .filter(|n: &usize| n.saturating_mul(4) <= c.remaining())
        .unwrap_or(0);
    let mut code: Vec<u32> = Vec::with_capacity(code_cap);
    for _ in 0..code_size {
        code.push(c.read_u32()?);
    }
    let const_count: u64 = read_varint(c)?;
    let const_cap: usize = usize::try_from(const_count)
        .ok()
        .filter(|n: &usize| *n <= c.remaining())
        .unwrap_or(0);
    let mut constants: Vec<LuaConstant> = Vec::with_capacity(const_cap);
    for _ in 0..const_count {
        let tag: u8 = c.read_u8()?;
        let value: LuaConstant = match tag {
            LUAU_K_NIL => LuaConstant::Nil,
            LUAU_K_BOOL => LuaConstant::Bool(c.read_u8()? != 0),
            LUAU_K_NUMBER => LuaConstant::Number(c.read_f64()?),
            LUAU_K_STRING => {
                let id: u64 = read_varint(c)?;
                let idx: usize = usize::try_from(id).unwrap_or(0).saturating_sub(1);
                strings
                    .get(idx)
                    .cloned()
                    .map_or(LuaConstant::Str(String::new()), LuaConstant::Str)
            }
            LUAU_K_IMPORT => {
                let _id: u32 = c.read_u32()?;
                LuaConstant::Nil
            }
            LUAU_K_TABLE => {
                let key_count: u64 = read_varint(c)?;
                for _ in 0..key_count {
                    let _k: u64 = read_varint(c)?;
                }
                LuaConstant::Nil
            }
            LUAU_K_CLOSURE => {
                let _fid: u64 = read_varint(c)?;
                LuaConstant::Nil
            }
            LUAU_K_VECTOR => {
                let _x: u32 = c.read_u32()?;
                let _y: u32 = c.read_u32()?;
                let _z: u32 = c.read_u32()?;
                let _w: u32 = c.read_u32()?;
                LuaConstant::Nil
            }
            LUAU_K_TABLE_WITH_CONSTANTS => {
                let key_count: u64 = read_varint(c)?;
                for _ in 0..key_count {
                    let _k: u64 = read_varint(c)?;
                    let _v: u32 = c.read_u32()?;
                }
                LuaConstant::Nil
            }
            LUAU_K_INTEGER => {
                let neg: u8 = c.read_u8()?;
                let mag: u64 = read_varint(c)?;
                let signed_value: i64 = if neg != 0 {
                    (mag as i64).wrapping_neg()
                } else {
                    mag as i64
                };
                LuaConstant::Integer(signed_value)
            }
            LUAU_K_CLASS_SHAPE => {
                let _cnid: u64 = read_varint(c)?;
                let num_properties: u64 = read_varint(c)?;
                let num_methods: u64 = read_varint(c)?;
                let total: u64 = num_properties.saturating_add(num_methods);
                for _ in 0..total {
                    let _mid: u64 = read_varint(c)?;
                }
                LuaConstant::Nil
            }
            other => return Err(Error::BadConstantTag(other, c.position())),
        };
        constants.push(value);
    }
    let inner_proto_count: u64 = read_varint(c)?;
    let inner_cap: usize = usize::try_from(inner_proto_count)
        .ok()
        .filter(|n: &usize| *n <= c.remaining())
        .unwrap_or(0);
    let mut protos_refs: Vec<LuaProto> = Vec::with_capacity(inner_cap);
    for _ in 0..inner_proto_count {
        let _id: u64 = read_varint(c)?;
        protos_refs.push(empty_proto());
    }
    let line_defined: u64 = read_varint(c)?;
    let debug_name_id: u64 = read_varint(c)?;
    let source: Option<String> = if debug_name_id == 0 {
        None
    } else {
        strings
            .get(
                usize::try_from(debug_name_id)
                    .unwrap_or(0)
                    .saturating_sub(1),
            )
            .cloned()
    };
    let has_lineinfo: u8 = c.read_u8()?;
    if has_lineinfo != 0 {
        let linegap: u8 = c.read_u8()?;
        let span: usize = usize::try_from(code_size).unwrap_or(0);
        for _ in 0..span {
            let _: u8 = c.read_u8()?;
        }
        let shift: u32 = u32::from(linegap).min(31);
        let intervals: usize = (span.saturating_sub(1) >> shift).saturating_add(1);
        for _ in 0..intervals {
            let _: u32 = c.read_u32()?;
        }
    }
    let has_debug: u8 = c.read_u8()?;
    let mut upvalues: Vec<LuaUpvalueName> = Vec::with_capacity(usize::from(nups));
    if has_debug != 0 {
        let local_count: u64 = read_varint(c)?;
        for _ in 0..local_count {
            let _name: u64 = read_varint(c)?;
            let _start: u64 = read_varint(c)?;
            let _end: u64 = read_varint(c)?;
            let _reg: u8 = c.read_u8()?;
        }
        let upval_count: u64 = read_varint(c)?;
        for _ in 0..upval_count {
            let id: u64 = read_varint(c)?;
            let name: String = strings
                .get(usize::try_from(id).unwrap_or(0).saturating_sub(1))
                .cloned()
                .unwrap_or_default();
            upvalues.push(LuaUpvalueName { name });
        }
    }
    if version >= 11 {
        let feedback_count: u64 = read_varint(c)?;
        for _ in 0..feedback_count {
            let _slottype: u8 = c.read_u8()?;
            let _pc: u64 = read_varint(c)?;
        }
    }
    Ok(LuaProto {
        source,
        line_defined: u32::try_from(line_defined).unwrap_or(0),
        last_line_defined: 0,
        num_params,
        is_vararg,
        max_stack_size,
        code,
        constants,
        protos: protos_refs,
        source_lines: Vec::new(),
        locals: Vec::new(),
        upvalues,
    })
}
