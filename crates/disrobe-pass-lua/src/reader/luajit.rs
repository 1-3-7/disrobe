use crate::cursor::ByteCursor;
use crate::error::{Error, Result};
use crate::reader::common::{
    LUAJIT_SIGNATURE, LuaChunk, LuaConstant, LuaDialect, LuaProto, LuaUpvalueName,
};

const FLAG_STRIPPED: u32 = 0x02;

pub fn read(bytes: &[u8]) -> Result<LuaChunk> {
    let mut c: ByteCursor<'_> = ByteCursor::new(bytes);
    let sig: &[u8] = c.read_bytes(3)?;
    if sig != LUAJIT_SIGNATURE {
        return Err(Error::BadLuaJitSignature);
    }
    let version: u8 = c.read_u8()?;
    let dialect: LuaDialect = match version {
        1 => LuaDialect::LuaJit20,
        2 => LuaDialect::LuaJit21,
        other => return Err(Error::UnsupportedLuaJitVersion(other)),
    };
    let flags: u64 = c.read_uleb128()?;
    let stripped: bool = (flags as u32) & FLAG_STRIPPED != 0;
    if !stripped {
        let src_len: u64 = c.read_uleb128()?;
        if src_len > 0 {
            let _src: &[u8] = c.read_bytes(usize::try_from(src_len).unwrap_or(0))?;
        }
    }
    let mut main: LuaProto = LuaProto {
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
    };
    loop {
        if c.remaining() == 0 {
            break;
        }
        let proto_len: u64 = c.read_uleb128()?;
        if proto_len == 0 {
            break;
        }
        let proto_end: usize = c
            .position()
            .checked_add(usize::try_from(proto_len).unwrap_or(0))
            .unwrap_or(usize::MAX);
        let proto: LuaProto = read_proto(&mut c, stripped, dialect, proto_end)?;
        main = proto;
    }
    Ok(LuaChunk {
        dialect,
        version_byte: version,
        format: 0,
        little_endian: true,
        size_of_int: 4,
        size_of_size_t: 8,
        size_of_instruction: 4,
        size_of_lua_integer: 0,
        size_of_lua_number: 8,
        integral_number: false,
        main,
    })
}

const KGC_CHILD: u8 = 0;
const KGC_TAB: u8 = 1;
const KGC_I64: u8 = 2;
const KGC_U64: u8 = 3;
const KGC_COMPLEX: u8 = 4;
const KGC_STR_BASE: u8 = 5;

const KTAB_NIL: u64 = 0;
const KTAB_FALSE: u64 = 1;
const KTAB_TRUE: u64 = 2;
const KTAB_INT: u64 = 3;
const KTAB_NUM: u64 = 4;
const KTAB_STR_BASE: u64 = 5;

fn skip_ktab_entry(c: &mut ByteCursor<'_>) -> Result<()> {
    let tp: u64 = c.read_uleb128()?;
    match tp {
        KTAB_NIL | KTAB_FALSE | KTAB_TRUE => Ok(()),
        KTAB_INT => {
            let _v: u64 = c.read_uleb128()?;
            Ok(())
        }
        KTAB_NUM => {
            let _lo: u64 = c.read_uleb128()?;
            let _hi: u64 = c.read_uleb128()?;
            Ok(())
        }
        _ => {
            let len: u64 = tp.saturating_sub(KTAB_STR_BASE);
            let n: usize = usize::try_from(len).unwrap_or(0);
            let _raw: &[u8] = c.read_bytes(n)?;
            Ok(())
        }
    }
}

fn skip_ktab(c: &mut ByteCursor<'_>) -> Result<()> {
    let narray: u64 = c.read_uleb128()?;
    let nhash: u64 = c.read_uleb128()?;
    for _ in 0..narray {
        skip_ktab_entry(c)?;
    }
    for _ in 0..nhash {
        skip_ktab_entry(c)?;
        skip_ktab_entry(c)?;
    }
    Ok(())
}

fn read_proto(
    c: &mut ByteCursor<'_>,
    stripped: bool,
    _dialect: LuaDialect,
    proto_end: usize,
) -> Result<LuaProto> {
    let flags: u8 = c.read_u8()?;
    let num_params: u8 = c.read_u8()?;
    let framesize: u8 = c.read_u8()?;
    let size_uv: u8 = c.read_u8()?;
    let size_kgc: u64 = c.read_uleb128()?;
    let size_kn: u64 = c.read_uleb128()?;
    let size_bc: u64 = c.read_uleb128()?;

    let size_dbg: u64 = if stripped { 0 } else { c.read_uleb128()? };
    let first_line: u64 = if stripped || size_dbg == 0 {
        0
    } else {
        c.read_uleb128()?
    };
    let num_line: u64 = if stripped || size_dbg == 0 {
        0
    } else {
        c.read_uleb128()?
    };

    let mut code: Vec<u32> = Vec::with_capacity(usize::try_from(size_bc).unwrap_or(0));
    for _ in 0..size_bc {
        code.push(c.read_u32()?);
    }

    let mut upvalues: Vec<LuaUpvalueName> = Vec::with_capacity(usize::from(size_uv));
    for _ in 0..size_uv {
        let _slot: u16 = c.read_u16()?;
        upvalues.push(LuaUpvalueName {
            name: String::new(),
        });
    }

    let mut constants: Vec<LuaConstant> = Vec::new();
    for _ in 0..size_kgc {
        let tag: u64 = c.read_uleb128()?;
        match tag {
            t if t == u64::from(KGC_CHILD) => {
                constants.push(LuaConstant::Nil);
            }
            t if t == u64::from(KGC_TAB) => {
                skip_ktab(c)?;
                constants.push(LuaConstant::Nil);
            }
            t if t == u64::from(KGC_I64) => {
                let _lo: u64 = c.read_uleb128()?;
                let _hi: u64 = c.read_uleb128()?;
                constants.push(LuaConstant::Integer(0));
            }
            t if t == u64::from(KGC_U64) => {
                let _lo: u64 = c.read_uleb128()?;
                let _hi: u64 = c.read_uleb128()?;
                constants.push(LuaConstant::Integer(0));
            }
            t if t == u64::from(KGC_COMPLEX) => {
                let _re_lo: u64 = c.read_uleb128()?;
                let _re_hi: u64 = c.read_uleb128()?;
                let _im_lo: u64 = c.read_uleb128()?;
                let _im_hi: u64 = c.read_uleb128()?;
                constants.push(LuaConstant::Nil);
            }
            _ => {
                let strlen_raw: u64 = tag.saturating_sub(u64::from(KGC_STR_BASE));
                let strlen: usize = usize::try_from(strlen_raw).unwrap_or(0);
                let raw: &[u8] = c.read_bytes(strlen)?;
                let s: String = String::from_utf8_lossy(raw).into_owned();
                constants.push(LuaConstant::Str(s));
            }
        }
    }

    for _ in 0..size_kn {
        let lo: u64 = c.read_uleb128()?;
        if lo & 1 != 0 {
            let hi: u64 = c.read_uleb128()?;
            let raw: u64 = (hi << 32) | (lo >> 1);
            constants.push(LuaConstant::Number(f64::from_bits(raw)));
        } else {
            constants.push(LuaConstant::Integer((lo >> 1) as i64));
        }
    }

    while c.position() < proto_end {
        let _: u8 = c.read_u8()?;
    }

    Ok(LuaProto {
        source: None,
        line_defined: u32::try_from(first_line).unwrap_or(0),
        last_line_defined: u32::try_from(first_line.saturating_add(num_line)).unwrap_or(0),
        num_params,
        is_vararg: flags & 0x02,
        max_stack_size: framesize,
        code,
        constants,
        protos: Vec::new(),
        source_lines: Vec::new(),
        locals: Vec::new(),
        upvalues,
    })
}
