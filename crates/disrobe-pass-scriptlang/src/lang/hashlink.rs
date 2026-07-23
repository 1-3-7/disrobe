use std::collections::BTreeMap;
use std::fmt::Arguments;

use disrobe_bytes::{ByteReadError, ByteReader};
use serde::Serialize;
use thiserror::Error;

pub const HL_MAGIC: &[u8; 3] = b"HLB";
const HL_MIN_VERSION: u8 = 2;
const HL_MAX_VERSION: u8 = 5;

const WIRE_MIN_I32: usize = 4;
const WIRE_MIN_F64: usize = 8;
const WIRE_MIN_VARINT: usize = 1;

macro_rules! push_line {
    ($output:expr, $($arg:tt)*) => {
        push_format_line(&mut $output, format_args!($($arg)*))
    };
}

fn push_format_line(output: &mut String, args: Arguments<'_>) {
    match std::fmt::write(output, args) {
        Ok(()) => output.push('\n'),
        Err(error) => unreachable!("string formatting failed: {error:?}"),
    }
}

const OP_LAST: u8 = 102;
const OP_CALL_N: u8 = 29;
const OP_CALL_METHOD: u8 = 30;
const OP_CALL_THIS: u8 = 31;
const OP_CALL_CLOSURE: u8 = 32;
const OP_SWITCH: u8 = 70;
const OP_MAKE_ENUM: u8 = 90;

const OPCODE_NAMES: [&str; 103] = [
    "Mov",
    "Int",
    "Float",
    "Bool",
    "Bytes",
    "String",
    "Null",
    "Add",
    "Sub",
    "Mul",
    "SDiv",
    "UDiv",
    "SMod",
    "UMod",
    "Shl",
    "SShr",
    "UShr",
    "And",
    "Or",
    "Xor",
    "Neg",
    "Not",
    "Incr",
    "Decr",
    "Call0",
    "Call1",
    "Call2",
    "Call3",
    "Call4",
    "CallN",
    "CallMethod",
    "CallThis",
    "CallClosure",
    "StaticClosure",
    "InstanceClosure",
    "VirtualClosure",
    "GetGlobal",
    "SetGlobal",
    "Field",
    "SetField",
    "GetThis",
    "SetThis",
    "DynGet",
    "DynSet",
    "JTrue",
    "JFalse",
    "JNull",
    "JNotNull",
    "JSLt",
    "JSGte",
    "JSGt",
    "JSLte",
    "JULt",
    "JUGte",
    "JNotLt",
    "JNotGte",
    "JEq",
    "JNotEq",
    "JAlways",
    "ToDyn",
    "ToSFloat",
    "ToUFloat",
    "ToInt",
    "SafeCast",
    "UnsafeCast",
    "ToVirtual",
    "Label",
    "Ret",
    "Throw",
    "Rethrow",
    "Switch",
    "NullCheck",
    "Trap",
    "EndTrap",
    "GetI8",
    "GetI16",
    "GetMem",
    "GetArray",
    "SetI8",
    "SetI16",
    "SetMem",
    "SetArray",
    "New",
    "ArraySize",
    "Type",
    "GetType",
    "GetTID",
    "Ref",
    "Unref",
    "Setref",
    "MakeEnum",
    "EnumAlloc",
    "EnumIndex",
    "EnumField",
    "SetEnumField",
    "Assert",
    "RefData",
    "RefOffset",
    "Nop",
    "Prefetch",
    "Asm",
    "Catch",
    "Last",
];

const OP_NARGS: [i8; 103] = [
    2, 2, 2, 2, 2, 2, 1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 1, 1, 2, 3, 4, 5, 6, -1, -1,
    -1, -1, 2, 3, 3, 2, 2, 3, 3, 2, 2, 3, 3, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 2, 2, 2,
    2, 2, 2, 2, 0, 1, 1, 1, -1, 1, 2, 1, 3, 3, 3, 3, 3, 3, 3, 3, 1, 2, 2, 2, 2, 2, 2, 2, -1, 2, 2,
    4, 3, 0, 2, 3, 0, 3, 3, 1, 0,
];

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HlError {
    #[error("DR-HL-0001: input does not start with the HLB magic")]
    BadMagic,
    #[error("DR-HL-0002: unsupported HL bytecode version {0}")]
    UnsupportedVersion(u8),
    #[error("DR-HL-0003: truncated HL stream at offset {offset}")]
    Truncated { offset: usize },
    #[error("DR-HL-0004: negative index where an unsigned value was required at offset {offset}")]
    NegativeIndex { offset: usize },
    #[error("DR-HL-0005: type index {index} out of range (ntypes={ntypes})")]
    TypeIndexOutOfRange { index: i32, ntypes: usize },
    #[error("DR-HL-0006: string index {index} out of range (nstrings={nstrings})")]
    StringIndexOutOfRange { index: i32, nstrings: usize },
    #[error("DR-HL-0007: invalid opcode {op}")]
    InvalidOpcode { op: u8 },
    #[error("DR-HL-0008: invalid type kind {kind}")]
    InvalidTypeKind { kind: u8 },
    #[error("DR-HL-0009: malformed string block")]
    InvalidString,
}

type HlResult<T> = core::result::Result<T, HlError>;

#[derive(Debug, Clone, Serialize)]
pub struct HlFunData {
    pub args: Vec<usize>,
    pub ret: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct HlObjField {
    pub name: String,
    pub type_index: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct HlObjProto {
    pub name: String,
    pub findex: usize,
    pub pindex: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct HlObjData {
    pub name: String,
    pub super_type: Option<usize>,
    pub global: usize,
    pub fields: Vec<HlObjField>,
    pub protos: Vec<HlObjProto>,
    pub bindings: Vec<(usize, usize)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HlEnumConstruct {
    pub name: String,
    pub params: Vec<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HlEnumData {
    pub name: String,
    pub global: usize,
    pub constructs: Vec<HlEnumConstruct>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum HlType {
    Void,
    U8,
    U16,
    I32,
    I64,
    F32,
    F64,
    Bool,
    Bytes,
    Dyn,
    Array,
    Type,
    DynObj,
    Guid,
    Fun(HlFunData),
    Method(HlFunData),
    Obj(HlObjData),
    Struct(HlObjData),
    Ref(usize),
    Null(usize),
    Packed(usize),
    Virtual(Vec<HlObjField>),
    Abstract(String),
    Enum(HlEnumData),
}

#[derive(Debug, Clone, Serialize)]
pub struct HlNative {
    pub lib: String,
    pub name: String,
    pub type_index: usize,
    pub findex: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct HlOpcode {
    pub op: u8,
    pub p1: i32,
    pub p2: i32,
    pub p3: i32,
    pub extra: Vec<i32>,
}

impl HlOpcode {
    #[must_use]
    pub fn mnemonic(&self) -> &'static str {
        OPCODE_NAMES
            .get(self.op as usize)
            .copied()
            .unwrap_or("Unknown")
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HlFunction {
    pub type_index: usize,
    pub findex: usize,
    pub regs: Vec<usize>,
    pub ops: Vec<HlOpcode>,
    pub debug: Vec<(i32, i32)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HlConstant {
    pub global: usize,
    pub fields: Vec<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HlCode {
    pub version: u8,
    pub has_debug: bool,
    pub ints: Vec<i32>,
    pub floats: Vec<f64>,
    pub strings: Vec<String>,
    pub bytes_pos: Vec<usize>,
    pub debug_files: Vec<String>,
    pub types: Vec<HlType>,
    pub globals: Vec<usize>,
    pub natives: Vec<HlNative>,
    pub functions: Vec<HlFunction>,
    pub constants: Vec<HlConstant>,
    pub entrypoint: usize,
    pub bytes_consumed: usize,
    pub total_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HlSummary {
    pub version: u8,
    pub has_debug: bool,
    pub num_ints: usize,
    pub num_floats: usize,
    pub num_strings: usize,
    pub num_types: usize,
    pub num_globals: usize,
    pub num_natives: usize,
    pub num_functions: usize,
    pub num_constants: usize,
    pub num_opcodes: usize,
    pub entrypoint: usize,
    pub fully_parsed: bool,
    pub object_types: Vec<String>,
    pub enum_types: Vec<String>,
    pub method_names: Vec<String>,
    pub native_names: Vec<String>,
    pub source_files: Vec<String>,
}

struct Reader<'a> {
    reader: ByteReader<'a>,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8], pos: usize) -> HlResult<Self> {
        let mut reader: ByteReader<'a> = ByteReader::new(data);
        reader.seek(pos).map_err(Self::truncated)?;
        Ok(Self { reader })
    }

    fn truncated(error: ByteReadError) -> HlError {
        HlError::Truncated {
            offset: error.offset,
        }
    }

    fn read_byte(&mut self) -> HlResult<u8> {
        self.reader.read_u8().map_err(Self::truncated)
    }

    fn read_bytes(&mut self, count: usize) -> HlResult<&'a [u8]> {
        self.reader.read_bytes(count).map_err(Self::truncated)
    }

    #[inline]
    fn remaining(&self) -> usize {
        self.reader.remaining()
    }

    #[inline]
    fn bounded_capacity(&self, count: usize, elem_bytes: usize) -> usize {
        disrobe_bytes::bounded_element_capacity(count as u64, elem_bytes, self.remaining())
    }

    fn read_i32(&mut self) -> HlResult<i32> {
        self.reader.read_i32_le().map_err(Self::truncated)
    }

    fn read_f64(&mut self) -> HlResult<f64> {
        let bits: u64 = self.reader.read_u64_le().map_err(Self::truncated)?;
        Ok(f64::from_bits(bits))
    }

    fn read_index(&mut self) -> HlResult<i32> {
        let lead: u8 = self.read_byte()?;
        if lead & 0x80 == 0 {
            return Ok(i32::from(lead & 0x7f));
        }
        let negative: bool = lead & 0x20 != 0;
        if lead & 0x40 == 0 {
            let low: u8 = self.read_byte()?;
            let value: i32 = i32::from(low) | (i32::from(lead & 0x1f) << 8);
            return Ok(if negative { -value } else { value });
        }
        let byte1: u8 = self.read_byte()?;
        let byte2: u8 = self.read_byte()?;
        let byte3: u8 = self.read_byte()?;
        let value: i32 = (i32::from(lead & 0x1f) << 24)
            | (i32::from(byte1) << 16)
            | (i32::from(byte2) << 8)
            | i32::from(byte3);
        Ok(if negative { -value } else { value })
    }

    fn read_uindex(&mut self) -> HlResult<usize> {
        let value: i32 = self.read_index()?;
        usize::try_from(value).map_err(|_| HlError::NegativeIndex {
            offset: self.reader.position(),
        })
    }

    fn read_type_ref(&mut self, ntypes: usize) -> HlResult<usize> {
        let raw: i32 = self.read_index()?;
        let idx: usize = usize::try_from(raw)
            .map_err(|_| HlError::TypeIndexOutOfRange { index: raw, ntypes })?;
        if idx >= ntypes {
            return Err(HlError::TypeIndexOutOfRange { index: raw, ntypes });
        }
        Ok(idx)
    }

    fn read_string_ref(&mut self, nstrings: usize) -> HlResult<usize> {
        let raw: i32 = self.read_index()?;
        let idx: usize = usize::try_from(raw).map_err(|_| HlError::StringIndexOutOfRange {
            index: raw,
            nstrings,
        })?;
        if idx >= nstrings {
            return Err(HlError::StringIndexOutOfRange {
                index: raw,
                nstrings,
            });
        }
        Ok(idx)
    }

    fn read_strings(&mut self, count: usize) -> HlResult<Vec<String>> {
        let size: i32 = self.read_i32()?;
        let size: usize = usize::try_from(size).map_err(|_| HlError::InvalidString)?;
        let buf: &[u8] = self.read_bytes(size)?;
        let mut out: Vec<String> =
            Vec::with_capacity(self.bounded_capacity(count, WIRE_MIN_VARINT));
        let mut cursor: usize = 0usize;
        for _ in 0..count {
            let sz: usize = self.read_uindex()?;
            let end: usize = cursor.checked_add(sz).ok_or(HlError::InvalidString)?;
            let raw: &[u8] = buf.get(cursor..end).ok_or(HlError::InvalidString)?;
            out.push(String::from_utf8_lossy(raw).into_owned());
            cursor = end;
            match buf.get(cursor) {
                Some(0u8) => cursor += 1,
                _ => return Err(HlError::InvalidString),
            }
        }
        Ok(out)
    }

    fn read_fun_data(&mut self, ntypes: usize) -> HlResult<HlFunData> {
        let nargs: usize = usize::from(self.read_byte()?);
        let mut args: Vec<usize> = Vec::with_capacity(nargs);
        for _ in 0..nargs {
            args.push(self.read_type_ref(ntypes)?);
        }
        let ret: usize = self.read_type_ref(ntypes)?;
        Ok(HlFunData { args, ret })
    }

    fn read_obj_data(&mut self, ntypes: usize, strings: &[String]) -> HlResult<HlObjData> {
        let name_idx: usize = self.read_string_ref(strings.len())?;
        let super_raw: i32 = self.read_index()?;
        let super_type: Option<usize> = if super_raw < 0 {
            None
        } else {
            let candidate: usize = super_raw as usize;
            if candidate >= ntypes {
                return Err(HlError::TypeIndexOutOfRange {
                    index: super_raw,
                    ntypes,
                });
            }
            Some(candidate)
        };
        let global: usize = self.read_uindex()?;
        let nfields: usize = self.read_uindex()?;
        let nproto: usize = self.read_uindex()?;
        let nbindings: usize = self.read_uindex()?;
        let mut fields: Vec<HlObjField> =
            Vec::with_capacity(self.bounded_capacity(nfields, WIRE_MIN_VARINT));
        for _ in 0..nfields {
            let field_name: usize = self.read_string_ref(strings.len())?;
            let field_type: usize = self.read_type_ref(ntypes)?;
            fields.push(HlObjField {
                name: strings[field_name].clone(),
                type_index: field_type,
            });
        }
        let mut protos: Vec<HlObjProto> =
            Vec::with_capacity(self.bounded_capacity(nproto, WIRE_MIN_VARINT));
        for _ in 0..nproto {
            let proto_name: usize = self.read_string_ref(strings.len())?;
            let findex: usize = self.read_uindex()?;
            let pindex: i32 = self.read_index()?;
            protos.push(HlObjProto {
                name: strings[proto_name].clone(),
                findex,
                pindex,
            });
        }
        let mut bindings: Vec<(usize, usize)> =
            Vec::with_capacity(self.bounded_capacity(nbindings, WIRE_MIN_VARINT));
        for _ in 0..nbindings {
            let field_index: usize = self.read_uindex()?;
            let findex: usize = self.read_uindex()?;
            bindings.push((field_index, findex));
        }
        Ok(HlObjData {
            name: strings[name_idx].clone(),
            super_type,
            global,
            fields,
            protos,
            bindings,
        })
    }

    fn read_type(&mut self, ntypes: usize, strings: &[String]) -> HlResult<HlType> {
        let kind: u8 = self.read_byte()?;
        match kind {
            0 => Ok(HlType::Void),
            1 => Ok(HlType::U8),
            2 => Ok(HlType::U16),
            3 => Ok(HlType::I32),
            4 => Ok(HlType::I64),
            5 => Ok(HlType::F32),
            6 => Ok(HlType::F64),
            7 => Ok(HlType::Bool),
            8 => Ok(HlType::Bytes),
            9 => Ok(HlType::Dyn),
            10 => Ok(HlType::Fun(self.read_fun_data(ntypes)?)),
            11 => Ok(HlType::Obj(self.read_obj_data(ntypes, strings)?)),
            12 => Ok(HlType::Array),
            13 => Ok(HlType::Type),
            14 => Ok(HlType::Ref(self.read_type_ref(ntypes)?)),
            15 => {
                let nfields: usize = self.read_uindex()?;
                let mut fields: Vec<HlObjField> =
                    Vec::with_capacity(self.bounded_capacity(nfields, WIRE_MIN_VARINT));
                for _ in 0..nfields {
                    let field_name: usize = self.read_string_ref(strings.len())?;
                    let field_type: usize = self.read_type_ref(ntypes)?;
                    fields.push(HlObjField {
                        name: strings[field_name].clone(),
                        type_index: field_type,
                    });
                }
                Ok(HlType::Virtual(fields))
            }
            16 => Ok(HlType::DynObj),
            17 => {
                let name_idx: usize = self.read_string_ref(strings.len())?;
                Ok(HlType::Abstract(strings[name_idx].clone()))
            }
            18 => {
                let name_idx: usize = self.read_string_ref(strings.len())?;
                let global: usize = self.read_uindex()?;
                let nconstructs: usize = self.read_uindex()?;
                let mut constructs: Vec<HlEnumConstruct> =
                    Vec::with_capacity(self.bounded_capacity(nconstructs, WIRE_MIN_VARINT));
                for _ in 0..nconstructs {
                    let cname_idx: usize = self.read_string_ref(strings.len())?;
                    let nparams: usize = self.read_uindex()?;
                    let mut params: Vec<usize> =
                        Vec::with_capacity(self.bounded_capacity(nparams, WIRE_MIN_VARINT));
                    for _ in 0..nparams {
                        params.push(self.read_type_ref(ntypes)?);
                    }
                    constructs.push(HlEnumConstruct {
                        name: strings[cname_idx].clone(),
                        params,
                    });
                }
                Ok(HlType::Enum(HlEnumData {
                    name: strings[name_idx].clone(),
                    global,
                    constructs,
                }))
            }
            19 => Ok(HlType::Null(self.read_type_ref(ntypes)?)),
            20 => Ok(HlType::Method(self.read_fun_data(ntypes)?)),
            21 => Ok(HlType::Struct(self.read_obj_data(ntypes, strings)?)),
            22 => Ok(HlType::Packed(self.read_type_ref(ntypes)?)),
            23 => Ok(HlType::Guid),
            other => Err(HlError::InvalidTypeKind { kind: other }),
        }
    }

    fn read_opcode(&mut self) -> HlResult<HlOpcode> {
        let op: u8 = self.read_byte()?;
        if op >= OP_LAST {
            return Err(HlError::InvalidOpcode { op });
        }
        let nargs: i8 = OP_NARGS[op as usize];
        let mut p1: i32 = 0;
        let mut p2: i32 = 0;
        let mut p3: i32 = 0;
        let mut extra: Vec<i32> = Vec::new();
        match nargs {
            0 => {}
            1 => p1 = self.read_index()?,
            2 => {
                p1 = self.read_index()?;
                p2 = self.read_index()?;
            }
            3 => {
                p1 = self.read_index()?;
                p2 = self.read_index()?;
                p3 = self.read_index()?;
            }
            4 => {
                p1 = self.read_index()?;
                p2 = self.read_index()?;
                p3 = self.read_index()?;
                extra.push(self.read_index()?);
            }
            n if n > 4 => {
                p1 = self.read_index()?;
                p2 = self.read_index()?;
                p3 = self.read_index()?;
                let count: usize = (n as usize) - 3usize;
                for _ in 0..count {
                    extra.push(self.read_index()?);
                }
            }
            _ => match op {
                OP_CALL_N | OP_CALL_METHOD | OP_CALL_THIS | OP_CALL_CLOSURE | OP_MAKE_ENUM => {
                    p1 = self.read_index()?;
                    p2 = self.read_index()?;
                    let count: usize = usize::from(self.read_byte()?);
                    p3 = count as i32;
                    for _ in 0..count {
                        extra.push(self.read_index()?);
                    }
                }
                OP_SWITCH => {
                    p1 = self.read_uindex()? as i32;
                    let ncases: usize = self.read_uindex()?;
                    p2 = ncases as i32;
                    for _ in 0..ncases {
                        extra.push(self.read_uindex()? as i32);
                    }
                    p3 = self.read_uindex()? as i32;
                }
                other => return Err(HlError::InvalidOpcode { op: other }),
            },
        }
        Ok(HlOpcode {
            op,
            p1,
            p2,
            p3,
            extra,
        })
    }

    fn read_function(&mut self, ntypes: usize) -> HlResult<HlFunction> {
        let type_index: usize = self.read_type_ref(ntypes)?;
        let findex: usize = self.read_uindex()?;
        let nregs: usize = self.read_uindex()?;
        let nops: usize = self.read_uindex()?;
        let mut regs: Vec<usize> =
            Vec::with_capacity(self.bounded_capacity(nregs, WIRE_MIN_VARINT));
        for _ in 0..nregs {
            regs.push(self.read_type_ref(ntypes)?);
        }
        let mut ops: Vec<HlOpcode> =
            Vec::with_capacity(self.bounded_capacity(nops, WIRE_MIN_VARINT));
        for _ in 0..nops {
            ops.push(self.read_opcode()?);
        }
        Ok(HlFunction {
            type_index,
            findex,
            regs,
            ops,
            debug: Vec::new(),
        })
    }

    fn read_debug_infos(&mut self, nops: usize) -> HlResult<Vec<(i32, i32)>> {
        let mut out: Vec<(i32, i32)> = vec![(-1i32, 0i32); nops];
        let mut curfile: i32 = -1;
        let mut curline: i32 = 0;
        let mut i: usize = 0usize;
        while i < nops {
            let c: i32 = i32::from(self.read_byte()?);
            if c & 1 != 0 {
                let hi: i32 = c >> 1;
                let lo: i32 = i32::from(self.read_byte()?);
                curfile = (hi << 8) | lo;
            } else if c & 2 != 0 {
                let delta: i32 = c >> 6;
                let count: i32 = (c >> 2) & 15;
                for _ in 0..count {
                    if i >= nops {
                        return Err(HlError::Truncated {
                            offset: self.reader.position(),
                        });
                    }
                    out[i] = (curfile, curline);
                    i += 1;
                }
                curline += delta;
            } else if c & 4 != 0 {
                curline += c >> 3;
                out[i] = (curfile, curline);
                i += 1;
            } else {
                let b2: i32 = i32::from(self.read_byte()?);
                let b3: i32 = i32::from(self.read_byte()?);
                curline = (c >> 3) | (b2 << 5) | (b3 << 13);
                out[i] = (curfile, curline);
                i += 1;
            }
        }
        Ok(out)
    }
}

pub fn read_code(data: &[u8]) -> HlResult<HlCode> {
    if data.len() < 4 || &data[0..3] != HL_MAGIC {
        return Err(HlError::BadMagic);
    }
    let mut r: Reader<'_> = Reader::new(data, 3)?;
    let version: u8 = r.read_byte()?;
    if !(HL_MIN_VERSION..=HL_MAX_VERSION).contains(&version) {
        return Err(HlError::UnsupportedVersion(version));
    }
    let flags: usize = r.read_uindex()?;
    let has_debug: bool = flags & 1 == 1;
    let nints: usize = r.read_uindex()?;
    let nfloats: usize = r.read_uindex()?;
    let nstrings: usize = r.read_uindex()?;
    let nbytes: usize = if version >= 5 {
        r.read_uindex()?
    } else {
        0usize
    };
    let ntypes: usize = r.read_uindex()?;
    let nglobals: usize = r.read_uindex()?;
    let nnatives: usize = r.read_uindex()?;
    let nfunctions: usize = r.read_uindex()?;
    let nconstants: usize = if version >= 4 {
        r.read_uindex()?
    } else {
        0usize
    };
    let entrypoint: usize = r.read_uindex()?;

    let mut ints: Vec<i32> = Vec::with_capacity(r.bounded_capacity(nints, WIRE_MIN_I32));
    for _ in 0..nints {
        ints.push(r.read_i32()?);
    }
    let mut floats: Vec<f64> = Vec::with_capacity(r.bounded_capacity(nfloats, WIRE_MIN_F64));
    for _ in 0..nfloats {
        floats.push(r.read_f64()?);
    }
    let strings: Vec<String> = r.read_strings(nstrings)?;

    let mut bytes_pos: Vec<usize> = Vec::new();
    if version >= 5 {
        let size: i32 = r.read_i32()?;
        let size: usize = usize::try_from(size).map_err(|_| HlError::InvalidString)?;
        let _: &[u8] = r.read_bytes(size)?;
        bytes_pos = Vec::with_capacity(r.bounded_capacity(nbytes, WIRE_MIN_VARINT));
        for _ in 0..nbytes {
            bytes_pos.push(r.read_uindex()?);
        }
    }

    let debug_files: Vec<String> = if has_debug {
        let ndebug: usize = r.read_uindex()?;
        r.read_strings(ndebug)?
    } else {
        Vec::new()
    };

    let mut types: Vec<HlType> = Vec::with_capacity(r.bounded_capacity(ntypes, WIRE_MIN_VARINT));
    for _ in 0..ntypes {
        types.push(r.read_type(ntypes, &strings)?);
    }

    let mut globals: Vec<usize> = Vec::with_capacity(r.bounded_capacity(nglobals, WIRE_MIN_VARINT));
    for _ in 0..nglobals {
        globals.push(r.read_type_ref(ntypes)?);
    }

    let mut natives: Vec<HlNative> =
        Vec::with_capacity(r.bounded_capacity(nnatives, WIRE_MIN_VARINT));
    for _ in 0..nnatives {
        let lib_idx: usize = r.read_string_ref(nstrings)?;
        let name_idx: usize = r.read_string_ref(nstrings)?;
        let type_index: usize = r.read_type_ref(ntypes)?;
        let findex: usize = r.read_uindex()?;
        natives.push(HlNative {
            lib: strings[lib_idx].clone(),
            name: strings[name_idx].clone(),
            type_index,
            findex,
        });
    }

    let mut functions: Vec<HlFunction> =
        Vec::with_capacity(r.bounded_capacity(nfunctions, WIRE_MIN_VARINT));
    for _ in 0..nfunctions {
        let mut function: HlFunction = r.read_function(ntypes)?;
        if has_debug {
            function.debug = r.read_debug_infos(function.ops.len())?;
            if version >= 3 {
                let nassigns: usize = r.read_uindex()?;
                for _ in 0..nassigns {
                    let _: usize = r.read_uindex()?;
                    let _: i32 = r.read_index()?;
                }
            }
        }
        functions.push(function);
    }

    let mut constants: Vec<HlConstant> =
        Vec::with_capacity(r.bounded_capacity(nconstants, WIRE_MIN_VARINT));
    for _ in 0..nconstants {
        let global: usize = r.read_uindex()?;
        let nfields: usize = r.read_uindex()?;
        let mut fields: Vec<usize> =
            Vec::with_capacity(r.bounded_capacity(nfields, WIRE_MIN_VARINT));
        for _ in 0..nfields {
            fields.push(r.read_uindex()?);
        }
        constants.push(HlConstant { global, fields });
    }

    Ok(HlCode {
        version,
        has_debug,
        ints,
        floats,
        strings,
        bytes_pos,
        debug_files,
        types,
        globals,
        natives,
        functions,
        constants,
        entrypoint,
        bytes_consumed: r.reader.position(),
        total_len: data.len(),
    })
}

const TYPE_NAME_DEPTH: u32 = 8;

fn dedup_sorted(items: &mut Vec<String>) {
    items.retain(|value: &String| !value.is_empty());
    items.sort_unstable();
    items.dedup();
}

fn is_std_source(path: &str) -> bool {
    path.contains("/_std/")
        || path.contains("_std/")
        || path.contains("/std/")
        || path.starts_with("hl/")
        || path.contains("/hl/")
        || path.contains("haxe/")
}

fn leaf_name(path: &str) -> String {
    path.rsplit(['/', '\\'])
        .next()
        .map_or(path, |value: &str| value)
        .to_owned()
}

impl HlCode {
    #[must_use]
    pub fn fully_parsed(&self) -> bool {
        self.bytes_consumed == self.total_len
    }

    #[must_use]
    pub fn object_type_names(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .types
            .iter()
            .filter_map(|t: &HlType| match t {
                HlType::Obj(o) | HlType::Struct(o) => Some(o.name.clone()),
                _ => None,
            })
            .collect();
        dedup_sorted(&mut out);
        out
    }

    #[must_use]
    pub fn enum_type_names(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .types
            .iter()
            .filter_map(|t: &HlType| match t {
                HlType::Enum(e) => Some(e.name.clone()),
                _ => None,
            })
            .collect();
        dedup_sorted(&mut out);
        out
    }

    #[must_use]
    pub fn method_names(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for t in &self.types {
            if let HlType::Obj(o) | HlType::Struct(o) = t {
                for proto in &o.protos {
                    out.push(proto.name.clone());
                }
                for field in &o.fields {
                    if matches!(
                        self.types.get(field.type_index),
                        Some(HlType::Fun(_) | HlType::Method(_))
                    ) {
                        out.push(field.name.clone());
                    }
                }
            }
        }
        dedup_sorted(&mut out);
        out
    }

    #[must_use]
    pub fn native_labels(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .natives
            .iter()
            .map(|n: &HlNative| format!("{}/{}", n.lib, n.name))
            .collect();
        dedup_sorted(&mut out);
        out
    }

    #[must_use]
    pub fn user_source_files(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .debug_files
            .iter()
            .filter(|f: &&String| f.ends_with(".hx") && !is_std_source(f))
            .map(|f: &String| leaf_name(f))
            .collect();
        dedup_sorted(&mut out);
        out
    }

    #[must_use]
    pub fn function_by_findex(&self, findex: usize) -> Option<&HlFunction> {
        self.functions
            .iter()
            .find(|f: &&HlFunction| f.findex == findex)
    }

    #[must_use]
    pub fn entry_function(&self) -> Option<&HlFunction> {
        self.function_by_findex(self.entrypoint)
    }

    #[must_use]
    pub fn function_name_map(&self) -> BTreeMap<usize, String> {
        let mut map: BTreeMap<usize, String> = BTreeMap::new();
        for t in &self.types {
            if let HlType::Obj(o) | HlType::Struct(o) = t {
                for proto in &o.protos {
                    map.entry(proto.findex)
                        .or_insert_with(|| format!("{}.{}", o.name, proto.name));
                }
                for &(field_index, findex) in &o.bindings {
                    if let Some(field) = o.fields.get(field_index) {
                        map.entry(findex)
                            .or_insert_with(|| format!("{}.{}", o.name, field.name));
                    }
                }
            }
        }
        for native in &self.natives {
            map.entry(native.findex)
                .or_insert_with(|| format!("{}/{}", native.lib, native.name));
        }
        map
    }

    #[must_use]
    pub fn type_name(&self, index: usize) -> String {
        self.type_name_depth(index, 0)
    }

    fn type_name_depth(&self, index: usize, depth: u32) -> String {
        if depth >= TYPE_NAME_DEPTH {
            return format!("type@{index}");
        }
        let Some(t): Option<&HlType> = self.types.get(index) else {
            return format!("type@{index}");
        };
        match t {
            HlType::Void => "void".to_owned(),
            HlType::U8 => "u8".to_owned(),
            HlType::U16 => "u16".to_owned(),
            HlType::I32 => "i32".to_owned(),
            HlType::I64 => "i64".to_owned(),
            HlType::F32 => "f32".to_owned(),
            HlType::F64 => "f64".to_owned(),
            HlType::Bool => "bool".to_owned(),
            HlType::Bytes => "bytes".to_owned(),
            HlType::Dyn => "dyn".to_owned(),
            HlType::Array => "array".to_owned(),
            HlType::Type => "type".to_owned(),
            HlType::DynObj => "dynobj".to_owned(),
            HlType::Guid => "guid".to_owned(),
            HlType::Fun(d) | HlType::Method(d) => {
                let args: Vec<String> = d
                    .args
                    .iter()
                    .map(|&a: &usize| self.type_name_depth(a, depth + 1))
                    .collect();
                format!(
                    "({}) -> {}",
                    args.join(", "),
                    self.type_name_depth(d.ret, depth + 1)
                )
            }
            HlType::Obj(o) | HlType::Struct(o) => o.name.clone(),
            HlType::Ref(t) => format!("ref<{}>", self.type_name_depth(*t, depth + 1)),
            HlType::Null(t) => format!("null<{}>", self.type_name_depth(*t, depth + 1)),
            HlType::Packed(t) => format!("packed<{}>", self.type_name_depth(*t, depth + 1)),
            HlType::Virtual(_) => "virtual".to_owned(),
            HlType::Abstract(name) => name.clone(),
            HlType::Enum(e) => e.name.clone(),
        }
    }

    #[must_use]
    pub fn summary(&self) -> HlSummary {
        let num_opcodes: usize = self
            .functions
            .iter()
            .map(|f: &HlFunction| f.ops.len())
            .sum();
        HlSummary {
            version: self.version,
            has_debug: self.has_debug,
            num_ints: self.ints.len(),
            num_floats: self.floats.len(),
            num_strings: self.strings.len(),
            num_types: self.types.len(),
            num_globals: self.globals.len(),
            num_natives: self.natives.len(),
            num_functions: self.functions.len(),
            num_constants: self.constants.len(),
            num_opcodes,
            entrypoint: self.entrypoint,
            fully_parsed: self.fully_parsed(),
            object_types: self.object_type_names(),
            enum_types: self.enum_type_names(),
            method_names: self.method_names(),
            native_names: self.native_labels(),
            source_files: self.user_source_files(),
        }
    }

    #[must_use]
    pub fn disassemble(&self) -> String {
        let names: BTreeMap<usize, String> = self.function_name_map();
        let mut out: String = String::new();
        push_line!(
            out,
            "; HashLink v{} functions={} types={} natives={} globals={} entry=@{}",
            self.version,
            self.functions.len(),
            self.types.len(),
            self.natives.len(),
            self.globals.len(),
            self.entrypoint
        );
        for function in &self.functions {
            out.push('\n');
            out.push_str(&self.disassemble_function(function, &names));
        }
        out
    }

    #[must_use]
    pub fn disassemble_function(
        &self,
        function: &HlFunction,
        names: &BTreeMap<usize, String>,
    ) -> String {
        let name: String = names
            .get(&function.findex)
            .cloned()
            .unwrap_or_else(|| format!("fun@{}", function.findex));
        let (arg_types, ret): (Vec<usize>, Option<usize>) =
            match self.types.get(function.type_index) {
                Some(HlType::Fun(d) | HlType::Method(d)) => (d.args.clone(), Some(d.ret)),
                _ => (Vec::new(), None),
            };
        let params: String = arg_types
            .iter()
            .enumerate()
            .map(|(i, &t): (usize, &usize)| format!("r{i}: {}", self.type_name(t)))
            .collect::<Vec<String>>()
            .join(", ");
        let ret_name: String = ret.map_or_else(|| "?".to_owned(), |t: usize| self.type_name(t));
        let mut out: String = String::new();
        push_line!(
            out,
            "fn {name}({params}) -> {ret_name}  [findex {}, {} regs, {} ops]",
            function.findex,
            function.regs.len(),
            function.ops.len()
        );
        for (i, &reg) in function.regs.iter().enumerate() {
            push_line!(out, "  reg r{i}: {}", self.type_name(reg));
        }
        for (ip, op) in function.ops.iter().enumerate() {
            let operands: String = self.operands_text(op, ip, names);
            let line: String = function
                .debug
                .get(ip)
                .filter(|_| self.has_debug)
                .map(|&(file, line): &(i32, i32)| {
                    let file_name: &str = usize::try_from(file)
                        .ok()
                        .and_then(|idx: usize| self.debug_files.get(idx))
                        .map_or("?", |value: &String| value.as_str());
                    format!(
                        "  {ip:>4}: {:<15} {operands}   ; {file_name}:{line}\n",
                        op.mnemonic()
                    )
                })
                .unwrap_or_else(|| format!("  {ip:>4}: {:<15} {operands}\n", op.mnemonic()));
            out.push_str(&line);
        }
        out
    }

    fn string_operand(&self, idx: i32) -> String {
        let Some(s): Option<&String> = usize::try_from(idx)
            .ok()
            .and_then(|i: usize| self.strings.get(i))
        else {
            return format!("str@{idx}");
        };
        let mut shown: String = String::new();
        for ch in s.chars().take(24) {
            for escaped in ch.escape_default() {
                shown.push(escaped);
            }
        }
        if s.chars().count() > 24 {
            shown.push_str("..");
        }
        format!("str@{idx} \"{shown}\"")
    }

    fn int_operand(&self, idx: i32) -> String {
        usize::try_from(idx)
            .ok()
            .and_then(|i: usize| self.ints.get(i))
            .map_or_else(|| format!("int@{idx}"), |v: &i32| v.to_string())
    }

    fn float_operand(&self, idx: i32) -> String {
        usize::try_from(idx)
            .ok()
            .and_then(|i: usize| self.floats.get(i))
            .map_or_else(|| format!("float@{idx}"), |v: &f64| v.to_string())
    }

    fn operands_text(&self, op: &HlOpcode, ip: usize, names: &BTreeMap<usize, String>) -> String {
        let fn_of = |idx: i32| -> String {
            usize::try_from(idx)
                .ok()
                .and_then(|i: usize| names.get(&i))
                .cloned()
                .unwrap_or_else(|| format!("fun@{idx}"))
        };
        let jump = |off: i32| -> String {
            let target: i64 = ip as i64 + 1i64 + i64::from(off);
            format!("@{target}")
        };
        let tokens: Vec<String> = match op.op {
            0 => vec![format!("r{}", op.p1), format!("r{}", op.p2)],
            1 => vec![format!("r{}", op.p1), self.int_operand(op.p2)],
            2 => vec![format!("r{}", op.p1), self.float_operand(op.p2)],
            3 => vec![format!("r{}", op.p1), (op.p2 != 0).to_string()],
            4 => vec![format!("r{}", op.p1), format!("bytes@{}", op.p2)],
            5 => vec![format!("r{}", op.p1), self.string_operand(op.p2)],
            6 => vec![format!("r{}", op.p1)],
            7..=19 => vec![
                format!("r{}", op.p1),
                format!("r{}", op.p2),
                format!("r{}", op.p3),
            ],
            20 | 21 => vec![format!("r{}", op.p1), format!("r{}", op.p2)],
            22 | 23 => vec![format!("r{}", op.p1)],
            24 => vec![format!("r{}", op.p1), format!("{}()", fn_of(op.p2))],
            25 => vec![format!("r{}", op.p1), fn_of(op.p2), format!("r{}", op.p3)],
            26 => vec![
                format!("r{}", op.p1),
                fn_of(op.p2),
                format!("r{}", op.p3),
                format!("r{}", op.extra.first().copied().unwrap_or(0)),
            ],
            27 | 28 => {
                let mut t: Vec<String> =
                    vec![format!("r{}", op.p1), fn_of(op.p2), format!("r{}", op.p3)];
                t.extend(op.extra.iter().map(|&a: &i32| format!("r{a}")));
                t
            }
            29 => {
                let mut t: Vec<String> = vec![format!("r{}", op.p1), fn_of(op.p2)];
                t.extend(op.extra.iter().map(|&a: &i32| format!("r{a}")));
                t
            }
            30 | 31 => {
                let mut t: Vec<String> = vec![format!("r{}", op.p1), format!("proto#{}", op.p2)];
                t.extend(op.extra.iter().map(|&a: &i32| format!("r{a}")));
                t
            }
            32 => {
                let mut t: Vec<String> = vec![format!("r{}", op.p1), format!("r{}", op.p2)];
                t.extend(op.extra.iter().map(|&a: &i32| format!("r{a}")));
                t
            }
            33 => vec![format!("r{}", op.p1), fn_of(op.p2)],
            34 => vec![format!("r{}", op.p1), format!("r{}", op.p2), fn_of(op.p3)],
            35 => vec![
                format!("r{}", op.p1),
                format!("r{}", op.p2),
                format!("proto#{}", op.p3),
            ],
            36 => vec![format!("r{}", op.p1), format!("global@{}", op.p2)],
            37 => vec![format!("global@{}", op.p1), format!("r{}", op.p2)],
            38 => vec![
                format!("r{}", op.p1),
                format!("r{}", op.p2),
                format!("field#{}", op.p3),
            ],
            39 => vec![
                format!("r{}", op.p1),
                format!("field#{}", op.p2),
                format!("r{}", op.p3),
            ],
            40 => vec![format!("r{}", op.p1), format!("field#{}", op.p2)],
            41 => vec![format!("field#{}", op.p1), format!("r{}", op.p2)],
            42 => vec![
                format!("r{}", op.p1),
                format!("r{}", op.p2),
                self.string_operand(op.p3),
            ],
            43 => vec![
                format!("r{}", op.p1),
                self.string_operand(op.p2),
                format!("r{}", op.p3),
            ],
            44..=47 => vec![format!("r{}", op.p1), jump(op.p2)],
            48..=57 => vec![format!("r{}", op.p1), format!("r{}", op.p2), jump(op.p3)],
            58 => vec![jump(op.p1)],
            59..=65 => vec![format!("r{}", op.p1), format!("r{}", op.p2)],
            66 => Vec::new(),
            67..=69 => vec![format!("r{}", op.p1)],
            70 => {
                let mut t: Vec<String> = vec![format!("r{}", op.p1)];
                t.extend(op.extra.iter().map(|&off: &i32| jump(off)));
                t.push(format!("end:{}", jump(op.p3)));
                t
            }
            71 => vec![format!("r{}", op.p1)],
            72 => vec![format!("r{}", op.p1), jump(op.p2)],
            73 => vec![format!("r{}", op.p1)],
            74..=81 => vec![
                format!("r{}", op.p1),
                format!("r{}", op.p2),
                format!("r{}", op.p3),
            ],
            82 => vec![format!("r{}", op.p1)],
            83 => vec![format!("r{}", op.p1), format!("r{}", op.p2)],
            84 => vec![format!("r{}", op.p1), self.type_name_or_index(op.p2)],
            85..=89 => vec![format!("r{}", op.p1), format!("r{}", op.p2)],
            90 => {
                let mut t: Vec<String> =
                    vec![format!("r{}", op.p1), format!("construct#{}", op.p2)];
                t.extend(op.extra.iter().map(|&a: &i32| format!("r{a}")));
                t
            }
            91 => vec![format!("r{}", op.p1), format!("construct#{}", op.p2)],
            92 => vec![format!("r{}", op.p1), format!("r{}", op.p2)],
            93 => vec![
                format!("r{}", op.p1),
                format!("r{}", op.p2),
                format!("construct#{}", op.p3),
                format!("field#{}", op.extra.first().copied().unwrap_or(0)),
            ],
            94 => vec![
                format!("r{}", op.p1),
                format!("field#{}", op.p2),
                format!("r{}", op.p3),
            ],
            95 => Vec::new(),
            96 => vec![format!("r{}", op.p1), format!("r{}", op.p2)],
            97 => vec![
                format!("r{}", op.p1),
                format!("r{}", op.p2),
                op.p3.to_string(),
            ],
            98 => Vec::new(),
            99 => vec![
                format!("r{}", op.p1),
                format!("field#{}", op.p2),
                format!("mode:{}", op.p3),
            ],
            100 => vec![op.p1.to_string(), op.p2.to_string(), op.p3.to_string()],
            101 => vec![jump(op.p1)],
            _ => vec![op.p1.to_string(), op.p2.to_string(), op.p3.to_string()],
        };
        tokens.join(", ")
    }

    fn type_name_or_index(&self, idx: i32) -> String {
        usize::try_from(idx).map_or_else(|_| format!("type@{idx}"), |i: usize| self.type_name(i))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn read_index_single_byte_is_seven_bit() {
        let mut r: Reader<'_> = Reader::new(&[0x2e], 0).unwrap();
        assert_eq!(r.read_index().unwrap(), 46);
    }

    #[test]
    fn read_index_two_byte_positive() {
        let mut r: Reader<'_> = Reader::new(&[0x81, 0x7e], 0).unwrap();
        assert_eq!(r.read_index().unwrap(), 0x17e);
    }

    #[test]
    fn read_index_two_byte_negative() {
        let mut r: Reader<'_> = Reader::new(&[0xa1, 0x00], 0).unwrap();
        assert_eq!(r.read_index().unwrap(), -0x100);
    }

    #[test]
    fn opcode_tables_are_aligned() {
        assert_eq!(OPCODE_NAMES.len(), OP_NARGS.len());
        assert_eq!(OPCODE_NAMES.len(), 103);
        assert_eq!((OPCODE_NAMES[0], OP_NARGS[0]), ("Mov", 2));
        assert_eq!((OPCODE_NAMES[6], OP_NARGS[6]), ("Null", 1));
        assert_eq!((OPCODE_NAMES[24], OP_NARGS[24]), ("Call0", 2));
        assert_eq!((OPCODE_NAMES[26], OP_NARGS[26]), ("Call2", 4));
        assert_eq!((OPCODE_NAMES[28], OP_NARGS[28]), ("Call4", 6));
        assert_eq!((OPCODE_NAMES[58], OP_NARGS[58]), ("JAlways", 1));
        assert_eq!(
            (
                OPCODE_NAMES[OP_MAKE_ENUM as usize],
                OP_NARGS[OP_MAKE_ENUM as usize]
            ),
            ("MakeEnum", -1)
        );
        assert_eq!((OPCODE_NAMES[93], OP_NARGS[93]), ("EnumField", 4));
        assert_eq!(OPCODE_NAMES[OP_SWITCH as usize], "Switch");
        assert_eq!(OP_NARGS[OP_SWITCH as usize], -1);
        assert_eq!(OPCODE_NAMES[OP_LAST as usize], "Last");
    }

    #[test]
    fn rejects_non_hlb() {
        assert_eq!(
            read_code(b"not hl bytecode").unwrap_err(),
            HlError::BadMagic
        );
    }

    #[test]
    fn truncated_header_reports_offset_after_version() {
        assert_eq!(
            read_code(b"HLB\x02").unwrap_err(),
            HlError::Truncated { offset: 4 }
        );
    }

    #[test]
    fn huge_ntypes_count_is_capped_not_aborted() {
        let ntypes_overflow: [u8; 4] = [0xdf, 0xff, 0xff, 0xff];
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(HL_MAGIC);
        data.push(HL_MIN_VERSION);
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&ntypes_overflow);
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&0i32.to_le_bytes());
        assert!(read_code(&data).is_err());
    }

    #[test]
    fn huge_nints_count_is_capped_not_aborted() {
        let nints_overflow: [u8; 4] = [0xdf, 0xff, 0xff, 0xff];
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(HL_MAGIC);
        data.push(HL_MIN_VERSION);
        data.push(0x00);
        data.extend_from_slice(&nints_overflow);
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&0i32.to_le_bytes());
        assert!(read_code(&data).is_err());
    }

    #[test]
    fn minimal_module_with_ints_still_parses() {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(HL_MAGIC);
        data.push(HL_MIN_VERSION);
        data.push(0x00);
        data.push(0x02);
        data.extend_from_slice(&[0x00, 0x00]);
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        data.push(0x00);
        data.extend_from_slice(&42i32.to_le_bytes());
        data.extend_from_slice(&7i32.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());
        let code: HlCode = read_code(&data).unwrap();
        assert_eq!(code.ints, vec![42, 7]);
        assert!(code.fully_parsed());
    }
}
