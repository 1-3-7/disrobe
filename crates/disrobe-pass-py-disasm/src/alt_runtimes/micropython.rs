use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::alt_runtimes::{AltRuntimeError, Result};

const MPY_MAGIC: u8 = b'M';
const MPY_MIN_VERSION: u8 = 0;
const MPY_MAX_VERSION: u8 = 6;
const MPY_FEATURE_BYTECODE: u8 = 0x00;
const MPY_FEATURE_ARCH_FLAGS_PRESENT: u8 = 0x40;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpyVersion(pub u8);

impl MpyVersion {
    #[must_use]
    pub const fn raw(self) -> u8 {
        self.0
    }

    #[must_use]
    pub const fn supports_native(self) -> bool {
        self.0 >= 3
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicroPythonModule {
    pub version: MpyVersion,
    pub features: u8,
    pub small_int_bits: u8,
    pub raw_code: Vec<u8>,
    pub opcode_histogram: BTreeMap<u8, u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpyInsn {
    pub offset: usize,
    pub opcode: u8,
}

pub fn parse(bytes: &[u8]) -> Result<MicroPythonModule> {
    if bytes.len() < 4 {
        return Err(AltRuntimeError::Truncated {
            offset: 0,
            needed: 4,
            had: bytes.len(),
        });
    }
    if bytes[0] != MPY_MAGIC {
        return Err(AltRuntimeError::BadMagic {
            runtime: "micropython",
            got: u32::from(bytes[0]),
        });
    }
    let version: u8 = bytes[1];
    if !(MPY_MIN_VERSION..=MPY_MAX_VERSION).contains(&version) {
        return Err(AltRuntimeError::UnsupportedVersion {
            runtime: "micropython",
            version: u32::from(version),
        });
    }
    let features: u8 = bytes[2];
    let small_int_bits: u8 = bytes[3];
    let payload_off: usize = payload_start(bytes)?;
    let raw_code: Vec<u8> = bytes[payload_off..].to_vec();
    let opcode_histogram: BTreeMap<u8, u32> = histogram(&raw_code);
    Ok(MicroPythonModule {
        version: MpyVersion(version),
        features,
        small_int_bits,
        raw_code,
        opcode_histogram,
    })
}

#[must_use]
pub fn detect(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && bytes[0] == MPY_MAGIC
        && (MPY_MIN_VERSION..=MPY_MAX_VERSION).contains(&bytes[1])
        && (bytes[2] & 0x03) == MPY_FEATURE_BYTECODE
}

fn payload_start(bytes: &[u8]) -> Result<usize> {
    if bytes.len() < 4 {
        return Err(AltRuntimeError::Truncated {
            offset: 0,
            needed: 4,
            had: bytes.len(),
        });
    }
    if bytes[2] & MPY_FEATURE_ARCH_FLAGS_PRESENT == 0 {
        return Ok(4);
    }
    let mut cursor: Cursor<'_> = Cursor::new(bytes);
    cursor.pos = 4;
    cursor.uint()?;
    Ok(cursor.pos)
}

impl MicroPythonModule {
    pub fn opcodes(&self) -> impl Iterator<Item = MpyInsn> + '_ {
        self.raw_code
            .iter()
            .enumerate()
            .map(|(i, &op): (usize, &u8)| -> MpyInsn {
                MpyInsn {
                    offset: i,
                    opcode: op,
                }
            })
    }
}

fn histogram(payload: &[u8]) -> BTreeMap<u8, u32> {
    let mut out: BTreeMap<u8, u32> = BTreeMap::new();
    for &b in payload {
        *out.entry(b).or_insert(0u32) += 1u32;
    }
    out
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn byte(&mut self) -> Result<u8> {
        let b: u8 = *self.data.get(self.pos).ok_or(AltRuntimeError::Truncated {
            offset: self.pos,
            needed: 1,
            had: 0,
        })?;
        self.pos += 1;
        Ok(b)
    }

    const fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn uint(&mut self) -> Result<u64> {
        let start: usize = self.pos;
        let mut value: u64 = 0;
        loop {
            let b: u8 = self.byte()?;
            if value >> 57 != 0 {
                return Err(AltRuntimeError::BadEncoding {
                    field: "varuint",
                    offset: start,
                });
            }
            value = (value << 7) | u64::from(b & 0x7f);
            if b & 0x80 == 0 {
                return Ok(value);
            }
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let had: usize = self.data.len().saturating_sub(self.pos);
        let end: usize = self.pos.checked_add(n).ok_or(AltRuntimeError::Truncated {
            offset: self.pos,
            needed: n,
            had,
        })?;
        let slice: &[u8] = self
            .data
            .get(self.pos..end)
            .ok_or(AltRuntimeError::Truncated {
                offset: self.pos,
                needed: n,
                had,
            })?;
        self.pos = end;
        Ok(slice)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpyBytecodeModule {
    pub version: u8,
    pub small_int_bits: u8,
    pub qstrs: Vec<String>,
    pub objects: Vec<String>,
    pub typed_objects: Vec<MpyObject>,
    pub function: MpyFunction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpyFunction {
    pub simple_name: String,
    pub n_state: u32,
    pub n_exc_stack: u32,
    pub scope_flags: u32,
    pub n_pos_args: u32,
    pub n_kwonly_args: u32,
    pub n_def_pos_args: u32,
    pub instructions: Vec<MpyDecodedInsn>,
    pub children: Vec<Self>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpyDecodedInsn {
    pub offset: usize,
    pub opcode: u8,
    pub mnemonic: String,
    pub operand: Option<String>,
    pub arg: MpyArg,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MpyArg {
    None,
    Qstr { index: u32, text: String },
    Uint(u64),
    SmallInt(i64),
    Object { index: u32 },
    RelTarget { byte_offset: usize },
    UnwindTarget { byte_offset: usize, depth: u8 },
    MakeClosure { table_index: u32, n_closed: u8 },
    UnaryOp(u8),
    BinaryOp(u8),
    UndecodableTail { opcode: u8, undecoded_bytes: usize },
}

pub fn parse_bytecode(bytes: &[u8]) -> Result<MpyBytecodeModule> {
    if bytes.len() < 4 {
        return Err(AltRuntimeError::Truncated {
            offset: 0,
            needed: 4,
            had: bytes.len(),
        });
    }
    if bytes[0] != MPY_MAGIC {
        return Err(AltRuntimeError::BadMagic {
            runtime: "micropython",
            got: u32::from(bytes[0]),
        });
    }
    let version: u8 = bytes[1];
    if !(MPY_MIN_VERSION..=MPY_MAX_VERSION).contains(&version) {
        return Err(AltRuntimeError::UnsupportedVersion {
            runtime: "micropython",
            version: u32::from(version),
        });
    }
    if (bytes[2] & 0x03) != MPY_FEATURE_BYTECODE {
        return Err(AltRuntimeError::NotDetected("micropython-bytecode"));
    }
    let small_int_bits: u8 = bytes[3];
    let payload_off: usize = payload_start(bytes)?;
    let mut cursor: Cursor<'_> = Cursor::new(bytes);
    cursor.pos = payload_off;
    let n_qstr: u64 = cursor.uint()?;
    let n_obj: u64 = cursor.uint()?;
    let qstr_count: usize = bounded_table_count(n_qstr, cursor.remaining(), "n_qstr", cursor.pos)?;
    let mut qstrs: Vec<String> = Vec::with_capacity(qstr_count.min(MAX_TABLE_PREALLOC));
    for _ in 0..qstr_count {
        qstrs.push(read_qstr(&mut cursor)?);
    }
    let obj_count: usize = bounded_table_count(n_obj, cursor.remaining(), "n_obj", cursor.pos)?;
    let mut typed_objects: Vec<MpyObject> = Vec::with_capacity(obj_count.min(MAX_TABLE_PREALLOC));
    for _ in 0..obj_count {
        typed_objects.push(read_obj(&mut cursor, 0)?);
    }
    let objects: Vec<String> = typed_objects
        .iter()
        .map(MpyObject::display_string)
        .collect();
    crate::debug::dbg_kv("mpy-bytecode", || {
        format!("v{version} small_int_bits={small_int_bits} qstrs={n_qstr} objects={n_obj}")
    });
    crate::debug::dbg_kv_guarded("mpy-qstrs", || qstrs.join(", "));
    let function: MpyFunction = read_function(&mut cursor, &qstrs, 0)?;
    Ok(MpyBytecodeModule {
        version,
        small_int_bits,
        qstrs,
        objects,
        typed_objects,
        function,
    })
}

pub(crate) const MAX_TABLE_PREALLOC: usize = 4096;

pub(crate) fn bounded_table_count(
    declared: u64,
    remaining: usize,
    field: &'static str,
    offset: usize,
) -> Result<usize> {
    let count: usize = usize_from_u64(declared, field, offset)?;
    if count > remaining {
        return Err(AltRuntimeError::BadEncoding { field, offset });
    }
    Ok(count)
}

fn usize_from_u64(value: u64, field: &'static str, offset: usize) -> Result<usize> {
    usize::try_from(value).map_err(|_| AltRuntimeError::BadEncoding { field, offset })
}

fn usize_from_u32(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

const MAX_NESTING: u8 = 48;

fn read_function(cursor: &mut Cursor<'_>, qstrs: &[String], depth: u8) -> Result<MpyFunction> {
    if depth > MAX_NESTING {
        return Err(AltRuntimeError::BadEncoding {
            field: "raw_code_nesting",
            offset: cursor.pos,
        });
    }
    let kind_len: u64 = cursor.uint()?;
    let kind: u8 = u8::try_from(kind_len & 3).map_err(|_| AltRuntimeError::BadEncoding {
        field: "raw_code_kind",
        offset: cursor.pos,
    })?;
    if kind != 0 {
        return Err(AltRuntimeError::NotDetected("micropython-bytecode"));
    }
    let has_children: bool = (kind_len >> 2) & 1 == 1;
    let fun_data_len: usize = usize_from_u64(kind_len >> 3, "raw_code_length", cursor.pos)?;
    let fun_data: &[u8] = cursor.take(fun_data_len)?;
    let decoded: DecodedFunctionBody = decode_function_body(fun_data, qstrs)?;
    let mut children: Vec<MpyFunction> = Vec::new();
    if has_children {
        let n_children: u64 = cursor.uint()?;
        for _ in 0..n_children {
            children.push(read_function(cursor, qstrs, depth + 1)?);
        }
    }
    Ok(MpyFunction {
        simple_name: decoded.simple_name,
        n_state: decoded.n_state,
        n_exc_stack: decoded.n_exc_stack,
        scope_flags: decoded.scope_flags,
        n_pos_args: decoded.n_pos_args,
        n_kwonly_args: decoded.n_kwonly_args,
        n_def_pos_args: decoded.n_def_pos_args,
        instructions: decoded.instructions,
        children,
    })
}

struct DecodedFunctionBody {
    simple_name: String,
    n_state: u32,
    n_exc_stack: u32,
    scope_flags: u32,
    n_pos_args: u32,
    n_kwonly_args: u32,
    n_def_pos_args: u32,
    instructions: Vec<MpyDecodedInsn>,
}

fn decode_function_body(fun_data: &[u8], qstrs: &[String]) -> Result<DecodedFunctionBody> {
    let mut ip: usize = 0;
    let sig: PreludeSig = decode_prelude_sig(fun_data, &mut ip)?;
    let size: PreludeSize = decode_prelude_size(fun_data, &mut ip)?;
    let code_info_start: usize = ip;
    let mut info_ip: usize = code_info_start;
    let name_index: u64 = decode_uint(fun_data, &mut info_ip)?;
    let simple_name: String = qstrs
        .get(usize::try_from(name_index).unwrap_or(usize::MAX))
        .cloned()
        .unwrap_or_else(|| format!("<qstr#{name_index}>"));
    let opcodes_start: usize = code_info_start
        .checked_add(size.n_info)
        .and_then(|v: usize| v.checked_add(size.n_cell))
        .ok_or(AltRuntimeError::BadEncoding {
            field: "prelude_size",
            offset: code_info_start,
        })?;
    let opcodes: &[u8] =
        fun_data
            .get(opcodes_start..)
            .ok_or_else(|| AltRuntimeError::Truncated {
                offset: opcodes_start,
                needed: 1,
                had: fun_data
                    .len()
                    .saturating_sub(opcodes_start.min(fun_data.len())),
            })?;
    let instructions: Vec<MpyDecodedInsn> = decode_opcodes(opcodes, qstrs)?;
    Ok(DecodedFunctionBody {
        simple_name,
        n_state: u32::try_from(sig.n_state).unwrap_or(u32::MAX),
        n_exc_stack: u32::try_from(sig.n_exc_stack).unwrap_or(u32::MAX),
        scope_flags: u32::try_from(sig.scope_flags).unwrap_or(u32::MAX),
        n_pos_args: u32::try_from(sig.n_pos_args).unwrap_or(u32::MAX),
        n_kwonly_args: u32::try_from(sig.n_kwonly_args).unwrap_or(u32::MAX),
        n_def_pos_args: u32::try_from(sig.n_def_pos_args).unwrap_or(u32::MAX),
        instructions,
    })
}

struct PreludeSig {
    n_state: usize,
    n_exc_stack: usize,
    scope_flags: usize,
    n_pos_args: usize,
    n_kwonly_args: usize,
    n_def_pos_args: usize,
}

fn decode_prelude_sig(fun_data: &[u8], ip: &mut usize) -> Result<PreludeSig> {
    let mut z: u8 = next_byte(fun_data, ip)?;
    let mut n_state: usize = usize::from((z >> 3) & 0x0f);
    let mut n_exc_stack: usize = usize::from((z >> 2) & 0x01);
    let mut scope_flags: usize = 0;
    let mut n_pos_args: usize = usize::from(z & 0x03);
    let mut n_kwonly_args: usize = 0;
    let mut n_def_pos_args: usize = 0;
    let mut n: u32 = 0;
    while z & 0x80 != 0 {
        z = next_byte(fun_data, ip)?;
        n_state |= shl_usize(usize::from(z & 0x30), 2 * n, *ip)?;
        n_exc_stack |= shl_usize(usize::from(z & 0x02), n, *ip)?;
        scope_flags |= shl_usize(usize::from((z & 0x40) >> 6), n, *ip)?;
        n_pos_args |= shl_usize(usize::from(z & 0x04), n, *ip)?;
        n_kwonly_args |= shl_usize(usize::from((z & 0x08) >> 3), n, *ip)?;
        n_def_pos_args |= shl_usize(usize::from(z & 0x01), n, *ip)?;
        n = n.saturating_add(1);
    }
    n_state += 1;
    Ok(PreludeSig {
        n_state,
        n_exc_stack,
        scope_flags,
        n_pos_args,
        n_kwonly_args,
        n_def_pos_args,
    })
}

struct PreludeSize {
    n_info: usize,
    n_cell: usize,
}

fn decode_prelude_size(fun_data: &[u8], ip: &mut usize) -> Result<PreludeSize> {
    let mut n_cell: usize = 0;
    let mut n_info: usize = 0;
    let mut n: u32 = 0;
    loop {
        let z: u8 = next_byte(fun_data, ip)?;
        n_cell |= shl_usize(usize::from(z & 0x01), n, *ip)?;
        n_info |= shl_usize(usize::from((z & 0x7e) >> 1), 6 * n, *ip)?;
        n = n.saturating_add(1);
        if z & 0x80 == 0 {
            break;
        }
    }
    Ok(PreludeSize { n_info, n_cell })
}

fn next_byte(data: &[u8], ip: &mut usize) -> Result<u8> {
    let b: u8 = *data.get(*ip).ok_or(AltRuntimeError::Truncated {
        offset: *ip,
        needed: 1,
        had: 0,
    })?;
    *ip += 1;
    Ok(b)
}

fn shl_usize(value: usize, shift: u32, offset: usize) -> Result<usize> {
    value
        .checked_shl(shift)
        .ok_or(AltRuntimeError::BadEncoding {
            field: "prelude_varint",
            offset,
        })
}

fn decode_uint(data: &[u8], ip: &mut usize) -> Result<u64> {
    let mut value: u64 = 0;
    loop {
        let b: u8 = next_byte(data, ip)?;
        value = (value << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Ok(value);
        }
    }
}

fn decode_ulabel(data: &[u8], ip: &mut usize) -> Result<u32> {
    let first: u8 = next_byte(data, ip)?;
    if first & 0x80 != 0 {
        let second: u8 = next_byte(data, ip)?;
        Ok(u32::from(first & 0x7f) | (u32::from(second) << 7))
    } else {
        Ok(u32::from(first))
    }
}

fn decode_slabel(data: &[u8], ip: &mut usize) -> Result<i32> {
    let first: u8 = next_byte(data, ip)?;
    if first & 0x80 != 0 {
        let second: u8 = next_byte(data, ip)?;
        let raw: i32 = i32::from(first & 0x7f) | (i32::from(second) << 7);
        Ok(raw - 0x4000)
    } else {
        Ok(i32::from(first) - 0x40)
    }
}

fn decode_signed_int(data: &[u8], ip: &mut usize) -> Result<i64> {
    let mut num: i64 = 0;
    let first: u8 = *data.get(*ip).ok_or(AltRuntimeError::Truncated {
        offset: *ip,
        needed: 1,
        had: 0,
    })?;
    if first & 0x40 != 0 {
        num = -1;
    }
    loop {
        let b: u8 = next_byte(data, ip)?;
        num = (num << 7) | i64::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Ok(num);
        }
    }
}

const BASE_QSTR_O: u8 = 0x10;
const BASE_VINT_E: u8 = 0x20;
const BASE_VINT_O: u8 = 0x30;
const BASE_JUMP_E: u8 = 0x40;
const BASE_BYTE_O: u8 = 0x50;
const BASE_BYTE_E: u8 = 0x60;
const BASE_SMALL_INT_MULTI: u8 = 0x70;
const SMALL_INT_MULTI_NUM: u8 = 64;
const SMALL_INT_MULTI_EXCESS: i32 = 16;
const BASE_LOAD_FAST_MULTI: u8 = 0xb0;
const LOAD_FAST_MULTI_NUM: u8 = 16;
const BASE_STORE_FAST_MULTI: u8 = 0xc0;
const STORE_FAST_MULTI_NUM: u8 = 16;
const BASE_UNARY_OP_MULTI: u8 = 0xd0;
const UNARY_OP_MULTI_NUM: u8 = 4;
const BASE_BINARY_OP_MULTI: u8 = 0xd7;
const BINARY_OP_MULTI_NUM: u8 = 35;

const UNARY_OPS: [&str; 4] = ["positive", "negative", "invert", "not"];
const BINARY_OPS: [&str; 35] = [
    "less",
    "more",
    "equal",
    "less_equal",
    "more_equal",
    "not_equal",
    "in",
    "is",
    "exception_match",
    "inplace_or",
    "inplace_xor",
    "inplace_and",
    "inplace_lshift",
    "inplace_rshift",
    "inplace_add",
    "inplace_subtract",
    "inplace_multiply",
    "inplace_mat_multiply",
    "inplace_floor_divide",
    "inplace_true_divide",
    "inplace_modulo",
    "inplace_power",
    "or",
    "xor",
    "and",
    "lshift",
    "rshift",
    "add",
    "subtract",
    "multiply",
    "mat_multiply",
    "floor_divide",
    "true_divide",
    "modulo",
    "power",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperandKind {
    None,
    Qstr,
    Uint,
    SignedInt,
    SignedLabel,
    UnsignedLabel,
    UnwindJump,
    Object,
    MakeClosure,
}

const fn opcode_info(op: u8) -> Option<(&'static str, OperandKind)> {
    let entry: (&'static str, OperandKind) = match op {
        v if v == BASE_QSTR_O => ("LOAD_CONST_STRING", OperandKind::Qstr),
        v if v == BASE_QSTR_O + 0x01 => ("LOAD_NAME", OperandKind::Qstr),
        v if v == BASE_QSTR_O + 0x02 => ("LOAD_GLOBAL", OperandKind::Qstr),
        v if v == BASE_QSTR_O + 0x03 => ("LOAD_ATTR", OperandKind::Qstr),
        v if v == BASE_QSTR_O + 0x04 => ("LOAD_METHOD", OperandKind::Qstr),
        v if v == BASE_QSTR_O + 0x05 => ("LOAD_SUPER_METHOD", OperandKind::Qstr),
        v if v == BASE_QSTR_O + 0x06 => ("STORE_NAME", OperandKind::Qstr),
        v if v == BASE_QSTR_O + 0x07 => ("STORE_GLOBAL", OperandKind::Qstr),
        v if v == BASE_QSTR_O + 0x08 => ("STORE_ATTR", OperandKind::Qstr),
        v if v == BASE_QSTR_O + 0x09 => ("DELETE_NAME", OperandKind::Qstr),
        v if v == BASE_QSTR_O + 0x0a => ("DELETE_GLOBAL", OperandKind::Qstr),
        v if v == BASE_QSTR_O + 0x0b => ("IMPORT_NAME", OperandKind::Qstr),
        v if v == BASE_QSTR_O + 0x0c => ("IMPORT_FROM", OperandKind::Qstr),
        v if v == BASE_VINT_E => ("MAKE_CLOSURE", OperandKind::MakeClosure),
        v if v == BASE_VINT_E + 0x01 => ("MAKE_CLOSURE_DEFARGS", OperandKind::MakeClosure),
        v if v == BASE_VINT_E + 0x02 => ("LOAD_CONST_SMALL_INT", OperandKind::SignedInt),
        v if v == BASE_VINT_E + 0x03 => ("LOAD_CONST_OBJ", OperandKind::Object),
        v if v == BASE_VINT_E + 0x04 => ("LOAD_FAST_N", OperandKind::Uint),
        v if v == BASE_VINT_E + 0x05 => ("LOAD_DEREF", OperandKind::Uint),
        v if v == BASE_VINT_E + 0x06 => ("STORE_FAST_N", OperandKind::Uint),
        v if v == BASE_VINT_E + 0x07 => ("STORE_DEREF", OperandKind::Uint),
        v if v == BASE_VINT_E + 0x08 => ("DELETE_FAST", OperandKind::Uint),
        v if v == BASE_VINT_E + 0x09 => ("DELETE_DEREF", OperandKind::Uint),
        v if v == BASE_VINT_E + 0x0a => ("BUILD_TUPLE", OperandKind::Uint),
        v if v == BASE_VINT_E + 0x0b => ("BUILD_LIST", OperandKind::Uint),
        v if v == BASE_VINT_E + 0x0c => ("BUILD_MAP", OperandKind::Uint),
        v if v == BASE_VINT_E + 0x0d => ("BUILD_SET", OperandKind::Uint),
        v if v == BASE_VINT_E + 0x0e => ("BUILD_SLICE", OperandKind::Uint),
        v if v == BASE_VINT_E + 0x0f => ("STORE_COMP", OperandKind::Uint),
        v if v == BASE_VINT_O => ("UNPACK_SEQUENCE", OperandKind::Uint),
        v if v == BASE_VINT_O + 0x01 => ("UNPACK_EX", OperandKind::Uint),
        v if v == BASE_VINT_O + 0x02 => ("MAKE_FUNCTION", OperandKind::Uint),
        v if v == BASE_VINT_O + 0x03 => ("MAKE_FUNCTION_DEFARGS", OperandKind::Uint),
        v if v == BASE_VINT_O + 0x04 => ("CALL_FUNCTION", OperandKind::Uint),
        v if v == BASE_VINT_O + 0x05 => ("CALL_FUNCTION_VAR_KW", OperandKind::Uint),
        v if v == BASE_VINT_O + 0x06 => ("CALL_METHOD", OperandKind::Uint),
        v if v == BASE_VINT_O + 0x07 => ("CALL_METHOD_VAR_KW", OperandKind::Uint),
        v if v == BASE_JUMP_E => ("UNWIND_JUMP", OperandKind::UnwindJump),
        v if v == BASE_JUMP_E + 0x02 => ("JUMP", OperandKind::SignedLabel),
        v if v == BASE_JUMP_E + 0x03 => ("POP_JUMP_IF_TRUE", OperandKind::SignedLabel),
        v if v == BASE_JUMP_E + 0x04 => ("POP_JUMP_IF_FALSE", OperandKind::SignedLabel),
        v if v == BASE_JUMP_E + 0x05 => ("JUMP_IF_TRUE_OR_POP", OperandKind::UnsignedLabel),
        v if v == BASE_JUMP_E + 0x06 => ("JUMP_IF_FALSE_OR_POP", OperandKind::UnsignedLabel),
        v if v == BASE_JUMP_E + 0x07 => ("SETUP_WITH", OperandKind::UnsignedLabel),
        v if v == BASE_JUMP_E + 0x08 => ("SETUP_EXCEPT", OperandKind::UnsignedLabel),
        v if v == BASE_JUMP_E + 0x09 => ("SETUP_FINALLY", OperandKind::UnsignedLabel),
        v if v == BASE_JUMP_E + 0x0a => ("POP_EXCEPT_JUMP", OperandKind::UnsignedLabel),
        v if v == BASE_JUMP_E + 0x0b => ("FOR_ITER", OperandKind::UnsignedLabel),
        v if v == BASE_BYTE_O => ("LOAD_CONST_FALSE", OperandKind::None),
        v if v == BASE_BYTE_O + 0x01 => ("LOAD_CONST_NONE", OperandKind::None),
        v if v == BASE_BYTE_O + 0x02 => ("LOAD_CONST_TRUE", OperandKind::None),
        v if v == BASE_BYTE_O + 0x03 => ("LOAD_NULL", OperandKind::None),
        v if v == BASE_BYTE_O + 0x04 => ("LOAD_BUILD_CLASS", OperandKind::None),
        v if v == BASE_BYTE_O + 0x05 => ("LOAD_SUBSCR", OperandKind::None),
        v if v == BASE_BYTE_O + 0x06 => ("STORE_SUBSCR", OperandKind::None),
        v if v == BASE_BYTE_O + 0x07 => ("DUP_TOP", OperandKind::None),
        v if v == BASE_BYTE_O + 0x08 => ("DUP_TOP_TWO", OperandKind::None),
        v if v == BASE_BYTE_O + 0x09 => ("POP_TOP", OperandKind::None),
        v if v == BASE_BYTE_O + 0x0a => ("ROT_TWO", OperandKind::None),
        v if v == BASE_BYTE_O + 0x0b => ("ROT_THREE", OperandKind::None),
        v if v == BASE_BYTE_O + 0x0c => ("WITH_CLEANUP", OperandKind::None),
        v if v == BASE_BYTE_O + 0x0d => ("END_FINALLY", OperandKind::None),
        v if v == BASE_BYTE_O + 0x0e => ("GET_ITER", OperandKind::None),
        v if v == BASE_BYTE_O + 0x0f => ("GET_ITER_STACK", OperandKind::None),
        v if v == BASE_BYTE_E + 0x02 => ("STORE_MAP", OperandKind::None),
        v if v == BASE_BYTE_E + 0x03 => ("RETURN_VALUE", OperandKind::None),
        v if v == BASE_BYTE_E + 0x04 => ("RAISE_LAST", OperandKind::None),
        v if v == BASE_BYTE_E + 0x05 => ("RAISE_OBJ", OperandKind::None),
        v if v == BASE_BYTE_E + 0x06 => ("RAISE_FROM", OperandKind::None),
        v if v == BASE_BYTE_E + 0x07 => ("YIELD_VALUE", OperandKind::None),
        v if v == BASE_BYTE_E + 0x08 => ("YIELD_FROM", OperandKind::None),
        v if v == BASE_BYTE_E + 0x09 => ("IMPORT_STAR", OperandKind::None),
        _ => return None,
    };
    Some(entry)
}

fn decode_opcodes(code: &[u8], qstrs: &[String]) -> Result<Vec<MpyDecodedInsn>> {
    let mut out: Vec<MpyDecodedInsn> = Vec::new();
    let mut ip: usize = 0;
    while ip < code.len() {
        let offset: usize = ip;
        let op: u8 = next_byte(code, &mut ip)?;
        if let Some(insn) = decode_multi_opcode(op, offset) {
            out.push(insn);
            continue;
        }
        let Some((mnemonic, kind)): Option<(&'static str, OperandKind)> = opcode_info(op) else {
            let undecoded_bytes: usize = code.len().saturating_sub(offset);
            crate::debug::dbg_kv("mpy-opcode", || {
                format!(
                    "unknown opcode 0x{op:02x} at offset {offset}; operand length unknown, marking \
                     {undecoded_bytes} trailing bytes undecodable rather than reframing them"
                )
            });
            out.push(MpyDecodedInsn {
                offset,
                opcode: op,
                mnemonic: format!("UNDECODABLE_{op:02X}"),
                operand: Some(format!(
                    "0x{op:02x} (+{} bytes undecoded)",
                    undecoded_bytes - 1
                )),
                arg: MpyArg::UndecodableTail {
                    opcode: op,
                    undecoded_bytes,
                },
            });
            break;
        };
        let (operand, arg): (Option<String>, MpyArg) =
            decode_operand(kind, op, code, &mut ip, qstrs)?;
        out.push(MpyDecodedInsn {
            offset,
            opcode: op,
            mnemonic: mnemonic.to_owned(),
            operand,
            arg,
        });
    }
    crate::debug::dbg_kv("mpy-opcodes", || {
        format!("decoded={} bytes={}", out.len(), code.len())
    });
    Ok(out)
}

fn decode_multi_opcode(op: u8, offset: usize) -> Option<MpyDecodedInsn> {
    if (BASE_SMALL_INT_MULTI..BASE_SMALL_INT_MULTI + SMALL_INT_MULTI_NUM).contains(&op) {
        let value: i32 = i32::from(op - BASE_SMALL_INT_MULTI) - SMALL_INT_MULTI_EXCESS;
        return Some(MpyDecodedInsn {
            offset,
            opcode: op,
            mnemonic: "LOAD_CONST_SMALL_INT".to_owned(),
            operand: Some(value.to_string()),
            arg: MpyArg::SmallInt(i64::from(value)),
        });
    }
    if (BASE_LOAD_FAST_MULTI..BASE_LOAD_FAST_MULTI + LOAD_FAST_MULTI_NUM).contains(&op) {
        let idx: u8 = op - BASE_LOAD_FAST_MULTI;
        return Some(MpyDecodedInsn {
            offset,
            opcode: op,
            mnemonic: "LOAD_FAST".to_owned(),
            operand: Some(idx.to_string()),
            arg: MpyArg::Uint(u64::from(idx)),
        });
    }
    if (BASE_STORE_FAST_MULTI..BASE_STORE_FAST_MULTI + STORE_FAST_MULTI_NUM).contains(&op) {
        let idx: u8 = op - BASE_STORE_FAST_MULTI;
        return Some(MpyDecodedInsn {
            offset,
            opcode: op,
            mnemonic: "STORE_FAST".to_owned(),
            operand: Some(idx.to_string()),
            arg: MpyArg::Uint(u64::from(idx)),
        });
    }
    if (BASE_UNARY_OP_MULTI..BASE_UNARY_OP_MULTI + UNARY_OP_MULTI_NUM).contains(&op) {
        let idx: u8 = op - BASE_UNARY_OP_MULTI;
        let name: &str = UNARY_OPS.get(usize::from(idx)).copied().unwrap_or("?");
        return Some(MpyDecodedInsn {
            offset,
            opcode: op,
            mnemonic: "UNARY_OP".to_owned(),
            operand: Some(name.to_owned()),
            arg: MpyArg::UnaryOp(idx),
        });
    }
    if (BASE_BINARY_OP_MULTI..=BASE_BINARY_OP_MULTI.wrapping_add(BINARY_OP_MULTI_NUM - 1))
        .contains(&op)
    {
        let idx: u8 = op - BASE_BINARY_OP_MULTI;
        let name: &str = BINARY_OPS.get(usize::from(idx)).copied().unwrap_or("?");
        return Some(MpyDecodedInsn {
            offset,
            opcode: op,
            mnemonic: "BINARY_OP".to_owned(),
            operand: Some(name.to_owned()),
            arg: MpyArg::BinaryOp(idx),
        });
    }
    None
}

fn decode_operand(
    kind: OperandKind,
    op: u8,
    code: &[u8],
    ip: &mut usize,
    qstrs: &[String],
) -> Result<(Option<String>, MpyArg)> {
    let result: (Option<String>, MpyArg) = match kind {
        OperandKind::None => (None, MpyArg::None),
        OperandKind::Qstr => {
            let index: u64 = decode_uint(code, ip)?;
            let text: String = qstr_label(qstrs, index);
            (
                Some(text.clone()),
                MpyArg::Qstr {
                    index: u32::try_from(index).unwrap_or(u32::MAX),
                    text,
                },
            )
        }
        OperandKind::Uint => {
            let value: u64 = decode_uint(code, ip)?;
            (Some(value.to_string()), MpyArg::Uint(value))
        }
        OperandKind::SignedInt => {
            let value: i64 = decode_signed_int(code, ip)?;
            (Some(value.to_string()), MpyArg::SmallInt(value))
        }
        OperandKind::Object => {
            let index: u64 = decode_uint(code, ip)?;
            (
                Some(format!("obj#{index}")),
                MpyArg::Object {
                    index: u32::try_from(index).unwrap_or(u32::MAX),
                },
            )
        }
        OperandKind::SignedLabel => {
            let rel: i32 = decode_slabel(code, ip)?;
            let target: usize = relative_target(*ip, rel);
            (
                Some(format!("to {target}")),
                MpyArg::RelTarget {
                    byte_offset: target,
                },
            )
        }
        OperandKind::UnsignedLabel => {
            let rel: u32 = decode_ulabel(code, ip)?;
            let target: usize = (*ip).saturating_add(usize_from_u32(rel));
            (
                Some(format!("to {target}")),
                MpyArg::RelTarget {
                    byte_offset: target,
                },
            )
        }
        OperandKind::UnwindJump => {
            let rel: i32 = decode_slabel(code, ip)?;
            let extra: u8 = next_byte(code, ip)?;
            let target: usize = relative_target(*ip, rel);
            (
                Some(format!("to {target} depth {extra}")),
                MpyArg::UnwindTarget {
                    byte_offset: target,
                    depth: extra,
                },
            )
        }
        OperandKind::MakeClosure => {
            let value: u64 = decode_uint(code, ip)?;
            let n_closed: u8 = next_byte(code, ip)?;
            (
                Some(format!("{value} closed {n_closed}")),
                MpyArg::MakeClosure {
                    table_index: u32::try_from(value).unwrap_or(u32::MAX),
                    n_closed,
                },
            )
        }
    };
    let _ = op;
    Ok(result)
}

fn relative_target(ip_after: usize, rel: i32) -> usize {
    if rel >= 0 {
        ip_after.saturating_add(usize_from_u32(rel.unsigned_abs()))
    } else {
        ip_after.saturating_sub(usize_from_u32(rel.unsigned_abs()))
    }
}

fn qstr_label(qstrs: &[String], index: u64) -> String {
    qstrs
        .get(usize::try_from(index).unwrap_or(usize::MAX))
        .cloned()
        .unwrap_or_else(|| format!("<qstr#{index}>"))
}

fn read_qstr(cursor: &mut Cursor<'_>) -> Result<String> {
    let header: u64 = cursor.uint()?;
    if header & 1 == 1 {
        let index: u64 = header >> 1;
        return Ok(super::mpy_static_qstr::static_qstr(index)
            .map_or_else(|| format!("<static#{index}>"), str::to_owned));
    }
    let len: usize = usize_from_u64(header >> 1, "qstr_length", cursor.pos)?;
    let raw: &[u8] = cursor.take(len)?;
    let text: String = String::from_utf8_lossy(raw).into_owned();
    cursor.byte()?;
    Ok(text)
}

const OBJ_FUN_TABLE: u8 = 0;
const OBJ_NONE: u8 = 1;
const OBJ_FALSE: u8 = 2;
const OBJ_TRUE: u8 = 3;
const OBJ_ELLIPSIS: u8 = 4;
const OBJ_STR: u8 = b'r';
const OBJ_BYTES: u8 = b'e';
const OBJ_INT: u8 = b'i';
const OBJ_FLOAT: u8 = b'f';
const OBJ_COMPLEX: u8 = b'c';
const OBJ_TUPLE: u8 = b't';

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MpyObject {
    FunTable,
    None,
    False,
    True,
    Ellipsis,
    Str(String),
    Bytes(Vec<u8>),
    Int(String),
    Float(String),
    Complex(String),
    Tuple(Vec<Self>),
}

impl MpyObject {
    #[must_use]
    pub fn display_string(&self) -> String {
        match self {
            Self::FunTable => "<fun-table>".to_owned(),
            Self::None => "None".to_owned(),
            Self::False => "False".to_owned(),
            Self::True => "True".to_owned(),
            Self::Ellipsis => "...".to_owned(),
            Self::Str(s) => format!("str:{s}"),
            Self::Bytes(b) => format!("bytes:{}", String::from_utf8_lossy(b)),
            Self::Int(s) | Self::Float(s) | Self::Complex(s) => format!("num:{s}"),
            Self::Tuple(items) => {
                let parts: Vec<String> = items.iter().map(Self::display_string).collect();
                format!("({})", parts.join(", "))
            }
        }
    }
}

const MAX_OBJ_NESTING: u8 = 64;

fn read_obj(cursor: &mut Cursor<'_>, depth: u8) -> Result<MpyObject> {
    if depth > MAX_OBJ_NESTING {
        return Err(AltRuntimeError::BadEncoding {
            field: "obj_table_nesting",
            offset: cursor.pos,
        });
    }
    let obj_type: u8 = cursor.byte()?;
    match obj_type {
        OBJ_FUN_TABLE => Ok(MpyObject::FunTable),
        OBJ_NONE => Ok(MpyObject::None),
        OBJ_FALSE => Ok(MpyObject::False),
        OBJ_TRUE => Ok(MpyObject::True),
        OBJ_ELLIPSIS => Ok(MpyObject::Ellipsis),
        OBJ_STR | OBJ_BYTES => {
            let len: usize = usize_from_u64(cursor.uint()?, "obj_bytes_length", cursor.pos)?;
            let raw: &[u8] = cursor.take(len)?;
            if obj_type == OBJ_STR {
                Ok(MpyObject::Str(String::from_utf8_lossy(raw).into_owned()))
            } else {
                Ok(MpyObject::Bytes(raw.to_vec()))
            }
        }
        OBJ_INT | OBJ_FLOAT | OBJ_COMPLEX => {
            let len: usize = usize_from_u64(cursor.uint()?, "obj_number_length", cursor.pos)?;
            let raw: &[u8] = cursor.take(len)?;
            let body: String = String::from_utf8_lossy(raw).into_owned();
            Ok(match obj_type {
                OBJ_INT => MpyObject::Int(body),
                OBJ_FLOAT => MpyObject::Float(body),
                _ => MpyObject::Complex(body),
            })
        }
        OBJ_TUPLE => {
            let len: u64 = cursor.uint()?;
            let mut parts: Vec<MpyObject> = Vec::new();
            for _ in 0..len {
                parts.push(read_obj(cursor, depth.saturating_add(1))?);
            }
            Ok(MpyObject::Tuple(parts))
        }
        _ => Err(AltRuntimeError::BadEncoding {
            field: "obj_table",
            offset: cursor.pos,
        }),
    }
}

#[must_use]
pub fn render(module: &MpyBytecodeModule) -> String {
    let mut out: String = String::new();
    crate::push_string_line(
        &mut out,
        format_args!(
            "; micropython bytecode module (mpy v{}, small_int_bits {})",
            module.version, module.small_int_bits
        ),
    );
    if !module.qstrs.is_empty() {
        crate::push_string_line(
            &mut out,
            format_args!("; qstr table: {}", module.qstrs.join(", ")),
        );
    }
    walk_function(&mut out, &module.function, 0);
    out
}

fn walk_function(out: &mut String, func: &MpyFunction, depth: usize) {
    let indent: String = "  ".repeat(depth);
    crate::push_string_line(
        out,
        format_args!(
            "\n{indent}; function {} (state {}, args {}, kwonly {}, defaults {})",
            func.simple_name,
            func.n_state,
            func.n_pos_args,
            func.n_kwonly_args,
            func.n_def_pos_args
        ),
    );
    for insn in &func.instructions {
        match &insn.operand {
            Some(operand) => {
                crate::push_string_line(
                    out,
                    format_args!(
                        "{indent}  {:>5} {:<22} {operand}",
                        insn.offset, insn.mnemonic
                    ),
                );
            }
            None => {
                crate::push_string_line(
                    out,
                    format_args!("{indent}  {:>5} {}", insn.offset, insn.mnemonic),
                );
            }
        }
    }
    for child in &func.children {
        walk_function(out, child, depth + 1);
    }
}

#[must_use]
pub fn count_instructions(func: &MpyFunction) -> usize {
    func.instructions.len() + func.children.iter().map(count_instructions).sum::<usize>()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    const HELLO_BYTECODE: &[u8] =
        include_bytes!("../../../../corpus/python/alt_runtimes/micropython/hello_bytecode.mpy");
    const CONTROL_FLOW: &[u8] =
        include_bytes!("../../../../corpus/python/alt_runtimes/micropython/control_flow.mpy");

    fn build_header(version: u8) -> Vec<u8> {
        vec![MPY_MAGIC, version, MPY_FEATURE_BYTECODE, 31]
    }

    #[test]
    fn parses_mpy_v0_header() {
        let mut bytes: Vec<u8> = build_header(0);
        bytes.extend_from_slice(&[1u8, 2u8, 3u8]);
        let module: MicroPythonModule = parse(&bytes).expect("parse mpy v0");
        assert_eq!(module.version.raw(), 0);
        assert_eq!(module.raw_code, vec![1u8, 2u8, 3u8]);
    }

    #[test]
    fn parses_mpy_v6_header_with_no_phantom_qstr_window_field() {
        let mut bytes: Vec<u8> = build_header(6);
        bytes.extend_from_slice(&[1u8, 2u8, 3u8]);
        let module: MicroPythonModule = parse(&bytes).expect("parse mpy v6");
        assert_eq!(
            module.raw_code,
            vec![1u8, 2u8, 3u8],
            "the real .mpy header is always exactly 4 bytes (magic, version, features, \
             small_int_bits) with no qstr-window field at any version; raw_code must start \
             immediately at byte 4"
        );
    }

    #[test]
    fn parses_real_v6_fixture_raw_code_starts_at_byte_four() {
        let module: MicroPythonModule = parse(HELLO_BYTECODE).expect("parse real v6 mpy");
        assert_eq!(
            module.raw_code,
            HELLO_BYTECODE[4..],
            "raw_code must be exactly bytes[4..] for a real v6 pure-bytecode module: no bytes \
             may be dropped or reinterpreted as a nonexistent header field"
        );
    }

    #[test]
    fn payload_start_skips_arch_flags_varint_when_present() {
        let mut bytes: Vec<u8> = vec![MPY_MAGIC, 6u8, MPY_FEATURE_ARCH_FLAGS_PRESENT, 31u8, 0x05u8];
        bytes.extend_from_slice(&[9u8, 9u8]);
        let off: usize = payload_start(&bytes).expect("payload_start with arch flags");
        assert_eq!(
            off, 5,
            "single-byte arch_flags varint consumes one byte past the header"
        );
        assert_eq!(&bytes[off..], &[9u8, 9u8]);
    }

    #[test]
    fn payload_start_rejects_truncated_arch_flags_varint() {
        let bytes: [u8; 4] = [MPY_MAGIC, 6u8, MPY_FEATURE_ARCH_FLAGS_PRESENT, 31u8];
        let err: AltRuntimeError =
            payload_start(&bytes).expect_err("must reject missing arch_flags byte, not panic");
        assert!(matches!(err, AltRuntimeError::Truncated { .. }));
    }

    #[test]
    fn rejects_bad_magic() {
        let bytes: [u8; 8] = [b'X', 3u8, 0u8, 31u8, 0u8, 0u8, 0u8, 0u8];
        let err: AltRuntimeError = parse(&bytes).expect_err("reject bad magic");
        assert!(matches!(err, AltRuntimeError::BadMagic { .. }));
    }

    #[test]
    fn detects_all_versions() {
        for v in MPY_MIN_VERSION..=MPY_MAX_VERSION {
            let bytes: Vec<u8> = build_header(v);
            assert!(detect(&bytes), "should detect v{v}");
        }
    }

    #[test]
    fn decodes_hello_bytecode_add_function() {
        let module: MpyBytecodeModule = parse_bytecode(HELLO_BYTECODE).expect("parse bytecode mpy");
        assert_eq!(module.version, 6);
        assert!(module.qstrs.iter().any(|q: &String| q == "add"));
        let add: &MpyFunction = module
            .function
            .children
            .iter()
            .find(|f: &&MpyFunction| f.simple_name == "add")
            .expect("add child present");
        assert_eq!(add.n_pos_args, 2);
        let mnemonics: Vec<&str> = add
            .instructions
            .iter()
            .map(|i: &MpyDecodedInsn| i.mnemonic.as_str())
            .collect();
        assert_eq!(
            mnemonics,
            vec!["LOAD_FAST", "LOAD_FAST", "BINARY_OP", "RETURN_VALUE"]
        );
        let binop: &MpyDecodedInsn = &add.instructions[2];
        assert_eq!(binop.operand.as_deref(), Some("add"));
    }

    #[test]
    fn hello_bytecode_module_defines_and_calls_add() {
        let module: MpyBytecodeModule = parse_bytecode(HELLO_BYTECODE).expect("parse");
        let rendered: String = render(&module);
        assert!(rendered.contains("MAKE_FUNCTION"));
        assert!(rendered.contains("STORE_NAME"));
        assert!(rendered.contains("CALL_FUNCTION"));
        let module_ops: Vec<&str> = module
            .function
            .instructions
            .iter()
            .map(|i: &MpyDecodedInsn| i.mnemonic.as_str())
            .collect();
        assert_eq!(module_ops.first().copied(), Some("MAKE_FUNCTION"));
        assert_eq!(module_ops.last().copied(), Some("RETURN_VALUE"));
        assert!(module_ops.contains(&"LOAD_NAME"));
        assert!(module_ops.contains(&"LOAD_CONST_SMALL_INT"));
    }

    #[test]
    fn decodes_control_flow_with_jumps() {
        let module: MpyBytecodeModule = parse_bytecode(CONTROL_FLOW).expect("parse control flow");
        let classify: &MpyFunction = module
            .function
            .children
            .iter()
            .find(|f: &&MpyFunction| f.simple_name == "classify")
            .expect("classify present");
        let has_jump: bool = classify
            .instructions
            .iter()
            .any(|i: &MpyDecodedInsn| i.mnemonic.contains("JUMP") || i.mnemonic == "FOR_ITER");
        assert!(has_jump, "control flow function must contain a jump opcode");
        assert!(count_instructions(&module.function) > 0);
    }

    #[test]
    fn rejects_native_payload_as_bytecode() {
        let native: &[u8] = include_bytes!(
            "../../../../corpus/python/alt_runtimes/micropython/hello_native_x64.mpy"
        );
        let err: AltRuntimeError = parse_bytecode(native).expect_err("native is not bytecode");
        assert!(matches!(err, AltRuntimeError::NotDetected(_)));
    }

    #[test]
    fn prelude_sig_long_continuation_returns_err_not_panic() {
        let fun_data: Vec<u8> = vec![0xB0u8; 64];
        let mut ip: usize = 0;
        assert!(matches!(
            decode_prelude_sig(&fun_data, &mut ip),
            Err(AltRuntimeError::BadEncoding { .. })
        ));
    }

    #[test]
    fn prelude_size_long_continuation_returns_err_not_panic() {
        let fun_data: Vec<u8> = vec![0xFFu8; 64];
        let mut ip: usize = 0;
        assert!(matches!(
            decode_prelude_size(&fun_data, &mut ip),
            Err(AltRuntimeError::BadEncoding { .. })
        ));
    }

    const fn low_u7(value: u64) -> u8 {
        value.to_le_bytes()[0] & 0x7f
    }

    fn push_mpy_uint(out: &mut Vec<u8>, mut value: u64) {
        let mut chunks: Vec<u8> = vec![low_u7(value)];
        value >>= 7;
        while value != 0 {
            chunks.push(low_u7(value));
            value >>= 7;
        }
        chunks.reverse();
        let last: usize = chunks.len() - 1;
        for (i, chunk) in chunks.iter().enumerate() {
            if i == last {
                out.push(*chunk);
            } else {
                out.push(chunk | 0x80);
            }
        }
    }

    #[test]
    fn huge_n_qstr_rejected_before_allocation() {
        let mut bytes: Vec<u8> = vec![MPY_MAGIC, 6u8, MPY_FEATURE_BYTECODE, 31u8];
        push_mpy_uint(&mut bytes, u64::MAX);
        push_mpy_uint(&mut bytes, 0u64);
        let err: AltRuntimeError =
            parse_bytecode(&bytes).expect_err("declared qstr count must be rejected");
        assert!(
            matches!(
                err,
                AltRuntimeError::BadEncoding {
                    field: "n_qstr",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn huge_n_obj_rejected_before_allocation() {
        let mut bytes: Vec<u8> = vec![MPY_MAGIC, 6u8, MPY_FEATURE_BYTECODE, 31u8];
        push_mpy_uint(&mut bytes, 0u64);
        push_mpy_uint(&mut bytes, 1_000_000_000u64);
        let err: AltRuntimeError =
            parse_bytecode(&bytes).expect_err("declared object count must be rejected");
        assert!(
            matches!(err, AltRuntimeError::BadEncoding { field: "n_obj", .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn valid_bytecode_still_parses_after_count_bound() {
        let module: MpyBytecodeModule =
            parse_bytecode(HELLO_BYTECODE).expect("valid bytecode still parses");
        assert!(module.qstrs.iter().any(|q: &String| q == "add"));
    }

    #[test]
    fn lone_unknown_opcode_marks_undecodable_tail() {
        let decoded: Vec<MpyDecodedInsn> =
            decode_opcodes(&[0xFEu8], &[]).expect("unknown opcode marks tail undecodable");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].offset, 0);
        assert_eq!(decoded[0].opcode, 0xFE);
        assert_eq!(decoded[0].mnemonic, "UNDECODABLE_FE");
        assert!(matches!(
            decoded[0].arg,
            MpyArg::UndecodableTail {
                opcode: 0xFE,
                undecoded_bytes: 1
            }
        ));
    }

    #[test]
    fn multibyte_unknown_opcode_does_not_reframe_downstream_bytes() {
        let valid_loadfast: u8 = BASE_LOAD_FAST_MULTI + 2;
        let dup_top: u8 = BASE_BYTE_O + 0x07;
        let pop_top: u8 = BASE_BYTE_O + 0x09;
        let mut code: Vec<u8> = vec![valid_loadfast, 0xFEu8, dup_top, pop_top];
        code.push(BASE_BYTE_O + 0x03);
        let decoded: Vec<MpyDecodedInsn> =
            decode_opcodes(&code, &[]).expect("decode stops cleanly at the unknown opcode");

        assert_eq!(
            decoded.len(),
            2,
            "the leading valid op decodes, then framing stops at the unknown op; the unknown op's \
             trailing operand bytes must NOT be re-decoded as the DUP_TOP/POP_TOP opcodes they \
             happen to collide with: {decoded:?}"
        );
        assert_eq!(decoded[0].mnemonic, "LOAD_FAST");
        assert_eq!(decoded[1].offset, 1);
        assert_eq!(decoded[1].mnemonic, "UNDECODABLE_FE");
        assert!(matches!(
            decoded[1].arg,
            MpyArg::UndecodableTail {
                opcode: 0xFE,
                undecoded_bytes: 4
            }
        ));
        assert!(
            decoded
                .iter()
                .all(|i: &MpyDecodedInsn| i.mnemonic != "DUP_TOP" && i.mnemonic != "POP_TOP"),
            "no downstream opcode may be fabricated from the unknown op's operand bytes: {decoded:?}"
        );
    }

    #[test]
    fn read_obj_deep_tuple_nesting_returns_err_not_stack_overflow() {
        let mut payload: Vec<u8> = Vec::new();
        for _ in 0..512 {
            payload.push(OBJ_TUPLE);
            payload.push(0x01);
        }
        payload.push(OBJ_NONE);
        let mut cursor: Cursor<'_> = Cursor::new(&payload);
        let err: AltRuntimeError = read_obj(&mut cursor, 0).expect_err("must bound recursion");
        assert!(matches!(err, AltRuntimeError::BadEncoding { .. }));
    }
}
