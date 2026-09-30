use crate::declaration::{
    ClassConstant, ClassDecl, ClassKind, Modifiers, Parameter, Property, Signature, Visibility,
};
use crate::decompile::{Literal, Op, OpArray, OpArrayKind, OperandType, TryCatch, op};
use crate::error::{Error, Result};

pub const OPCACHE_MAGIC: &[u8; 8] = b"OPCACHE\0";

const HEADER_LEN: usize = 80;
const HEADER_MEM_SIZE: usize = 40;
const HEADER_STR_SIZE: usize = 48;
const HEADER_SCRIPT_OFFSET: usize = 56;
const HEADER_CHECKSUM: usize = 72;

const SCRIPT_MAIN_OP_ARRAY: u64 = 8;
const SCRIPT_FUNCTION_TABLE: u64 = 264;
const SCRIPT_CLASS_TABLE: u64 = 320;

const OA_TYPE: u64 = 0;
const OA_FN_FLAGS: u64 = 4;
const OA_FUNCTION_NAME: u64 = 8;
const OA_NUM_ARGS: u64 = 32;
const OA_ARG_INFO: u64 = 40;
const OA_T: u64 = 72;
const OA_LAST_VAR: u64 = 92;
const OA_LAST: u64 = 96;
const OA_OPCODES: u64 = 104;
const OA_STATIC_VARIABLES: u64 = 120;
const OA_VARS: u64 = 128;
const OA_LAST_TRY_CATCH: u64 = 148;
const OA_TRY_CATCH: u64 = 160;
const OA_LAST_LITERAL: u64 = 184;
const OA_NUM_DYNAMIC: u64 = 188;
const OA_LITERALS: u64 = 192;
const OA_DYNAMIC: u64 = 200;

const OP_SIZE: u64 = 32;
const OP_OP1: u64 = 8;
const OP_OP2: u64 = 12;
const OP_RESULT: u64 = 16;
const OP_EXT: u64 = 20;
const OP_LINENO: u64 = 24;
const OP_OPCODE: u64 = 28;

const ZVAL_SIZE: u64 = 16;
const ZVAL_TYPE: u64 = 8;
const ZVAL_U2: u64 = 12;
const HT_FLAGS: u64 = 8;
const HT_DATA: u64 = 16;
const HT_USED: u64 = 24;
const BUCKET_SIZE: u64 = 32;
const BUCKET_H: u64 = 16;
const BUCKET_KEY: u64 = 24;
const STR_LEN: u64 = 16;
const STR_VAL: u64 = 24;
const ARG_INFO_SIZE: u64 = 32;
const TYPE_PTR: u64 = 0;
const TYPE_MASK: u64 = 8;
const TRY_CATCH_SIZE: u64 = 16;
const AST_REF_HEADER: u64 = 8;
const AST_CHILD: u64 = 8;
const AST_LIST_COUNT: u64 = 8;
const AST_LIST_CHILD: u64 = 16;
const CLASS_NAME_SIZE: u64 = 16;

const CE_NAME: u64 = 8;
const CE_PARENT: u64 = 16;
const CE_FLAGS: u64 = 28;
const CE_DEFAULT_PROPERTIES_COUNT: u64 = 32;
const CE_DEFAULT_STATIC_COUNT: u64 = 36;
const CE_DEFAULT_PROPERTIES: u64 = 40;
const CE_DEFAULT_STATICS: u64 = 48;
const CE_FUNCTION_TABLE: u64 = 64;
const CE_PROPERTIES_INFO: u64 = 120;
const CE_CONSTANTS_TABLE: u64 = 176;
const CE_NUM_INTERFACES: u64 = 424;
const CE_NUM_TRAITS: u64 = 428;
const CE_NUM_HOOKED_PROPS: u64 = 432;
const CE_INTERFACE_NAMES: u64 = 440;
const CE_TRAIT_NAMES: u64 = 448;
const CE_TRAIT_ALIASES: u64 = 456;
const CE_TRAIT_PRECEDENCES: u64 = 464;
const CE_ENUM_BACKING_TYPE: u64 = 480;

const PROP_OFFSET: u64 = 0;
const PROP_FLAGS: u64 = 4;
const PROP_TYPE: u64 = 40;
const PROP_HOOKS: u64 = 64;
const OBJECT_PROPERTIES_TABLE: u64 = 40;

const CALL_FRAME_SLOTS: u32 = 5;
const ZEND_USER_FUNCTION: u8 = 2;

const IS_UNDEF: u8 = 0;
const IS_NULL: u8 = 1;
const IS_FALSE: u8 = 2;
const IS_TRUE: u8 = 3;
const IS_LONG: u8 = 4;
const IS_DOUBLE: u8 = 5;
const IS_STRING: u8 = 6;
const IS_ARRAY: u8 = 7;
const IS_CONSTANT_AST: u8 = 11;
const IS_PTR: u8 = 13;

const HASH_FLAG_PACKED: u32 = 1 << 2;
const HASH_FLAG_UNINITIALIZED: u32 = 1 << 3;

const ACC_PUBLIC: u32 = 1 << 0;
const ACC_PROTECTED: u32 = 1 << 1;
const ACC_PRIVATE: u32 = 1 << 2;
const ACC_STATIC: u32 = 1 << 4;
const ACC_FINAL: u32 = 1 << 5;
const ACC_ABSTRACT: u32 = 1 << 6;
const ACC_READONLY: u32 = 1 << 7;
const ACC_VIRTUAL: u32 = 1 << 9;
const ACC_PUBLIC_SET: u32 = 1 << 10;
const ACC_PROTECTED_SET: u32 = 1 << 11;
const ACC_PRIVATE_SET: u32 = 1 << 12;
const ACC_RETURN_REFERENCE: u32 = 1 << 12;
const ACC_HAS_RETURN_TYPE: u32 = 1 << 13;
const ACC_VARIADIC: u32 = 1 << 14;
const ACC_CLOSURE: u32 = 1 << 22;
const ACC_INTERFACE: u32 = 1 << 0;
const ACC_TRAIT: u32 = 1 << 1;
const ACC_LINKED: u32 = 1 << 3;
const ACC_EXPLICIT_ABSTRACT_CLASS: u32 = 1 << 6;
const ACC_READONLY_CLASS: u32 = 1 << 16;
const ACC_ENUM: u32 = 1 << 28;

const TYPE_NAME_BIT: u32 = 1 << 24;
const TYPE_LITERAL_NAME_BIT: u32 = 1 << 23;
const TYPE_LIST_BIT: u32 = 1 << 22;
const TYPE_INTERSECTION_BIT: u32 = 1 << 19;
const TYPE_MAY_BE_MASK: u32 = (1 << 18) - 1;
const MAY_BE_NULL: u32 = 1 << 1;
const MAY_BE_FALSE: u32 = 1 << 2;
const MAY_BE_TRUE: u32 = 1 << 3;
const MAY_BE_LONG: u32 = 1 << 4;
const MAY_BE_DOUBLE: u32 = 1 << 5;
const MAY_BE_STRING: u32 = 1 << 6;
const MAY_BE_ARRAY: u32 = 1 << 7;
const MAY_BE_OBJECT: u32 = 1 << 8;
const MAY_BE_RESOURCE: u32 = 1 << 9;
const MAY_BE_CALLABLE: u32 = 1 << 12;
const MAY_BE_VOID: u32 = 1 << 14;
const MAY_BE_STATIC: u32 = 1 << 15;
const MAY_BE_NEVER: u32 = 1 << 17;
const MAY_BE_ANY: u32 = MAY_BE_NULL
    | MAY_BE_FALSE
    | MAY_BE_TRUE
    | MAY_BE_LONG
    | MAY_BE_DOUBLE
    | MAY_BE_STRING
    | MAY_BE_ARRAY
    | MAY_BE_OBJECT
    | MAY_BE_RESOURCE;
const SEND_MODE_SHIFT: u32 = 25;
const SEND_BY_REFERENCE: u32 = 1;

const FETCH_CLASS_MASK: u32 = 0x0f;
const FETCH_CLASS_SELF: u32 = 1;
const FETCH_CLASS_PARENT: u32 = 2;
const FETCH_CLASS_STATIC: u32 = 3;
const FETCH_TYPE_MASK: u32 = 0x0e;
const FETCH_LOCAL: u32 = 1 << 2;
const FETCH_GLOBAL: u32 = 1 << 1;
const FETCH_GLOBAL_LOCK: u32 = 1 << 3;
const ISEMPTY: u32 = 1;
const LAST_CATCH: u32 = 1;
const ARRAY_ELEMENT_REF: u32 = 1;
const BIND_REF: u32 = 1;
const BIND_IMPLICIT: u32 = 2;
const BIND_EXPLICIT: u32 = 4;
const BIND_MODE_MASK: u32 = 7;

pub const BIND_LEXICAL_BY_REFERENCE: u32 = 1;
pub const BIND_LEXICAL_IMPLICIT: u32 = 2;

const AST_ZVAL: u16 = 64;
const AST_CONSTANT: u16 = 65;
const AST_ARRAY: u16 = 129;
const AST_CONSTANT_CLASS: u16 = 2;
const AST_UNPACK: u16 = 258;
const AST_UNARY_PLUS: u16 = 259;
const AST_UNARY_MINUS: u16 = 260;
const AST_UNARY_OP: u16 = 270;
const AST_CLASS_NAME: u16 = 276;
const AST_DIM: u16 = 512;
const AST_CLASS_CONST: u16 = 517;
const AST_BINARY_OP: u16 = 521;
const AST_GREATER: u16 = 522;
const AST_GREATER_EQUAL: u16 = 523;
const AST_AND: u16 = 524;
const AST_OR: u16 = 525;
const AST_ARRAY_ELEM: u16 = 526;
const AST_COALESCE: u16 = 530;
const AST_CONDITIONAL: u16 = 771;
const AST_CONST_ENUM_INIT: u16 = 777;
const AST_IS_LIST_BIT: u16 = 1 << 7;
const AST_CHILDREN_SHIFT: u16 = 8;

const MAX_OPS: u32 = 1 << 20;
const MAX_LITERALS: u32 = 1 << 20;
const MAX_VARS: u32 = 1 << 16;
const MAX_TEMPORARIES: u32 = 1 << 20;
const MAX_ARGS: u32 = 1 << 16;
const MAX_TRY_CATCH: u32 = 1 << 16;
const MAX_HASH_ELEMENTS: u32 = 1 << 20;
const MAX_DYNAMIC_DEFS: u32 = 1 << 16;
const MAX_CLASS_NAMES: u32 = 1 << 12;
const MAX_TYPE_LIST: u32 = 1 << 8;
const MAX_DEPTH: u32 = 64;
const MAX_OP_ARRAYS: usize = 1 << 16;
const MAX_VALUE_NODES: usize = 1 << 22;
const MAX_COPIED_BYTES: usize = 1 << 28;

const FRAMELESS_FUNCTIONS: [(&str, u8); 28] = [
    ("property_exists", 2),
    ("class_exists", 1),
    ("class_exists", 2),
    ("preg_match", 2),
    ("preg_replace", 3),
    ("min", 2),
    ("max", 2),
    ("in_array", 2),
    ("in_array", 3),
    ("trim", 1),
    ("trim", 2),
    ("implode", 1),
    ("implode", 2),
    ("dirname", 1),
    ("dirname", 2),
    ("strstr", 2),
    ("strstr", 3),
    ("strpos", 2),
    ("strpos", 3),
    ("str_contains", 2),
    ("str_starts_with", 2),
    ("substr", 2),
    ("substr", 3),
    ("strtr", 2),
    ("strtr", 3),
    ("str_replace", 3),
    ("dechex", 1),
    ("is_numeric", 1),
];

pub const FRAMELESS_ICALL_0: u8 = 204;
pub const FRAMELESS_ICALL_3: u8 = 207;

pub fn is_opcache_file(bytes: &[u8]) -> bool {
    bytes.starts_with(OPCACHE_MAGIC)
}

pub fn parse_opcache_file(bytes: &[u8]) -> Result<OpArray> {
    if !is_opcache_file(bytes) {
        return Err(Error::OpcacheBadMagic);
    }
    let header: &[u8] = bytes.get(..HEADER_LEN).ok_or(Error::OpcacheTruncated {
        region: "header",
        offset: 0,
        need: HEADER_LEN as u64,
        len: bytes.len() as u64,
    })?;
    let mem_size: u64 = header_u64(header, HEADER_MEM_SIZE);
    let str_size: u64 = header_u64(header, HEADER_STR_SIZE);
    let script_offset: u64 = header_u64(header, HEADER_SCRIPT_OFFSET);
    let stored: u32 = u32::from_le_bytes([
        header[HEADER_CHECKSUM],
        header[HEADER_CHECKSUM + 1],
        header[HEADER_CHECKSUM + 2],
        header[HEADER_CHECKSUM + 3],
    ]);
    let body: &[u8] = &bytes[HEADER_LEN..];
    let total: u64 = mem_size
        .checked_add(str_size)
        .ok_or(Error::OpcacheOversize {
            field: "mem_size + str_size",
            value: u64::MAX,
            cap: body.len() as u64,
        })?;
    if total > body.len() as u64 {
        return Err(Error::OpcacheTruncated {
            region: "script memory",
            offset: HEADER_LEN as u64,
            need: total,
            len: body.len() as u64,
        });
    }
    let (mem, rest): (&[u8], &[u8]) = body.split_at(mem_size as usize);
    let strings: &[u8] = &rest[..str_size as usize];
    let computed: u32 = adler32(adler32(1, mem), strings);
    if computed != stored {
        return Err(Error::OpcacheChecksum { stored, computed });
    }
    let copied: std::cell::Cell<usize> = std::cell::Cell::new(0);
    let image: Image<'_> = Image {
        mem,
        strings,
        copied: &copied,
    };
    let mut reader: Reader<'_> = Reader {
        image,
        op_arrays: 0,
        value_nodes: 0,
    };
    reader.script(script_offset)
}

fn header_u64(header: &[u8], at: usize) -> u64 {
    let mut raw: [u8; 8] = [0; 8];
    raw.copy_from_slice(&header[at..at + 8]);
    u64::from_le_bytes(raw)
}

fn adler32(seed: u32, data: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    let mut a: u32 = seed & 0xffff;
    let mut b: u32 = seed >> 16;
    for chunk in data.chunks(5552) {
        for &byte in chunk {
            a += u32::from(byte);
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

#[derive(Clone, Copy)]
struct Image<'a> {
    mem: &'a [u8],
    strings: &'a [u8],
    copied: &'a std::cell::Cell<usize>,
}

impl<'a> Image<'a> {
    fn bytes(self, field: &'static str, offset: u64, len: u64) -> Result<&'a [u8]> {
        let end: u64 = offset.checked_add(len).ok_or(Error::OpcacheBadPointer {
            field,
            pointer: offset,
        })?;
        if end > self.mem.len() as u64 {
            return Err(Error::OpcacheTruncated {
                region: field,
                offset,
                need: len,
                len: self.mem.len() as u64,
            });
        }
        Ok(&self.mem[offset as usize..end as usize])
    }

    fn u8(self, field: &'static str, offset: u64) -> Result<u8> {
        Ok(self.bytes(field, offset, 1)?[0])
    }

    fn u16(self, field: &'static str, offset: u64) -> Result<u16> {
        let raw: &[u8] = self.bytes(field, offset, 2)?;
        Ok(u16::from_le_bytes([raw[0], raw[1]]))
    }

    fn u32(self, field: &'static str, offset: u64) -> Result<u32> {
        let raw: &[u8] = self.bytes(field, offset, 4)?;
        Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
    }

    fn u64(self, field: &'static str, offset: u64) -> Result<u64> {
        let raw: &[u8] = self.bytes(field, offset, 8)?;
        let mut out: [u8; 8] = [0; 8];
        out.copy_from_slice(raw);
        Ok(u64::from_le_bytes(out))
    }

    fn count(self, field: &'static str, offset: u64, cap: u32) -> Result<u32> {
        let value: u32 = self.u32(field, offset)?;
        if value > cap {
            return Err(Error::OpcacheOversize {
                field,
                value: u64::from(value),
                cap: u64::from(cap),
            });
        }
        Ok(value)
    }

    fn pointer(self, field: &'static str, offset: u64) -> Result<Option<u64>> {
        let value: u64 = self.u64(field, offset)?;
        if value == 0 {
            return Ok(None);
        }
        if value & 1 != 0 || value >= self.mem.len() as u64 {
            return Err(Error::OpcacheBadPointer {
                field,
                pointer: value,
            });
        }
        Ok(Some(value))
    }

    fn required_pointer(self, field: &'static str, offset: u64) -> Result<u64> {
        self.pointer(field, offset)?
            .ok_or(Error::OpcacheBadPointer { field, pointer: 0 })
    }

    fn string(self, field: &'static str, offset: u64) -> Result<Option<&'a [u8]>> {
        let value: u64 = self.u64(field, offset)?;
        self.string_at(field, value)
    }

    fn string_at(self, field: &'static str, value: u64) -> Result<Option<&'a [u8]>> {
        if value == 0 {
            return Ok(None);
        }
        let (region, at): (&'a [u8], u64) = if value & 1 == 1 {
            (self.strings, value & !1)
        } else {
            (self.mem, value)
        };
        let header_end: u64 = at.checked_add(STR_VAL).ok_or(Error::OpcacheBadPointer {
            field,
            pointer: value,
        })?;
        if header_end > region.len() as u64 {
            return Err(Error::OpcacheBadPointer {
                field,
                pointer: value,
            });
        }
        let len_at: usize = (at + STR_LEN) as usize;
        let mut raw: [u8; 8] = [0; 8];
        raw.copy_from_slice(&region[len_at..len_at + 8]);
        let len: u64 = u64::from_le_bytes(raw);
        let end: u64 = header_end
            .checked_add(len)
            .ok_or(Error::OpcacheBadPointer {
                field,
                pointer: value,
            })?;
        if end > region.len() as u64 {
            return Err(Error::OpcacheTruncated {
                region: field,
                offset: header_end,
                need: len,
                len: region.len() as u64,
            });
        }
        let total: usize = self.copied.get().saturating_add(len as usize);
        if total > MAX_COPIED_BYTES {
            return Err(Error::OpcacheOversize {
                field: "decoded string bytes",
                value: total as u64,
                cap: MAX_COPIED_BYTES as u64,
            });
        }
        self.copied.set(total);
        Ok(Some(&region[header_end as usize..end as usize]))
    }

    fn name(self, field: &'static str, offset: u64) -> Result<String> {
        let raw: &[u8] = self
            .string(field, offset)?
            .ok_or(Error::OpcacheBadPointer { field, pointer: 0 })?;
        Ok(String::from_utf8_lossy(raw).into_owned())
    }
}

#[derive(Debug)]
enum HashKey {
    Index(i64),
    Name(Vec<u8>),
}

impl HashKey {
    fn literal(self) -> Literal {
        match self {
            Self::Index(index) => Literal::Long(index),
            Self::Name(bytes) => string_literal(bytes),
        }
    }

    fn text(&self) -> String {
        match self {
            Self::Index(index) => index.to_string(),
            Self::Name(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        }
    }
}

fn string_literal(bytes: Vec<u8>) -> Literal {
    match String::from_utf8(bytes) {
        Ok(text) => Literal::Str(text),
        Err(error) => Literal::Bytes(error.into_bytes()),
    }
}

struct Reader<'a> {
    image: Image<'a>,
    op_arrays: usize,
    value_nodes: usize,
}

struct RawOperand {
    kind: u8,
    value: u32,
}

struct RawOp {
    opcode: u8,
    op1: RawOperand,
    op2: RawOperand,
    result: RawOperand,
    extended_value: u32,
    lineno: u32,
}

#[derive(Clone, Copy)]
struct Frame {
    temporaries: u32,
    op_count: u32,
    index: u32,
}

impl Reader<'_> {
    fn script(&mut self, script: u64) -> Result<OpArray> {
        let mut main: OpArray =
            self.op_array(script + SCRIPT_MAIN_OP_ARRAY, OpArrayKind::Main, None, 0)?;
        let mut functions: Vec<OpArray> = Vec::new();
        for (_, zval) in self.hash_entries("function_table", script + SCRIPT_FUNCTION_TABLE)? {
            let at: u64 = self.ptr_zval("function_table entry", zval)?;
            let name: String = self.image.name("function name", at + OA_FUNCTION_NAME)?;
            functions.push(self.op_array(at, OpArrayKind::Function, None, 1)?);
            if let Some(function) = functions.last_mut() {
                function.name = Some(name);
            }
        }
        functions.append(&mut main.children);
        main.children = functions;
        for (key, zval) in self.hash_entries("class_table", script + SCRIPT_CLASS_TABLE)? {
            let at: u64 = self.ptr_zval("class_table entry", zval)?;
            main.classes.push(self.class(at, key.text())?);
        }
        Ok(main)
    }

    fn ptr_zval(&self, field: &'static str, zval: u64) -> Result<u64> {
        let kind: u8 = self.image.u8(field, zval + ZVAL_TYPE)?;
        if kind != IS_PTR {
            return Err(Error::OpcacheLayout {
                field,
                value: u64::from(kind),
            });
        }
        self.image.required_pointer(field, zval)
    }

    fn hash_entries(&mut self, field: &'static str, table: u64) -> Result<Vec<(HashKey, u64)>> {
        let flags: u32 = self.image.u32(field, table + HT_FLAGS)?;
        if flags & HASH_FLAG_UNINITIALIZED != 0 {
            return Ok(Vec::new());
        }
        let used: u32 = self
            .image
            .count(field, table + HT_USED, MAX_HASH_ELEMENTS)?;
        if used == 0 {
            return Ok(Vec::new());
        }
        let data: u64 = self.image.required_pointer(field, table + HT_DATA)?;
        self.charge(used as usize)?;
        let packed: bool = flags & HASH_FLAG_PACKED != 0;
        let stride: u64 = if packed { ZVAL_SIZE } else { BUCKET_SIZE };
        self.image
            .bytes(field, data, u64::from(used) * stride)
            .map(|_| ())?;
        let mut out: Vec<(HashKey, u64)> = Vec::with_capacity(used as usize);
        for position in 0..u64::from(used) {
            let entry: u64 = data + position * stride;
            if self.image.u8(field, entry + ZVAL_TYPE)? == IS_UNDEF {
                continue;
            }
            let key: HashKey = if packed {
                HashKey::Index(position as i64)
            } else {
                match self.image.string(field, entry + BUCKET_KEY)? {
                    Some(name) => HashKey::Name(name.to_vec()),
                    None => HashKey::Index(self.image.u64(field, entry + BUCKET_H)? as i64),
                }
            };
            out.push((key, entry));
        }
        Ok(out)
    }

    fn charge(&mut self, nodes: usize) -> Result<()> {
        self.value_nodes = self.value_nodes.saturating_add(nodes);
        if self.value_nodes > MAX_VALUE_NODES {
            return Err(Error::OpcacheOversize {
                field: "decoded values",
                value: self.value_nodes as u64,
                cap: MAX_VALUE_NODES as u64,
            });
        }
        Ok(())
    }

    fn zval(&mut self, field: &'static str, at: u64, depth: u32) -> Result<Literal> {
        if depth > MAX_DEPTH {
            return Err(Error::OpcacheNestTooDeep(depth));
        }
        self.charge(1)?;
        let kind: u8 = self.image.u8(field, at + ZVAL_TYPE)?;
        Ok(match kind {
            IS_NULL => Literal::Null,
            IS_FALSE => Literal::Bool(false),
            IS_TRUE => Literal::Bool(true),
            IS_LONG => Literal::Long(self.image.u64(field, at)? as i64),
            IS_DOUBLE => Literal::Double(f64::from_bits(self.image.u64(field, at)?)),
            IS_STRING => {
                let bytes: &[u8] = self
                    .image
                    .string(field, at)?
                    .ok_or(Error::OpcacheBadPointer { field, pointer: 0 })?;
                string_literal(bytes.to_vec())
            }
            IS_ARRAY => {
                let table: u64 = self.image.required_pointer(field, at)?;
                let mut entries: Vec<(Literal, Literal)> = Vec::new();
                for (key, value) in self.hash_entries(field, table)? {
                    entries.push((key.literal(), self.zval(field, value, depth + 1)?));
                }
                Literal::Values(entries)
            }
            IS_CONSTANT_AST => {
                let reference: u64 = self.image.required_pointer(field, at)?;
                match self.ast(reference + AST_REF_HEADER, depth + 1)? {
                    Ok(text) => Literal::ConstExpr(text),
                    Err(reason) => Literal::Unrenderable(reason),
                }
            }
            other => {
                return Err(Error::OpcacheLayout {
                    field,
                    value: u64::from(other),
                });
            }
        })
    }

    fn ast(&mut self, at: u64, depth: u32) -> Result<core::result::Result<String, String>> {
        if depth > MAX_DEPTH {
            return Err(Error::OpcacheNestTooDeep(depth));
        }
        self.charge(1)?;
        let kind: u16 = self.image.u16("constant expression", at)?;
        let attr: u16 = self.image.u16("constant expression", at + 2)?;
        match kind {
            AST_ZVAL => {
                let value: Literal = self.zval("constant expression value", at + 8, depth + 1)?;
                return Ok(value.try_render().ok_or_else(|| {
                    "a constant expression holds an unrenderable value".to_owned()
                }));
            }
            AST_CONSTANT => {
                let name: Literal = self.zval("constant expression name", at + 8, depth + 1)?;
                return Ok(match name {
                    Literal::Str(name) => Ok(name),
                    _ => Err("a constant reference is not named by a string".to_owned()),
                });
            }
            AST_CONSTANT_CLASS => return Ok(Ok("__CLASS__".to_owned())),
            _ => {}
        }
        if kind & AST_IS_LIST_BIT != 0 && kind >> AST_CHILDREN_SHIFT == 0 {
            if kind != AST_ARRAY {
                return Ok(Err(format!("constant expression list kind {kind}")));
            }
            let count: u32 = self.image.count(
                "constant expression list",
                at + AST_LIST_COUNT,
                MAX_HASH_ELEMENTS,
            )?;
            let mut items: Vec<String> = Vec::with_capacity(count as usize);
            for index in 0..u64::from(count) {
                match self.ast_child(at + AST_LIST_CHILD, index, depth)? {
                    Some(Ok(item)) => items.push(item),
                    Some(Err(reason)) => return Ok(Err(reason)),
                    None => return Ok(Err("an array constant holds an empty slot".to_owned())),
                }
            }
            return Ok(Ok(format!("[{}]", items.join(", "))));
        }
        let child = |reader: &mut Self,
                     index: u64|
         -> Result<Option<core::result::Result<String, String>>> {
            reader.ast_child(at + AST_CHILD, index, depth)
        };
        let required = |value: Option<core::result::Result<String, String>>| -> core::result::Result<String, String> {
            value.unwrap_or_else(|| Err("a constant expression lacks an operand".to_owned()))
        };
        let text: core::result::Result<String, String> = match kind {
            AST_UNPACK => required(child(self, 0)?).map(|value: String| format!("...{value}")),
            AST_UNARY_PLUS => required(child(self, 0)?).map(|value: String| format!("+({value})")),
            AST_UNARY_MINUS => required(child(self, 0)?).map(|value: String| format!("-({value})")),
            AST_UNARY_OP => {
                let symbol: Option<&str> = match u8::try_from(attr).ok() {
                    Some(op::BW_NOT) => Some("~"),
                    Some(op::BOOL_NOT) => Some("!"),
                    _ => None,
                };
                match symbol {
                    Some(symbol) => {
                        required(child(self, 0)?).map(|value: String| format!("{symbol}({value})"))
                    }
                    None => Err(format!("constant expression unary operator {attr}")),
                }
            }
            AST_CLASS_NAME => required(child(self, 0)?)
                .map(|class: String| format!("{}::class", strip_string_quotes(&class))),
            AST_DIM => {
                let base: core::result::Result<String, String> = required(child(self, 0)?);
                let index: core::result::Result<String, String> = required(child(self, 1)?);
                base.and_then(|base: String| {
                    index.map(|index: String| format!("({base})[{index}]"))
                })
            }
            AST_CLASS_CONST => {
                let class: core::result::Result<String, String> = required(child(self, 0)?);
                let name: core::result::Result<String, String> = required(child(self, 1)?);
                class.and_then(|class: String| {
                    name.map(|name: String| {
                        format!(
                            "{}::{}",
                            strip_string_quotes(&class),
                            strip_string_quotes(&name)
                        )
                    })
                })
            }
            AST_BINARY_OP | AST_GREATER | AST_GREATER_EQUAL | AST_AND | AST_OR | AST_COALESCE => {
                let symbol: Option<&str> = match kind {
                    AST_GREATER => Some(">"),
                    AST_GREATER_EQUAL => Some(">="),
                    AST_AND => Some("&&"),
                    AST_OR => Some("||"),
                    AST_COALESCE => Some("??"),
                    _ => u8::try_from(attr).ok().and_then(binary_symbol),
                };
                match symbol {
                    Some(symbol) => {
                        let left: core::result::Result<String, String> = required(child(self, 0)?);
                        let right: core::result::Result<String, String> = required(child(self, 1)?);
                        left.and_then(|left: String| {
                            right.map(|right: String| format!("({left} {symbol} {right})"))
                        })
                    }
                    None => Err(format!("constant expression binary operator {attr}")),
                }
            }
            AST_ARRAY_ELEM => {
                if attr != 0 {
                    Err("a constant array element binds by reference".to_owned())
                } else {
                    let value: core::result::Result<String, String> = required(child(self, 0)?);
                    match child(self, 1)? {
                        None => value,
                        Some(key) => key.and_then(|key: String| {
                            value.map(|value: String| format!("{key} => {value}"))
                        }),
                    }
                }
            }
            AST_CONDITIONAL => {
                let condition: core::result::Result<String, String> = required(child(self, 0)?);
                let when_true: Option<core::result::Result<String, String>> = child(self, 1)?;
                let when_false: core::result::Result<String, String> = required(child(self, 2)?);
                condition.and_then(|condition: String| {
                    when_false.and_then(|when_false: String| {
                        when_true.map_or_else(
                            || Ok(format!("({condition} ?: {when_false})")),
                            |when_true: core::result::Result<String, String>| {
                                when_true.map(|when_true: String| {
                                    format!("({condition} ? {when_true} : {when_false})")
                                })
                            },
                        )
                    })
                })
            }
            other => Err(format!("constant expression kind {other}")),
        };
        Ok(text)
    }

    fn ast_child(
        &mut self,
        base: u64,
        index: u64,
        depth: u32,
    ) -> Result<Option<core::result::Result<String, String>>> {
        self.image
            .pointer("constant expression child", base + index * 8)?
            .map_or(Ok(None), |child: u64| self.ast(child, depth + 1).map(Some))
    }

    fn op_array(
        &mut self,
        at: u64,
        kind: OpArrayKind,
        class_name: Option<&str>,
        depth: u32,
    ) -> Result<OpArray> {
        if depth > MAX_DEPTH {
            return Err(Error::OpcacheNestTooDeep(depth));
        }
        self.op_arrays += 1;
        if self.op_arrays > MAX_OP_ARRAYS {
            return Err(Error::OpcacheOversize {
                field: "op_arrays",
                value: self.op_arrays as u64,
                cap: MAX_OP_ARRAYS as u64,
            });
        }
        let image: Image<'_> = self.image;
        let function_type: u8 = image.u8("op_array type", at + OA_TYPE)?;
        if function_type != ZEND_USER_FUNCTION {
            return Err(Error::OpcacheLayout {
                field: "op_array type",
                value: u64::from(function_type),
            });
        }
        let fn_flags: u32 = image.u32("fn_flags", at + OA_FN_FLAGS)?;
        let name: Option<String> = image
            .string("function_name", at + OA_FUNCTION_NAME)?
            .map(|raw: &[u8]| String::from_utf8_lossy(raw).into_owned());
        let num_args: u32 = image.count("num_args", at + OA_NUM_ARGS, MAX_ARGS)?;
        let temporaries: u32 = image.count("T", at + OA_T, MAX_TEMPORARIES)?;
        let last_var: u32 = image.count("last_var", at + OA_LAST_VAR, MAX_VARS)?;
        let op_count: u32 = image.count("last", at + OA_LAST, MAX_OPS)?;
        let literal_count: u32 = image.count("last_literal", at + OA_LAST_LITERAL, MAX_LITERALS)?;
        let try_count: u32 =
            image.count("last_try_catch", at + OA_LAST_TRY_CATCH, MAX_TRY_CATCH)?;
        let dynamic_count: u32 = image.count(
            "num_dynamic_func_defs",
            at + OA_NUM_DYNAMIC,
            MAX_DYNAMIC_DEFS,
        )?;

        let mut var_names: Vec<Option<String>> = Vec::with_capacity(last_var as usize);
        if last_var > 0 {
            let vars: u64 = image.required_pointer("vars", at + OA_VARS)?;
            for slot in 0..u64::from(last_var) {
                let name: String = image.name("var name", vars + slot * 8)?;
                var_names.push(Some(name));
            }
        }

        let mut literals: Vec<Literal> = Vec::with_capacity(literal_count as usize);
        if literal_count > 0 {
            let table: u64 = image.required_pointer("literals", at + OA_LITERALS)?;
            for index in 0..u64::from(literal_count) {
                literals.push(self.zval("literal", table + index * ZVAL_SIZE, depth)?);
            }
        }

        let mut try_catch: Vec<TryCatch> = Vec::with_capacity(try_count as usize);
        if try_count > 0 {
            let table: u64 = image.required_pointer("try_catch_array", at + OA_TRY_CATCH)?;
            for index in 0..u64::from(try_count) {
                let row: u64 = table + index * TRY_CATCH_SIZE;
                let field = |offset: u64| image.u32("try_catch element", row + offset);
                let boundary = |value: u32, name: &'static str| -> Result<Option<u32>> {
                    if value == 0 {
                        return Ok(None);
                    }
                    if value >= op_count {
                        return Err(Error::OpcacheLayout {
                            field: name,
                            value: u64::from(value),
                        });
                    }
                    Ok(Some(value))
                };
                let try_op: u32 = field(0)?;
                if try_op >= op_count {
                    return Err(Error::OpcacheLayout {
                        field: "try_op",
                        value: u64::from(try_op),
                    });
                }
                try_catch.push(TryCatch {
                    try_op,
                    catch_op: boundary(field(4)?, "catch_op")?,
                    finally_op: boundary(field(8)?, "finally_op")?,
                    finally_end: boundary(field(12)?, "finally_end")?,
                });
            }
        }

        let mut static_variables: Vec<(String, Literal)> = Vec::new();
        if let Some(table) = image.pointer("static_variables", at + OA_STATIC_VARIABLES)? {
            for (key, value) in self.hash_entries("static_variables", table)? {
                let literal: Literal =
                    if image.u8("static variable", value + ZVAL_TYPE)? == IS_UNDEF {
                        Literal::Null
                    } else {
                        self.zval("static variable", value, depth)?
                    };
                static_variables.push((key.text(), literal));
            }
        }

        let signature: Option<Signature> = if kind == OpArrayKind::Main {
            None
        } else {
            Some(self.signature(at, fn_flags, num_args)?)
        };

        let mut children: Vec<OpArray> = Vec::new();
        let mut closure_ordinals: Vec<Option<u32>> = Vec::with_capacity(dynamic_count as usize);
        if dynamic_count > 0 {
            let defs: u64 = image.required_pointer("dynamic_func_defs", at + OA_DYNAMIC)?;
            let mut closures: u32 = 0;
            for index in 0..u64::from(dynamic_count) {
                let def: u64 = image.required_pointer("dynamic_func_def", defs + index * 8)?;
                let def_flags: u32 = image.u32("fn_flags", def + OA_FN_FLAGS)?;
                let is_closure: bool = def_flags & ACC_CLOSURE != 0;
                let child_kind: OpArrayKind = if is_closure {
                    closure_ordinals.push(Some(closures));
                    closures += 1;
                    OpArrayKind::Closure
                } else {
                    closure_ordinals.push(None);
                    OpArrayKind::Function
                };
                let child_class: Option<&str> = if is_closure { None } else { class_name };
                let mut child: OpArray = self.op_array(def, child_kind, child_class, depth + 1)?;
                if is_closure {
                    child.name = None;
                }
                children.push(child);
            }
        }

        let mut ops: Vec<Op> = Vec::with_capacity(op_count as usize);
        if op_count > 0 {
            let opcodes: u64 = image.required_pointer("opcodes", at + OA_OPCODES)?;
            image.bytes("opcodes", opcodes, u64::from(op_count) * OP_SIZE)?;
            let frame: Frame = Frame {
                temporaries: last_var.saturating_add(temporaries),
                op_count,
                index: 0,
            };
            for index in 0..op_count {
                let raw: RawOp = read_op(image, opcodes + u64::from(index) * OP_SIZE)?;
                let frame: Frame = Frame { index, ..frame };
                ops.push(lower(&raw, &frame, &mut literals, &closure_ordinals)?);
            }
        }

        Ok(OpArray {
            kind,
            name: if kind == OpArrayKind::Main {
                None
            } else {
                name
            },
            class_name: class_name.map(str::to_owned),
            num_args,
            literals,
            ops,
            children,
            var_names,
            try_catch,
            signature,
            static_variables,
            classes: Vec::new(),
        })
    }

    fn signature(&mut self, at: u64, fn_flags: u32, num_args: u32) -> Result<Signature> {
        let image: Image<'_> = self.image;
        let mut params: Vec<Parameter> = Vec::new();
        let mut return_type: Option<String> = None;
        let variadic: bool = fn_flags & ACC_VARIADIC != 0;
        let has_return_type: bool = fn_flags & ACC_HAS_RETURN_TYPE != 0;
        let declared: u32 = num_args + u32::from(variadic);
        if let Some(info) = image.pointer("arg_info", at + OA_ARG_INFO)? {
            if has_return_type {
                let entry: u64 =
                    info.checked_sub(ARG_INFO_SIZE)
                        .ok_or(Error::OpcacheBadPointer {
                            field: "return type arg_info",
                            pointer: info,
                        })?;
                return_type = self.type_decl(entry + 8, 0)?;
            }
            for index in 0..u64::from(declared) {
                let entry: u64 = info + index * ARG_INFO_SIZE;
                let name: String = image.name("parameter name", entry)?;
                let mask: u32 = image.u32("parameter type", entry + 8 + TYPE_MASK)?;
                params.push(Parameter {
                    name,
                    type_decl: self.type_decl(entry + 8, 0)?,
                    by_reference: (mask >> SEND_MODE_SHIFT) & 3 == SEND_BY_REFERENCE,
                    variadic: variadic && index == u64::from(num_args),
                });
            }
        } else if declared > 0 {
            return Err(Error::OpcacheBadPointer {
                field: "arg_info",
                pointer: 0,
            });
        }
        Ok(Signature {
            params,
            return_type,
            returns_reference: fn_flags & ACC_RETURN_REFERENCE != 0,
            modifiers: Modifiers {
                is_readonly: false,
                ..member_modifiers(fn_flags)
            },
        })
    }

    fn type_decl(&mut self, at: u64, depth: u32) -> Result<Option<String>> {
        if depth > MAX_DEPTH {
            return Err(Error::OpcacheNestTooDeep(depth));
        }
        let image: Image<'_> = self.image;
        let mask: u32 = image.u32("type mask", at + TYPE_MASK)?;
        let pure: u32 = mask & TYPE_MAY_BE_MASK;
        let mut names: Vec<String> = Vec::new();
        let mut intersection: bool = false;
        if mask & TYPE_LIST_BIT != 0 {
            let list: u64 = image.required_pointer("type list", at + TYPE_PTR)?;
            let count: u32 = image.count("type list count", list, MAX_TYPE_LIST)?;
            intersection = mask & TYPE_INTERSECTION_BIT != 0;
            for index in 0..u64::from(count) {
                let entry: u64 = list + 8 + index * 16;
                if let Some(name) = self.type_decl(entry, depth + 1)? {
                    names.push(if intersection || !name.contains('&') {
                        name
                    } else {
                        format!("({name})")
                    });
                }
            }
        } else if mask & (TYPE_NAME_BIT | TYPE_LITERAL_NAME_BIT) != 0 {
            names.push(image.name("type name", at + TYPE_PTR)?);
        }
        if intersection {
            return Ok(Some(names.join("&")));
        }
        if pure & MAY_BE_ANY == MAY_BE_ANY {
            return Ok(Some("mixed".to_owned()));
        }
        let builtin: [(u32, &str); 11] = [
            (MAY_BE_ARRAY, "array"),
            (MAY_BE_CALLABLE, "callable"),
            (MAY_BE_OBJECT, "object"),
            (MAY_BE_STATIC, "static"),
            (MAY_BE_STRING, "string"),
            (MAY_BE_LONG, "int"),
            (MAY_BE_DOUBLE, "float"),
            (MAY_BE_FALSE | MAY_BE_TRUE, "bool"),
            (MAY_BE_VOID, "void"),
            (MAY_BE_NEVER, "never"),
            (MAY_BE_RESOURCE, "resource"),
        ];
        for (bits, name) in builtin {
            if pure & bits == bits {
                names.push(name.to_owned());
            }
        }
        if pure & (MAY_BE_FALSE | MAY_BE_TRUE) == MAY_BE_FALSE {
            names.push("false".to_owned());
        }
        if pure & (MAY_BE_FALSE | MAY_BE_TRUE) == MAY_BE_TRUE {
            names.push("true".to_owned());
        }
        let nullable: bool = pure & MAY_BE_NULL != 0;
        Ok(match (names.len(), nullable) {
            (0, false) => None,
            (0, true) => Some("null".to_owned()),
            (1, true) if !names[0].starts_with('(') => Some(format!("?{}", names[0])),
            (_, true) => {
                names.push("null".to_owned());
                Some(names.join("|"))
            }
            (_, false) => Some(names.join("|")),
        })
    }

    fn class(&mut self, at: u64, key: String) -> Result<ClassDecl> {
        let image: Image<'_> = self.image;
        let name: String = image.name("class name", at + CE_NAME)?;
        let flags: u32 = image.u32("ce_flags", at + CE_FLAGS)?;
        let mut unsupported: Option<String> = None;
        let kind: ClassKind = if flags & ACC_INTERFACE != 0 {
            ClassKind::Interface
        } else if flags & ACC_TRAIT != 0 {
            ClassKind::Trait
        } else if flags & ACC_ENUM != 0 {
            ClassKind::Enum
        } else {
            ClassKind::Class
        };
        let parent: Option<String> = match image.u64("parent", at + CE_PARENT)? {
            0 => None,
            _ if flags & ACC_LINKED == 0 => Some(image.name("parent name", at + CE_PARENT)?),
            _ => {
                let parent: u64 = image.required_pointer("parent", at + CE_PARENT)?;
                Some(image.name("parent class name", parent + CE_NAME)?)
            }
        };
        let interfaces: Vec<String> =
            self.class_names(at + CE_NUM_INTERFACES, at + CE_INTERFACE_NAMES)?;
        let traits: Vec<String> = self.class_names(at + CE_NUM_TRAITS, at + CE_TRAIT_NAMES)?;
        if image.u64("trait_aliases", at + CE_TRAIT_ALIASES)? != 0
            || image.u64("trait_precedences", at + CE_TRAIT_PRECEDENCES)? != 0
        {
            unsupported = Some("trait adaptations".to_owned());
        }
        if image.u32("num_hooked_props", at + CE_NUM_HOOKED_PROPS)? != 0 {
            unsupported = Some("property hooks".to_owned());
        }

        let mut constants: Vec<ClassConstant> = Vec::new();
        for (key, zval) in self.hash_entries("constants_table", at + CE_CONSTANTS_TABLE)? {
            let constant: u64 = self.ptr_zval("class constant", zval)?;
            let constant_flags: u32 = image.u32("class constant flags", constant + ZVAL_U2)?;
            let case_value: Option<Literal> = self.enum_case_value(constant)?;
            let enum_case: bool = case_value.is_some();
            let value: Literal = match case_value {
                Some(value) => value,
                None => self.zval("class constant value", constant, 1)?,
            };
            constants.push(ClassConstant {
                name: key.text(),
                modifiers: member_modifiers(constant_flags),
                value,
                enum_case,
            });
        }
        let enum_backing: Option<String> = if kind == ClassKind::Enum {
            match image.u32("enum backing type", at + CE_ENUM_BACKING_TYPE)? {
                0 => None,
                4 => Some("int".to_owned()),
                6 => Some("string".to_owned()),
                other => {
                    return Err(Error::OpcacheLayout {
                        field: "enum backing type",
                        value: u64::from(other),
                    });
                }
            }
        } else {
            None
        };

        let property_count: u32 = image.count(
            "default_properties_count",
            at + CE_DEFAULT_PROPERTIES_COUNT,
            MAX_VARS,
        )?;
        let static_count: u32 = image.count(
            "default_static_members_count",
            at + CE_DEFAULT_STATIC_COUNT,
            MAX_VARS,
        )?;
        let defaults: Option<u64> =
            image.pointer("default_properties_table", at + CE_DEFAULT_PROPERTIES)?;
        let statics: Option<u64> =
            image.pointer("default_static_members_table", at + CE_DEFAULT_STATICS)?;
        let mut properties: Vec<Property> = Vec::new();
        for (key, zval) in self.hash_entries("properties_info", at + CE_PROPERTIES_INFO)? {
            let info: u64 = self.ptr_zval("property info", zval)?;
            let offset: u32 = image.u32("property offset", info + PROP_OFFSET)?;
            let property_flags: u32 = image.u32("property flags", info + PROP_FLAGS)?;
            if image.u64("property hooks", info + PROP_HOOKS)? != 0
                || property_flags & ACC_VIRTUAL != 0
            {
                unsupported = Some("property hooks".to_owned());
            }
            let slot: Option<u64> = if property_flags & ACC_STATIC != 0 {
                (offset < static_count)
                    .then(|| statics.map(|table: u64| table + u64::from(offset) * ZVAL_SIZE))
                    .flatten()
            } else {
                u64::from(offset)
                    .checked_sub(OBJECT_PROPERTIES_TABLE)
                    .filter(|delta: &u64| delta.is_multiple_of(ZVAL_SIZE))
                    .map(|delta: u64| delta / ZVAL_SIZE)
                    .filter(|index: &u64| *index < u64::from(property_count))
                    .and_then(|index: u64| defaults.map(|table: u64| table + index * ZVAL_SIZE))
            };
            let Some(slot) = slot else {
                return Err(Error::OpcacheLayout {
                    field: "property offset",
                    value: u64::from(offset),
                });
            };
            let default: Option<Literal> =
                if image.u8("property default", slot + ZVAL_TYPE)? == IS_UNDEF {
                    None
                } else {
                    Some(self.zval("property default", slot, 1)?)
                };
            let type_decl: Option<String> = self.type_decl(info + PROP_TYPE, 0)?;
            let mut modifiers: Modifiers = member_modifiers(property_flags);
            let set_visibility: u32 =
                property_flags & (ACC_PUBLIC_SET | ACC_PROTECTED_SET | ACC_PRIVATE_SET);
            let implied: u32 = if modifiers.is_readonly {
                ACC_PROTECTED_SET
            } else {
                0
            };
            if set_visibility != 0 && set_visibility != implied {
                unsupported = Some("asymmetric property visibility".to_owned());
            }
            if type_decl.is_none() && modifiers.is_readonly {
                modifiers.is_readonly = false;
            }
            properties.push(Property {
                name: key.text(),
                modifiers,
                type_decl,
                default,
            });
        }

        let mut methods: Vec<OpArray> = Vec::new();
        for (_, zval) in self.hash_entries("class function_table", at + CE_FUNCTION_TABLE)? {
            let method: u64 = self.ptr_zval("method", zval)?;
            let method_name: String = image.name("method name", method + OA_FUNCTION_NAME)?;
            let mut lifted: OpArray = self.op_array(method, OpArrayKind::Method, Some(&name), 1)?;
            lifted.name = Some(method_name);
            methods.push(lifted);
        }

        let mut modifiers: Modifiers = Modifiers::default();
        if kind == ClassKind::Class {
            modifiers.is_abstract = flags & ACC_EXPLICIT_ABSTRACT_CLASS != 0;
            modifiers.is_final = flags & ACC_FINAL != 0;
            modifiers.is_readonly = flags & ACC_READONLY_CLASS != 0;
        }
        Ok(ClassDecl {
            name,
            declaration_key: key,
            kind,
            modifiers,
            enum_backing,
            parent,
            interfaces,
            traits,
            constants,
            properties,
            methods,
            unsupported,
        })
    }

    fn enum_case_value(&mut self, constant: u64) -> Result<Option<Literal>> {
        let image: Image<'_> = self.image;
        if image.u8("class constant type", constant + ZVAL_TYPE)? != IS_CONSTANT_AST {
            return Ok(None);
        }
        let reference: u64 = image.required_pointer("class constant expression", constant)?;
        let ast: u64 = reference + AST_REF_HEADER;
        if image.u16("class constant expression", ast)? != AST_CONST_ENUM_INIT {
            return Ok(None);
        }
        Ok(Some(match self.ast_child(ast + AST_CHILD, 2, 1)? {
            None => Literal::Null,
            Some(Ok(text)) => Literal::ConstExpr(text),
            Some(Err(reason)) => Literal::Unrenderable(reason),
        }))
    }

    fn class_names(&self, count_at: u64, names_at: u64) -> Result<Vec<String>> {
        let image: Image<'_> = self.image;
        let count: u32 = image.count("class name list", count_at, MAX_CLASS_NAMES)?;
        if count == 0 {
            return Ok(Vec::new());
        }
        let table: u64 = image.required_pointer("class name list", names_at)?;
        let mut out: Vec<String> = Vec::with_capacity(count as usize);
        for index in 0..u64::from(count) {
            out.push(image.name("class name", table + index * CLASS_NAME_SIZE)?);
        }
        Ok(out)
    }
}

fn member_modifiers(flags: u32) -> Modifiers {
    let visibility: Option<Visibility> = if flags & ACC_PRIVATE != 0 {
        Some(Visibility::Private)
    } else if flags & ACC_PROTECTED != 0 {
        Some(Visibility::Protected)
    } else if flags & ACC_PUBLIC != 0 {
        Some(Visibility::Public)
    } else {
        None
    };
    Modifiers {
        visibility,
        is_static: flags & ACC_STATIC != 0,
        is_abstract: flags & ACC_ABSTRACT != 0,
        is_final: flags & ACC_FINAL != 0,
        is_readonly: flags & ACC_READONLY != 0,
    }
}

fn strip_string_quotes(text: &str) -> String {
    text.strip_prefix('\'')
        .and_then(|inner: &str| inner.strip_suffix('\''))
        .map_or_else(|| text.to_owned(), str::to_owned)
}

const fn binary_symbol(opcode: u8) -> Option<&'static str> {
    Some(match opcode {
        op::ADD => "+",
        op::SUB => "-",
        op::MUL => "*",
        op::DIV => "/",
        op::MOD => "%",
        op::SL => "<<",
        op::SR => ">>",
        op::CONCAT => ".",
        op::BW_OR => "|",
        op::BW_AND => "&",
        op::BW_XOR => "^",
        op::POW => "**",
        op::IS_IDENTICAL => "===",
        op::IS_NOT_IDENTICAL => "!==",
        op::IS_EQUAL => "==",
        op::IS_NOT_EQUAL => "!=",
        op::IS_SMALLER => "<",
        op::IS_SMALLER_OR_EQUAL => "<=",
        op::SPACESHIP => "<=>",
        BOOL_XOR => "xor",
        _ => return None,
    })
}

fn read_op(image: Image<'_>, at: u64) -> Result<RawOp> {
    let operand = |value_at: u64, type_at: u64| -> Result<RawOperand> {
        Ok(RawOperand {
            kind: image.u8("operand type", type_at)?,
            value: image.u32("operand", value_at)?,
        })
    };
    Ok(RawOp {
        opcode: image.u8("opcode", at + OP_OPCODE)?,
        op1: operand(at + OP_OP1, at + OP_OPCODE + 1)?,
        op2: operand(at + OP_OP2, at + OP_OPCODE + 2)?,
        result: operand(at + OP_RESULT, at + OP_OPCODE + 3)?,
        extended_value: image.u32("extended_value", at + OP_EXT)?,
        lineno: image.u32("lineno", at + OP_LINENO)?,
    })
}

const FAST_CONCAT: u8 = 53;
const BOOL_XOR: u8 = 15;
const SEND_VAR_NO_REF_EX: u8 = 50;
const SEND_VAR_NO_REF: u8 = 106;
const SEND_FUNC_ARG: u8 = 185;
const STRLEN: u8 = 121;
const COUNT: u8 = 190;
const VERIFY_RETURN_TYPE: u8 = 124;
const FE_FREE: u8 = 127;
const GENERATOR_CREATE: u8 = 139;
const FETCH_FUNC_ARG: u8 = 92;
const FETCH_DIM_FUNC_ARG: u8 = 93;
const FETCH_OBJ_FUNC_ARG: u8 = 94;
const FETCH_UNSET: u8 = 95;
const FETCH_DIM_UNSET: u8 = 96;
const FETCH_OBJ_UNSET: u8 = 97;
const CHECK_FUNC_ARG: u8 = 100;
const FETCH_STATIC_PROP_IS: u8 = 176;
const FETCH_STATIC_PROP_FUNC_ARG: u8 = 177;
const FETCH_STATIC_PROP_UNSET: u8 = 178;
const JMP_FRAMELESS: u8 = 208;
const BIND_INIT_STATIC_OR_JMP: u8 = 203;
const ASSERT_CHECK: u8 = 151;
const CASE_STRICT: u8 = 196;

fn lower(
    raw: &RawOp,
    frame: &Frame,
    literals: &mut Vec<Literal>,
    closure_ordinals: &[Option<u32>],
) -> Result<Op> {
    let mut out: Op = Op {
        opcode: raw.opcode,
        op1_type: OperandType::Unused,
        op2_type: OperandType::Unused,
        result_type: OperandType::Unused,
        op1: 0,
        op2: 0,
        result: 0,
        extended_value: 0,
        lineno: raw.lineno,
    };
    let (op1_type, op1): (OperandType, u32) = operand(&raw.op1, frame, literals.len())?;
    let (op2_type, op2): (OperandType, u32) = operand(&raw.op2, frame, literals.len())?;
    let (result_type, result): (OperandType, u32) = operand(&raw.result, frame, literals.len())?;
    let used = |ty: OperandType| ty != OperandType::Unused;
    out.result_type = result_type;
    out.result = result;
    match raw.opcode {
        op::JMP => {
            out.op1 = relative_jump(frame, raw.op1.value)?;
            out.result_type = OperandType::Unused;
            out.result = 0;
        }
        op::JMPZ
        | op::JMPNZ
        | op::JMPZ_EX
        | op::JMPNZ_EX
        | op::COALESCE
        | op::JMP_SET
        | op::JMP_NULL
        | op::FE_RESET_R
        | op::FE_RESET_RW
        | JMP_FRAMELESS
        | BIND_INIT_STATIC_OR_JMP
        | ASSERT_CHECK => {
            out.op1_type = op1_type;
            out.op1 = op1;
            out.op2 = relative_jump(frame, raw.op2.value)?;
        }
        op::FE_FETCH_R | op::FE_FETCH_RW => {
            out.op1_type = op1_type;
            out.op1 = op1;
            out.op2_type = op2_type;
            out.op2 = op2;
            out.extended_value = u32::from(used(result_type));
        }
        op::CATCH => {
            out.op1_type = op1_type;
            out.op1 = op1;
            if raw.extended_value & LAST_CATCH != 0 {
                out.extended_value = 1;
            } else {
                out.op2 = relative_jump(frame, raw.op2.value)?;
            }
        }
        op::FAST_CALL => {
            out.op1 = relative_jump(frame, raw.op1.value)?;
        }
        op::FAST_RET => {
            out.op1_type = op1_type;
            out.op1 = op1;
            if raw.op2.value != u32::MAX {
                out.extended_value = raw.op2.value.saturating_add(1);
            }
        }
        op::SWITCH_LONG | op::SWITCH_STRING | op::MATCH => {
            out.op1_type = op1_type;
            out.op1 = op1;
            let table: Option<Literal> = match literals.get(op2 as usize) {
                Some(Literal::Values(entries)) if op2_type == OperandType::Const => {
                    if raw.opcode == op::MATCH {
                        match_table(frame, entries)?
                    } else {
                        switch_table(frame, entries)?
                    }
                }
                _ => None,
            };
            if let Some(table) = table {
                out.op2_type = OperandType::Const;
                out.op2 = push_literal(literals, table);
                out.extended_value = relative_jump(frame, raw.extended_value)?;
            }
        }
        op::INIT_FCALL | op::INIT_FCALL_BY_NAME | op::INIT_NS_FCALL => {
            out.op2_type = op2_type;
            out.op2 = op2;
            out.result_type = OperandType::Unused;
            out.result = 0;
        }
        op::INIT_METHOD_CALL | op::INIT_DYNAMIC_CALL | op::NEW => {
            out.op1_type = op1_type;
            out.op1 = op1;
            if raw.opcode == op::NEW
                && !used(op1_type)
                && let Some(literal) = class_reference(raw.op1.value, literals)
            {
                out.op1_type = OperandType::Const;
                out.op1 = literal;
            }
            if raw.opcode == op::INIT_METHOD_CALL {
                out.op2_type = op2_type;
                out.op2 = op2;
            }
            if raw.opcode == op::INIT_DYNAMIC_CALL {
                out.op1_type = op2_type;
                out.op1 = op2;
            }
            if raw.opcode != op::NEW {
                out.result_type = OperandType::Unused;
                out.result = 0;
            }
            out.extended_value = raw.extended_value;
        }
        op::INIT_STATIC_METHOD_CALL => {
            out.op1_type = op1_type;
            out.op1 = op1;
            if !used(op1_type)
                && let Some(literal) = class_reference(raw.op1.value, literals)
            {
                out.op1_type = OperandType::Const;
                out.op1 = literal;
            }
            out.op2_type = op2_type;
            out.op2 = op2;
            if !used(op2_type) {
                out.op2_type = OperandType::Const;
                out.op2 = push_literal(literals, Literal::Str("__construct".to_owned()));
            }
            out.result_type = OperandType::Unused;
            out.result = 0;
            out.extended_value = raw.extended_value;
        }
        op::FETCH_CLASS => {
            out.op2_type = op2_type;
            out.op2 = op2;
            if !used(op2_type)
                && let Some(literal) = class_reference(raw.op1.value, literals)
            {
                out.op2_type = OperandType::Const;
                out.op2 = literal;
            }
        }
        op::INSTANCEOF => {
            out.op1_type = op1_type;
            out.op1 = op1;
            out.op2_type = op2_type;
            out.op2 = op2;
            if !used(op2_type)
                && let Some(literal) = class_reference(raw.op2.value, literals)
            {
                out.op2_type = OperandType::Const;
                out.op2 = literal;
            }
        }
        op::FETCH_STATIC_PROP_R
        | op::FETCH_STATIC_PROP_W
        | op::FETCH_STATIC_PROP_RW
        | FETCH_STATIC_PROP_IS
        | FETCH_STATIC_PROP_FUNC_ARG
        | FETCH_STATIC_PROP_UNSET
        | op::ASSIGN_STATIC_PROP
        | op::ASSIGN_STATIC_PROP_REF
        | op::ASSIGN_STATIC_PROP_OP
        | op::PRE_INC_STATIC_PROP
        | op::PRE_DEC_STATIC_PROP
        | op::POST_INC_STATIC_PROP
        | op::POST_DEC_STATIC_PROP => {
            out.opcode = match raw.opcode {
                FETCH_STATIC_PROP_FUNC_ARG => op::FETCH_STATIC_PROP_R,
                FETCH_STATIC_PROP_UNSET => op::FETCH_STATIC_PROP_W,
                other => other,
            };
            out.op1_type = op1_type;
            out.op1 = op1;
            out.op2_type = op2_type;
            out.op2 = op2;
            if !used(op2_type)
                && let Some(literal) = class_reference(raw.op2.value, literals)
            {
                out.op2_type = OperandType::Const;
                out.op2 = literal;
            }
            if raw.opcode == op::ASSIGN_STATIC_PROP_OP {
                out.extended_value = raw.extended_value;
            }
        }
        op::FETCH_CLASS_CONSTANT | op::FETCH_CLASS_NAME => {
            out.op1_type = op1_type;
            out.op1 = op1;
            if !used(op1_type)
                && let Some(literal) = class_reference(raw.op1.value, literals)
            {
                out.op1_type = OperandType::Const;
                out.op1 = literal;
            }
            out.op2_type = op2_type;
            out.op2 = op2;
        }
        op::ASSIGN_OP
        | op::ASSIGN_DIM_OP
        | op::ASSIGN_OBJ_OP
        | op::CAST
        | op::TYPE_CHECK
        | op::ROPE_INIT
        | op::ROPE_ADD
        | op::ROPE_END => {
            out.op1_type = op1_type;
            out.op1 = op1;
            out.op2_type = op2_type;
            out.op2 = op2;
            out.extended_value = raw.extended_value;
        }
        op::ISSET_ISEMPTY_VAR => {
            out.op1_type = op1_type;
            out.op1 = op1;
            out.extended_value = raw.extended_value & ISEMPTY;
            if raw.extended_value & FETCH_TYPE_MASK != FETCH_LOCAL {
                out.extended_value |= raw.extended_value & FETCH_TYPE_MASK;
            }
        }
        op::ISSET_ISEMPTY_DIM_OBJ | op::ISSET_ISEMPTY_PROP_OBJ | op::ISSET_ISEMPTY_CV => {
            out.op1_type = op1_type;
            out.op1 = op1;
            out.op2_type = op2_type;
            out.op2 = op2;
            out.extended_value = raw.extended_value & ISEMPTY;
        }
        op::DECLARE_LAMBDA_FUNCTION => {
            let ordinal: Option<u32> = closure_ordinals
                .get(raw.op2.value as usize)
                .copied()
                .flatten();
            let Some(ordinal) = ordinal else {
                return Err(Error::OpcacheLayout {
                    field: "closure index",
                    value: u64::from(raw.op2.value),
                });
            };
            out.extended_value = ordinal;
        }
        op::RECV_VARIADIC => {
            out.op1 = raw.op1.value;
        }
        op::RECV | op::RECV_INIT => {
            out.op2_type = if raw.opcode == op::RECV_INIT {
                op2_type
            } else {
                OperandType::Unused
            };
            out.op2 = if raw.opcode == op::RECV_INIT { op2 } else { 0 };
        }
        op::SEND_VAL
        | op::SEND_VAL_EX
        | op::SEND_VAR
        | op::SEND_VAR_EX
        | op::SEND_REF
        | SEND_VAR_NO_REF
        | SEND_VAR_NO_REF_EX
        | SEND_FUNC_ARG => {
            out.op1_type = op1_type;
            out.op1 = op1;
            out.result_type = OperandType::Unused;
            out.result = 0;
            if op2_type == OperandType::Const {
                out.opcode = match raw.opcode {
                    SEND_VAR_NO_REF | SEND_VAR_NO_REF_EX | SEND_FUNC_ARG => op::SEND_VAR,
                    other => other,
                };
                out.op2_type = op2_type;
                out.op2 = op2;
            } else {
                out.opcode = op::SEND_VAL;
            }
        }
        op::SEND_UNPACK => {
            out.op1_type = op1_type;
            out.op1 = op1;
            out.op2 = raw.op2.value;
        }
        op::INIT_ARRAY | op::ADD_ARRAY_ELEMENT => {
            out.op1_type = op1_type;
            out.op1 = op1;
            out.op2_type = op2_type;
            out.op2 = op2;
            out.extended_value = raw.extended_value & ARRAY_ELEMENT_REF;
        }
        op::FETCH_IS => {
            out.op1_type = op1_type;
            out.op1 = op1;
            out.extended_value = match raw.extended_value & FETCH_TYPE_MASK {
                FETCH_LOCAL => 0,
                FETCH_GLOBAL => 1,
                FETCH_GLOBAL_LOCK => 3,
                other => other,
            };
        }
        op::FETCH_R | op::FETCH_W | op::FETCH_RW | FETCH_FUNC_ARG | FETCH_UNSET | op::UNSET_VAR => {
            out.opcode = match raw.opcode {
                FETCH_FUNC_ARG => op::FETCH_R,
                FETCH_UNSET => op::FETCH_W,
                other => other,
            };
            out.op1_type = op1_type;
            out.op1 = op1;
            let fetch: u32 = raw.extended_value & FETCH_TYPE_MASK;
            out.extended_value = if fetch == FETCH_LOCAL { 0 } else { fetch };
        }
        FETCH_DIM_FUNC_ARG | FETCH_DIM_UNSET | FETCH_OBJ_FUNC_ARG | FETCH_OBJ_UNSET => {
            out.opcode = match raw.opcode {
                FETCH_DIM_FUNC_ARG => op::FETCH_DIM_R,
                FETCH_DIM_UNSET => op::FETCH_DIM_W,
                FETCH_OBJ_FUNC_ARG => op::FETCH_OBJ_R,
                _ => op::FETCH_OBJ_W,
            };
            out.op1_type = op1_type;
            out.op1 = op1;
            out.op2_type = op2_type;
            out.op2 = op2;
        }
        CHECK_FUNC_ARG => {
            out.opcode = op::NOP;
        }
        op::DECLARE_CLASS | op::DECLARE_CLASS_DELAYED => {
            let key: u32 = op1.saturating_add(1);
            if op1_type != OperandType::Const || key as usize >= literals.len() {
                return Err(Error::OpcacheLayout {
                    field: "class declaration key",
                    value: u64::from(op1),
                });
            }
            out.op1_type = OperandType::Const;
            out.op1 = key;
            out.op2_type = op2_type;
            out.op2 = op2;
        }
        op::BIND_LEXICAL => {
            out.op1_type = op1_type;
            out.op1 = op1;
            out.op2_type = op2_type;
            out.op2 = op2;
            let mode: u32 = raw.extended_value & BIND_MODE_MASK;
            out.extended_value = (u32::from(mode & BIND_REF != 0) * BIND_LEXICAL_BY_REFERENCE)
                | (u32::from(mode & BIND_IMPLICIT != 0) * BIND_LEXICAL_IMPLICIT);
        }
        op::BIND_STATIC if raw.extended_value & (BIND_IMPLICIT | BIND_EXPLICIT) != 0 => {
            out.opcode = op::NOP;
            out.result_type = OperandType::Unused;
            out.result = 0;
        }
        op::BIND_STATIC => {
            out.op1_type = op1_type;
            out.op1 = op1;
            out.op2_type = op2_type;
            out.op2 = op2;
            let offset: u32 = raw.extended_value & !BIND_MODE_MASK;
            if !offset.is_multiple_of(BUCKET_SIZE as u32) {
                return Err(Error::OpcacheLayout {
                    field: "static variable offset",
                    value: u64::from(offset),
                });
            }
            out.extended_value = offset / BUCKET_SIZE as u32;
        }
        FRAMELESS_ICALL_0..=FRAMELESS_ICALL_3 => {
            out.op1_type = op1_type;
            out.op1 = op1;
            out.op2_type = op2_type;
            out.op2 = op2;
            let arity: u8 = raw.opcode - FRAMELESS_ICALL_0;
            let function: Option<&(&str, u8)> =
                FRAMELESS_FUNCTIONS.get(raw.extended_value as usize);
            match function {
                Some((name, expected)) if *expected == arity => {
                    out.extended_value = push_literal(literals, Literal::Str((*name).to_owned()));
                }
                _ => {
                    out.extended_value = u32::MAX;
                }
            }
        }
        FAST_CONCAT | STRLEN | COUNT | VERIFY_RETURN_TYPE | FE_FREE | GENERATOR_CREATE => {
            out.opcode = match raw.opcode {
                FAST_CONCAT => op::CONCAT,
                STRLEN => op::STRLEN,
                COUNT => op::COUNT,
                VERIFY_RETURN_TYPE => op::VERIFY_RETURN_TYPE,
                FE_FREE => op::FE_FREE,
                _ => op::GENERATOR_CREATE,
            };
            out.op1_type = op1_type;
            out.op1 = op1;
            if raw.opcode == FAST_CONCAT {
                out.op2_type = op2_type;
                out.op2 = op2;
            }
        }
        op::RETURN | op::RETURN_BY_REF | op::INCLUDE_OR_EVAL | op::ASSIGN_REF | CASE_STRICT => {
            out.op1_type = op1_type;
            out.op1 = op1;
            out.op2_type = op2_type;
            out.op2 = op2;
            out.extended_value = raw.extended_value;
            if raw.opcode == op::ASSIGN_REF {
                out.extended_value = 0;
            }
        }
        _ => {
            out.op1_type = op1_type;
            out.op1 = op1;
            out.op2_type = op2_type;
            out.op2 = op2;
        }
    }
    Ok(out)
}

fn class_reference(fetch: u32, literals: &mut Vec<Literal>) -> Option<u32> {
    let name: &str = match fetch & FETCH_CLASS_MASK {
        FETCH_CLASS_SELF => "self",
        FETCH_CLASS_PARENT => "parent",
        FETCH_CLASS_STATIC => "static",
        _ => return None,
    };
    Some(push_literal(literals, Literal::Str(name.to_owned())))
}

fn push_literal(literals: &mut Vec<Literal>, literal: Literal) -> u32 {
    literals.push(literal);
    u32::try_from(literals.len() - 1).unwrap_or(u32::MAX)
}

fn operand(raw: &RawOperand, frame: &Frame, literal_count: usize) -> Result<(OperandType, u32)> {
    match raw.kind & 0x0f {
        0 => Ok((OperandType::Unused, 0)),
        1 => {
            if raw.value as usize >= literal_count {
                return Err(Error::OpcacheLayout {
                    field: "constant operand",
                    value: u64::from(raw.value),
                });
            }
            Ok((OperandType::Const, raw.value))
        }
        kind @ (2 | 4 | 8) => {
            let slot: Option<u32> = raw
                .value
                .is_multiple_of(ZVAL_SIZE as u32)
                .then(|| (raw.value / ZVAL_SIZE as u32).checked_sub(CALL_FRAME_SLOTS))
                .flatten()
                .filter(|slot: &u32| *slot < frame.temporaries);
            let Some(slot) = slot else {
                return Err(Error::OpcacheLayout {
                    field: "variable operand",
                    value: u64::from(raw.value),
                });
            };
            let ty: OperandType = match kind {
                2 => OperandType::TmpVar,
                4 => OperandType::Var,
                _ => OperandType::Cv,
            };
            Ok((ty, slot))
        }
        other => Err(Error::OpcacheLayout {
            field: "operand type",
            value: u64::from(other),
        }),
    }
}

fn relative_jump(frame: &Frame, raw: u32) -> Result<u32> {
    let offset: i64 = i64::from(raw as i32);
    let target: Option<u32> = (offset % OP_SIZE as i64 == 0)
        .then(|| i64::from(frame.index) + offset / OP_SIZE as i64)
        .and_then(|target: i64| u32::try_from(target).ok())
        .filter(|target: &u32| *target < frame.op_count);
    target.ok_or_else(|| Error::OpcacheLayout {
        field: "jump offset",
        value: u64::from(raw),
    })
}

fn match_table(frame: &Frame, entries: &[(Literal, Literal)]) -> Result<Option<Literal>> {
    let mut table: Vec<(Literal, u32)> = Vec::with_capacity(entries.len());
    for (key, target) in entries {
        let Literal::Long(offset) = target else {
            return Ok(None);
        };
        if !matches!(key, Literal::Long(_) | Literal::Str(_)) {
            return Ok(None);
        }
        table.push((key.clone(), relative_jump(frame, *offset as u32)?));
    }
    Ok(Some(Literal::MatchTable(table)))
}

fn switch_table(frame: &Frame, entries: &[(Literal, Literal)]) -> Result<Option<Literal>> {
    let mut longs: Vec<(i64, u32)> = Vec::new();
    let mut strings: Vec<(String, u32)> = Vec::new();
    for (key, target) in entries {
        let Literal::Long(offset) = target else {
            return Ok(None);
        };
        let target: u32 = relative_jump(frame, *offset as u32)?;
        match key {
            Literal::Long(key) => longs.push((*key, target)),
            Literal::Str(key) => strings.push((key.clone(), target)),
            _ => return Ok(None),
        }
    }
    Ok(match (longs.is_empty(), strings.is_empty()) {
        (false, true) => Some(Literal::SwitchLong(longs)),
        (true, false) => Some(Literal::SwitchString(strings)),
        _ => None,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn sealed(mem: &[u8], strings: &[u8], script_offset: u64) -> Vec<u8> {
        let mut image: Vec<u8> = Vec::with_capacity(HEADER_LEN + mem.len() + strings.len());
        image.extend_from_slice(OPCACHE_MAGIC);
        image.extend_from_slice(&[0; 32]);
        image.extend_from_slice(&(mem.len() as u64).to_le_bytes());
        image.extend_from_slice(&(strings.len() as u64).to_le_bytes());
        image.extend_from_slice(&script_offset.to_le_bytes());
        image.extend_from_slice(&0u64.to_le_bytes());
        let checksum: u32 = adler32(adler32(1, mem), strings);
        image.extend_from_slice(&checksum.to_le_bytes());
        image.extend_from_slice(&[0; 4]);
        image.extend_from_slice(mem);
        image.extend_from_slice(strings);
        image
    }

    fn put_u32(mem: &mut [u8], at: u64, value: u32) {
        mem[at as usize..at as usize + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(mem: &mut [u8], at: u64, value: u64) {
        mem[at as usize..at as usize + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn empty_script() -> Vec<u8> {
        let mut mem: Vec<u8> = vec![0; 512];
        mem[(SCRIPT_MAIN_OP_ARRAY + OA_TYPE) as usize] = ZEND_USER_FUNCTION;
        put_u32(
            &mut mem,
            SCRIPT_FUNCTION_TABLE + HT_FLAGS,
            HASH_FLAG_UNINITIALIZED,
        );
        put_u32(
            &mut mem,
            SCRIPT_CLASS_TABLE + HT_FLAGS,
            HASH_FLAG_UNINITIALIZED,
        );
        mem
    }

    #[test]
    fn a_minimal_image_parses_to_an_empty_main() {
        let parsed: OpArray =
            parse_opcache_file(&sealed(&empty_script(), &[], 0)).expect("minimal image parses");
        assert_eq!(parsed.kind, OpArrayKind::Main);
        assert!(parsed.ops.is_empty() && parsed.children.is_empty() && parsed.classes.is_empty());
    }

    #[test]
    fn a_wrong_magic_short_header_or_changed_byte_is_a_typed_error() {
        let image: Vec<u8> = sealed(&empty_script(), &[], 0);
        let mut wrong: Vec<u8> = image.clone();
        wrong[0] = b'X';
        assert!(matches!(
            parse_opcache_file(&wrong),
            Err(Error::OpcacheBadMagic)
        ));
        assert!(matches!(
            parse_opcache_file(&image[..40]),
            Err(Error::OpcacheTruncated { .. })
        ));
        assert!(matches!(
            parse_opcache_file(&image[..image.len() - 1]),
            Err(Error::OpcacheTruncated { .. })
        ));
        let mut changed: Vec<u8> = image;
        let last: usize = changed.len() - 1;
        changed[last] ^= 1;
        assert!(matches!(
            parse_opcache_file(&changed),
            Err(Error::OpcacheChecksum { .. })
        ));
    }

    #[test]
    fn a_dynamic_function_table_that_points_back_at_its_owner_is_bounded() {
        let mut mem: Vec<u8> = empty_script();
        let table: u64 = 400;
        put_u32(&mut mem, SCRIPT_MAIN_OP_ARRAY + OA_NUM_DYNAMIC, 1);
        put_u64(&mut mem, SCRIPT_MAIN_OP_ARRAY + OA_DYNAMIC, table);
        put_u64(&mut mem, table, SCRIPT_MAIN_OP_ARRAY);
        let outcome: Result<OpArray> = parse_opcache_file(&sealed(&mem, &[], 0));
        assert!(
            matches!(
                outcome,
                Err(Error::OpcacheNestTooDeep(_) | Error::OpcacheOversize { .. })
            ),
            "a self-referencing closure table must stop at the nesting bound: {outcome:?}"
        );
    }

    #[test]
    fn an_opcode_array_pointer_outside_the_image_is_rejected() {
        let mut mem: Vec<u8> = empty_script();
        put_u32(&mut mem, SCRIPT_MAIN_OP_ARRAY + OA_LAST, 1);
        put_u64(&mut mem, SCRIPT_MAIN_OP_ARRAY + OA_OPCODES, 1 << 40);
        assert!(matches!(
            parse_opcache_file(&sealed(&mem, &[], 0)),
            Err(Error::OpcacheBadPointer { .. })
        ));
    }

    #[test]
    fn a_declared_count_beyond_its_cap_is_rejected_before_reading() {
        let mut mem: Vec<u8> = empty_script();
        put_u32(&mut mem, SCRIPT_MAIN_OP_ARRAY + OA_LAST, MAX_OPS + 1);
        assert!(matches!(
            parse_opcache_file(&sealed(&mem, &[], 0)),
            Err(Error::OpcacheOversize { field: "last", .. })
        ));
    }

    #[test]
    fn frameless_calls_are_named_only_when_the_table_arity_matches_the_opcode() {
        let frame: Frame = Frame {
            temporaries: 4,
            op_count: 1,
            index: 0,
        };
        let raw = |opcode: u8, extended_value: u32| RawOp {
            opcode,
            op1: RawOperand { kind: 8, value: 80 },
            op2: RawOperand { kind: 8, value: 96 },
            result: RawOperand {
                kind: 2,
                value: 112,
            },
            extended_value,
            lineno: 1,
        };
        let mut literals: Vec<Literal> = Vec::new();
        let named: Op = lower(&raw(FRAMELESS_ICALL_0 + 2, 7), &frame, &mut literals, &[])
            .expect("a two-argument in_array lowers");
        assert_eq!(
            literals.get(named.extended_value as usize),
            Some(&Literal::Str("in_array".to_owned()))
        );
        let mismatched: Op = lower(&raw(FRAMELESS_ICALL_0 + 3, 7), &frame, &mut literals, &[])
            .expect("a mismatched frameless call still lowers");
        assert_eq!(mismatched.extended_value, u32::MAX);
    }
}
