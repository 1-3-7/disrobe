use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgKind {
    None,
    Uint1,
    Uint2,
    Uint4,
    Uint8,
    Int4,
    DecimalNlLong,
    DecimalNlShort,
    Float8,
    FloatNl,
    StringNl,
    StringNlNoEscape,
    StringNlNoEscapePair,
    String1,
    String4,
    Bytes1,
    Bytes4,
    Bytes8,
    ByteArray8,
    UnicodeStringNl,
    UnicodeString1,
    UnicodeString4,
    UnicodeString8,
    Long1,
    Long4,
}

impl ArgKind {
    #[inline]
    #[must_use]
    pub const fn fixed_len(self) -> Option<usize> {
        match self {
            Self::None => Some(0),
            Self::Uint1 | Self::Long1 | Self::Bytes1 | Self::String1 | Self::UnicodeString1 => {
                Some(1)
            }
            Self::Uint2 => Some(2),
            Self::Uint4
            | Self::Int4
            | Self::Long4
            | Self::Bytes4
            | Self::String4
            | Self::UnicodeString4 => Some(4),
            Self::Uint8 | Self::Float8 | Self::Bytes8 | Self::ByteArray8 | Self::UnicodeString8 => {
                Some(8)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    PushConst,
    PushMark,
    PushMemo,
    StoreMemo,
    Build,
    Pop,
    Reduce,
    Global,
    StackGlobal,
    Ext,
    Stop,
    Frame,
    Proto,
    PersId,
    NextBuffer,
    ReadonlyBuffer,
    Dup,
}

#[derive(Debug, Clone, Copy)]
pub struct OpInfo {
    pub code: u8,
    pub name: &'static str,
    pub arg: ArgKind,
    pub proto: u8,
    pub effect: Effect,
}

macro_rules! op {
    ($code:literal, $name:literal, $arg:ident, $proto:literal, $effect:ident) => {
        OpInfo {
            code: $code,
            name: $name,
            arg: ArgKind::$arg,
            proto: $proto,
            effect: Effect::$effect,
        }
    };
}

pub const OPCODES: &[OpInfo] = &[
    op!(0x28, "MARK", None, 0, PushMark),
    op!(0x29, "EMPTY_TUPLE", None, 1, PushConst),
    op!(0x2e, "STOP", None, 0, Stop),
    op!(0x30, "POP", None, 0, Pop),
    op!(0x31, "POP_MARK", None, 1, Pop),
    op!(0x32, "DUP", None, 0, Dup),
    op!(0x42, "BINBYTES", Bytes4, 3, PushConst),
    op!(0x43, "SHORT_BINBYTES", Bytes1, 3, PushConst),
    op!(0x46, "FLOAT", FloatNl, 0, PushConst),
    op!(0x47, "BINFLOAT", Float8, 1, PushConst),
    op!(0x49, "INT", DecimalNlShort, 0, PushConst),
    op!(0x4a, "BININT", Int4, 1, PushConst),
    op!(0x4b, "BININT1", Uint1, 1, PushConst),
    op!(0x4c, "LONG", DecimalNlLong, 0, PushConst),
    op!(0x4d, "BININT2", Uint2, 1, PushConst),
    op!(0x4e, "NONE", None, 0, PushConst),
    op!(0x50, "PERSID", StringNlNoEscape, 0, PersId),
    op!(0x51, "BINPERSID", None, 1, PersId),
    op!(0x52, "REDUCE", None, 0, Reduce),
    op!(0x53, "STRING", StringNl, 0, PushConst),
    op!(0x54, "BINSTRING", String4, 1, PushConst),
    op!(0x55, "SHORT_BINSTRING", String1, 1, PushConst),
    op!(0x56, "UNICODE", UnicodeStringNl, 0, PushConst),
    op!(0x58, "BINUNICODE", UnicodeString4, 1, PushConst),
    op!(0x5d, "EMPTY_LIST", None, 1, PushConst),
    op!(0x61, "APPEND", None, 0, Build),
    op!(0x62, "BUILD", None, 0, Build),
    op!(0x63, "GLOBAL", StringNlNoEscapePair, 0, Global),
    op!(0x64, "DICT", None, 0, Build),
    op!(0x65, "APPENDS", None, 1, Build),
    op!(0x67, "GET", DecimalNlShort, 0, PushMemo),
    op!(0x68, "BINGET", Uint1, 1, PushMemo),
    op!(0x69, "INST", StringNlNoEscapePair, 0, Reduce),
    op!(0x6a, "LONG_BINGET", Uint4, 1, PushMemo),
    op!(0x6c, "LIST", None, 0, Build),
    op!(0x6f, "OBJ", None, 1, Reduce),
    op!(0x70, "PUT", DecimalNlShort, 0, StoreMemo),
    op!(0x71, "BINPUT", Uint1, 1, StoreMemo),
    op!(0x72, "LONG_BINPUT", Uint4, 1, StoreMemo),
    op!(0x73, "SETITEM", None, 0, Build),
    op!(0x74, "TUPLE", None, 0, Build),
    op!(0x75, "SETITEMS", None, 1, Build),
    op!(0x7d, "EMPTY_DICT", None, 1, PushConst),
    op!(0x80, "PROTO", Uint1, 2, Proto),
    op!(0x81, "NEWOBJ", None, 2, Reduce),
    op!(0x82, "EXT1", Uint1, 2, Ext),
    op!(0x83, "EXT2", Uint2, 2, Ext),
    op!(0x84, "EXT4", Int4, 2, Ext),
    op!(0x85, "TUPLE1", None, 2, Build),
    op!(0x86, "TUPLE2", None, 2, Build),
    op!(0x87, "TUPLE3", None, 2, Build),
    op!(0x88, "NEWTRUE", None, 2, PushConst),
    op!(0x89, "NEWFALSE", None, 2, PushConst),
    op!(0x8a, "LONG1", Long1, 2, PushConst),
    op!(0x8b, "LONG4", Long4, 2, PushConst),
    op!(0x8c, "SHORT_BINUNICODE", UnicodeString1, 4, PushConst),
    op!(0x8d, "BINUNICODE8", UnicodeString8, 4, PushConst),
    op!(0x8e, "BINBYTES8", Bytes8, 4, PushConst),
    op!(0x8f, "EMPTY_SET", None, 4, PushConst),
    op!(0x90, "ADDITEMS", None, 4, Build),
    op!(0x91, "FROZENSET", None, 4, Build),
    op!(0x92, "NEWOBJ_EX", None, 4, Reduce),
    op!(0x93, "STACK_GLOBAL", None, 4, StackGlobal),
    op!(0x94, "MEMOIZE", None, 4, StoreMemo),
    op!(0x95, "FRAME", Uint8, 4, Frame),
    op!(0x96, "BYTEARRAY8", ByteArray8, 5, PushConst),
    op!(0x97, "NEXT_BUFFER", None, 5, NextBuffer),
    op!(0x98, "READONLY_BUFFER", None, 5, ReadonlyBuffer),
];

static TABLE: OnceLock<[Option<OpInfo>; 256]> = OnceLock::new();

fn table() -> &'static [Option<OpInfo>; 256] {
    TABLE.get_or_init(|| {
        let mut t: [Option<OpInfo>; 256] = [None; 256];
        for info in OPCODES {
            t[info.code as usize] = Some(*info);
        }
        t
    })
}

#[inline]
#[must_use]
pub fn lookup(code: u8) -> Option<&'static OpInfo> {
    table()[code as usize].as_ref()
}

#[inline]
#[must_use]
pub const fn max_proto() -> u8 {
    5
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn every_opcode_is_unique() {
        let mut seen: [bool; 256] = [false; 256];
        for info in OPCODES {
            assert!(!seen[info.code as usize], "duplicate code {:#x}", info.code);
            seen[info.code as usize] = true;
        }
    }

    #[test]
    fn table_count_matches() {
        assert_eq!(OPCODES.len(), 68);
    }

    #[test]
    fn proto_opener_is_known() {
        let info: &OpInfo = lookup(0x80).expect("PROTO");
        assert_eq!(info.name, "PROTO");
        assert_eq!(info.arg, ArgKind::Uint1);
    }

    #[test]
    fn stack_global_present() {
        assert_eq!(lookup(0x93).expect("STACK_GLOBAL").name, "STACK_GLOBAL");
    }

    #[test]
    fn fixed_len_correct() {
        assert_eq!(ArgKind::Uint8.fixed_len(), Some(8));
        assert_eq!(ArgKind::StringNl.fixed_len(), None);
    }
}
