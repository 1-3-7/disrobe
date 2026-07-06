use serde::{Deserialize, Serialize};

use crate::debug::{dbg_kv, dbg_line};
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperandKind {
    InlineNone,
    InlineI,
    InlineI8,
    InlineR,
    InlineShortR,
    InlineVar,
    InlineShortVar,
    InlineShortI,
    InlineMethod,
    InlineField,
    InlineType,
    InlineString,
    InlineSig,
    InlineTok,
    InlineBrTarget,
    InlineShortBrTarget,
    InlineSwitch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FlowControl {
    Next,
    Branch,
    CondBranch,
    Call,
    Return,
    Throw,
    Break,
    Meta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OpcodeDef {
    pub code: u16,
    pub name: &'static str,
    pub operand: OperandKind,
    pub flow: FlowControl,
    pub size: u8,
}

impl OpcodeDef {
    #[inline]
    #[must_use]
    pub const fn one(
        code: u8,
        name: &'static str,
        operand: OperandKind,
        flow: FlowControl,
    ) -> Self {
        Self {
            code: code as u16,
            name,
            operand,
            flow,
            size: 1,
        }
    }

    #[inline]
    #[must_use]
    pub const fn two(
        code: u8,
        name: &'static str,
        operand: OperandKind,
        flow: FlowControl,
    ) -> Self {
        Self {
            code: 0xFE00 | code as u16,
            name,
            operand,
            flow,
            size: 2,
        }
    }
}

#[allow(clippy::too_many_lines)]
pub const ONE_BYTE_OPCODES: &[OpcodeDef] = &[
    OpcodeDef::one(0x00, "nop", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x01, "break", OperandKind::InlineNone, FlowControl::Break),
    OpcodeDef::one(0x02, "ldarg.0", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x03, "ldarg.1", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x04, "ldarg.2", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x05, "ldarg.3", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x06, "ldloc.0", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x07, "ldloc.1", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x08, "ldloc.2", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x09, "ldloc.3", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x0A, "stloc.0", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x0B, "stloc.1", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x0C, "stloc.2", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x0D, "stloc.3", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(
        0x0E,
        "ldarg.s",
        OperandKind::InlineShortVar,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0x0F,
        "ldarga.s",
        OperandKind::InlineShortVar,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0x10,
        "starg.s",
        OperandKind::InlineShortVar,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0x11,
        "ldloc.s",
        OperandKind::InlineShortVar,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0x12,
        "ldloca.s",
        OperandKind::InlineShortVar,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0x13,
        "stloc.s",
        OperandKind::InlineShortVar,
        FlowControl::Next,
    ),
    OpcodeDef::one(0x14, "ldnull", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(
        0x15,
        "ldc.i4.m1",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(0x16, "ldc.i4.0", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x17, "ldc.i4.1", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x18, "ldc.i4.2", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x19, "ldc.i4.3", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x1A, "ldc.i4.4", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x1B, "ldc.i4.5", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x1C, "ldc.i4.6", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x1D, "ldc.i4.7", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x1E, "ldc.i4.8", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(
        0x1F,
        "ldc.i4.s",
        OperandKind::InlineShortI,
        FlowControl::Next,
    ),
    OpcodeDef::one(0x20, "ldc.i4", OperandKind::InlineI, FlowControl::Next),
    OpcodeDef::one(0x21, "ldc.i8", OperandKind::InlineI8, FlowControl::Next),
    OpcodeDef::one(0x22, "ldc.r4", OperandKind::InlineShortR, FlowControl::Next),
    OpcodeDef::one(0x23, "ldc.r8", OperandKind::InlineR, FlowControl::Next),
    OpcodeDef::one(0x25, "dup", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x26, "pop", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x27, "jmp", OperandKind::InlineMethod, FlowControl::Call),
    OpcodeDef::one(0x28, "call", OperandKind::InlineMethod, FlowControl::Call),
    OpcodeDef::one(0x29, "calli", OperandKind::InlineSig, FlowControl::Call),
    OpcodeDef::one(0x2A, "ret", OperandKind::InlineNone, FlowControl::Return),
    OpcodeDef::one(
        0x2B,
        "br.s",
        OperandKind::InlineShortBrTarget,
        FlowControl::Branch,
    ),
    OpcodeDef::one(
        0x2C,
        "brfalse.s",
        OperandKind::InlineShortBrTarget,
        FlowControl::CondBranch,
    ),
    OpcodeDef::one(
        0x2D,
        "brtrue.s",
        OperandKind::InlineShortBrTarget,
        FlowControl::CondBranch,
    ),
    OpcodeDef::one(
        0x2E,
        "beq.s",
        OperandKind::InlineShortBrTarget,
        FlowControl::CondBranch,
    ),
    OpcodeDef::one(
        0x2F,
        "bge.s",
        OperandKind::InlineShortBrTarget,
        FlowControl::CondBranch,
    ),
    OpcodeDef::one(
        0x30,
        "bgt.s",
        OperandKind::InlineShortBrTarget,
        FlowControl::CondBranch,
    ),
    OpcodeDef::one(
        0x31,
        "ble.s",
        OperandKind::InlineShortBrTarget,
        FlowControl::CondBranch,
    ),
    OpcodeDef::one(
        0x32,
        "blt.s",
        OperandKind::InlineShortBrTarget,
        FlowControl::CondBranch,
    ),
    OpcodeDef::one(
        0x33,
        "bne.un.s",
        OperandKind::InlineShortBrTarget,
        FlowControl::CondBranch,
    ),
    OpcodeDef::one(
        0x34,
        "bge.un.s",
        OperandKind::InlineShortBrTarget,
        FlowControl::CondBranch,
    ),
    OpcodeDef::one(
        0x35,
        "bgt.un.s",
        OperandKind::InlineShortBrTarget,
        FlowControl::CondBranch,
    ),
    OpcodeDef::one(
        0x36,
        "ble.un.s",
        OperandKind::InlineShortBrTarget,
        FlowControl::CondBranch,
    ),
    OpcodeDef::one(
        0x37,
        "blt.un.s",
        OperandKind::InlineShortBrTarget,
        FlowControl::CondBranch,
    ),
    OpcodeDef::one(0x38, "br", OperandKind::InlineBrTarget, FlowControl::Branch),
    OpcodeDef::one(
        0x39,
        "brfalse",
        OperandKind::InlineBrTarget,
        FlowControl::CondBranch,
    ),
    OpcodeDef::one(
        0x3A,
        "brtrue",
        OperandKind::InlineBrTarget,
        FlowControl::CondBranch,
    ),
    OpcodeDef::one(
        0x3B,
        "beq",
        OperandKind::InlineBrTarget,
        FlowControl::CondBranch,
    ),
    OpcodeDef::one(
        0x3C,
        "bge",
        OperandKind::InlineBrTarget,
        FlowControl::CondBranch,
    ),
    OpcodeDef::one(
        0x3D,
        "bgt",
        OperandKind::InlineBrTarget,
        FlowControl::CondBranch,
    ),
    OpcodeDef::one(
        0x3E,
        "ble",
        OperandKind::InlineBrTarget,
        FlowControl::CondBranch,
    ),
    OpcodeDef::one(
        0x3F,
        "blt",
        OperandKind::InlineBrTarget,
        FlowControl::CondBranch,
    ),
    OpcodeDef::one(
        0x40,
        "bne.un",
        OperandKind::InlineBrTarget,
        FlowControl::CondBranch,
    ),
    OpcodeDef::one(
        0x41,
        "bge.un",
        OperandKind::InlineBrTarget,
        FlowControl::CondBranch,
    ),
    OpcodeDef::one(
        0x42,
        "bgt.un",
        OperandKind::InlineBrTarget,
        FlowControl::CondBranch,
    ),
    OpcodeDef::one(
        0x43,
        "ble.un",
        OperandKind::InlineBrTarget,
        FlowControl::CondBranch,
    ),
    OpcodeDef::one(
        0x44,
        "blt.un",
        OperandKind::InlineBrTarget,
        FlowControl::CondBranch,
    ),
    OpcodeDef::one(
        0x45,
        "switch",
        OperandKind::InlineSwitch,
        FlowControl::CondBranch,
    ),
    OpcodeDef::one(0x46, "ldind.i1", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x47, "ldind.u1", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x48, "ldind.i2", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x49, "ldind.u2", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x4A, "ldind.i4", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x4B, "ldind.u4", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x4C, "ldind.i8", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x4D, "ldind.i", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x4E, "ldind.r4", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x4F, "ldind.r8", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(
        0x50,
        "ldind.ref",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0x51,
        "stind.ref",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(0x52, "stind.i1", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x53, "stind.i2", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x54, "stind.i4", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x55, "stind.i8", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x56, "stind.r4", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x57, "stind.r8", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x58, "add", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x59, "sub", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x5A, "mul", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x5B, "div", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x5C, "div.un", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x5D, "rem", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x5E, "rem.un", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x5F, "and", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x60, "or", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x61, "xor", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x62, "shl", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x63, "shr", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x64, "shr.un", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x65, "neg", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x66, "not", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x67, "conv.i1", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x68, "conv.i2", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x69, "conv.i4", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x6A, "conv.i8", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x6B, "conv.r4", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x6C, "conv.r8", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x6D, "conv.u4", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x6E, "conv.u8", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(
        0x6F,
        "callvirt",
        OperandKind::InlineMethod,
        FlowControl::Call,
    ),
    OpcodeDef::one(0x70, "cpobj", OperandKind::InlineType, FlowControl::Next),
    OpcodeDef::one(0x71, "ldobj", OperandKind::InlineType, FlowControl::Next),
    OpcodeDef::one(0x72, "ldstr", OperandKind::InlineString, FlowControl::Next),
    OpcodeDef::one(0x73, "newobj", OperandKind::InlineMethod, FlowControl::Call),
    OpcodeDef::one(
        0x74,
        "castclass",
        OperandKind::InlineType,
        FlowControl::Next,
    ),
    OpcodeDef::one(0x75, "isinst", OperandKind::InlineType, FlowControl::Next),
    OpcodeDef::one(
        0x76,
        "conv.r.un",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(0x79, "unbox", OperandKind::InlineType, FlowControl::Next),
    OpcodeDef::one(0x7A, "throw", OperandKind::InlineNone, FlowControl::Throw),
    OpcodeDef::one(0x7B, "ldfld", OperandKind::InlineField, FlowControl::Next),
    OpcodeDef::one(0x7C, "ldflda", OperandKind::InlineField, FlowControl::Next),
    OpcodeDef::one(0x7D, "stfld", OperandKind::InlineField, FlowControl::Next),
    OpcodeDef::one(0x7E, "ldsfld", OperandKind::InlineField, FlowControl::Next),
    OpcodeDef::one(0x7F, "ldsflda", OperandKind::InlineField, FlowControl::Next),
    OpcodeDef::one(0x80, "stsfld", OperandKind::InlineField, FlowControl::Next),
    OpcodeDef::one(0x81, "stobj", OperandKind::InlineType, FlowControl::Next),
    OpcodeDef::one(
        0x82,
        "conv.ovf.i1.un",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0x83,
        "conv.ovf.i2.un",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0x84,
        "conv.ovf.i4.un",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0x85,
        "conv.ovf.i8.un",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0x86,
        "conv.ovf.u1.un",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0x87,
        "conv.ovf.u2.un",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0x88,
        "conv.ovf.u4.un",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0x89,
        "conv.ovf.u8.un",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0x8A,
        "conv.ovf.i.un",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0x8B,
        "conv.ovf.u.un",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(0x8C, "box", OperandKind::InlineType, FlowControl::Next),
    OpcodeDef::one(0x8D, "newarr", OperandKind::InlineType, FlowControl::Next),
    OpcodeDef::one(0x8E, "ldlen", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0x8F, "ldelema", OperandKind::InlineType, FlowControl::Next),
    OpcodeDef::one(
        0x90,
        "ldelem.i1",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0x91,
        "ldelem.u1",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0x92,
        "ldelem.i2",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0x93,
        "ldelem.u2",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0x94,
        "ldelem.i4",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0x95,
        "ldelem.u4",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0x96,
        "ldelem.i8",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(0x97, "ldelem.i", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(
        0x98,
        "ldelem.r4",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0x99,
        "ldelem.r8",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0x9A,
        "ldelem.ref",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(0x9B, "stelem.i", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(
        0x9C,
        "stelem.i1",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0x9D,
        "stelem.i2",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0x9E,
        "stelem.i4",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0x9F,
        "stelem.i8",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0xA0,
        "stelem.r4",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0xA1,
        "stelem.r8",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0xA2,
        "stelem.ref",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(0xA3, "ldelem", OperandKind::InlineType, FlowControl::Next),
    OpcodeDef::one(0xA4, "stelem", OperandKind::InlineType, FlowControl::Next),
    OpcodeDef::one(
        0xA5,
        "unbox.any",
        OperandKind::InlineType,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0xB3,
        "conv.ovf.i1",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0xB4,
        "conv.ovf.u1",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0xB5,
        "conv.ovf.i2",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0xB6,
        "conv.ovf.u2",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0xB7,
        "conv.ovf.i4",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0xB8,
        "conv.ovf.u4",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0xB9,
        "conv.ovf.i8",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0xBA,
        "conv.ovf.u8",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0xC2,
        "refanyval",
        OperandKind::InlineType,
        FlowControl::Next,
    ),
    OpcodeDef::one(0xC3, "ckfinite", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0xC6, "mkrefany", OperandKind::InlineType, FlowControl::Next),
    OpcodeDef::one(0xD0, "ldtoken", OperandKind::InlineTok, FlowControl::Next),
    OpcodeDef::one(0xD1, "conv.u2", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0xD2, "conv.u1", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0xD3, "conv.i", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(
        0xD4,
        "conv.ovf.i",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0xD5,
        "conv.ovf.u",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(0xD6, "add.ovf", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(
        0xD7,
        "add.ovf.un",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(0xD8, "mul.ovf", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(
        0xD9,
        "mul.ovf.un",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(0xDA, "sub.ovf", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(
        0xDB,
        "sub.ovf.un",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::one(
        0xDC,
        "endfinally",
        OperandKind::InlineNone,
        FlowControl::Return,
    ),
    OpcodeDef::one(
        0xDD,
        "leave",
        OperandKind::InlineBrTarget,
        FlowControl::Branch,
    ),
    OpcodeDef::one(
        0xDE,
        "leave.s",
        OperandKind::InlineShortBrTarget,
        FlowControl::Branch,
    ),
    OpcodeDef::one(0xDF, "stind.i", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::one(0xE0, "conv.u", OperandKind::InlineNone, FlowControl::Next),
];

pub const TWO_BYTE_OPCODES: &[OpcodeDef] = &[
    OpcodeDef::two(0x00, "arglist", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::two(0x01, "ceq", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::two(0x02, "cgt", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::two(0x03, "cgt.un", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::two(0x04, "clt", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::two(0x05, "clt.un", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::two(0x06, "ldftn", OperandKind::InlineMethod, FlowControl::Next),
    OpcodeDef::two(
        0x07,
        "ldvirtftn",
        OperandKind::InlineMethod,
        FlowControl::Next,
    ),
    OpcodeDef::two(0x09, "ldarg", OperandKind::InlineVar, FlowControl::Next),
    OpcodeDef::two(0x0A, "ldarga", OperandKind::InlineVar, FlowControl::Next),
    OpcodeDef::two(0x0B, "starg", OperandKind::InlineVar, FlowControl::Next),
    OpcodeDef::two(0x0C, "ldloc", OperandKind::InlineVar, FlowControl::Next),
    OpcodeDef::two(0x0D, "ldloca", OperandKind::InlineVar, FlowControl::Next),
    OpcodeDef::two(0x0E, "stloc", OperandKind::InlineVar, FlowControl::Next),
    OpcodeDef::two(0x0F, "localloc", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::two(
        0x11,
        "endfilter",
        OperandKind::InlineNone,
        FlowControl::Return,
    ),
    OpcodeDef::two(
        0x12,
        "unaligned.",
        OperandKind::InlineShortI,
        FlowControl::Meta,
    ),
    OpcodeDef::two(
        0x13,
        "volatile.",
        OperandKind::InlineNone,
        FlowControl::Meta,
    ),
    OpcodeDef::two(0x14, "tail.", OperandKind::InlineNone, FlowControl::Meta),
    OpcodeDef::two(0x15, "initobj", OperandKind::InlineType, FlowControl::Next),
    OpcodeDef::two(
        0x16,
        "constrained.",
        OperandKind::InlineType,
        FlowControl::Meta,
    ),
    OpcodeDef::two(0x17, "cpblk", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::two(0x18, "initblk", OperandKind::InlineNone, FlowControl::Next),
    OpcodeDef::two(0x19, "no.", OperandKind::InlineShortI, FlowControl::Meta),
    OpcodeDef::two(0x1A, "rethrow", OperandKind::InlineNone, FlowControl::Throw),
    OpcodeDef::two(0x1C, "sizeof", OperandKind::InlineType, FlowControl::Next),
    OpcodeDef::two(
        0x1D,
        "refanytype",
        OperandKind::InlineNone,
        FlowControl::Next,
    ),
    OpcodeDef::two(
        0x1E,
        "readonly.",
        OperandKind::InlineNone,
        FlowControl::Meta,
    ),
];

#[must_use]
pub fn lookup(code: u16) -> Option<&'static OpcodeDef> {
    if code < 0x100 {
        ONE_BYTE_OPCODES
            .iter()
            .find(|o: &&OpcodeDef| o.code == code)
    } else {
        TWO_BYTE_OPCODES
            .iter()
            .find(|o: &&OpcodeDef| o.code == code)
    }
}

#[must_use]
pub const fn total_opcode_count() -> usize {
    ONE_BYTE_OPCODES.len() + TWO_BYTE_OPCODES.len()
}

#[must_use]
pub const fn ecma_335_spec_total() -> usize {
    220
}

#[must_use]
pub const fn coverage_percent() -> u32 {
    let total: u64 = total_opcode_count() as u64;
    let spec: u64 = ecma_335_spec_total() as u64;
    let pct: u64 = total * 100 / spec;
    if pct > u32::MAX as u64 {
        u32::MAX
    } else {
        #[allow(clippy::cast_possible_truncation)]
        let narrowed: u32 = pct as u32;
        narrowed
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instruction {
    pub offset: u32,
    pub opcode: u16,
    pub name: String,
    pub operand: OperandValue,
    pub flow: FlowControl,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperandValue {
    None,
    I32(i32),
    I64(i64),
    U8(u8),
    U16(u16),
    F32Bits(u32),
    F64Bits(u64),
    BrTarget(i32),
    Token(u32),
    Switch(Vec<i32>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExceptionClauseKind {
    Catch,

    Filter,
    Finally,
    Fault,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionClause {
    pub kind: ExceptionClauseKind,
    pub try_offset: u32,
    pub try_length: u32,
    pub handler_offset: u32,
    pub handler_length: u32,
    pub class_token_or_filter: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodBody {
    pub max_stack: u16,
    pub code_size: u32,
    pub local_var_sig_tok: u32,
    pub init_locals: bool,
    pub instructions: Vec<Instruction>,
    pub exception_clauses: Vec<ExceptionClause>,
}

const COR_IL_METHOD_FAT: u8 = 0x03;
const COR_IL_METHOD_TINY: u8 = 0x02;
const COR_IL_METHOD_MORE_SECTS: u16 = 0x08;
const COR_IL_METHOD_INIT_LOCALS: u16 = 0x10;
const SECT_EH_TABLE: u8 = 0x01;
const SECT_FAT_FORMAT: u8 = 0x40;
const SECT_MORE_SECTS: u8 = 0x80;

pub fn parse_method_body(bytes: &[u8]) -> Result<MethodBody> {
    if bytes.is_empty() {
        return Err(Error::CilTruncated(0));
    }
    let header_byte: u8 = bytes[0];
    let mut more_sects: bool = false;
    let (max_stack, code_size, local_var_sig_tok, init_locals, header_size): (
        u16,
        u32,
        u32,
        bool,
        usize,
    ) = if (header_byte & 0x03) == COR_IL_METHOD_TINY {
        let code_size_v: u32 = u32::from(header_byte >> 2);
        (8, code_size_v, 0, false, 1)
    } else if (header_byte & 0x03) == COR_IL_METHOD_FAT {
        if bytes.len() < 12 {
            return Err(Error::CilTruncated(bytes.len()));
        }
        let flags_size: u16 = u16::from_le_bytes([bytes[0], bytes[1]]);
        let init: bool = (flags_size & COR_IL_METHOD_INIT_LOCALS) != 0;
        more_sects = (flags_size & COR_IL_METHOD_MORE_SECTS) != 0;
        let header_words: usize = usize::from(flags_size >> 12);
        let max_stack_v: u16 = u16::from_le_bytes([bytes[2], bytes[3]]);
        let code_size_v: u32 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let local_sig: u32 = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        (max_stack_v, code_size_v, local_sig, init, header_words * 4)
    } else {
        return Err(Error::BadMethodHeader(header_byte));
    };
    let body_end: usize = header_size + code_size as usize;
    if body_end > bytes.len() {
        return Err(Error::CilTruncated(body_end));
    }
    let code: &[u8] = &bytes[header_size..body_end];
    let instructions: Vec<Instruction> = disassemble(code)?;
    let exception_clauses: Vec<ExceptionClause> = if more_sects {
        parse_exception_sections(bytes, body_end)?
    } else {
        Vec::new()
    };
    dbg_kv("cil-body", || {
        let fat: bool = header_size != 1;
        format!(
            "header={} code_size={code_size} max_stack={max_stack} locals_tok=0x{local_var_sig_tok:x} init_locals={init_locals} instrs={} eh_clauses={}",
            if fat { "fat" } else { "tiny" },
            instructions.len(),
            exception_clauses.len()
        )
    });
    Ok(MethodBody {
        max_stack,
        code_size,
        local_var_sig_tok,
        init_locals,
        instructions,
        exception_clauses,
    })
}

fn parse_exception_sections(bytes: &[u8], code_end: usize) -> Result<Vec<ExceptionClause>> {
    let mut pos: usize = (code_end + 3) & !3usize;
    let mut clauses: Vec<ExceptionClause> = Vec::new();
    loop {
        if pos >= bytes.len() {
            break;
        }
        let kind_byte: u8 = bytes[pos];
        let is_fat: bool = kind_byte & SECT_FAT_FORMAT != 0;
        let more: bool = kind_byte & SECT_MORE_SECTS != 0;
        let is_eh: bool = kind_byte & SECT_EH_TABLE != 0;
        if pos + 4 > bytes.len() {
            break;
        }
        let data_size: usize = if is_fat {
            (usize::from(bytes[pos + 1]))
                | (usize::from(bytes[pos + 2]) << 8)
                | (usize::from(bytes[pos + 3]) << 16)
        } else {
            usize::from(bytes[pos + 1])
        };
        let section_end: usize = pos + data_size.max(4);
        if section_end > bytes.len() {
            return Err(Error::CilTruncated(section_end));
        }
        if is_eh {
            parse_eh_clauses(bytes, pos + 4, section_end, is_fat, &mut clauses);
        }
        if !more {
            break;
        }
        pos = (section_end + 3) & !3usize;
    }
    Ok(clauses)
}

fn parse_eh_clauses(
    bytes: &[u8],
    start: usize,
    end: usize,
    is_fat: bool,
    out: &mut Vec<ExceptionClause>,
) {
    let entry_size: usize = if is_fat { 24 } else { 12 };
    let mut p: usize = start;
    while p + entry_size <= end {
        let (flags, try_offset, try_length, handler_offset, handler_length, class_or_filter): (
            u32,
            u32,
            u32,
            u32,
            u32,
            u32,
        ) = if is_fat {
            (
                u32::from_le_bytes([bytes[p], bytes[p + 1], bytes[p + 2], bytes[p + 3]]),
                u32::from_le_bytes([bytes[p + 4], bytes[p + 5], bytes[p + 6], bytes[p + 7]]),
                u32::from_le_bytes([bytes[p + 8], bytes[p + 9], bytes[p + 10], bytes[p + 11]]),
                u32::from_le_bytes([bytes[p + 12], bytes[p + 13], bytes[p + 14], bytes[p + 15]]),
                u32::from_le_bytes([bytes[p + 16], bytes[p + 17], bytes[p + 18], bytes[p + 19]]),
                u32::from_le_bytes([bytes[p + 20], bytes[p + 21], bytes[p + 22], bytes[p + 23]]),
            )
        } else {
            (
                u32::from(u16::from_le_bytes([bytes[p], bytes[p + 1]])),
                u32::from(u16::from_le_bytes([bytes[p + 2], bytes[p + 3]])),
                u32::from(bytes[p + 4]),
                u32::from(u16::from_le_bytes([bytes[p + 5], bytes[p + 6]])),
                u32::from(bytes[p + 7]),
                u32::from_le_bytes([bytes[p + 8], bytes[p + 9], bytes[p + 10], bytes[p + 11]]),
            )
        };
        let kind: ExceptionClauseKind = match flags & 0x0007 {
            0x0001 => ExceptionClauseKind::Filter,
            0x0002 => ExceptionClauseKind::Finally,
            0x0004 => ExceptionClauseKind::Fault,
            _ => ExceptionClauseKind::Catch,
        };
        out.push(ExceptionClause {
            kind,
            try_offset,
            try_length,
            handler_offset,
            handler_length,
            class_token_or_filter: class_or_filter,
        });
        p += entry_size;
    }
}

pub fn disassemble(code: &[u8]) -> Result<Vec<Instruction>> {
    let mut out: Vec<Instruction> = Vec::with_capacity(code.len() / 2);
    let mut pos: usize = 0;
    while pos < code.len() {
        let start: u32 = u32::try_from(pos).unwrap_or(u32::MAX);
        let b0: u8 = code[pos];
        let (op_code, op_size): (u16, usize) = if b0 == 0xFE {
            if pos + 1 >= code.len() {
                return Err(Error::CilTruncated(pos));
            }
            (0xFE00 | u16::from(code[pos + 1]), 2)
        } else {
            (u16::from(b0), 1)
        };
        let Some(def): Option<&OpcodeDef> = lookup(op_code) else {
            dbg_line(|| format!("disasm bail: unknown opcode 0x{op_code:04x} at offset {pos}"));
            return Err(Error::UnknownOpcode(op_code, pos));
        };
        pos += op_size;
        let (operand, consumed): (OperandValue, usize) = read_operand(def.operand, code, pos)?;
        pos += consumed;
        out.push(Instruction {
            offset: start,
            opcode: op_code,
            name: def.name.to_owned(),
            operand,
            flow: def.flow,
        });
    }
    Ok(out)
}

fn read_operand(kind: OperandKind, code: &[u8], pos: usize) -> Result<(OperandValue, usize)> {
    match kind {
        OperandKind::InlineNone => Ok((OperandValue::None, 0)),
        OperandKind::InlineShortI | OperandKind::InlineShortVar => {
            if pos >= code.len() {
                return Err(Error::CilTruncated(pos));
            }
            Ok((OperandValue::U8(code[pos]), 1))
        }
        OperandKind::InlineVar => {
            if pos + 2 > code.len() {
                return Err(Error::CilTruncated(pos));
            }
            Ok((
                OperandValue::U16(u16::from_le_bytes([code[pos], code[pos + 1]])),
                2,
            ))
        }
        OperandKind::InlineI
        | OperandKind::InlineMethod
        | OperandKind::InlineField
        | OperandKind::InlineType
        | OperandKind::InlineString
        | OperandKind::InlineSig
        | OperandKind::InlineTok => {
            if pos + 4 > code.len() {
                return Err(Error::CilTruncated(pos));
            }
            let v: u32 =
                u32::from_le_bytes([code[pos], code[pos + 1], code[pos + 2], code[pos + 3]]);
            if matches!(kind, OperandKind::InlineI) {
                Ok((OperandValue::I32(v.cast_signed()), 4))
            } else {
                Ok((OperandValue::Token(v), 4))
            }
        }
        OperandKind::InlineI8 => {
            if pos + 8 > code.len() {
                return Err(Error::CilTruncated(pos));
            }
            let mut buf: [u8; 8] = [0u8; 8];
            buf.copy_from_slice(&code[pos..pos + 8]);
            Ok((OperandValue::I64(i64::from_le_bytes(buf)), 8))
        }
        OperandKind::InlineShortR => {
            if pos + 4 > code.len() {
                return Err(Error::CilTruncated(pos));
            }
            Ok((
                OperandValue::F32Bits(u32::from_le_bytes([
                    code[pos],
                    code[pos + 1],
                    code[pos + 2],
                    code[pos + 3],
                ])),
                4,
            ))
        }
        OperandKind::InlineR => {
            if pos + 8 > code.len() {
                return Err(Error::CilTruncated(pos));
            }
            let mut buf: [u8; 8] = [0u8; 8];
            buf.copy_from_slice(&code[pos..pos + 8]);
            Ok((OperandValue::F64Bits(u64::from_le_bytes(buf)), 8))
        }
        OperandKind::InlineShortBrTarget => {
            if pos >= code.len() {
                return Err(Error::CilTruncated(pos));
            }
            Ok((
                OperandValue::BrTarget(i32::from(code[pos].cast_signed())),
                1,
            ))
        }
        OperandKind::InlineBrTarget => {
            if pos + 4 > code.len() {
                return Err(Error::CilTruncated(pos));
            }
            let v: i32 =
                i32::from_le_bytes([code[pos], code[pos + 1], code[pos + 2], code[pos + 3]]);
            Ok((OperandValue::BrTarget(v), 4))
        }
        OperandKind::InlineSwitch => {
            if pos + 4 > code.len() {
                return Err(Error::CilTruncated(pos));
            }
            let n: usize =
                u32::from_le_bytes([code[pos], code[pos + 1], code[pos + 2], code[pos + 3]])
                    as usize;
            let total: usize = 4 + n * 4;
            if pos + total > code.len() {
                return Err(Error::CilTruncated(pos));
            }
            let mut targets: Vec<i32> = Vec::with_capacity(n);
            for i in 0..n {
                let base: usize = pos + 4 + i * 4;
                targets.push(i32::from_le_bytes([
                    code[base],
                    code[base + 1],
                    code[base + 2],
                    code[base + 3],
                ]));
            }
            Ok((OperandValue::Switch(targets), total))
        }
    }
}

#[must_use]
pub(crate) fn fold_null_coalesce(body: &MethodBody) -> MethodBody {
    let instrs: &[Instruction] = &body.instructions;
    let mut rewrites: Vec<CoalesceWindow> = Vec::new();
    for j in 0..instrs.len() {
        if let Some(window) = match_coalesce_window(instrs, j) {
            rewrites.push(window);
        }
    }
    if rewrites.is_empty() {
        return body.clone();
    }
    let mut out: MethodBody = body.clone();
    for window in rewrites.iter().rev() {
        nop_instruction(&mut out.instructions[window.dup]);
        nop_instruction(&mut out.instructions[window.brtrue]);
        nop_instruction(&mut out.instructions[window.pop]);
        if let Some(throw_idx) = window.throw_alt {
            throw_expression_instruction(&mut out.instructions[throw_idx]);
        }
        out.instructions.insert(
            window.merge,
            coalesce_marker(out.instructions[window.merge].offset),
        );
    }
    out
}

#[must_use]
pub(crate) fn fold_null_conditional_call(body: &MethodBody) -> MethodBody {
    let instrs: &[Instruction] = &body.instructions;
    let mut windows: Vec<CondCallWindow> = Vec::new();
    for j in 0..instrs.len() {
        if let Some(window) = match_cond_call_window(instrs, j) {
            windows.push(window);
        }
    }
    if windows.is_empty() {
        return body.clone();
    }
    let mut out: MethodBody = body.clone();
    for window in windows.iter().rev() {
        nop_instruction(&mut out.instructions[window.dup]);
        nop_instruction(&mut out.instructions[window.brtrue]);
        nop_instruction(&mut out.instructions[window.pop]);
        nop_instruction(&mut out.instructions[window.br]);
        out.instructions.insert(
            window.call,
            null_cond_marker(out.instructions[window.call].offset),
        );
    }
    out
}

#[derive(Debug, Clone, Copy)]
struct CondCallWindow {
    dup: usize,
    brtrue: usize,
    pop: usize,
    br: usize,
    call: usize,
}

fn match_cond_call_window(instrs: &[Instruction], dup: usize) -> Option<CondCallWindow> {
    if instrs.get(dup)?.name != "dup" || dup == 0 {
        return None;
    }
    let brtrue: usize = dup + 1;
    let cond: &Instruction = instrs.get(brtrue)?;
    if !matches!(cond.name.as_str(), "brtrue" | "brtrue.s") {
        return None;
    }
    let call_off: u32 = match cond.operand {
        OperandValue::BrTarget(rel) => (i64::from(cond.offset) + i64::from(rel)) as u32,
        _ => return None,
    };
    let pop: usize = brtrue + 1;
    if instrs.get(pop)?.name != "pop" {
        return None;
    }
    let br: usize = pop + 1;
    let branch: &Instruction = instrs.get(br)?;
    if !matches!(branch.name.as_str(), "br" | "br.s") {
        return None;
    }
    let merge_off: u32 = match branch.operand {
        OperandValue::BrTarget(rel) => (i64::from(branch.offset) + i64::from(rel)) as u32,
        _ => return None,
    };
    let l1: usize = br + 1;
    if instrs.get(l1)?.offset != call_off {
        return None;
    }
    let merge: usize = instrs
        .iter()
        .position(|i: &Instruction| i.offset == merge_off)?;
    if merge <= l1 {
        return None;
    }
    let block: &[Instruction] = &instrs[l1..merge];
    let (last, head): (&Instruction, &[Instruction]) = block.split_last()?;
    if !matches!(last.name.as_str(), "call" | "callvirt" | "calli") {
        return None;
    }
    if !head.iter().all(|ins: &Instruction| {
        matches!(
            ins.flow,
            FlowControl::Next | FlowControl::Call | FlowControl::Meta
        )
    }) {
        return None;
    }
    Some(CondCallWindow {
        dup,
        brtrue,
        pop,
        br,
        call: merge - 1,
    })
}

fn null_cond_marker(offset: u32) -> Instruction {
    Instruction {
        offset,
        opcode: 0,
        name: "__null_cond".to_owned(),
        operand: OperandValue::None,
        flow: FlowControl::Next,
    }
}

#[derive(Debug, Clone, Copy)]
struct CoalesceWindow {
    dup: usize,
    brtrue: usize,
    pop: usize,
    merge: usize,
    throw_alt: Option<usize>,
}

fn match_coalesce_window(instrs: &[Instruction], dup: usize) -> Option<CoalesceWindow> {
    if instrs.get(dup)?.name != "dup" || dup == 0 {
        return None;
    }
    let brtrue: usize = dup + 1;
    let cond: &Instruction = instrs.get(brtrue)?;
    if !matches!(cond.name.as_str(), "brtrue" | "brtrue.s") {
        return None;
    }
    let target: u32 = match cond.operand {
        OperandValue::BrTarget(rel) => (i64::from(cond.offset) + i64::from(rel)) as u32,
        _ => return None,
    };
    let pop: usize = brtrue + 1;
    if instrs.get(pop)?.name != "pop" {
        return None;
    }
    let merge: usize = instrs
        .iter()
        .position(|i: &Instruction| i.offset == target)?;
    if merge <= pop {
        return None;
    }
    let alt: &[Instruction] = &instrs[pop + 1..merge];
    if alt.is_empty() {
        return None;
    }
    let throw_alt: Option<usize> = alt_throw_expression(alt, pop + 1);
    if throw_alt.is_none() && !alt_is_straight_line(alt) {
        return None;
    }
    consumes_single_value(&instrs[merge]).then_some(CoalesceWindow {
        dup,
        brtrue,
        pop,
        merge,
        throw_alt,
    })
}

fn alt_is_straight_line(alt: &[Instruction]) -> bool {
    alt.iter().all(|ins: &Instruction| {
        matches!(
            ins.flow,
            FlowControl::Next | FlowControl::Call | FlowControl::Meta
        )
    })
}

fn alt_throw_expression(alt: &[Instruction], base: usize) -> Option<usize> {
    let (last, head): (&Instruction, &[Instruction]) = alt.split_last()?;
    if last.name != "throw" || !alt_is_straight_line(head) {
        return None;
    }
    Some(base + head.len())
}

fn consumes_single_value(merge: &Instruction) -> bool {
    matches!(merge.name.as_str(), "throw")
        || merge.name.starts_with("stloc")
        || merge.name.starts_with("starg")
        || matches!(merge.name.as_str(), "stfld" | "stsfld")
        || (merge.name.starts_with("stind") && merge.name != "stind.ref")
        || merge.name == "ret"
}

fn nop_instruction(ins: &mut Instruction) {
    ins.opcode = 0x00;
    "nop".clone_into(&mut ins.name);
    ins.operand = OperandValue::None;
    ins.flow = FlowControl::Next;
}

fn coalesce_marker(offset: u32) -> Instruction {
    Instruction {
        offset,
        opcode: 0,
        name: "__coalesce".to_owned(),
        operand: OperandValue::None,
        flow: FlowControl::Next,
    }
}

fn throw_expression_instruction(ins: &mut Instruction) {
    ins.opcode = 0;
    "__throw_expr".clone_into(&mut ins.name);
    ins.operand = OperandValue::None;
    ins.flow = FlowControl::Next;
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn lookup_nop_returns_inline_none() {
        let def: &OpcodeDef = lookup(0x00).expect("nop");
        assert_eq!(def.name, "nop");
        assert_eq!(def.operand, OperandKind::InlineNone);
    }

    #[test]
    fn lookup_ldarg_two_byte() {
        let def: &OpcodeDef = lookup(0xFE09).expect("ldarg");
        assert_eq!(def.name, "ldarg");
        assert_eq!(def.operand, OperandKind::InlineVar);
    }

    #[test]
    fn coverage_is_at_least_eighty_five_percent() {
        assert!(coverage_percent() >= 85, "got {}", coverage_percent());
    }

    #[test]
    fn parse_tiny_method_body_succeeds() {
        let bytes: [u8; 4] = [(3u8 << 2) | 0x02, 0x02, 0x03, 0x2A];
        let body: MethodBody = parse_method_body(&bytes).expect("tiny");
        assert_eq!(body.code_size, 3);
        assert_eq!(body.instructions.len(), 3);
        assert_eq!(body.instructions[0].name, "ldarg.0");
        assert_eq!(body.instructions[1].name, "ldarg.1");
        assert_eq!(body.instructions[2].name, "ret");
    }

    #[test]
    fn disasm_simple_addition_sequence() {
        let code: [u8; 4] = [0x16, 0x17, 0x58, 0x2A];
        let insns: Vec<Instruction> = disassemble(&code).expect("simple");
        assert_eq!(insns.len(), 4);
        assert_eq!(insns[0].name, "ldc.i4.0");
        assert_eq!(insns[1].name, "ldc.i4.1");
        assert_eq!(insns[2].name, "add");
        assert_eq!(insns[3].name, "ret");
    }

    #[test]
    fn unknown_opcode_yields_error() {
        let err: Error = disassemble(&[0xA6]).expect_err("unknown");
        assert!(matches!(err, Error::UnknownOpcode(0xA6, _)));
    }

    #[test]
    fn fat_method_with_finally_clause_parses_eh() {
        let mut bytes: Vec<u8> = Vec::new();
        let flags_size: u16 = (3u16 << 12) | 0x03 | super::COR_IL_METHOD_MORE_SECTS;
        bytes.extend_from_slice(&flags_size.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.push(0x00);
        bytes.push(0x2A);
        while !bytes.len().is_multiple_of(4) {
            bytes.push(0);
        }
        bytes.push(super::SECT_EH_TABLE);
        let section_len: u8 = 4 + 12;
        bytes.push(section_len);
        bytes.push(0);
        bytes.push(0);
        bytes.extend_from_slice(&0x0002u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        let body: MethodBody = parse_method_body(&bytes).expect("fat eh");
        assert_eq!(body.exception_clauses.len(), 1);
        assert_eq!(body.exception_clauses[0].kind, ExceptionClauseKind::Finally);
    }

    #[test]
    fn tiny_body_has_no_exception_clauses() {
        let bytes: [u8; 2] = [(1u8 << 2) | 0x02, 0x2A];
        let body: MethodBody = parse_method_body(&bytes).expect("tiny");
        assert!(body.exception_clauses.is_empty());
    }

    #[test]
    fn switch_operand_decodes_targets() {
        let code: [u8; 13] = [
            0x45, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00,
        ];
        let insns: Vec<Instruction> = disassemble(&code).expect("switch");
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].name, "switch");
        let OperandValue::Switch(ref t) = insns[0].operand else {
            unreachable!("switch operand expected");
        };
        assert_eq!(t, &vec![5, 10]);
    }

    fn ins(offset: u32, name: &str, operand: OperandValue, flow: FlowControl) -> Instruction {
        Instruction {
            offset,
            opcode: 0,
            name: name.to_owned(),
            operand,
            flow,
        }
    }

    fn coalesce_body() -> MethodBody {
        MethodBody {
            max_stack: 8,
            code_size: 7,
            local_var_sig_tok: 0,
            init_locals: false,
            instructions: vec![
                ins(
                    0,
                    "ldsfld",
                    OperandValue::Token(0x0400_0001),
                    FlowControl::Next,
                ),
                ins(1, "dup", OperandValue::None, FlowControl::Next),
                ins(
                    2,
                    "brtrue.s",
                    OperandValue::BrTarget(4),
                    FlowControl::CondBranch,
                ),
                ins(4, "pop", OperandValue::None, FlowControl::Next),
                ins(
                    5,
                    "ldsfld",
                    OperandValue::Token(0x0400_0002),
                    FlowControl::Next,
                ),
                ins(6, "throw", OperandValue::None, FlowControl::Throw),
            ],
            exception_clauses: Vec::new(),
        }
    }

    #[test]
    fn fold_null_coalesce_collapses_dup_brtrue_pop_throw_idiom() {
        let folded: MethodBody = fold_null_coalesce(&coalesce_body());
        let names: Vec<&str> = folded
            .instructions
            .iter()
            .map(|i: &Instruction| i.name.as_str())
            .collect();
        assert_eq!(
            names,
            vec![
                "ldsfld",
                "nop",
                "nop",
                "nop",
                "ldsfld",
                "__coalesce",
                "throw"
            ],
            "the dup/brtrue/pop coalesce scaffolding must collapse to a __coalesce marker before the consumer"
        );
        let marker: &Instruction = &folded.instructions[5];
        assert_eq!(marker.offset, 6, "__coalesce inherits the consumer offset");
    }

    #[test]
    fn fold_null_coalesce_ignores_branching_alternative() {
        let mut body: MethodBody = coalesce_body();
        body.instructions[3] = ins(4, "br.s", OperandValue::BrTarget(6), FlowControl::Branch);
        let folded: MethodBody = fold_null_coalesce(&body);
        assert!(
            folded
                .instructions
                .iter()
                .all(|i: &Instruction| i.name != "__coalesce"),
            "an alternative that is not straight-line must not be folded"
        );
    }

    #[test]
    fn fold_null_coalesce_folds_a_return_sink() {
        let mut body: MethodBody = coalesce_body();
        body.instructions[5] = ins(6, "ret", OperandValue::None, FlowControl::Return);
        let folded: MethodBody = fold_null_coalesce(&body);
        let coalesced: usize = folded
            .instructions
            .iter()
            .filter(|i: &&Instruction| i.name == "__coalesce")
            .count();
        assert_eq!(coalesced, 1, "return a ?? b is a valid coalesce sink");
    }

    #[test]
    fn fold_null_coalesce_skips_a_non_consuming_merge() {
        let mut body: MethodBody = coalesce_body();
        body.instructions[5] = ins(
            6,
            "ldsfld",
            OperandValue::Token(0x0400_0003),
            FlowControl::Next,
        );
        let folded: MethodBody = fold_null_coalesce(&body);
        assert!(
            folded
                .instructions
                .iter()
                .all(|i: &Instruction| i.name != "__coalesce"),
            "a merge that pushes rather than consumes is not a coalesce sink"
        );
    }

    fn cond_call_body() -> MethodBody {
        MethodBody {
            max_stack: 8,
            code_size: 20,
            local_var_sig_tok: 0,
            init_locals: false,
            instructions: vec![
                ins(0, "ldarg.0", OperandValue::None, FlowControl::Next),
                ins(
                    1,
                    "ldfld",
                    OperandValue::Token(0x0400_0001),
                    FlowControl::Next,
                ),
                ins(6, "dup", OperandValue::None, FlowControl::Next),
                ins(
                    7,
                    "brtrue.s",
                    OperandValue::BrTarget(5),
                    FlowControl::CondBranch,
                ),
                ins(9, "pop", OperandValue::None, FlowControl::Next),
                ins(10, "br.s", OperandValue::BrTarget(8), FlowControl::Branch),
                ins(12, "ldarg.1", OperandValue::None, FlowControl::Next),
                ins(
                    13,
                    "callvirt",
                    OperandValue::Token(0x0A00_0002),
                    FlowControl::Call,
                ),
                ins(18, "ret", OperandValue::None, FlowControl::Return),
            ],
            exception_clauses: Vec::new(),
        }
    }

    #[test]
    fn fold_null_conditional_call_collapses_dup_brtrue_pop_br_call_idiom() {
        let folded: MethodBody = fold_null_conditional_call(&cond_call_body());
        let names: Vec<&str> = folded
            .instructions
            .iter()
            .map(|i: &Instruction| i.name.as_str())
            .collect();
        assert_eq!(
            names,
            vec![
                "ldarg.0",
                "ldfld",
                "nop",
                "nop",
                "nop",
                "nop",
                "ldarg.1",
                "__null_cond",
                "callvirt",
                "ret",
            ],
            "the dup/brtrue/pop/br guard collapses to straight-line with a __null_cond marker before the call"
        );
    }

    #[test]
    fn fold_null_conditional_call_ignores_missing_trailing_branch() {
        let mut body: MethodBody = cond_call_body();
        body.instructions[5] = ins(10, "nop", OperandValue::None, FlowControl::Next);
        let folded: MethodBody = fold_null_conditional_call(&body);
        assert!(
            folded
                .instructions
                .iter()
                .all(|i: &Instruction| i.name != "__null_cond"),
            "without the br.s over the call the pattern is not a null-conditional call"
        );
    }

    fn coalesce_throw_body() -> MethodBody {
        MethodBody {
            max_stack: 8,
            code_size: 12,
            local_var_sig_tok: 0,
            init_locals: false,
            instructions: vec![
                ins(0, "ldarg.0", OperandValue::None, FlowControl::Next),
                ins(1, "ldarg.1", OperandValue::None, FlowControl::Next),
                ins(2, "dup", OperandValue::None, FlowControl::Next),
                ins(
                    3,
                    "brtrue.s",
                    OperandValue::BrTarget(6),
                    FlowControl::CondBranch,
                ),
                ins(5, "pop", OperandValue::None, FlowControl::Next),
                ins(
                    6,
                    "ldstr",
                    OperandValue::Token(0x7000_0001),
                    FlowControl::Next,
                ),
                ins(
                    7,
                    "newobj",
                    OperandValue::Token(0x0A00_0001),
                    FlowControl::Call,
                ),
                ins(8, "throw", OperandValue::None, FlowControl::Throw),
                ins(
                    9,
                    "stfld",
                    OperandValue::Token(0x0400_0001),
                    FlowControl::Next,
                ),
                ins(11, "ret", OperandValue::None, FlowControl::Return),
            ],
            exception_clauses: Vec::new(),
        }
    }

    #[test]
    fn fold_null_coalesce_folds_a_throw_expression_alternative() {
        let folded: MethodBody = fold_null_coalesce(&coalesce_throw_body());
        let names: Vec<&str> = folded
            .instructions
            .iter()
            .map(|i: &Instruction| i.name.as_str())
            .collect();
        assert_eq!(
            names.iter().filter(|n: &&&str| **n == "__coalesce").count(),
            1,
            "field = arg ?? throw new E() is a valid coalesce sink"
        );
        assert_eq!(
            names
                .iter()
                .filter(|n: &&&str| **n == "__throw_expr")
                .count(),
            1,
            "the trailing throw of the alternative becomes a throw expression"
        );
        assert!(
            names.iter().all(|n: &&str| *n != "throw"),
            "the raw throw must be consumed into the throw expression"
        );
    }
}
