use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodBody {
    pub max_stack: u16,
    pub code_size: u32,
    pub local_var_sig_tok: u32,
    pub init_locals: bool,
    pub instructions: Vec<Instruction>,
}

pub fn parse_method_body(bytes: &[u8]) -> Result<MethodBody> {
    if bytes.is_empty() {
        return Err(Error::CilTruncated(0));
    }
    let header_byte: u8 = bytes[0];
    let (max_stack, code_size, local_var_sig_tok, init_locals, header_size): (
        u16,
        u32,
        u32,
        bool,
        usize,
    ) = if (header_byte & 0x03) == 0x02 {
        let code_size_v: u32 = u32::from(header_byte >> 2);
        (8, code_size_v, 0, false, 1)
    } else if (header_byte & 0x03) == 0x03 {
        if bytes.len() < 12 {
            return Err(Error::CilTruncated(bytes.len()));
        }
        let flags_size: u16 = u16::from_le_bytes([bytes[0], bytes[1]]);
        let init: bool = (flags_size & 0x10) != 0;
        let max_stack_v: u16 = u16::from_le_bytes([bytes[2], bytes[3]]);
        let code_size_v: u32 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let local_sig: u32 = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        (max_stack_v, code_size_v, local_sig, init, 12)
    } else {
        return Err(Error::BadMethodHeader(header_byte));
    };
    let body_end: usize = header_size + code_size as usize;
    if body_end > bytes.len() {
        return Err(Error::CilTruncated(body_end));
    }
    let code: &[u8] = &bytes[header_size..body_end];
    let instructions: Vec<Instruction> = disassemble(code)?;
    Ok(MethodBody {
        max_stack,
        code_size,
        local_var_sig_tok,
        init_locals,
        instructions,
    })
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
        let def: &OpcodeDef = lookup(op_code).ok_or(Error::UnknownOpcode(op_code, pos))?;
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
}
