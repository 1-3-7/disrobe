use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::bytenode::NodeVersion;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum OperandKind {
    None,
    Reg,
    RegOut,
    RegOutPair,
    RegOutTriple,
    RegOutList,
    RegPair,
    RegList,
    RegCount,
    Idx,
    UImm,
    Imm,
    Flag8,
    Flag16,
    RuntimeId,
    NativeContextIndex,
    IntrinsicId,
}

impl OperandKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Reg => "reg",
            Self::RegOut => "reg_out",
            Self::RegOutPair => "reg_out_pair",
            Self::RegOutTriple => "reg_out_triple",
            Self::RegOutList => "reg_out_list",
            Self::RegPair => "reg_pair",
            Self::RegList => "reg_list",
            Self::RegCount => "reg_count",
            Self::Idx => "idx",
            Self::UImm => "uimm",
            Self::Imm => "imm",
            Self::Flag8 => "flag8",
            Self::Flag16 => "flag16",
            Self::RuntimeId => "runtime_id",
            Self::NativeContextIndex => "native_ctx_idx",
            Self::IntrinsicId => "intrinsic_id",
        }
    }

    #[must_use]
    pub const fn unscaled_byte_size(self) -> usize {
        match self {
            Self::None => 0,
            Self::Reg
            | Self::RegOut
            | Self::RegOutPair
            | Self::RegOutTriple
            | Self::RegOutList
            | Self::RegPair
            | Self::RegList
            | Self::RegCount
            | Self::UImm
            | Self::Imm
            | Self::Idx
            | Self::Flag8
            | Self::RuntimeId
            | Self::IntrinsicId
            | Self::NativeContextIndex => 1,
            Self::Flag16 => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum AccumulatorUse {
    None,
    Read,
    Write,
    ReadWrite,
    Clobber,
    ReadAndClobber,
    ReadWriteShortStar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct V8OpcodeSpec {
    pub mnemonic: &'static str,
    pub accumulator_use: AccumulatorUse,
    pub operands: [OperandKind; 4],
    pub operand_count: u8,
}

impl V8OpcodeSpec {
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub const fn new(
        mnemonic: &'static str,
        accumulator_use: AccumulatorUse,
        operands: &[OperandKind],
    ) -> Self {
        let mut padded: [OperandKind; 4] = [OperandKind::None; 4];
        let mut i: usize = 0;
        while i < operands.len() && i < 4 {
            padded[i] = operands[i];
            i += 1;
        }
        let count_clamped: usize = if operands.len() > u8::MAX as usize {
            u8::MAX as usize
        } else {
            operands.len()
        };
        Self {
            mnemonic,
            accumulator_use,
            operands: padded,
            operand_count: count_clamped as u8,
        }
    }

    #[must_use]
    pub fn unscaled_size(&self) -> usize {
        let mut sum: usize = 1usize;
        for i in 0..self.operand_count as usize {
            sum = sum.saturating_add(self.operands[i].unscaled_byte_size());
        }
        sum
    }
}

const fn op(name: &'static str, acc: AccumulatorUse, ops: &[OperandKind]) -> V8OpcodeSpec {
    V8OpcodeSpec::new(name, acc, ops)
}

const BASE_OPCODES_V12_4: &[V8OpcodeSpec] = &[
    op("Wide", AccumulatorUse::None, &[]),
    op("ExtraWide", AccumulatorUse::None, &[]),
    op("DebugBreakWide", AccumulatorUse::ReadWrite, &[]),
    op("DebugBreakExtraWide", AccumulatorUse::ReadWrite, &[]),
    op("DebugBreak0", AccumulatorUse::ReadWrite, &[]),
    op(
        "DebugBreak1",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg],
    ),
    op(
        "DebugBreak2",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg, OperandKind::Reg],
    ),
    op(
        "DebugBreak3",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg, OperandKind::Reg, OperandKind::Reg],
    ),
    op(
        "DebugBreak4",
        AccumulatorUse::ReadWrite,
        &[
            OperandKind::Reg,
            OperandKind::Reg,
            OperandKind::Reg,
            OperandKind::Reg,
        ],
    ),
    op(
        "DebugBreak5",
        AccumulatorUse::ReadWrite,
        &[OperandKind::RuntimeId, OperandKind::Reg, OperandKind::Reg],
    ),
    op(
        "DebugBreak6",
        AccumulatorUse::ReadWrite,
        &[
            OperandKind::RuntimeId,
            OperandKind::Reg,
            OperandKind::Reg,
            OperandKind::Reg,
        ],
    ),
    op("Ldar", AccumulatorUse::Write, &[OperandKind::Reg]),
    op("LdaZero", AccumulatorUse::Write, &[]),
    op("LdaSmi", AccumulatorUse::Write, &[OperandKind::Imm]),
    op("LdaUndefined", AccumulatorUse::Write, &[]),
    op("LdaNull", AccumulatorUse::Write, &[]),
    op("LdaTheHole", AccumulatorUse::Write, &[]),
    op("LdaTrue", AccumulatorUse::Write, &[]),
    op("LdaFalse", AccumulatorUse::Write, &[]),
    op("LdaConstant", AccumulatorUse::Write, &[OperandKind::Idx]),
    op(
        "LdaContextSlot",
        AccumulatorUse::Write,
        &[OperandKind::Reg, OperandKind::Idx, OperandKind::UImm],
    ),
    op(
        "LdaImmutableContextSlot",
        AccumulatorUse::Write,
        &[OperandKind::Reg, OperandKind::Idx, OperandKind::UImm],
    ),
    op(
        "LdaCurrentContextSlot",
        AccumulatorUse::Write,
        &[OperandKind::Idx],
    ),
    op(
        "LdaImmutableCurrentContextSlot",
        AccumulatorUse::Write,
        &[OperandKind::Idx],
    ),
    op("Star", AccumulatorUse::Read, &[OperandKind::RegOut]),
    op(
        "Mov",
        AccumulatorUse::None,
        &[OperandKind::Reg, OperandKind::RegOut],
    ),
    op("PushContext", AccumulatorUse::Read, &[OperandKind::RegOut]),
    op("PopContext", AccumulatorUse::None, &[OperandKind::Reg]),
    op(
        "TestReferenceEqual",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg],
    ),
    op("TestUndetectable", AccumulatorUse::ReadWrite, &[]),
    op("TestNull", AccumulatorUse::ReadWrite, &[]),
    op("TestUndefined", AccumulatorUse::ReadWrite, &[]),
    op(
        "TestTypeOf",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Flag8],
    ),
    op(
        "LdaGlobal",
        AccumulatorUse::Write,
        &[OperandKind::Idx, OperandKind::Idx],
    ),
    op(
        "LdaGlobalInsideTypeof",
        AccumulatorUse::Write,
        &[OperandKind::Idx, OperandKind::Idx],
    ),
    op(
        "StaGlobal",
        AccumulatorUse::ReadAndClobber,
        &[OperandKind::Idx, OperandKind::Idx],
    ),
    op(
        "StaContextSlot",
        AccumulatorUse::Read,
        &[OperandKind::Reg, OperandKind::Idx, OperandKind::UImm],
    ),
    op(
        "StaCurrentContextSlot",
        AccumulatorUse::Read,
        &[OperandKind::Idx],
    ),
    op(
        "StaScriptContextSlot",
        AccumulatorUse::Read,
        &[OperandKind::Reg, OperandKind::Idx, OperandKind::UImm],
    ),
    op(
        "StaCurrentScriptContextSlot",
        AccumulatorUse::Read,
        &[OperandKind::Idx],
    ),
    op("LdaLookupSlot", AccumulatorUse::Write, &[OperandKind::Idx]),
    op(
        "LdaLookupContextSlot",
        AccumulatorUse::Write,
        &[OperandKind::Idx, OperandKind::Idx, OperandKind::UImm],
    ),
    op(
        "LdaLookupGlobalSlot",
        AccumulatorUse::Write,
        &[OperandKind::Idx, OperandKind::Idx, OperandKind::UImm],
    ),
    op(
        "LdaLookupSlotInsideTypeof",
        AccumulatorUse::Write,
        &[OperandKind::Idx],
    ),
    op(
        "LdaLookupContextSlotInsideTypeof",
        AccumulatorUse::Write,
        &[OperandKind::Idx, OperandKind::Idx, OperandKind::UImm],
    ),
    op(
        "LdaLookupGlobalSlotInsideTypeof",
        AccumulatorUse::Write,
        &[OperandKind::Idx, OperandKind::Idx, OperandKind::UImm],
    ),
    op(
        "StaLookupSlot",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Idx, OperandKind::Flag8],
    ),
    op(
        "GetNamedProperty",
        AccumulatorUse::Write,
        &[OperandKind::Reg, OperandKind::Idx, OperandKind::Idx],
    ),
    op(
        "GetNamedPropertyFromSuper",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg, OperandKind::Idx, OperandKind::Idx],
    ),
    op(
        "GetKeyedProperty",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg, OperandKind::Idx],
    ),
    op(
        "GetEnumeratedKeyedProperty",
        AccumulatorUse::ReadWrite,
        &[
            OperandKind::Reg,
            OperandKind::Reg,
            OperandKind::Reg,
            OperandKind::Idx,
        ],
    ),
    op(
        "LdaModuleVariable",
        AccumulatorUse::Write,
        &[OperandKind::Imm, OperandKind::UImm],
    ),
    op(
        "StaModuleVariable",
        AccumulatorUse::Read,
        &[OperandKind::Imm, OperandKind::UImm],
    ),
    op(
        "SetNamedProperty",
        AccumulatorUse::ReadAndClobber,
        &[OperandKind::Reg, OperandKind::Idx, OperandKind::Idx],
    ),
    op(
        "DefineNamedOwnProperty",
        AccumulatorUse::ReadAndClobber,
        &[OperandKind::Reg, OperandKind::Idx, OperandKind::Idx],
    ),
    op(
        "SetKeyedProperty",
        AccumulatorUse::ReadAndClobber,
        &[OperandKind::Reg, OperandKind::Reg, OperandKind::Idx],
    ),
    op(
        "DefineKeyedOwnProperty",
        AccumulatorUse::ReadAndClobber,
        &[
            OperandKind::Reg,
            OperandKind::Reg,
            OperandKind::Flag8,
            OperandKind::Idx,
        ],
    ),
    op(
        "StaInArrayLiteral",
        AccumulatorUse::ReadAndClobber,
        &[OperandKind::Reg, OperandKind::Reg, OperandKind::Idx],
    ),
    op(
        "DefineKeyedOwnPropertyInLiteral",
        AccumulatorUse::Read,
        &[
            OperandKind::Reg,
            OperandKind::Reg,
            OperandKind::Flag8,
            OperandKind::Idx,
        ],
    ),
    op(
        "Add",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg, OperandKind::Idx],
    ),
    op(
        "Sub",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg, OperandKind::Idx],
    ),
    op(
        "Mul",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg, OperandKind::Idx],
    ),
    op(
        "Div",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg, OperandKind::Idx],
    ),
    op(
        "Mod",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg, OperandKind::Idx],
    ),
    op(
        "Exp",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg, OperandKind::Idx],
    ),
    op(
        "BitwiseOr",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg, OperandKind::Idx],
    ),
    op(
        "BitwiseXor",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg, OperandKind::Idx],
    ),
    op(
        "BitwiseAnd",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg, OperandKind::Idx],
    ),
    op(
        "ShiftLeft",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg, OperandKind::Idx],
    ),
    op(
        "ShiftRight",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg, OperandKind::Idx],
    ),
    op(
        "ShiftRightLogical",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg, OperandKind::Idx],
    ),
    op(
        "AddSmi",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Imm, OperandKind::Idx],
    ),
    op(
        "SubSmi",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Imm, OperandKind::Idx],
    ),
    op(
        "MulSmi",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Imm, OperandKind::Idx],
    ),
    op(
        "DivSmi",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Imm, OperandKind::Idx],
    ),
    op(
        "ModSmi",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Imm, OperandKind::Idx],
    ),
    op(
        "ExpSmi",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Imm, OperandKind::Idx],
    ),
    op(
        "BitwiseOrSmi",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Imm, OperandKind::Idx],
    ),
    op(
        "BitwiseXorSmi",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Imm, OperandKind::Idx],
    ),
    op(
        "BitwiseAndSmi",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Imm, OperandKind::Idx],
    ),
    op(
        "ShiftLeftSmi",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Imm, OperandKind::Idx],
    ),
    op(
        "ShiftRightSmi",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Imm, OperandKind::Idx],
    ),
    op(
        "ShiftRightLogicalSmi",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Imm, OperandKind::Idx],
    ),
    op("Inc", AccumulatorUse::ReadWrite, &[OperandKind::Idx]),
    op("Dec", AccumulatorUse::ReadWrite, &[OperandKind::Idx]),
    op("Negate", AccumulatorUse::ReadWrite, &[OperandKind::Idx]),
    op("BitwiseNot", AccumulatorUse::ReadWrite, &[OperandKind::Idx]),
    op("ToBooleanLogicalNot", AccumulatorUse::ReadWrite, &[]),
    op("LogicalNot", AccumulatorUse::ReadWrite, &[]),
    op("TypeOf", AccumulatorUse::ReadWrite, &[]),
    op(
        "DeletePropertyStrict",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg],
    ),
    op(
        "DeletePropertySloppy",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg],
    ),
    op(
        "GetSuperConstructor",
        AccumulatorUse::Read,
        &[OperandKind::RegOut],
    ),
    op(
        "FindNonDefaultConstructorOrConstruct",
        AccumulatorUse::None,
        &[OperandKind::Reg, OperandKind::Reg, OperandKind::RegOutPair],
    ),
    op(
        "CallAnyReceiver",
        AccumulatorUse::Write,
        &[
            OperandKind::Reg,
            OperandKind::RegList,
            OperandKind::RegCount,
            OperandKind::Idx,
        ],
    ),
    op(
        "CallProperty",
        AccumulatorUse::Write,
        &[
            OperandKind::Reg,
            OperandKind::RegList,
            OperandKind::RegCount,
            OperandKind::Idx,
        ],
    ),
    op(
        "CallProperty0",
        AccumulatorUse::Write,
        &[OperandKind::Reg, OperandKind::Reg, OperandKind::Idx],
    ),
    op(
        "CallProperty1",
        AccumulatorUse::Write,
        &[
            OperandKind::Reg,
            OperandKind::Reg,
            OperandKind::Reg,
            OperandKind::Idx,
        ],
    ),
    op(
        "CallProperty2",
        AccumulatorUse::Write,
        &[
            OperandKind::Reg,
            OperandKind::Reg,
            OperandKind::Reg,
            OperandKind::Reg,
        ],
    ),
    op(
        "CallUndefinedReceiver",
        AccumulatorUse::Write,
        &[
            OperandKind::Reg,
            OperandKind::RegList,
            OperandKind::RegCount,
            OperandKind::Idx,
        ],
    ),
    op(
        "CallUndefinedReceiver0",
        AccumulatorUse::Write,
        &[OperandKind::Reg, OperandKind::Idx],
    ),
    op(
        "CallUndefinedReceiver1",
        AccumulatorUse::Write,
        &[OperandKind::Reg, OperandKind::Reg, OperandKind::Idx],
    ),
    op(
        "CallUndefinedReceiver2",
        AccumulatorUse::Write,
        &[
            OperandKind::Reg,
            OperandKind::Reg,
            OperandKind::Reg,
            OperandKind::Idx,
        ],
    ),
    op(
        "CallWithSpread",
        AccumulatorUse::Write,
        &[
            OperandKind::Reg,
            OperandKind::RegList,
            OperandKind::RegCount,
            OperandKind::Idx,
        ],
    ),
    op(
        "CallRuntime",
        AccumulatorUse::Write,
        &[
            OperandKind::RuntimeId,
            OperandKind::RegList,
            OperandKind::RegCount,
        ],
    ),
    op(
        "CallRuntimeForPair",
        AccumulatorUse::Clobber,
        &[
            OperandKind::RuntimeId,
            OperandKind::RegList,
            OperandKind::RegCount,
            OperandKind::RegOutPair,
        ],
    ),
    op(
        "CallJSRuntime",
        AccumulatorUse::Write,
        &[
            OperandKind::NativeContextIndex,
            OperandKind::RegList,
            OperandKind::RegCount,
        ],
    ),
    op(
        "InvokeIntrinsic",
        AccumulatorUse::Write,
        &[
            OperandKind::IntrinsicId,
            OperandKind::RegList,
            OperandKind::RegCount,
        ],
    ),
    op(
        "Construct",
        AccumulatorUse::ReadWrite,
        &[
            OperandKind::Reg,
            OperandKind::RegList,
            OperandKind::RegCount,
            OperandKind::Idx,
        ],
    ),
    op(
        "ConstructWithSpread",
        AccumulatorUse::ReadWrite,
        &[
            OperandKind::Reg,
            OperandKind::RegList,
            OperandKind::RegCount,
            OperandKind::Idx,
        ],
    ),
    op(
        "ConstructForwardAllArgs",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg, OperandKind::Idx],
    ),
    op(
        "TestEqual",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg, OperandKind::Idx],
    ),
    op(
        "TestEqualStrict",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg, OperandKind::Idx],
    ),
    op(
        "TestLessThan",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg, OperandKind::Idx],
    ),
    op(
        "TestGreaterThan",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg, OperandKind::Idx],
    ),
    op(
        "TestLessThanOrEqual",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg, OperandKind::Idx],
    ),
    op(
        "TestGreaterThanOrEqual",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg, OperandKind::Idx],
    ),
    op(
        "TestInstanceOf",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg, OperandKind::Idx],
    ),
    op(
        "TestIn",
        AccumulatorUse::ReadWrite,
        &[OperandKind::Reg, OperandKind::Idx],
    ),
    op("ToName", AccumulatorUse::ReadWrite, &[]),
    op("ToNumber", AccumulatorUse::ReadWrite, &[OperandKind::Idx]),
    op("ToNumeric", AccumulatorUse::ReadWrite, &[OperandKind::Idx]),
    op("ToObject", AccumulatorUse::Read, &[OperandKind::RegOut]),
    op("ToString", AccumulatorUse::ReadWrite, &[]),
    op("ToBoolean", AccumulatorUse::ReadWrite, &[]),
    op(
        "CreateRegExpLiteral",
        AccumulatorUse::Write,
        &[OperandKind::Idx, OperandKind::Idx, OperandKind::Flag16],
    ),
    op(
        "CreateArrayLiteral",
        AccumulatorUse::Write,
        &[OperandKind::Idx, OperandKind::Idx, OperandKind::Flag8],
    ),
    op("CreateArrayFromIterable", AccumulatorUse::ReadWrite, &[]),
    op(
        "CreateEmptyArrayLiteral",
        AccumulatorUse::Write,
        &[OperandKind::Idx],
    ),
    op(
        "CreateObjectLiteral",
        AccumulatorUse::Write,
        &[OperandKind::Idx, OperandKind::Idx, OperandKind::Flag8],
    ),
    op("CreateEmptyObjectLiteral", AccumulatorUse::Write, &[]),
    op(
        "CloneObject",
        AccumulatorUse::Write,
        &[OperandKind::Reg, OperandKind::Flag8, OperandKind::Idx],
    ),
    op(
        "GetTemplateObject",
        AccumulatorUse::Write,
        &[OperandKind::Idx, OperandKind::Idx],
    ),
    op(
        "CreateClosure",
        AccumulatorUse::Write,
        &[OperandKind::Idx, OperandKind::Idx, OperandKind::Flag8],
    ),
    op(
        "CreateBlockContext",
        AccumulatorUse::Write,
        &[OperandKind::Idx],
    ),
    op(
        "CreateCatchContext",
        AccumulatorUse::Write,
        &[OperandKind::Reg, OperandKind::Idx],
    ),
    op(
        "CreateFunctionContext",
        AccumulatorUse::Write,
        &[OperandKind::Idx, OperandKind::UImm],
    ),
    op(
        "CreateEvalContext",
        AccumulatorUse::Write,
        &[OperandKind::Idx, OperandKind::UImm],
    ),
    op(
        "CreateWithContext",
        AccumulatorUse::Write,
        &[OperandKind::Reg, OperandKind::Idx],
    ),
    op("CreateMappedArguments", AccumulatorUse::Write, &[]),
    op("CreateUnmappedArguments", AccumulatorUse::Write, &[]),
    op("CreateRestParameter", AccumulatorUse::Write, &[]),
    op(
        "JumpLoop",
        AccumulatorUse::Clobber,
        &[OperandKind::UImm, OperandKind::Imm, OperandKind::Idx],
    ),
    op("Jump", AccumulatorUse::None, &[OperandKind::UImm]),
    op("JumpConstant", AccumulatorUse::None, &[OperandKind::Idx]),
    op(
        "JumpIfNullConstant",
        AccumulatorUse::Read,
        &[OperandKind::Idx],
    ),
    op(
        "JumpIfNotNullConstant",
        AccumulatorUse::Read,
        &[OperandKind::Idx],
    ),
    op(
        "JumpIfUndefinedConstant",
        AccumulatorUse::Read,
        &[OperandKind::Idx],
    ),
    op(
        "JumpIfNotUndefinedConstant",
        AccumulatorUse::Read,
        &[OperandKind::Idx],
    ),
    op(
        "JumpIfUndefinedOrNullConstant",
        AccumulatorUse::Read,
        &[OperandKind::Idx],
    ),
    op(
        "JumpIfTrueConstant",
        AccumulatorUse::Read,
        &[OperandKind::Idx],
    ),
    op(
        "JumpIfFalseConstant",
        AccumulatorUse::Read,
        &[OperandKind::Idx],
    ),
    op(
        "JumpIfJSReceiverConstant",
        AccumulatorUse::Read,
        &[OperandKind::Idx],
    ),
    op(
        "JumpIfToBooleanTrueConstant",
        AccumulatorUse::Read,
        &[OperandKind::Idx],
    ),
    op(
        "JumpIfToBooleanFalseConstant",
        AccumulatorUse::Read,
        &[OperandKind::Idx],
    ),
    op(
        "JumpIfToBooleanTrue",
        AccumulatorUse::Read,
        &[OperandKind::UImm],
    ),
    op(
        "JumpIfToBooleanFalse",
        AccumulatorUse::Read,
        &[OperandKind::UImm],
    ),
    op("JumpIfTrue", AccumulatorUse::Read, &[OperandKind::UImm]),
    op("JumpIfFalse", AccumulatorUse::Read, &[OperandKind::UImm]),
    op("JumpIfNull", AccumulatorUse::Read, &[OperandKind::UImm]),
    op("JumpIfNotNull", AccumulatorUse::Read, &[OperandKind::UImm]),
    op(
        "JumpIfUndefined",
        AccumulatorUse::Read,
        &[OperandKind::UImm],
    ),
    op(
        "JumpIfNotUndefined",
        AccumulatorUse::Read,
        &[OperandKind::UImm],
    ),
    op(
        "JumpIfUndefinedOrNull",
        AccumulatorUse::Read,
        &[OperandKind::UImm],
    ),
    op(
        "JumpIfJSReceiver",
        AccumulatorUse::Read,
        &[OperandKind::UImm],
    ),
    op(
        "SwitchOnSmiNoFeedback",
        AccumulatorUse::Read,
        &[OperandKind::Idx, OperandKind::UImm, OperandKind::Imm],
    ),
    op("ForInEnumerate", AccumulatorUse::Write, &[OperandKind::Reg]),
    op(
        "ForInPrepare",
        AccumulatorUse::ReadAndClobber,
        &[OperandKind::RegOutTriple, OperandKind::Idx],
    ),
    op(
        "ForInContinue",
        AccumulatorUse::Write,
        &[OperandKind::Reg, OperandKind::Reg],
    ),
    op(
        "ForInNext",
        AccumulatorUse::Write,
        &[
            OperandKind::Reg,
            OperandKind::Reg,
            OperandKind::RegPair,
            OperandKind::Idx,
        ],
    ),
    op("ForInStep", AccumulatorUse::Write, &[OperandKind::Reg]),
    op("SetPendingMessage", AccumulatorUse::ReadWrite, &[]),
    op("Throw", AccumulatorUse::Read, &[]),
    op("ReThrow", AccumulatorUse::Read, &[]),
    op("Return", AccumulatorUse::Read, &[]),
    op(
        "ThrowReferenceErrorIfHole",
        AccumulatorUse::Read,
        &[OperandKind::Idx],
    ),
    op("ThrowSuperNotCalledIfHole", AccumulatorUse::Read, &[]),
    op(
        "ThrowSuperAlreadyCalledIfNotHole",
        AccumulatorUse::Read,
        &[],
    ),
    op(
        "ThrowIfNotSuperConstructor",
        AccumulatorUse::None,
        &[OperandKind::Reg],
    ),
    op(
        "SwitchOnGeneratorState",
        AccumulatorUse::None,
        &[OperandKind::Reg, OperandKind::Idx, OperandKind::UImm],
    ),
    op(
        "SuspendGenerator",
        AccumulatorUse::Read,
        &[
            OperandKind::Reg,
            OperandKind::RegList,
            OperandKind::RegCount,
            OperandKind::UImm,
        ],
    ),
    op(
        "ResumeGenerator",
        AccumulatorUse::Write,
        &[
            OperandKind::Reg,
            OperandKind::RegOutList,
            OperandKind::RegCount,
        ],
    ),
    op(
        "GetIterator",
        AccumulatorUse::Write,
        &[OperandKind::Reg, OperandKind::Idx, OperandKind::Idx],
    ),
    op("Debugger", AccumulatorUse::Clobber, &[]),
    op("IncBlockCounter", AccumulatorUse::None, &[OperandKind::Idx]),
    op("Abort", AccumulatorUse::None, &[OperandKind::Idx]),
    op("Star15", AccumulatorUse::ReadWriteShortStar, &[]),
    op("Star14", AccumulatorUse::ReadWriteShortStar, &[]),
    op("Star13", AccumulatorUse::ReadWriteShortStar, &[]),
    op("Star12", AccumulatorUse::ReadWriteShortStar, &[]),
    op("Star11", AccumulatorUse::ReadWriteShortStar, &[]),
    op("Star10", AccumulatorUse::ReadWriteShortStar, &[]),
    op("Star9", AccumulatorUse::ReadWriteShortStar, &[]),
    op("Star8", AccumulatorUse::ReadWriteShortStar, &[]),
    op("Star7", AccumulatorUse::ReadWriteShortStar, &[]),
    op("Star6", AccumulatorUse::ReadWriteShortStar, &[]),
    op("Star5", AccumulatorUse::ReadWriteShortStar, &[]),
    op("Star4", AccumulatorUse::ReadWriteShortStar, &[]),
    op("Star3", AccumulatorUse::ReadWriteShortStar, &[]),
    op("Star2", AccumulatorUse::ReadWriteShortStar, &[]),
    op("Star1", AccumulatorUse::ReadWriteShortStar, &[]),
    op("Star0", AccumulatorUse::ReadWriteShortStar, &[]),
    op("Illegal", AccumulatorUse::None, &[]),
];

#[derive(Debug, Clone)]
pub struct OpcodeTable {
    pub node_version: NodeVersion,
    pub v8_version_label: &'static str,
    by_byte: BTreeMap<u8, V8OpcodeSpec>,
    by_mnemonic: BTreeMap<&'static str, u8>,
}

impl OpcodeTable {
    fn build(node_version: NodeVersion, v8_label: &'static str, specs: &[V8OpcodeSpec]) -> Self {
        let mut by_byte: BTreeMap<u8, V8OpcodeSpec> = BTreeMap::new();
        let mut by_mnemonic: BTreeMap<&'static str, u8> = BTreeMap::new();
        let cap: usize = specs.len().min(256usize);
        for (idx, spec) in specs.iter().take(cap).enumerate() {
            let byte: u8 = u8::try_from(idx).unwrap_or(u8::MAX);
            by_byte.insert(byte, *spec);
            by_mnemonic.insert(spec.mnemonic, byte);
        }
        Self {
            node_version,
            v8_version_label: v8_label,
            by_byte,
            by_mnemonic,
        }
    }

    #[must_use]
    pub fn for_node(node: NodeVersion) -> Self {
        match node {
            NodeVersion::Node18 => Self::build(node, "v10.2", &filter_by_minimum(0)),
            NodeVersion::Node20 => Self::build(node, "v11.3", &filter_by_minimum(1)),
            NodeVersion::Node22 => Self::build(node, "v12.4", BASE_OPCODES_V12_4),
            NodeVersion::Node24 => Self::build(node, "v13.6", BASE_OPCODES_V12_4),
            NodeVersion::Unknown => {
                Self::build(NodeVersion::Unknown, "unknown", BASE_OPCODES_V12_4)
            }
        }
    }

    #[must_use]
    pub fn lookup_byte(&self, byte: u8) -> Option<&V8OpcodeSpec> {
        self.by_byte.get(&byte)
    }

    #[must_use]
    pub fn lookup_mnemonic(&self, mnemonic: &str) -> Option<u8> {
        self.by_mnemonic.get(mnemonic).copied()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.by_byte.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_byte.is_empty()
    }

    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn coverage_fraction(&self) -> f64 {
        let n: f64 = self.by_byte.len() as f64;
        let upstream: f64 = BASE_OPCODES_V12_4.len() as f64;
        if upstream == 0.0 { 0.0 } else { n / upstream }
    }

    pub fn iter_specs(&self) -> impl Iterator<Item = (u8, &V8OpcodeSpec)> {
        self.by_byte.iter().map(|(b, s)| (*b, s))
    }
}

fn filter_by_minimum(skip_recent: usize) -> Vec<V8OpcodeSpec> {
    let removed_recent: &[&str] = &[
        "ConstructForwardAllArgs",
        "GetEnumeratedKeyedProperty",
        "StaScriptContextSlot",
        "StaCurrentScriptContextSlot",
        "FindNonDefaultConstructorOrConstruct",
    ];
    let cutoff: usize = skip_recent.min(removed_recent.len());
    let filtered: Vec<V8OpcodeSpec> = BASE_OPCODES_V12_4
        .iter()
        .copied()
        .filter(|s: &V8OpcodeSpec| {
            !removed_recent
                .iter()
                .skip(cutoff)
                .any(|name: &&str| *name == s.mnemonic)
        })
        .collect();
    filtered
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn node22_table_has_core_opcodes() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node22);
        assert!(table.lookup_mnemonic("Return").is_some());
        assert!(table.lookup_mnemonic("LdaConstant").is_some());
        assert!(table.lookup_mnemonic("CallProperty0").is_some());
        assert!(table.lookup_mnemonic("Star0").is_some());
    }

    #[test]
    fn node24_table_includes_recent_opcodes() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node24);
        assert!(table.lookup_mnemonic("ConstructForwardAllArgs").is_some());
        assert!(
            table
                .lookup_mnemonic("GetEnumeratedKeyedProperty")
                .is_some()
        );
    }

    #[test]
    fn node18_table_excludes_node24_only_opcodes() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node18);
        assert!(table.lookup_mnemonic("ConstructForwardAllArgs").is_none());
        assert!(table.lookup_mnemonic("Return").is_some());
    }

    #[test]
    fn coverage_fraction_reasonable() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node22);
        let frac: f64 = table.coverage_fraction();
        assert!(frac > 0.95, "expected >95% coverage, got {frac}");
    }

    #[test]
    fn unscaled_size_matches_operand_widths() {
        let spec: V8OpcodeSpec = op(
            "Test",
            AccumulatorUse::Write,
            &[OperandKind::Reg, OperandKind::Flag16],
        );
        assert_eq!(spec.unscaled_size(), 1 + 1 + 2);
    }
}
