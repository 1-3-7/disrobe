use std::borrow::Cow;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operand {
    Reg8,
    Reg32,
    UInt8,
    UInt16,
    UInt32,
    Imm32,
    Double,
    Addr8,
    Addr32,
    StringId8,
    StringId16,
    StringId32,
    FunctionId16,
    FunctionId32,
    BigIntId16,
    BigIntId32,
}

impl Operand {
    #[must_use]
    pub(crate) const fn width(self) -> usize {
        match self {
            Self::Reg8 | Self::UInt8 | Self::Addr8 | Self::StringId8 => 1,
            Self::UInt16 | Self::StringId16 | Self::FunctionId16 | Self::BigIntId16 => 2,
            Self::Reg32
            | Self::UInt32
            | Self::Imm32
            | Self::Addr32
            | Self::StringId32
            | Self::FunctionId32
            | Self::BigIntId32 => 4,
            Self::Double => 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OpcodeSpec {
    pub name: &'static str,
    pub operands: &'static [Operand],
}

macro_rules! op {
    ($name:literal $(, $o:ident)*) => {
        OpcodeSpec { name: $name, operands: &[$(Operand::$o),*] }
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BytecodeTable {
    pub version: u32,
    pub specs: &'static [OpcodeSpec],
    pub upstream_tag: &'static str,
    pub graded_sample: &'static str,
}

#[rustfmt::skip]
pub(crate) const OPCODES_HBC62: &[OpcodeSpec] = &[
    op!("NewObjectWithBuffer", Reg8, UInt16, UInt16, UInt16, UInt16),
    op!("NewObjectWithBufferLong", Reg8, UInt16, UInt16, UInt32, UInt32),
    op!("NewObject", Reg8),
    op!("NewObjectWithParent", Reg8, Reg8),
    op!("NewArrayWithBuffer", Reg8, UInt16, UInt16, UInt16),
    op!("NewArrayWithBufferLong", Reg8, UInt16, UInt16, UInt32),
    op!("NewArray", Reg8, UInt16),
    op!("Mov", Reg8, Reg8),
    op!("MovLong", Reg32, Reg32),
    op!("Negate", Reg8, Reg8),
    op!("Not", Reg8, Reg8),
    op!("BitNot", Reg8, Reg8),
    op!("TypeOf", Reg8, Reg8),
    op!("Eq", Reg8, Reg8, Reg8),
    op!("StrictEq", Reg8, Reg8, Reg8),
    op!("Neq", Reg8, Reg8, Reg8),
    op!("StrictNeq", Reg8, Reg8, Reg8),
    op!("Less", Reg8, Reg8, Reg8),
    op!("LessEq", Reg8, Reg8, Reg8),
    op!("Greater", Reg8, Reg8, Reg8),
    op!("GreaterEq", Reg8, Reg8, Reg8),
    op!("Add", Reg8, Reg8, Reg8),
    op!("AddN", Reg8, Reg8, Reg8),
    op!("Mul", Reg8, Reg8, Reg8),
    op!("MulN", Reg8, Reg8, Reg8),
    op!("Div", Reg8, Reg8, Reg8),
    op!("DivN", Reg8, Reg8, Reg8),
    op!("Mod", Reg8, Reg8, Reg8),
    op!("Sub", Reg8, Reg8, Reg8),
    op!("SubN", Reg8, Reg8, Reg8),
    op!("LShift", Reg8, Reg8, Reg8),
    op!("RShift", Reg8, Reg8, Reg8),
    op!("URshift", Reg8, Reg8, Reg8),
    op!("BitAnd", Reg8, Reg8, Reg8),
    op!("BitXor", Reg8, Reg8, Reg8),
    op!("BitOr", Reg8, Reg8, Reg8),
    op!("InstanceOf", Reg8, Reg8, Reg8),
    op!("IsIn", Reg8, Reg8, Reg8),
    op!("GetEnvironment", Reg8, UInt8),
    op!("StoreToEnvironment", Reg8, UInt8, Reg8),
    op!("StoreToEnvironmentL", Reg8, UInt16, Reg8),
    op!("StoreNPToEnvironment", Reg8, UInt8, Reg8),
    op!("StoreNPToEnvironmentL", Reg8, UInt16, Reg8),
    op!("LoadFromEnvironment", Reg8, Reg8, UInt8),
    op!("LoadFromEnvironmentL", Reg8, Reg8, UInt16),
    op!("GetGlobalObject", Reg8),
    op!("GetNewTarget", Reg8),
    op!("CreateEnvironment", Reg8),
    op!("DeclareGlobalVar", StringId32),
    op!("GetByIdShort", Reg8, Reg8, UInt8, StringId8),
    op!("GetById", Reg8, Reg8, UInt8, StringId16),
    op!("GetByIdLong", Reg8, Reg8, UInt8, StringId32),
    op!("TryGetById", Reg8, Reg8, UInt8, StringId16),
    op!("TryGetByIdLong", Reg8, Reg8, UInt8, StringId32),
    op!("PutById", Reg8, Reg8, UInt8, StringId16),
    op!("PutByIdLong", Reg8, Reg8, UInt8, StringId32),
    op!("TryPutById", Reg8, Reg8, UInt8, StringId16),
    op!("TryPutByIdLong", Reg8, Reg8, UInt8, StringId32),
    op!("PutNewOwnByIdShort", Reg8, Reg8, StringId8),
    op!("PutNewOwnById", Reg8, Reg8, StringId16),
    op!("PutNewOwnByIdLong", Reg8, Reg8, StringId32),
    op!("PutNewOwnNEById", Reg8, Reg8, StringId16),
    op!("PutNewOwnNEByIdLong", Reg8, Reg8, StringId32),
    op!("PutOwnByIndex", Reg8, Reg8, UInt8),
    op!("PutOwnByIndexL", Reg8, Reg8, UInt32),
    op!("PutOwnByVal", Reg8, Reg8, Reg8, UInt8),
    op!("DelById", Reg8, Reg8, StringId16),
    op!("DelByIdLong", Reg8, Reg8, StringId32),
    op!("GetByVal", Reg8, Reg8, Reg8),
    op!("PutByVal", Reg8, Reg8, Reg8),
    op!("DelByVal", Reg8, Reg8, Reg8),
    op!("PutOwnGetterSetterByVal", Reg8, Reg8, Reg8, Reg8, UInt8),
    op!("GetPNameList", Reg8, Reg8, Reg8, Reg8),
    op!("GetNextPName", Reg8, Reg8, Reg8, Reg8, Reg8),
    op!("Call", Reg8, Reg8, UInt8),
    op!("Construct", Reg8, Reg8, UInt8),
    op!("Call1", Reg8, Reg8, Reg8),
    op!("CallDirect", Reg8, UInt8, FunctionId16),
    op!("Call2", Reg8, Reg8, Reg8, Reg8),
    op!("Call3", Reg8, Reg8, Reg8, Reg8, Reg8),
    op!("Call4", Reg8, Reg8, Reg8, Reg8, Reg8, Reg8),
    op!("CallLong", Reg8, Reg8, UInt32),
    op!("ConstructLong", Reg8, Reg8, UInt32),
    op!("CallDirectLongIndex", Reg8, UInt8, FunctionId32),
    op!("CallBuiltin", Reg8, UInt8, UInt8),
    op!("Ret", Reg8),
    op!("Catch", Reg8),
    op!("DirectEval", Reg8, Reg8),
    op!("Throw", Reg8),
    op!("ThrowIfUndefinedInst", Reg8),
    op!("Debugger"),
    op!("AsyncBreakCheck"),
    op!("ProfilePoint", UInt16),
    op!("Unreachable"),
    op!("CreateClosure", Reg8, Reg8, FunctionId16),
    op!("CreateClosureLongIndex", Reg8, Reg8, FunctionId32),
    op!("CreateGeneratorClosure", Reg8, Reg8, FunctionId16),
    op!("CreateGeneratorClosureLongIndex", Reg8, Reg8, FunctionId32),
    op!("CreateThis", Reg8, Reg8, Reg8),
    op!("SelectObject", Reg8, Reg8, Reg8),
    op!("LoadParam", Reg8, UInt8),
    op!("LoadParamLong", Reg8, UInt32),
    op!("LoadConstUInt8", Reg8, UInt8),
    op!("LoadConstInt", Reg8, Imm32),
    op!("LoadConstDouble", Reg8, Double),
    op!("LoadConstString", Reg8, StringId16),
    op!("LoadConstStringLongIndex", Reg8, StringId32),
    op!("LoadConstUndefined", Reg8),
    op!("LoadConstNull", Reg8),
    op!("LoadConstTrue", Reg8),
    op!("LoadConstFalse", Reg8),
    op!("LoadConstZero", Reg8),
    op!("CoerceThisNS", Reg8, Reg8),
    op!("LoadThisNS", Reg8),
    op!("ToNumber", Reg8, Reg8),
    op!("ToInt32", Reg8, Reg8),
    op!("AddEmptyString", Reg8, Reg8),
    op!("GetArgumentsPropByVal", Reg8, Reg8, Reg8),
    op!("GetArgumentsLength", Reg8, Reg8),
    op!("ReifyArguments", Reg8),
    op!("CreateRegExp", Reg8, StringId32, StringId32, UInt32),
    op!("SwitchImm", Reg8, UInt32, Addr32, UInt32, UInt32),
    op!("StartGenerator"),
    op!("ResumeGenerator", Reg8, Reg8),
    op!("CompleteGenerator"),
    op!("CreateGenerator", Reg8, Reg8, FunctionId16),
    op!("CreateGeneratorLongIndex", Reg8, Reg8, FunctionId32),
    op!("Jmp", Addr8),
    op!("JmpLong", Addr32),
    op!("JmpTrue", Addr8, Reg8),
    op!("JmpTrueLong", Addr32, Reg8),
    op!("JmpFalse", Addr8, Reg8),
    op!("JmpFalseLong", Addr32, Reg8),
    op!("JmpUndefined", Addr8, Reg8),
    op!("JmpUndefinedLong", Addr32, Reg8),
    op!("SaveGenerator", Addr8),
    op!("SaveGeneratorLong", Addr32),
    op!("JLess", Addr8, Reg8, Reg8),
    op!("JLessLong", Addr32, Reg8, Reg8),
    op!("JNotLess", Addr8, Reg8, Reg8),
    op!("JNotLessLong", Addr32, Reg8, Reg8),
    op!("JLessN", Addr8, Reg8, Reg8),
    op!("JLessNLong", Addr32, Reg8, Reg8),
    op!("JNotLessN", Addr8, Reg8, Reg8),
    op!("JNotLessNLong", Addr32, Reg8, Reg8),
    op!("JLessEqual", Addr8, Reg8, Reg8),
    op!("JLessEqualLong", Addr32, Reg8, Reg8),
    op!("JNotLessEqual", Addr8, Reg8, Reg8),
    op!("JNotLessEqualLong", Addr32, Reg8, Reg8),
    op!("JLessEqualN", Addr8, Reg8, Reg8),
    op!("JLessEqualNLong", Addr32, Reg8, Reg8),
    op!("JNotLessEqualN", Addr8, Reg8, Reg8),
    op!("JNotLessEqualNLong", Addr32, Reg8, Reg8),
    op!("JGreater", Addr8, Reg8, Reg8),
    op!("JGreaterLong", Addr32, Reg8, Reg8),
    op!("JNotGreater", Addr8, Reg8, Reg8),
    op!("JNotGreaterLong", Addr32, Reg8, Reg8),
    op!("JGreaterN", Addr8, Reg8, Reg8),
    op!("JGreaterNLong", Addr32, Reg8, Reg8),
    op!("JNotGreaterN", Addr8, Reg8, Reg8),
    op!("JNotGreaterNLong", Addr32, Reg8, Reg8),
    op!("JGreaterEqual", Addr8, Reg8, Reg8),
    op!("JGreaterEqualLong", Addr32, Reg8, Reg8),
    op!("JNotGreaterEqual", Addr8, Reg8, Reg8),
    op!("JNotGreaterEqualLong", Addr32, Reg8, Reg8),
    op!("JGreaterEqualN", Addr8, Reg8, Reg8),
    op!("JGreaterEqualNLong", Addr32, Reg8, Reg8),
    op!("JNotGreaterEqualN", Addr8, Reg8, Reg8),
    op!("JNotGreaterEqualNLong", Addr32, Reg8, Reg8),
    op!("JEqual", Addr8, Reg8, Reg8),
    op!("JEqualLong", Addr32, Reg8, Reg8),
    op!("JNotEqual", Addr8, Reg8, Reg8),
    op!("JNotEqualLong", Addr32, Reg8, Reg8),
    op!("JStrictEqual", Addr8, Reg8, Reg8),
    op!("JStrictEqualLong", Addr32, Reg8, Reg8),
    op!("JStrictNotEqual", Addr8, Reg8, Reg8),
    op!("JStrictNotEqualLong", Addr32, Reg8, Reg8),
];

#[rustfmt::skip]
pub(crate) const OPCODES_HBC76: &[OpcodeSpec] = &[
    op!("NewObjectWithBuffer", Reg8, UInt16, UInt16, UInt16, UInt16),
    op!("NewObjectWithBufferLong", Reg8, UInt16, UInt16, UInt32, UInt32),
    op!("NewObject", Reg8),
    op!("NewObjectWithParent", Reg8, Reg8),
    op!("NewArrayWithBuffer", Reg8, UInt16, UInt16, UInt16),
    op!("NewArrayWithBufferLong", Reg8, UInt16, UInt16, UInt32),
    op!("NewArray", Reg8, UInt16),
    op!("Mov", Reg8, Reg8),
    op!("MovLong", Reg32, Reg32),
    op!("Negate", Reg8, Reg8),
    op!("Not", Reg8, Reg8),
    op!("BitNot", Reg8, Reg8),
    op!("TypeOf", Reg8, Reg8),
    op!("Eq", Reg8, Reg8, Reg8),
    op!("StrictEq", Reg8, Reg8, Reg8),
    op!("Neq", Reg8, Reg8, Reg8),
    op!("StrictNeq", Reg8, Reg8, Reg8),
    op!("Less", Reg8, Reg8, Reg8),
    op!("LessEq", Reg8, Reg8, Reg8),
    op!("Greater", Reg8, Reg8, Reg8),
    op!("GreaterEq", Reg8, Reg8, Reg8),
    op!("Add", Reg8, Reg8, Reg8),
    op!("AddN", Reg8, Reg8, Reg8),
    op!("Mul", Reg8, Reg8, Reg8),
    op!("MulN", Reg8, Reg8, Reg8),
    op!("Div", Reg8, Reg8, Reg8),
    op!("DivN", Reg8, Reg8, Reg8),
    op!("Mod", Reg8, Reg8, Reg8),
    op!("Sub", Reg8, Reg8, Reg8),
    op!("SubN", Reg8, Reg8, Reg8),
    op!("LShift", Reg8, Reg8, Reg8),
    op!("RShift", Reg8, Reg8, Reg8),
    op!("URshift", Reg8, Reg8, Reg8),
    op!("BitAnd", Reg8, Reg8, Reg8),
    op!("BitXor", Reg8, Reg8, Reg8),
    op!("BitOr", Reg8, Reg8, Reg8),
    op!("InstanceOf", Reg8, Reg8, Reg8),
    op!("IsIn", Reg8, Reg8, Reg8),
    op!("GetEnvironment", Reg8, UInt8),
    op!("StoreToEnvironment", Reg8, UInt8, Reg8),
    op!("StoreToEnvironmentL", Reg8, UInt16, Reg8),
    op!("StoreNPToEnvironment", Reg8, UInt8, Reg8),
    op!("StoreNPToEnvironmentL", Reg8, UInt16, Reg8),
    op!("LoadFromEnvironment", Reg8, Reg8, UInt8),
    op!("LoadFromEnvironmentL", Reg8, Reg8, UInt16),
    op!("GetGlobalObject", Reg8),
    op!("GetNewTarget", Reg8),
    op!("CreateEnvironment", Reg8),
    op!("DeclareGlobalVar", StringId32),
    op!("GetByIdShort", Reg8, Reg8, UInt8, StringId8),
    op!("GetById", Reg8, Reg8, UInt8, StringId16),
    op!("GetByIdLong", Reg8, Reg8, UInt8, StringId32),
    op!("TryGetById", Reg8, Reg8, UInt8, StringId16),
    op!("TryGetByIdLong", Reg8, Reg8, UInt8, StringId32),
    op!("PutById", Reg8, Reg8, UInt8, StringId16),
    op!("PutByIdLong", Reg8, Reg8, UInt8, StringId32),
    op!("TryPutById", Reg8, Reg8, UInt8, StringId16),
    op!("TryPutByIdLong", Reg8, Reg8, UInt8, StringId32),
    op!("PutNewOwnByIdShort", Reg8, Reg8, StringId8),
    op!("PutNewOwnById", Reg8, Reg8, StringId16),
    op!("PutNewOwnByIdLong", Reg8, Reg8, StringId32),
    op!("PutNewOwnNEById", Reg8, Reg8, StringId16),
    op!("PutNewOwnNEByIdLong", Reg8, Reg8, StringId32),
    op!("PutOwnByIndex", Reg8, Reg8, UInt8),
    op!("PutOwnByIndexL", Reg8, Reg8, UInt32),
    op!("PutOwnByVal", Reg8, Reg8, Reg8, UInt8),
    op!("DelById", Reg8, Reg8, StringId16),
    op!("DelByIdLong", Reg8, Reg8, StringId32),
    op!("GetByVal", Reg8, Reg8, Reg8),
    op!("PutByVal", Reg8, Reg8, Reg8),
    op!("DelByVal", Reg8, Reg8, Reg8),
    op!("PutOwnGetterSetterByVal", Reg8, Reg8, Reg8, Reg8, UInt8),
    op!("GetPNameList", Reg8, Reg8, Reg8, Reg8),
    op!("GetNextPName", Reg8, Reg8, Reg8, Reg8, Reg8),
    op!("Call", Reg8, Reg8, UInt8),
    op!("Construct", Reg8, Reg8, UInt8),
    op!("Call1", Reg8, Reg8, Reg8),
    op!("CallDirect", Reg8, UInt8, FunctionId16),
    op!("Call2", Reg8, Reg8, Reg8, Reg8),
    op!("Call3", Reg8, Reg8, Reg8, Reg8, Reg8),
    op!("Call4", Reg8, Reg8, Reg8, Reg8, Reg8, Reg8),
    op!("CallLong", Reg8, Reg8, UInt32),
    op!("ConstructLong", Reg8, Reg8, UInt32),
    op!("CallDirectLongIndex", Reg8, UInt8, FunctionId32),
    op!("CallBuiltin", Reg8, UInt8, UInt8),
    op!("Ret", Reg8),
    op!("Catch", Reg8),
    op!("DirectEval", Reg8, Reg8),
    op!("Throw", Reg8),
    op!("ThrowIfUndefinedInst", Reg8),
    op!("Debugger"),
    op!("AsyncBreakCheck"),
    op!("ProfilePoint", UInt16),
    op!("Unreachable"),
    op!("CreateClosure", Reg8, Reg8, FunctionId16),
    op!("CreateClosureLongIndex", Reg8, Reg8, FunctionId32),
    op!("CreateGeneratorClosure", Reg8, Reg8, FunctionId16),
    op!("CreateGeneratorClosureLongIndex", Reg8, Reg8, FunctionId32),
    op!("CreateThis", Reg8, Reg8, Reg8),
    op!("SelectObject", Reg8, Reg8, Reg8),
    op!("LoadParam", Reg8, UInt8),
    op!("LoadParamLong", Reg8, UInt32),
    op!("LoadConstUInt8", Reg8, UInt8),
    op!("LoadConstInt", Reg8, Imm32),
    op!("LoadConstDouble", Reg8, Double),
    op!("LoadConstString", Reg8, StringId16),
    op!("LoadConstStringLongIndex", Reg8, StringId32),
    op!("LoadConstUndefined", Reg8),
    op!("LoadConstNull", Reg8),
    op!("LoadConstTrue", Reg8),
    op!("LoadConstFalse", Reg8),
    op!("LoadConstZero", Reg8),
    op!("CoerceThisNS", Reg8, Reg8),
    op!("LoadThisNS", Reg8),
    op!("ToNumber", Reg8, Reg8),
    op!("ToInt32", Reg8, Reg8),
    op!("AddEmptyString", Reg8, Reg8),
    op!("GetArgumentsPropByVal", Reg8, Reg8, Reg8),
    op!("GetArgumentsLength", Reg8, Reg8),
    op!("ReifyArguments", Reg8),
    op!("CreateRegExp", Reg8, StringId32, StringId32, UInt32),
    op!("SwitchImm", Reg8, UInt32, Addr32, UInt32, UInt32),
    op!("StartGenerator"),
    op!("ResumeGenerator", Reg8, Reg8),
    op!("CompleteGenerator"),
    op!("CreateGenerator", Reg8, Reg8, FunctionId16),
    op!("CreateGeneratorLongIndex", Reg8, Reg8, FunctionId32),
    op!("IteratorBegin", Reg8, Reg8),
    op!("IteratorNext", Reg8, Reg8, Reg8),
    op!("IteratorClose", Reg8, UInt8),
    op!("Jmp", Addr8),
    op!("JmpLong", Addr32),
    op!("JmpTrue", Addr8, Reg8),
    op!("JmpTrueLong", Addr32, Reg8),
    op!("JmpFalse", Addr8, Reg8),
    op!("JmpFalseLong", Addr32, Reg8),
    op!("JmpUndefined", Addr8, Reg8),
    op!("JmpUndefinedLong", Addr32, Reg8),
    op!("SaveGenerator", Addr8),
    op!("SaveGeneratorLong", Addr32),
    op!("JLess", Addr8, Reg8, Reg8),
    op!("JLessLong", Addr32, Reg8, Reg8),
    op!("JNotLess", Addr8, Reg8, Reg8),
    op!("JNotLessLong", Addr32, Reg8, Reg8),
    op!("JLessN", Addr8, Reg8, Reg8),
    op!("JLessNLong", Addr32, Reg8, Reg8),
    op!("JNotLessN", Addr8, Reg8, Reg8),
    op!("JNotLessNLong", Addr32, Reg8, Reg8),
    op!("JLessEqual", Addr8, Reg8, Reg8),
    op!("JLessEqualLong", Addr32, Reg8, Reg8),
    op!("JNotLessEqual", Addr8, Reg8, Reg8),
    op!("JNotLessEqualLong", Addr32, Reg8, Reg8),
    op!("JLessEqualN", Addr8, Reg8, Reg8),
    op!("JLessEqualNLong", Addr32, Reg8, Reg8),
    op!("JNotLessEqualN", Addr8, Reg8, Reg8),
    op!("JNotLessEqualNLong", Addr32, Reg8, Reg8),
    op!("JGreater", Addr8, Reg8, Reg8),
    op!("JGreaterLong", Addr32, Reg8, Reg8),
    op!("JNotGreater", Addr8, Reg8, Reg8),
    op!("JNotGreaterLong", Addr32, Reg8, Reg8),
    op!("JGreaterN", Addr8, Reg8, Reg8),
    op!("JGreaterNLong", Addr32, Reg8, Reg8),
    op!("JNotGreaterN", Addr8, Reg8, Reg8),
    op!("JNotGreaterNLong", Addr32, Reg8, Reg8),
    op!("JGreaterEqual", Addr8, Reg8, Reg8),
    op!("JGreaterEqualLong", Addr32, Reg8, Reg8),
    op!("JNotGreaterEqual", Addr8, Reg8, Reg8),
    op!("JNotGreaterEqualLong", Addr32, Reg8, Reg8),
    op!("JGreaterEqualN", Addr8, Reg8, Reg8),
    op!("JGreaterEqualNLong", Addr32, Reg8, Reg8),
    op!("JNotGreaterEqualN", Addr8, Reg8, Reg8),
    op!("JNotGreaterEqualNLong", Addr32, Reg8, Reg8),
    op!("JEqual", Addr8, Reg8, Reg8),
    op!("JEqualLong", Addr32, Reg8, Reg8),
    op!("JNotEqual", Addr8, Reg8, Reg8),
    op!("JNotEqualLong", Addr32, Reg8, Reg8),
    op!("JStrictEqual", Addr8, Reg8, Reg8),
    op!("JStrictEqualLong", Addr32, Reg8, Reg8),
    op!("JStrictNotEqual", Addr8, Reg8, Reg8),
    op!("JStrictNotEqualLong", Addr32, Reg8, Reg8),
];

#[rustfmt::skip]
pub(crate) const OPCODES_HBC84: &[OpcodeSpec] = &[
    op!("Unreachable"),
    op!("NewObjectWithBuffer", Reg8, UInt16, UInt16, UInt16, UInt16),
    op!("NewObjectWithBufferLong", Reg8, UInt16, UInt16, UInt32, UInt32),
    op!("NewObject", Reg8),
    op!("NewObjectWithParent", Reg8, Reg8),
    op!("NewArrayWithBuffer", Reg8, UInt16, UInt16, UInt16),
    op!("NewArrayWithBufferLong", Reg8, UInt16, UInt16, UInt32),
    op!("NewArray", Reg8, UInt16),
    op!("Mov", Reg8, Reg8),
    op!("MovLong", Reg32, Reg32),
    op!("Negate", Reg8, Reg8),
    op!("Not", Reg8, Reg8),
    op!("BitNot", Reg8, Reg8),
    op!("TypeOf", Reg8, Reg8),
    op!("Eq", Reg8, Reg8, Reg8),
    op!("StrictEq", Reg8, Reg8, Reg8),
    op!("Neq", Reg8, Reg8, Reg8),
    op!("StrictNeq", Reg8, Reg8, Reg8),
    op!("Less", Reg8, Reg8, Reg8),
    op!("LessEq", Reg8, Reg8, Reg8),
    op!("Greater", Reg8, Reg8, Reg8),
    op!("GreaterEq", Reg8, Reg8, Reg8),
    op!("Add", Reg8, Reg8, Reg8),
    op!("AddN", Reg8, Reg8, Reg8),
    op!("Mul", Reg8, Reg8, Reg8),
    op!("MulN", Reg8, Reg8, Reg8),
    op!("Div", Reg8, Reg8, Reg8),
    op!("DivN", Reg8, Reg8, Reg8),
    op!("Mod", Reg8, Reg8, Reg8),
    op!("Sub", Reg8, Reg8, Reg8),
    op!("SubN", Reg8, Reg8, Reg8),
    op!("LShift", Reg8, Reg8, Reg8),
    op!("RShift", Reg8, Reg8, Reg8),
    op!("URshift", Reg8, Reg8, Reg8),
    op!("BitAnd", Reg8, Reg8, Reg8),
    op!("BitXor", Reg8, Reg8, Reg8),
    op!("BitOr", Reg8, Reg8, Reg8),
    op!("InstanceOf", Reg8, Reg8, Reg8),
    op!("IsIn", Reg8, Reg8, Reg8),
    op!("GetEnvironment", Reg8, UInt8),
    op!("StoreToEnvironment", Reg8, UInt8, Reg8),
    op!("StoreToEnvironmentL", Reg8, UInt16, Reg8),
    op!("StoreNPToEnvironment", Reg8, UInt8, Reg8),
    op!("StoreNPToEnvironmentL", Reg8, UInt16, Reg8),
    op!("LoadFromEnvironment", Reg8, Reg8, UInt8),
    op!("LoadFromEnvironmentL", Reg8, Reg8, UInt16),
    op!("GetGlobalObject", Reg8),
    op!("GetNewTarget", Reg8),
    op!("CreateEnvironment", Reg8),
    op!("DeclareGlobalVar", StringId32),
    op!("GetByIdShort", Reg8, Reg8, UInt8, StringId8),
    op!("GetById", Reg8, Reg8, UInt8, StringId16),
    op!("GetByIdLong", Reg8, Reg8, UInt8, StringId32),
    op!("TryGetById", Reg8, Reg8, UInt8, StringId16),
    op!("TryGetByIdLong", Reg8, Reg8, UInt8, StringId32),
    op!("PutById", Reg8, Reg8, UInt8, StringId16),
    op!("PutByIdLong", Reg8, Reg8, UInt8, StringId32),
    op!("TryPutById", Reg8, Reg8, UInt8, StringId16),
    op!("TryPutByIdLong", Reg8, Reg8, UInt8, StringId32),
    op!("PutNewOwnByIdShort", Reg8, Reg8, StringId8),
    op!("PutNewOwnById", Reg8, Reg8, StringId16),
    op!("PutNewOwnByIdLong", Reg8, Reg8, StringId32),
    op!("PutNewOwnNEById", Reg8, Reg8, StringId16),
    op!("PutNewOwnNEByIdLong", Reg8, Reg8, StringId32),
    op!("PutOwnByIndex", Reg8, Reg8, UInt8),
    op!("PutOwnByIndexL", Reg8, Reg8, UInt32),
    op!("PutOwnByVal", Reg8, Reg8, Reg8, UInt8),
    op!("DelById", Reg8, Reg8, StringId16),
    op!("DelByIdLong", Reg8, Reg8, StringId32),
    op!("GetByVal", Reg8, Reg8, Reg8),
    op!("PutByVal", Reg8, Reg8, Reg8),
    op!("DelByVal", Reg8, Reg8, Reg8),
    op!("PutOwnGetterSetterByVal", Reg8, Reg8, Reg8, Reg8, UInt8),
    op!("GetPNameList", Reg8, Reg8, Reg8, Reg8),
    op!("GetNextPName", Reg8, Reg8, Reg8, Reg8, Reg8),
    op!("Call", Reg8, Reg8, UInt8),
    op!("Construct", Reg8, Reg8, UInt8),
    op!("Call1", Reg8, Reg8, Reg8),
    op!("CallDirect", Reg8, UInt8, FunctionId16),
    op!("Call2", Reg8, Reg8, Reg8, Reg8),
    op!("Call3", Reg8, Reg8, Reg8, Reg8, Reg8),
    op!("Call4", Reg8, Reg8, Reg8, Reg8, Reg8, Reg8),
    op!("CallLong", Reg8, Reg8, UInt32),
    op!("ConstructLong", Reg8, Reg8, UInt32),
    op!("CallDirectLongIndex", Reg8, UInt8, FunctionId32),
    op!("CallBuiltin", Reg8, UInt8, UInt8),
    op!("CallBuiltinLong", Reg8, UInt8, UInt32),
    op!("GetBuiltinClosure", Reg8, UInt8),
    op!("Ret", Reg8),
    op!("Catch", Reg8),
    op!("DirectEval", Reg8, Reg8),
    op!("Throw", Reg8),
    op!("ThrowIfEmpty", Reg8, Reg8),
    op!("Debugger"),
    op!("AsyncBreakCheck"),
    op!("ProfilePoint", UInt16),
    op!("CreateClosure", Reg8, Reg8, FunctionId16),
    op!("CreateClosureLongIndex", Reg8, Reg8, FunctionId32),
    op!("CreateGeneratorClosure", Reg8, Reg8, FunctionId16),
    op!("CreateGeneratorClosureLongIndex", Reg8, Reg8, FunctionId32),
    op!("CreateAsyncClosure", Reg8, Reg8, FunctionId16),
    op!("CreateAsyncClosureLongIndex", Reg8, Reg8, FunctionId32),
    op!("CreateThis", Reg8, Reg8, Reg8),
    op!("SelectObject", Reg8, Reg8, Reg8),
    op!("LoadParam", Reg8, UInt8),
    op!("LoadParamLong", Reg8, UInt32),
    op!("LoadConstUInt8", Reg8, UInt8),
    op!("LoadConstInt", Reg8, Imm32),
    op!("LoadConstDouble", Reg8, Double),
    op!("LoadConstString", Reg8, StringId16),
    op!("LoadConstStringLongIndex", Reg8, StringId32),
    op!("LoadConstEmpty", Reg8),
    op!("LoadConstUndefined", Reg8),
    op!("LoadConstNull", Reg8),
    op!("LoadConstTrue", Reg8),
    op!("LoadConstFalse", Reg8),
    op!("LoadConstZero", Reg8),
    op!("CoerceThisNS", Reg8, Reg8),
    op!("LoadThisNS", Reg8),
    op!("ToNumber", Reg8, Reg8),
    op!("ToInt32", Reg8, Reg8),
    op!("AddEmptyString", Reg8, Reg8),
    op!("GetArgumentsPropByVal", Reg8, Reg8, Reg8),
    op!("GetArgumentsLength", Reg8, Reg8),
    op!("ReifyArguments", Reg8),
    op!("CreateRegExp", Reg8, StringId32, StringId32, UInt32),
    op!("SwitchImm", Reg8, UInt32, Addr32, UInt32, UInt32),
    op!("StartGenerator"),
    op!("ResumeGenerator", Reg8, Reg8),
    op!("CompleteGenerator"),
    op!("CreateGenerator", Reg8, Reg8, FunctionId16),
    op!("CreateGeneratorLongIndex", Reg8, Reg8, FunctionId32),
    op!("IteratorBegin", Reg8, Reg8),
    op!("IteratorNext", Reg8, Reg8, Reg8),
    op!("IteratorClose", Reg8, UInt8),
    op!("Jmp", Addr8),
    op!("JmpLong", Addr32),
    op!("JmpTrue", Addr8, Reg8),
    op!("JmpTrueLong", Addr32, Reg8),
    op!("JmpFalse", Addr8, Reg8),
    op!("JmpFalseLong", Addr32, Reg8),
    op!("JmpUndefined", Addr8, Reg8),
    op!("JmpUndefinedLong", Addr32, Reg8),
    op!("SaveGenerator", Addr8),
    op!("SaveGeneratorLong", Addr32),
    op!("JLess", Addr8, Reg8, Reg8),
    op!("JLessLong", Addr32, Reg8, Reg8),
    op!("JNotLess", Addr8, Reg8, Reg8),
    op!("JNotLessLong", Addr32, Reg8, Reg8),
    op!("JLessN", Addr8, Reg8, Reg8),
    op!("JLessNLong", Addr32, Reg8, Reg8),
    op!("JNotLessN", Addr8, Reg8, Reg8),
    op!("JNotLessNLong", Addr32, Reg8, Reg8),
    op!("JLessEqual", Addr8, Reg8, Reg8),
    op!("JLessEqualLong", Addr32, Reg8, Reg8),
    op!("JNotLessEqual", Addr8, Reg8, Reg8),
    op!("JNotLessEqualLong", Addr32, Reg8, Reg8),
    op!("JLessEqualN", Addr8, Reg8, Reg8),
    op!("JLessEqualNLong", Addr32, Reg8, Reg8),
    op!("JNotLessEqualN", Addr8, Reg8, Reg8),
    op!("JNotLessEqualNLong", Addr32, Reg8, Reg8),
    op!("JGreater", Addr8, Reg8, Reg8),
    op!("JGreaterLong", Addr32, Reg8, Reg8),
    op!("JNotGreater", Addr8, Reg8, Reg8),
    op!("JNotGreaterLong", Addr32, Reg8, Reg8),
    op!("JGreaterN", Addr8, Reg8, Reg8),
    op!("JGreaterNLong", Addr32, Reg8, Reg8),
    op!("JNotGreaterN", Addr8, Reg8, Reg8),
    op!("JNotGreaterNLong", Addr32, Reg8, Reg8),
    op!("JGreaterEqual", Addr8, Reg8, Reg8),
    op!("JGreaterEqualLong", Addr32, Reg8, Reg8),
    op!("JNotGreaterEqual", Addr8, Reg8, Reg8),
    op!("JNotGreaterEqualLong", Addr32, Reg8, Reg8),
    op!("JGreaterEqualN", Addr8, Reg8, Reg8),
    op!("JGreaterEqualNLong", Addr32, Reg8, Reg8),
    op!("JNotGreaterEqualN", Addr8, Reg8, Reg8),
    op!("JNotGreaterEqualNLong", Addr32, Reg8, Reg8),
    op!("JEqual", Addr8, Reg8, Reg8),
    op!("JEqualLong", Addr32, Reg8, Reg8),
    op!("JNotEqual", Addr8, Reg8, Reg8),
    op!("JNotEqualLong", Addr32, Reg8, Reg8),
    op!("JStrictEqual", Addr8, Reg8, Reg8),
    op!("JStrictEqualLong", Addr32, Reg8, Reg8),
    op!("JStrictNotEqual", Addr8, Reg8, Reg8),
    op!("JStrictNotEqualLong", Addr32, Reg8, Reg8),
];

#[rustfmt::skip]
pub(crate) const OPCODES_HBC89: &[OpcodeSpec] = &[
    op!("Unreachable"),
    op!("NewObjectWithBuffer", Reg8, UInt16, UInt16, UInt16, UInt16),
    op!("NewObjectWithBufferLong", Reg8, UInt16, UInt16, UInt32, UInt32),
    op!("NewObject", Reg8),
    op!("NewObjectWithParent", Reg8, Reg8),
    op!("NewArrayWithBuffer", Reg8, UInt16, UInt16, UInt16),
    op!("NewArrayWithBufferLong", Reg8, UInt16, UInt16, UInt32),
    op!("NewArray", Reg8, UInt16),
    op!("Mov", Reg8, Reg8),
    op!("MovLong", Reg32, Reg32),
    op!("Negate", Reg8, Reg8),
    op!("Not", Reg8, Reg8),
    op!("BitNot", Reg8, Reg8),
    op!("TypeOf", Reg8, Reg8),
    op!("Eq", Reg8, Reg8, Reg8),
    op!("StrictEq", Reg8, Reg8, Reg8),
    op!("Neq", Reg8, Reg8, Reg8),
    op!("StrictNeq", Reg8, Reg8, Reg8),
    op!("Less", Reg8, Reg8, Reg8),
    op!("LessEq", Reg8, Reg8, Reg8),
    op!("Greater", Reg8, Reg8, Reg8),
    op!("GreaterEq", Reg8, Reg8, Reg8),
    op!("Add", Reg8, Reg8, Reg8),
    op!("AddN", Reg8, Reg8, Reg8),
    op!("Mul", Reg8, Reg8, Reg8),
    op!("MulN", Reg8, Reg8, Reg8),
    op!("Div", Reg8, Reg8, Reg8),
    op!("DivN", Reg8, Reg8, Reg8),
    op!("Mod", Reg8, Reg8, Reg8),
    op!("Sub", Reg8, Reg8, Reg8),
    op!("SubN", Reg8, Reg8, Reg8),
    op!("LShift", Reg8, Reg8, Reg8),
    op!("RShift", Reg8, Reg8, Reg8),
    op!("URshift", Reg8, Reg8, Reg8),
    op!("BitAnd", Reg8, Reg8, Reg8),
    op!("BitXor", Reg8, Reg8, Reg8),
    op!("BitOr", Reg8, Reg8, Reg8),
    op!("Inc", Reg8, Reg8),
    op!("Dec", Reg8, Reg8),
    op!("InstanceOf", Reg8, Reg8, Reg8),
    op!("IsIn", Reg8, Reg8, Reg8),
    op!("GetEnvironment", Reg8, UInt8),
    op!("StoreToEnvironment", Reg8, UInt8, Reg8),
    op!("StoreToEnvironmentL", Reg8, UInt16, Reg8),
    op!("StoreNPToEnvironment", Reg8, UInt8, Reg8),
    op!("StoreNPToEnvironmentL", Reg8, UInt16, Reg8),
    op!("LoadFromEnvironment", Reg8, Reg8, UInt8),
    op!("LoadFromEnvironmentL", Reg8, Reg8, UInt16),
    op!("GetGlobalObject", Reg8),
    op!("GetNewTarget", Reg8),
    op!("CreateEnvironment", Reg8),
    op!("DeclareGlobalVar", StringId32),
    op!("GetByIdShort", Reg8, Reg8, UInt8, StringId8),
    op!("GetById", Reg8, Reg8, UInt8, StringId16),
    op!("GetByIdLong", Reg8, Reg8, UInt8, StringId32),
    op!("TryGetById", Reg8, Reg8, UInt8, StringId16),
    op!("TryGetByIdLong", Reg8, Reg8, UInt8, StringId32),
    op!("PutById", Reg8, Reg8, UInt8, StringId16),
    op!("PutByIdLong", Reg8, Reg8, UInt8, StringId32),
    op!("TryPutById", Reg8, Reg8, UInt8, StringId16),
    op!("TryPutByIdLong", Reg8, Reg8, UInt8, StringId32),
    op!("PutNewOwnByIdShort", Reg8, Reg8, StringId8),
    op!("PutNewOwnById", Reg8, Reg8, StringId16),
    op!("PutNewOwnByIdLong", Reg8, Reg8, StringId32),
    op!("PutNewOwnNEById", Reg8, Reg8, StringId16),
    op!("PutNewOwnNEByIdLong", Reg8, Reg8, StringId32),
    op!("PutOwnByIndex", Reg8, Reg8, UInt8),
    op!("PutOwnByIndexL", Reg8, Reg8, UInt32),
    op!("PutOwnByVal", Reg8, Reg8, Reg8, UInt8),
    op!("DelById", Reg8, Reg8, StringId16),
    op!("DelByIdLong", Reg8, Reg8, StringId32),
    op!("GetByVal", Reg8, Reg8, Reg8),
    op!("PutByVal", Reg8, Reg8, Reg8),
    op!("DelByVal", Reg8, Reg8, Reg8),
    op!("PutOwnGetterSetterByVal", Reg8, Reg8, Reg8, Reg8, UInt8),
    op!("GetPNameList", Reg8, Reg8, Reg8, Reg8),
    op!("GetNextPName", Reg8, Reg8, Reg8, Reg8, Reg8),
    op!("Call", Reg8, Reg8, UInt8),
    op!("Construct", Reg8, Reg8, UInt8),
    op!("Call1", Reg8, Reg8, Reg8),
    op!("CallDirect", Reg8, UInt8, FunctionId16),
    op!("Call2", Reg8, Reg8, Reg8, Reg8),
    op!("Call3", Reg8, Reg8, Reg8, Reg8, Reg8),
    op!("Call4", Reg8, Reg8, Reg8, Reg8, Reg8, Reg8),
    op!("CallLong", Reg8, Reg8, UInt32),
    op!("ConstructLong", Reg8, Reg8, UInt32),
    op!("CallDirectLongIndex", Reg8, UInt8, FunctionId32),
    op!("CallBuiltin", Reg8, UInt8, UInt8),
    op!("CallBuiltinLong", Reg8, UInt8, UInt32),
    op!("GetBuiltinClosure", Reg8, UInt8),
    op!("Ret", Reg8),
    op!("Catch", Reg8),
    op!("DirectEval", Reg8, Reg8),
    op!("Throw", Reg8),
    op!("ThrowIfEmpty", Reg8, Reg8),
    op!("Debugger"),
    op!("AsyncBreakCheck"),
    op!("ProfilePoint", UInt16),
    op!("CreateClosure", Reg8, Reg8, FunctionId16),
    op!("CreateClosureLongIndex", Reg8, Reg8, FunctionId32),
    op!("CreateGeneratorClosure", Reg8, Reg8, FunctionId16),
    op!("CreateGeneratorClosureLongIndex", Reg8, Reg8, FunctionId32),
    op!("CreateAsyncClosure", Reg8, Reg8, FunctionId16),
    op!("CreateAsyncClosureLongIndex", Reg8, Reg8, FunctionId32),
    op!("CreateThis", Reg8, Reg8, Reg8),
    op!("SelectObject", Reg8, Reg8, Reg8),
    op!("LoadParam", Reg8, UInt8),
    op!("LoadParamLong", Reg8, UInt32),
    op!("LoadConstUInt8", Reg8, UInt8),
    op!("LoadConstInt", Reg8, Imm32),
    op!("LoadConstDouble", Reg8, Double),
    op!("LoadConstBigInt", Reg8, BigIntId16),
    op!("LoadConstBigIntLongIndex", Reg8, BigIntId32),
    op!("LoadConstString", Reg8, StringId16),
    op!("LoadConstStringLongIndex", Reg8, StringId32),
    op!("LoadConstEmpty", Reg8),
    op!("LoadConstUndefined", Reg8),
    op!("LoadConstNull", Reg8),
    op!("LoadConstTrue", Reg8),
    op!("LoadConstFalse", Reg8),
    op!("LoadConstZero", Reg8),
    op!("CoerceThisNS", Reg8, Reg8),
    op!("LoadThisNS", Reg8),
    op!("ToNumber", Reg8, Reg8),
    op!("ToNumeric", Reg8, Reg8),
    op!("ToInt32", Reg8, Reg8),
    op!("AddEmptyString", Reg8, Reg8),
    op!("GetArgumentsPropByVal", Reg8, Reg8, Reg8),
    op!("GetArgumentsLength", Reg8, Reg8),
    op!("ReifyArguments", Reg8),
    op!("CreateRegExp", Reg8, StringId32, StringId32, UInt32),
    op!("SwitchImm", Reg8, UInt32, Addr32, UInt32, UInt32),
    op!("StartGenerator"),
    op!("ResumeGenerator", Reg8, Reg8),
    op!("CompleteGenerator"),
    op!("CreateGenerator", Reg8, Reg8, FunctionId16),
    op!("CreateGeneratorLongIndex", Reg8, Reg8, FunctionId32),
    op!("IteratorBegin", Reg8, Reg8),
    op!("IteratorNext", Reg8, Reg8, Reg8),
    op!("IteratorClose", Reg8, UInt8),
    op!("Jmp", Addr8),
    op!("JmpLong", Addr32),
    op!("JmpTrue", Addr8, Reg8),
    op!("JmpTrueLong", Addr32, Reg8),
    op!("JmpFalse", Addr8, Reg8),
    op!("JmpFalseLong", Addr32, Reg8),
    op!("JmpUndefined", Addr8, Reg8),
    op!("JmpUndefinedLong", Addr32, Reg8),
    op!("SaveGenerator", Addr8),
    op!("SaveGeneratorLong", Addr32),
    op!("JLess", Addr8, Reg8, Reg8),
    op!("JLessLong", Addr32, Reg8, Reg8),
    op!("JNotLess", Addr8, Reg8, Reg8),
    op!("JNotLessLong", Addr32, Reg8, Reg8),
    op!("JLessN", Addr8, Reg8, Reg8),
    op!("JLessNLong", Addr32, Reg8, Reg8),
    op!("JNotLessN", Addr8, Reg8, Reg8),
    op!("JNotLessNLong", Addr32, Reg8, Reg8),
    op!("JLessEqual", Addr8, Reg8, Reg8),
    op!("JLessEqualLong", Addr32, Reg8, Reg8),
    op!("JNotLessEqual", Addr8, Reg8, Reg8),
    op!("JNotLessEqualLong", Addr32, Reg8, Reg8),
    op!("JLessEqualN", Addr8, Reg8, Reg8),
    op!("JLessEqualNLong", Addr32, Reg8, Reg8),
    op!("JNotLessEqualN", Addr8, Reg8, Reg8),
    op!("JNotLessEqualNLong", Addr32, Reg8, Reg8),
    op!("JGreater", Addr8, Reg8, Reg8),
    op!("JGreaterLong", Addr32, Reg8, Reg8),
    op!("JNotGreater", Addr8, Reg8, Reg8),
    op!("JNotGreaterLong", Addr32, Reg8, Reg8),
    op!("JGreaterN", Addr8, Reg8, Reg8),
    op!("JGreaterNLong", Addr32, Reg8, Reg8),
    op!("JNotGreaterN", Addr8, Reg8, Reg8),
    op!("JNotGreaterNLong", Addr32, Reg8, Reg8),
    op!("JGreaterEqual", Addr8, Reg8, Reg8),
    op!("JGreaterEqualLong", Addr32, Reg8, Reg8),
    op!("JNotGreaterEqual", Addr8, Reg8, Reg8),
    op!("JNotGreaterEqualLong", Addr32, Reg8, Reg8),
    op!("JGreaterEqualN", Addr8, Reg8, Reg8),
    op!("JGreaterEqualNLong", Addr32, Reg8, Reg8),
    op!("JNotGreaterEqualN", Addr8, Reg8, Reg8),
    op!("JNotGreaterEqualNLong", Addr32, Reg8, Reg8),
    op!("JEqual", Addr8, Reg8, Reg8),
    op!("JEqualLong", Addr32, Reg8, Reg8),
    op!("JNotEqual", Addr8, Reg8, Reg8),
    op!("JNotEqualLong", Addr32, Reg8, Reg8),
    op!("JStrictEqual", Addr8, Reg8, Reg8),
    op!("JStrictEqualLong", Addr32, Reg8, Reg8),
    op!("JStrictNotEqual", Addr8, Reg8, Reg8),
    op!("JStrictNotEqualLong", Addr32, Reg8, Reg8),
];

#[rustfmt::skip]
pub(crate) const OPCODES_HBC96: &[OpcodeSpec] = &[
    op!("Unreachable"),
    op!("NewObjectWithBuffer", Reg8, UInt16, UInt16, UInt16, UInt16),
    op!("NewObjectWithBufferLong", Reg8, UInt16, UInt16, UInt32, UInt32),
    op!("NewObject", Reg8),
    op!("NewObjectWithParent", Reg8, Reg8),
    op!("NewArrayWithBuffer", Reg8, UInt16, UInt16, UInt16),
    op!("NewArrayWithBufferLong", Reg8, UInt16, UInt16, UInt32),
    op!("NewArray", Reg8, UInt16),
    op!("Mov", Reg8, Reg8),
    op!("MovLong", Reg32, Reg32),
    op!("Negate", Reg8, Reg8),
    op!("Not", Reg8, Reg8),
    op!("BitNot", Reg8, Reg8),
    op!("TypeOf", Reg8, Reg8),
    op!("Eq", Reg8, Reg8, Reg8),
    op!("StrictEq", Reg8, Reg8, Reg8),
    op!("Neq", Reg8, Reg8, Reg8),
    op!("StrictNeq", Reg8, Reg8, Reg8),
    op!("Less", Reg8, Reg8, Reg8),
    op!("LessEq", Reg8, Reg8, Reg8),
    op!("Greater", Reg8, Reg8, Reg8),
    op!("GreaterEq", Reg8, Reg8, Reg8),
    op!("Add", Reg8, Reg8, Reg8),
    op!("AddN", Reg8, Reg8, Reg8),
    op!("Mul", Reg8, Reg8, Reg8),
    op!("MulN", Reg8, Reg8, Reg8),
    op!("Div", Reg8, Reg8, Reg8),
    op!("DivN", Reg8, Reg8, Reg8),
    op!("Mod", Reg8, Reg8, Reg8),
    op!("Sub", Reg8, Reg8, Reg8),
    op!("SubN", Reg8, Reg8, Reg8),
    op!("LShift", Reg8, Reg8, Reg8),
    op!("RShift", Reg8, Reg8, Reg8),
    op!("URshift", Reg8, Reg8, Reg8),
    op!("BitAnd", Reg8, Reg8, Reg8),
    op!("BitXor", Reg8, Reg8, Reg8),
    op!("BitOr", Reg8, Reg8, Reg8),
    op!("Inc", Reg8, Reg8),
    op!("Dec", Reg8, Reg8),
    op!("InstanceOf", Reg8, Reg8, Reg8),
    op!("IsIn", Reg8, Reg8, Reg8),
    op!("GetEnvironment", Reg8, UInt8),
    op!("StoreToEnvironment", Reg8, UInt8, Reg8),
    op!("StoreToEnvironmentL", Reg8, UInt16, Reg8),
    op!("StoreNPToEnvironment", Reg8, UInt8, Reg8),
    op!("StoreNPToEnvironmentL", Reg8, UInt16, Reg8),
    op!("LoadFromEnvironment", Reg8, Reg8, UInt8),
    op!("LoadFromEnvironmentL", Reg8, Reg8, UInt16),
    op!("GetGlobalObject", Reg8),
    op!("GetNewTarget", Reg8),
    op!("CreateEnvironment", Reg8),
    op!("CreateInnerEnvironment", Reg8, Reg8, UInt32),
    op!("DeclareGlobalVar", StringId32),
    op!("ThrowIfHasRestrictedGlobalProperty", StringId32),
    op!("GetByIdShort", Reg8, Reg8, UInt8, StringId8),
    op!("GetById", Reg8, Reg8, UInt8, StringId16),
    op!("GetByIdLong", Reg8, Reg8, UInt8, StringId32),
    op!("TryGetById", Reg8, Reg8, UInt8, StringId16),
    op!("TryGetByIdLong", Reg8, Reg8, UInt8, StringId32),
    op!("PutById", Reg8, Reg8, UInt8, StringId16),
    op!("PutByIdLong", Reg8, Reg8, UInt8, StringId32),
    op!("TryPutById", Reg8, Reg8, UInt8, StringId16),
    op!("TryPutByIdLong", Reg8, Reg8, UInt8, StringId32),
    op!("PutNewOwnByIdShort", Reg8, Reg8, StringId8),
    op!("PutNewOwnById", Reg8, Reg8, StringId16),
    op!("PutNewOwnByIdLong", Reg8, Reg8, StringId32),
    op!("PutNewOwnNEById", Reg8, Reg8, StringId16),
    op!("PutNewOwnNEByIdLong", Reg8, Reg8, StringId32),
    op!("PutOwnByIndex", Reg8, Reg8, UInt8),
    op!("PutOwnByIndexL", Reg8, Reg8, UInt32),
    op!("PutOwnByVal", Reg8, Reg8, Reg8, UInt8),
    op!("DelById", Reg8, Reg8, StringId16),
    op!("DelByIdLong", Reg8, Reg8, StringId32),
    op!("GetByVal", Reg8, Reg8, Reg8),
    op!("PutByVal", Reg8, Reg8, Reg8),
    op!("DelByVal", Reg8, Reg8, Reg8),
    op!("PutOwnGetterSetterByVal", Reg8, Reg8, Reg8, Reg8, UInt8),
    op!("GetPNameList", Reg8, Reg8, Reg8, Reg8),
    op!("GetNextPName", Reg8, Reg8, Reg8, Reg8, Reg8),
    op!("Call", Reg8, Reg8, UInt8),
    op!("Construct", Reg8, Reg8, UInt8),
    op!("Call1", Reg8, Reg8, Reg8),
    op!("CallDirect", Reg8, UInt8, FunctionId16),
    op!("Call2", Reg8, Reg8, Reg8, Reg8),
    op!("Call3", Reg8, Reg8, Reg8, Reg8, Reg8),
    op!("Call4", Reg8, Reg8, Reg8, Reg8, Reg8, Reg8),
    op!("CallLong", Reg8, Reg8, UInt32),
    op!("ConstructLong", Reg8, Reg8, UInt32),
    op!("CallDirectLongIndex", Reg8, UInt8, FunctionId32),
    op!("CallBuiltin", Reg8, UInt8, UInt8),
    op!("CallBuiltinLong", Reg8, UInt8, UInt32),
    op!("GetBuiltinClosure", Reg8, UInt8),
    op!("Ret", Reg8),
    op!("Catch", Reg8),
    op!("DirectEval", Reg8, Reg8, UInt8),
    op!("Throw", Reg8),
    op!("ThrowIfEmpty", Reg8, Reg8),
    op!("Debugger"),
    op!("AsyncBreakCheck"),
    op!("ProfilePoint", UInt16),
    op!("CreateClosure", Reg8, Reg8, FunctionId16),
    op!("CreateClosureLongIndex", Reg8, Reg8, FunctionId32),
    op!("CreateGeneratorClosure", Reg8, Reg8, FunctionId16),
    op!("CreateGeneratorClosureLongIndex", Reg8, Reg8, FunctionId32),
    op!("CreateAsyncClosure", Reg8, Reg8, FunctionId16),
    op!("CreateAsyncClosureLongIndex", Reg8, Reg8, FunctionId32),
    op!("CreateThis", Reg8, Reg8, Reg8),
    op!("SelectObject", Reg8, Reg8, Reg8),
    op!("LoadParam", Reg8, UInt8),
    op!("LoadParamLong", Reg8, UInt32),
    op!("LoadConstUInt8", Reg8, UInt8),
    op!("LoadConstInt", Reg8, Imm32),
    op!("LoadConstDouble", Reg8, Double),
    op!("LoadConstBigInt", Reg8, BigIntId16),
    op!("LoadConstBigIntLongIndex", Reg8, BigIntId32),
    op!("LoadConstString", Reg8, StringId16),
    op!("LoadConstStringLongIndex", Reg8, StringId32),
    op!("LoadConstEmpty", Reg8),
    op!("LoadConstUndefined", Reg8),
    op!("LoadConstNull", Reg8),
    op!("LoadConstTrue", Reg8),
    op!("LoadConstFalse", Reg8),
    op!("LoadConstZero", Reg8),
    op!("CoerceThisNS", Reg8, Reg8),
    op!("LoadThisNS", Reg8),
    op!("ToNumber", Reg8, Reg8),
    op!("ToNumeric", Reg8, Reg8),
    op!("ToInt32", Reg8, Reg8),
    op!("AddEmptyString", Reg8, Reg8),
    op!("GetArgumentsPropByVal", Reg8, Reg8, Reg8),
    op!("GetArgumentsLength", Reg8, Reg8),
    op!("ReifyArguments", Reg8),
    op!("CreateRegExp", Reg8, StringId32, StringId32, UInt32),
    op!("SwitchImm", Reg8, UInt32, Addr32, UInt32, UInt32),
    op!("StartGenerator"),
    op!("ResumeGenerator", Reg8, Reg8),
    op!("CompleteGenerator"),
    op!("CreateGenerator", Reg8, Reg8, FunctionId16),
    op!("CreateGeneratorLongIndex", Reg8, Reg8, FunctionId32),
    op!("IteratorBegin", Reg8, Reg8),
    op!("IteratorNext", Reg8, Reg8, Reg8),
    op!("IteratorClose", Reg8, UInt8),
    op!("Jmp", Addr8),
    op!("JmpLong", Addr32),
    op!("JmpTrue", Addr8, Reg8),
    op!("JmpTrueLong", Addr32, Reg8),
    op!("JmpFalse", Addr8, Reg8),
    op!("JmpFalseLong", Addr32, Reg8),
    op!("JmpUndefined", Addr8, Reg8),
    op!("JmpUndefinedLong", Addr32, Reg8),
    op!("SaveGenerator", Addr8),
    op!("SaveGeneratorLong", Addr32),
    op!("JLess", Addr8, Reg8, Reg8),
    op!("JLessLong", Addr32, Reg8, Reg8),
    op!("JNotLess", Addr8, Reg8, Reg8),
    op!("JNotLessLong", Addr32, Reg8, Reg8),
    op!("JLessN", Addr8, Reg8, Reg8),
    op!("JLessNLong", Addr32, Reg8, Reg8),
    op!("JNotLessN", Addr8, Reg8, Reg8),
    op!("JNotLessNLong", Addr32, Reg8, Reg8),
    op!("JLessEqual", Addr8, Reg8, Reg8),
    op!("JLessEqualLong", Addr32, Reg8, Reg8),
    op!("JNotLessEqual", Addr8, Reg8, Reg8),
    op!("JNotLessEqualLong", Addr32, Reg8, Reg8),
    op!("JLessEqualN", Addr8, Reg8, Reg8),
    op!("JLessEqualNLong", Addr32, Reg8, Reg8),
    op!("JNotLessEqualN", Addr8, Reg8, Reg8),
    op!("JNotLessEqualNLong", Addr32, Reg8, Reg8),
    op!("JGreater", Addr8, Reg8, Reg8),
    op!("JGreaterLong", Addr32, Reg8, Reg8),
    op!("JNotGreater", Addr8, Reg8, Reg8),
    op!("JNotGreaterLong", Addr32, Reg8, Reg8),
    op!("JGreaterN", Addr8, Reg8, Reg8),
    op!("JGreaterNLong", Addr32, Reg8, Reg8),
    op!("JNotGreaterN", Addr8, Reg8, Reg8),
    op!("JNotGreaterNLong", Addr32, Reg8, Reg8),
    op!("JGreaterEqual", Addr8, Reg8, Reg8),
    op!("JGreaterEqualLong", Addr32, Reg8, Reg8),
    op!("JNotGreaterEqual", Addr8, Reg8, Reg8),
    op!("JNotGreaterEqualLong", Addr32, Reg8, Reg8),
    op!("JGreaterEqualN", Addr8, Reg8, Reg8),
    op!("JGreaterEqualNLong", Addr32, Reg8, Reg8),
    op!("JNotGreaterEqualN", Addr8, Reg8, Reg8),
    op!("JNotGreaterEqualNLong", Addr32, Reg8, Reg8),
    op!("JEqual", Addr8, Reg8, Reg8),
    op!("JEqualLong", Addr32, Reg8, Reg8),
    op!("JNotEqual", Addr8, Reg8, Reg8),
    op!("JNotEqualLong", Addr32, Reg8, Reg8),
    op!("JStrictEqual", Addr8, Reg8, Reg8),
    op!("JStrictEqualLong", Addr32, Reg8, Reg8),
    op!("JStrictNotEqual", Addr8, Reg8, Reg8),
    op!("JStrictNotEqualLong", Addr32, Reg8, Reg8),
];

pub(crate) const BYTECODE_TABLES: &[BytecodeTable] = &[
    BytecodeTable {
        version: 62,
        specs: OPCODES_HBC62,
        upstream_tag: "v0.2.1",
        graded_sample: "corpus/mobile/hermes/sample/sample.hbc.v62",
    },
    BytecodeTable {
        version: 71,
        specs: OPCODES_HBC62,
        upstream_tag: "v0.3.0",
        graded_sample: "corpus/mobile/hermes/sample/sample.hbc.v71",
    },
    BytecodeTable {
        version: 74,
        specs: OPCODES_HBC76,
        upstream_tag: "v0.4.0",
        graded_sample: "corpus/mobile/hermes/sample/sample.hbc.v74",
    },
    BytecodeTable {
        version: 76,
        specs: OPCODES_HBC76,
        upstream_tag: "v0.7.2",
        graded_sample: "corpus/mobile/hermes/sample/sample.hbc.v76",
    },
    BytecodeTable {
        version: 83,
        specs: OPCODES_HBC84,
        upstream_tag: "v0.8.0",
        graded_sample: "corpus/mobile/hermes/sample/sample.hbc.v83",
    },
    BytecodeTable {
        version: 84,
        specs: OPCODES_HBC84,
        upstream_tag: "v0.11.0",
        graded_sample: "corpus/mobile/hermes/sample/sample.hbc.v84",
    },
    BytecodeTable {
        version: 89,
        specs: OPCODES_HBC89,
        upstream_tag: "v0.12.0",
        graded_sample: "corpus/mobile/hermes/sample/sample.hbc.v89",
    },
    BytecodeTable {
        version: 96,
        specs: OPCODES_HBC96,
        upstream_tag: "v0.13.0",
        graded_sample: "corpus/mobile/hermes/sample/sample.hbc.v96",
    },
];

#[must_use]
pub(crate) fn bytecode_table(version: u32) -> Option<&'static BytecodeTable> {
    BYTECODE_TABLES
        .iter()
        .find(|table: &&BytecodeTable| table.version == version)
}

#[must_use]
pub(crate) fn opcode_specs(version: u32) -> Option<&'static [OpcodeSpec]> {
    bytecode_table(version).map(|table: &BytecodeTable| table.specs)
}

#[must_use]
pub(crate) fn opcode_label_in(specs: &[OpcodeSpec], opcode: u8) -> Cow<'static, str> {
    match specs.get(opcode as usize) {
        Some(spec) => Cow::Borrowed(spec.name),
        None => Cow::Owned(format!("Unknown_0x{opcode:02x}")),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::hermes::{HERMES_LIFT_VERSION, HERMES_LIFTED_VERSIONS};

    const OPCODES_THAT_CHANGED_ARITY_BEFORE_V96: [&str; 1] = ["DirectEval"];

    fn position(specs: &[OpcodeSpec], name: &str) -> Option<usize> {
        specs.iter().position(|spec: &OpcodeSpec| spec.name == name)
    }

    fn names(specs: &[OpcodeSpec], name: &str) -> bool {
        position(specs, name).is_some()
    }

    fn widths(spec: &OpcodeSpec) -> Vec<usize> {
        spec.operands
            .iter()
            .map(|operand: &Operand| operand.width())
            .collect()
    }

    #[test]
    fn every_table_is_indexable_by_a_single_opcode_byte() {
        for table in BYTECODE_TABLES {
            assert!(
                table.specs.len() <= 256,
                "hbc v{} carries {} opcodes, but a Hermes opcode is one byte, so a longer table \
                 holds entries no bytecode can name",
                table.version,
                table.specs.len()
            );
            assert!(
                !table.specs.is_empty(),
                "hbc v{} carries an empty opcode table, so every instruction at that version would \
                 decode as unknown while the version still reported a table",
                table.version
            );
        }
    }

    #[test]
    fn the_registry_holds_exactly_the_versions_whose_bodies_are_graded() {
        let registered: Vec<u32> = BYTECODE_TABLES
            .iter()
            .map(|table: &BytecodeTable| table.version)
            .collect();
        assert_eq!(
            registered,
            HERMES_LIFTED_VERSIONS.to_vec(),
            "a registered opcode table lifts bodies at its version, so the registry and the lifted \
             set are the same list; registering a version with no graded sample would emit \
             JavaScript that nothing measures"
        );
        assert!(
            registered.contains(&HERMES_LIFT_VERSION),
            "v{HERMES_LIFT_VERSION} is the reference version every published Hermes figure is \
             measured at, so it must carry a table"
        );
        let mut sorted: Vec<u32> = registered.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted, registered,
            "the registry is ascending and free of repeats, so a version cannot resolve to two \
             different opcode tables depending on scan order"
        );
    }

    #[test]
    fn each_table_reproduces_the_opcode_order_of_its_upstream_release() {
        let expected: [(u32, &str, usize, &str, &str); 8] = [
            (
                62,
                "v0.2.1",
                177,
                "NewObjectWithBuffer",
                "JStrictNotEqualLong",
            ),
            (
                71,
                "v0.3.0",
                177,
                "NewObjectWithBuffer",
                "JStrictNotEqualLong",
            ),
            (
                74,
                "v0.4.0",
                180,
                "NewObjectWithBuffer",
                "JStrictNotEqualLong",
            ),
            (
                76,
                "v0.7.2",
                180,
                "NewObjectWithBuffer",
                "JStrictNotEqualLong",
            ),
            (83, "v0.8.0", 185, "Unreachable", "JStrictNotEqualLong"),
            (84, "v0.11.0", 185, "Unreachable", "JStrictNotEqualLong"),
            (89, "v0.12.0", 190, "Unreachable", "JStrictNotEqualLong"),
            (96, "v0.13.0", 192, "Unreachable", "JStrictNotEqualLong"),
        ];
        for (version, tag, count, first, last) in expected {
            let table: &BytecodeTable = bytecode_table(version).unwrap_or_else(|| {
                panic!("hbc v{version} must carry a table for this shape check to grade anything")
            });
            assert_eq!(
                table.upstream_tag, tag,
                "the hbc v{version} opcode order is the expansion order of \
                 include/hermes/BCGen/HBC/BytecodeList.def at facebook/hermes tag {tag}, which is \
                 the release whose BYTECODE_VERSION is {version}"
            );
            assert_eq!(
                table.specs.len(),
                count,
                "BytecodeList.def at {tag} expands to {count} opcodes, so a table of a different \
                 length has lost or gained an entry and every opcode after the change decodes as a \
                 different instruction"
            );
            assert_eq!(
                table.specs.first().map(|spec: &OpcodeSpec| spec.name),
                Some(first),
                "opcode 0 anchors the whole table at hbc v{version}"
            );
            assert_eq!(
                table.specs.last().map(|spec: &OpcodeSpec| spec.name),
                Some(last),
                "the last opcode anchors the tail of the table at hbc v{version}"
            );
        }
    }

    #[test]
    fn the_version_deltas_upstream_recorded_are_present_in_the_tables() {
        let v62: &[OpcodeSpec] = opcode_specs(62).expect("hbc v62 table");
        let v71: &[OpcodeSpec] = opcode_specs(71).expect("hbc v71 table");
        let v74: &[OpcodeSpec] = opcode_specs(74).expect("hbc v74 table");
        let v76: &[OpcodeSpec] = opcode_specs(76).expect("hbc v76 table");
        let v83: &[OpcodeSpec] = opcode_specs(83).expect("hbc v83 table");
        let v84: &[OpcodeSpec] = opcode_specs(84).expect("hbc v84 table");
        let v89: &[OpcodeSpec] = opcode_specs(89).expect("hbc v89 table");
        let v96: &[OpcodeSpec] = opcode_specs(96).expect("hbc v96 table");

        assert!(
            names(v76, "ThrowIfUndefinedInst") && !names(v96, "ThrowIfUndefinedInst"),
            "ThrowIfUndefinedInst is replaced by ThrowIfEmpty at hbc v83, so a table that carries \
             it at v96 was copied from the wrong release"
        );
        for late in ["Inc", "Dec", "LoadConstBigInt", "ToNumeric"] {
            assert!(
                !names(v76, late) && !names(v84, late) && names(v89, late) && names(v96, late),
                "{late} arrives at hbc v89 with facebook/hermes tag v0.12.0, so finding it earlier \
                 means the older table was copied from a newer release"
            );
        }
        for latest in [
            "CreateInnerEnvironment",
            "ThrowIfHasRestrictedGlobalProperty",
        ] {
            assert!(
                !names(v89, latest) && names(v96, latest),
                "{latest} arrives at hbc v96, so a v89 table that carries it was copied from tag \
                 v0.13.0 rather than v0.12.0"
            );
        }
        for mid in ["LoadConstEmpty", "CallBuiltinLong", "CreateAsyncClosure"] {
            assert!(
                !names(v76, mid) && names(v83, mid) && names(v84, mid) && names(v96, mid),
                "{mid} arrives at hbc v83, so it must be absent at v76 and present from v83"
            );
        }
        for iterator in ["IteratorBegin", "IteratorNext", "IteratorClose"] {
            assert!(
                !names(v62, iterator) && !names(v71, iterator) && names(v74, iterator),
                "{iterator} arrives at hbc v74 with tag v0.4.0, and it is the whole difference \
                 between the 177-opcode and the 180-opcode list"
            );
        }
        assert_eq!(
            position(v62, "Jmp"),
            Some(127),
            "the three iterator opcodes sit between CreateGeneratorLongIndex and the jump block, so \
             their absence at hbc v62 shifts every jump opcode down by three from its v74 byte"
        );
        assert_eq!(position(v74, "Jmp"), Some(130));

        assert_eq!(
            position(v76, "Unreachable"),
            Some(93),
            "Unreachable sits at opcode 93 before hbc v83 and moves to opcode 0 at v83, so the \
             same instruction is a different byte at the two versions and one shared table would \
             misread every function that uses either"
        );
        assert_eq!(position(v62, "Unreachable"), Some(93));
        assert_eq!(position(v83, "Unreachable"), Some(0));
        assert_eq!(position(v84, "Unreachable"), Some(0));
        assert_eq!(position(v89, "Unreachable"), Some(0));
        assert_eq!(position(v96, "Unreachable"), Some(0));

        assert_ne!(
            v76.first().map(|spec: &OpcodeSpec| spec.name),
            v96.first().map(|spec: &OpcodeSpec| spec.name),
            "the whole point of a per-version table is that opcode 0 does not name the same \
             instruction at every version"
        );
    }

    #[test]
    fn two_versions_share_one_table_only_where_their_releases_ship_the_same_opcode_list() {
        const SHARED: [(u32, u32); 3] = [(62, 71), (74, 76), (83, 84)];
        for (earlier, later) in SHARED {
            let left: &[OpcodeSpec] = opcode_specs(earlier).expect("earlier table");
            let right: &[OpcodeSpec] = opcode_specs(later).expect("later table");
            assert_eq!(
                left, right,
                "hbc v{earlier} and v{later} are registered against one opcode list because \
                 BytecodeList.def is unchanged between their releases; forking one of them without \
                 forking the other would leave the two versions disagreeing about the same byte"
            );
            assert!(
                std::ptr::eq(left, right),
                "hbc v{earlier} and v{later} hold equal opcode lists, so they must point at one \
                 constant rather than two copies that can drift apart"
            );
        }

        let mut tags: Vec<&'static str> = BYTECODE_TABLES
            .iter()
            .map(|table: &BytecodeTable| table.upstream_tag)
            .collect();
        let registered: usize = tags.len();
        tags.sort_unstable();
        tags.dedup();
        assert_eq!(
            tags.len(),
            registered,
            "every registered version names the upstream release its list was read from, so two \
             versions must never claim the same tag"
        );

        let mut samples: Vec<&'static str> = BYTECODE_TABLES
            .iter()
            .map(|table: &BytecodeTable| table.graded_sample)
            .collect();
        samples.sort_unstable();
        samples.dedup();
        assert_eq!(
            samples.len(),
            registered,
            "each registered version is graded by a bundle compiled at that version, so two \
             versions pointing at one file would leave one of them measured by bytes it never \
             produced"
        );
        for table in BYTECODE_TABLES {
            assert!(
                table
                    .graded_sample
                    .ends_with(&format!("v{}", table.version)),
                "hbc v{} is registered against {}, which is not a sample at that version",
                table.version,
                table.graded_sample
            );
        }
    }

    #[test]
    fn every_operand_slot_a_lifter_reads_as_a_function_index_is_typed_as_one() {
        for table in BYTECODE_TABLES {
            for spec in table.specs {
                let function_indexed: bool = spec.operands.iter().any(|operand: &Operand| {
                    matches!(operand, Operand::FunctionId16 | Operand::FunctionId32)
                });
                let resolves_a_function: bool = spec.name.starts_with("CreateClosure")
                    || spec.name.starts_with("CreateGenerator")
                    || spec.name.starts_with("CreateAsyncClosure")
                    || spec.name.starts_with("CallDirect");
                assert_eq!(
                    function_indexed, resolves_a_function,
                    "hbc v{}: {} resolves a function through the function table, so its index \
                     operand is typed as a function id at every version. Older BytecodeList.def \
                     releases leave that operand untagged, and an untagged operand reaches the \
                     lifter as a plain integer, which silently drops the closure body",
                    table.version, spec.name
                );
            }
        }
    }

    #[test]
    fn a_big_int_index_is_typed_only_where_the_release_carries_big_ints() {
        for table in BYTECODE_TABLES {
            for spec in table.specs {
                let big_int_indexed: bool = spec.operands.iter().any(|operand: &Operand| {
                    matches!(operand, Operand::BigIntId16 | Operand::BigIntId32)
                });
                assert_eq!(
                    big_int_indexed,
                    spec.name.starts_with("LoadConstBigInt"),
                    "hbc v{}: {} carries a big-int index operand it should not, or lacks one it \
                     should",
                    table.version,
                    spec.name
                );
            }
        }
        let v76: &[OpcodeSpec] = opcode_specs(76).expect("hbc v76 table");
        assert!(
            !names(v76, "LoadConstBigInt") && !names(v76, "LoadConstBigIntLongIndex"),
            "hbc v76 predates big-int support, so a big-int load there would be an opcode that \
             release could never emit"
        );
    }

    #[test]
    fn an_operand_layout_changes_only_where_the_release_changed_the_instruction() {
        let mut changed: Vec<&str> = Vec::new();
        for table in BYTECODE_TABLES {
            for spec in table.specs {
                let Some(reference): Option<&OpcodeSpec> = OPCODES_HBC96
                    .iter()
                    .find(|candidate: &&OpcodeSpec| candidate.name == spec.name)
                else {
                    continue;
                };
                let here: Vec<usize> = widths(spec);
                let there: Vec<usize> = widths(reference);
                if here == there {
                    continue;
                }
                assert!(
                    OPCODES_THAT_CHANGED_ARITY_BEFORE_V96.contains(&spec.name),
                    "hbc v{}: {} decodes {:?} bytes of operands here and {:?} at v96. An opcode \
                     that keeps its name normally keeps its encoded width, so an unlisted mismatch \
                     means one of the two tables was transcribed wrong and every instruction after \
                     it in a function decodes at the wrong offset",
                    table.version,
                    spec.name,
                    here,
                    there
                );
                assert!(
                    here.len() < there.len() && here[..] == there[..here.len()],
                    "hbc v{}: {} is recorded as an instruction that gained an operand, so its \
                     older layout must be a prefix of the newer one; got {:?} against {:?}",
                    table.version,
                    spec.name,
                    here,
                    there
                );
                changed.push(spec.name);
            }
        }
        changed.sort_unstable();
        changed.dedup();
        assert_eq!(
            changed,
            OPCODES_THAT_CHANGED_ARITY_BEFORE_V96.to_vec(),
            "the set of instructions whose operand list changed between the graded releases is \
             pinned by equality; DirectEval gains its strict-caller flag at hbc v96 and no other \
             shared opcode changes shape. An empty result here would mean the tables are identical \
             and this check compares nothing"
        );
    }

    #[test]
    fn an_unknown_opcode_byte_is_named_by_its_byte_rather_than_guessed() {
        let v76: &[OpcodeSpec] = opcode_specs(76).expect("hbc v76 table");
        let beyond: u8 = u8::try_from(v76.len()).expect("the table is shorter than 256 entries");
        assert_eq!(opcode_label_in(v76, beyond), "Unknown_0xb4");
        assert_eq!(opcode_label_in(v76, 0), "NewObjectWithBuffer");
        assert_eq!(opcode_label_in(OPCODES_HBC96, 0), "Unreachable");
    }

    #[test]
    fn a_version_with_no_table_resolves_to_no_table_rather_than_the_nearest_one() {
        for absent in [
            0u32,
            59,
            60,
            61,
            63,
            70,
            72,
            75,
            77,
            82,
            85,
            88,
            90,
            95,
            97,
            u32::MAX,
        ] {
            assert!(
                bytecode_table(absent).is_none(),
                "hbc v{absent} has no committed sample, so it must resolve to no opcode table; \
                 falling back to a neighbouring table decodes its bytes as different instructions \
                 and reports the result as recovered JavaScript"
            );
            assert!(opcode_specs(absent).is_none(), "hbc v{absent}");
        }
    }
}
