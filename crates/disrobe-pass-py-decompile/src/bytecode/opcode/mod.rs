pub mod pypy;
pub mod pypy_extras;
pub mod v1_0;
pub mod v1_1;
pub mod v1_3;
pub mod v1_4;
pub mod v1_5;
pub mod v1_6;
pub mod v2_0;
pub mod v2_1;
pub mod v2_2;
pub mod v2_3;
pub mod v2_4;
pub mod v2_5;
pub mod v2_6;
pub mod v2_7;
pub mod v3_0;
pub mod v3_1;
pub mod v3_10;
pub mod v3_11;
pub mod v3_12;
pub mod v3_13;
pub mod v3_14;
pub mod v3_15;
pub mod v3_2;
pub mod v3_3;
pub mod v3_4;
pub mod v3_5;
pub mod v3_6;
pub mod v3_7;
pub mod v3_8;
pub mod v3_9;

use crate::bytecode::version::PyVersion;
use disrobe_py_marshal::PyVersion as MarshalVersion;
use std::fmt::Debug;

pub type StackSlot = u32;
pub type ConstIndex = u32;
pub type NameIndex = u32;
pub type LocalIndex = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    MatMul,
    TrueDiv,
    FloorDiv,
    Mod,
    Pow,
    Lshift,
    Rshift,
    BitAnd,
    BitOr,
    BitXor,
    InplaceAdd,
    InplaceSub,
    InplaceMul,
    InplaceMatMul,
    InplaceTrueDiv,
    InplaceFloorDiv,
    InplaceMod,
    InplacePow,
    InplaceLshift,
    InplaceRshift,
    InplaceBitAnd,
    InplaceBitOr,
    InplaceBitXor,
    OldDivide,
    InplaceOldDivide,
    Generic(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnaryOp {
    Positive,
    Negative,
    Not,
    Invert,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CmpOp {
    Lt,
    Le,
    Eq,
    Ne,
    Gt,
    Ge,
    In,
    NotIn,
    Is,
    IsNot,
    ExcMatch,
    BadEq,
    Generic(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JumpKind {
    None,
    Relative,
    Absolute,
    Backward,
    BackwardNoInterrupt,
    ForIter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpcodeFamily {
    Load,
    Store,
    Delete,
    Call,
    BuildCollection,
    Jump,
    Compare,
    Await,
    Match,
    ExceptionHandling,
    Misc,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CanonicalOp {
    Nop,
    Pop,
    DiscardTop,
    Dup,
    Push(StackSlot),
    LoadConst(ConstIndex),
    LoadName(NameIndex),
    LoadFast(LocalIndex),
    StoreName(NameIndex),
    StoreFast(LocalIndex),
    StoreAnnotation(NameIndex),
    LoadGlobal(NameIndex),
    StoreGlobal(NameIndex),
    LoadAttr(NameIndex),
    StoreAttr(NameIndex),
    ImportName(NameIndex),
    ImportFrom(NameIndex),
    ImportStar,
    LoadBuildClass,
    LoadAssertionError,
    LoadSubscr,
    StoreSubscr,
    BinaryOp(BinOp),
    UnaryOp(UnaryOp),
    Compare(CmpOp),
    JumpForward(i32),
    JumpAbsolute(u32),
    PopJumpIfFalse(u32),
    PopJumpIfTrue(u32),
    JumpIfTrueOrPop(u32),
    JumpIfFalseOrPop(u32),
    JumpBackward(u32),
    JumpBackwardNoInterrupt(u32),
    Return,
    ReturnConst(ConstIndex),
    CallFunction(u8),
    CallFunctionKw(u8),
    CallFunctionEx(bool),
    MakeFunction(u8),
    MakeCell(LocalIndex),
    BuildList(u32),
    BuildTuple(u32),
    BuildSet(u32),
    BuildMap(u32),
    BuildString(u32),
    BuildSlice(u8),
    ListAppend,
    SetAdd,
    MapAdd,
    FormatValue(u8),
    ConvertValue(u8),
    GetIter,
    GetAiter,
    GetAnext,
    EndAsyncFor,
    ForIter(u32),
    Send(u32),
    EndSend,
    Resume(u8),
    Yield,
    YieldFrom,
    ReturnGenerator,
    BeforeAsyncWith,
    SetupAsyncWith,
    AsyncForLoop,
    AsyncWithExitStart,
    AsyncWithExitFinish,
    Raise(u8),
    Reraise(u8),
    PushExcInfo,
    PopExcept,
    CheckExcMatch,
    CheckEgMatch,
    CleanupThrow,
    WithExceptStart,
    BeforeWith,
    MatchClass(u8),
    MatchMapping,
    MatchSequence,
    MatchKeys,
    GetLen,
    Copy(u8),
    Swap(u8),
    ToBool,
    LoadFastLoadFast(LocalIndex, LocalIndex),
    StoreFastLoadFast(LocalIndex, LocalIndex),
    StoreFastStoreFast(LocalIndex, LocalIndex),
    Cache,
    ExtendedArg(u8),
    Specialized(u16),
    Other(u8, u8),
}

pub trait OpcodeMap: Debug + Send + Sync {
    fn version(&self) -> PyVersion;
    fn decode(&self, raw: u8, arg: u32) -> CanonicalOp;
    fn cache_size(&self, op: u8) -> u8;
    fn has_arg(&self) -> u8;
    fn opname(&self, op: u8) -> &'static str;
    fn jump_kind(&self, op: u8) -> JumpKind;
    fn family(&self, op: u8) -> OpcodeFamily;
}

#[must_use]
pub fn map_for(version: PyVersion) -> Box<dyn OpcodeMap> {
    match version {
        PyVersion::V1_0 => Box::new(v1_0::V10OpcodeMap),
        PyVersion::V1_1 => Box::new(v1_1::V11OpcodeMap),
        PyVersion::V1_3 => Box::new(v1_3::V13OpcodeMap),
        PyVersion::V1_4 => Box::new(v1_4::V14OpcodeMap),
        PyVersion::V1_5 => Box::new(v1_5::V15OpcodeMap),
        PyVersion::V1_6 => Box::new(v1_6::V16OpcodeMap),
        PyVersion::V2_0 => Box::new(v2_0::V20OpcodeMap),
        PyVersion::V2_1 => Box::new(v2_1::V21OpcodeMap),
        PyVersion::V2_2 => Box::new(v2_2::V22OpcodeMap),
        PyVersion::V2_3 => Box::new(v2_3::V23OpcodeMap),
        PyVersion::V2_4 => Box::new(v2_4::V24OpcodeMap),
        PyVersion::V2_5 => Box::new(v2_5::V25OpcodeMap),
        PyVersion::V2_6 => Box::new(v2_6::V26OpcodeMap),
        PyVersion::V2_7 => Box::new(v2_7::V27OpcodeMap),
        PyVersion::V3_0 => Box::new(v3_0::V30OpcodeMap),
        PyVersion::V3_1 => Box::new(v3_1::V31OpcodeMap),
        PyVersion::V3_2 => Box::new(v3_2::V32OpcodeMap),
        PyVersion::V3_3 => Box::new(v3_3::V33OpcodeMap),
        PyVersion::V3_4 => Box::new(v3_4::V34OpcodeMap),
        PyVersion::V3_5 => Box::new(v3_5::V35OpcodeMap),
        PyVersion::V3_6 => Box::new(v3_6::V36OpcodeMap),
        PyVersion::V3_7 => Box::new(v3_7::V37OpcodeMap),
        PyVersion::V3_8 => Box::new(v3_8::V38OpcodeMap),
        PyVersion::V3_9 => Box::new(v3_9::V39OpcodeMap),
        PyVersion::V3_10 => Box::new(v3_10::V310OpcodeMap),
        PyVersion::V3_11 => Box::new(v3_11::V311OpcodeMap),
        PyVersion::V3_12 => Box::new(v3_12::V312OpcodeMap),
        PyVersion::V3_13 => Box::new(v3_13::V313OpcodeMap),
        PyVersion::V3_14 => Box::new(v3_14::V314OpcodeMap),
        PyVersion::V3_15 => Box::new(v3_15::V315OpcodeMap),
        PyVersion::PyPy(inner) => Box::new(pypy::PyPyOpcodeMap {
            base: map_for(*inner),
        }),
    }
}

#[must_use]
pub fn shared_marshal_version(version: &PyVersion) -> MarshalVersion {
    let (maj, min): (u8, u8) = (version.major(), version.minor());
    match (maj, min) {
        (1, _) | (2, 0..=6) => MarshalVersion::PY27,
        (3, 15) => MarshalVersion::PY314,
        _ => MarshalVersion {
            major: maj,
            minor: min,
        },
    }
}

#[must_use]
pub fn shared_opname(version: &PyVersion, op: u8) -> &'static str {
    disrobe_pass_py_disasm::opname(op, shared_marshal_version(version))
}

#[must_use]
pub fn shared_has_arg(version: &PyVersion) -> u8 {
    let (maj, min): (u8, u8) = (version.major(), version.minor());
    match (maj, min) {
        (1 | 2, _) | (3, 0..=5) => 90,
        (3, 13) => 44,
        (3, 14 | 15) => 43,
        _ => 0,
    }
}

#[must_use]
pub fn shared_cache_size(version: &PyVersion, op: u8) -> u8 {
    disrobe_pass_py_disasm::cache_size(op, shared_marshal_version(version))
}

#[must_use]
pub fn shared_decode(version: &PyVersion, raw: u8, arg: u32) -> CanonicalOp {
    let name: &'static str = shared_opname(version, raw);
    decode_by_name(name, raw, arg)
}

#[allow(
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    clippy::match_same_arms
)]
fn decode_by_name(name: &'static str, raw: u8, arg: u32) -> CanonicalOp {
    if is_specialized_name(name) {
        return CanonicalOp::Specialized(u16::from(raw));
    }
    let arg_lo: u8 = u8::try_from(arg & 0xFF).unwrap_or(0);
    match name {
        "NOP" | "STOP_CODE" => CanonicalOp::Nop,
        "POP_TOP" => CanonicalOp::Pop,
        "DUP_TOP" | "DUP_TOP_TWO" | "DUP_TOPX" => CanonicalOp::Dup,
        "PUSH_NULL" => CanonicalOp::Push(0),
        "LOAD_CONST" => CanonicalOp::LoadConst(arg),
        "LOAD_NAME" => CanonicalOp::LoadName(arg),
        "LOAD_FAST" | "LOAD_FAST_CHECK" | "LOAD_FAST_AND_CLEAR" | "LOAD_FAST_BORROW" => {
            CanonicalOp::LoadFast(arg)
        }
        "STORE_FAST" => CanonicalOp::StoreFast(arg),
        "LOAD_GLOBAL" => CanonicalOp::LoadGlobal(arg),
        "STORE_GLOBAL" => CanonicalOp::StoreGlobal(arg),
        "LOAD_ATTR" | "LOAD_METHOD" => CanonicalOp::LoadAttr(arg),
        "STORE_ATTR" => CanonicalOp::StoreAttr(arg),
        "BINARY_SUBSCR" => CanonicalOp::LoadSubscr,
        "STORE_SUBSCR" => CanonicalOp::StoreSubscr,
        "BINARY_ADD" => CanonicalOp::BinaryOp(BinOp::Add),
        "BINARY_SUBTRACT" => CanonicalOp::BinaryOp(BinOp::Sub),
        "BINARY_MULTIPLY" => CanonicalOp::BinaryOp(BinOp::Mul),
        "BINARY_MATRIX_MULTIPLY" => CanonicalOp::BinaryOp(BinOp::MatMul),
        "BINARY_TRUE_DIVIDE" => CanonicalOp::BinaryOp(BinOp::TrueDiv),
        "BINARY_FLOOR_DIVIDE" => CanonicalOp::BinaryOp(BinOp::FloorDiv),
        "BINARY_MODULO" => CanonicalOp::BinaryOp(BinOp::Mod),
        "BINARY_POWER" => CanonicalOp::BinaryOp(BinOp::Pow),
        "BINARY_LSHIFT" => CanonicalOp::BinaryOp(BinOp::Lshift),
        "BINARY_RSHIFT" => CanonicalOp::BinaryOp(BinOp::Rshift),
        "BINARY_AND" => CanonicalOp::BinaryOp(BinOp::BitAnd),
        "BINARY_OR" => CanonicalOp::BinaryOp(BinOp::BitOr),
        "BINARY_XOR" => CanonicalOp::BinaryOp(BinOp::BitXor),
        "BINARY_DIVIDE" => CanonicalOp::BinaryOp(BinOp::OldDivide),
        "INPLACE_ADD" => CanonicalOp::BinaryOp(BinOp::InplaceAdd),
        "INPLACE_SUBTRACT" => CanonicalOp::BinaryOp(BinOp::InplaceSub),
        "INPLACE_MULTIPLY" => CanonicalOp::BinaryOp(BinOp::InplaceMul),
        "INPLACE_MATRIX_MULTIPLY" => CanonicalOp::BinaryOp(BinOp::InplaceMatMul),
        "INPLACE_TRUE_DIVIDE" => CanonicalOp::BinaryOp(BinOp::InplaceTrueDiv),
        "INPLACE_FLOOR_DIVIDE" => CanonicalOp::BinaryOp(BinOp::InplaceFloorDiv),
        "INPLACE_MODULO" => CanonicalOp::BinaryOp(BinOp::InplaceMod),
        "INPLACE_POWER" => CanonicalOp::BinaryOp(BinOp::InplacePow),
        "INPLACE_LSHIFT" => CanonicalOp::BinaryOp(BinOp::InplaceLshift),
        "INPLACE_RSHIFT" => CanonicalOp::BinaryOp(BinOp::InplaceRshift),
        "INPLACE_AND" => CanonicalOp::BinaryOp(BinOp::InplaceBitAnd),
        "INPLACE_OR" => CanonicalOp::BinaryOp(BinOp::InplaceBitOr),
        "INPLACE_XOR" => CanonicalOp::BinaryOp(BinOp::InplaceBitXor),
        "INPLACE_DIVIDE" => CanonicalOp::BinaryOp(BinOp::InplaceOldDivide),
        "BINARY_OP" => {
            if arg_lo == 26 {
                CanonicalOp::LoadSubscr
            } else {
                CanonicalOp::BinaryOp(binary_op_from_nb(arg_lo))
            }
        }
        "UNARY_POSITIVE" => CanonicalOp::UnaryOp(UnaryOp::Positive),
        "UNARY_NEGATIVE" => CanonicalOp::UnaryOp(UnaryOp::Negative),
        "UNARY_NOT" => CanonicalOp::UnaryOp(UnaryOp::Not),
        "UNARY_INVERT" => CanonicalOp::UnaryOp(UnaryOp::Invert),
        "COMPARE_OP" => CanonicalOp::Compare(cmp_from_arg(arg)),
        "CONTAINS_OP" => CanonicalOp::Compare(if arg & 1 == 1 {
            CmpOp::NotIn
        } else {
            CmpOp::In
        }),
        "IS_OP" => CanonicalOp::Compare(if arg & 1 == 1 {
            CmpOp::IsNot
        } else {
            CmpOp::Is
        }),
        "JUMP_FORWARD" => CanonicalOp::JumpForward(i32::try_from(arg).unwrap_or(i32::MAX)),
        "JUMP_ABSOLUTE" | "JUMP" => CanonicalOp::JumpAbsolute(arg),
        "POP_JUMP_IF_FALSE"
        | "POP_JUMP_FORWARD_IF_FALSE"
        | "POP_JUMP_BACKWARD_IF_FALSE"
        | "POP_JUMP_IF_NONE"
        | "POP_JUMP_FORWARD_IF_NONE"
        | "POP_JUMP_BACKWARD_IF_NONE" => CanonicalOp::PopJumpIfFalse(arg),
        "POP_JUMP_IF_TRUE"
        | "POP_JUMP_FORWARD_IF_TRUE"
        | "POP_JUMP_BACKWARD_IF_TRUE"
        | "POP_JUMP_IF_NOT_NONE"
        | "POP_JUMP_FORWARD_IF_NOT_NONE"
        | "POP_JUMP_BACKWARD_IF_NOT_NONE" => CanonicalOp::PopJumpIfTrue(arg),
        "JUMP_IF_TRUE_OR_POP" => CanonicalOp::JumpIfTrueOrPop(arg),
        "JUMP_IF_FALSE_OR_POP" => CanonicalOp::JumpIfFalseOrPop(arg),
        "JUMP_BACKWARD" => CanonicalOp::JumpBackward(arg),
        "JUMP_BACKWARD_NO_INTERRUPT" => CanonicalOp::JumpBackwardNoInterrupt(arg),
        "RETURN_VALUE" => CanonicalOp::Return,
        "RETURN_CONST" => CanonicalOp::ReturnConst(arg),
        "CALL_FUNCTION" | "CALL" => CanonicalOp::CallFunction(arg_lo),
        "CALL_FUNCTION_KW" | "CALL_KW" => CanonicalOp::CallFunctionKw(arg_lo),
        "CALL_FUNCTION_EX" => CanonicalOp::CallFunctionEx(arg & 1 == 1),
        "MAKE_FUNCTION" => CanonicalOp::MakeFunction(arg_lo),
        "MAKE_CELL" => CanonicalOp::MakeCell(arg),
        "BUILD_LIST" => CanonicalOp::BuildList(arg),
        "BUILD_TUPLE" => CanonicalOp::BuildTuple(arg),
        "BUILD_SET" => CanonicalOp::BuildSet(arg),
        "BUILD_MAP" | "BUILD_CONST_KEY_MAP" => CanonicalOp::BuildMap(arg),
        "BUILD_STRING" => CanonicalOp::BuildString(arg),
        "BUILD_SLICE" => CanonicalOp::BuildSlice(arg_lo),
        "LIST_APPEND" => CanonicalOp::ListAppend,
        "SET_ADD" => CanonicalOp::SetAdd,
        "MAP_ADD" => CanonicalOp::MapAdd,
        "FORMAT_VALUE" | "FORMAT_SIMPLE" | "FORMAT_WITH_SPEC" => CanonicalOp::FormatValue(arg_lo),
        "CONVERT_VALUE" => CanonicalOp::ConvertValue(arg_lo),
        "GET_ITER" => CanonicalOp::GetIter,
        "GET_AITER" => CanonicalOp::GetAiter,
        "GET_ANEXT" => CanonicalOp::GetAnext,
        "END_ASYNC_FOR" => CanonicalOp::EndAsyncFor,
        "FOR_ITER" => CanonicalOp::ForIter(arg),
        "SEND" => CanonicalOp::Send(arg),
        "END_SEND" => CanonicalOp::EndSend,
        "RESUME" => CanonicalOp::Resume(arg_lo),
        "YIELD_VALUE" => CanonicalOp::Yield,
        "YIELD_FROM" => CanonicalOp::YieldFrom,
        "RETURN_GENERATOR" => CanonicalOp::ReturnGenerator,
        "BEFORE_ASYNC_WITH" => CanonicalOp::BeforeAsyncWith,
        "SETUP_ASYNC_WITH" => CanonicalOp::SetupAsyncWith,
        "GET_AWAITABLE" => CanonicalOp::AsyncForLoop,
        "ASYNC_GEN_WRAP" => CanonicalOp::AsyncWithExitStart,
        "INTERPRETER_EXIT" => CanonicalOp::Nop,
        "END_FOR" => CanonicalOp::Pop,
        "ROT_TWO" | "ROT_THREE" | "ROT_FOUR" | "ROT_N" => CanonicalOp::Swap(arg_lo.max(2)),
        "LOAD_DEREF" | "LOAD_CLASSDEREF" | "LOAD_CLOSURE" => CanonicalOp::LoadFast(arg),
        "STORE_DEREF" => CanonicalOp::StoreFast(arg),
        "DELETE_FAST" | "DELETE_DEREF" | "DELETE_NAME" | "DELETE_GLOBAL" | "DELETE_ATTR"
        | "DELETE_SUBSCR" => CanonicalOp::Pop,
        "STORE_NAME" => CanonicalOp::StoreName(arg),
        "PRINT_EXPR" | "PRINT_ITEM" | "PRINT_ITEM_TO" | "PRINT_NEWLINE" | "PRINT_NEWLINE_TO"
        | "EXEC_STMT" | "PRINT_TOS" => CanonicalOp::Pop,
        "LOAD_BUILD_CLASS" => CanonicalOp::LoadBuildClass,
        "LOAD_ASSERTION_ERROR" => CanonicalOp::LoadAssertionError,
        "LOAD_LOCALS" | "LOAD_LOCAL" | "LOAD_COMMON_CONSTANT" => CanonicalOp::Push(0),
        "BUILD_CLASS"
        | "BUILD_FUNCTION"
        | "BUILD_TUPLE_UNPACK"
        | "BUILD_TUPLE_UNPACK_WITH_CALL"
        | "BUILD_LIST_UNPACK"
        | "BUILD_SET_UNPACK"
        | "BUILD_MAP_UNPACK"
        | "BUILD_MAP_UNPACK_WITH_CALL" => CanonicalOp::BuildTuple(arg),
        "MAKE_CLOSURE" => CanonicalOp::MakeFunction(arg_lo),
        "IMPORT_NAME" => CanonicalOp::ImportName(arg),
        "IMPORT_FROM" => CanonicalOp::ImportFrom(arg),
        "IMPORT_STAR" => CanonicalOp::ImportStar,
        "SETUP_LOOP"
        | "SETUP_EXCEPT"
        | "SETUP_FINALLY"
        | "SETUP_WITH"
        | "POP_BLOCK"
        | "POP_FINALLY"
        | "POP_TRY_BLOCK"
        | "BEGIN_FINALLY"
        | "END_FINALLY"
        | "CALL_FINALLY"
        | "WITH_CLEANUP_START"
        | "WITH_CLEANUP_FINISH"
        | "WITH_CLEANUP"
        | "BREAK_LOOP"
        | "CONTINUE_LOOP" => CanonicalOp::Nop,
        "UNPACK_SEQUENCE" | "UNPACK_EX" | "UNPACK_TUPLE" | "UNPACK_LIST" | "UNPACK_ARG"
        | "UNPACK_VARARG" => CanonicalOp::BuildTuple(arg),
        "STORE_SLICE" | "STORE_SLICE+0" | "STORE_SLICE+1" | "STORE_SLICE+2" | "STORE_SLICE+3"
        | "DELETE_SLICE" | "DELETE_SLICE+0" | "DELETE_SLICE+1" | "DELETE_SLICE+2"
        | "DELETE_SLICE+3" | "SLICE" | "SLICE+0" | "SLICE+1" | "SLICE+2" | "SLICE+3"
        | "SLICE_2" | "SLICE_3" => CanonicalOp::StoreSubscr,
        "BUILD_LIST_FROM_ARG" => CanonicalOp::BuildList(arg),
        "JUMP_IF_NOT_DEBUG" => CanonicalOp::JumpForward(i32::try_from(arg).unwrap_or(0)),
        "LOOKUP_METHOD" => CanonicalOp::LoadAttr(arg),
        "CALL_METHOD" => CanonicalOp::CallFunction(arg_lo),
        "CALL_METHOD_KW" => CanonicalOp::CallFunctionKw(arg_lo),
        "LOAD_REVDB_VAR" => CanonicalOp::LoadName(arg),
        "GET_YIELD_FROM_ITER" => CanonicalOp::GetIter,
        "LIST_TO_TUPLE" => CanonicalOp::BuildTuple(arg),
        "LIST_EXTEND" | "SET_UPDATE" | "DICT_MERGE" | "DICT_UPDATE" | "MAP_EXTEND" => {
            CanonicalOp::Nop
        }
        "KW_NAMES" => CanonicalOp::LoadConst(arg),
        "PRECALL" => CanonicalOp::Nop,
        "SET_FUNCTION_ATTRIBUTE" => CanonicalOp::DiscardTop,
        "COPY_FREE_VARS" | "COPY_DICT_WITHOUT_KEYS" => CanonicalOp::Nop,
        "LIST_TO_TUPLE_EX" => CanonicalOp::BuildTuple(arg),
        "SETUP_ANNOTATIONS" => CanonicalOp::Nop,
        "STORE_ANNOTATION" => CanonicalOp::StoreAnnotation(arg),
        "GET_LEN_NEXT" => CanonicalOp::GetLen,
        "BUILD_TSTRING" => CanonicalOp::BuildString(arg),
        "RETURN_VALUE_FROM_CACHE" => CanonicalOp::Return,
        "BINARY_SLICE" => CanonicalOp::LoadSubscr,
        "STORE_SLICE_NEW" => CanonicalOp::StoreSubscr,
        "RAISE" | "RAISE_2" | "RAISE_3" => CanonicalOp::Raise(arg_lo),
        "GLOBAL_DECL" | "NONLOCAL_DECL" => CanonicalOp::Nop,
        "LIST_APPEND_NEW" => CanonicalOp::ListAppend,
        "FORMAT_STRING" => CanonicalOp::BuildString(arg),
        "STORE_LOCAL" => CanonicalOp::StoreFast(arg),
        "RESERVE_FAST" | "RESERVE_STACK" => CanonicalOp::Nop,
        "UNARY_CONVERT" => CanonicalOp::UnaryOp(UnaryOp::Not),
        "UNARY_CALL" => CanonicalOp::CallFunction(0),
        "BINARY_CALL" => CanonicalOp::CallFunction(1),
        "BINARY_DIVMOD" => CanonicalOp::BinaryOp(BinOp::OldDivide),
        "PRINT_NEWLINE_LIST" | "PRINT_NEWLINE_TO_LIST" => CanonicalOp::Pop,
        "STORE_TRY_BLOCK" | "STORE_BLOCK" => CanonicalOp::Nop,
        "LOAD_FRAME_RANGE" => CanonicalOp::Push(0),
        "INSTRUMENTED_RESUME"
        | "INSTRUMENTED_CALL"
        | "INSTRUMENTED_RETURN_VALUE"
        | "INSTRUMENTED_YIELD_VALUE"
        | "INSTRUMENTED_CALL_FUNCTION_EX"
        | "INSTRUMENTED_CALL_KW"
        | "INSTRUMENTED_JUMP_FORWARD"
        | "INSTRUMENTED_JUMP_BACKWARD"
        | "INSTRUMENTED_POP_JUMP_IF_FALSE"
        | "INSTRUMENTED_POP_JUMP_IF_TRUE"
        | "INSTRUMENTED_POP_JUMP_IF_NONE"
        | "INSTRUMENTED_POP_JUMP_IF_NOT_NONE"
        | "INSTRUMENTED_FOR_ITER"
        | "INSTRUMENTED_LOAD_SUPER_ATTR"
        | "INSTRUMENTED_END_FOR"
        | "INSTRUMENTED_END_SEND"
        | "INSTRUMENTED_RETURN_CONST"
        | "INSTRUMENTED_INSTRUCTION"
        | "INSTRUMENTED_LINE" => CanonicalOp::Specialized(u16::from(raw)),
        "RESERVED" | "ENTER_EXECUTOR" | "JUMP_BACKWARD_NO_JIT" => {
            CanonicalOp::Specialized(u16::from(raw))
        }
        "RAISE_VARARGS" => CanonicalOp::Raise(arg_lo),
        "RERAISE" => CanonicalOp::Reraise(arg_lo),
        "PUSH_EXC_INFO" => CanonicalOp::PushExcInfo,
        "POP_EXCEPT" => CanonicalOp::PopExcept,
        "CHECK_EXC_MATCH" => CanonicalOp::CheckExcMatch,
        "CHECK_EG_MATCH" => CanonicalOp::CheckEgMatch,
        "CLEANUP_THROW" => CanonicalOp::CleanupThrow,
        "WITH_EXCEPT_START" => CanonicalOp::WithExceptStart,
        "BEFORE_WITH" => CanonicalOp::BeforeWith,
        "MATCH_CLASS" => CanonicalOp::MatchClass(arg_lo),
        "MATCH_MAPPING" => CanonicalOp::MatchMapping,
        "MATCH_SEQUENCE" => CanonicalOp::MatchSequence,
        "MATCH_KEYS" => CanonicalOp::MatchKeys,
        "GET_LEN" => CanonicalOp::GetLen,
        "COPY" => CanonicalOp::Copy(arg_lo),
        "SWAP" => CanonicalOp::Swap(arg_lo),
        "TO_BOOL" => CanonicalOp::ToBool,
        "LOAD_FAST_LOAD_FAST" => CanonicalOp::LoadFastLoadFast(arg >> 4, arg & 0xF),
        "STORE_FAST_LOAD_FAST" => CanonicalOp::StoreFastLoadFast(arg >> 4, arg & 0xF),
        "STORE_FAST_STORE_FAST" => CanonicalOp::StoreFastStoreFast(arg >> 4, arg & 0xF),
        "CACHE" => CanonicalOp::Cache,
        "EXTENDED_ARG" => CanonicalOp::ExtendedArg(arg_lo),
        _ => CanonicalOp::Other(raw, arg_lo),
    }
}

fn is_specialized_name(name: &'static str) -> bool {
    if name.ends_with("_ADAPTIVE")
        || name.ends_with("_QUICK")
        || name.contains("__")
        || name.starts_with("LOAD_FAST__")
        || name.starts_with("STORE_FAST__")
        || name.contains("_JUMP") && (name.starts_with("COMPARE_OP_") || name.starts_with("CHECK_"))
    {
        return true;
    }
    matches!(
        name,
        "BINARY_OP_ADD_INT"
            | "BINARY_OP_ADD_FLOAT"
            | "BINARY_OP_ADD_UNICODE"
            | "BINARY_OP_INPLACE_ADD_UNICODE"
            | "BINARY_OP_MULTIPLY_INT"
            | "BINARY_OP_MULTIPLY_FLOAT"
            | "BINARY_OP_SUBTRACT_INT"
            | "BINARY_OP_SUBTRACT_FLOAT"
            | "BINARY_OP_EXTEND"
            | "BINARY_SUBSCR_DICT"
            | "BINARY_SUBSCR_GETITEM"
            | "BINARY_SUBSCR_LIST_INT"
            | "BINARY_SUBSCR_TUPLE_INT"
            | "BINARY_SUBSCR_STR_INT"
            | "STORE_SUBSCR_DICT"
            | "STORE_SUBSCR_LIST_INT"
            | "CALL_PY_EXACT_ARGS"
            | "CALL_PY_WITH_DEFAULTS"
            | "CALL_PY_GENERAL"
            | "CALL_BOUND_METHOD_EXACT_ARGS"
            | "CALL_BOUND_METHOD_GENERAL"
            | "CALL_BUILTIN_CLASS"
            | "CALL_BUILTIN_FAST"
            | "CALL_BUILTIN_FAST_WITH_KEYWORDS"
            | "CALL_BUILTIN_O"
            | "CALL_LIST_APPEND"
            | "CALL_METHOD_DESCRIPTOR_FAST"
            | "CALL_METHOD_DESCRIPTOR_FAST_WITH_KEYWORDS"
            | "CALL_METHOD_DESCRIPTOR_NOARGS"
            | "CALL_METHOD_DESCRIPTOR_O"
            | "CALL_TYPE_1"
            | "CALL_STR_1"
            | "CALL_TUPLE_1"
            | "CALL_ALLOC_AND_ENTER_INIT"
            | "CALL_ISINSTANCE"
            | "CALL_LEN"
            | "CALL_NON_PY_GENERAL"
            | "CALL_KW_BOUND_METHOD"
            | "CALL_KW_NON_PY"
            | "CALL_KW_PY"
            | "LOAD_ATTR_CLASS"
            | "LOAD_ATTR_GETATTRIBUTE_OVERRIDDEN"
            | "LOAD_ATTR_INSTANCE_VALUE"
            | "LOAD_ATTR_METHOD_LAZY_DICT"
            | "LOAD_ATTR_METHOD_NO_DICT"
            | "LOAD_ATTR_METHOD_WITH_VALUES"
            | "LOAD_ATTR_MODULE"
            | "LOAD_ATTR_NONDESCRIPTOR_NO_DICT"
            | "LOAD_ATTR_NONDESCRIPTOR_WITH_VALUES"
            | "LOAD_ATTR_PROPERTY"
            | "LOAD_ATTR_SLOT"
            | "LOAD_ATTR_WITH_HINT"
            | "LOAD_GLOBAL_BUILTIN"
            | "LOAD_GLOBAL_MODULE"
            | "LOAD_SUPER_ATTR_ATTR"
            | "LOAD_SUPER_ATTR_METHOD"
            | "STORE_ATTR_INSTANCE_VALUE"
            | "STORE_ATTR_SLOT"
            | "STORE_ATTR_WITH_HINT"
            | "UNPACK_SEQUENCE_LIST"
            | "UNPACK_SEQUENCE_TUPLE"
            | "UNPACK_SEQUENCE_TWO_TUPLE"
            | "COMPARE_OP_FLOAT"
            | "COMPARE_OP_INT"
            | "COMPARE_OP_STR"
            | "CONTAINS_OP_DICT"
            | "CONTAINS_OP_SET"
            | "FOR_ITER_GEN"
            | "FOR_ITER_LIST"
            | "FOR_ITER_RANGE"
            | "FOR_ITER_TUPLE"
            | "RESUME_CHECK"
            | "SEND_GEN"
            | "TO_BOOL_ALWAYS_TRUE"
            | "TO_BOOL_BOOL"
            | "TO_BOOL_INT"
            | "TO_BOOL_LIST"
            | "TO_BOOL_NONE"
            | "TO_BOOL_STR"
            | "JUMP_BACKWARD_NO_JIT"
    )
}

#[must_use]
#[allow(clippy::match_same_arms)]
pub fn shared_jump_kind(version: &PyVersion, op: u8) -> JumpKind {
    let name: &'static str = shared_opname(version, op);
    match name {
        "FOR_ITER" => JumpKind::ForIter,
        "JUMP_FORWARD" => JumpKind::Relative,
        "JUMP_ABSOLUTE"
        | "JUMP"
        | "JUMP_IF_TRUE_OR_POP"
        | "JUMP_IF_FALSE_OR_POP"
        | "POP_JUMP_IF_FALSE"
        | "POP_JUMP_IF_TRUE"
        | "POP_JUMP_IF_NONE"
        | "POP_JUMP_IF_NOT_NONE" => JumpKind::Absolute,
        "POP_JUMP_FORWARD_IF_FALSE"
        | "POP_JUMP_FORWARD_IF_TRUE"
        | "POP_JUMP_FORWARD_IF_NONE"
        | "POP_JUMP_FORWARD_IF_NOT_NONE"
        | "SEND" => JumpKind::Relative,
        "JUMP_BACKWARD"
        | "POP_JUMP_BACKWARD_IF_FALSE"
        | "POP_JUMP_BACKWARD_IF_TRUE"
        | "POP_JUMP_BACKWARD_IF_NONE"
        | "POP_JUMP_BACKWARD_IF_NOT_NONE" => JumpKind::Backward,
        "JUMP_BACKWARD_NO_INTERRUPT" => JumpKind::BackwardNoInterrupt,
        _ => JumpKind::None,
    }
}

#[must_use]
pub fn shared_family(version: &PyVersion, op: u8) -> OpcodeFamily {
    let name: &'static str = shared_opname(version, op);
    if name.starts_with("LOAD_") {
        OpcodeFamily::Load
    } else if name.starts_with("STORE_") {
        OpcodeFamily::Store
    } else if name.starts_with("DELETE_") {
        OpcodeFamily::Delete
    } else if name.starts_with("CALL") {
        OpcodeFamily::Call
    } else if name.starts_with("BUILD_") {
        OpcodeFamily::BuildCollection
    } else if name.starts_with("JUMP_")
        || name.starts_with("POP_JUMP_")
        || name == "FOR_ITER"
        || name == "SEND"
    {
        OpcodeFamily::Jump
    } else if name == "COMPARE_OP" || name == "CONTAINS_OP" || name == "IS_OP" {
        OpcodeFamily::Compare
    } else if name.starts_with("GET_A") || name == "END_SEND" || name == "RESUME" {
        OpcodeFamily::Await
    } else if name.starts_with("MATCH_") || name == "GET_LEN" {
        OpcodeFamily::Match
    } else if name.starts_with("RAISE_")
        || name == "RERAISE"
        || name == "PUSH_EXC_INFO"
        || name == "POP_EXCEPT"
        || name == "CHECK_EXC_MATCH"
        || name == "CHECK_EG_MATCH"
        || name == "WITH_EXCEPT_START"
        || name == "CLEANUP_THROW"
    {
        OpcodeFamily::ExceptionHandling
    } else {
        OpcodeFamily::Misc
    }
}

fn binary_op_from_nb(arg: u8) -> BinOp {
    match arg {
        0 => BinOp::Add,
        1 => BinOp::BitAnd,
        2 => BinOp::FloorDiv,
        3 => BinOp::Lshift,
        4 => BinOp::MatMul,
        5 => BinOp::Mul,
        6 => BinOp::Mod,
        7 => BinOp::BitOr,
        8 => BinOp::Pow,
        9 => BinOp::Rshift,
        10 => BinOp::Sub,
        11 => BinOp::TrueDiv,
        12 => BinOp::BitXor,
        13 => BinOp::InplaceAdd,
        14 => BinOp::InplaceBitAnd,
        15 => BinOp::InplaceFloorDiv,
        16 => BinOp::InplaceLshift,
        17 => BinOp::InplaceMatMul,
        18 => BinOp::InplaceMul,
        19 => BinOp::InplaceMod,
        20 => BinOp::InplaceBitOr,
        21 => BinOp::InplacePow,
        22 => BinOp::InplaceRshift,
        23 => BinOp::InplaceSub,
        24 => BinOp::InplaceTrueDiv,
        25 => BinOp::InplaceBitXor,
        other => BinOp::Generic(other),
    }
}

fn cmp_from_arg(arg: u32) -> CmpOp {
    let normalized: u8 = u8::try_from(arg & 0xFF).unwrap_or(0);
    match normalized {
        0 => CmpOp::Lt,
        1 => CmpOp::Le,
        2 => CmpOp::Eq,
        3 => CmpOp::Ne,
        4 => CmpOp::Gt,
        5 => CmpOp::Ge,
        6 => CmpOp::In,
        7 => CmpOp::NotIn,
        8 => CmpOp::Is,
        9 => CmpOp::IsNot,
        10 => CmpOp::ExcMatch,
        11 => CmpOp::BadEq,
        other => CmpOp::Generic(other),
    }
}
