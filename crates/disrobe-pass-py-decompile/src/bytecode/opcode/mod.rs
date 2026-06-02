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

/// Sentinel bit OR'd into a `LocalIndex` to mark it as indexing into the cellvars+freevars pool.
///
/// Set for pre-3.11 `LOAD_DEREF`/`STORE_DEREF`/`LOAD_CLOSURE`/`LOAD_CLASSDEREF`/`DELETE_DEREF`
/// rather than the varnames pool. On 3.11+ all locals share `localsplusnames` so the sentinel is
/// unused but indexes still go through the unified resolver. `CPython` opargs never exceed
/// `u16::MAX` in practice (`EXTENDED_ARG` caps via 32-bit, but real index space is per-codeobj
/// name-pool length), so the high bit is safe.
pub const DEREF_BIT: u32 = 1u32 << 31;

#[must_use]
pub const fn is_deref_local(idx: LocalIndex) -> bool {
    idx & DEREF_BIT != 0
}

#[must_use]
pub const fn deref_local_payload(idx: LocalIndex) -> u32 {
    idx & !DEREF_BIT
}

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
    Repr,
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
    LoadSmallInt(i32),
    LoadCommonConst(u8),
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
    PopJumpIfFalseBackward(u32),
    PopJumpIfTrueBackward(u32),
    JumpIfTrueOrPop(u32),
    JumpIfFalseOrPop(u32),
    JumpBackward(u32),
    JumpBackwardNoInterrupt(u32),
    ContinueLoop(u32),
    PopJumpIfFalseRel(u32),
    PopJumpIfTrueRel(u32),
    PrintItem,
    PrintNewline,
    PrintItemTo,
    PrintNewlineTo,
    PrintExpr,
    Exec,
    BuildClassLegacy,
    Return,
    ReturnConst(ConstIndex),
    CallFunction(u8),
    CallFunctionKw(u8),
    CallFunctionLegacy(u32),
    CallFunctionVarLegacy(u32),
    CallFunctionKwLegacy(u32),
    CallFunctionVarKwLegacy(u32),
    CallFunctionEx(bool),
    KwNames(ConstIndex),
    LoadSuperAttr(NameIndex),
    DeleteFast(LocalIndex),
    DeleteName(NameIndex),
    DeleteAttr(NameIndex),
    DeleteSubscr,
    MakeFunction(u8),
    MakeFunctionLegacy(u32),
    MakeClosureLegacy(u32),
    MakeCell(LocalIndex),
    BuildList(u32),
    BuildTuple(u32),
    BuildSet(u32),
    BuildMap(u32),
    StoreMap,
    BuildConstKeyMap(u32),
    BuildString(u32),
    BuildSlice(u8),
    UnpackSequence(u32),
    UnpackEx(u32),
    ListExtend(u32),
    ListToTuple,
    SetUpdate(u32),
    DictMerge(u32),
    DictUpdate(u32),
    BuildTupleUnpack(u32),
    BuildListUnpack(u32),
    BuildSetUnpack(u32),
    BuildMapUnpack(u32),
    GetAwaitable,
    ListAppend,
    SetAdd,
    MapAdd,
    FormatValue(u8),
    FormatSimple,
    FormatWithSpec,
    BinarySlice,
    StoreSlice,
    LoadSliceLegacy(u8),
    StoreSliceLegacy(u8),
    DeleteSliceLegacy(u8),
    ConvertValue(u8),
    BuildInterpolation(u8),
    BuildTemplate,
    GetIter,
    GetAiter,
    GetAnext,
    EndAsyncFor,
    ForIter(u32),
    ForLoopLegacy(u32),
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
    AsyncGenWrap,
    Raise(u8),
    Reraise(u8),
    PushExcInfo,
    PopExcept,
    CheckExcMatch,
    CheckEgMatch,
    CleanupThrow,
    WithExceptStart,
    BeforeWith,
    SetupWith(u32),
    LoadSpecial(u32),
    LoadFastAndClear(u32),
    MatchClass(u8),
    MatchMapping,
    MatchSequence,
    MatchKeys,
    GetLen,
    Copy(u8),
    Swap(u8),
    RotN(u8),
    ToBool,
    SetFunctionAttribute(u8),
    CallIntrinsic1(u8),
    CallIntrinsic2(u8),
    LoadFromDictOrDeref(LocalIndex),
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
    MarshalVersion {
        major: maj,
        minor: min,
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
        (3, 14) => 43,
        (3, 15) => 41,
        _ => 0,
    }
}

#[must_use]
pub fn shared_cache_size(version: &PyVersion, op: u8) -> u8 {
    disrobe_pass_py_disasm::cache_size(op, shared_marshal_version(version))
}

/// Whether `LOAD_GLOBAL` implicitly pushes a `PUSH_NULL` self-slot ahead of the loaded global.
///
/// The 3.11+ calling convention encodes this in oparg bit 0. `LOAD_METHOD`/`LOAD_ATTR` method forms
/// also push a self-slot, but the decoder collapses those to a bound `Attribute` node that already
/// carries the receiver, so only the bare-global form needs a synthetic `Push` injected by the
/// stream builder.
#[must_use]
pub fn shared_pushes_self_slot(version: &PyVersion, raw: u8, arg: u32) -> bool {
    let (maj, min): (u8, u8) = (version.major(), version.minor());
    (maj, min) >= (3, 11) && (arg & 1) == 1 && shared_opname(version, raw) == "LOAD_GLOBAL"
}

/// Whether the method-form load needs a synthetic `PUSH_NULL`.
///
/// Applies to `LOAD_METHOD` (3.11) or `LOAD_ATTR` method-form (3.12+, oparg bit 0): the `PUSH_NULL`
/// is emitted AFTER the canonical `LoadAttr`, so the 3.11+ `CALL` convention's two-slot pattern
/// resolves to a plain attribute call (`obj.method(args)`) rather than treating the receiver as an
/// implicit-self positional argument.
#[must_use]
pub fn shared_method_form_load_attr(version: &PyVersion, raw: u8, arg: u32) -> bool {
    let (maj, min): (u8, u8) = (version.major(), version.minor());
    if (maj, min) < (3, 11) {
        return false;
    }
    let name: &'static str = shared_opname(version, raw);
    match name {
        "LOAD_METHOD" => true,
        "LOAD_ATTR" if (maj, min) >= (3, 12) => (arg & 1) == 1,
        _ => false,
    }
}

#[must_use]
pub fn shared_decode(version: &PyVersion, raw: u8, arg: u32) -> CanonicalOp {
    let name: &'static str = shared_opname(version, raw);
    let (maj, min): (u8, u8) = (version.major(), version.minor());
    if maj == 3 && min <= 5 && name == "MAKE_FUNCTION" {
        return CanonicalOp::MakeFunctionLegacy(arg);
    }
    if name == "MAKE_CLOSURE" {
        return CanonicalOp::MakeClosureLegacy(arg);
    }
    if (maj, min) < (3, 6) {
        match name {
            "CALL_FUNCTION" if (arg >> 8) & 0xFF != 0 => {
                return CanonicalOp::CallFunctionLegacy(arg);
            }
            "CALL_FUNCTION_VAR" => return CanonicalOp::CallFunctionVarLegacy(arg),
            "CALL_FUNCTION_KW" => return CanonicalOp::CallFunctionKwLegacy(arg),
            "CALL_FUNCTION_VAR_KW" => return CanonicalOp::CallFunctionVarKwLegacy(arg),
            _ => {}
        }
    }
    let attr_index: u32 = if (maj, min) >= (3, 12) { arg >> 1 } else { arg };
    let global_index: u32 = if (maj, min) >= (3, 11) { arg >> 1 } else { arg };
    let compare_index: u32 = match (maj, min) {
        (3, 13..=15) => arg >> 5,
        (3, 12) => arg >> 4,
        _ => arg,
    };
    decode_by_name(name, raw, arg, attr_index, global_index, compare_index)
}

#[allow(
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    clippy::match_same_arms
)]
fn decode_by_name(
    name: &'static str,
    raw: u8,
    arg: u32,
    attr_index: u32,
    global_index: u32,
    compare_index: u32,
) -> CanonicalOp {
    if let Some(canonical) = demote_specialized(name, arg) {
        return canonical;
    }
    if is_specialized_name(name) {
        return CanonicalOp::Specialized(u16::from(raw));
    }
    let arg_lo: u8 = u8::try_from(arg & 0xFF).unwrap_or(0);
    match name {
        "LOAD_SMALL_INT" => CanonicalOp::LoadSmallInt(i32::from(arg_lo)),
        "LOAD_COMMON_CONSTANT" => CanonicalOp::LoadCommonConst(arg_lo),
        "LOAD_FAST_BORROW_LOAD_FAST_BORROW" => CanonicalOp::LoadFastLoadFast(arg >> 4, arg & 0xF),
        "LOAD_FROM_DICT_OR_DEREF" => CanonicalOp::LoadFromDictOrDeref(arg | DEREF_BIT),
        "LOAD_FROM_DICT_OR_GLOBALS" => CanonicalOp::LoadName(arg),
        "LOAD_SUPER_ATTR" => CanonicalOp::LoadSuperAttr(arg >> 2),
        "LOAD_SPECIAL" => CanonicalOp::LoadSpecial(arg),
        "NOP" | "STOP_CODE" | "NOT_TAKEN" => CanonicalOp::Nop,
        "POP_TOP" => CanonicalOp::Pop,
        "DUP_TOP" | "DUP_TOP_TWO" | "DUP_TOPX" => CanonicalOp::Dup,
        "PUSH_NULL" => CanonicalOp::Push(0),
        "LOAD_CONST" => CanonicalOp::LoadConst(arg),
        "LOAD_NAME" => CanonicalOp::LoadName(arg),
        "LOAD_FAST_AND_CLEAR" => CanonicalOp::LoadFastAndClear(arg),
        "LOAD_FAST" | "LOAD_FAST_CHECK" | "LOAD_FAST_BORROW" => CanonicalOp::LoadFast(arg),
        "STORE_FAST" => CanonicalOp::StoreFast(arg),
        "LOAD_GLOBAL" => CanonicalOp::LoadGlobal(global_index),
        "STORE_GLOBAL" => CanonicalOp::StoreGlobal(arg),
        "LOAD_ATTR" => CanonicalOp::LoadAttr(attr_index),
        "LOAD_METHOD" => CanonicalOp::LoadAttr(arg),
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
        "COMPARE_OP" => CanonicalOp::Compare(cmp_from_arg(compare_index)),
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
        "JUMP_IF_FALSE" => CanonicalOp::PopJumpIfFalseRel(arg),
        "JUMP_IF_TRUE" => CanonicalOp::PopJumpIfTrueRel(arg),
        "POP_JUMP_IF_FALSE"
        | "POP_JUMP_FORWARD_IF_FALSE"
        | "POP_JUMP_IF_NONE"
        | "POP_JUMP_FORWARD_IF_NONE" => CanonicalOp::PopJumpIfFalse(arg),
        "POP_JUMP_BACKWARD_IF_FALSE" | "POP_JUMP_BACKWARD_IF_NONE" => {
            CanonicalOp::PopJumpIfFalseBackward(arg)
        }
        "POP_JUMP_IF_TRUE"
        | "POP_JUMP_FORWARD_IF_TRUE"
        | "POP_JUMP_IF_NOT_NONE"
        | "POP_JUMP_FORWARD_IF_NOT_NONE" => CanonicalOp::PopJumpIfTrue(arg),
        "POP_JUMP_BACKWARD_IF_TRUE" | "POP_JUMP_BACKWARD_IF_NOT_NONE" => {
            CanonicalOp::PopJumpIfTrueBackward(arg)
        }
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
        "BUILD_MAP" => CanonicalOp::BuildMap(arg),
        "STORE_MAP" => CanonicalOp::StoreMap,
        "BUILD_CONST_KEY_MAP" => CanonicalOp::BuildConstKeyMap(arg),
        "BUILD_STRING" => CanonicalOp::BuildString(arg),
        "BUILD_SLICE" => CanonicalOp::BuildSlice(arg_lo),
        "LIST_APPEND" => CanonicalOp::ListAppend,
        "SET_ADD" => CanonicalOp::SetAdd,
        "MAP_ADD" => CanonicalOp::MapAdd,
        "FORMAT_VALUE" => CanonicalOp::FormatValue(arg_lo),
        "FORMAT_SIMPLE" => CanonicalOp::FormatSimple,
        "FORMAT_WITH_SPEC" => CanonicalOp::FormatWithSpec,
        "BUILD_INTERPOLATION" => CanonicalOp::BuildInterpolation(arg_lo),
        "BUILD_TEMPLATE" => CanonicalOp::BuildTemplate,
        "CONVERT_VALUE" => CanonicalOp::ConvertValue(arg_lo),
        "GET_ITER" => CanonicalOp::GetIter,
        "GET_AITER" => CanonicalOp::GetAiter,
        "GET_ANEXT" => CanonicalOp::GetAnext,
        "END_ASYNC_FOR" => CanonicalOp::EndAsyncFor,
        "FOR_ITER" => CanonicalOp::ForIter(arg),
        "FOR_LOOP" => CanonicalOp::ForLoopLegacy(arg),
        "SEND" => CanonicalOp::Send(arg),
        "END_SEND" => CanonicalOp::EndSend,
        "RESUME" => CanonicalOp::Resume(arg_lo),
        "YIELD_VALUE" => CanonicalOp::Yield,
        "YIELD_FROM" => CanonicalOp::YieldFrom,
        "RETURN_GENERATOR" => CanonicalOp::ReturnGenerator,
        "BEFORE_ASYNC_WITH" => CanonicalOp::BeforeAsyncWith,
        "SETUP_ASYNC_WITH" => CanonicalOp::SetupAsyncWith,
        "GET_AWAITABLE" => CanonicalOp::GetAwaitable,
        "ASYNC_GEN_WRAP" => CanonicalOp::AsyncGenWrap,
        "INTERPRETER_EXIT" => CanonicalOp::Nop,
        "END_FOR" | "POP_ITER" => CanonicalOp::Pop,
        "ROT_TWO" => CanonicalOp::RotN(2),
        "ROT_THREE" => CanonicalOp::RotN(3),
        "ROT_FOUR" => CanonicalOp::RotN(4),
        "ROT_N" => CanonicalOp::RotN(arg_lo.max(2)),
        "LOAD_DEREF" | "LOAD_CLASSDEREF" | "LOAD_CLOSURE" => CanonicalOp::LoadFast(arg | DEREF_BIT),
        "STORE_DEREF" => CanonicalOp::StoreFast(arg | DEREF_BIT),
        "DELETE_FAST" => CanonicalOp::DeleteFast(arg),
        "DELETE_DEREF" => CanonicalOp::DeleteFast(arg | DEREF_BIT),
        "DELETE_NAME" | "DELETE_GLOBAL" => CanonicalOp::DeleteName(arg),
        "DELETE_ATTR" => CanonicalOp::DeleteAttr(arg),
        "DELETE_SUBSCR" => CanonicalOp::DeleteSubscr,
        "STORE_NAME" => CanonicalOp::StoreName(arg),
        "PRINT_EXPR" => CanonicalOp::PrintExpr,
        "PRINT_ITEM" => CanonicalOp::PrintItem,
        "PRINT_ITEM_TO" => CanonicalOp::PrintItemTo,
        "PRINT_NEWLINE" => CanonicalOp::PrintNewline,
        "PRINT_NEWLINE_TO" => CanonicalOp::PrintNewlineTo,
        "EXEC_STMT" => CanonicalOp::Exec,
        "PRINT_TOS" => CanonicalOp::Pop,
        "LOAD_BUILD_CLASS" => CanonicalOp::LoadBuildClass,
        "LOAD_ASSERTION_ERROR" => CanonicalOp::LoadAssertionError,
        "LOAD_LOCALS" | "LOAD_LOCAL" => CanonicalOp::Push(0),
        "BUILD_CLASS" => CanonicalOp::BuildClassLegacy,
        "BUILD_FUNCTION" => CanonicalOp::BuildTuple(arg),
        "BUILD_TUPLE_UNPACK" | "BUILD_TUPLE_UNPACK_WITH_CALL" => CanonicalOp::BuildTupleUnpack(arg),
        "BUILD_LIST_UNPACK" => CanonicalOp::BuildListUnpack(arg),
        "BUILD_SET_UNPACK" => CanonicalOp::BuildSetUnpack(arg),
        "BUILD_MAP_UNPACK" | "BUILD_MAP_UNPACK_WITH_CALL" => CanonicalOp::BuildMapUnpack(arg),
        "MAKE_CLOSURE" => CanonicalOp::MakeClosureLegacy(arg),
        "IMPORT_NAME" => CanonicalOp::ImportName(arg),
        "IMPORT_FROM" => CanonicalOp::ImportFrom(arg),
        "IMPORT_STAR" => CanonicalOp::ImportStar,
        "SETUP_WITH" => CanonicalOp::SetupWith(arg),
        "SETUP_LOOP"
        | "SETUP_EXCEPT"
        | "SETUP_FINALLY"
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
        | "SET_LINENO" => CanonicalOp::Nop,
        "CONTINUE_LOOP" => CanonicalOp::ContinueLoop(arg),
        "UNPACK_SEQUENCE" | "UNPACK_TUPLE" | "UNPACK_LIST" | "UNPACK_ARG" | "UNPACK_VARARG" => {
            CanonicalOp::UnpackSequence(arg)
        }
        "UNPACK_EX" => CanonicalOp::UnpackEx(arg),
        "STORE_SLICE" => CanonicalOp::StoreSlice,
        "SLICE" | "SLICE+0" => CanonicalOp::LoadSliceLegacy(0),
        "SLICE+1" | "SLICE_2" => CanonicalOp::LoadSliceLegacy(1),
        "SLICE+2" => CanonicalOp::LoadSliceLegacy(2),
        "SLICE+3" | "SLICE_3" => CanonicalOp::LoadSliceLegacy(3),
        "STORE_SLICE+0" => CanonicalOp::StoreSliceLegacy(0),
        "STORE_SLICE+1" => CanonicalOp::StoreSliceLegacy(1),
        "STORE_SLICE+2" => CanonicalOp::StoreSliceLegacy(2),
        "STORE_SLICE+3" => CanonicalOp::StoreSliceLegacy(3),
        "DELETE_SLICE" | "DELETE_SLICE+0" => CanonicalOp::DeleteSliceLegacy(0),
        "DELETE_SLICE+1" => CanonicalOp::DeleteSliceLegacy(1),
        "DELETE_SLICE+2" => CanonicalOp::DeleteSliceLegacy(2),
        "DELETE_SLICE+3" => CanonicalOp::DeleteSliceLegacy(3),
        "BUILD_LIST_FROM_ARG" => CanonicalOp::BuildList(arg),
        "JUMP_IF_NOT_DEBUG" => CanonicalOp::JumpForward(i32::try_from(arg).unwrap_or(0)),
        "LOOKUP_METHOD" => CanonicalOp::LoadAttr(arg),
        "CALL_METHOD" => CanonicalOp::CallFunction(arg_lo),
        "CALL_METHOD_KW" => CanonicalOp::CallFunctionKw(arg_lo),
        "LOAD_REVDB_VAR" => CanonicalOp::LoadName(arg),
        "GET_YIELD_FROM_ITER" => CanonicalOp::GetIter,
        "LIST_TO_TUPLE" => CanonicalOp::ListToTuple,
        "LIST_EXTEND" | "MAP_EXTEND" => CanonicalOp::ListExtend(arg),
        "SET_UPDATE" => CanonicalOp::SetUpdate(arg),
        "DICT_MERGE" => CanonicalOp::DictMerge(arg),
        "DICT_UPDATE" => CanonicalOp::DictUpdate(arg),
        "KW_NAMES" => CanonicalOp::KwNames(arg),
        "PRECALL" => CanonicalOp::Nop,
        "SET_FUNCTION_ATTRIBUTE" => CanonicalOp::SetFunctionAttribute(arg_lo),
        "CALL_INTRINSIC_1" => CanonicalOp::CallIntrinsic1(arg_lo),
        "CALL_INTRINSIC_2" => CanonicalOp::CallIntrinsic2(arg_lo),
        "COPY_FREE_VARS" => CanonicalOp::Nop,
        "COPY_DICT_WITHOUT_KEYS" => CanonicalOp::DeleteSubscr,
        "LIST_TO_TUPLE_EX" => CanonicalOp::ListToTuple,
        "SETUP_ANNOTATIONS" => CanonicalOp::Nop,
        "STORE_ANNOTATION" => CanonicalOp::StoreAnnotation(arg),
        "GET_LEN_NEXT" => CanonicalOp::GetLen,
        "RETURN_VALUE_FROM_CACHE" => CanonicalOp::Return,
        "BINARY_SLICE" => CanonicalOp::BinarySlice,
        "STORE_SLICE_NEW" => CanonicalOp::StoreSubscr,
        "RAISE" | "RAISE_2" | "RAISE_3" => CanonicalOp::Raise(arg_lo),
        "GLOBAL_DECL" | "NONLOCAL_DECL" => CanonicalOp::Nop,
        "LIST_APPEND_NEW" => CanonicalOp::ListAppend,
        "STORE_LOCAL" => CanonicalOp::StoreFast(arg),
        "RESERVE_FAST" | "RESERVE_STACK" => CanonicalOp::Nop,
        "UNARY_CONVERT" => CanonicalOp::UnaryOp(UnaryOp::Repr),
        "UNARY_CALL" => CanonicalOp::CallFunction(0),
        "BINARY_CALL" => CanonicalOp::CallFunction(1),
        "BINARY_DIVMOD" => CanonicalOp::BinaryOp(BinOp::OldDivide),
        "PRINT_NEWLINE_LIST" => CanonicalOp::PrintNewline,
        "PRINT_NEWLINE_TO_LIST" => CanonicalOp::PrintNewlineTo,
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

fn demote_specialized(name: &'static str, arg: u32) -> Option<CanonicalOp> {
    let arg_lo: u8 = u8::try_from(arg & 0xFF).unwrap_or(0);
    match name {
        "BINARY_OP_ADD_INT" | "BINARY_OP_ADD_FLOAT" | "BINARY_OP_ADD_UNICODE" => {
            Some(CanonicalOp::BinaryOp(BinOp::Add))
        }
        "BINARY_OP_INPLACE_ADD_UNICODE" => Some(CanonicalOp::BinaryOp(BinOp::InplaceAdd)),
        "BINARY_OP_MULTIPLY_INT" | "BINARY_OP_MULTIPLY_FLOAT" => {
            Some(CanonicalOp::BinaryOp(BinOp::Mul))
        }
        "BINARY_OP_SUBTRACT_INT" | "BINARY_OP_SUBTRACT_FLOAT" => {
            Some(CanonicalOp::BinaryOp(BinOp::Sub))
        }
        "BINARY_OP_EXTEND" => Some(CanonicalOp::BinaryOp(binary_op_from_nb(arg_lo))),
        "BINARY_SUBSCR_DICT"
        | "BINARY_SUBSCR_GETITEM"
        | "BINARY_SUBSCR_LIST_INT"
        | "BINARY_SUBSCR_TUPLE_INT"
        | "BINARY_SUBSCR_STR_INT"
        | "BINARY_OP_SUBSCR_DICT"
        | "BINARY_OP_SUBSCR_GETITEM"
        | "BINARY_OP_SUBSCR_LIST_INT"
        | "BINARY_OP_SUBSCR_LIST_SLICE"
        | "BINARY_OP_SUBSCR_STR_INT"
        | "BINARY_OP_SUBSCR_TUPLE_INT" => Some(CanonicalOp::LoadSubscr),
        "STORE_SUBSCR_DICT" | "STORE_SUBSCR_LIST_INT" => Some(CanonicalOp::StoreSubscr),
        "CALL_PY_EXACT_ARGS"
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
        | "CALL_NON_PY_GENERAL" => Some(CanonicalOp::CallFunction(arg_lo)),
        "CALL_KW_BOUND_METHOD" | "CALL_KW_NON_PY" | "CALL_KW_PY" => {
            Some(CanonicalOp::CallFunctionKw(arg_lo))
        }
        "LOAD_ATTR_CLASS"
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
        | "LOAD_ATTR_WITH_HINT" => Some(CanonicalOp::LoadAttr(arg >> 1)),
        "LOAD_GLOBAL_BUILTIN" | "LOAD_GLOBAL_MODULE" => Some(CanonicalOp::LoadGlobal(arg >> 1)),
        "LOAD_SUPER_ATTR_ATTR" | "LOAD_SUPER_ATTR_METHOD" => Some(CanonicalOp::LoadAttr(arg >> 2)),
        "STORE_ATTR_INSTANCE_VALUE" | "STORE_ATTR_SLOT" | "STORE_ATTR_WITH_HINT" => {
            Some(CanonicalOp::StoreAttr(arg))
        }
        "UNPACK_SEQUENCE_LIST" | "UNPACK_SEQUENCE_TUPLE" | "UNPACK_SEQUENCE_TWO_TUPLE" => {
            Some(CanonicalOp::UnpackSequence(arg))
        }
        "COMPARE_OP_FLOAT" | "COMPARE_OP_INT" | "COMPARE_OP_STR" => {
            Some(CanonicalOp::Compare(cmp_from_arg(arg >> 4)))
        }
        "CONTAINS_OP_DICT" | "CONTAINS_OP_SET" => Some(CanonicalOp::Compare(if arg & 1 == 1 {
            CmpOp::NotIn
        } else {
            CmpOp::In
        })),
        "FOR_ITER_GEN" | "FOR_ITER_LIST" | "FOR_ITER_RANGE" | "FOR_ITER_TUPLE" => {
            Some(CanonicalOp::ForIter(arg))
        }
        "TO_BOOL_ALWAYS_TRUE"
        | "TO_BOOL_BOOL"
        | "TO_BOOL_INT"
        | "TO_BOOL_LIST"
        | "TO_BOOL_NONE"
        | "TO_BOOL_STR" => Some(CanonicalOp::ToBool),
        "RESUME_CHECK" => Some(CanonicalOp::Resume(arg_lo)),
        "SEND_GEN" => Some(CanonicalOp::Send(arg)),
        _ => None,
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
        | "JUMP_IF_FALSE"
        | "JUMP_IF_TRUE"
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
