use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const OPARRAY_MAGIC: &[u8; 4] = b"DZOA";

pub const OPARRAY_VERSION: u8 = 3;

pub const OPARRAY_MIN_VERSION: u8 = 1;

pub const OPARRAY_MAX_VERSION: u8 = 4;

const SANE_OP_CAP: u32 = 4_000_000;
const SANE_LITERAL_CAP: u32 = 4_000_000;
const SANE_VAR_CAP: u32 = 1 << 20;
const SANE_NAME_CAP: u32 = 1 << 20;
const SANE_CHILD_CAP: u32 = 1 << 16;
const SANE_NEST_DEPTH: u32 = 64;
const MAX_PREALLOC: usize = 1 << 16;
const SANE_LIFT_DEPTH: u32 = 256;
const MAX_UNRECOVERED_RECORDS: usize = 4096;
const SANE_ROPE_WORK_CAP: usize = 1 << 16;
const SANE_LIST_ELEMENT_CAP: usize = 1 << 16;
const SANE_LIST_RENDER_CAP: usize = 1 << 20;
const SANE_SWITCH_ARM_CAP: usize = 1 << 16;
const SANE_SWITCH_LABEL_WORK_CAP: usize = 1 << 20;
const SANE_SWITCH_STATE_WORK_CAP: usize = 1 << 20;
const SANE_LOOP_RELIFT_WORK_CAP: usize = 1 << 20;
const SANE_FOR_STEP_CAP: usize = 16;
const SANE_NULLSAFE_LINKS: usize = 64;
const SANE_CLOSURE_USE_CAP: usize = 256;
const SANE_CALL_ARGUMENT_CAP: usize = 1 << 16;
const SANE_CALL_RENDER_CAP: usize = 1 << 20;
const SANE_TRY_CATCH_CAP: u32 = 1 << 16;
const SANE_CATCH_TYPE_CAP: usize = 256;
const SANE_CATCH_CLAUSE_CAP: usize = 256;
const CATCH_LAST: u32 = 1;
const SANE_LOOP_EXIT_FREE_CAP: u32 = SANE_LIFT_DEPTH;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OperandType {
    Unused,

    Const,

    TmpVar,

    Var,

    Cv,
}

impl OperandType {
    #[must_use]
    pub const fn from_wire(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Unused),
            1 => Some(Self::Const),
            2 => Some(Self::TmpVar),
            4 => Some(Self::Var),
            8 => Some(Self::Cv),
            _ => None,
        }
    }

    #[must_use]
    pub fn render(self, value: u32, literals: &[Literal]) -> Option<String> {
        match self {
            Self::Unused => None,
            Self::Const => Some(
                literals
                    .get(value as usize)
                    .map_or_else(|| format!("CONST#{value}"), Literal::render),
            ),
            Self::Cv => Some(format!("$v{value}")),
            Self::TmpVar => Some(format!("~{value}")),
            Self::Var => Some(format!("@{value}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Op {
    pub opcode: u8,
    pub op1_type: OperandType,
    pub op2_type: OperandType,
    pub result_type: OperandType,
    pub op1: u32,
    pub op2: u32,
    pub result: u32,
    pub extended_value: u32,
    pub lineno: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExtendedValueProvenance {
    Known(u32),
    Unavailable,
}

impl Op {
    const fn extended_value_provenance(&self) -> ExtendedValueProvenance {
        if self.opcode == op::FREE && self.extended_value == 0 {
            ExtendedValueProvenance::Unavailable
        } else {
            ExtendedValueProvenance::Known(self.extended_value)
        }
    }

    #[must_use]
    pub fn mnemonic(&self) -> &'static str {
        opcode_name(self.opcode)
    }

    #[must_use]
    pub fn branch_target(&self) -> Branch {
        match self.opcode {
            o if o == op::JMP => Branch::Uncond(self.op1),
            o if o == op::JMPZ || o == op::JMPZ_EX => Branch::Cond {
                taken: self.op2,
                fallthrough: true,
            },
            o if o == op::JMPNZ || o == op::JMPNZ_EX => Branch::Cond {
                taken: self.op2,
                fallthrough: true,
            },
            o if o == op::JMP_SET || o == op::COALESCE || o == op::JMP_NULL => Branch::Cond {
                taken: self.op2,
                fallthrough: true,
            },
            o if o == op::FE_FETCH_R || o == op::FE_FETCH_RW => Branch::Cond {
                taken: self.op2,
                fallthrough: true,
            },
            o if o == op::FE_RESET_R || o == op::FE_RESET_RW => Branch::Cond {
                taken: self.op2,
                fallthrough: true,
            },
            o if o == op::RETURN || o == op::RETURN_BY_REF || o == op::GENERATOR_RETURN => {
                Branch::Terminal
            }
            o if o == op::THROW || o == op::EXIT => Branch::Terminal,
            _ => Branch::None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Branch {
    None,

    Uncond(u32),

    Cond { taken: u32, fallthrough: bool },

    Terminal,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Literal {
    Null,
    Bool(bool),
    Long(i64),
    Double(f64),
    Str(String),
    Array(u32),
    SwitchLong(Vec<(i64, u32)>),
    SwitchString(Vec<(String, u32)>),
}

impl Eq for Literal {}

impl Literal {
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::Null => "null".to_owned(),
            Self::Bool(b) => if *b { "true" } else { "false" }.to_owned(),
            Self::Long(n) => n.to_string(),
            Self::Double(d) => render_php_double(*d),
            Self::Str(s) => format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'")),
            Self::Array(_) | Self::SwitchLong(_) | Self::SwitchString(_) => "array()".to_owned(),
        }
    }

    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

fn render_php_double(d: f64) -> String {
    if d.is_nan() {
        return "NAN".to_owned();
    }
    if d.is_infinite() {
        return if d < 0.0 { "-INF" } else { "INF" }.to_owned();
    }
    let text: String = format!("{d}");
    if text
        .bytes()
        .any(|b: u8| b == b'.' || b == b'e' || b == b'E')
    {
        text
    } else {
        format!("{text}.0")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpArrayKind {
    Main,

    Function,

    Method,

    Closure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TryCatch {
    pub try_op: u32,
    pub catch_op: Option<u32>,
    pub finally_op: Option<u32>,
    pub finally_end: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpArray {
    pub kind: OpArrayKind,
    pub name: Option<String>,
    pub class_name: Option<String>,
    pub num_args: u32,
    pub literals: Vec<Literal>,
    pub ops: Vec<Op>,
    pub children: Vec<Self>,
    pub var_names: Vec<Option<String>>,
    #[serde(default)]
    pub try_catch: Vec<TryCatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasicBlock {
    pub start: u32,
    pub end: u32,
    pub successors: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cfg {
    pub blocks: Vec<BasicBlock>,
    pub block_at: BTreeMap<u32, usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Fidelity {
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnrecoveredOp {
    pub container: String,
    pub index: u32,
    pub opcode: u8,
    pub mnemonic: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limitation {
    pub container: String,
    pub index: u32,
    pub opcode: u8,
    pub mnemonic: String,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decompilation {
    pub fidelity: Fidelity,
    pub php_skeleton: String,
    pub op_array_count: usize,
    pub op_count: usize,
    pub literal_count: usize,
    pub unrecovered: Vec<UnrecoveredOp>,
    pub unrecovered_total: usize,
    #[serde(default)]
    pub limitations: Vec<Limitation>,
    #[serde(default)]
    pub limitations_total: usize,
}

pub mod op {

    pub const NOP: u8 = 0;
    pub const ADD: u8 = 1;
    pub const SUB: u8 = 2;
    pub const MUL: u8 = 3;
    pub const DIV: u8 = 4;
    pub const MOD: u8 = 5;
    pub const CONCAT: u8 = 8;
    pub const BW_NOT: u8 = 13;
    pub const IS_IDENTICAL: u8 = 16;
    pub const IS_NOT_IDENTICAL: u8 = 17;
    pub const IS_EQUAL: u8 = 18;
    pub const IS_NOT_EQUAL: u8 = 19;
    pub const IS_SMALLER: u8 = 20;
    pub const IS_SMALLER_OR_EQUAL: u8 = 21;
    pub const ASSIGN: u8 = 22;
    pub const ASSIGN_DIM: u8 = 23;
    pub const ASSIGN_OBJ: u8 = 24;
    pub const ASSIGN_OP: u8 = 26;
    pub const QM_ASSIGN: u8 = 31;
    pub const PRE_INC: u8 = 34;
    pub const PRE_DEC: u8 = 35;
    pub const POST_INC: u8 = 36;
    pub const POST_DEC: u8 = 37;
    pub const JMP: u8 = 42;
    pub const JMPZ: u8 = 43;
    pub const JMPNZ: u8 = 44;
    pub const JMPZ_EX: u8 = 46;
    pub const JMPNZ_EX: u8 = 47;
    pub const CASE: u8 = 48;
    pub const CAST: u8 = 51;
    pub const BOOL: u8 = 52;
    pub const ROPE_INIT: u8 = 54;
    pub const ROPE_ADD: u8 = 55;
    pub const ROPE_END: u8 = 56;
    pub const INIT_FCALL_BY_NAME: u8 = 59;
    pub const DO_FCALL: u8 = 60;
    pub const INIT_FCALL: u8 = 61;
    pub const INIT_NS_FCALL: u8 = 69;
    pub const RETURN: u8 = 62;
    pub const RECV: u8 = 63;
    pub const RECV_INIT: u8 = 64;
    pub const SEND_VAL: u8 = 65;
    pub const SEND_VAR_EX: u8 = 66;
    pub const RECV_VARIADIC: u8 = 164;
    pub const SEND_UNPACK: u8 = 165;
    pub const CHECK_UNDEF_ARGS: u8 = 199;
    pub const CALLABLE_CONVERT: u8 = 202;
    pub const NEW: u8 = 68;
    pub const FREE: u8 = 70;
    pub const INIT_ARRAY: u8 = 71;
    pub const ADD_ARRAY_ELEMENT: u8 = 72;
    pub const INCLUDE_OR_EVAL: u8 = 73;
    pub const UNSET_VAR: u8 = 74;
    pub const FE_RESET_R: u8 = 77;
    pub const FE_FETCH_R: u8 = 78;
    pub const FETCH_R: u8 = 80;
    pub const FETCH_DIM_R: u8 = 81;
    pub const FETCH_LIST_R: u8 = 98;
    pub const FETCH_OBJ_R: u8 = 82;
    pub const FETCH_W: u8 = 83;
    pub const FETCH_RW: u8 = 86;
    pub const FETCH_IS: u8 = 89;
    pub const FETCH_CONSTANT: u8 = 99;
    pub const THROW: u8 = 108;
    pub const FETCH_CLASS: u8 = 109;
    pub const CLONE: u8 = 110;
    pub const INIT_METHOD_CALL: u8 = 112;
    pub const INIT_STATIC_METHOD_CALL: u8 = 113;
    pub const ISSET_ISEMPTY_VAR: u8 = 114;
    pub const ISSET_ISEMPTY_DIM_OBJ: u8 = 115;
    pub const ISSET_ISEMPTY_PROP_OBJ: u8 = 148;
    pub const ISSET_ISEMPTY_CV: u8 = 154;
    pub const SEND_VAL_EX: u8 = 116;
    pub const SEND_VAR: u8 = 117;
    pub const RETURN_BY_REF: u8 = 111;
    pub const ECHO: u8 = 136;
    pub const INSTANCEOF: u8 = 138;
    pub const DECLARE_FUNCTION: u8 = 141;
    pub const DECLARE_LAMBDA_FUNCTION: u8 = 142;
    pub const DECLARE_CONST: u8 = 143;
    pub const DECLARE_CLASS: u8 = 144;
    pub const DECLARE_CLASS_DELAYED: u8 = 145;
    pub const DECLARE_ANON_CLASS: u8 = 146;
    pub const HANDLE_EXCEPTION: u8 = 149;
    pub const DISCARD_EXCEPTION: u8 = 159;
    pub const FAST_CALL: u8 = 162;
    pub const FAST_RET: u8 = 163;
    pub const JMP_SET: u8 = 152;
    pub const UNSET_CV: u8 = 153;
    pub const YIELD: u8 = 160;
    pub const GENERATOR_RETURN: u8 = 161;
    pub const YIELD_FROM: u8 = 166;
    pub const DO_ICALL: u8 = 129;
    pub const DO_UCALL: u8 = 130;
    pub const DO_FCALL_BY_NAME: u8 = 131;
    pub const FE_RESET_RW: u8 = 125;
    pub const FE_FETCH_RW: u8 = 126;
    pub const COALESCE: u8 = 169;
    pub const JMP_NULL: u8 = 198;
    pub const SWITCH_LONG: u8 = 187;
    pub const SWITCH_STRING: u8 = 188;
    pub const MATCH: u8 = 195;
    pub const EXIT: u8 = 79;
    pub const CATCH: u8 = 107;
    pub const BOOL_NOT: u8 = 14;
    pub const SL: u8 = 6;
    pub const SR: u8 = 7;
    pub const BW_OR: u8 = 9;
    pub const BW_AND: u8 = 10;
    pub const BW_XOR: u8 = 11;
    pub const POW: u8 = 12;
    pub const STRLEN: u8 = 210;
    pub const COUNT: u8 = 211;
    pub const VERIFY_RETURN_TYPE: u8 = 212;
    pub const FE_FREE: u8 = 213;
    pub const GENERATOR_CREATE: u8 = 214;
    pub const OP_DATA: u8 = 137;
    pub const ASSIGN_STATIC_PROP: u8 = 25;
    pub const TYPE_CHECK: u8 = 123;
    pub const SPACESHIP: u8 = 170;
    pub const INIT_DYNAMIC_CALL: u8 = 128;
    pub const BIND_LEXICAL: u8 = 182;
    pub const BIND_STATIC: u8 = 183;
    pub const ASSIGN_REF: u8 = 30;
    pub const ASSIGN_OBJ_REF: u8 = 32;
    pub const ASSIGN_STATIC_PROP_REF: u8 = 33;
    pub const ASSIGN_DIM_OP: u8 = 27;
    pub const ASSIGN_OBJ_OP: u8 = 28;
    pub const ASSIGN_STATIC_PROP_OP: u8 = 29;
    pub const PRE_INC_STATIC_PROP: u8 = 38;
    pub const PRE_DEC_STATIC_PROP: u8 = 39;
    pub const POST_INC_STATIC_PROP: u8 = 40;
    pub const POST_DEC_STATIC_PROP: u8 = 41;
    pub const SEND_REF: u8 = 67;
    pub const FETCH_DIM_IS: u8 = 90;
    pub const FETCH_OBJ_IS: u8 = 91;
    pub const FETCH_DIM_W: u8 = 84;
    pub const FETCH_OBJ_W: u8 = 85;
    pub const FETCH_DIM_RW: u8 = 87;
    pub const FETCH_OBJ_RW: u8 = 88;
    pub const PRE_INC_OBJ: u8 = 132;
    pub const PRE_DEC_OBJ: u8 = 133;
    pub const POST_INC_OBJ: u8 = 134;
    pub const POST_DEC_OBJ: u8 = 135;
    pub const FETCH_STATIC_PROP_R: u8 = 173;
    pub const FETCH_STATIC_PROP_W: u8 = 174;
    pub const FETCH_STATIC_PROP_RW: u8 = 175;
    pub const FETCH_CLASS_CONSTANT: u8 = 181;
}

#[must_use]
pub fn opcode_name(opcode: u8) -> &'static str {
    match opcode {
        0 => "ZEND_NOP",
        1 => "ZEND_ADD",
        2 => "ZEND_SUB",
        3 => "ZEND_MUL",
        4 => "ZEND_DIV",
        5 => "ZEND_MOD",
        6 => "ZEND_SL",
        7 => "ZEND_SR",
        8 => "ZEND_CONCAT",
        9 => "ZEND_BW_OR",
        10 => "ZEND_BW_AND",
        11 => "ZEND_BW_XOR",
        12 => "ZEND_POW",
        13 => "ZEND_BW_NOT",
        14 => "ZEND_BOOL_NOT",
        16 => "ZEND_IS_IDENTICAL",
        17 => "ZEND_IS_NOT_IDENTICAL",
        18 => "ZEND_IS_EQUAL",
        19 => "ZEND_IS_NOT_EQUAL",
        20 => "ZEND_IS_SMALLER",
        21 => "ZEND_IS_SMALLER_OR_EQUAL",
        22 => "ZEND_ASSIGN",
        23 => "ZEND_ASSIGN_DIM",
        24 => "ZEND_ASSIGN_OBJ",
        25 => "ZEND_ASSIGN_STATIC_PROP",
        30 => "ZEND_ASSIGN_REF",
        32 => "ZEND_ASSIGN_OBJ_REF",
        33 => "ZEND_ASSIGN_STATIC_PROP_REF",
        26 => "ZEND_ASSIGN_OP",
        27 => "ZEND_ASSIGN_DIM_OP",
        28 => "ZEND_ASSIGN_OBJ_OP",
        29 => "ZEND_ASSIGN_STATIC_PROP_OP",
        31 => "ZEND_QM_ASSIGN",
        34 => "ZEND_PRE_INC",
        35 => "ZEND_PRE_DEC",
        36 => "ZEND_POST_INC",
        37 => "ZEND_POST_DEC",
        38 => "ZEND_PRE_INC_STATIC_PROP",
        39 => "ZEND_PRE_DEC_STATIC_PROP",
        40 => "ZEND_POST_INC_STATIC_PROP",
        41 => "ZEND_POST_DEC_STATIC_PROP",
        42 => "ZEND_JMP",
        43 => "ZEND_JMPZ",
        44 => "ZEND_JMPNZ",
        46 => "ZEND_JMPZ_EX",
        47 => "ZEND_JMPNZ_EX",
        48 => "ZEND_CASE",
        51 => "ZEND_CAST",
        52 => "ZEND_BOOL",
        54 => "ZEND_ROPE_INIT",
        55 => "ZEND_ROPE_ADD",
        56 => "ZEND_ROPE_END",
        59 => "ZEND_INIT_FCALL_BY_NAME",
        60 => "ZEND_DO_FCALL",
        61 => "ZEND_INIT_FCALL",
        62 => "ZEND_RETURN",
        63 => "ZEND_RECV",
        64 => "ZEND_RECV_INIT",
        65 => "ZEND_SEND_VAL",
        66 => "ZEND_SEND_VAR_EX",
        67 => "ZEND_SEND_REF",
        68 => "ZEND_NEW",
        69 => "ZEND_INIT_NS_FCALL_BY_NAME",
        70 => "ZEND_FREE",
        71 => "ZEND_INIT_ARRAY",
        72 => "ZEND_ADD_ARRAY_ELEMENT",
        73 => "ZEND_INCLUDE_OR_EVAL",
        74 => "ZEND_UNSET_VAR",
        77 => "ZEND_FE_RESET_R",
        78 => "ZEND_FE_FETCH_R",
        79 => "ZEND_EXIT",
        80 => "ZEND_FETCH_R",
        81 => "ZEND_FETCH_DIM_R",
        82 => "ZEND_FETCH_OBJ_R",
        83 => "ZEND_FETCH_W",
        84 => "ZEND_FETCH_DIM_W",
        90 => "ZEND_FETCH_DIM_IS",
        91 => "ZEND_FETCH_OBJ_IS",
        85 => "ZEND_FETCH_OBJ_W",
        86 => "ZEND_FETCH_RW",
        87 => "ZEND_FETCH_DIM_RW",
        88 => "ZEND_FETCH_OBJ_RW",
        89 => "ZEND_FETCH_IS",
        98 => "ZEND_FETCH_LIST_R",
        99 => "ZEND_FETCH_CONSTANT",
        107 => "ZEND_CATCH",
        108 => "ZEND_THROW",
        109 => "ZEND_FETCH_CLASS",
        110 => "ZEND_CLONE",
        111 => "ZEND_RETURN_BY_REF",
        112 => "ZEND_INIT_METHOD_CALL",
        113 => "ZEND_INIT_STATIC_METHOD_CALL",
        114 => "ZEND_ISSET_ISEMPTY_VAR",
        115 => "ZEND_ISSET_ISEMPTY_DIM_OBJ",
        116 => "ZEND_SEND_VAL_EX",
        117 => "ZEND_SEND_VAR",
        125 => "ZEND_FE_RESET_RW",
        126 => "ZEND_FE_FETCH_RW",
        129 => "ZEND_DO_ICALL",
        130 => "ZEND_DO_UCALL",
        131 => "ZEND_DO_FCALL_BY_NAME",
        132 => "ZEND_PRE_INC_OBJ",
        133 => "ZEND_PRE_DEC_OBJ",
        134 => "ZEND_POST_INC_OBJ",
        135 => "ZEND_POST_DEC_OBJ",
        173 => "ZEND_FETCH_STATIC_PROP_R",
        174 => "ZEND_FETCH_STATIC_PROP_W",
        175 => "ZEND_FETCH_STATIC_PROP_RW",
        181 => "ZEND_FETCH_CLASS_CONSTANT",
        136 => "ZEND_ECHO",
        138 => "ZEND_INSTANCEOF",
        141 => "ZEND_DECLARE_FUNCTION",
        142 => "ZEND_DECLARE_LAMBDA_FUNCTION",
        143 => "ZEND_DECLARE_CONST",
        144 => "ZEND_DECLARE_CLASS",
        145 => "ZEND_DECLARE_CLASS_DELAYED",
        146 => "ZEND_DECLARE_ANON_CLASS",
        148 => "ZEND_ISSET_ISEMPTY_PROP_OBJ",
        149 => "ZEND_HANDLE_EXCEPTION",
        159 => "ZEND_DISCARD_EXCEPTION",
        162 => "ZEND_FAST_CALL",
        163 => "ZEND_FAST_RET",
        152 => "ZEND_JMP_SET",
        153 => "ZEND_UNSET_CV",
        154 => "ZEND_ISSET_ISEMPTY_CV",
        160 => "ZEND_YIELD",
        161 => "ZEND_GENERATOR_RETURN",
        164 => "ZEND_RECV_VARIADIC",
        165 => "ZEND_SEND_UNPACK",
        166 => "ZEND_YIELD_FROM",
        169 => "ZEND_COALESCE",
        128 => "ZEND_INIT_DYNAMIC_CALL",
        123 => "ZEND_TYPE_CHECK",
        170 => "ZEND_SPACESHIP",
        182 => "ZEND_BIND_LEXICAL",
        183 => "ZEND_BIND_STATIC",
        187 => "ZEND_SWITCH_LONG",
        188 => "ZEND_SWITCH_STRING",
        195 => "ZEND_MATCH",
        198 => "ZEND_JMP_NULL",
        199 => "ZEND_CHECK_UNDEF_ARGS",
        202 => "ZEND_CALLABLE_CONVERT",
        137 => "ZEND_OP_DATA",
        210 => "ZEND_STRLEN",
        211 => "ZEND_COUNT",
        212 => "ZEND_VERIFY_RETURN_TYPE",
        213 => "ZEND_FE_FREE",
        214 => "ZEND_GENERATOR_CREATE",
        other => unknown_name(other),
    }
}

fn unknown_name(opcode: u8) -> &'static str {
    static TABLE: [&str; 256] = build_unknown_table();
    TABLE[opcode as usize]
}

const fn build_unknown_table() -> [&'static str; 256] {
    ["UNKNOWN"; 256]
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn need(&self, n: usize) -> Result<()> {
        if self.pos.saturating_add(n) > self.buf.len() {
            return Err(Error::OpArrayTruncated {
                offset: self.pos,
                need: n,
            });
        }
        Ok(())
    }

    const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn u8(&mut self) -> Result<u8> {
        self.need(1)?;
        let v: u8 = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn u32(&mut self) -> Result<u32> {
        self.need(4)?;
        let v: u32 = u32::from_le_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn i64(&mut self) -> Result<i64> {
        self.need(8)?;
        let mut bytes: [u8; 8] = [0u8; 8];
        bytes.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(i64::from_le_bytes(bytes))
    }

    fn f64(&mut self) -> Result<f64> {
        Ok(f64::from_bits(self.i64()? as u64))
    }

    fn string(&mut self, cap: u32) -> Result<String> {
        let len: u32 = self.u32()?;
        if len > cap {
            return Err(Error::OpArrayFieldOversize {
                field: "string",
                value: len,
                cap,
            });
        }
        self.need(len as usize)?;
        let raw: &[u8] = &self.buf[self.pos..self.pos + len as usize];
        self.pos += len as usize;
        Ok(String::from_utf8_lossy(raw).into_owned())
    }

    fn operand_type(&mut self) -> Result<OperandType> {
        let raw: u8 = self.u8()?;
        OperandType::from_wire(raw).ok_or(Error::OpArrayBadOperandType(raw))
    }
}

fn ensure_count_fits(cur: &Cursor<'_>, count: u32) -> Result<()> {
    if count as usize > cur.remaining() {
        return Err(Error::OpArrayTruncated {
            offset: cur.pos,
            need: count as usize,
        });
    }
    Ok(())
}

pub fn parse_oparray(bytes: &[u8]) -> Result<OpArray> {
    let mut cur: Cursor<'_> = Cursor::new(bytes);
    cur.need(5)?;
    if &bytes[..4] != OPARRAY_MAGIC {
        return Err(Error::OpArrayBadMagic);
    }
    cur.pos = 4;
    let version: u8 = cur.u8()?;
    if !(OPARRAY_MIN_VERSION..=OPARRAY_MAX_VERSION).contains(&version) {
        return Err(Error::OpArrayUnsupportedVersion {
            version,
            min: OPARRAY_MIN_VERSION,
            max: OPARRAY_MAX_VERSION,
        });
    }
    parse_one(&mut cur, version, 0)
}

fn parse_one(cur: &mut Cursor<'_>, version: u8, depth: u32) -> Result<OpArray> {
    if depth > SANE_NEST_DEPTH {
        return Err(Error::OpArrayNestTooDeep(depth));
    }
    let kind: OpArrayKind = match cur.u8()? {
        0 => OpArrayKind::Main,
        1 => OpArrayKind::Function,
        2 => OpArrayKind::Method,
        3 => OpArrayKind::Closure,
        other => return Err(Error::OpArrayBadKind(other)),
    };
    let name: Option<String> = read_opt_string(cur)?;
    let class_name: Option<String> = read_opt_string(cur)?;
    let num_args: u32 = cur.u32()?;
    let var_names: Vec<Option<String>> = if version >= 2 {
        parse_var_names(cur)?
    } else {
        Vec::new()
    };
    let literals: Vec<Literal> = parse_literals(cur, version)?;
    let ops: Vec<Op> = parse_ops(cur)?;
    let try_catch: Vec<TryCatch> = if version >= 4 {
        parse_try_catch(cur, ops.len())?
    } else {
        Vec::new()
    };
    let child_count: u32 = cur.u32()?;
    if child_count > SANE_CHILD_CAP {
        return Err(Error::OpArrayFieldOversize {
            field: "children",
            value: child_count,
            cap: SANE_CHILD_CAP,
        });
    }
    ensure_count_fits(cur, child_count)?;
    let mut children: Vec<OpArray> = Vec::with_capacity((child_count as usize).min(MAX_PREALLOC));
    for _ in 0..child_count {
        children.push(parse_one(cur, version, depth + 1)?);
    }
    Ok(OpArray {
        kind,
        name,
        class_name,
        num_args,
        literals,
        ops,
        children,
        var_names,
        try_catch,
    })
}

fn parse_try_catch(cur: &mut Cursor<'_>, op_count: usize) -> Result<Vec<TryCatch>> {
    let count: u32 = cur.u32()?;
    if count > SANE_TRY_CATCH_CAP {
        return Err(Error::OpArrayFieldOversize {
            field: "try_catch",
            value: count,
            cap: SANE_TRY_CATCH_CAP,
        });
    }
    ensure_count_fits(cur, count)?;
    let bound: u32 = u32::try_from(op_count).unwrap_or(u32::MAX);
    let mut out: Vec<TryCatch> = Vec::with_capacity((count as usize).min(MAX_PREALLOC));
    for _ in 0..count {
        let try_op: u32 = cur.u32()?;
        let catch_op: u32 = cur.u32()?;
        let finally_op: u32 = cur.u32()?;
        let finally_end: u32 = cur.u32()?;
        if try_op >= bound {
            return Err(Error::OpArrayTryCatchRange {
                field: "try_op",
                value: try_op,
                ops: bound,
            });
        }
        out.push(TryCatch {
            try_op,
            catch_op: try_catch_boundary("catch_op", catch_op, bound)?,
            finally_op: try_catch_boundary("finally_op", finally_op, bound)?,
            finally_end: try_catch_boundary("finally_end", finally_end, bound)?,
        });
    }
    Ok(out)
}

fn try_catch_boundary(field: &'static str, value: u32, bound: u32) -> Result<Option<u32>> {
    if value == 0 {
        return Ok(None);
    }
    if value >= bound {
        return Err(Error::OpArrayTryCatchRange {
            field,
            value,
            ops: bound,
        });
    }
    Ok(Some(value))
}

fn parse_var_names(cur: &mut Cursor<'_>) -> Result<Vec<Option<String>>> {
    let count: u32 = cur.u32()?;
    if count > SANE_VAR_CAP {
        return Err(Error::OpArrayFieldOversize {
            field: "vars",
            value: count,
            cap: SANE_VAR_CAP,
        });
    }
    ensure_count_fits(cur, count)?;
    let mut out: Vec<Option<String>> = Vec::with_capacity((count as usize).min(MAX_PREALLOC));
    for _ in 0..count {
        out.push(read_opt_string(cur)?);
    }
    Ok(out)
}

fn read_opt_string(cur: &mut Cursor<'_>) -> Result<Option<String>> {
    let present: u8 = cur.u8()?;
    if present == 0 {
        return Ok(None);
    }
    Ok(Some(cur.string(SANE_NAME_CAP)?))
}

fn parse_literals(cur: &mut Cursor<'_>, version: u8) -> Result<Vec<Literal>> {
    let count: u32 = cur.u32()?;
    if count > SANE_LITERAL_CAP {
        return Err(Error::OpArrayFieldOversize {
            field: "literals",
            value: count,
            cap: SANE_LITERAL_CAP,
        });
    }
    ensure_count_fits(cur, count)?;
    let mut out: Vec<Literal> = Vec::with_capacity((count as usize).min(MAX_PREALLOC));
    for _ in 0..count {
        let tag: u8 = cur.u8()?;
        let lit: Literal = match tag {
            0 => Literal::Null,
            1 => Literal::Bool(cur.u8()? != 0),
            2 => Literal::Long(cur.i64()?),
            3 => Literal::Double(cur.f64()?),
            4 => Literal::Str(cur.string(SANE_NAME_CAP)?),
            5 => Literal::Array(cur.u32()?),
            6 if version >= 3 => Literal::SwitchLong(parse_switch_long(cur)?),
            7 if version >= 3 => Literal::SwitchString(parse_switch_string(cur)?),
            other => return Err(Error::OpArrayBadLiteralTag(other)),
        };
        out.push(lit);
    }
    Ok(out)
}

fn switch_table_count(cur: &mut Cursor<'_>, minimum_entry_size: usize) -> Result<u32> {
    let count: u32 = cur.u32()?;
    if count as usize > SANE_SWITCH_ARM_CAP {
        return Err(Error::OpArrayFieldOversize {
            field: "switch_table",
            value: count,
            cap: SANE_SWITCH_ARM_CAP as u32,
        });
    }
    let minimum_bytes: usize =
        (count as usize)
            .checked_mul(minimum_entry_size)
            .ok_or(Error::OpArrayFieldOversize {
                field: "switch_table_bytes",
                value: u32::MAX,
                cap: SANE_SWITCH_LABEL_WORK_CAP as u32,
            })?;
    cur.need(minimum_bytes)?;
    Ok(count)
}

fn parse_switch_long(cur: &mut Cursor<'_>) -> Result<Vec<(i64, u32)>> {
    let count: u32 = switch_table_count(cur, size_of::<i64>() + size_of::<u32>())?;
    let mut entries: Vec<(i64, u32)> = Vec::with_capacity((count as usize).min(MAX_PREALLOC));
    for _ in 0..count {
        entries.push((cur.i64()?, cur.u32()?));
    }
    Ok(entries)
}

fn parse_switch_string(cur: &mut Cursor<'_>) -> Result<Vec<(String, u32)>> {
    let count: u32 = switch_table_count(cur, size_of::<u32>() * 2)?;
    let mut entries: Vec<(String, u32)> = Vec::with_capacity((count as usize).min(MAX_PREALLOC));
    let mut work: usize = 0;
    for _ in 0..count {
        let key: String = cur.string(SANE_NAME_CAP)?;
        work =
            work.checked_add(key.len().saturating_add(1))
                .ok_or(Error::OpArrayFieldOversize {
                    field: "switch_table_work",
                    value: u32::MAX,
                    cap: SANE_SWITCH_LABEL_WORK_CAP as u32,
                })?;
        if work > SANE_SWITCH_LABEL_WORK_CAP {
            let value: u32 = u32::try_from(work).map_or(u32::MAX, |value: u32| value);
            return Err(Error::OpArrayFieldOversize {
                field: "switch_table_work",
                value,
                cap: SANE_SWITCH_LABEL_WORK_CAP as u32,
            });
        }
        entries.push((key, cur.u32()?));
    }
    Ok(entries)
}

fn parse_ops(cur: &mut Cursor<'_>) -> Result<Vec<Op>> {
    let count: u32 = cur.u32()?;
    if count > SANE_OP_CAP {
        return Err(Error::OpArrayFieldOversize {
            field: "ops",
            value: count,
            cap: SANE_OP_CAP,
        });
    }
    ensure_count_fits(cur, count)?;
    let mut out: Vec<Op> = Vec::with_capacity((count as usize).min(MAX_PREALLOC));
    for _ in 0..count {
        let opcode: u8 = cur.u8()?;
        let op1_type: OperandType = cur.operand_type()?;
        let op2_type: OperandType = cur.operand_type()?;
        let result_type: OperandType = cur.operand_type()?;
        let op1: u32 = cur.u32()?;
        let op2: u32 = cur.u32()?;
        let result: u32 = cur.u32()?;
        let extended_value: u32 = cur.u32()?;
        let lineno: u32 = cur.u32()?;
        out.push(Op {
            opcode,
            op1_type,
            op2_type,
            result_type,
            op1,
            op2,
            result,
            extended_value,
            lineno,
        });
    }
    Ok(out)
}

#[must_use]
pub fn build_cfg(ops: &[Op]) -> Cfg {
    if ops.is_empty() {
        return Cfg {
            blocks: Vec::new(),
            block_at: BTreeMap::new(),
        };
    }
    let n: u32 = ops.len() as u32;
    let mut leaders: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    leaders.insert(0);
    for (idx, op) in ops.iter().enumerate() {
        let i: u32 = idx as u32;
        match op.branch_target() {
            Branch::Uncond(t) => {
                if t < n {
                    leaders.insert(t);
                }
                if i + 1 < n {
                    leaders.insert(i + 1);
                }
            }
            Branch::Cond { taken, .. } => {
                if taken < n {
                    leaders.insert(taken);
                }
                if i + 1 < n {
                    leaders.insert(i + 1);
                }
            }
            Branch::Terminal => {
                if i + 1 < n {
                    leaders.insert(i + 1);
                }
            }
            Branch::None => {}
        }
    }
    let leader_vec: Vec<u32> = leaders.iter().copied().collect();
    let mut blocks: Vec<BasicBlock> = Vec::with_capacity(leader_vec.len());
    let mut block_at: BTreeMap<u32, usize> = BTreeMap::new();
    for (bi, &start) in leader_vec.iter().enumerate() {
        let end: u32 = leader_vec.get(bi + 1).copied().unwrap_or(n);
        block_at.insert(start, bi);
        blocks.push(BasicBlock {
            start,
            end,
            successors: Vec::new(),
        });
    }
    for block in &mut blocks {
        let last: u32 = block.end - 1;
        let op: &Op = &ops[last as usize];
        match op.branch_target() {
            Branch::Uncond(t) => {
                if t < n {
                    block.successors.push(t);
                }
            }
            Branch::Cond { taken, fallthrough } => {
                if taken < n {
                    block.successors.push(taken);
                }
                if fallthrough && block.end < n {
                    block.successors.push(block.end);
                }
            }
            Branch::Terminal => {}
            Branch::None => {
                if block.end < n {
                    block.successors.push(block.end);
                }
            }
        }
    }
    Cfg { blocks, block_at }
}

#[must_use]
pub fn decompile(root: &OpArray) -> Decompilation {
    let mut emitter: SkeletonEmitter = SkeletonEmitter::default();
    emitter.emit_oparray(root, 0);
    let (op_array_count, op_count, literal_count): (usize, usize, usize) = count_totals(root);
    let unrecovered: Vec<UnrecoveredOp> = std::mem::take(&mut emitter.unrecovered);
    let unrecovered_total: usize = emitter.unrecovered_total;
    let limitations: Vec<Limitation> = std::mem::take(&mut emitter.limitations);
    let limitations_total: usize = emitter.limitations_total;
    Decompilation {
        fidelity: Fidelity::Partial,
        php_skeleton: emitter.finish(),
        op_array_count,
        op_count,
        literal_count,
        unrecovered,
        unrecovered_total,
        limitations,
        limitations_total,
    }
}

fn count_totals(node: &OpArray) -> (usize, usize, usize) {
    let mut arrays: usize = 1;
    let mut ops: usize = node.ops.len();
    let mut lits: usize = node.literals.len();
    for child in &node.children {
        let (a, o, l): (usize, usize, usize) = count_totals(child);
        arrays += a;
        ops += o;
        lits += l;
    }
    (arrays, ops, lits)
}

#[derive(Default)]
struct SkeletonEmitter {
    out: String,
    emitted_open_tag: bool,
    unrecovered: Vec<UnrecoveredOp>,
    unrecovered_total: usize,
    limitations: Vec<Limitation>,
    limitations_total: usize,
}

impl SkeletonEmitter {
    fn finish(mut self) -> String {
        if !self.emitted_open_tag {
            self.out.insert_str(0, "<?php\n");
        }
        self.out
    }

    fn line(&mut self, indent: usize, text: &str) {
        for _ in 0..indent {
            self.out.push_str("    ");
        }
        self.out.push_str(text);
        self.out.push('\n');
    }

    fn emit_oparray(&mut self, node: &OpArray, indent: usize) {
        match node.kind {
            OpArrayKind::Main => {
                if !self.emitted_open_tag {
                    self.out.push_str("<?php\n");
                    self.emitted_open_tag = true;
                }
                self.emit_children_first(node, indent);
                self.emit_body(node, indent);
            }
            OpArrayKind::Function | OpArrayKind::Closure => {
                let sig: String = Self::function_signature(node);
                self.line(indent, &sig);
                self.line(indent, "{");
                self.emit_body(node, indent + 1);
                self.line(indent, "}");
                for child in &node.children {
                    if child.kind == OpArrayKind::Closure {
                        continue;
                    }
                    self.out.push('\n');
                    self.emit_oparray(child, indent);
                }
            }
            OpArrayKind::Method => {
                self.emit_class(&[node], indent);
            }
        }
    }

    fn emit_class(&mut self, methods: &[&OpArray], indent: usize) {
        let class: &str = methods
            .first()
            .and_then(|method: &&OpArray| method.class_name.as_deref())
            .unwrap_or("UnknownClass");
        self.line(indent, &format!("class {class}"));
        self.line(indent, "{");
        for (position, method) in methods.iter().enumerate() {
            if position > 0 {
                self.out.push('\n');
            }
            let sig: String = Self::method_signature(method);
            self.line(indent + 1, &sig);
            self.line(indent + 1, "{");
            self.emit_body(method, indent + 2);
            self.line(indent + 1, "}");
        }
        self.line(indent, "}");
    }

    fn emit_children_first(&mut self, node: &OpArray, indent: usize) {
        let mut classes: Vec<(&str, Vec<&OpArray>)> = Vec::new();
        for child in &node.children {
            if child.kind != OpArrayKind::Method {
                continue;
            }
            let class: &str = child.class_name.as_deref().unwrap_or("UnknownClass");
            match classes
                .iter_mut()
                .find(|(name, _): &&mut (&str, Vec<&OpArray>)| *name == class)
            {
                Some((_, methods)) => methods.push(child),
                None => classes.push((class, vec![child])),
            }
        }
        for (_, methods) in &classes {
            self.emit_class(methods, indent);
            self.out.push('\n');
        }
        for child in &node.children {
            if child.kind == OpArrayKind::Method || child.kind == OpArrayKind::Closure {
                continue;
            }
            self.emit_oparray(child, indent);
            self.out.push('\n');
        }
    }

    fn function_signature(node: &OpArray) -> String {
        let name: &str = node.name.as_deref().unwrap_or("{closure}");
        let params: String = Self::param_list(node);
        format!("function {name}({params})")
    }

    fn method_signature(node: &OpArray) -> String {
        let name: &str = node.name.as_deref().unwrap_or("method");
        let params: String = Self::param_list(node);
        format!("public function {name}({params})")
    }

    fn param_list(node: &OpArray) -> String {
        if node.num_args > SANE_VAR_CAP {
            return String::new();
        }
        let expected_position: Option<u32> = node.num_args.checked_add(1);
        let variadic: bool = node.ops.iter().any(|op: &Op| {
            op.opcode == op::RECV_VARIADIC
                && op.op1_type == OperandType::Unused
                && Some(op.op1) == expected_position
                && op.op2_type == OperandType::Unused
                && op.result_type == OperandType::Cv
                && op.result == node.num_args
        });
        let count: u32 = node.num_args.saturating_add(u32::from(variadic));
        if count == 0 {
            return String::new();
        }
        (0..count)
            .map(|i: u32| {
                let prefix: &str = if variadic && i == node.num_args {
                    "..."
                } else {
                    ""
                };
                format!("{prefix}${}", cv_name(i, &node.var_names))
            })
            .collect::<Vec<String>>()
            .join(", ")
    }

    fn emit_body(&mut self, node: &OpArray, indent: usize) {
        let mut lifter: Lifter<'_> = Lifter::new(
            &node.ops,
            &node.literals,
            &node.var_names,
            &node.try_catch,
            &node.children,
            node.num_args,
        );
        let stmts: Vec<Stmt> = lifter.lift();
        let container: String = Self::container_label(node);
        self.unrecovered_total = self.unrecovered_total.saturating_add(lifter.refused.len());
        let mut refused: Vec<(u32, u8, &'static str)> = std::mem::take(&mut lifter.unrecovered);
        refused.sort_unstable_by_key(|(index, _, _): &(u32, u8, &'static str)| *index);
        for (index, opcode, reason) in refused {
            if self.unrecovered.len() >= MAX_UNRECOVERED_RECORDS {
                break;
            }
            self.unrecovered.push(UnrecoveredOp {
                container: container.clone(),
                index,
                opcode,
                mnemonic: opcode_name(opcode).to_owned(),
                reason: reason.to_owned(),
            });
        }
        self.limitations_total = self.limitations_total.saturating_add(lifter.limited.len());
        let mut limited: Vec<(u32, u8, &'static str)> = std::mem::take(&mut lifter.limitations);
        limited.sort_unstable_by_key(|(index, _, _): &(u32, u8, &'static str)| *index);
        for (index, opcode, note) in limited {
            if self.limitations.len() >= MAX_UNRECOVERED_RECORDS {
                break;
            }
            self.limitations.push(Limitation {
                container: container.clone(),
                index,
                opcode,
                mnemonic: opcode_name(opcode).to_owned(),
                note: note.to_owned(),
            });
        }
        for stmt in &stmts {
            stmt.render_into(self, indent);
        }
    }

    fn container_label(node: &OpArray) -> String {
        match node.kind {
            OpArrayKind::Main => "$_main".to_owned(),
            OpArrayKind::Function => node
                .name
                .clone()
                .unwrap_or_else(|| "{anonymous function}".to_owned()),
            OpArrayKind::Closure => node.name.clone().unwrap_or_else(|| "{closure}".to_owned()),
            OpArrayKind::Method => format!(
                "{}::{}",
                node.class_name.as_deref().unwrap_or("UnknownClass"),
                node.name.as_deref().unwrap_or("method")
            ),
        }
    }
}

#[must_use]
fn cv_name(slot: u32, var_names: &[Option<String>]) -> String {
    match var_names.get(slot as usize) {
        Some(Some(name)) if is_valid_php_ident(name) => name.clone(),
        _ => format!("v{slot}"),
    }
}

#[must_use]
fn is_valid_php_ident(name: &str) -> bool {
    let mut chars: std::str::Chars<'_> = name.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c: char| c == '_' || c.is_ascii_alphanumeric())
}

#[must_use]
fn is_valid_php_qualified_name(name: &str) -> bool {
    let trimmed: &str = name.strip_prefix('\\').unwrap_or(name);
    !trimmed.is_empty() && !trimmed.starts_with('\\') && trimmed.split('\\').all(is_valid_php_ident)
}

#[derive(Debug, Clone)]
struct Expr {
    text: String,
    prec: u8,
}

const PREC_ATOM: u8 = 100;
const PREC_CALL: u8 = 90;
const PREC_POW: u8 = 80;
const PREC_MUL: u8 = 70;
const PREC_ADD: u8 = 60;
const PREC_SHIFT: u8 = 55;
const PREC_CONCAT: u8 = 52;
const PREC_REL: u8 = 51;
const PREC_CMP: u8 = 50;
const PREC_BITAND: u8 = 45;
const PREC_BITXOR: u8 = 44;
const PREC_BITOR: u8 = 43;
const PREC_COALESCE: u8 = 35;
const PREC_TERNARY: u8 = 30;
const PREC_UNARY: u8 = 78;
const PREC_INSTANCEOF: u8 = 75;

impl Expr {
    fn atom(text: String) -> Self {
        Self {
            text,
            prec: PREC_ATOM,
        }
    }

    fn wrapped(&self, parent_prec: u8) -> String {
        if self.prec < parent_prec {
            format!("({})", self.text)
        } else {
            self.text.clone()
        }
    }
}

#[derive(Debug)]
enum Stmt {
    Line(String),
    If {
        cond: String,
        then_body: Vec<Self>,
        else_body: Vec<Self>,
    },
    While {
        cond: String,
        body: Vec<Self>,
    },
    For {
        cond: String,
        step: Vec<String>,
        body: Vec<Self>,
    },
    DoWhile {
        cond: String,
        body: Vec<Self>,
    },
    Break(u32),
    Continue(u32),
    Foreach {
        subject: String,
        key: Option<String>,
        value: String,
        by_reference: bool,
        body: Vec<Self>,
    },
    Label(String),
    Closure {
        prefix: String,
        signature: String,
        body: Vec<Self>,
        suffix: String,
    },
    Switch {
        subject: String,
        arms: Vec<SwitchArm>,
    },
    Try {
        body: Vec<Self>,
        catches: Vec<CatchArm>,
        finally_body: Option<Vec<Self>>,
    },
}

#[derive(Debug)]
struct SwitchArm {
    labels: Vec<Option<String>>,
    body: Vec<Stmt>,
    breaks: bool,
}

#[derive(Debug)]
struct CatchArm {
    types: Vec<String>,
    variable: Option<String>,
    body: Vec<Stmt>,
}

impl Stmt {
    fn render_into(&self, emitter: &mut SkeletonEmitter, indent: usize) {
        match self {
            Self::Line(text) => emitter.line(indent, text),
            Self::If {
                cond,
                then_body,
                else_body,
            } => {
                emitter.line(indent, &format!("if ({cond}) {{"));
                for stmt in then_body {
                    stmt.render_into(emitter, indent + 1);
                }
                if !else_body.is_empty() {
                    emitter.line(indent, "} else {");
                    for stmt in else_body {
                        stmt.render_into(emitter, indent + 1);
                    }
                }
                emitter.line(indent, "}");
            }
            Self::Try {
                body,
                catches,
                finally_body,
            } => {
                emitter.line(indent, "try {");
                for stmt in body {
                    stmt.render_into(emitter, indent + 1);
                }
                for arm in catches {
                    let types: String = arm.types.join(" | ");
                    let header: String = arm.variable.as_ref().map_or_else(
                        || format!("}} catch ({types}) {{"),
                        |name: &String| format!("}} catch ({types} ${name}) {{"),
                    );
                    emitter.line(indent, &header);
                    for stmt in &arm.body {
                        stmt.render_into(emitter, indent + 1);
                    }
                }
                if let Some(finally_stmts) = finally_body {
                    emitter.line(indent, "} finally {");
                    for stmt in finally_stmts {
                        stmt.render_into(emitter, indent + 1);
                    }
                }
                emitter.line(indent, "}");
            }
            Self::While { cond, body } => {
                emitter.line(indent, &format!("while ({cond}) {{"));
                for stmt in body {
                    stmt.render_into(emitter, indent + 1);
                }
                emitter.line(indent, "}");
            }
            Self::For { cond, step, body } => {
                emitter.line(indent, &format!("for (; {cond}; {}) {{", step.join(", ")));
                for stmt in body {
                    stmt.render_into(emitter, indent + 1);
                }
                emitter.line(indent, "}");
            }
            Self::DoWhile { cond, body } => {
                emitter.line(indent, "do {");
                for stmt in body {
                    stmt.render_into(emitter, indent + 1);
                }
                emitter.line(indent, &format!("}} while ({cond});"));
            }
            Self::Break(level) => emitter.line(
                indent,
                &if *level > 1 {
                    format!("break {level};")
                } else {
                    "break;".to_owned()
                },
            ),
            Self::Continue(level) => emitter.line(
                indent,
                &if *level > 1 {
                    format!("continue {level};")
                } else {
                    "continue;".to_owned()
                },
            ),
            Self::Foreach {
                subject,
                key,
                value,
                by_reference,
                body,
            } => {
                let bound: String = if *by_reference {
                    format!("&{value}")
                } else {
                    value.clone()
                };
                let header: String = key.as_ref().map_or_else(
                    || format!("foreach ({subject} as {bound}) {{"),
                    |k: &String| format!("foreach ({subject} as {k} => {bound}) {{"),
                );
                emitter.line(indent, &header);
                for stmt in body {
                    stmt.render_into(emitter, indent + 1);
                }
                emitter.line(indent, "}");
            }
            Self::Label(label) => emitter.line(indent, &format!("{label}:")),
            Self::Closure {
                prefix,
                signature,
                body,
                suffix,
            } => {
                emitter.line(indent, &format!("{prefix}{signature} {{"));
                for stmt in body {
                    stmt.render_into(emitter, indent + 1);
                }
                emitter.line(indent, &format!("}}{suffix}"));
            }
            Self::Switch { subject, arms } => {
                emitter.line(indent, &format!("switch ({subject}) {{"));
                for arm in arms {
                    for label in &arm.labels {
                        emitter.line(
                            indent + 1,
                            &label.as_ref().map_or_else(
                                || "default:".to_owned(),
                                |value: &String| format!("case {value}:"),
                            ),
                        );
                    }
                    for stmt in &arm.body {
                        stmt.render_into(emitter, indent + 2);
                    }
                    if arm.breaks {
                        emitter.line(indent + 2, "break;");
                    }
                }
                emitter.line(indent, "}");
            }
        }
    }
}

#[derive(Clone)]
enum PendingArgument {
    Positional(String),
    Named { name: String, value: String },
    Unpacked(String),
}

impl PendingArgument {
    fn render(&self) -> String {
        match self {
            Self::Positional(value) => value.clone(),
            Self::Named { name, value } => format!("{name}: {value}"),
            Self::Unpacked(value) => format!("...{value}"),
        }
    }

    fn rendered_len(&self) -> usize {
        match self {
            Self::Positional(value) => value.len(),
            Self::Named { name, value } => name.len().saturating_add(value.len()).saturating_add(2),
            Self::Unpacked(value) => value.len().saturating_add(3),
        }
    }
}

#[derive(Clone)]
struct PendingCall {
    callee: String,
    is_method: bool,
    nullsafe: bool,
    object: Option<String>,
    is_static: bool,
    args: Vec<PendingArgument>,
    rendered_args: usize,
    positional_count: u32,
    result: Option<(OperandType, u32, u32)>,
    callable_shape: bool,
}

struct LiftSnapshot {
    entered_try: BTreeSet<usize>,
    slots: BTreeMap<(OperandType, u32), Expr>,
    call_stack: Vec<PendingCall>,
    reserved_names: BTreeSet<String>,
    writable_slots: BTreeMap<(OperandType, u32), u32>,
    refused: BTreeSet<u32>,
    unrecovered: Vec<(u32, u8, &'static str)>,
    goto_targets: BTreeSet<u32>,
    placed_labels: BTreeSet<u32>,
}

#[derive(Debug, Clone)]
struct BreakableFrame {
    body_start: u32,
    body_end: u32,
    continue_target: u32,
    break_target: u32,
    iterator: Option<(OperandType, u32)>,
    unexplained_targets: BTreeSet<u32>,
}

struct SwitchArmPlan {
    target: u32,
    body_end: u32,
    labels: Vec<Option<String>>,
    breaks: bool,
    terminates: bool,
}

struct SwitchDispatch {
    subject_key: (OperandType, u32),
    subject: String,
    labels_by_target: BTreeMap<u32, Vec<Option<String>>>,
    result_keys: BTreeSet<(OperandType, u32)>,
    default_target: u32,
    dispatch_end: u32,
}

struct DispatchLabels {
    by_target: BTreeMap<u32, Vec<Option<String>>>,
    work: usize,
}

struct CatchPlan {
    clause_start: u32,
    types: Vec<String>,
    variable: Option<String>,
    body_start: u32,
}

struct TryRegion {
    row: usize,
    try_start: u32,
    try_end: u32,
    catch_op: Option<u32>,
    catch_end: u32,
    finally_op: Option<u32>,
    finally_end: Option<u32>,
    construct_end: u32,
}

struct ListEntry {
    key: ListKey,
    value: ListValue,
}

struct ListKey {
    literal: u32,
    position: Option<usize>,
}

enum ListValue {
    Variable(String),
    Nested(Vec<ListEntry>),
}

struct Lifter<'a> {
    ops: &'a [Op],
    literals: &'a [Literal],
    var_names: &'a [Option<String>],
    try_catch: &'a [TryCatch],
    entered_try: BTreeSet<usize>,
    slots: BTreeMap<(OperandType, u32), Expr>,
    call_stack: Vec<PendingCall>,
    back_jump_targets: BTreeSet<u32>,
    result_use_counts: Vec<u32>,
    reserved_names: BTreeSet<String>,
    writable_slots: BTreeMap<(OperandType, u32), u32>,
    limitations: Vec<(u32, u8, &'static str)>,
    limited: BTreeSet<u32>,
    nullsafe_link: Option<(OperandType, u32)>,
    children: &'a [OpArray],
    num_args: u32,
    goto_targets: BTreeSet<u32>,
    placed_labels: BTreeSet<u32>,
    emit_gotos: bool,
    refused: BTreeSet<u32>,
    unrecovered: Vec<(u32, u8, &'static str)>,
    breakables: Vec<BreakableFrame>,
    relift_work: usize,
}

impl<'a> Lifter<'a> {
    fn new(
        ops: &'a [Op],
        literals: &'a [Literal],
        var_names: &'a [Option<String>],
        try_catch: &'a [TryCatch],
        children: &'a [OpArray],
        num_args: u32,
    ) -> Self {
        let back_jump_targets: BTreeSet<u32> = ops
            .iter()
            .filter_map(|op: &Op| {
                (op.opcode == op::JMPNZ || op.opcode == op::JMPNZ_EX || op.opcode == op::JMPZ)
                    .then_some(op.op2)
            })
            .collect();
        let mut live_uses: BTreeMap<(OperandType, u32), u32> = BTreeMap::new();
        let mut result_use_counts: Vec<u32> = vec![0; ops.len()];
        let reversed_ops: std::iter::Rev<std::iter::Enumerate<std::slice::Iter<'_, Op>>> =
            ops.iter().enumerate().rev();
        for (idx, op) in reversed_ops {
            let result_key: (OperandType, u32) = (op.result_type, op.result);
            if op.result_type == OperandType::TmpVar || op.result_type == OperandType::Var {
                result_use_counts[idx] = live_uses.remove(&result_key).unwrap_or(0);
            }
            if op.opcode != op::FREE {
                for key in [(op.op1_type, op.op1), (op.op2_type, op.op2)] {
                    if key.0 == OperandType::TmpVar || key.0 == OperandType::Var {
                        let count: &mut u32 = live_uses.entry(key).or_default();
                        *count = count.saturating_add(1);
                    }
                }
            }
        }
        let mut reserved_names: BTreeSet<String> = var_names
            .iter()
            .flatten()
            .filter(|name: &&String| is_valid_php_ident(name))
            .cloned()
            .collect();
        for op in ops {
            for key in [
                (op.op1_type, op.op1),
                (op.op2_type, op.op2),
                (op.result_type, op.result),
            ] {
                if key.0 == OperandType::TmpVar || key.0 == OperandType::Var {
                    reserved_names.insert(
                        slot_fallback(key.0, key.1)
                            .trim_start_matches('$')
                            .to_owned(),
                    );
                }
            }
        }
        Self {
            ops,
            literals,
            var_names,
            try_catch,
            entered_try: BTreeSet::new(),
            slots: BTreeMap::new(),
            call_stack: Vec::new(),
            back_jump_targets,
            result_use_counts,
            reserved_names,
            writable_slots: BTreeMap::new(),
            limitations: Vec::new(),
            limited: BTreeSet::new(),
            nullsafe_link: None,
            children,
            num_args,
            goto_targets: BTreeSet::new(),
            placed_labels: BTreeSet::new(),
            emit_gotos: false,
            refused: BTreeSet::new(),
            unrecovered: Vec::new(),
            breakables: Vec::new(),
            relift_work: 0,
        }
    }

    fn refuse(&mut self, idx: u32, opcode: u8, reason: &'static str) -> String {
        if self.refused.insert(idx) && self.unrecovered.len() < MAX_UNRECOVERED_RECORDS {
            self.unrecovered.push((idx, opcode, reason));
        }
        format!(
            "// disrobe: unrecovered {} at op {idx} ({reason})",
            opcode_name(opcode)
        )
    }

    fn limit(&mut self, idx: u32, opcode: u8, note: &'static str) {
        if self.limited.insert(idx) && self.limitations.len() < MAX_UNRECOVERED_RECORDS {
            self.limitations.push((idx, opcode, note));
        }
    }

    fn cv(&self, slot: u32) -> String {
        cv_name(slot, self.var_names)
    }

    fn lift(&mut self) -> Vec<Stmt> {
        let len: u32 = self.ops.len() as u32;
        self.record_opaque_literals(len);
        let structured: Vec<Stmt> = self.lift_range(0, len, 0);
        if self.goto_targets.is_empty() {
            return structured;
        }
        let targets: BTreeSet<u32> = std::mem::take(&mut self.goto_targets);
        let mut second: Lifter<'a> = Lifter::new(
            self.ops,
            self.literals,
            self.var_names,
            self.try_catch,
            self.children,
            self.num_args,
        );
        second.goto_targets.clone_from(&targets);
        second.emit_gotos = true;
        second.record_opaque_literals(len);
        let relabelled: Vec<Stmt> = second.lift_range(0, len, 0);
        let placed: BTreeSet<u32> = std::mem::take(&mut second.placed_labels);
        self.refused = std::mem::take(&mut second.refused);
        self.unrecovered = std::mem::take(&mut second.unrecovered);
        self.limitations = std::mem::take(&mut second.limitations);
        self.limited = std::mem::take(&mut second.limited);
        if placed == targets {
            return relabelled;
        }
        let unplaced: Option<u32> = targets.difference(&placed).copied().next();
        let marker: String = self.refuse(unplaced.unwrap_or_default(), op::JMP, REASON_GOTO_TARGET);
        vec![Stmt::Line(marker)]
    }

    fn goto_label(target: u32) -> String {
        format!("disrobe_label_{target}")
    }

    fn record_opaque_literals(&mut self, len: u32) {
        for idx in 0..len {
            let Some(op): Option<&Op> = self.ops.get(idx as usize) else {
                break;
            };
            if !Self::reads_opaque_array(op, self.literals) {
                continue;
            }
            let opcode: u8 = op.opcode;
            if self.limited.insert(idx) && self.limitations.len() < MAX_UNRECOVERED_RECORDS {
                self.limitations
                    .push((idx, opcode, LIMITATION_OPAQUE_ARRAY_LITERAL));
            }
        }
    }

    fn reads_opaque_array(op: &Op, literals: &[Literal]) -> bool {
        let operand = |ty: OperandType, value: u32| -> bool {
            ty == OperandType::Const
                && matches!(literals.get(value as usize), Some(Literal::Array(_)))
        };
        operand(op.op1_type, op.op1) || operand(op.op2_type, op.op2)
    }

    fn opaque_literal_marker(&self, idx: u32) -> Option<String> {
        let op: &Op = self.ops.get(idx as usize)?;
        if !Self::reads_opaque_array(op, self.literals) {
            return None;
        }
        Some(format!(
            "// disrobe: unverified {} at op {idx} ({LIMITATION_OPAQUE_ARRAY_LITERAL})",
            opcode_name(op.opcode)
        ))
    }

    fn lift_range(&mut self, start: u32, end: u32, depth: u32) -> Vec<Stmt> {
        let mut out: Vec<Stmt> = Vec::new();
        let mut i: u32 = start;
        while i < end {
            if depth < SANE_LIFT_DEPTH
                && let Some((stmt, next)) = self.try_structure(i, end, depth)
            {
                out.extend(stmt);
                i = next;
                continue;
            }
            if self.emit_gotos && self.goto_targets.contains(&i) {
                self.placed_labels.insert(i);
                out.push(Stmt::Label(Self::goto_label(i)));
            }
            let marker: Option<String> = self.opaque_literal_marker(i);
            let lifted: Option<String> = self.eval_op(i);
            if let Some(marker) = marker {
                out.push(Stmt::Line(marker));
            }
            if let Some(stmt) = lifted {
                out.push(Stmt::Line(stmt));
            }
            i += 1;
        }
        out
    }

    fn try_structure(&mut self, i: u32, end: u32, depth: u32) -> Option<(Vec<Stmt>, u32)> {
        if let Some(region) = self.try_region_at(i, end) {
            let row: usize = region.row;
            self.entered_try.insert(row);
            let structured: Option<(Vec<Stmt>, u32)> = self.structure_try(region, depth);
            if structured.is_none() {
                self.entered_try.remove(&row);
            } else {
                return structured;
            }
        }
        let op: &Op = self.ops.get(i as usize)?;
        match op.opcode {
            op::CASE | op::IS_EQUAL | op::SWITCH_LONG | op::SWITCH_STRING => {
                self.structure_switch(i, end, depth)
            }
            op::MATCH => self
                .structure_optimized_match(i, end)
                .or_else(|| self.refuse_optimized_match_region(i, end)),
            o if o == op::FETCH_LIST_R => self.fold_list_assign(i, end),
            o if o == op::ROPE_INIT => self.fold_rope(i, end),
            o if o == op::FE_RESET_R || o == op::FE_RESET_RW => {
                self.structure_foreach(i, end, depth)
            }
            o if o == op::JMPZ_EX || o == op::JMPNZ_EX => self.fold_short_circuit(i, end),
            o if o == op::COALESCE || o == op::JMP_SET => self.fold_default_join(i, end),
            o if o == op::JMP_NULL => self.fold_nullsafe_chain(i, end),
            o if o == op::DECLARE_LAMBDA_FUNCTION => self.fold_closure(i, end),
            o if o == op::JMP => {
                let structured: Option<(Vec<Stmt>, u32)> = self
                    .structure_while(i, end, depth)
                    .or_else(|| self.structure_loop_jump(i));
                if structured.is_none() {
                    self.record_unexplained_jump(i);
                }
                structured
            }
            o if o == op::JMPZ => self
                .structure_ternary(i, end)
                .or_else(|| self.structure_if(i, end, depth)),
            _ => self.structure_do_while(i, end, depth),
        }
    }

    fn try_region_at(&self, i: u32, end: u32) -> Option<TryRegion> {
        let mut best: Option<TryRegion> = None;
        for (row, entry) in self.try_catch.iter().enumerate() {
            if entry.try_op != i || self.entered_try.contains(&row) {
                continue;
            }
            let Some(region) = self.try_region(row, entry, end) else {
                continue;
            };
            if best
                .as_ref()
                .is_none_or(|held: &TryRegion| region.construct_end > held.construct_end)
            {
                best = Some(region);
            }
        }
        best
    }

    fn try_region(&self, row: usize, entry: &TryCatch, end: u32) -> Option<TryRegion> {
        let construct_end: u32 = if let Some(finally_end) = entry.finally_end {
            finally_end.checked_add(1)?
        } else {
            let catch_op: u32 = entry.catch_op?;
            let skip: &Op = self.ops.get(catch_op.checked_sub(1)? as usize)?;
            if skip.opcode != op::JMP {
                return None;
            }
            skip.op1
        };
        if construct_end > end || construct_end <= entry.try_op {
            return None;
        }
        let finally_gate: u32 = match entry.finally_op {
            Some(finally_op) => self.finally_trampoline(finally_op, construct_end)?,
            None => construct_end,
        };
        if let (Some(finally_op), Some(finally_end)) = (entry.finally_op, entry.finally_end)
            && (finally_end < finally_op
                || self.ops.get(finally_end as usize)?.opcode != op::FAST_RET)
        {
            return None;
        }
        let (try_end, catch_end): (u32, u32) = match entry.catch_op {
            Some(catch_op) => {
                if catch_op <= entry.try_op || catch_op > finally_gate {
                    return None;
                }
                let boundary: u32 = catch_op.checked_sub(1)?;
                let ends_with_skip: bool = self
                    .ops
                    .get(boundary as usize)
                    .is_some_and(|op: &Op| op.opcode == op::JMP);
                (
                    if ends_with_skip { boundary } else { catch_op },
                    finally_gate,
                )
            }
            None => (finally_gate, finally_gate),
        };
        Some(TryRegion {
            row,
            try_start: entry.try_op,
            try_end,
            catch_op: entry.catch_op,
            catch_end,
            finally_op: entry.finally_op,
            finally_end: entry.finally_end,
            construct_end,
        })
    }

    fn finally_trampoline(&self, finally_op: u32, construct_end: u32) -> Option<u32> {
        let jump_idx: u32 = finally_op.checked_sub(1)?;
        let jump: &Op = self.ops.get(jump_idx as usize)?;
        if jump.opcode != op::JMP || jump.op1 != construct_end {
            return None;
        }
        let call_idx: u32 = jump_idx.checked_sub(1)?;
        let call: &Op = self.ops.get(call_idx as usize)?;
        if call.opcode != op::FAST_CALL || call.op1 != finally_op {
            return None;
        }
        Some(call_idx)
    }

    fn structure_try(&mut self, region: TryRegion, depth: u32) -> Option<(Vec<Stmt>, u32)> {
        if !self.call_stack.is_empty() {
            return None;
        }
        let snapshot: LiftSnapshot = self.lift_snapshot();
        let body: Vec<Stmt> = self.lift_range(region.try_start, region.try_end, depth + 1);
        let catches: Vec<CatchArm> = if let Some(catch_op) = region.catch_op {
            if let Some(arms) = self.lift_catch_arms(catch_op, region.catch_end, depth) {
                arms
            } else {
                self.restore_lift_snapshot(snapshot);
                return None;
            }
        } else {
            Vec::new()
        };
        let finally_body: Option<Vec<Stmt>> = match (region.finally_op, region.finally_end) {
            (Some(finally_op), Some(finally_end)) => {
                Some(self.lift_range(finally_op, finally_end, depth + 1))
            }
            _ => None,
        };
        if catches.is_empty() && finally_body.is_none() {
            self.restore_lift_snapshot(snapshot);
            return None;
        }
        Some((
            vec![Stmt::Try {
                body,
                catches,
                finally_body,
            }],
            region.construct_end,
        ))
    }

    fn lift_catch_arms(
        &mut self,
        catch_op: u32,
        catch_end: u32,
        depth: u32,
    ) -> Option<Vec<CatchArm>> {
        let mut plans: Vec<CatchPlan> = Vec::new();
        let mut cursor: u32 = catch_op;
        while cursor < catch_end {
            if plans.len() >= SANE_CATCH_CLAUSE_CAP {
                return None;
            }
            let (plan, next): (CatchPlan, Option<u32>) = self.catch_clause(cursor, catch_end)?;
            plans.push(plan);
            match next {
                Some(target) if target > cursor && target < catch_end => cursor = target,
                Some(_) => return None,
                None => break,
            }
        }
        if plans.is_empty() {
            return None;
        }
        let mut arms: Vec<CatchArm> = Vec::with_capacity(plans.len());
        for index in 0..plans.len() {
            let limit: u32 = plans
                .get(index + 1)
                .map_or(catch_end, |next: &CatchPlan| next.clause_start);
            let plan: &CatchPlan = plans.get(index)?;
            let body_start: u32 = plan.body_start;
            let types: Vec<String> = plan.types.clone();
            let variable: Option<String> = plan.variable.clone();
            let clause_end: u32 = self.catch_body_end(body_start, limit)?;
            let body: Vec<Stmt> = self.lift_range(body_start, clause_end, depth + 1);
            arms.push(CatchArm {
                types,
                variable,
                body,
            });
        }
        Some(arms)
    }

    fn catch_clause(&self, start: u32, catch_end: u32) -> Option<(CatchPlan, Option<u32>)> {
        let mut types: Vec<String> = Vec::new();
        let mut variable: Option<String> = None;
        let mut cursor: u32 = start;
        loop {
            let entry: &Op = self.ops.get(cursor as usize)?;
            if entry.opcode != op::CATCH || types.len() >= SANE_CATCH_TYPE_CAP {
                return None;
            }
            let name: String = strip_quotes(&self.literal_string(entry.op1_type, entry.op1)?);
            if name.is_empty() {
                return None;
            }
            types.push(constant_reference(&name));
            if entry.result_type == OperandType::Cv {
                let bound: String = self.cv(entry.result);
                if variable
                    .as_ref()
                    .is_some_and(|held: &String| *held != bound)
                {
                    return None;
                }
                variable = Some(bound);
            }
            let follows: u32 = cursor.checked_add(1)?;
            if entry.extended_value == CATCH_LAST {
                if follows > catch_end {
                    return None;
                }
                return Some((
                    CatchPlan {
                        clause_start: start,
                        types,
                        variable,
                        body_start: follows,
                    },
                    None,
                ));
            }
            let alternate: u32 = entry.op2;
            if alternate <= cursor || alternate >= catch_end {
                return None;
            }
            let bridge: &Op = self.ops.get(follows as usize)?;
            if bridge.opcode == op::JMP {
                let body_start: u32 = bridge.op1;
                if body_start <= follows || body_start > catch_end {
                    return None;
                }
                if self.clause_shares_body(alternate, body_start) {
                    cursor = alternate;
                    continue;
                }
                return Some((
                    CatchPlan {
                        clause_start: start,
                        types,
                        variable,
                        body_start,
                    },
                    Some(alternate),
                ));
            }
            return Some((
                CatchPlan {
                    clause_start: start,
                    types,
                    variable,
                    body_start: follows,
                },
                Some(alternate),
            ));
        }
    }

    fn clause_shares_body(&self, alternate: u32, body_start: u32) -> bool {
        let Some(entry): Option<&Op> = self.ops.get(alternate as usize) else {
            return false;
        };
        if entry.opcode != op::CATCH {
            return false;
        }
        if alternate.saturating_add(1) == body_start {
            return true;
        }
        self.ops
            .get(alternate.saturating_add(1) as usize)
            .is_some_and(|bridge: &Op| bridge.opcode == op::JMP && bridge.op1 == body_start)
    }

    fn catch_body_end(&self, body_start: u32, limit: u32) -> Option<u32> {
        if body_start > limit {
            return None;
        }
        let last: u32 = limit.checked_sub(1)?;
        if last < body_start {
            return Some(body_start);
        }
        let tail: &Op = self.ops.get(last as usize)?;
        if tail.opcode == op::JMP {
            return Some(last);
        }
        Some(limit)
    }

    fn structure_switch(&mut self, i: u32, end: u32, depth: u32) -> Option<(Vec<Stmt>, u32)> {
        if !self.call_stack.is_empty() {
            return None;
        }
        let first: &Op = self.ops.get(i as usize)?;
        let dispatch: SwitchDispatch = match first.opcode {
            op::CASE | op::IS_EQUAL => self.linear_switch_dispatch(i, end)?,
            op::SWITCH_LONG | op::SWITCH_STRING => self.optimized_switch_dispatch(i, end)?,
            _ => return None,
        };
        self.structure_switch_dispatch(dispatch, end, depth)
    }

    fn linear_switch_dispatch(&self, i: u32, end: u32) -> Option<SwitchDispatch> {
        let first: &Op = self.ops.get(i as usize)?;
        if !matches!(
            first.op1_type,
            OperandType::Const | OperandType::Cv | OperandType::TmpVar | OperandType::Var
        ) {
            return None;
        }
        let subject_key: (OperandType, u32) = (first.op1_type, first.op1);
        let subject: String = self.defined_operand_expr(first.op1_type, first.op1)?.text;
        let comparison_opcode: u8 =
            if matches!(subject_key.0, OperandType::TmpVar | OperandType::Var) {
                op::CASE
            } else {
                op::IS_EQUAL
            };
        if begins_inside_switch_dispatch(self.ops, i as usize, comparison_opcode, subject_key) {
            return None;
        }
        let mut labels_by_target: BTreeMap<u32, Vec<Option<String>>> = BTreeMap::new();
        let mut result_keys: BTreeSet<(OperandType, u32)> = BTreeSet::new();
        let mut comparison_result: Option<(OperandType, u32)> = None;
        let mut last_case_target: Option<u32> = None;
        let mut label_slots: BTreeMap<(OperandType, u32), Expr> = self.slots.clone();
        let mut label_work: usize = 0;
        let mut cursor: u32 = i;
        let mut case_count: usize = 0;
        while cursor < end && case_count < SANE_SWITCH_ARM_CAP {
            while !is_linear_switch_comparison(
                self.ops,
                cursor as usize,
                comparison_opcode,
                subject_key,
            ) {
                let producer: &Op = self.ops.get(cursor as usize)?;
                if producer.opcode == op::JMP {
                    break;
                }
                let (result_key, expression): ((OperandType, u32), Expr) =
                    self.evaluate_switch_label_op(producer, &label_slots)?;
                let expression_work: usize = expression.text.len().checked_add(1)?;
                label_work = switch_label_work_after(label_work, expression_work)?;
                label_slots.insert(result_key, expression);
                cursor = cursor.checked_add(1)?;
            }
            let comparison: &Op = self.ops.get(cursor as usize)?;
            if comparison.opcode != comparison_opcode {
                break;
            }
            if (comparison.op1_type, comparison.op1) != subject_key
                || comparison.result_type != OperandType::TmpVar
            {
                return None;
            }
            let result_key: (OperandType, u32) = (comparison.result_type, comparison.result);
            if comparison_result.is_some_and(|expected: (OperandType, u32)| expected != result_key)
            {
                return None;
            }
            comparison_result = Some(result_key);
            let jump_index: u32 = cursor.checked_add(1)?;
            let jump: &Op = self.ops.get(jump_index as usize)?;
            if jump.opcode != op::JMPNZ
                || (jump.op1_type, jump.op1) != (comparison.result_type, comparison.result)
                || jump.op2_type != OperandType::Unused
                || jump.result_type != OperandType::Unused
                || jump.op2 <= jump_index
                || jump.op2 >= end
                || last_case_target.is_some_and(|target: u32| jump.op2 < target)
            {
                return None;
            }
            let label: String = self
                .switch_operand_expr(comparison.op2_type, comparison.op2, &label_slots)?
                .text;
            let retained_work: usize = label.len().checked_add(1)?;
            label_work = switch_label_work_after(label_work, retained_work)?;
            labels_by_target
                .entry(jump.op2)
                .or_default()
                .push(Some(label));
            result_keys.insert(result_key);
            last_case_target = Some(jump.op2);
            case_count = case_count.checked_add(1)?;
            cursor = cursor.checked_add(2)?;
        }
        if case_count == 0 {
            return None;
        }
        let default_jump: &Op = self.ops.get(cursor as usize)?;
        if default_jump.opcode != op::JMP || default_jump.op1 <= cursor || default_jump.op1 >= end {
            return None;
        }
        let default_target: u32 = default_jump.op1;
        Some(SwitchDispatch {
            subject_key,
            subject,
            labels_by_target,
            result_keys,
            default_target,
            dispatch_end: cursor.checked_add(1)?,
        })
    }

    fn optimized_switch_dispatch(&self, i: u32, end: u32) -> Option<SwitchDispatch> {
        let first: &Op = self.ops.get(i as usize)?;
        if !matches!(
            first.op1_type,
            OperandType::Const | OperandType::Cv | OperandType::TmpVar | OperandType::Var
        ) || first.op2_type != OperandType::Const
            || first.result_type != OperandType::Unused
        {
            return None;
        }
        let subject_key: (OperandType, u32) = (first.op1_type, first.op1);
        let subject: String = self.defined_operand_expr(first.op1_type, first.op1)?.text;
        let DispatchLabels {
            by_target: labels_by_target,
            work: _,
        }: DispatchLabels = self.optimized_dispatch_labels(first.opcode, first.op2, i, end)?;
        let default_target: u32 = first.extended_value;
        if default_target <= i || default_target >= end {
            return None;
        }
        Some(SwitchDispatch {
            subject_key,
            subject,
            labels_by_target,
            result_keys: BTreeSet::new(),
            default_target,
            dispatch_end: i.checked_add(1)?,
        })
    }

    fn optimized_dispatch_labels(
        &self,
        opcode: u8,
        literal: u32,
        i: u32,
        end: u32,
    ) -> Option<DispatchLabels> {
        let mut labels_by_target: BTreeMap<u32, Vec<Option<String>>> = BTreeMap::new();
        let mut seen_long: BTreeSet<i64> = BTreeSet::new();
        let mut seen_string: BTreeSet<&str> = BTreeSet::new();
        let mut work: usize = 0;
        match (opcode, self.literals.get(literal as usize)?) {
            (op::SWITCH_LONG | op::MATCH, Literal::SwitchLong(entries)) => {
                if entries.is_empty() || entries.len() > SANE_SWITCH_ARM_CAP {
                    return None;
                }
                for &(key, target) in entries {
                    if !seen_long.insert(key) || target <= i || target >= end {
                        return None;
                    }
                    let label: String = key.to_string();
                    work = switch_label_work_after(work, label.len().checked_add(1)?)?;
                    labels_by_target
                        .entry(target)
                        .or_default()
                        .push(Some(label));
                }
            }
            (op::SWITCH_STRING | op::MATCH, Literal::SwitchString(entries)) => {
                if entries.is_empty() || entries.len() > SANE_SWITCH_ARM_CAP {
                    return None;
                }
                for (key, target) in entries {
                    if !seen_string.insert(key.as_str()) || *target <= i || *target >= end {
                        return None;
                    }
                    let label: String = Literal::Str(key.clone()).render();
                    work = switch_label_work_after(work, label.len().checked_add(1)?)?;
                    labels_by_target
                        .entry(*target)
                        .or_default()
                        .push(Some(label));
                }
            }
            _ => return None,
        }
        Some(DispatchLabels {
            by_target: labels_by_target,
            work,
        })
    }

    fn structure_optimized_match(&mut self, i: u32, end: u32) -> Option<(Vec<Stmt>, u32)> {
        if !self.call_stack.is_empty() {
            return None;
        }
        let dispatch: &Op = self.ops.get(i as usize)?;
        if !matches!(
            dispatch.op1_type,
            OperandType::Const | OperandType::Cv | OperandType::TmpVar | OperandType::Var
        ) || dispatch.op2_type != OperandType::Const
            || dispatch.result_type != OperandType::Unused
        {
            return None;
        }
        let subject_key: (OperandType, u32) = (dispatch.op1_type, dispatch.op1);
        let subject: Expr = self.defined_operand_expr(dispatch.op1_type, dispatch.op1)?;
        let DispatchLabels {
            by_target: mut labels_by_target,
            work: label_work,
        }: DispatchLabels =
            self.optimized_dispatch_labels(dispatch.opcode, dispatch.op2, i, end)?;
        let label_count: usize = labels_by_target.values().map(Vec::len).sum();
        let label_separator_work: usize = label_count.checked_mul(2)?;
        let mut work: usize = switch_label_work_after(label_work, label_separator_work)?;
        work = switch_label_work_after(work, subject.text.len().checked_add(12)?)?;
        let default_target: u32 = dispatch.extended_value;
        if default_target <= i
            || default_target >= end
            || labels_by_target.contains_key(&default_target)
        {
            return None;
        }
        labels_by_target.insert(default_target, vec![None]);
        let targets: Vec<u32> = labels_by_target.keys().copied().collect();
        if targets.first().copied()? != i.checked_add(1)? {
            return None;
        }
        for pair in targets.windows(2) {
            let left: u32 = *pair.first()?;
            let right: u32 = *pair.get(1)?;
            if left.checked_add(2)? != right {
                return None;
            }
        }
        let mut arms: Vec<(Vec<Option<String>>, Expr)> = Vec::with_capacity(targets.len());
        let mut result_key: Option<(OperandType, u32)> = None;
        let mut join: Option<u32> = None;
        for target in targets {
            let producer: &Op = self.ops.get(target as usize)?;
            if producer.opcode != op::QM_ASSIGN
                || !matches!(producer.op1_type, OperandType::Const | OperandType::Cv)
                || producer.op2_type != OperandType::Unused
                || producer.result_type != OperandType::TmpVar
            {
                return None;
            }
            let candidate_result: (OperandType, u32) = (producer.result_type, producer.result);
            if candidate_result == subject_key
                || result_key
                    .is_some_and(|expected: (OperandType, u32)| expected != candidate_result)
            {
                return None;
            }
            result_key = Some(candidate_result);
            let expression: Expr =
                self.switch_operand_expr(producer.op1_type, producer.op1, &self.slots)?;
            work = switch_label_work_after(work, expression.text.len().checked_add(7)?)?;
            let jump_index: u32 = target.checked_add(1)?;
            let jump: &Op = self.ops.get(jump_index as usize)?;
            if jump.opcode != op::JMP
                || jump.op1_type != OperandType::Unused
                || jump.op2_type != OperandType::Unused
                || jump.result_type != OperandType::Unused
                || jump.op1 <= jump_index
                || jump.op1 >= end
                || join.is_some_and(|expected: u32| expected != jump.op1)
            {
                return None;
            }
            join = Some(jump.op1);
            arms.push((labels_by_target.remove(&target)?, expression));
        }
        let join: u32 = join?;
        if join
            != i.checked_add(1)?
                .checked_add(u32::try_from(arms.len()).ok()?.checked_mul(2)?)?
        {
            return None;
        }
        let mut rendered_arms: Vec<String> = Vec::with_capacity(arms.len());
        for (labels, expression) in arms {
            let label: String = if labels == [None] {
                "default".to_owned()
            } else {
                labels
                    .into_iter()
                    .collect::<Option<Vec<String>>>()?
                    .join(", ")
            };
            rendered_arms.push(format!("{label} => {}", expression.text));
        }
        let expression: Expr = Expr::atom(format!(
            "match ({}) {{ {} }}",
            subject.text,
            rendered_arms.join(", ")
        ));
        let result_key: (OperandType, u32) = result_key?;
        self.slots.insert(result_key, expression);
        if matches!(subject_key.0, OperandType::TmpVar | OperandType::Var) {
            self.slots.remove(&subject_key);
            self.writable_slots.remove(&subject_key);
        }
        Some((Vec::new(), join))
    }

    fn refuse_optimized_match_region(&mut self, i: u32, end: u32) -> Option<(Vec<Stmt>, u32)> {
        let dispatch: &Op = self.ops.get(i as usize)?;
        if dispatch.opcode != op::MATCH {
            return None;
        }
        let mut cursor: u32 = i.checked_add(1)?;
        let mut count: usize = 0;
        let mut jump_targets: Vec<u32> = Vec::new();
        while count < SANE_SWITCH_ARM_CAP {
            let Some(producer): Option<&Op> = self.ops.get(cursor as usize) else {
                break;
            };
            if producer.opcode != op::QM_ASSIGN {
                break;
            }
            let jump_index: u32 = cursor.checked_add(1)?;
            let jump: &Op = self.ops.get(jump_index as usize)?;
            if jump.opcode != op::JMP {
                break;
            }
            count = count.checked_add(1)?;
            jump_targets.push(jump.op1);
            cursor = cursor.checked_add(2)?;
        }
        let forward_join_count: usize = jump_targets
            .iter()
            .filter(|target: &&u32| **target == cursor)
            .count();
        if count == 0
            || cursor > end
            || forward_join_count <= count.checked_div(2)?
            || self.ops.get(cursor as usize).is_none()
        {
            return None;
        }
        let refusal: String = self.refuse(i, dispatch.opcode, REASON_OPTIMIZED_MATCH);
        Some((vec![Stmt::Line(refusal)], cursor))
    }

    fn structure_switch_dispatch(
        &mut self,
        dispatch: SwitchDispatch,
        end: u32,
        depth: u32,
    ) -> Option<(Vec<Stmt>, u32)> {
        let SwitchDispatch {
            subject_key,
            subject,
            mut labels_by_target,
            result_keys,
            default_target,
            dispatch_end,
        }: SwitchDispatch = dispatch;
        let case_targets: Vec<u32> = labels_by_target.keys().copied().collect();
        let explicit_default_join: bool = case_targets.last().is_some_and(|last: &u32| {
            default_target > *last
                && case_targets.iter().copied().enumerate().any(
                    |(target_index, target): (usize, u32)| {
                        let boundary: u32 = case_targets
                            .get(target_index + 1)
                            .copied()
                            .unwrap_or(default_target);
                        boundary > target
                            && self.ops.get((boundary - 1) as usize).is_some_and(
                                |terminator: &Op| {
                                    terminator.opcode == op::JMP && terminator.op1 == default_target
                                },
                            )
                    },
                )
        });
        let default_has_forward_break: bool = (default_target..end)
            .find_map(|index: u32| {
                self.ops.get(index as usize).and_then(|candidate: &Op| {
                    (candidate.branch_target() != Branch::None).then_some((index, candidate))
                })
            })
            .is_some_and(|(index, candidate): (u32, &Op)| {
                candidate.opcode == op::JMP && candidate.op1 > index
            });
        let natural_default_join: bool = case_targets.last().is_some_and(|last: &u32| {
            default_target > *last
                && !default_has_forward_break
                && (*last..default_target).all(|index: u32| {
                    self.ops
                        .get(index as usize)
                        .is_some_and(|candidate: &Op| candidate.branch_target() == Branch::None)
                })
        });
        let default_is_join: bool = explicit_default_join || natural_default_join;
        if !default_is_join {
            labels_by_target
                .entry(default_target)
                .or_default()
                .push(None);
        }
        if labels_by_target
            .keys()
            .any(|target: &u32| *target < dispatch_end)
        {
            return None;
        }
        let targets: Vec<u32> = labels_by_target.keys().copied().collect();
        let max_target: u32 = *targets.last()?;
        let mut join: Option<u32> = default_is_join.then_some(default_target);
        for target_index in 1..targets.len() {
            let boundary: u32 = targets.get(target_index)?.checked_sub(1)?;
            if self.exits_enclosing_loop(boundary) {
                continue;
            }
            let terminator: &Op = self.ops.get(boundary as usize)?;
            if terminator.opcode == op::JMP && terminator.op1 > max_target && terminator.op1 <= end
            {
                match join {
                    Some(existing) if existing != terminator.op1 => return None,
                    Some(_) => {}
                    None => join = Some(terminator.op1),
                }
            }
        }
        if join.is_none() && !default_is_join {
            let mut scan: u32 = max_target;
            while scan < end {
                let candidate: &Op = self.ops.get(scan as usize)?;
                if candidate.opcode == op::JMP {
                    if candidate.op1 <= scan || candidate.op1 > end {
                        return None;
                    }
                    join = Some(candidate.op1);
                    break;
                }
                if is_switch_terminal(candidate.opcode) {
                    join = scan.checked_add(1);
                    break;
                }
                if candidate.branch_target() != Branch::None {
                    return None;
                }
                scan = scan.checked_add(1)?;
            }
        }
        let join: u32 = join?;
        let next: u32 = if matches!(subject_key.0, OperandType::TmpVar | OperandType::Var) {
            let free: &Op = self.ops.get(join as usize)?;
            if free.opcode != op::FREE
                || (free.op1_type, free.op1) != subject_key
                || !matches!(
                    free.extended_value_provenance(),
                    ExtendedValueProvenance::Known(2) | ExtendedValueProvenance::Unavailable
                )
            {
                return None;
            }
            join.checked_add(1)?
        } else {
            join
        };
        let incoming_slots: BTreeMap<(OperandType, u32), Expr> = self.slots.clone();
        let incoming_writable: BTreeMap<(OperandType, u32), u32> = self.writable_slots.clone();
        if !switch_state_work_within_budget(
            targets.len(),
            incoming_slots.len(),
            incoming_writable.len(),
        ) {
            return None;
        }
        let mut arm_plans: Vec<SwitchArmPlan> = Vec::with_capacity(targets.len());
        for (target_index, target) in targets.iter().copied().enumerate() {
            let boundary: u32 = targets.get(target_index + 1).copied().unwrap_or(join);
            if boundary <= target || boundary > join {
                return None;
            }
            let terminal_index: u32 = boundary.checked_sub(1)?;
            let exits_loop: bool = self.exits_enclosing_loop(terminal_index);
            let terminal: &Op = self.ops.get(terminal_index as usize)?;
            let breaks: bool = !exits_loop && terminal.opcode == op::JMP && terminal.op1 == join;
            let terminates: bool = !breaks && (exits_loop || is_switch_terminal(terminal.opcode));
            let body_end: u32 = if breaks { terminal_index } else { boundary };
            arm_plans.push(SwitchArmPlan {
                target,
                body_end,
                labels: labels_by_target.remove(&target)?,
                breaks,
                terminates,
            });
        }
        let snapshot: LiftSnapshot = self.lift_snapshot();
        let mut fallthrough_slots: Option<BTreeMap<(OperandType, u32), Expr>> = None;
        let mut fallthrough_writable: Option<BTreeMap<(OperandType, u32), u32>> = None;
        let mut exit_slots: Vec<BTreeMap<(OperandType, u32), Expr>> = if default_is_join {
            vec![incoming_slots.clone()]
        } else {
            Vec::new()
        };
        let mut exit_writable: Vec<BTreeMap<(OperandType, u32), u32>> = if default_is_join {
            vec![incoming_writable.clone()]
        } else {
            Vec::new()
        };
        let mut arms: Vec<SwitchArm> = Vec::with_capacity(targets.len());
        for arm_plan in arm_plans {
            self.slots = fallthrough_slots.as_ref().map_or_else(
                || incoming_slots.clone(),
                |prior: &BTreeMap<(OperandType, u32), Expr>| {
                    Self::common_slots(&incoming_slots, prior)
                },
            );
            self.writable_slots = fallthrough_writable.as_ref().map_or_else(
                || incoming_writable.clone(),
                |prior: &BTreeMap<(OperandType, u32), u32>| {
                    Self::common_writable_slots(&incoming_writable, prior)
                },
            );
            let (body, _): (Vec<Stmt>, BTreeSet<u32>) = self.lift_breakable_body(
                BreakableFrame {
                    body_start: arm_plan.target,
                    body_end: arm_plan.body_end,
                    continue_target: join,
                    break_target: join,
                    iterator: None,
                    unexplained_targets: BTreeSet::new(),
                },
                depth,
            );
            if !self.call_stack.is_empty() {
                self.restore_lift_snapshot(snapshot);
                return None;
            }
            if arm_plan.breaks {
                exit_slots.push(self.slots.clone());
                exit_writable.push(self.writable_slots.clone());
                fallthrough_slots = None;
                fallthrough_writable = None;
            } else if arm_plan.terminates {
                fallthrough_slots = None;
                fallthrough_writable = None;
            } else {
                fallthrough_slots = Some(self.slots.clone());
                fallthrough_writable = Some(self.writable_slots.clone());
                if arm_plan.body_end == join {
                    exit_slots.push(self.slots.clone());
                    exit_writable.push(self.writable_slots.clone());
                }
            }
            arms.push(SwitchArm {
                labels: arm_plan.labels,
                body,
                breaks: arm_plan.breaks,
            });
        }
        let mut merged_slots: BTreeMap<(OperandType, u32), Expr> =
            exit_slots.first().cloned().unwrap_or_default();
        for state in exit_slots.iter().skip(1) {
            merged_slots = Self::common_slots(&merged_slots, state);
        }
        let mut merged_writable: BTreeMap<(OperandType, u32), u32> =
            exit_writable.first().cloned().unwrap_or_default();
        for state in exit_writable.iter().skip(1) {
            merged_writable = Self::common_writable_slots(&merged_writable, state);
        }
        for result_key in result_keys {
            merged_slots.remove(&result_key);
            merged_writable.remove(&result_key);
        }
        if matches!(subject_key.0, OperandType::TmpVar | OperandType::Var) {
            merged_slots.remove(&subject_key);
            merged_writable.remove(&subject_key);
        }
        self.slots = merged_slots;
        self.writable_slots = merged_writable;
        Some((vec![Stmt::Switch { subject, arms }], next))
    }

    fn lift_snapshot(&self) -> LiftSnapshot {
        LiftSnapshot {
            entered_try: self.entered_try.clone(),
            slots: self.slots.clone(),
            call_stack: self.call_stack.clone(),
            reserved_names: self.reserved_names.clone(),
            writable_slots: self.writable_slots.clone(),
            refused: self.refused.clone(),
            unrecovered: self.unrecovered.clone(),
            goto_targets: self.goto_targets.clone(),
            placed_labels: self.placed_labels.clone(),
        }
    }

    fn restore_lift_snapshot(&mut self, snapshot: LiftSnapshot) {
        self.entered_try = snapshot.entered_try;
        self.slots = snapshot.slots;
        self.call_stack = snapshot.call_stack;
        self.reserved_names = snapshot.reserved_names;
        self.writable_slots = snapshot.writable_slots;
        self.refused = snapshot.refused;
        self.unrecovered = snapshot.unrecovered;
        self.goto_targets = snapshot.goto_targets;
        self.placed_labels = snapshot.placed_labels;
    }

    fn evaluate_switch_label_op(
        &self,
        producer: &Op,
        slots: &BTreeMap<(OperandType, u32), Expr>,
    ) -> Option<((OperandType, u32), Expr)> {
        if producer.result_type != OperandType::TmpVar {
            return None;
        }
        let result_key: (OperandType, u32) = (producer.result_type, producer.result);
        let expression: Expr = if is_binary(producer.opcode) {
            let lhs: Expr = self.switch_operand_expr(producer.op1_type, producer.op1, slots)?;
            let rhs: Expr = self.switch_operand_expr(producer.op2_type, producer.op2, slots)?;
            let (symbol, precedence): (&str, u8) = binary_symbol(producer.opcode);
            let (left_precedence, right_precedence): (u8, u8) =
                if is_right_associative(producer.opcode) {
                    (precedence + 1, precedence)
                } else {
                    (precedence, precedence + 1)
                };
            Expr {
                text: format!(
                    "{} {symbol} {}",
                    lhs.wrapped(left_precedence),
                    rhs.wrapped(right_precedence)
                ),
                prec: precedence,
            }
        } else if producer.opcode == op::BOOL_NOT {
            let value: Expr = self.switch_operand_expr(producer.op1_type, producer.op1, slots)?;
            Expr {
                text: format!("!{}", value.wrapped(PREC_CALL)),
                prec: PREC_CALL,
            }
        } else if producer.opcode == op::BOOL || producer.opcode == op::QM_ASSIGN {
            self.switch_operand_expr(producer.op1_type, producer.op1, slots)?
        } else if producer.opcode == op::CAST {
            let symbol: &'static str = cast_symbol(producer.extended_value)?;
            let value: Expr = self.switch_operand_expr(producer.op1_type, producer.op1, slots)?;
            Expr {
                text: format!("{symbol} {}", value.wrapped(PREC_UNARY)),
                prec: PREC_UNARY,
            }
        } else {
            return None;
        };
        Some((result_key, expression))
    }

    fn switch_operand_expr(
        &self,
        ty: OperandType,
        value: u32,
        slots: &BTreeMap<(OperandType, u32), Expr>,
    ) -> Option<Expr> {
        match ty {
            OperandType::Unused => None,
            OperandType::Const => self
                .literals
                .get(value as usize)
                .map(Literal::render)
                .map(Expr::atom),
            OperandType::Cv => Some(Expr::atom(format!("${}", self.cv(value)))),
            OperandType::TmpVar | OperandType::Var => slots.get(&(ty, value)).cloned(),
        }
    }

    fn structure_do_while(&mut self, i: u32, end: u32, depth: u32) -> Option<(Vec<Stmt>, u32)> {
        let jump_idx: u32 = self.find_back_jump(i, end)?;
        let jump: Op = self.ops.get(jump_idx as usize)?.clone();
        let negate: bool = jump.opcode == op::JMPZ;
        let cond_start: u32 = self.condition_start(&jump, i, jump_idx);
        let (body, _): (Vec<Stmt>, BTreeSet<u32>) = self.lift_breakable_body(
            BreakableFrame {
                body_start: i,
                body_end: cond_start,
                continue_target: cond_start,
                break_target: jump_idx + 1,
                iterator: None,
                unexplained_targets: BTreeSet::new(),
            },
            depth,
        );
        let cond_expr: Expr = self.lift_condition(cond_start, jump_idx, &jump)?;
        let cond_text: String = if negate {
            format!("!({})", cond_expr.wrapped(PREC_CALL))
        } else {
            cond_expr.text
        };
        Some((
            vec![Stmt::DoWhile {
                cond: cond_text,
                body,
            }],
            jump_idx + 1,
        ))
    }

    fn find_back_jump(&self, body_start: u32, end: u32) -> Option<u32> {
        if !self.back_jump_targets.contains(&body_start) {
            return None;
        }
        let mut k: u32 = body_start;
        while k < end {
            let op: &Op = self.ops.get(k as usize)?;
            match op.opcode {
                o if (o == op::JMPNZ || o == op::JMPNZ_EX || o == op::JMPZ)
                    && op.op2 == body_start
                    && k > body_start =>
                {
                    return Some(k);
                }
                o if o == op::JMP && op.op1 <= body_start && k > body_start => return None,
                o if o == op::FE_RESET_R || o == op::FE_RESET_RW => return None,
                _ => {}
            }
            k += 1;
        }
        None
    }

    fn condition_start(&self, jump: &Op, lower: u32, jump_idx: u32) -> u32 {
        if jump.op1_type != OperandType::TmpVar && jump.op1_type != OperandType::Var {
            return jump_idx;
        }
        let mut k: u32 = jump_idx;
        while k > lower {
            k -= 1;
            let op: &Op = match self.ops.get(k as usize) {
                Some(o) => o,
                None => return jump_idx,
            };
            if op.result_type == jump.op1_type && op.result == jump.op1 {
                return k;
            }
        }
        jump_idx
    }

    fn fold_short_circuit(&mut self, i: u32, end: u32) -> Option<(Vec<Stmt>, u32)> {
        let gate: Op = self.ops.get(i as usize)?.clone();
        let join: u32 = gate.op2;
        if join <= i || join > end {
            return None;
        }
        let result_key: (OperandType, u32) = (gate.result_type, gate.result);
        let lhs: Expr = self.operand_expr(gate.op1_type, gate.op1)?;
        let incoming_slots: BTreeMap<(OperandType, u32), Expr> = self.slots.clone();
        let incoming_writable: BTreeMap<(OperandType, u32), u32> = self.writable_slots.clone();
        let connector: &str = if gate.opcode == op::JMPZ_EX {
            "&&"
        } else {
            "||"
        };
        let mut k: u32 = i + 1;
        while k < join {
            self.eval_op(k);
            k += 1;
        }
        let rhs: Expr = self
            .slots
            .get(&result_key)
            .cloned()
            .unwrap_or_else(|| Expr::atom("true".to_owned()));
        let text: String = format!(
            "{} {} {}",
            lhs.wrapped(PREC_CMP),
            connector,
            rhs.wrapped(PREC_CMP)
        );
        self.slots = Self::common_slots(&incoming_slots, &self.slots);
        self.writable_slots = Self::common_writable_slots(&incoming_writable, &self.writable_slots);
        self.writable_slots.remove(&result_key);
        self.slots.insert(
            result_key,
            Expr {
                text,
                prec: if connector == "&&" {
                    PREC_BITAND
                } else {
                    PREC_BITOR
                },
            },
        );
        Some((Vec::new(), join))
    }

    fn fold_closure(&self, i: u32, end: u32) -> Option<(Vec<Stmt>, u32)> {
        let declare: Op = self.ops.get(i as usize)?.clone();
        if declare.result_type != OperandType::TmpVar {
            return None;
        }
        let slot: (OperandType, u32) = (declare.result_type, declare.result);
        let child: &OpArray = self
            .children
            .iter()
            .filter(|node: &&OpArray| node.kind == OpArrayKind::Closure)
            .nth(declare.extended_value as usize)?;
        let mut uses: Vec<String> = Vec::new();
        let mut cursor: u32 = i.saturating_add(1);
        while cursor < end {
            let bind: &Op = self.ops.get(cursor as usize)?;
            if bind.opcode != op::BIND_LEXICAL {
                break;
            }
            if (bind.op1_type, bind.op1) != slot || bind.op2_type != OperandType::Cv {
                return None;
            }
            uses.push(format!("${}", self.cv(bind.op2)));
            if uses.len() > SANE_CLOSURE_USE_CAP {
                return None;
            }
            cursor = cursor.saturating_add(1);
        }
        if self
            .ops
            .get(cursor as usize)
            .is_some_and(|op: &Op| op.opcode == op::VERIFY_RETURN_TYPE)
        {
            cursor = cursor.saturating_add(1);
        }
        let consumer: Op = self.ops.get(cursor as usize)?.clone();
        let (prefix, suffix): (String, String) = match consumer.opcode {
            op::ASSIGN
                if (consumer.op2_type, consumer.op2) == slot
                    && consumer.op1_type == OperandType::Cv
                    && consumer.result_type == OperandType::Unused =>
            {
                (format!("${} = ", self.cv(consumer.op1)), ";".to_owned())
            }
            op::RETURN if (consumer.op1_type, consumer.op1) == slot => {
                ("return ".to_owned(), ";".to_owned())
            }
            _ => return None,
        };
        let params: String = SkeletonEmitter::param_list(child);
        let signature: String = if uses.is_empty() {
            format!("function ({params})")
        } else {
            format!("function ({params}) use ({})", uses.join(", "))
        };
        let mut inner: Lifter<'_> = Lifter::new(
            &child.ops,
            &child.literals,
            &child.var_names,
            &child.try_catch,
            &child.children,
            child.num_args,
        );
        let body: Vec<Stmt> = inner.lift();
        if !inner.unrecovered.is_empty() {
            return None;
        }
        Some((
            vec![Stmt::Closure {
                prefix,
                signature,
                body,
                suffix,
            }],
            cursor.saturating_add(1),
        ))
    }

    fn fold_nullsafe_chain(&mut self, i: u32, end: u32) -> Option<(Vec<Stmt>, u32)> {
        let gate: Op = self.ops.get(i as usize)?.clone();
        let join: u32 = gate.op2;
        if join <= i || join > end || gate.result_type == OperandType::Unused {
            return None;
        }
        let result_key: (OperandType, u32) = (gate.result_type, gate.result);
        let incoming_slots: BTreeMap<(OperandType, u32), Expr> = self.slots.clone();
        let incoming_writable: BTreeMap<(OperandType, u32), u32> = self.writable_slots.clone();
        let refused_before: usize = self.refused.len();
        let mut chain: Expr = self.operand_expr(gate.op1_type, gate.op1)?;
        let mut link: (OperandType, u32) = (gate.op1_type, gate.op1);
        let mut cursor: u32 = i;
        let mut links: usize = 0;
        while cursor < join {
            let guard: Op = self.ops.get(cursor as usize)?.clone();
            if guard.opcode != op::JMP_NULL
                || guard.op2 != join
                || (guard.op1_type, guard.op1) != link
                || (guard.result_type, guard.result) != result_key
            {
                return self.abandon_nullsafe(incoming_slots, incoming_writable);
            }
            let segment_end: u32 = self.nullsafe_segment_end(cursor, join)?;
            let head: Op = self.ops.get(cursor as usize + 1)?.clone();
            let advanced: Option<((OperandType, u32), Expr)> =
                if head.opcode == op::FETCH_OBJ_IS && segment_end == cursor.saturating_add(2) {
                    self.nullsafe_property(&head, link, &chain)
                } else if head.opcode == op::INIT_METHOD_CALL && (head.op1_type, head.op1) == link {
                    self.nullsafe_call(cursor, segment_end, link, refused_before)
                } else {
                    None
                };
            let Some((produced, next)): Option<((OperandType, u32), Expr)> = advanced else {
                return self.abandon_nullsafe(incoming_slots, incoming_writable);
            };
            chain = next;
            link = produced;
            cursor = segment_end;
            links = links.saturating_add(1);
            if links > SANE_NULLSAFE_LINKS {
                return self.abandon_nullsafe(incoming_slots, incoming_writable);
            }
        }
        if cursor != join || links == 0 || link != result_key {
            return self.abandon_nullsafe(incoming_slots, incoming_writable);
        }
        self.writable_slots.remove(&result_key);
        self.slots.insert(result_key, chain);
        Some((Vec::new(), join))
    }

    fn abandon_nullsafe(
        &mut self,
        slots: BTreeMap<(OperandType, u32), Expr>,
        writable: BTreeMap<(OperandType, u32), u32>,
    ) -> Option<(Vec<Stmt>, u32)> {
        self.slots = slots;
        self.writable_slots = writable;
        self.nullsafe_link = None;
        None
    }

    fn nullsafe_segment_end(&self, cursor: u32, join: u32) -> Option<u32> {
        let mut scan: u32 = cursor.checked_add(1)?;
        while scan < join {
            if self.ops.get(scan as usize)?.opcode == op::JMP_NULL {
                return Some(scan);
            }
            scan = scan.checked_add(1)?;
        }
        Some(join)
    }

    fn nullsafe_property(
        &self,
        fetch: &Op,
        link: (OperandType, u32),
        chain: &Expr,
    ) -> Option<((OperandType, u32), Expr)> {
        if (fetch.op1_type, fetch.op1) != link {
            return None;
        }
        let name: String = self.literal_string(fetch.op2_type, fetch.op2)?;
        if !is_valid_php_ident(&name) {
            return None;
        }
        Some((
            (fetch.result_type, fetch.result),
            Expr {
                text: format!("{}?->{name}", chain.wrapped(PREC_CALL)),
                prec: PREC_CALL,
            },
        ))
    }

    fn nullsafe_call(
        &mut self,
        cursor: u32,
        segment_end: u32,
        link: (OperandType, u32),
        refused_before: usize,
    ) -> Option<((OperandType, u32), Expr)> {
        let depth: usize = self.call_stack.len();
        self.nullsafe_link = Some(link);
        let mut k: u32 = cursor.saturating_add(1);
        while k < segment_end {
            self.eval_op(k);
            k = k.saturating_add(1);
        }
        self.nullsafe_link = None;
        if self.refused.len() != refused_before || self.call_stack.len() != depth {
            return None;
        }
        let last: Op = self.ops.get(segment_end as usize - 1)?.clone();
        if last.result_type == OperandType::Unused {
            return None;
        }
        let produced: (OperandType, u32) = (last.result_type, last.result);
        let expr: Expr = self.slots.get(&produced).cloned()?;
        Some((produced, expr))
    }

    fn fold_default_join(&mut self, i: u32, end: u32) -> Option<(Vec<Stmt>, u32)> {
        let gate: Op = self.ops.get(i as usize)?.clone();
        let join: u32 = gate.op2;
        if join <= i || join > end || gate.result_type == OperandType::Unused {
            return None;
        }
        let result_key: (OperandType, u32) = (gate.result_type, gate.result);
        let lhs: Expr = self.operand_expr(gate.op1_type, gate.op1)?;
        let incoming_slots: BTreeMap<(OperandType, u32), Expr> = self.slots.clone();
        let incoming_writable: BTreeMap<(OperandType, u32), u32> = self.writable_slots.clone();
        let refused_before: usize = self.refused.len();
        let mut k: u32 = i + 1;
        while k < join {
            self.eval_op(k);
            k += 1;
        }
        if self.refused.len() != refused_before {
            self.slots = incoming_slots;
            self.writable_slots = incoming_writable;
            return None;
        }
        let rhs: Expr = self.slots.get(&result_key).cloned()?;
        let (connector, prec, right_prec): (&str, u8, u8) = if gate.opcode == op::COALESCE {
            ("??", PREC_COALESCE, PREC_COALESCE)
        } else {
            ("?:", PREC_TERNARY, PREC_TERNARY + 1)
        };
        let text: String = format!(
            "{} {} {}",
            lhs.wrapped(prec + 1),
            connector,
            rhs.wrapped(right_prec)
        );
        self.slots = Self::common_slots(&incoming_slots, &self.slots);
        self.writable_slots = Self::common_writable_slots(&incoming_writable, &self.writable_slots);
        self.writable_slots.remove(&result_key);
        self.slots.insert(result_key, Expr { text, prec });
        Some((Vec::new(), join))
    }

    fn fold_rope(&mut self, i: u32, end: u32) -> Option<(Vec<Stmt>, u32)> {
        let init: Op = self.ops.get(i as usize)?.clone();
        let total: u32 = init.extended_value;
        let remaining: u32 = end.checked_sub(i)?;
        if init.op1_type != OperandType::Unused
            || init.op2_type == OperandType::Unused
            || init.result_type != OperandType::TmpVar
            || total < 3
            || total > remaining
        {
            return None;
        }
        let total_usize: usize = usize::try_from(total).ok()?;
        if total_usize > SANE_ROPE_WORK_CAP {
            let refusal: String = self.refuse(i, init.opcode, REASON_ROPE_BUDGET);
            return Some((vec![Stmt::Line(refusal)], i.saturating_add(1)));
        }
        let rope_key: (OperandType, u32) = (init.result_type, init.result);
        let capacity: usize = total_usize.min(MAX_PREALLOC);
        let mut elements: Vec<(u32, Op)> = Vec::with_capacity(capacity);
        let mut intermediates: Vec<u32> = Vec::new();
        elements.push((i, init.clone()));
        let mut position: u32 = 1;
        let mut cursor: u32 = i.checked_add(1)?;
        while position < total {
            if cursor >= end {
                return None;
            }
            let visited: usize = usize::try_from(cursor.checked_sub(i)?).ok()?;
            if visited >= SANE_ROPE_WORK_CAP {
                let refusal: String = self.refuse(i, init.opcode, REASON_ROPE_BUDGET);
                return Some((vec![Stmt::Line(refusal)], i.saturating_add(1)));
            }
            let current: Op = self.ops.get(cursor as usize)?.clone();
            if !matches!(current.opcode, op::ROPE_ADD | op::ROPE_END) {
                let touches_rope: bool = [
                    (current.op1_type, current.op1),
                    (current.op2_type, current.op2),
                    (current.result_type, current.result),
                ]
                .contains(&rope_key);
                if current.opcode == op::ROPE_INIT
                    || touches_rope
                    || !is_rope_intermediate(current.opcode)
                {
                    return None;
                }
                intermediates.push(cursor);
                cursor = cursor.checked_add(1)?;
                continue;
            }
            let last: bool = position.checked_add(1)? == total;
            if current.op1_type != rope_key.0
                || current.op1 != rope_key.1
                || current.op2_type == OperandType::Unused
                || current.extended_value != position
                || (last && current.opcode != op::ROPE_END)
                || (!last && current.opcode != op::ROPE_ADD)
                || (!last && (current.result_type, current.result) != rope_key)
                || (last
                    && (current.result_type != OperandType::TmpVar
                        || (current.result_type, current.result) == rope_key))
            {
                return None;
            }
            elements.push((cursor, current));
            position = position.checked_add(1)?;
            cursor = cursor.checked_add(1)?;
        }
        if !self.call_stack.is_empty() {
            return None;
        }
        let mut touched_keys: BTreeSet<(OperandType, u32)> = BTreeSet::new();
        for index in &intermediates {
            let current: &Op = self.ops.get(*index as usize)?;
            if matches!(current.result_type, OperandType::TmpVar | OperandType::Var) {
                touched_keys.insert((current.result_type, current.result));
            }
        }
        let saved_slots: Vec<((OperandType, u32), Option<Expr>)> = touched_keys
            .iter()
            .map(|key: &(OperandType, u32)| (*key, self.slots.get(key).cloned()))
            .collect();
        let saved_writable: Vec<((OperandType, u32), Option<u32>)> = touched_keys
            .iter()
            .map(|key: &(OperandType, u32)| (*key, self.writable_slots.get(key).copied()))
            .collect();
        let unrecovered_len: usize = self.unrecovered.len();
        let parts: Option<Vec<Expr>> = (|| {
            let mut captured: Vec<Expr> = Vec::with_capacity(capacity);
            captured.push(self.defined_operand_expr(init.op2_type, init.op2)?);
            let mut scan: u32 = i.checked_add(1)?;
            for (element_index, element) in elements.iter().skip(1) {
                while scan < *element_index {
                    let refused_before: usize = self.refused.len();
                    if self.eval_op(scan).is_some() || self.refused.len() != refused_before {
                        return None;
                    }
                    scan = scan.checked_add(1)?;
                }
                if !self.call_stack.is_empty() {
                    return None;
                }
                captured.push(self.defined_operand_expr(element.op2_type, element.op2)?);
                scan = element_index.checked_add(1)?;
            }
            Some(captured)
        })();
        let Some(parts): Option<Vec<Expr>> = parts else {
            for (key, previous) in saved_slots {
                match previous {
                    Some(expr) => {
                        self.slots.insert(key, expr);
                    }
                    None => {
                        self.slots.remove(&key);
                    }
                }
            }
            for (key, previous) in saved_writable {
                match previous {
                    Some(index) => {
                        self.writable_slots.insert(key, index);
                    }
                    None => {
                        self.writable_slots.remove(&key);
                    }
                }
            }
            self.call_stack.clear();
            self.unrecovered.truncate(unrecovered_len);
            for index in intermediates {
                self.refused.remove(&index);
            }
            return None;
        };
        let finish_index: u32 = elements.last()?.0;
        let finish: Op = elements.last()?.1.clone();
        let part_family: String = format!("rope_{i}_part");
        let mut statements: Vec<Stmt> = Vec::with_capacity(parts.len().saturating_add(1));
        let mut part_refs: Vec<String> = Vec::with_capacity(parts.len());
        for (part_index, part) in parts.into_iter().enumerate() {
            let part_index: u32 = u32::try_from(part_index).ok()?;
            let name: String = self.reserve_spill(&part_family, part_index);
            statements.push(Stmt::Line(format!("${name} = (string) ({});", part.text)));
            part_refs.push(format!("${name}"));
        }
        let text: String = part_refs.join(" . ");
        let result_key: (OperandType, u32) = (finish.result_type, finish.result);
        let uses: u32 = self
            .result_use_counts
            .get(finish_index as usize)
            .copied()
            .unwrap_or(0);
        let next_consumes_once: bool = uses == 1
            && self.ops.get(cursor as usize).is_some_and(|next: &Op| {
                (next.op1_type, next.op1) == result_key || (next.op2_type, next.op2) == result_key
            });
        if uses == 0 {
            statements.push(Stmt::Line(format!("{text};")));
        } else if next_consumes_once {
            self.store_result(
                &finish,
                Expr {
                    text,
                    prec: PREC_CONCAT,
                },
            );
        } else {
            let spill_name: String = self.reserve_spill("rope", finish_index);
            self.store_result(&finish, Expr::atom(format!("${spill_name}")));
            statements.push(Stmt::Line(format!("${spill_name} = {text};")));
        }
        Some((statements, cursor))
    }

    fn structure_ternary(&mut self, i: u32, end: u32) -> Option<(Vec<Stmt>, u32)> {
        let jmpz: Op = self.ops.get(i as usize)?.clone();
        let else_addr: u32 = jmpz.op2;
        if else_addr <= i || else_addr > end {
            return None;
        }
        let then_idx: u32 = i + 1;
        let then_op: Op = self.ops.get(then_idx as usize)?.clone();
        if then_op.opcode != op::QM_ASSIGN {
            return None;
        }
        let jmp_idx: u32 = then_idx + 1;
        let jmp_op: Op = self.ops.get(jmp_idx as usize)?.clone();
        if jmp_op.opcode != op::JMP {
            return None;
        }
        let else_op: Op = self.ops.get(else_addr as usize)?.clone();
        if else_op.opcode != op::QM_ASSIGN || else_op.result != then_op.result {
            return None;
        }
        let cond: Expr = self.operand_expr(jmpz.op1_type, jmpz.op1)?;
        let then_val: Expr = self.operand_expr(then_op.op1_type, then_op.op1)?;
        let else_val: Expr = self.operand_expr(else_op.op1_type, else_op.op1)?;
        let text: String = format!(
            "{} ? {} : {}",
            cond.wrapped(PREC_CMP),
            then_val.wrapped(PREC_CMP),
            else_val.wrapped(PREC_CMP)
        );
        let result_key: (OperandType, u32) = (then_op.result_type, then_op.result);
        self.writable_slots.remove(&result_key);
        self.slots.insert(
            result_key,
            Expr {
                text,
                prec: PREC_TERNARY,
            },
        );
        Some((Vec::new(), else_addr + 1))
    }

    fn structure_if(&mut self, i: u32, end: u32, depth: u32) -> Option<(Vec<Stmt>, u32)> {
        let jmpz: Op = self.ops.get(i as usize)?.clone();
        let target: u32 = jmpz.op2;
        if target <= i || target > end {
            return None;
        }
        let cond_expr: Expr = self.operand_expr(jmpz.op1_type, jmpz.op1)?;
        let incoming_slots: BTreeMap<(OperandType, u32), Expr> = self.slots.clone();
        let incoming_writable: BTreeMap<(OperandType, u32), u32> = self.writable_slots.clone();
        let then_last: u32 = target - 1;
        let then_terminator: &Op = self.ops.get(then_last as usize)?;
        let then_exits_loop: bool = then_terminator.opcode == op::JMP
            && self
                .loop_jump_level(then_terminator.op1, then_last)
                .is_some_and(|(position, _): (usize, bool)| {
                    self.exit_frees_match(then_last, position)
                });
        if then_terminator.opcode == op::JMP && !then_exits_loop {
            let join: u32 = then_terminator.op1;
            if join > target && join <= end {
                self.slots = incoming_slots.clone();
                self.writable_slots = incoming_writable.clone();
                let then_body: Vec<Stmt> = self.lift_range(i + 1, then_last, depth + 1);
                let then_slots: BTreeMap<(OperandType, u32), Expr> =
                    std::mem::take(&mut self.slots);
                let then_writable: BTreeMap<(OperandType, u32), u32> =
                    std::mem::take(&mut self.writable_slots);
                self.slots = incoming_slots;
                self.writable_slots = incoming_writable;
                let else_body: Vec<Stmt> = self.lift_range(target, join, depth + 1);
                let else_slots: BTreeMap<(OperandType, u32), Expr> =
                    std::mem::take(&mut self.slots);
                let else_writable: BTreeMap<(OperandType, u32), u32> =
                    std::mem::take(&mut self.writable_slots);
                self.slots = Self::common_slots(&then_slots, &else_slots);
                self.writable_slots = Self::common_writable_slots(&then_writable, &else_writable);
                return Some((
                    vec![Stmt::If {
                        cond: cond_expr.text,
                        then_body,
                        else_body,
                    }],
                    join,
                ));
            }
        }
        self.slots = incoming_slots.clone();
        self.writable_slots = incoming_writable.clone();
        let then_body: Vec<Stmt> = self.lift_range(i + 1, target, depth + 1);
        let then_slots: BTreeMap<(OperandType, u32), Expr> = std::mem::take(&mut self.slots);
        let then_writable: BTreeMap<(OperandType, u32), u32> =
            std::mem::take(&mut self.writable_slots);
        self.slots = Self::common_slots(&incoming_slots, &then_slots);
        self.writable_slots = Self::common_writable_slots(&incoming_writable, &then_writable);
        Some((
            vec![Stmt::If {
                cond: cond_expr.text,
                then_body,
                else_body: Vec::new(),
            }],
            target,
        ))
    }

    fn common_slots(
        left: &BTreeMap<(OperandType, u32), Expr>,
        right: &BTreeMap<(OperandType, u32), Expr>,
    ) -> BTreeMap<(OperandType, u32), Expr> {
        left.iter()
            .filter_map(|(key, left_expr): (&(OperandType, u32), &Expr)| {
                right
                    .get(key)
                    .filter(|right_expr: &&Expr| {
                        left_expr.text == right_expr.text && left_expr.prec == right_expr.prec
                    })
                    .map(|_: &Expr| (*key, left_expr.clone()))
            })
            .collect()
    }

    fn common_writable_slots(
        left: &BTreeMap<(OperandType, u32), u32>,
        right: &BTreeMap<(OperandType, u32), u32>,
    ) -> BTreeMap<(OperandType, u32), u32> {
        left.iter()
            .filter_map(|(key, left_idx): (&(OperandType, u32), &u32)| {
                (right.get(key) == Some(left_idx)).then_some((*key, *left_idx))
            })
            .collect()
    }

    fn structure_while(&mut self, i: u32, end: u32, depth: u32) -> Option<(Vec<Stmt>, u32)> {
        let jmp: Op = self.ops.get(i as usize)?.clone();
        let cond_block: u32 = jmp.op1;
        if cond_block <= i || cond_block >= end {
            return None;
        }
        let mut tail: u32 = cond_block;
        while tail < end {
            let op: &Op = self.ops.get(tail as usize)?;
            if op.opcode == op::JMPNZ || op.opcode == op::JMPNZ_EX {
                break;
            }
            if op.branch_target() != Branch::None || op.opcode == op::JMPZ {
                return None;
            }
            tail += 1;
        }
        let cond_op: &Op = self.ops.get(tail as usize)?;
        if cond_op.op2 != i + 1 {
            return None;
        }
        let after_loop: u32 = tail + 1;
        let body_start: u32 = i + 1;
        let snapshot: LiftSnapshot = self.lift_snapshot();
        let (body, unexplained): (Vec<Stmt>, BTreeSet<u32>) = self.lift_breakable_body(
            BreakableFrame {
                body_start,
                body_end: cond_block,
                continue_target: cond_block,
                break_target: after_loop,
                iterator: None,
                unexplained_targets: BTreeSet::new(),
            },
            depth,
        );
        let refused_as_while: usize = self.refused.len() - snapshot.refused.len();
        if let Some(step_start) = self.for_step_start(&unexplained, body_start, cond_block)
            && let Some(statements) = self.relift_for(
                snapshot,
                body_start,
                step_start,
                cond_block,
                after_loop,
                depth,
                refused_as_while,
            )
        {
            let (for_body, step): (Vec<Stmt>, Vec<String>) = statements;
            let cond_expr: Expr = self.lift_condition(cond_block, tail, cond_op)?;
            return Some((
                vec![Stmt::For {
                    cond: cond_expr.text,
                    step,
                    body: for_body,
                }],
                after_loop,
            ));
        }
        let cond_expr: Expr = self.lift_condition(cond_block, tail, cond_op)?;
        Some((
            vec![Stmt::While {
                cond: cond_expr.text,
                body,
            }],
            after_loop,
        ))
    }

    fn lift_breakable_body(
        &mut self,
        frame: BreakableFrame,
        depth: u32,
    ) -> (Vec<Stmt>, BTreeSet<u32>) {
        let start: u32 = frame.body_start;
        let end: u32 = frame.body_end;
        self.breakables.push(frame);
        let body: Vec<Stmt> = self.lift_range(start, end, depth + 1);
        let popped: Option<BreakableFrame> = self.breakables.pop();
        let unexplained: BTreeSet<u32> = popped
            .map_or_else(BTreeSet::new, |frame: BreakableFrame| {
                frame.unexplained_targets
            });
        (body, unexplained)
    }

    fn for_step_start(
        &self,
        unexplained: &BTreeSet<u32>,
        body_start: u32,
        cond_block: u32,
    ) -> Option<u32> {
        let mut inner: std::collections::btree_set::Iter<'_, u32> = unexplained.iter();
        let step_start: u32 = *inner.next()?;
        if inner.next().is_some() {
            return None;
        }
        if step_start <= body_start || step_start >= cond_block {
            return None;
        }
        let width: usize = (cond_block - step_start) as usize;
        if width > SANE_FOR_STEP_CAP {
            return None;
        }
        let step_is_straight_line: bool = (step_start..cond_block).all(|index: u32| {
            self.ops
                .get(index as usize)
                .is_some_and(|op: &Op| op.branch_target() == Branch::None)
        });
        step_is_straight_line.then_some(step_start)
    }

    fn relift_for(
        &mut self,
        snapshot: LiftSnapshot,
        body_start: u32,
        step_start: u32,
        cond_block: u32,
        after_loop: u32,
        depth: u32,
        refused_as_while: usize,
    ) -> Option<(Vec<Stmt>, Vec<String>)> {
        let work: usize = (cond_block - body_start) as usize;
        self.relift_work = loop_relift_charge(self.relift_work, work)?;
        let restored: LiftSnapshot = self.lift_snapshot();
        let baseline: usize = snapshot.refused.len();
        self.restore_lift_snapshot(snapshot);
        let (body, unexplained): (Vec<Stmt>, BTreeSet<u32>) = self.lift_breakable_body(
            BreakableFrame {
                body_start,
                body_end: step_start,
                continue_target: step_start,
                break_target: after_loop,
                iterator: None,
                unexplained_targets: BTreeSet::new(),
            },
            depth,
        );
        let step_stmts: Vec<Stmt> = self.lift_range(step_start, cond_block, depth + 1);
        let step: Option<Vec<String>> = step_stmts
            .iter()
            .filter(|stmt: &&Stmt| !matches!(stmt, Stmt::Label(_)))
            .map(|stmt: &Stmt| match stmt {
                Stmt::Line(text) => Some(text.trim_end_matches(';').to_owned()),
                _ => None,
            })
            .collect();
        let refused_as_for: usize = self.refused.len() - baseline;
        match step {
            Some(step)
                if !step.is_empty()
                    && unexplained.is_empty()
                    && refused_as_for <= refused_as_while =>
            {
                Some((body, step))
            }
            _ => {
                self.restore_lift_snapshot(restored);
                None
            }
        }
    }

    fn record_unexplained_jump(&mut self, idx: u32) {
        let Some(target): Option<u32> = self
            .ops
            .get(idx as usize)
            .filter(|op: &&Op| op.opcode == op::JMP)
            .map(|op: &Op| op.op1)
        else {
            return;
        };
        let holder: Option<&mut BreakableFrame> =
            self.breakables
                .iter_mut()
                .rev()
                .find(|frame: &&mut BreakableFrame| {
                    target > frame.body_start && target < frame.body_end
                });
        if let Some(frame) = holder {
            frame.unexplained_targets.insert(target);
        }
    }

    fn loop_jump_level(&self, target: u32, index: u32) -> Option<(usize, bool)> {
        self.breakables.iter().enumerate().rev().find_map(
            |(position, frame): (usize, &BreakableFrame)| {
                if index < frame.body_start || index >= frame.body_end {
                    return None;
                }
                if frame.break_target == target {
                    return Some((position, true));
                }
                (frame.continue_target == target).then_some((position, false))
            },
        )
    }

    fn exits_enclosing_loop(&self, index: u32) -> bool {
        self.ops
            .get(index as usize)
            .filter(|op: &&Op| op.opcode == op::JMP)
            .and_then(|op: &Op| self.loop_jump_level(op.op1, index))
            .is_some_and(|(position, _): (usize, bool)| self.exit_frees_match(index, position))
    }

    fn structure_loop_jump(&self, i: u32) -> Option<(Vec<Stmt>, u32)> {
        let jump: &Op = self.ops.get(i as usize)?;
        if jump.opcode != op::JMP {
            return None;
        }
        let target: u32 = jump.op1;
        let (position, is_break): (usize, bool) = self.loop_jump_level(target, i)?;
        if !self.exit_frees_match(i, position) {
            return None;
        }
        let level: u32 = u32::try_from(self.breakables.len() - position).ok()?;
        let stmt: Stmt = if is_break {
            Stmt::Break(level)
        } else {
            Stmt::Continue(level)
        };
        Some((vec![stmt], i + 1))
    }

    fn exit_frees_match(&self, index: u32, position: usize) -> bool {
        let expected: Vec<(OperandType, u32)> = self
            .breakables
            .iter()
            .skip(position + 1)
            .rev()
            .filter_map(|frame: &BreakableFrame| frame.iterator)
            .collect();
        if u32::try_from(expected.len()).is_ok_and(|count: u32| count > SANE_LOOP_EXIT_FREE_CAP) {
            return false;
        }
        let mut cursor: u32 = index;
        for iterator in expected {
            let Some(previous): Option<u32> = cursor.checked_sub(1) else {
                return false;
            };
            let Some(free): Option<&Op> = self.ops.get(previous as usize) else {
                return false;
            };
            if free.opcode != op::FE_FREE || (free.op1_type, free.op1) != iterator {
                return false;
            }
            cursor = previous;
        }
        true
    }

    fn lift_condition(&mut self, start: u32, jump_idx: u32, jump_op: &Op) -> Option<Expr> {
        let mut k: u32 = start;
        while k < jump_idx {
            let op: Op = self.ops.get(k as usize)?.clone();
            self.eval_op(k);
            let _ = op;
            k += 1;
        }
        self.operand_expr(jump_op.op1_type, jump_op.op1)
    }

    fn structure_foreach(&mut self, i: u32, end: u32, depth: u32) -> Option<(Vec<Stmt>, u32)> {
        let reset: Op = self.ops.get(i as usize)?.clone();
        let after_loop: u32 = reset.op2;
        if after_loop <= i || after_loop > end {
            return None;
        }
        let subject: Expr = self.operand_expr(reset.op1_type, reset.op1)?;
        let fetch_idx: u32 = i + 1;
        let fetch: Op = self.ops.get(fetch_idx as usize)?.clone();
        let by_reference: bool = match (reset.opcode, fetch.opcode) {
            (op::FE_RESET_R, op::FE_FETCH_R) => false,
            (op::FE_RESET_RW, op::FE_FETCH_RW) => true,
            _ => return None,
        };
        let value: String = match fetch.op2_type {
            OperandType::Cv => format!("${}", self.cv(fetch.op2)),
            _ => return None,
        };
        let mut value_start: u32 = fetch_idx + 1;
        let key: Option<String> =
            if fetch.extended_value != 0 && fetch.result_type != OperandType::Unused {
                self.bind_foreach_key(&fetch, value_start)
                    .map(|(name, consumed): (String, u32)| {
                        value_start = consumed;
                        name
                    })
            } else {
                None
            };
        let body_start: u32 = value_start;
        let body_end: u32 = after_loop.saturating_sub(1);
        let back: &Op = self.ops.get(body_end as usize)?;
        if back.opcode != op::JMP || back.op1 != fetch_idx {
            return None;
        }
        let (body, _): (Vec<Stmt>, BTreeSet<u32>) = self.lift_breakable_body(
            BreakableFrame {
                body_start,
                body_end,
                continue_target: fetch_idx,
                break_target: after_loop,
                iterator: Some((reset.result_type, reset.result)),
                unexplained_targets: BTreeSet::new(),
            },
            depth,
        );
        let has_free: bool = self
            .ops
            .get(after_loop as usize)
            .is_some_and(|free: &Op| free.opcode == op::FE_FREE);
        let next: u32 = if has_free { after_loop + 1 } else { after_loop };
        Some((
            vec![Stmt::Foreach {
                subject: subject.text,
                key,
                value,
                by_reference,
                body,
            }],
            next,
        ))
    }

    fn bind_foreach_key(&self, fetch: &Op, after_fetch: u32) -> Option<(String, u32)> {
        let assign: &Op = self.ops.get(after_fetch as usize)?;
        if assign.opcode != op::ASSIGN
            || assign.op2_type != fetch.result_type
            || assign.op2 != fetch.result
            || assign.op1_type != OperandType::Cv
        {
            return None;
        }
        Some((format!("${}", self.cv(assign.op1)), after_fetch + 1))
    }

    fn fold_list_assign(&mut self, start: u32, end: u32) -> Option<(Vec<Stmt>, u32)> {
        let first: &Op = self.ops.get(start as usize)?;
        if first.opcode != op::FETCH_LIST_R
            || !matches!(
                first.op1_type,
                OperandType::Const | OperandType::TmpVar | OperandType::Var
            )
            || matches!(
                (first.op1_type, self.literals.get(first.op1 as usize)),
                (OperandType::Const, Some(Literal::Array(_)))
            )
        {
            return None;
        }
        let subject: Expr = self.defined_operand_expr(first.op1_type, first.op1)?;
        let container: (OperandType, u32) = (first.op1_type, first.op1);
        let mut work: usize = 0;
        let mut name_bytes: usize = 0;
        let (entries, nested_end): (Vec<ListEntry>, u32) =
            self.list_entries(start, end, container, 0, &mut work, &mut name_bytes)?;
        let next: u32 = self.skip_list_free(nested_end, end, container)?;
        let mut pattern: String = String::new();
        self.render_list_entries(&entries, &mut pattern)?;
        let statement_bytes: usize = pattern
            .len()
            .checked_add(subject.text.len())?
            .checked_add(4)?;
        if statement_bytes > SANE_LIST_RENDER_CAP {
            return None;
        }
        let used_after: bool = matches!(container.0, OperandType::TmpVar | OperandType::Var)
            && self
                .ops
                .get(next as usize..end as usize)?
                .iter()
                .any(|op: &Op| {
                    op.opcode != op::FREE
                        && ((op.op1_type, op.op1) == container
                            || (op.op2_type, op.op2) == container)
                });
        if !used_after {
            return Some((
                vec![Stmt::Line(format!("{pattern} = {};", subject.text))],
                next,
            ));
        }
        let spill: String = self.reserve_spill("list", start);
        let spill_expr: String = format!("${spill}");
        let spill_bytes: usize = statement_bytes
            .checked_add(spill_expr.len().checked_mul(2)?)?
            .checked_add(8)?;
        if spill_bytes > SANE_LIST_RENDER_CAP {
            self.reserved_names.remove(&spill);
            return None;
        }
        self.writable_slots.remove(&container);
        self.slots.insert(container, Expr::atom(spill_expr.clone()));
        Some((
            vec![
                Stmt::Line(format!("{spill_expr} = {};", subject.text)),
                Stmt::Line(format!("{pattern} = {spill_expr};")),
            ],
            next,
        ))
    }

    fn list_entries(
        &self,
        start: u32,
        end: u32,
        container: (OperandType, u32),
        depth: u32,
        work: &mut usize,
        name_bytes: &mut usize,
    ) -> Option<(Vec<ListEntry>, u32)> {
        if depth >= SANE_NEST_DEPTH {
            return None;
        }
        let mut entries: Vec<ListEntry> = Vec::new();
        let mut cursor: u32 = start;
        while cursor < end {
            let fetch: &Op = self.ops.get(cursor as usize)?;
            if fetch.opcode != op::FETCH_LIST_R || (fetch.op1_type, fetch.op1) != container {
                break;
            }
            *work = work.checked_add(1)?;
            if *work > SANE_LIST_ELEMENT_CAP
                || fetch.op2_type != OperandType::Const
                || !matches!(fetch.result_type, OperandType::TmpVar | OperandType::Var)
                || fetch.extended_value != 0
            {
                return None;
            }
            let key_literal: &Literal = self.literals.get(fetch.op2 as usize)?;
            let position: Option<usize> = match key_literal {
                Literal::Long(value) if *value >= 0 => usize::try_from(*value)
                    .ok()
                    .filter(|position: &usize| *position < SANE_LIST_ELEMENT_CAP),
                Literal::Long(_) | Literal::Str(_) => None,
                _ => return None,
            };
            let key: ListKey = ListKey {
                literal: fetch.op2,
                position,
            };
            let result: (OperandType, u32) = (fetch.result_type, fetch.result);
            let consumer_index: u32 = cursor.checked_add(1)?;
            let consumer: &Op = self.ops.get(consumer_index as usize)?;
            let (value, next): (ListValue, u32) = if consumer.opcode == op::ASSIGN {
                if consumer.op1_type != OperandType::Cv
                    || (consumer.op2_type, consumer.op2) != result
                    || consumer.result_type != OperandType::Unused
                    || consumer.extended_value != 0
                    || self.result_use_counts.get(cursor as usize).copied() != Some(1)
                {
                    return None;
                }
                let name: String = self
                    .var_names
                    .get(consumer.op1 as usize)
                    .and_then(Option::as_deref)
                    .filter(|name: &&str| is_valid_php_ident(name))
                    .map(str::to_owned)?;
                *name_bytes = name_bytes.checked_add(name.len().checked_add(1)?)?;
                if *name_bytes > SANE_LIST_RENDER_CAP {
                    return None;
                }
                (
                    ListValue::Variable(format!("${name}")),
                    consumer_index.checked_add(1)?,
                )
            } else if consumer.opcode == op::FETCH_LIST_R
                && (consumer.op1_type, consumer.op1) == result
            {
                let (nested, nested_end): (Vec<ListEntry>, u32) = self.list_entries(
                    consumer_index,
                    end,
                    result,
                    depth.checked_add(1)?,
                    work,
                    name_bytes,
                )?;
                let direct_uses: u32 = u32::try_from(nested.len()).ok()?;
                if self.result_use_counts.get(cursor as usize).copied() != Some(direct_uses) {
                    return None;
                }
                let next: u32 = self.skip_list_free(nested_end, end, result)?;
                (ListValue::Nested(nested), next)
            } else {
                return None;
            };
            entries.push(ListEntry { key, value });
            cursor = next;
        }
        (!entries.is_empty()).then_some((entries, cursor))
    }

    fn skip_list_free(&self, cursor: u32, end: u32, container: (OperandType, u32)) -> Option<u32> {
        if cursor >= end {
            return Some(cursor);
        }
        let next: &Op = self.ops.get(cursor as usize)?;
        if next.opcode != op::FREE {
            return Some(cursor);
        }
        if (next.op1_type, next.op1) != container
            || next.op2_type != OperandType::Unused
            || next.result_type != OperandType::Unused
            || next.extended_value_provenance() != ExtendedValueProvenance::Unavailable
        {
            return None;
        }
        cursor.checked_add(1)
    }

    fn render_list_entries(&self, entries: &[ListEntry], out: &mut String) -> Option<()> {
        Self::push_list_text(out, "[")?;
        let mut prior: Option<usize> = None;
        let positional: bool = entries.iter().all(|entry: &ListEntry| {
            entry.key.position.is_some_and(|position: usize| {
                let ordered: bool = prior.is_none_or(|held: usize| position > held);
                prior = Some(position);
                ordered
            })
        });
        if positional {
            let last: usize = entries.last()?.key.position?;
            let mut entry_index: usize = 0;
            for position in 0..=last {
                if position != 0 {
                    Self::push_list_text(out, ", ")?;
                }
                let Some(entry): Option<&ListEntry> = entries.get(entry_index) else {
                    continue;
                };
                if entry.key.position == Some(position) {
                    self.render_list_value(&entry.value, out)?;
                    entry_index = entry_index.checked_add(1)?;
                }
            }
        } else {
            for (index, entry) in entries.iter().enumerate() {
                if index != 0 {
                    Self::push_list_text(out, ", ")?;
                }
                let key: &Literal = self.literals.get(entry.key.literal as usize)?;
                Self::push_list_text(out, &key.render())?;
                Self::push_list_text(out, " => ")?;
                self.render_list_value(&entry.value, out)?;
            }
        }
        Self::push_list_text(out, "]")
    }

    fn render_list_value(&self, value: &ListValue, out: &mut String) -> Option<()> {
        match value {
            ListValue::Variable(name) => Self::push_list_text(out, name),
            ListValue::Nested(entries) => self.render_list_entries(entries, out),
        }
    }

    fn push_list_text(out: &mut String, text: &str) -> Option<()> {
        let next: usize = out.len().checked_add(text.len())?;
        if next > SANE_LIST_RENDER_CAP {
            return None;
        }
        out.push_str(text);
        Some(())
    }

    fn eval_op(&mut self, idx: u32) -> Option<String> {
        let op: Op = self.ops.get(idx as usize)?.clone();
        let op: &Op = &op;
        match op.opcode {
            o if o == op::OP_DATA || o == op::GENERATOR_CREATE => None,
            o if is_binary(o) => self.fold_binary(idx, op),
            o if o == op::BOOL || o == op::QM_ASSIGN => {
                if let Some(v) = self.operand_expr(op.op1_type, op.op1) {
                    self.store_result(op, v);
                }
                None
            }
            o if o == op::BOOL_NOT => {
                if let Some(v) = self.operand_expr(op.op1_type, op.op1) {
                    let neg: Expr = Expr {
                        text: format!("!{}", v.wrapped(PREC_CALL)),
                        prec: PREC_CALL,
                    };
                    self.store_result(op, neg);
                }
                None
            }
            o if o == op::STRLEN || o == op::COUNT => {
                self.fold_unary_call(op, builtin_name(o));
                None
            }
            o if o == op::FETCH_LIST_R => Some(self.refuse(idx, o, REASON_LIST_DESTRUCTURING)),
            o if o == op::FETCH_DIM_R => {
                self.fold_fetch_dim(op);
                None
            }
            o if o == op::FETCH_OBJ_R => {
                let text: String = self.property_access(op);
                self.store_result(
                    op,
                    Expr {
                        text,
                        prec: PREC_ATOM,
                    },
                );
                None
            }
            o if o == op::ASSIGN_OBJ => {
                let target: String = self.property_access(op);
                let value: Expr = self
                    .ops
                    .get(idx as usize + 1)
                    .filter(|n: &&Op| n.opcode == op::OP_DATA)
                    .and_then(|data: &Op| self.operand_expr(data.op1_type, data.op1))
                    .unwrap_or_else(|| Expr::atom("null".to_owned()));
                if op.result_type != OperandType::Unused {
                    self.store_result(op, Expr::atom(target.clone()));
                }
                Some(format!("{target} = {};", value.text))
            }
            o if o == op::FETCH_CONSTANT => {
                let Some(name): Option<String> = self.constant_name(op) else {
                    return Some(self.refuse(idx, o, REASON_CONSTANT_NAME));
                };
                self.store_result(
                    op,
                    Expr {
                        text: constant_reference(&name),
                        prec: PREC_ATOM,
                    },
                );
                None
            }
            o if o == op::DECLARE_CONST => {
                let name: Expr = self.operand_expr(op.op1_type, op.op1)?;
                let value: Expr = self.operand_expr(op.op2_type, op.op2)?;
                Some(format!("define({}, {});", name.text, value.text))
            }
            o if o == op::INSTANCEOF => {
                let value: Expr = self.operand_expr(op.op1_type, op.op1)?;
                let class: String = self
                    .operand_expr(op.op2_type, op.op2)
                    .map_or_else(|| "stdClass".to_owned(), |e: Expr| strip_quotes(&e.text));
                self.store_result(
                    op,
                    Expr {
                        text: format!("{} instanceof {class}", value.wrapped(PREC_INSTANCEOF + 1)),
                        prec: PREC_INSTANCEOF,
                    },
                );
                None
            }
            o if o == op::CAST => {
                let Some(symbol): Option<&'static str> = cast_symbol(op.extended_value) else {
                    return Some(self.refuse(idx, o, REASON_CAST_KIND));
                };
                let value: Expr = self.operand_expr(op.op1_type, op.op1)?;
                self.store_result(
                    op,
                    Expr {
                        text: format!("{symbol} {}", value.wrapped(PREC_UNARY)),
                        prec: PREC_UNARY,
                    },
                );
                None
            }
            o if o == op::BW_NOT || o == op::CLONE => {
                let value: Expr = self.operand_expr(op.op1_type, op.op1)?;
                let text: String = if o == op::BW_NOT {
                    format!("~{}", value.wrapped(PREC_UNARY))
                } else {
                    format!("clone {}", value.wrapped(PREC_UNARY))
                };
                self.store_result(
                    op,
                    Expr {
                        text,
                        prec: PREC_UNARY,
                    },
                );
                None
            }
            o if is_isset_isempty(o) => {
                let Some(probe): Option<&'static str> = isset_probe(op.extended_value) else {
                    return Some(self.refuse(idx, o, REASON_ISSET_MODE));
                };
                let subject: String = if o == op::ISSET_ISEMPTY_PROP_OBJ {
                    self.property_access(op)
                } else if o == op::ISSET_ISEMPTY_DIM_OBJ {
                    let base: Expr = self.operand_expr(op.op1_type, op.op1)?;
                    let index: Expr = self.operand_expr(op.op2_type, op.op2)?;
                    format!("{}[{}]", base.wrapped(PREC_CALL), index.text)
                } else {
                    self.operand_expr(op.op1_type, op.op1)?.text
                };
                self.store_result(
                    op,
                    Expr {
                        text: format!("{probe}({subject})"),
                        prec: PREC_CALL,
                    },
                );
                None
            }
            o if o == op::FETCH_IS => self.fold_fetch_is(idx, op),
            o if o == op::FETCH_R || o == op::FETCH_W || o == op::FETCH_RW => {
                self.fold_variable_variable(idx, op)
            }
            o if o == op::FE_RESET_R || o == op::FE_RESET_RW => {
                Some(self.refuse(idx, o, REASON_ITERATION))
            }
            o if o == op::FE_FREE => None,
            o if o == op::VERIFY_RETURN_TYPE || o == op::NOP || o == op::HANDLE_EXCEPTION => None,
            o if o == op::FAST_CALL || o == op::FAST_RET || o == op::DISCARD_EXCEPTION => None,
            o if o == op::RECV || o == op::RECV_INIT || o == op::BIND_STATIC => None,
            o if o == op::RECV_VARIADIC => {
                if self.num_args.checked_add(1) == Some(op.op1)
                    && op.op1_type == OperandType::Unused
                    && op.op2_type == OperandType::Unused
                    && op.result_type == OperandType::Cv
                    && op.result == self.num_args
                {
                    self.limit(idx, o, LIMITATION_VARIADIC_PARAMETER_REFERENCE);
                    None
                } else {
                    Some(self.refuse(idx, o, REASON_VARIADIC_PARAMETER_SHAPE))
                }
            }
            o if o == op::INIT_FCALL || o == op::INIT_FCALL_BY_NAME || o == op::INIT_NS_FCALL => {
                let direct_callee: Option<String> = self
                    .callable_literal_string(op.op2_type, op.op2)
                    .filter(|name: &&str| is_valid_php_qualified_name(name))
                    .map(str::to_owned);
                let callable_shape: bool = op.op1_type == OperandType::Unused
                    && op.op1 == 0
                    && op.op2_type == OperandType::Const
                    && op.result_type == OperandType::Unused
                    && op.extended_value == 0
                    && direct_callee.is_some();
                let callee: String = direct_callee.unwrap_or_else(|| "func".to_owned());
                self.call_stack.push(PendingCall {
                    callee,
                    is_method: false,
                    nullsafe: false,
                    object: None,
                    is_static: false,
                    args: Vec::new(),
                    rendered_args: 0,
                    positional_count: 0,
                    result: None,
                    callable_shape,
                });
                None
            }
            o if o == op::INIT_DYNAMIC_CALL => {
                let callable_shape: bool = op.op2_type == OperandType::Unused
                    && op.result_type == OperandType::Unused
                    && op.extended_value == 0
                    && self.callable_operand_expr(op.op1_type, op.op1).is_some();
                let Some(callee): Option<Expr> = self.callable_operand_expr(op.op1_type, op.op1)
                else {
                    return Some(self.refuse(idx, o, REASON_EXPRESSION_OPERAND));
                };
                self.call_stack.push(PendingCall {
                    callee: callee.wrapped(PREC_CALL),
                    is_method: false,
                    nullsafe: false,
                    object: None,
                    is_static: false,
                    args: Vec::new(),
                    rendered_args: 0,
                    positional_count: 0,
                    result: None,
                    callable_shape,
                });
                None
            }
            o if o == op::INIT_METHOD_CALL => {
                let callable_shape: bool = op.op2_type != OperandType::Unused
                    && op.result_type == OperandType::Unused
                    && op.extended_value == 0
                    && self
                        .nullsafe_link
                        .is_none_or(|link: (OperandType, u32)| link != (op.op1_type, op.op1))
                    && self
                        .callable_operand_expr(op.op2_type, op.op2)
                        .is_some_and(|name: Expr| {
                            op.op2_type != OperandType::Const
                                || is_valid_php_ident(name.text.trim_matches('\''))
                        })
                    && (op.op1_type == OperandType::Unused && op.op1 == 0
                        || self.callable_operand_expr(op.op1_type, op.op1).is_some());
                let object: String = match op.op1_type {
                    OperandType::Unused => "$this".to_owned(),
                    ty => self
                        .operand_expr(ty, op.op1)
                        .map_or_else(|| "$this".to_owned(), |e: Expr| e.text),
                };
                let method: String = self
                    .operand_expr(op.op2_type, op.op2)
                    .map_or_else(|| "method".to_owned(), |e: Expr| strip_quotes(&e.text));
                let nullsafe: bool = self.nullsafe_link == Some((op.op1_type, op.op1));
                self.call_stack.push(PendingCall {
                    callee: method,
                    is_method: true,
                    nullsafe,
                    object: Some(object),
                    is_static: false,
                    args: Vec::new(),
                    rendered_args: 0,
                    positional_count: 0,
                    result: None,
                    callable_shape,
                });
                None
            }
            o if o == op::INIT_STATIC_METHOD_CALL => {
                let callable_shape: bool = op.op1_type != OperandType::Unused
                    && op.op2_type != OperandType::Unused
                    && op.result_type == OperandType::Unused
                    && op.extended_value == 0
                    && (self
                        .callable_literal_string(op.op1_type, op.op1)
                        .is_some_and(is_valid_php_qualified_name)
                        || (op.op1_type != OperandType::Const
                            && self.callable_operand_expr(op.op1_type, op.op1).is_some()))
                    && (self
                        .callable_literal_string(op.op2_type, op.op2)
                        .is_some_and(is_valid_php_ident)
                        || (op.op2_type != OperandType::Const
                            && self.callable_operand_expr(op.op2_type, op.op2).is_some()));
                let class: String = self
                    .callable_literal_string(op.op1_type, op.op1)
                    .map_or_else(
                        || {
                            self.callable_operand_expr(op.op1_type, op.op1)
                                .map_or_else(|| "self".to_owned(), |e: Expr| e.text)
                        },
                        str::to_owned,
                    );
                let method: String = self
                    .callable_literal_string(op.op2_type, op.op2)
                    .map_or_else(
                        || {
                            self.callable_operand_expr(op.op2_type, op.op2)
                                .map_or_else(|| "method".to_owned(), |e: Expr| e.text)
                        },
                        str::to_owned,
                    );
                self.call_stack.push(PendingCall {
                    callee: method,
                    is_method: true,
                    nullsafe: false,
                    object: Some(class),
                    is_static: true,
                    args: Vec::new(),
                    rendered_args: 0,
                    positional_count: 0,
                    result: None,
                    callable_shape,
                });
                None
            }
            o if is_send(o) => self.push_send(idx, op),
            o if o == op::SEND_UNPACK => self.push_unpack(idx, op),
            o if o == op::CHECK_UNDEF_ARGS => {
                if op.op1_type != OperandType::Unused
                    || op.op2_type != OperandType::Unused
                    || op.result_type != OperandType::Unused
                    || self.call_stack.is_empty()
                {
                    Some(self.refuse(idx, o, REASON_CALL_ARGUMENT_SHAPE))
                } else {
                    None
                }
            }
            o if o == op::DO_FCALL
                || o == op::DO_ICALL
                || o == op::DO_UCALL
                || o == op::DO_FCALL_BY_NAME =>
            {
                self.finish_call(idx, op)
            }
            o if o == op::CALLABLE_CONVERT => self.finish_callable_convert(idx, op),
            o if o == op::FETCH_CLASS => {
                if op.op1_type != OperandType::Unused
                    || op.result_type != OperandType::Var
                    || op.extended_value != 0
                {
                    return Some(self.refuse(idx, o, REASON_FETCH_CLASS_SHAPE));
                }
                let Some(class): Option<Expr> = self.callable_operand_expr(op.op2_type, op.op2)
                else {
                    return Some(self.refuse(idx, o, REASON_FETCH_CLASS_SHAPE));
                };
                self.store_result(op, class);
                None
            }
            o if o == op::NEW => {
                let cls: String = self
                    .operand_expr(op.op1_type, op.op1)
                    .map_or_else(|| "stdClass".to_owned(), |e: Expr| strip_quotes(&e.text));
                self.call_stack.push(PendingCall {
                    callee: format!("new {cls}"),
                    is_method: false,
                    nullsafe: false,
                    object: None,
                    is_static: false,
                    args: Vec::new(),
                    rendered_args: 0,
                    positional_count: 0,
                    result: (op.result_type != OperandType::Unused).then_some((
                        op.result_type,
                        op.result,
                        idx,
                    )),
                    callable_shape: false,
                });
                None
            }
            o if o == op::JMP => {
                let target: u32 = op.op1;
                if target as usize >= self.ops.len() {
                    return Some(self.refuse(idx, o, REASON_JUMP));
                }
                if !self.emit_gotos {
                    self.goto_targets.insert(target);
                    return Some(self.refuse(idx, o, REASON_JUMP));
                }
                self.refused.insert(idx);
                Some(format!("goto {};", Self::goto_label(target)))
            }
            o if o == op::TYPE_CHECK => {
                let Some(subject): Option<Expr> = self.operand_expr(op.op1_type, op.op1) else {
                    return Some(self.refuse(idx, o, REASON_EXPRESSION_OPERAND));
                };
                let text: String = match type_check_probe(op.extended_value) {
                    Some(TypeProbe::Builtin(name)) => format!("{name}({})", subject.text),
                    Some(TypeProbe::NotNull) => {
                        format!("{} !== null", subject.wrapped(PREC_CMP + 1))
                    }
                    None => return Some(self.refuse(idx, o, REASON_TYPE_CHECK)),
                };
                let prec: u8 = if op.extended_value == TYPE_MASK_NOT_NULL {
                    PREC_CMP
                } else {
                    PREC_CALL
                };
                self.store_result(op, Expr { text, prec });
                None
            }
            o if o == op::FETCH_CLASS_CONSTANT => {
                let Some(text): Option<String> = self.class_constant_access(op) else {
                    return Some(self.refuse(idx, o, REASON_CLASS_REFERENCE));
                };
                self.store_result(op, Expr::atom(text));
                None
            }
            o if o == op::FETCH_STATIC_PROP_R
                || o == op::FETCH_STATIC_PROP_W
                || o == op::FETCH_STATIC_PROP_RW =>
            {
                let Some(text): Option<String> = self.static_property(op) else {
                    return Some(self.refuse(idx, o, REASON_CLASS_REFERENCE));
                };
                self.store_result(op, Expr::atom(text));
                None
            }
            o if o == op::FETCH_OBJ_W || o == op::FETCH_OBJ_RW => {
                let text: String = self.property_access(op);
                self.store_result(op, Expr::atom(text));
                self.mark_writable(idx, op);
                None
            }
            o if o == op::FETCH_DIM_W || o == op::FETCH_DIM_RW => {
                let Some(text): Option<String> = self.dimension_access(op) else {
                    return Some(self.refuse(idx, o, REASON_EXPRESSION_OPERAND));
                };
                self.store_result(op, Expr::atom(text));
                self.mark_writable(idx, op);
                None
            }
            o if o == op::ASSIGN_REF => {
                if !matches!(op.op1_type, OperandType::Cv | OperandType::Var) {
                    return Some(self.refuse(idx, o, REASON_REFERENCE_TARGET));
                }
                let Some(target): Option<Expr> = self.defined_operand_expr(op.op1_type, op.op1)
                else {
                    return Some(self.refuse(idx, o, REASON_REFERENCE_TARGET));
                };
                let Some(source): Option<Expr> = self.operand_expr(op.op2_type, op.op2) else {
                    return Some(self.refuse(idx, o, REASON_EXPRESSION_OPERAND));
                };
                if op.result_type != OperandType::Unused {
                    self.store_result(op, Expr::atom(target.text.clone()));
                }
                Some(format!("{} = &{};", target.text, source.text))
            }
            o if o == op::ASSIGN_OBJ_REF => {
                let target: String = self.property_access(op);
                let Some(source): Option<Expr> = self.op_data_value(idx) else {
                    return Some(self.refuse(idx, o, REASON_EXPRESSION_OPERAND));
                };
                if op.result_type != OperandType::Unused {
                    self.store_result(op, Expr::atom(target.clone()));
                }
                Some(format!("{target} = &{};", source.text))
            }
            o if o == op::ASSIGN_STATIC_PROP_REF => {
                let Some(target): Option<String> = self.static_property(op) else {
                    return Some(self.refuse(idx, o, REASON_CLASS_REFERENCE));
                };
                let Some(source): Option<Expr> = self.op_data_value(idx) else {
                    return Some(self.refuse(idx, o, REASON_EXPRESSION_OPERAND));
                };
                if op.result_type != OperandType::Unused {
                    self.store_result(op, Expr::atom(target.clone()));
                }
                Some(format!("{target} = &{};", source.text))
            }
            o if o == op::ASSIGN_STATIC_PROP => {
                let Some(target): Option<String> = self.static_property(op) else {
                    return Some(self.refuse(idx, o, REASON_CLASS_REFERENCE));
                };
                let Some(value): Option<Expr> = self.op_data_value(idx) else {
                    return Some(self.refuse(idx, o, REASON_EXPRESSION_OPERAND));
                };
                if op.result_type != OperandType::Unused {
                    self.store_result(op, Expr::atom(target.clone()));
                }
                Some(format!("{target} = {};", value.text))
            }
            o if o == op::ASSIGN_STATIC_PROP_OP => {
                let Some(target): Option<String> = self.static_property(op) else {
                    return Some(self.refuse(idx, o, REASON_CLASS_REFERENCE));
                };
                Some(self.compound_member_assign(idx, op, target))
            }
            o if o == op::ASSIGN_OBJ_OP => {
                let target: String = self.property_access(op);
                Some(self.compound_member_assign(idx, op, target))
            }
            o if o == op::ASSIGN_DIM_OP => {
                let Some(target): Option<String> = self.dimension_access(op) else {
                    return Some(self.refuse(idx, o, REASON_EXPRESSION_OPERAND));
                };
                Some(self.compound_member_assign(idx, op, target))
            }
            o if o == op::PRE_INC_OBJ
                || o == op::PRE_DEC_OBJ
                || o == op::POST_INC_OBJ
                || o == op::POST_DEC_OBJ =>
            {
                let target: String = self.property_access(op);
                Some(self.step_member(idx, op, target))
            }
            o if o == op::PRE_INC_STATIC_PROP
                || o == op::PRE_DEC_STATIC_PROP
                || o == op::POST_INC_STATIC_PROP
                || o == op::POST_DEC_STATIC_PROP =>
            {
                let Some(target): Option<String> = self.static_property(op) else {
                    return Some(self.refuse(idx, o, REASON_CLASS_REFERENCE));
                };
                Some(self.step_member(idx, op, target))
            }
            o if o == op::INIT_ARRAY => self.fold_array_init(idx, op),
            o if o == op::ADD_ARRAY_ELEMENT => self.fold_array_append(idx, op),
            o if o == op::ECHO => {
                let arg: Expr = self.operand_expr(op.op1_type, op.op1)?;
                Some(format!("echo {};", arg.text))
            }
            o if o == op::ASSIGN => {
                if !matches!(
                    op.result_type,
                    OperandType::Unused | OperandType::TmpVar | OperandType::Var
                ) {
                    return Some(self.refuse(idx, o, REASON_EXPRESSION_OPERAND));
                }
                let lhs: Option<Expr> = match op.op1_type {
                    OperandType::Cv | OperandType::Var => {
                        self.defined_operand_expr(op.op1_type, op.op1)
                    }
                    _ => None,
                };
                let Some(lhs): Option<Expr> = lhs else {
                    return Some(self.refuse(idx, o, REASON_EXPRESSION_OPERAND));
                };
                let Some(rhs): Option<Expr> = self.defined_operand_expr(op.op2_type, op.op2) else {
                    return Some(self.refuse(idx, o, REASON_EXPRESSION_OPERAND));
                };
                let use_count: u32 = self
                    .result_use_counts
                    .get(idx as usize)
                    .copied()
                    .unwrap_or(0);
                if op.result_type == OperandType::Unused || use_count == 0 {
                    return Some(format!("{} = {};", lhs.text, rhs.text));
                }
                let spill_name: String = self.reserve_spill("assign", idx);
                self.store_result(op, Expr::atom(format!("${spill_name}")));
                Some(format!("${spill_name} = ({} = {});", lhs.text, rhs.text))
            }
            o if o == op::ASSIGN_DIM => {
                let target: Expr = self.operand_expr(op.op1_type, op.op1)?;
                let index: Option<Expr> = self.operand_expr(op.op2_type, op.op2);
                let value: Expr = self
                    .ops
                    .get(idx as usize + 1)
                    .filter(|n: &&Op| n.opcode == op::OP_DATA)
                    .and_then(|data: &Op| self.operand_expr(data.op1_type, data.op1))
                    .unwrap_or_else(|| Expr::atom("null".to_owned()));
                let slot: String = index.map_or_else(
                    || format!("{}[]", target.text),
                    |i: Expr| format!("{}[{}]", target.text, i.text),
                );
                Some(format!("{} = {};", slot, value.text))
            }
            o if o == op::ASSIGN_OP => {
                let lhs: Expr = self.operand_expr(op.op1_type, op.op1)?;
                let rhs: Expr = self
                    .operand_expr(op.op2_type, op.op2)
                    .unwrap_or_else(|| Expr::atom("null".to_owned()));
                Some(format!(
                    "{} {}= {};",
                    lhs.text,
                    assign_op_symbol(op.extended_value),
                    rhs.text
                ))
            }
            o if is_inc_dec(o) => self.fold_inc_dec(idx, op),
            o if o == op::YIELD => self.fold_yield(idx, op),
            o if o == op::YIELD_FROM => self.fold_yield_from(idx, op),
            o if o == op::GENERATOR_RETURN => {
                if op.op1_type == OperandType::Unused {
                    return Some("return;".to_owned());
                }
                self.operand_expr(op.op1_type, op.op1)
                    .map(|value: Expr| format!("return {};", value.text))
            }
            o if o == op::EXIT => {
                if op.op1_type == OperandType::Unused {
                    return Some("exit;".to_owned());
                }
                self.operand_expr(op.op1_type, op.op1)
                    .map(|value: Expr| format!("exit({});", value.text))
            }
            o if o == op::RETURN || o == op::RETURN_BY_REF => {
                if op.op2_type != OperandType::Unused || op.result_type != OperandType::Unused {
                    return Some(self.refuse(idx, o, REASON_EXPRESSION_OPERAND));
                }
                if op.op1_type == OperandType::Unused {
                    return Some(self.refuse(idx, o, REASON_EXPRESSION_OPERAND));
                }
                if op.op1_type == OperandType::Const
                    && matches!(
                        self.literals.get(op.op1 as usize),
                        Some(Literal::Null | Literal::Long(1))
                    )
                {
                    if op.extended_value == u32::MAX {
                        return None;
                    }
                    if o == op::RETURN_BY_REF {
                        return Some(self.refuse(idx, o, REASON_FINAL_RETURN_PROVENANCE));
                    }
                }
                let Some(v): Option<Expr> = self.defined_operand_expr(op.op1_type, op.op1) else {
                    return Some(self.refuse(idx, o, REASON_EXPRESSION_OPERAND));
                };
                Some(format!("return {};", v.text))
            }
            o if o == op::THROW => {
                let v: Expr = self
                    .operand_expr(op.op1_type, op.op1)
                    .unwrap_or_else(|| Expr::atom("$exception".to_owned()));
                Some(format!("throw {};", v.text))
            }
            o if o == op::UNSET_VAR => {
                let v: Expr = self.operand_expr(op.op1_type, op.op1)?;
                Some(format!("unset({});", v.text))
            }
            o if o == op::UNSET_CV => {
                if op.op1_type != OperandType::Cv
                    || op.op2_type != OperandType::Unused
                    || op.result_type != OperandType::Unused
                    || op.extended_value != 0
                {
                    return Some(self.refuse(idx, o, REASON_UNSET_CV_OPERAND));
                }
                let name: Option<String> = self
                    .var_names
                    .get(op.op1 as usize)
                    .and_then(Option::as_deref)
                    .filter(|name: &&str| is_valid_php_ident(name))
                    .map(str::to_owned);
                let Some(name): Option<String> = name else {
                    return Some(self.refuse(idx, o, REASON_UNSET_CV_OPERAND));
                };
                Some(format!("unset(${name});"))
            }
            o if o == op::FREE => None,
            o if o == op::INCLUDE_OR_EVAL => {
                let arg: Expr = self
                    .operand_expr(op.op1_type, op.op1)
                    .unwrap_or_else(|| Expr::atom("''".to_owned()));
                Some(format!("{} {};", include_kind(op.extended_value), arg.text))
            }
            other => {
                let typed_dispatch: bool = matches!(
                    self.literals.get(op.op2 as usize),
                    Some(Literal::SwitchLong(_) | Literal::SwitchString(_))
                );
                let reason: &'static str = match other {
                    op::SWITCH_LONG | op::SWITCH_STRING if typed_dispatch => {
                        REASON_OPTIMIZED_SWITCH
                    }
                    op::MATCH if typed_dispatch => REASON_OPTIMIZED_MATCH,
                    _ => refusal_reason(other),
                };
                Some(self.refuse(idx, other, reason))
            }
        }
    }

    fn property_access(&self, op: &Op) -> String {
        let base: String = match op.op1_type {
            OperandType::Unused => "$this".to_owned(),
            ty => self
                .operand_expr(ty, op.op1)
                .map_or_else(|| "$this".to_owned(), |e: Expr| e.wrapped(PREC_CALL)),
        };
        match self.literal_string(op.op2_type, op.op2) {
            Some(name) if is_valid_php_ident(&name) => format!("{base}->{name}"),
            _ => self.operand_expr(op.op2_type, op.op2).map_or_else(
                || format!("{base}->{{null}}"),
                |e: Expr| format!("{base}->{{{}}}", e.text),
            ),
        }
    }

    fn mark_writable(&mut self, idx: u32, op: &Op) {
        if op.result_type == OperandType::Var {
            self.writable_slots.insert((op.result_type, op.result), idx);
        }
    }

    fn static_property(&self, op: &Op) -> Option<String> {
        let name: String = self.literal_string(op.op1_type, op.op1)?;
        let class: String = self.literal_string(op.op2_type, op.op2)?;
        if !is_valid_php_ident(&name) {
            return None;
        }
        Some(format!("{}::${name}", class_reference(&class)))
    }

    fn class_constant_access(&self, op: &Op) -> Option<String> {
        let class: String = self.literal_string(op.op1_type, op.op1)?;
        let name: String = self.literal_string(op.op2_type, op.op2)?;
        if !is_valid_php_ident(&name) {
            return None;
        }
        Some(format!("{}::{name}", class_reference(&class)))
    }

    fn dimension_access(&self, op: &Op) -> Option<String> {
        let base: Expr = self.operand_expr(op.op1_type, op.op1)?;
        if op.op2_type == OperandType::Unused {
            return Some(format!("{}[]", base.wrapped(PREC_CALL)));
        }
        let index: Expr = self.operand_expr(op.op2_type, op.op2)?;
        Some(format!("{}[{}]", base.wrapped(PREC_CALL), index.text))
    }

    fn op_data_value(&self, idx: u32) -> Option<Expr> {
        let data: Op = self
            .ops
            .get(idx as usize + 1)
            .filter(|next: &&Op| next.opcode == op::OP_DATA)?
            .clone();
        self.operand_expr(data.op1_type, data.op1)
    }

    fn compound_member_assign(&mut self, idx: u32, op: &Op, target: String) -> String {
        let symbol: &'static str = assign_op_symbol(op.extended_value);
        if symbol == "?" {
            return self.refuse(idx, op.opcode, REASON_COMPOUND_OPERATOR);
        }
        let Some(value): Option<Expr> = self.op_data_value(idx) else {
            return self.refuse(idx, op.opcode, REASON_EXPRESSION_OPERAND);
        };
        if op.result_type != OperandType::Unused {
            self.store_result(op, Expr::atom(target.clone()));
        }
        format!("{target} {symbol}= {};", value.text)
    }

    fn step_member(&mut self, idx: u32, op: &Op, target: String) -> String {
        let prefix: bool = matches!(
            op.opcode,
            op::PRE_INC_OBJ | op::PRE_DEC_OBJ | op::PRE_INC_STATIC_PROP | op::PRE_DEC_STATIC_PROP
        );
        let up: bool = matches!(
            op.opcode,
            op::PRE_INC_OBJ | op::POST_INC_OBJ | op::PRE_INC_STATIC_PROP | op::POST_INC_STATIC_PROP
        );
        let symbol: &str = if up { "++" } else { "--" };
        let rendered: String = if prefix {
            format!("{symbol}{target}")
        } else {
            format!("{target}{symbol}")
        };
        if op.result_type == OperandType::Unused {
            return format!("{rendered};");
        }
        let spill: String = self.reserve_spill("step", idx);
        self.store_result(op, Expr::atom(format!("${spill}")));
        format!("${spill} = {rendered};")
    }

    fn literal_string(&self, ty: OperandType, value: u32) -> Option<String> {
        if ty != OperandType::Const {
            return None;
        }
        self.literals
            .get(value as usize)
            .and_then(Literal::as_str)
            .map(str::to_owned)
    }

    fn constant_name(&self, op: &Op) -> Option<String> {
        self.literal_string(op.op2_type, op.op2)
            .or_else(|| self.literal_string(op.op1_type, op.op1))
    }

    fn fold_binary(&mut self, idx: u32, op: &Op) -> Option<String> {
        if !matches!(op.result_type, OperandType::TmpVar | OperandType::Var) {
            return Some(self.refuse(idx, op.opcode, REASON_EXPRESSION_OPERAND));
        }
        let Some(lhs): Option<Expr> = self.defined_operand_expr(op.op1_type, op.op1) else {
            return Some(self.refuse(idx, op.opcode, REASON_EXPRESSION_OPERAND));
        };
        let Some(rhs): Option<Expr> = self.defined_operand_expr(op.op2_type, op.op2) else {
            return Some(self.refuse(idx, op.opcode, REASON_EXPRESSION_OPERAND));
        };
        let (symbol, precedence): (&str, u8) = binary_symbol(op.opcode);
        let (left_precedence, right_precedence): (u8, u8) = if is_right_associative(op.opcode) {
            (precedence + 1, precedence)
        } else {
            (precedence, precedence + 1)
        };
        let text: String = format!(
            "{} {} {}",
            lhs.wrapped(left_precedence),
            symbol,
            rhs.wrapped(right_precedence)
        );
        self.store_result(
            op,
            Expr {
                text,
                prec: precedence,
            },
        );
        None
    }

    fn fold_yield(&mut self, idx: u32, op: &Op) -> Option<String> {
        let value: Expr = self
            .operand_expr(op.op1_type, op.op1)
            .unwrap_or_else(|| Expr::atom("null".to_owned()));
        let text: String = self.operand_expr(op.op2_type, op.op2).map_or_else(
            || format!("yield {}", value.text),
            |key: Expr| format!("yield {} => {}", key.text, value.text),
        );
        self.store_expression_or_statement(idx, op, text)
    }

    fn fold_inc_dec(&mut self, idx: u32, op: &Op) -> Option<String> {
        let use_count: u32 = self
            .result_use_counts
            .get(idx as usize)
            .copied()
            .unwrap_or(0);
        if !matches!(op.op1_type, OperandType::Cv | OperandType::Var)
            || op.op2_type != OperandType::Unused
            || !matches!(
                op.result_type,
                OperandType::Unused | OperandType::TmpVar | OperandType::Var
            )
            || (op.result_type == OperandType::Var && use_count != 0)
        {
            return Some(self.refuse(idx, op.opcode, REASON_INC_DEC_OPERAND));
        }
        if op.op1_type == OperandType::Var {
            let key: (OperandType, u32) = (op.op1_type, op.op1);
            let Some(fetch_idx): Option<u32> = self.writable_slots.get(&key).copied() else {
                return Some(self.refuse(idx, op.opcode, REASON_INC_DEC_OPERAND));
            };
            if fetch_idx.checked_add(1) != Some(idx) {
                return Some(self.refuse(idx, op.opcode, REASON_INC_DEC_OPERAND));
            }
        }
        let Some(target): Option<Expr> = self.defined_operand_expr(op.op1_type, op.op1) else {
            return Some(self.refuse(idx, op.opcode, REASON_INC_DEC_OPERAND));
        };
        let symbol: &str = if matches!(op.opcode, op::PRE_INC | op::POST_INC) {
            "++"
        } else {
            "--"
        };
        let is_prefix: bool = matches!(op.opcode, op::PRE_INC | op::PRE_DEC);
        let text: String = if is_prefix {
            format!("{symbol}{}", target.wrapped(PREC_UNARY))
        } else {
            format!("{}{symbol}", target.wrapped(PREC_CALL))
        };
        if op.result_type == OperandType::Unused || use_count == 0 {
            return Some(format!("{text};"));
        }
        let key: (OperandType, u32) = (op.result_type, op.result);
        let next_consumes_once: bool = use_count == 1
            && self.ops.get(idx as usize + 1).is_some_and(|next: &Op| {
                (next.op1_type, next.op1) == key || (next.op2_type, next.op2) == key
            });
        if next_consumes_once {
            self.store_result(
                op,
                Expr {
                    text,
                    prec: if is_prefix { PREC_UNARY } else { PREC_CALL },
                },
            );
            return None;
        }
        let spill_name: String = self.reserve_spill("incdec", idx);
        self.store_result(op, Expr::atom(format!("${spill_name}")));
        Some(format!("${spill_name} = {text};"))
    }

    fn fold_yield_from(&mut self, idx: u32, op: &Op) -> Option<String> {
        let source: Expr = self.operand_expr(op.op1_type, op.op1)?;
        self.store_expression_or_statement(idx, op, format!("yield from {}", source.text))
    }

    fn store_expression_or_statement(&mut self, idx: u32, op: &Op, text: String) -> Option<String> {
        let use_count: u32 = self
            .result_use_counts
            .get(idx as usize)
            .copied()
            .unwrap_or(0);
        if op.result_type == OperandType::Unused || use_count == 0 {
            return Some(format!("{text};"));
        }
        if use_count > 1 {
            let spill_name: String = self.reserve_spill("yield", idx);
            self.store_result(op, Expr::atom(format!("${spill_name}")));
            return Some(format!("${spill_name} = {text};"));
        }
        self.store_result(
            op,
            Expr {
                text,
                prec: PREC_COALESCE,
            },
        );
        None
    }

    fn reserve_spill(&mut self, family: &str, idx: u32) -> String {
        let base: String = format!("_disrobe_{family}_{idx}");
        if self.reserved_names.insert(base.clone()) {
            return base;
        }
        let candidate_count: usize = self.reserved_names.len().saturating_add(1);
        for suffix in 1..=candidate_count {
            let candidate: String = format!("{base}_{suffix}");
            if self.reserved_names.insert(candidate.clone()) {
                return candidate;
            }
        }
        let fallback: String = format!("{base}_{}", candidate_count.saturating_add(1));
        self.reserved_names.insert(fallback.clone());
        fallback
    }

    fn fold_unary_call(&mut self, op: &Op, name: &str) {
        if let Some(arg) = self.operand_expr(op.op1_type, op.op1) {
            let text: String = format!("{}({})", name, arg.text);
            self.store_result(
                op,
                Expr {
                    text,
                    prec: PREC_CALL,
                },
            );
        }
    }

    fn fold_fetch_dim(&mut self, op: &Op) {
        let base: Option<Expr> = self.operand_expr(op.op1_type, op.op1);
        let index: Option<Expr> = self.operand_expr(op.op2_type, op.op2);
        if let (Some(b), Some(idx)) = (base, index) {
            let text: String = format!("{}[{}]", b.wrapped(PREC_CALL), idx.text);
            self.store_result(
                op,
                Expr {
                    text,
                    prec: PREC_ATOM,
                },
            );
        }
    }

    fn fold_variable_variable(&mut self, idx: u32, op: &Op) -> Option<String> {
        let Some(name): Option<Expr> = self.operand_expr(op.op1_type, op.op1) else {
            return Some(self.refuse(idx, op.opcode, REASON_EXPRESSION_OPERAND));
        };
        let text: String = match op.op1_type {
            OperandType::Cv => format!("${}", name.text),
            OperandType::Const => match self.literals.get(op.op1 as usize) {
                Some(Literal::Str(s)) if is_valid_php_ident(s) => format!("${s}"),
                _ => format!("${{{}}}", name.text),
            },
            _ => format!("${{{}}}", name.text),
        };
        self.store_result(
            op,
            Expr {
                text,
                prec: PREC_ATOM,
            },
        );
        if op.result_type == OperandType::Var && matches!(op.opcode, op::FETCH_W | op::FETCH_RW) {
            self.writable_slots.insert((op.result_type, op.result), idx);
        }
        None
    }

    fn fold_fetch_is(&mut self, idx: u32, op: &Op) -> Option<String> {
        if op.extended_value != 0
            || op.op2_type != OperandType::Unused
            || op.op2 != 0
            || op.result_type != OperandType::TmpVar
        {
            return Some(self.refuse(idx, op.opcode, REASON_FETCH_IS_SHAPE));
        }
        let name: Option<Expr> = match op.op1_type {
            OperandType::Const => self
                .literals
                .get(op.op1 as usize)
                .map(Literal::render)
                .map(Expr::atom),
            OperandType::Cv => self
                .var_names
                .get(op.op1 as usize)
                .and_then(Option::as_deref)
                .filter(|name: &&str| is_valid_php_ident(name))
                .map(|name: &str| Expr::atom(format!("${name}"))),
            OperandType::TmpVar | OperandType::Var => {
                self.slots.get(&(op.op1_type, op.op1)).cloned()
            }
            OperandType::Unused => None,
        };
        let Some(name): Option<Expr> = name else {
            return Some(self.refuse(idx, op.opcode, REASON_EXPRESSION_OPERAND));
        };
        let text: String = match op.op1_type {
            OperandType::Cv => format!("${}", name.text),
            OperandType::Const => match self.literals.get(op.op1 as usize) {
                Some(Literal::Str(value)) if is_valid_php_ident(value) => format!("${value}"),
                _ => format!("${{{}}}", name.text),
            },
            OperandType::TmpVar | OperandType::Var => format!("${{{}}}", name.text),
            OperandType::Unused => {
                return Some(self.refuse(idx, op.opcode, REASON_EXPRESSION_OPERAND));
            }
        };
        self.store_result(
            op,
            Expr {
                text,
                prec: PREC_ATOM,
            },
        );
        None
    }

    fn array_element(&self, op: &Op) -> Option<String> {
        let value: Expr = self.operand_expr(op.op1_type, op.op1)?;
        if op.op2_type == OperandType::Unused {
            return Some(value.text);
        }
        let key: Expr = self.operand_expr(op.op2_type, op.op2)?;
        Some(format!("{} => {}", key.text, value.text))
    }

    fn fold_array_init(&mut self, idx: u32, op: &Op) -> Option<String> {
        if op.op1_type == OperandType::Unused && op.op2_type != OperandType::Unused {
            return Some(self.refuse(idx, op.opcode, REASON_ARRAY_SHAPE));
        }
        let mut parts: Vec<String> = Vec::new();
        if op.op1_type != OperandType::Unused {
            let Some(first): Option<String> = self.array_element(op) else {
                return Some(self.refuse(idx, op.opcode, REASON_EXPRESSION_OPERAND));
            };
            parts.push(first);
        }
        let text: String = format!("[{}]", parts.join(", "));
        self.store_result(
            op,
            Expr {
                text,
                prec: PREC_ATOM,
            },
        );
        None
    }

    fn fold_array_append(&mut self, idx: u32, op: &Op) -> Option<String> {
        if op.op1_type == OperandType::Unused {
            return Some(self.refuse(idx, op.opcode, REASON_ARRAY_SHAPE));
        }
        let slot: (OperandType, u32) = (op.result_type, op.result);
        let Some(array): Option<Expr> = self.slots.get(&slot).cloned() else {
            return Some(self.refuse(idx, op.opcode, REASON_EXPRESSION_OPERAND));
        };
        let Some(element): Option<String> = self.array_element(op) else {
            return Some(self.refuse(idx, op.opcode, REASON_EXPRESSION_OPERAND));
        };
        let inner: String = array
            .text
            .strip_prefix('[')
            .and_then(|s: &str| s.strip_suffix(']'))
            .map(str::to_owned)
            .unwrap_or(array.text);
        let joined: String = if inner.is_empty() {
            element
        } else {
            format!("{inner}, {element}")
        };
        self.writable_slots.remove(&slot);
        self.slots.insert(
            slot,
            Expr {
                text: format!("[{joined}]"),
                prec: PREC_ATOM,
            },
        );
        None
    }

    fn push_send(&mut self, idx: u32, op: &Op) -> Option<String> {
        let Some(value): Option<Expr> = self.operand_expr(op.op1_type, op.op1) else {
            return Some(self.refuse(idx, op.opcode, REASON_EXPRESSION_OPERAND));
        };
        let argument: PendingArgument = match op.op2_type {
            OperandType::Unused => {
                let Some(call): Option<&PendingCall> = self.call_stack.last() else {
                    return Some(self.refuse(idx, op.opcode, REASON_CALL_ARGUMENT_SHAPE));
                };
                let Some(expected_position): Option<u32> = call.positional_count.checked_add(1)
                else {
                    return Some(self.refuse(idx, op.opcode, REASON_CALL_ARGUMENT_SHAPE));
                };
                if op.op2 != 0 && op.op2 != expected_position {
                    return Some(self.refuse(idx, op.opcode, REASON_CALL_ARGUMENT_SHAPE));
                }
                PendingArgument::Positional(value.text)
            }
            OperandType::Const => {
                let Some(Literal::Str(name)): Option<&Literal> = self.literals.get(op.op2 as usize)
                else {
                    return Some(self.refuse(idx, op.opcode, REASON_CALL_ARGUMENT_NAME));
                };
                if !is_valid_php_ident(name) {
                    return Some(self.refuse(idx, op.opcode, REASON_CALL_ARGUMENT_NAME));
                }
                PendingArgument::Named {
                    name: name.clone(),
                    value: value.text,
                }
            }
            _ => return Some(self.refuse(idx, op.opcode, REASON_CALL_ARGUMENT_SHAPE)),
        };
        let positional: bool = matches!(argument, PendingArgument::Positional(_));
        let refusal: Option<String> = self.push_call_argument(idx, op.opcode, argument);
        if refusal.is_none()
            && positional
            && let Some(call) = self.call_stack.last_mut()
        {
            call.positional_count = call.positional_count.saturating_add(1);
        }
        refusal
    }

    fn push_unpack(&mut self, idx: u32, op: &Op) -> Option<String> {
        if op.op2_type != OperandType::Unused || op.result_type != OperandType::Unused {
            return Some(self.refuse(idx, op.opcode, REASON_CALL_ARGUMENT_SHAPE));
        }
        let Some(call): Option<&PendingCall> = self.call_stack.last() else {
            return Some(self.refuse(idx, op.opcode, REASON_CALL_ARGUMENT_SHAPE));
        };
        if op.op2 != call.positional_count {
            return Some(self.refuse(idx, op.opcode, REASON_CALL_ARGUMENT_SHAPE));
        }
        let Some(value): Option<Expr> = self.operand_expr(op.op1_type, op.op1) else {
            return Some(self.refuse(idx, op.opcode, REASON_EXPRESSION_OPERAND));
        };
        self.push_call_argument(idx, op.opcode, PendingArgument::Unpacked(value.text))
    }

    fn push_call_argument(
        &mut self,
        idx: u32,
        opcode: u8,
        argument: PendingArgument,
    ) -> Option<String> {
        let Some(call): Option<&PendingCall> = self.call_stack.last() else {
            return Some(self.refuse(idx, opcode, REASON_CALL_ARGUMENT_SHAPE));
        };
        let invalid_order: bool = match &argument {
            PendingArgument::Positional(_) => call.args.iter().any(|existing: &PendingArgument| {
                matches!(existing, PendingArgument::Named { .. } | PendingArgument::Unpacked(_))
            }),
            PendingArgument::Unpacked(_) => call
                .args
                .iter()
                .any(|existing: &PendingArgument| matches!(existing, PendingArgument::Named { .. })),
            PendingArgument::Named { name, .. } => call.args.iter().any(
                |existing: &PendingArgument| {
                    matches!(existing, PendingArgument::Named { name: existing_name, .. } if existing_name == name)
                },
            ),
        };
        let rendered: usize = call
            .rendered_args
            .saturating_add(argument.rendered_len())
            .saturating_add(usize::from(!call.args.is_empty()) * 2);
        if invalid_order
            || call.args.len() >= SANE_CALL_ARGUMENT_CAP
            || rendered > SANE_CALL_RENDER_CAP
        {
            return Some(self.refuse(idx, opcode, REASON_CALL_ARGUMENT_SHAPE));
        }
        let Some(call): Option<&mut PendingCall> = self.call_stack.last_mut() else {
            return Some(self.refuse(idx, opcode, REASON_CALL_ARGUMENT_SHAPE));
        };
        call.rendered_args = rendered;
        call.args.push(argument);
        None
    }

    fn finish_call(&mut self, idx: u32, op: &Op) -> Option<String> {
        let call: PendingCall = self.call_stack.pop()?;
        let args: String = call
            .args
            .iter()
            .map(PendingArgument::render)
            .collect::<Vec<String>>()
            .join(", ");
        let text: String = format!("{}({args})", render_pending_callable_target(&call));
        let (target, producer): (Option<(OperandType, u32)>, u32) = call.result.map_or_else(
            || {
                (
                    (op.result_type != OperandType::Unused).then_some((op.result_type, op.result)),
                    idx,
                )
            },
            |(ty, slot, produced_at): (OperandType, u32, u32)| (Some((ty, slot)), produced_at),
        );
        let uses: u32 = self
            .result_use_counts
            .get(producer as usize)
            .copied()
            .unwrap_or(0);
        match target {
            Some(key) if uses > 0 => {
                self.writable_slots.remove(&key);
                self.slots.insert(
                    key,
                    Expr {
                        text,
                        prec: PREC_CALL,
                    },
                );
                None
            }
            _ => Some(format!("{text};")),
        }
    }

    fn finish_callable_convert(&mut self, idx: u32, op: &Op) -> Option<String> {
        let Some(call): Option<PendingCall> = self.call_stack.pop() else {
            return Some(self.refuse(idx, op.opcode, REASON_CALLABLE_CONVERT));
        };
        if op.op1_type != OperandType::Unused
            || op.op2_type != OperandType::Unused
            || op.op1 != 0
            || op.op2 != 0
            || op.result_type != OperandType::TmpVar
            || op.extended_value != 0
            || !call.callable_shape
            || !call.args.is_empty()
            || call.rendered_args != 0
            || call.positional_count != 0
            || call.result.is_some()
        {
            return Some(self.refuse(idx, op.opcode, REASON_CALLABLE_CONVERT));
        }
        let text: String = format!("{}(...)", render_pending_callable_target(&call));
        self.store_result(
            op,
            Expr {
                text,
                prec: PREC_CALL,
            },
        );
        None
    }

    fn store_result(&mut self, op: &Op, expr: Expr) {
        if op.result_type == OperandType::Unused {
            return;
        }
        let key: (OperandType, u32) = (op.result_type, op.result);
        self.writable_slots.remove(&key);
        self.slots.insert(key, expr);
    }

    fn operand_expr(&self, ty: OperandType, value: u32) -> Option<Expr> {
        match ty {
            OperandType::Unused => None,
            OperandType::Const => Some(Expr::atom(
                self.literals
                    .get(value as usize)
                    .map_or_else(|| format!("CONST#{value}"), Literal::render),
            )),
            OperandType::Cv => Some(Expr::atom(format!("${}", self.cv(value)))),
            OperandType::TmpVar | OperandType::Var => self
                .slots
                .get(&(ty, value))
                .cloned()
                .or_else(|| Some(Expr::atom(slot_fallback(ty, value)))),
        }
    }

    fn defined_operand_expr(&self, ty: OperandType, value: u32) -> Option<Expr> {
        match ty {
            OperandType::Unused => None,
            OperandType::Const => self
                .literals
                .get(value as usize)
                .map(Literal::render)
                .map(Expr::atom),
            OperandType::Cv => Some(Expr::atom(format!("${}", self.cv(value)))),
            OperandType::TmpVar | OperandType::Var => self.slots.get(&(ty, value)).cloned(),
        }
    }

    fn callable_operand_expr(&self, ty: OperandType, value: u32) -> Option<Expr> {
        match ty {
            OperandType::Cv => self
                .var_names
                .get(value as usize)
                .and_then(Option::as_ref)
                .filter(|name: &&String| is_valid_php_ident(name))
                .map(|name: &String| Expr::atom(format!("${name}"))),
            OperandType::Unused | OperandType::Const | OperandType::TmpVar | OperandType::Var => {
                self.defined_operand_expr(ty, value)
            }
        }
    }

    fn callable_literal_string(&self, ty: OperandType, value: u32) -> Option<&str> {
        (ty == OperandType::Const)
            .then(|| self.literals.get(value as usize).and_then(Literal::as_str))
            .flatten()
    }
}

fn render_pending_callable_target(call: &PendingCall) -> String {
    if call.is_method {
        let sep: &str = if call.is_static {
            "::"
        } else if call.nullsafe {
            "?->"
        } else {
            "->"
        };
        let object: String = call.object.clone().unwrap_or_else(|| "$this".to_owned());
        format!("{object}{sep}{}", call.callee)
    } else {
        call.callee.clone()
    }
}

fn loop_relift_charge(charged: usize, work: usize) -> Option<usize> {
    let total: usize = charged.checked_add(work)?;
    (total <= SANE_LOOP_RELIFT_WORK_CAP).then_some(total)
}

fn switch_state_work_within_budget(arms: usize, slots: usize, writable_slots: usize) -> bool {
    let Some(state_width): Option<usize> = slots
        .checked_add(writable_slots)
        .and_then(|width: usize| width.checked_add(1))
    else {
        return false;
    };
    let Some(work): Option<usize> = arms
        .checked_add(1)
        .and_then(|states: usize| states.checked_mul(state_width))
    else {
        return false;
    };
    work <= SANE_SWITCH_STATE_WORK_CAP
}

fn switch_label_work_after(current: usize, additional: usize) -> Option<usize> {
    current
        .checked_add(additional)
        .filter(|work: &usize| *work <= SANE_SWITCH_LABEL_WORK_CAP)
}

fn begins_inside_switch_dispatch(
    ops: &[Op],
    index: usize,
    comparison_opcode: u8,
    subject_key: (OperandType, u32),
) -> bool {
    let mut cursor: usize = index;
    while let Some(previous_index) = cursor.checked_sub(1) {
        let Some(previous): Option<&Op> = ops.get(previous_index) else {
            return false;
        };
        if previous.opcode == op::JMPNZ {
            let Some(comparison_index): Option<usize> = previous_index.checked_sub(1) else {
                return false;
            };
            return is_linear_switch_comparison(
                ops,
                comparison_index,
                comparison_opcode,
                subject_key,
            );
        }
        if previous.branch_target() != Branch::None
            || previous.result_type != OperandType::TmpVar
            || !(is_binary(previous.opcode)
                || matches!(
                    previous.opcode,
                    op::BOOL_NOT | op::BOOL | op::QM_ASSIGN | op::CAST
                ))
        {
            return false;
        }
        cursor = previous_index;
    }
    false
}

fn is_linear_switch_comparison(
    ops: &[Op],
    index: usize,
    comparison_opcode: u8,
    subject_key: (OperandType, u32),
) -> bool {
    let Some(candidate): Option<&Op> = ops.get(index) else {
        return false;
    };
    let Some(jump): Option<&Op> = index.checked_add(1).and_then(|next: usize| ops.get(next)) else {
        return false;
    };
    candidate.opcode == comparison_opcode
        && (candidate.op1_type, candidate.op1) == subject_key
        && candidate.result_type == OperandType::TmpVar
        && jump.opcode == op::JMPNZ
        && (jump.op1_type, jump.op1) == (candidate.result_type, candidate.result)
}

const fn is_switch_terminal(opcode: u8) -> bool {
    matches!(
        opcode,
        op::RETURN | op::RETURN_BY_REF | op::GENERATOR_RETURN | op::THROW | op::EXIT
    )
}

const REASON_CAST_KIND: &str = "the cast target type is not a php 8 cast";
const REASON_ISSET_MODE: &str = "the isset or empty mode flag is not a php 8 mode";
const REASON_INC_DEC_OPERAND: &str =
    "increment or decrement requires a writable variable and an optional temporary result";
const REASON_CONSTANT_NAME: &str = "the constant name is not a literal string in this op array";
const REASON_EXPRESSION_OPERAND: &str =
    "an expression operand has no literal or reaching definition";
const REASON_FETCH_IS_SHAPE: &str =
    "FETCH_IS must be a local read with one defined name operand and a temporary result";
const REASON_FETCH_CLASS_SHAPE: &str =
    "FETCH_CLASS must carry one defined class operand and a variable result";
const REASON_UNSET_CV_OPERAND: &str =
    "UNSET_CV requires one declared compiled variable and no other operands";
const REASON_FINAL_RETURN_PROVENANCE: &str =
    "a constant null or 1 return lacks compiler-final provenance";
const REASON_REFERENCE_TARGET: &str =
    "a reference assignment requires a writable variable as its target";
const REASON_CLASS_REFERENCE: &str =
    "the class reference on this member access is not carried in this op array";
const REASON_COMPOUND_OPERATOR: &str =
    "the compound assignment operator is not a php 8 binary operator";
const LIMITATION_OPAQUE_ARRAY_LITERAL: &str = "the constant array literal's elements are not carried in this op array, so an empty array \
     and a populated one are indistinguishable here";
const LIMITATION_VARIADIC_PARAMETER_REFERENCE: &str = "the op array does not carry parameter metadata, so a by-value variadic parameter and a by-reference variadic parameter are indistinguishable";
const REASON_TYPE_CHECK: &str =
    "the type check names no php 8 type combination this container can spell";
const REASON_ARRAY_SHAPE: &str =
    "an array element carries a key with no value, so this is not a php 8 array construction";
const REASON_CALL_ARGUMENT_NAME: &str =
    "the named call argument has no literal php identifier in this op array";
const REASON_CALL_ARGUMENT_SHAPE: &str =
    "the call argument order, container evidence, or bounded render shape is invalid";
const REASON_CALLABLE_CONVERT: &str =
    "the first-class callable has no verified zero-argument call frame";
const REASON_VARIADIC_PARAMETER_SHAPE: &str =
    "the variadic receive does not name the cv immediately after the fixed parameters";
const REASON_LIST_DESTRUCTURING: &str = "list destructuring requires a literal key, a defined container, and one bounded assignment tree";
const REASON_JUMP: &str = "this jump matched no structured control-flow shape";
const REASON_GOTO_TARGET: &str = "a jump targets a position no label can be placed at, so this whole function is \
     rejected rather than recovered around it";
const REASON_ITERATION: &str =
    "the foreach reset, fetch and back edge do not form a php 8 iteration";
const REASON_ROPE: &str =
    "the rope operands, element indexes or declared length do not form a php 8 rope";
const REASON_ROPE_BUDGET: &str = "the rope exceeds the bounded php 8 rope folding budget";
const REASON_DISPATCH: &str = "switch and match dispatch is not reconstructed";
const REASON_OPTIMIZED_SWITCH: &str =
    "the optimized switch table or its control-flow region is structurally ambiguous";
const REASON_OPTIMIZED_MATCH: &str =
    "the optimized match table or its result region is structurally ambiguous";
const REASON_EXCEPTION: &str = "try, catch and finally regions are not reconstructed";
const REASON_DECLARATION: &str = "the declared body is not carried in this op array";
const REASON_UNMODELLED: &str = "the expression lifter does not model this opcode";

#[must_use]
const fn refusal_reason(opcode: u8) -> &'static str {
    match opcode {
        op::JMP
        | op::JMPZ
        | op::JMPNZ
        | op::JMPZ_EX
        | op::JMPNZ_EX
        | op::JMP_SET
        | op::JMP_NULL
        | op::COALESCE => REASON_JUMP,
        op::SWITCH_LONG | op::SWITCH_STRING | op::MATCH | op::CASE => REASON_DISPATCH,
        op::ROPE_INIT | op::ROPE_ADD | op::ROPE_END => REASON_ROPE,
        op::CATCH | op::FAST_CALL | op::FAST_RET | op::DISCARD_EXCEPTION => REASON_EXCEPTION,
        op::FETCH_LIST_R => REASON_LIST_DESTRUCTURING,
        op::DECLARE_FUNCTION
        | op::DECLARE_LAMBDA_FUNCTION
        | op::DECLARE_CLASS
        | op::DECLARE_CLASS_DELAYED
        | op::DECLARE_ANON_CLASS => REASON_DECLARATION,
        _ => REASON_UNMODELLED,
    }
}

const TYPE_MASK_NOT_NULL: u32 = 0x0C | 0x10 | 0x20 | 0x40 | 0x80 | 0x100 | 0x200;

enum TypeProbe {
    Builtin(&'static str),
    NotNull,
}

#[must_use]
const fn type_check_probe(mask: u32) -> Option<TypeProbe> {
    match mask {
        2 => Some(TypeProbe::Builtin("is_null")),
        12 => Some(TypeProbe::Builtin("is_bool")),
        16 => Some(TypeProbe::Builtin("is_int")),
        32 => Some(TypeProbe::Builtin("is_float")),
        64 => Some(TypeProbe::Builtin("is_string")),
        128 => Some(TypeProbe::Builtin("is_array")),
        256 => Some(TypeProbe::Builtin("is_object")),
        512 => Some(TypeProbe::Builtin("is_resource")),
        TYPE_MASK_NOT_NULL => Some(TypeProbe::NotNull),
        _ => None,
    }
}

#[must_use]
const fn cast_symbol(extended_value: u32) -> Option<&'static str> {
    match extended_value {
        4 => Some("(int)"),
        5 => Some("(float)"),
        6 => Some("(string)"),
        7 => Some("(array)"),
        8 => Some("(object)"),
        18 => Some("(bool)"),
        _ => None,
    }
}

#[must_use]
const fn isset_probe(extended_value: u32) -> Option<&'static str> {
    match extended_value {
        0 => Some("isset"),
        1 => Some("empty"),
        _ => None,
    }
}

#[must_use]
const fn is_isset_isempty(opcode: u8) -> bool {
    matches!(
        opcode,
        op::ISSET_ISEMPTY_CV
            | op::ISSET_ISEMPTY_VAR
            | op::ISSET_ISEMPTY_DIM_OBJ
            | op::ISSET_ISEMPTY_PROP_OBJ
    )
}

#[must_use]
const fn is_inc_dec(opcode: u8) -> bool {
    matches!(
        opcode,
        op::PRE_INC | op::PRE_DEC | op::POST_INC | op::POST_DEC
    )
}

#[must_use]
fn class_reference(name: &str) -> String {
    let unqualified: &str = name.trim_start_matches('\\');
    if unqualified
        .split('\\')
        .all(|segment: &str| is_valid_php_ident(segment))
    {
        return unqualified.to_owned();
    }
    name.to_owned()
}

fn constant_reference(name: &str) -> String {
    let unqualified: &str = name.trim_start_matches('\\');
    if !unqualified.is_empty()
        && unqualified
            .split('\\')
            .all(|segment: &str| is_valid_php_ident(segment))
    {
        return format!("\\{unqualified}");
    }
    format!("constant('{}')", name.replace('\\', "\\\\"))
}

#[must_use]
fn slot_fallback(kind: OperandType, value: u32) -> String {
    match kind {
        OperandType::TmpVar => format!("$tmp{value}"),
        OperandType::Var => format!("$var{value}"),
        _ => format!("$slot{value}"),
    }
}

#[must_use]
const fn is_right_associative(opcode: u8) -> bool {
    opcode == op::POW
}

#[must_use]
const fn is_binary(opcode: u8) -> bool {
    matches!(
        opcode,
        op::ADD
            | op::SUB
            | op::MUL
            | op::DIV
            | op::MOD
            | op::POW
            | op::SL
            | op::SR
            | op::CONCAT
            | op::BW_OR
            | op::BW_AND
            | op::BW_XOR
            | op::IS_IDENTICAL
            | op::IS_NOT_IDENTICAL
            | op::IS_EQUAL
            | op::IS_NOT_EQUAL
            | op::IS_SMALLER
            | op::IS_SMALLER_OR_EQUAL
            | op::SPACESHIP
    )
}

#[must_use]
const fn is_rope_intermediate(opcode: u8) -> bool {
    is_binary(opcode)
        || is_isset_isempty(opcode)
        || is_send(opcode)
        || matches!(opcode, op::SEND_UNPACK | op::CHECK_UNDEF_ARGS)
        || matches!(
            opcode,
            op::NOP
                | op::BOOL
                | op::BOOL_NOT
                | op::QM_ASSIGN
                | op::CAST
                | op::BW_NOT
                | op::STRLEN
                | op::COUNT
                | op::FETCH_DIM_R
                | op::FETCH_OBJ_R
                | op::FETCH_CONSTANT
                | op::INSTANCEOF
                | op::CLONE
                | op::FETCH_R
                | op::FETCH_IS
                | op::FREE
                | op::VERIFY_RETURN_TYPE
                | op::HANDLE_EXCEPTION
                | op::INIT_FCALL
                | op::INIT_FCALL_BY_NAME
                | op::INIT_NS_FCALL
                | op::INIT_METHOD_CALL
                | op::INIT_STATIC_METHOD_CALL
                | op::DO_FCALL
                | op::DO_ICALL
                | op::DO_UCALL
                | op::DO_FCALL_BY_NAME
                | op::NEW
                | op::INIT_ARRAY
                | op::ADD_ARRAY_ELEMENT
        )
}

#[must_use]
const fn is_send(opcode: u8) -> bool {
    matches!(
        opcode,
        op::SEND_VAL | op::SEND_VAL_EX | op::SEND_VAR | op::SEND_VAR_EX | op::SEND_REF
    )
}

#[must_use]
const fn binary_symbol(opcode: u8) -> (&'static str, u8) {
    match opcode {
        op::ADD => ("+", PREC_ADD),
        op::SUB => ("-", PREC_ADD),
        op::MUL => ("*", PREC_MUL),
        op::DIV => ("/", PREC_MUL),
        op::MOD => ("%", PREC_MUL),
        op::POW => ("**", PREC_POW),
        op::SL => ("<<", PREC_SHIFT),
        op::SR => (">>", PREC_SHIFT),
        op::CONCAT => (".", PREC_CONCAT),
        op::BW_OR => ("|", PREC_BITOR),
        op::BW_AND => ("&", PREC_BITAND),
        op::BW_XOR => ("^", PREC_BITXOR),
        op::IS_IDENTICAL => ("===", PREC_CMP),
        op::IS_NOT_IDENTICAL => ("!==", PREC_CMP),
        op::IS_EQUAL => ("==", PREC_CMP),
        op::IS_NOT_EQUAL => ("!=", PREC_CMP),
        op::IS_SMALLER => ("<", PREC_REL),
        op::IS_SMALLER_OR_EQUAL => ("<=", PREC_REL),
        op::SPACESHIP => ("<=>", PREC_CMP),
        _ => ("/* op */", PREC_ATOM),
    }
}

#[must_use]
const fn builtin_name(opcode: u8) -> &'static str {
    match opcode {
        op::STRLEN => "strlen",
        op::COUNT => "count",
        _ => "builtin",
    }
}

fn strip_quotes(s: &str) -> String {
    s.trim_matches('\'').to_owned()
}

const fn assign_op_symbol(ext: u32) -> &'static str {
    match ext as u8 {
        o if o == op::ADD => "+",
        o if o == op::SUB => "-",
        o if o == op::MUL => "*",
        o if o == op::DIV => "/",
        o if o == op::MOD => "%",
        o if o == op::CONCAT => ".",
        o if o == op::POW => "**",
        o if o == op::SL => "<<",
        o if o == op::SR => ">>",
        o if o == op::BW_OR => "|",
        o if o == op::BW_AND => "&",
        o if o == op::BW_XOR => "^",
        _ => "?",
    }
}

const fn include_kind(ext: u32) -> &'static str {
    match ext {
        1 => "include",
        2 => "include_once",
        4 => "require",
        8 => "require_once",
        _ => "eval",
    }
}

#[cfg(test)]
mod render_tests {
    use super::Literal;

    #[test]
    fn integral_double_keeps_float_type_on_reemit() {
        assert_eq!(Literal::Double(2.0).render(), "2.0");
        assert_eq!(Literal::Double(-0.0).render(), "-0.0");
        assert_eq!(Literal::Double(1.0e10).render(), "10000000000.0");
        assert_eq!(Literal::Long(2).render(), "2");
        assert_eq!(Literal::Double(2.5).render(), "2.5");
        assert_eq!(Literal::Double(f64::INFINITY).render(), "INF");
        assert_eq!(Literal::Double(f64::NEG_INFINITY).render(), "-INF");
        assert_eq!(Literal::Double(f64::NAN).render(), "NAN");
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod oparray_bounds_tests {
    use super::*;

    fn try_catch_wire(ops: u32, rows: &[[u32; 4]], declared_rows: Option<u32>) -> Vec<u8> {
        let mut wire: Vec<u8> = Vec::new();
        wire.extend_from_slice(&OPARRAY_MAGIC[..]);
        wire.push(4);
        wire.push(0);
        wire.push(0);
        wire.push(0);
        wire.extend_from_slice(&0u32.to_le_bytes());
        wire.extend_from_slice(&0u32.to_le_bytes());
        wire.extend_from_slice(&0u32.to_le_bytes());
        wire.extend_from_slice(&ops.to_le_bytes());
        for _ in 0..ops {
            wire.push(op::NOP);
            wire.push(0);
            wire.push(0);
            wire.push(0);
            for _ in 0..5 {
                wire.extend_from_slice(&0u32.to_le_bytes());
            }
        }
        let count: u32 = declared_rows.unwrap_or_else(|| u32::try_from(rows.len()).unwrap_or(0));
        wire.extend_from_slice(&count.to_le_bytes());
        for row in rows {
            for field in row {
                wire.extend_from_slice(&field.to_le_bytes());
            }
        }
        wire.extend_from_slice(&0u32.to_le_bytes());
        wire
    }

    #[test]
    fn a_try_catch_boundary_outside_the_op_array_is_a_typed_error() {
        for row in [[9, 0, 0, 0], [0, 9, 0, 0], [0, 0, 9, 0], [0, 0, 0, 9]] {
            let wire: Vec<u8> = try_catch_wire(4, &[row], None);
            let err: Error = parse_oparray(&wire)
                .expect_err("a try_catch boundary past the last opcode must be rejected");
            assert!(
                matches!(
                    err,
                    Error::OpArrayTryCatchRange {
                        value: 9,
                        ops: 4,
                        ..
                    }
                ),
                "row {row:?} must be rejected against the op count, got {err:?}"
            );
        }
    }

    #[test]
    fn a_try_op_of_zero_is_accepted_because_php_compiles_a_leading_try_there() {
        let wire: Vec<u8> = try_catch_wire(4, &[[0, 2, 0, 0]], None);
        let parsed: OpArray = parse_oparray(&wire).expect("try_op 0 is a real php shape");
        assert_eq!(
            parsed.try_catch,
            vec![TryCatch {
                try_op: 0,
                catch_op: Some(2),
                finally_op: None,
                finally_end: None,
            }]
        );
    }

    #[test]
    fn an_oversized_try_catch_count_is_rejected_before_reserving() {
        let wire: Vec<u8> = try_catch_wire(4, &[], Some(SANE_TRY_CATCH_CAP + 1));
        let err: Error =
            parse_oparray(&wire).expect_err("a try_catch count past the sane cap must be rejected");
        assert!(
            matches!(
                err,
                Error::OpArrayFieldOversize {
                    field: "try_catch",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn a_declared_try_catch_count_exceeding_remaining_input_is_rejected_before_reserving() {
        let wire: Vec<u8> = try_catch_wire(4, &[], Some(SANE_TRY_CATCH_CAP));
        let err: Error = parse_oparray(&wire)
            .expect_err("a try_catch count past the remaining input must be rejected");
        assert!(matches!(err, Error::OpArrayTruncated { .. }), "got {err:?}");
    }

    #[test]
    fn a_version_three_container_carries_no_try_catch_table() {
        let mut wire: Vec<u8> = Vec::new();
        wire.extend_from_slice(&OPARRAY_MAGIC[..]);
        wire.push(3);
        wire.push(0);
        wire.push(0);
        wire.push(0);
        wire.extend_from_slice(&0u32.to_le_bytes());
        wire.extend_from_slice(&0u32.to_le_bytes());
        wire.extend_from_slice(&0u32.to_le_bytes());
        wire.extend_from_slice(&0u32.to_le_bytes());
        wire.extend_from_slice(&0u32.to_le_bytes());
        let parsed: OpArray =
            parse_oparray(&wire).expect("a version 3 container still parses without a table");
        assert!(parsed.try_catch.is_empty());
    }

    #[test]
    fn declared_ops_count_exceeding_remaining_input_is_rejected_before_reserving() {
        const DECLARED: u32 = 3_000_000;
        let mut wire: Vec<u8> = Vec::new();
        wire.extend_from_slice(&OPARRAY_MAGIC[..]);
        wire.push(OPARRAY_VERSION);
        wire.push(0);
        wire.push(0);
        wire.push(0);
        wire.extend_from_slice(&0u32.to_le_bytes());
        wire.extend_from_slice(&0u32.to_le_bytes());
        wire.extend_from_slice(&0u32.to_le_bytes());
        wire.extend_from_slice(&DECLARED.to_le_bytes());
        let err: Error = parse_oparray(&wire).expect_err("oversized ops count must be rejected");
        assert!(
            matches!(err, Error::OpArrayTruncated { need, .. } if need as u32 == DECLARED),
            "declared count must be rejected against remaining input, got {err:?}"
        );
    }

    fn echo_const() -> Op {
        Op {
            opcode: op::ECHO,
            op1_type: OperandType::Const,
            op2_type: OperandType::Unused,
            result_type: OperandType::Unused,
            op1: 0,
            op2: 0,
            result: 0,
            extended_value: 0,
            lineno: 0,
        }
    }

    #[test]
    fn straight_line_lift_scales_sub_quadratically() {
        use std::time::{Duration, Instant};
        fn lift_secs(n: usize) -> f64 {
            let ops: Vec<Op> = (0..n).map(|_| echo_const()).collect();
            let literals: Vec<Literal> = vec![Literal::Str("x".to_owned())];
            let var_names: Vec<Option<String>> = Vec::new();
            let start: Instant = Instant::now();
            let stmts: Vec<Stmt> = Lifter::new(&ops, &literals, &var_names, &[], &[], 0).lift();
            let elapsed: Duration = start.elapsed();
            assert_eq!(
                stmts.len(),
                n,
                "each straight-line op should lift to one statement"
            );
            elapsed.as_secs_f64()
        }
        const BASE: usize = 200_000;
        let t1: f64 = lift_secs(BASE);
        let t4: f64 = lift_secs(BASE * 4);
        let ratio: f64 = t4 / t1.max(1e-6);
        assert!(
            ratio < 8.0,
            "lift cost grew {ratio:.1}x for a 4x input (linear is ~4x, quadratic ~16x); \
             find_back_jump regressed to O(n^2): t1={t1:.4}s t4={t4:.4}s"
        );
    }

    #[test]
    fn many_rope_folds_scale_sub_quadratically() {
        use std::time::{Duration, Instant};
        fn lift_secs(rope_count: usize) -> f64 {
            let mut ops: Vec<Op> = Vec::with_capacity(rope_count.saturating_mul(3));
            for rope in 0..rope_count {
                let base: u32 = u32::try_from(rope.saturating_mul(2)).unwrap_or(u32::MAX);
                ops.push(Op {
                    opcode: op::ROPE_INIT,
                    op1_type: OperandType::Unused,
                    op2_type: OperandType::Const,
                    result_type: OperandType::TmpVar,
                    op1: 0,
                    op2: 0,
                    result: base,
                    extended_value: 3,
                    lineno: 0,
                });
                ops.push(Op {
                    opcode: op::ROPE_ADD,
                    op1_type: OperandType::TmpVar,
                    op2_type: OperandType::Const,
                    result_type: OperandType::TmpVar,
                    op1: base,
                    op2: 0,
                    result: base,
                    extended_value: 1,
                    lineno: 0,
                });
                ops.push(Op {
                    opcode: op::ROPE_END,
                    op1_type: OperandType::TmpVar,
                    op2_type: OperandType::Const,
                    result_type: OperandType::TmpVar,
                    op1: base,
                    op2: 0,
                    result: base.saturating_add(1),
                    extended_value: 2,
                    lineno: 0,
                });
            }
            let literals: Vec<Literal> = vec![Literal::Str("x".to_owned())];
            let var_names: Vec<Option<String>> = Vec::new();
            let start: Instant = Instant::now();
            let stmts: Vec<Stmt> = Lifter::new(&ops, &literals, &var_names, &[], &[], 0).lift();
            let elapsed: Duration = start.elapsed();
            assert_eq!(stmts.len(), rope_count.saturating_mul(4));
            elapsed.as_secs_f64()
        }
        const BASE: usize = 2_000;
        let t1: f64 = lift_secs(BASE);
        let t4: f64 = lift_secs(BASE * 4);
        let ratio: f64 = t4 / t1.max(1e-6);
        assert!(
            ratio < 8.0,
            "rope lift cost grew {ratio:.1}x for a 4x input: t1={t1:.4}s t4={t4:.4}s"
        );
    }

    #[test]
    fn do_while_header_still_recovers_with_target_cache() {
        let ops: Vec<Op> = vec![
            echo_const(),
            Op {
                opcode: op::JMPNZ,
                op1_type: OperandType::Const,
                op2_type: OperandType::Unused,
                result_type: OperandType::Unused,
                op1: 0,
                op2: 0,
                result: 0,
                extended_value: 0,
                lineno: 0,
            },
        ];
        let literals: Vec<Literal> = vec![Literal::Bool(true)];
        let var_names: Vec<Option<String>> = Vec::new();
        let stmts: Vec<Stmt> = Lifter::new(&ops, &literals, &var_names, &[], &[], 0).lift();
        assert!(
            matches!(stmts.first(), Some(Stmt::DoWhile { .. })),
            "back-jump target present in cache should still structure a do-while, got {stmts:?}"
        );
    }

    #[test]
    fn switch_state_work_budget_accepts_the_boundary_and_rejects_one_more() {
        assert!(switch_state_work_within_budget(1023, 1023, 0));
        assert!(!switch_state_work_within_budget(1024, 1023, 0));
        assert!(!switch_state_work_within_budget(
            usize::MAX,
            usize::MAX,
            usize::MAX
        ));
    }

    #[test]
    fn switch_label_work_budget_accepts_the_boundary_and_rejects_one_more() {
        assert_eq!(
            switch_label_work_after(0, SANE_SWITCH_LABEL_WORK_CAP),
            Some(SANE_SWITCH_LABEL_WORK_CAP)
        );
        assert_eq!(
            switch_label_work_after(SANE_SWITCH_LABEL_WORK_CAP - 1, 1),
            Some(SANE_SWITCH_LABEL_WORK_CAP)
        );
        assert_eq!(switch_label_work_after(SANE_SWITCH_LABEL_WORK_CAP, 1), None);
        assert_eq!(switch_label_work_after(usize::MAX, 1), None);
    }

    #[test]
    fn loop_relift_budget_accepts_the_boundary_and_rejects_one_more() {
        assert_eq!(
            loop_relift_charge(0, SANE_LOOP_RELIFT_WORK_CAP),
            Some(SANE_LOOP_RELIFT_WORK_CAP)
        );
        assert_eq!(
            loop_relift_charge(SANE_LOOP_RELIFT_WORK_CAP - 1, 1),
            Some(SANE_LOOP_RELIFT_WORK_CAP)
        );
        assert_eq!(loop_relift_charge(SANE_LOOP_RELIFT_WORK_CAP, 1), None);
        assert_eq!(loop_relift_charge(usize::MAX, 1), None);
    }

    fn jump(opcode: u8, op1: u32, op2: u32) -> Op {
        Op {
            opcode,
            op1_type: if opcode == op::JMPZ {
                OperandType::Cv
            } else {
                OperandType::Unused
            },
            op2_type: OperandType::Unused,
            result_type: OperandType::Unused,
            op1,
            op2,
            result: 0,
            extended_value: 0,
            lineno: 0,
        }
    }

    fn assign_const(slot: u32) -> Op {
        Op {
            opcode: op::ASSIGN,
            op1_type: OperandType::Cv,
            op2_type: OperandType::Const,
            result_type: OperandType::Unused,
            op1: slot,
            op2: 1,
            result: 0,
            extended_value: 0,
            lineno: 0,
        }
    }

    fn bottom_tested_loop(base: u32, step_width: u32, plain_continues: u32) -> Vec<Op> {
        let head: u32 = if plain_continues == 0 {
            base + 3
        } else {
            base + 5 + plain_continues * 2
        };
        let step_start: u32 = head;
        let cond_block: u32 = step_start + step_width;
        let mut ops: Vec<Op> = vec![jump(op::JMP, cond_block, 0)];
        if plain_continues == 0 {
            ops.push(jump(op::JMPZ, 0, head));
            ops.push(jump(op::JMP, step_start, 0));
        } else {
            ops.push(jump(op::JMPZ, 0, base + 5));
            ops.push(jump(op::JMPZ, 0, base + 4));
            ops.push(jump(op::JMP, step_start, 0));
            ops.push(assign_const(3));
            for index in 0..plain_continues {
                ops.push(jump(op::JMPZ, 0, base + 7 + index * 2));
                ops.push(jump(op::JMP, cond_block, 0));
            }
        }
        for offset in 0..step_width {
            ops.push(assign_const(offset + 1));
        }
        ops.push(Op {
            opcode: op::IS_SMALLER,
            op1_type: OperandType::Cv,
            op2_type: OperandType::Const,
            result_type: OperandType::TmpVar,
            op1: 0,
            op2: 1,
            result: 9,
            extended_value: 0,
            lineno: 0,
        });
        ops.push(Op {
            opcode: op::JMPNZ,
            op1_type: OperandType::TmpVar,
            op2_type: OperandType::Unused,
            result_type: OperandType::Unused,
            op1: 9,
            op2: base + 1,
            result: 0,
            extended_value: 0,
            lineno: 0,
        });
        ops
    }

    fn lift_source(ops: &[Op]) -> String {
        let literals: Vec<Literal> = vec![Literal::Long(0), Literal::Long(7)];
        let var_names: Vec<Option<String>> = Vec::new();
        let node: OpArray = OpArray {
            kind: OpArrayKind::Main,
            name: None,
            class_name: None,
            num_args: 0,
            literals,
            ops: ops.to_vec(),
            children: Vec::new(),
            var_names,
            try_catch: Vec::new(),
        };
        decompile(&node).php_skeleton
    }

    #[test]
    fn for_step_budget_accepts_the_boundary_and_rejects_one_more() {
        let accepted: String = lift_source(&bottom_tested_loop(
            0,
            u32::try_from(SANE_FOR_STEP_CAP).expect("the for step cap fits a u32"),
            0,
        ));
        assert!(
            accepted.contains("for (; ") && !accepted.contains("unrecovered"),
            "a step exactly at the cap must still reconstruct a for header\n{accepted}"
        );
        let rejected: String = lift_source(&bottom_tested_loop(
            0,
            u32::try_from(SANE_FOR_STEP_CAP + 1).expect("one past the for step cap fits a u32"),
            0,
        ));
        assert!(
            !rejected.contains("for (; "),
            "a step one wider than the cap must not reconstruct a for header\n{rejected}"
        );
        assert!(
            rejected.contains("goto disrobe_label_"),
            "the continue edge the refused for header cannot explain must still be reproduced as \
             the jump it is\n{rejected}"
        );
    }

    #[test]
    fn a_for_reading_that_explains_less_than_the_while_reading_is_refused() {
        let source: String = lift_source(&bottom_tested_loop(0, 2, 2));
        assert!(
            !source.contains("for (; "),
            "hoisting the tail into a for step would leave both jumps to the condition              unstructured, which is worse than the while reading it replaces
{source}"
        );
        assert!(
            source.contains("while ("),
            "the loop must keep the reading that explains the most jumps
{source}"
        );
        assert_eq!(
            source
                .lines()
                .filter(|line: &&str| line.trim() == "continue;")
                .count(),
            2,
            "both jumps to the condition are while continues
{source}"
        );
        assert_eq!(
            source.matches("goto disrobe_label_").count(),
            1,
            "only the jump to the tail stays unstructured under the while reading, and it is              reproduced as the goto it is rather than marked and left out of the body
{source}"
        );
    }

    #[test]
    fn deeply_nested_for_shapes_stay_bounded() {
        use std::time::{Duration, Instant};
        const DEPTH: u32 = 40;
        let mut ops: Vec<Op> = Vec::new();
        let mut opened: Vec<u32> = Vec::new();
        for _ in 0..DEPTH {
            opened.push(u32::try_from(ops.len()).expect("nested loop base fits a u32"));
            ops.extend([
                jump(op::JMP, 0, 0),
                jump(op::JMPZ, 0, 0),
                jump(op::JMP, 0, 0),
            ]);
        }
        for base in opened.into_iter().rev() {
            let step_start: u32 = u32::try_from(ops.len()).expect("step start fits a u32");
            ops.push(assign_const(1));
            let cond_block: u32 = u32::try_from(ops.len()).expect("condition fits a u32");
            ops.push(Op {
                opcode: op::IS_SMALLER,
                op1_type: OperandType::Cv,
                op2_type: OperandType::Const,
                result_type: OperandType::TmpVar,
                op1: 0,
                op2: 1,
                result: 9,
                extended_value: 0,
                lineno: 0,
            });
            ops.push(Op {
                opcode: op::JMPNZ,
                op1_type: OperandType::TmpVar,
                op2_type: OperandType::Unused,
                result_type: OperandType::Unused,
                op1: 9,
                op2: base + 1,
                result: 0,
                extended_value: 0,
                lineno: 0,
            });
            let head: usize = base as usize;
            ops[head] = jump(op::JMP, cond_block, 0);
            ops[head + 1] = jump(op::JMPZ, 0, base + 3);
            ops[head + 2] = jump(op::JMP, step_start, 0);
        }
        let start: Instant = Instant::now();
        let first: String = lift_source(&ops);
        let elapsed: Duration = start.elapsed();
        let second: String = lift_source(&ops);
        assert_eq!(
            first, second,
            "a bounded relift must still be deterministic across runs"
        );
        assert!(
            first.contains("for (; "),
            "the nested shapes must actually reach the relift path, otherwise this measures \
             nothing about the budget that bounds it\n{first}"
        );
        assert!(
            elapsed < Duration::from_secs(20),
            "forty nested for shapes took {elapsed:?}; the relift budget is not bounding the \
             doubled lift"
        );
    }
}
