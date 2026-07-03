use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const OPARRAY_MAGIC: &[u8; 4] = b"DZOA";

/// Container schema version stamped by the emitter on fresh dumps.
pub const OPARRAY_VERSION: u8 = 2;

/// Oldest container schema this parser decodes.
pub const OPARRAY_MIN_VERSION: u8 = 1;

/// Newest container schema this parser decodes.
pub const OPARRAY_MAX_VERSION: u8 = 2;

const SANE_OP_CAP: u32 = 4_000_000;
const SANE_LITERAL_CAP: u32 = 4_000_000;
const SANE_VAR_CAP: u32 = 1 << 20;
const SANE_NAME_CAP: u32 = 1 << 20;
const SANE_CHILD_CAP: u32 = 1 << 16;
const SANE_NEST_DEPTH: u32 = 64;
const MAX_PREALLOC: usize = 1 << 16;
const SANE_LIFT_DEPTH: u32 = 256;

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

impl Op {
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
}

impl Eq for Literal {}

impl Literal {
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::Null => "null".to_owned(),
            Self::Bool(b) => if *b { "true" } else { "false" }.to_owned(),
            Self::Long(n) => n.to_string(),
            Self::Double(d) => format!("{d}"),
            Self::Str(s) => format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'")),
            Self::Array(_) => "array()".to_owned(),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpArrayKind {
    Main,

    Function,

    Method,

    Closure,
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
    /// Source names of compiled variables, indexed by `Cv` slot.
    pub var_names: Vec<Option<String>>,
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
pub struct Decompilation {
    pub fidelity: Fidelity,
    pub php_skeleton: String,
    pub op_array_count: usize,
    pub op_count: usize,
    pub literal_count: usize,
}

pub mod op {

    pub const NOP: u8 = 0;
    pub const ADD: u8 = 1;
    pub const SUB: u8 = 2;
    pub const MUL: u8 = 3;
    pub const DIV: u8 = 4;
    pub const MOD: u8 = 5;
    pub const CONCAT: u8 = 8;
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
    pub const BOOL: u8 = 52;
    pub const INIT_FCALL_BY_NAME: u8 = 59;
    pub const DO_FCALL: u8 = 60;
    pub const INIT_FCALL: u8 = 61;
    pub const INIT_NS_FCALL: u8 = 69;
    pub const RETURN: u8 = 62;
    pub const RECV: u8 = 63;
    pub const RECV_INIT: u8 = 64;
    pub const SEND_VAL: u8 = 65;
    pub const SEND_VAR_EX: u8 = 66;
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
    pub const FETCH_OBJ_R: u8 = 82;
    pub const FETCH_W: u8 = 83;
    pub const FETCH_RW: u8 = 86;
    pub const FETCH_CONSTANT: u8 = 99;
    pub const THROW: u8 = 108;
    pub const FETCH_CLASS: u8 = 109;
    pub const INIT_METHOD_CALL: u8 = 112;
    pub const INIT_STATIC_METHOD_CALL: u8 = 113;
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
    pub const JMP_SET: u8 = 152;
    pub const YIELD: u8 = 160;
    pub const GENERATOR_RETURN: u8 = 161;
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
    pub const OP_DATA: u8 = 137;
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
        26 => "ZEND_ASSIGN_OP",
        31 => "ZEND_QM_ASSIGN",
        34 => "ZEND_PRE_INC",
        35 => "ZEND_PRE_DEC",
        36 => "ZEND_POST_INC",
        37 => "ZEND_POST_DEC",
        42 => "ZEND_JMP",
        43 => "ZEND_JMPZ",
        44 => "ZEND_JMPNZ",
        46 => "ZEND_JMPZ_EX",
        47 => "ZEND_JMPNZ_EX",
        48 => "ZEND_CASE",
        52 => "ZEND_BOOL",
        59 => "ZEND_INIT_FCALL_BY_NAME",
        60 => "ZEND_DO_FCALL",
        61 => "ZEND_INIT_FCALL",
        62 => "ZEND_RETURN",
        63 => "ZEND_RECV",
        64 => "ZEND_RECV_INIT",
        65 => "ZEND_SEND_VAL",
        66 => "ZEND_SEND_VAR_EX",
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
        86 => "ZEND_FETCH_RW",
        99 => "ZEND_FETCH_CONSTANT",
        107 => "ZEND_CATCH",
        108 => "ZEND_THROW",
        109 => "ZEND_FETCH_CLASS",
        111 => "ZEND_RETURN_BY_REF",
        112 => "ZEND_INIT_METHOD_CALL",
        113 => "ZEND_INIT_STATIC_METHOD_CALL",
        116 => "ZEND_SEND_VAL_EX",
        117 => "ZEND_SEND_VAR",
        125 => "ZEND_FE_RESET_RW",
        126 => "ZEND_FE_FETCH_RW",
        129 => "ZEND_DO_ICALL",
        130 => "ZEND_DO_UCALL",
        131 => "ZEND_DO_FCALL_BY_NAME",
        136 => "ZEND_ECHO",
        138 => "ZEND_INSTANCEOF",
        141 => "ZEND_DECLARE_FUNCTION",
        142 => "ZEND_DECLARE_LAMBDA_FUNCTION",
        143 => "ZEND_DECLARE_CONST",
        144 => "ZEND_DECLARE_CLASS",
        145 => "ZEND_DECLARE_CLASS_DELAYED",
        146 => "ZEND_DECLARE_ANON_CLASS",
        149 => "ZEND_HANDLE_EXCEPTION",
        152 => "ZEND_JMP_SET",
        160 => "ZEND_YIELD",
        161 => "ZEND_GENERATOR_RETURN",
        169 => "ZEND_COALESCE",
        187 => "ZEND_SWITCH_LONG",
        188 => "ZEND_SWITCH_STRING",
        195 => "ZEND_MATCH",
        198 => "ZEND_JMP_NULL",
        137 => "ZEND_OP_DATA",
        210 => "ZEND_STRLEN",
        211 => "ZEND_COUNT",
        212 => "ZEND_VERIFY_RETURN_TYPE",
        213 => "ZEND_FE_FREE",
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
    let literals: Vec<Literal> = parse_literals(cur)?;
    let ops: Vec<Op> = parse_ops(cur)?;
    let child_count: u32 = cur.u32()?;
    if child_count > SANE_CHILD_CAP {
        return Err(Error::OpArrayFieldOversize {
            field: "children",
            value: child_count,
            cap: SANE_CHILD_CAP,
        });
    }
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
    })
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

fn parse_literals(cur: &mut Cursor<'_>) -> Result<Vec<Literal>> {
    let count: u32 = cur.u32()?;
    if count > SANE_LITERAL_CAP {
        return Err(Error::OpArrayFieldOversize {
            field: "literals",
            value: count,
            cap: SANE_LITERAL_CAP,
        });
    }
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
            other => return Err(Error::OpArrayBadLiteralTag(other)),
        };
        out.push(lit);
    }
    Ok(out)
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
    Decompilation {
        fidelity: Fidelity::Partial,
        php_skeleton: emitter.finish(),
        op_array_count,
        op_count,
        literal_count,
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
                    self.out.push('\n');
                    self.emit_oparray(child, indent);
                }
            }
            OpArrayKind::Method => {
                let class: &str = node.class_name.as_deref().unwrap_or("UnknownClass");
                self.line(indent, &format!("class {class}"));
                self.line(indent, "{");
                let sig: String = Self::method_signature(node);
                self.line(indent + 1, &sig);
                self.line(indent + 1, "{");
                self.emit_body(node, indent + 2);
                self.line(indent + 1, "}");
                self.line(indent, "}");
            }
        }
    }

    fn emit_children_first(&mut self, node: &OpArray, indent: usize) {
        for child in &node.children {
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
        if node.num_args == 0 {
            return String::new();
        }
        (0..node.num_args)
            .map(|i: u32| format!("${}", cv_name(i, &node.var_names)))
            .collect::<Vec<String>>()
            .join(", ")
    }

    fn emit_body(&mut self, node: &OpArray, indent: usize) {
        let mut lifter: Lifter<'_> = Lifter::new(&node.ops, &node.literals, &node.var_names);
        let stmts: Vec<Stmt> = lifter.lift();
        for stmt in &stmts {
            stmt.render_into(self, indent);
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
const PREC_CMP: u8 = 50;
const PREC_BITAND: u8 = 45;
const PREC_BITXOR: u8 = 44;
const PREC_BITOR: u8 = 43;
const PREC_COALESCE: u8 = 35;

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
    DoWhile {
        cond: String,
        body: Vec<Self>,
    },
    Foreach {
        subject: String,
        key: Option<String>,
        value: String,
        body: Vec<Self>,
    },
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
            Self::While { cond, body } => {
                emitter.line(indent, &format!("while ({cond}) {{"));
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
            Self::Foreach {
                subject,
                key,
                value,
                body,
            } => {
                let header: String = key.as_ref().map_or_else(
                    || format!("foreach ({subject} as {value}) {{"),
                    |k: &String| format!("foreach ({subject} as {k} => {value}) {{"),
                );
                emitter.line(indent, &header);
                for stmt in body {
                    stmt.render_into(emitter, indent + 1);
                }
                emitter.line(indent, "}");
            }
        }
    }
}

struct PendingCall {
    callee: String,
    is_method: bool,
    object: Option<String>,
    is_static: bool,
    args: Vec<String>,
}

struct Lifter<'a> {
    ops: &'a [Op],
    literals: &'a [Literal],
    var_names: &'a [Option<String>],
    slots: BTreeMap<(OperandType, u32), Expr>,
    call_stack: Vec<PendingCall>,
}

impl<'a> Lifter<'a> {
    fn new(ops: &'a [Op], literals: &'a [Literal], var_names: &'a [Option<String>]) -> Self {
        Self {
            ops,
            literals,
            var_names,
            slots: BTreeMap::new(),
            call_stack: Vec::new(),
        }
    }

    fn cv(&self, slot: u32) -> String {
        cv_name(slot, self.var_names)
    }

    fn lift(&mut self) -> Vec<Stmt> {
        let len: u32 = self.ops.len() as u32;
        self.lift_range(0, len, 0)
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
            if let Some(stmt) = self.eval_op(i) {
                out.push(Stmt::Line(stmt));
            }
            i += 1;
        }
        out
    }

    fn try_structure(&mut self, i: u32, end: u32, depth: u32) -> Option<(Vec<Stmt>, u32)> {
        let op: &Op = self.ops.get(i as usize)?;
        match op.opcode {
            o if o == op::FE_RESET_R || o == op::FE_RESET_RW => {
                self.structure_foreach(i, end, depth)
            }
            o if o == op::JMPZ_EX || o == op::JMPNZ_EX => self.fold_short_circuit(i, end),
            o if o == op::JMP => self.structure_while(i, end, depth),
            o if o == op::JMPZ => self
                .structure_ternary(i, end)
                .or_else(|| self.structure_if(i, end, depth)),
            _ => self.structure_do_while(i, end, depth),
        }
    }

    fn structure_do_while(&mut self, i: u32, end: u32, depth: u32) -> Option<(Vec<Stmt>, u32)> {
        let jump_idx: u32 = self.find_back_jump(i, end)?;
        let jump: Op = self.ops.get(jump_idx as usize)?.clone();
        let negate: bool = jump.opcode == op::JMPZ;
        let cond_start: u32 = self.condition_start(&jump, i, jump_idx);
        let body: Vec<Stmt> = self.lift_range(i, cond_start, depth + 1);
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
        self.slots.insert(
            (then_op.result_type, then_op.result),
            Expr {
                text,
                prec: PREC_COALESCE,
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
        let then_last: u32 = target - 1;
        let then_terminator: &Op = self.ops.get(then_last as usize)?;
        if then_terminator.opcode == op::JMP {
            let join: u32 = then_terminator.op1;
            if join > target && join <= end {
                let then_body: Vec<Stmt> = self.lift_range(i + 1, then_last, depth + 1);
                let else_body: Vec<Stmt> = self.lift_range(target, join, depth + 1);
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
        let then_body: Vec<Stmt> = self.lift_range(i + 1, target, depth + 1);
        Some((
            vec![Stmt::If {
                cond: cond_expr.text,
                then_body,
                else_body: Vec::new(),
            }],
            target,
        ))
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
        let body: Vec<Stmt> = self.lift_range(i + 1, cond_block, depth + 1);
        let cond_expr: Expr = self.lift_condition(cond_block, tail, cond_op)?;
        Some((
            vec![Stmt::While {
                cond: cond_expr.text,
                body,
            }],
            tail + 1,
        ))
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
        if fetch.opcode != op::FE_FETCH_R && fetch.opcode != op::FE_FETCH_RW {
            return None;
        }
        let value: String = match fetch.op2_type {
            OperandType::Cv => format!("${}", self.cv(fetch.op2)),
            _ => "$value".to_owned(),
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
        let body: Vec<Stmt> = self.lift_range(body_start, body_end, depth + 1);
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

    fn eval_op(&mut self, idx: u32) -> Option<String> {
        let op: Op = self.ops.get(idx as usize)?.clone();
        let op: &Op = &op;
        match op.opcode {
            o if o == op::OP_DATA => None,
            o if is_binary(o) => {
                self.fold_binary(op);
                None
            }
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
            o if o == op::FETCH_DIM_R => {
                self.fold_fetch_dim(op);
                None
            }
            o if o == op::FETCH_R || o == op::FETCH_W || o == op::FETCH_RW => {
                self.fold_variable_variable(op);
                None
            }
            o if o == op::FE_RESET_R || o == op::FE_RESET_RW || o == op::FE_FREE => None,
            o if o == op::VERIFY_RETURN_TYPE || o == op::NOP || o == op::HANDLE_EXCEPTION => None,
            o if o == op::RECV || o == op::RECV_INIT => None,
            o if o == op::INIT_FCALL || o == op::INIT_FCALL_BY_NAME || o == op::INIT_NS_FCALL => {
                let callee: String = self
                    .operand_expr(op.op2_type, op.op2)
                    .map_or_else(|| "func".to_owned(), |e: Expr| strip_quotes(&e.text));
                self.call_stack.push(PendingCall {
                    callee,
                    is_method: false,
                    object: None,
                    is_static: false,
                    args: Vec::new(),
                });
                None
            }
            o if o == op::INIT_METHOD_CALL => {
                let object: String = self
                    .operand_expr(op.op1_type, op.op1)
                    .map_or_else(|| "$object".to_owned(), |e: Expr| e.text);
                let method: String = self
                    .operand_expr(op.op2_type, op.op2)
                    .map_or_else(|| "method".to_owned(), |e: Expr| strip_quotes(&e.text));
                self.call_stack.push(PendingCall {
                    callee: method,
                    is_method: true,
                    object: Some(object),
                    is_static: false,
                    args: Vec::new(),
                });
                None
            }
            o if o == op::INIT_STATIC_METHOD_CALL => {
                let class: String = self
                    .operand_expr(op.op1_type, op.op1)
                    .map_or_else(|| "self".to_owned(), |e: Expr| strip_quotes(&e.text));
                let method: String = self
                    .operand_expr(op.op2_type, op.op2)
                    .map_or_else(|| "method".to_owned(), |e: Expr| strip_quotes(&e.text));
                self.call_stack.push(PendingCall {
                    callee: method,
                    is_method: true,
                    object: Some(class),
                    is_static: true,
                    args: Vec::new(),
                });
                None
            }
            o if is_send(o) => {
                if let Some(arg) = self.operand_expr(op.op1_type, op.op1)
                    && let Some(call) = self.call_stack.last_mut()
                {
                    call.args.push(arg.text);
                }
                None
            }
            o if o == op::DO_FCALL
                || o == op::DO_ICALL
                || o == op::DO_UCALL
                || o == op::DO_FCALL_BY_NAME =>
            {
                self.finish_call(op)
            }
            o if o == op::NEW => {
                let cls: String = self
                    .operand_expr(op.op1_type, op.op1)
                    .map_or_else(|| "stdClass".to_owned(), |e: Expr| strip_quotes(&e.text));
                self.call_stack.push(PendingCall {
                    callee: format!("new {cls}"),
                    is_method: false,
                    object: None,
                    is_static: false,
                    args: Vec::new(),
                });
                None
            }
            o if o == op::INIT_ARRAY => {
                self.fold_array_init(op);
                None
            }
            o if o == op::ADD_ARRAY_ELEMENT => {
                self.fold_array_append(op);
                None
            }
            o if o == op::ECHO => {
                let arg: Expr = self.operand_expr(op.op1_type, op.op1)?;
                Some(format!("echo {};", arg.text))
            }
            o if o == op::ASSIGN => {
                let lhs: Expr = self.operand_expr(op.op1_type, op.op1)?;
                let rhs: Expr = self
                    .operand_expr(op.op2_type, op.op2)
                    .unwrap_or_else(|| Expr::atom("null".to_owned()));
                if op.result_type != OperandType::Unused {
                    self.store_result(op, Expr::atom(lhs.text.clone()));
                }
                Some(format!("{} = {};", lhs.text, rhs.text))
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
            o if o == op::PRE_INC || o == op::POST_INC => {
                let v: Expr = self.operand_expr(op.op1_type, op.op1)?;
                Some(format!("{}++;", v.text))
            }
            o if o == op::PRE_DEC || o == op::POST_DEC => {
                let v: Expr = self.operand_expr(op.op1_type, op.op1)?;
                Some(format!("{}--;", v.text))
            }
            o if o == op::RETURN || o == op::RETURN_BY_REF || o == op::GENERATOR_RETURN => {
                if op.op1_type == OperandType::Unused {
                    return Some("return;".to_owned());
                }
                self.operand_expr(op.op1_type, op.op1).map_or_else(
                    || Some("return;".to_owned()),
                    |v: Expr| {
                        if v.text == "null" || v.text == "1" {
                            None
                        } else {
                            Some(format!("return {};", v.text))
                        }
                    },
                )
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
            o if o == op::FREE => None,
            o if o == op::INCLUDE_OR_EVAL => {
                let arg: Expr = self
                    .operand_expr(op.op1_type, op.op1)
                    .unwrap_or_else(|| Expr::atom("''".to_owned()));
                Some(format!("{} {};", include_kind(op.extended_value), arg.text))
            }
            _ => None,
        }
    }

    fn fold_binary(&mut self, op: &Op) {
        let lhs: Option<Expr> = self.operand_expr(op.op1_type, op.op1);
        let rhs: Option<Expr> = self.operand_expr(op.op2_type, op.op2);
        if let (Some(l), Some(r)) = (lhs, rhs) {
            let (sym, prec): (&str, u8) = binary_symbol(op.opcode);
            let text: String = format!("{} {} {}", l.wrapped(prec), sym, r.wrapped(prec + 1));
            self.store_result(op, Expr { text, prec });
        }
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

    fn fold_variable_variable(&mut self, op: &Op) {
        let Some(name): Option<Expr> = self.operand_expr(op.op1_type, op.op1) else {
            return;
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
    }

    fn fold_array_init(&mut self, op: &Op) {
        let mut parts: Vec<String> = Vec::new();
        if let Some(first) = self.operand_expr(op.op1_type, op.op1) {
            parts.push(first.text);
        }
        let text: String = format!("[{}]", parts.join(", "));
        self.store_result(
            op,
            Expr {
                text,
                prec: PREC_ATOM,
            },
        );
    }

    fn fold_array_append(&mut self, op: &Op) {
        let key: (OperandType, u32) = (op.result_type, op.result);
        let existing: Option<Expr> = self.slots.get(&key).cloned();
        let elem: Option<Expr> = self.operand_expr(op.op1_type, op.op1);
        if let (Some(arr), Some(e)) = (existing, elem) {
            let inner: String = arr
                .text
                .strip_prefix('[')
                .and_then(|s: &str| s.strip_suffix(']'))
                .map(str::to_owned)
                .unwrap_or(arr.text);
            let joined: String = if inner.is_empty() {
                e.text
            } else {
                format!("{inner}, {}", e.text)
            };
            self.slots.insert(
                key,
                Expr {
                    text: format!("[{joined}]"),
                    prec: PREC_ATOM,
                },
            );
        }
    }

    fn finish_call(&mut self, op: &Op) -> Option<String> {
        let call: PendingCall = self.call_stack.pop()?;
        let args: String = call.args.join(", ");
        let text: String = if call.is_method {
            let sep: &str = if call.is_static { "::" } else { "->" };
            let object: String = call.object.unwrap_or_else(|| "$object".to_owned());
            format!("{object}{sep}{}({args})", call.callee)
        } else {
            format!("{}({args})", call.callee)
        };
        if op.result_type == OperandType::Unused {
            return Some(format!("{text};"));
        }
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
        self.slots.insert((op.result_type, op.result), expr);
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
    )
}

#[must_use]
const fn is_send(opcode: u8) -> bool {
    matches!(
        opcode,
        op::SEND_VAL | op::SEND_VAL_EX | op::SEND_VAR | op::SEND_VAR_EX
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
        op::IS_SMALLER => ("<", PREC_CMP),
        op::IS_SMALLER_OR_EQUAL => ("<=", PREC_CMP),
        op::COALESCE => ("??", PREC_COALESCE),
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
