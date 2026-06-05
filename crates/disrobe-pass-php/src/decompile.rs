use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Magic prefix for the disrobe canonical Zend `op_array` container.
pub const OPARRAY_MAGIC: &[u8; 4] = b"DZOA";

/// Container format revision. Bumped if the wire layout changes.
pub const OPARRAY_VERSION: u8 = 1;

const SANE_OP_CAP: u32 = 4_000_000;
const SANE_LITERAL_CAP: u32 = 4_000_000;
const SANE_NAME_CAP: u32 = 1 << 20;
const SANE_CHILD_CAP: u32 = 1 << 16;
const SANE_NEST_DEPTH: u32 = 64;

/// Zend operand storage class, mirroring the `IS_*` constants in `Zend/zend_compile.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperandType {
    /// `IS_UNUSED` (0): the slot carries no operand.
    Unused,
    /// `IS_CONST` (1<<0): operand indexes the literal pool.
    Const,
    /// `IS_TMP_VAR` (1<<1): a compiler temporary.
    TmpVar,
    /// `IS_VAR` (1<<2): an internal VM variable.
    Var,
    /// `IS_CV` (1<<3): a compiled variable (a `$name` slot, name erased by encoders).
    Cv,
}

impl OperandType {
    /// Decodes the wire byte into an operand class, mapping the canonical `IS_*` bit values.
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

    /// Renders the operand slot as PHP-skeleton text given its raw value and the literal pool.
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

/// A single Zend VM instruction recovered from a decrypted `op_array`.
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
    /// Returns the canonical Zend mnemonic for this instruction's opcode.
    #[must_use]
    pub fn mnemonic(&self) -> &'static str {
        opcode_name(self.opcode)
    }

    /// Reports whether this instruction transfers control, and to which absolute op index.
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

/// Classification of an instruction's effect on control flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Branch {
    /// Falls through to the next instruction.
    None,
    /// Unconditionally jumps to the target op index.
    Uncond(u32),
    /// Conditionally jumps; may also fall through to the next instruction.
    Cond { taken: u32, fallthrough: bool },
    /// Ends the current flow (return / throw / exit).
    Terminal,
}

/// A literal recovered from the `op_array` constant pool.
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
    /// Renders the literal as a PHP source token.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::Null => "null".to_owned(),
            Self::Bool(b) => if *b { "true" } else { "false" }.to_owned(),
            Self::Long(n) => n.to_string(),
            Self::Double(d) => format!("{d}"),
            Self::Str(s) => format!("'{}'", s.replace('\'', "\\'")),
            Self::Array(n) => format!("array(#{n})"),
        }
    }

    /// Returns the inner string if this literal is a string, used to recover identifiers.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

/// The kind of definition an `op_array` represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpArrayKind {
    /// Top-level / file scope.
    Main,
    /// A free function.
    Function,
    /// A class method.
    Method,
    /// A closure / lambda.
    Closure,
}

/// A fully parsed Zend `op_array`: opcodes, literals, declared symbol name, and nested children.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpArray {
    pub kind: OpArrayKind,
    pub name: Option<String>,
    pub class_name: Option<String>,
    pub num_args: u32,
    pub literals: Vec<Literal>,
    pub ops: Vec<Op>,
    pub children: Vec<Self>,
}

/// A basic block in an `op_array`'s control-flow graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasicBlock {
    pub start: u32,
    pub end: u32,
    pub successors: Vec<u32>,
}

/// The reconstructed control-flow graph for a single `op_array`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cfg {
    pub blocks: Vec<BasicBlock>,
    pub block_at: BTreeMap<u32, usize>,
}

/// Fidelity grade attached to a decompilation, so callers never over-claim recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Fidelity {
    /// Structural skeleton + control flow recovered; variable names are erased (`$vN`).
    Partial,
}

/// The result of decompiling a decrypted Zend `op_array` container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decompilation {
    pub fidelity: Fidelity,
    pub php_skeleton: String,
    pub op_array_count: usize,
    pub op_count: usize,
    pub literal_count: usize,
}

pub mod op {
    //! Canonical Zend opcode numbers, transcribed from `Zend/zend_vm_opcodes.h`.
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
}

/// Returns the canonical Zend mnemonic for an opcode number, or UNKNOWN if unmapped.
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

/// Parses a disrobe canonical `op_array` container ([`OPARRAY_MAGIC`]) into an [`OpArray`] tree.
pub fn parse_oparray(bytes: &[u8]) -> Result<OpArray> {
    let mut cur: Cursor<'_> = Cursor::new(bytes);
    cur.need(5)?;
    if &bytes[..4] != OPARRAY_MAGIC {
        return Err(Error::OpArrayBadMagic);
    }
    cur.pos = 4;
    let version: u8 = cur.u8()?;
    if version != OPARRAY_VERSION {
        return Err(Error::OpArrayUnsupportedVersion(version));
    }
    parse_one(&mut cur, 0)
}

fn parse_one(cur: &mut Cursor<'_>, depth: u32) -> Result<OpArray> {
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
    let mut children: Vec<OpArray> = Vec::with_capacity(child_count as usize);
    for _ in 0..child_count {
        children.push(parse_one(cur, depth + 1)?);
    }
    Ok(OpArray {
        kind,
        name,
        class_name,
        num_args,
        literals,
        ops,
        children,
    })
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
    let mut out: Vec<Literal> = Vec::with_capacity(count as usize);
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
    let mut out: Vec<Op> = Vec::with_capacity(count as usize);
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

/// Reconstructs the control-flow graph from an `op_array`'s branch instructions.
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

/// Decompiles a parsed `op_array` tree into a partial PHP skeleton.
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
                self.emit_body(node, indent);
                for child in &node.children {
                    self.out.push('\n');
                    self.emit_oparray(child, indent);
                }
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
            .map(|i: u32| format!("$v{i}"))
            .collect::<Vec<String>>()
            .join(", ")
    }

    fn emit_body(&mut self, node: &OpArray, indent: usize) {
        let cfg: Cfg = build_cfg(&node.ops);
        let mut structurer: Structurer<'_> = Structurer {
            ops: &node.ops,
            literals: &node.literals,
            cfg: &cfg,
            emitter: self,
        };
        structurer.emit_linear(indent);
    }
}

struct Structurer<'a> {
    ops: &'a [Op],
    literals: &'a [Literal],
    cfg: &'a Cfg,
    emitter: &'a mut SkeletonEmitter,
}

impl Structurer<'_> {
    fn emit_linear(&mut self, indent: usize) {
        let mut open_blocks: Vec<&'static str> = Vec::new();
        let loop_headers: std::collections::BTreeSet<u32> = self.loop_headers_from_cfg();
        for (idx, op) in self.ops.iter().enumerate() {
            let i: u32 = idx as u32;
            if let Some(stmt) = self.statement_for(op) {
                self.emitter.line(indent + open_blocks.len(), &stmt);
            }
            self.maybe_open_close(op, i, indent, &loop_headers, &mut open_blocks);
        }
        while open_blocks.pop().is_some() {
            self.emitter.line(indent + open_blocks.len(), "}");
        }
    }

    /// CFG block leaders that are the destination of a back edge (loop headers).
    fn loop_headers_from_cfg(&self) -> std::collections::BTreeSet<u32> {
        let mut headers: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
        for block in &self.cfg.blocks {
            for &succ in &block.successors {
                if succ <= block.start {
                    headers.insert(succ);
                }
            }
        }
        headers
    }

    fn maybe_open_close(
        &mut self,
        op: &Op,
        i: u32,
        indent: usize,
        loop_headers: &std::collections::BTreeSet<u32>,
        open_blocks: &mut Vec<&'static str>,
    ) {
        match op.opcode {
            o if o == op::JMPZ || o == op::JMPNZ => {
                let keyword: &str = if loop_headers.contains(&i) {
                    "while"
                } else {
                    "if"
                };
                let cond: String = self
                    .operand(op.op1_type, op.op1)
                    .unwrap_or_else(|| "/* cond */".to_owned());
                self.emitter.line(
                    indent + open_blocks.len(),
                    &format!("{keyword} ({cond}) {{"),
                );
                open_blocks.push("}");
            }
            o if o == op::FE_FETCH_R || o == op::FE_FETCH_RW => {
                self.emitter.line(
                    indent + open_blocks.len(),
                    "foreach ($vIter as $vKey => $vVal) {",
                );
                open_blocks.push("}");
            }
            o if o == op::SWITCH_LONG || o == op::SWITCH_STRING => {
                let subject: String = self
                    .operand(op.op1_type, op.op1)
                    .unwrap_or_else(|| "$vSwitch".to_owned());
                self.emitter.line(
                    indent + open_blocks.len(),
                    &format!("switch ({subject}) {{"),
                );
                open_blocks.push("}");
            }
            _ => {}
        }
    }

    fn statement_for(&self, op: &Op) -> Option<String> {
        match op.opcode {
            o if o == op::ECHO => {
                let arg: String = self.operand(op.op1_type, op.op1)?;
                Some(format!("echo {arg};"))
            }
            o if o == op::ASSIGN => {
                let lhs: String = self.operand(op.op1_type, op.op1)?;
                let rhs: String = self
                    .operand(op.op2_type, op.op2)
                    .unwrap_or_else(|| "/* expr */".to_owned());
                Some(format!("{lhs} = {rhs};"))
            }
            o if o == op::ASSIGN_OP => {
                let lhs: String = self.operand(op.op1_type, op.op1)?;
                let rhs: String = self
                    .operand(op.op2_type, op.op2)
                    .unwrap_or_else(|| "/* expr */".to_owned());
                Some(format!(
                    "{lhs} {}= {rhs};",
                    assign_op_symbol(op.extended_value)
                ))
            }
            o if o == op::RETURN || o == op::RETURN_BY_REF || o == op::GENERATOR_RETURN => {
                self.operand(op.op1_type, op.op1).map_or_else(
                    || Some("return;".to_owned()),
                    |v: String| Some(format!("return {v};")),
                )
            }
            o if o == op::THROW => {
                let v: String = self
                    .operand(op.op1_type, op.op1)
                    .unwrap_or_else(|| "$vEx".to_owned());
                Some(format!("throw {v};"))
            }
            o if o == op::INIT_FCALL || o == op::INIT_FCALL_BY_NAME || o == op::INIT_NS_FCALL => {
                let name: String = self.callee_name(op).unwrap_or_else(|| "func".to_owned());
                Some(format!("{name}(...);"))
            }
            o if o == op::INIT_METHOD_CALL => {
                let method: String = self
                    .operand(op.op2_type, op.op2)
                    .unwrap_or_else(|| "method".to_owned());
                Some(format!("$vObj->{}(...);", strip_quotes(&method)))
            }
            o if o == op::INIT_STATIC_METHOD_CALL => {
                let method: String = self
                    .operand(op.op2_type, op.op2)
                    .unwrap_or_else(|| "method".to_owned());
                Some(format!("self::{}(...);", strip_quotes(&method)))
            }
            o if o == op::NEW => {
                let cls: String = self
                    .operand(op.op1_type, op.op1)
                    .unwrap_or_else(|| "stdClass".to_owned());
                Some(format!("new {}(...);", strip_quotes(&cls)))
            }
            o if o == op::INCLUDE_OR_EVAL => {
                Some(format!("/* {} */", include_kind(op.extended_value)))
            }
            o if o == op::UNSET_VAR => {
                let v: String = self.operand(op.op1_type, op.op1)?;
                Some(format!("unset({v});"))
            }
            o if o == op::YIELD => Some("yield /* ... */;".to_owned()),
            _ => None,
        }
    }

    fn callee_name(&self, op: &Op) -> Option<String> {
        self.operand(op.op2_type, op.op2)
            .map(|s: String| strip_quotes(&s))
    }

    fn operand(&self, ty: OperandType, value: u32) -> Option<String> {
        ty.render(value, self.literals)
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
