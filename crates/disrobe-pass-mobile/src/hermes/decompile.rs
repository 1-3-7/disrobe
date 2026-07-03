use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Arguments;

use serde::{Deserialize, Serialize};

use super::literals::{BufferKind, LiteralValue, decode_literals, render_key, render_value};
use super::{HermesModule, SmallFunctionHeader};

const MAX_RENDERED_CALL_ARGS: u64 = 256;

const UNRECOVERED_ARG: &str = "<arg?>";

const MAX_DECODED_INSTRUCTIONS: usize = 1 << 20;

const MAX_REG_EXPR_BYTES: usize = 4096;

const MAX_RENDER_BYTES: usize = 1 << 20;

const MAX_SWITCH_CASES: u64 = 4096;

const MAX_INLINE_CLOSURE_BYTES: usize = 1 << 16;

const MAX_INLINE_CLOSURE_DEPTH: usize = 8;

macro_rules! push_text {
    ($output:expr, $($arg:tt)*) => {
        push_format(&mut $output, format_args!($($arg)*))
    };
}

macro_rules! push_line {
    ($output:expr, $($arg:tt)*) => {
        push_format_line(&mut $output, format_args!($($arg)*))
    };
}

fn push_format(output: &mut String, args: Arguments<'_>) {
    match std::fmt::write(output, args) {
        Ok(()) => {}
        Err(error) => unreachable!("string formatting failed: {error:?}"),
    }
}

fn push_format_line(output: &mut String, args: Arguments<'_>) {
    push_format(output, args);
    output.push('\n');
}

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
    const fn width(self) -> usize {
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

#[rustfmt::skip]
pub(crate) const OPCODES: &[OpcodeSpec] = &[
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum OperandValue {
    Reg(u32),
    UInt(u64),
    Imm(i64),
    Float(u64),
    Target(usize),
    StringId(u32),
    FunctionId(u32),
    BigIntId(u32),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Instruction {
    pub offset: usize,
    pub size: usize,
    pub opcode: u8,
    pub name: Cow<'static, str>,
    pub operands: Vec<OperandValue>,
}

#[must_use]
pub(crate) fn decode_instructions(code: &[u8]) -> Vec<Instruction> {
    let cap: usize = (code.len() / 3).min(MAX_DECODED_INSTRUCTIONS);
    let mut out: Vec<Instruction> = Vec::with_capacity(cap);
    let mut pc: usize = 0;
    while pc < code.len() && out.len() < MAX_DECODED_INSTRUCTIONS {
        let opcode: u8 = code[pc];
        let spec: Option<&OpcodeSpec> = OPCODES.get(opcode as usize);
        let Some(spec): Option<&OpcodeSpec> = spec else {
            out.push(Instruction {
                offset: pc,
                size: 1,
                opcode,
                name: Cow::Owned(format!("Unknown_0x{opcode:02x}")),
                operands: Vec::new(),
            });
            pc += 1;
            continue;
        };
        let mut cursor: usize = pc + 1;
        let mut operands: Vec<OperandValue> = Vec::with_capacity(spec.operands.len());
        let mut truncated: bool = false;
        for operand in spec.operands {
            let w: usize = operand.width();
            if cursor + w > code.len() {
                truncated = true;
                break;
            }
            let raw: &[u8] = &code[cursor..cursor + w];
            let value: OperandValue = decode_operand(*operand, raw, pc);
            operands.push(value);
            cursor += w;
        }
        if truncated {
            out.push(Instruction {
                offset: pc,
                size: code.len() - pc,
                opcode,
                name: Cow::Owned(format!("{}<truncated>", spec.name)),
                operands,
            });
            break;
        }
        let size: usize = cursor - pc;
        out.push(Instruction {
            offset: pc,
            size,
            opcode,
            name: Cow::Borrowed(spec.name),
            operands,
        });
        pc = cursor;
    }
    out
}

#[must_use]
fn decode_operand(operand: Operand, raw: &[u8], pc: usize) -> OperandValue {
    let read_u: fn(&[u8]) -> u64 = |b: &[u8]| {
        let mut acc: u64 = 0;
        for (i, byte) in b.iter().enumerate() {
            acc |= (*byte as u64) << (8 * i);
        }
        acc
    };
    match operand {
        Operand::Reg8 | Operand::Reg32 => OperandValue::Reg(read_u(raw) as u32),
        Operand::UInt8 | Operand::UInt16 | Operand::UInt32 => OperandValue::UInt(read_u(raw)),
        Operand::Imm32 => {
            OperandValue::Imm(i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) as i64)
        }
        Operand::Double => OperandValue::Float(read_u(raw)),
        Operand::Addr8 => {
            let rel: i64 = (raw[0] as i8) as i64;
            OperandValue::Target(relative_target(pc, rel))
        }
        Operand::Addr32 => {
            let rel: i64 = i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) as i64;
            OperandValue::Target(relative_target(pc, rel))
        }
        Operand::StringId8 | Operand::StringId16 | Operand::StringId32 => {
            OperandValue::StringId(read_u(raw) as u32)
        }
        Operand::FunctionId16 | Operand::FunctionId32 => {
            OperandValue::FunctionId(read_u(raw) as u32)
        }
        Operand::BigIntId16 | Operand::BigIntId32 => OperandValue::BigIntId(read_u(raw) as u32),
    }
}

#[must_use]
fn relative_target(pc: usize, rel: i64) -> usize {
    if rel >= 0 {
        return match usize::try_from(rel) {
            Ok(delta) => pc.saturating_add(delta),
            Err(_) => usize::MAX,
        };
    }
    match usize::try_from(rel.unsigned_abs()) {
        Ok(delta) => pc.saturating_sub(delta),
        Err(_) => 0,
    }
}

#[must_use]
pub(crate) fn instruction_targets(inst: &Instruction) -> Vec<usize> {
    inst.operands
        .iter()
        .filter_map(|o: &OperandValue| match o {
            OperandValue::Target(t) => Some(*t),
            _ => None,
        })
        .collect()
}

#[must_use]
pub(crate) fn is_unconditional_jump(name: &str) -> bool {
    matches!(name, "Jmp" | "JmpLong")
}

#[must_use]
pub(crate) fn is_conditional_jump(name: &str) -> bool {
    name.starts_with('J') && !is_unconditional_jump(name) && name != "Jmp"
}

#[must_use]
pub(crate) fn is_terminator(name: &str) -> bool {
    matches!(name, "Ret" | "Throw" | "Unreachable")
        || is_unconditional_jump(name)
        || is_conditional_jump(name)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BasicBlock {
    pub start: usize,
    pub end: usize,
    pub instr_range: (usize, usize),
    pub successors: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Cfg {
    pub blocks: Vec<BasicBlock>,
    pub offset_to_block: BTreeMap<usize, usize>,
}

#[must_use]
pub(crate) fn build_cfg(instructions: &[Instruction]) -> Cfg {
    if instructions.is_empty() {
        return Cfg {
            blocks: Vec::new(),
            offset_to_block: BTreeMap::new(),
        };
    }
    let mut leaders: BTreeSet<usize> = BTreeSet::new();
    leaders.insert(instructions[0].offset);
    for (i, inst) in instructions.iter().enumerate() {
        if is_terminator(&inst.name) {
            for t in instruction_targets(inst) {
                leaders.insert(t);
            }
            if let Some(next) = instructions.get(i + 1) {
                leaders.insert(next.offset);
            }
        }
    }
    let valid_offsets: BTreeSet<usize> = instructions
        .iter()
        .map(|i: &Instruction| i.offset)
        .collect();
    let leaders: Vec<usize> = leaders
        .into_iter()
        .filter(|o: &usize| valid_offsets.contains(o))
        .collect();

    let mut offset_to_index: BTreeMap<usize, usize> = BTreeMap::new();
    for (i, inst) in instructions.iter().enumerate() {
        offset_to_index.insert(inst.offset, i);
    }

    let mut blocks: Vec<BasicBlock> = Vec::with_capacity(leaders.len());
    let mut offset_to_block: BTreeMap<usize, usize> = BTreeMap::new();
    for (li, leader) in leaders.iter().enumerate() {
        let start_idx: usize = offset_to_index[leader];
        let next_leader: Option<&usize> = leaders.get(li + 1);
        let end_idx: usize = match next_leader {
            Some(nl) => offset_to_index[nl],
            None => instructions.len(),
        };
        let last: &Instruction = &instructions[end_idx - 1];
        let block: BasicBlock = BasicBlock {
            start: *leader,
            end: last.offset + last.size,
            instr_range: (start_idx, end_idx),
            successors: Vec::new(),
        };
        offset_to_block.insert(*leader, blocks.len());
        blocks.push(block);
    }

    let successors: Vec<Vec<usize>> = blocks
        .iter()
        .map(|block: &BasicBlock| {
            let (_s, e): (usize, usize) = block.instr_range;
            let last: &Instruction = &instructions[e - 1];
            let mut succ: Vec<usize> = Vec::new();
            if is_unconditional_jump(&last.name) {
                for t in instruction_targets(last) {
                    if let Some(b) = offset_to_block.get(&t) {
                        succ.push(*b);
                    }
                }
            } else if is_conditional_jump(&last.name) {
                for t in instruction_targets(last) {
                    if let Some(b) = offset_to_block.get(&t) {
                        succ.push(*b);
                    }
                }
                if let Some(next) = instructions.get(e)
                    && let Some(b) = offset_to_block.get(&next.offset)
                {
                    succ.push(*b);
                }
            } else if matches!(&*last.name, "Ret" | "Throw" | "Unreachable") {
            } else if let Some(next) = instructions.get(e)
                && let Some(b) = offset_to_block.get(&next.offset)
            {
                succ.push(*b);
            }
            succ.dedup();
            succ
        })
        .collect();
    for (block, succ) in blocks.iter_mut().zip(successors) {
        block.successors = succ;
    }

    Cfg {
        blocks,
        offset_to_block,
    }
}

struct LiftCtx<'a> {
    module: &'a HermesModule,
    code: &'a [u8],
    regs: BTreeMap<u32, String>,
    env_levels: BTreeMap<u32, u32>,
    materialized: BTreeSet<u32>,
    window_consumed: BTreeSet<u32>,
    declared: BTreeSet<u32>,
    inline_bodies: &'a BTreeMap<u32, String>,
    reconstructed: usize,
    fallback: usize,
}

impl<'a> LiftCtx<'a> {
    fn new(
        module: &'a HermesModule,
        code: &'a [u8],
        materialized: BTreeSet<u32>,
        window_consumed: BTreeSet<u32>,
        inline_bodies: &'a BTreeMap<u32, String>,
    ) -> Self {
        LiftCtx {
            module,
            code,
            regs: BTreeMap::new(),
            env_levels: BTreeMap::new(),
            materialized,
            window_consumed,
            declared: BTreeSet::new(),
            inline_bodies,
            reconstructed: 0,
            fallback: 0,
        }
    }

    fn closure_expr(&self, fid: u32, prefix: &str) -> String {
        if let Some(body) = self.inline_bodies.get(&fid)
            && body.len() <= MAX_INLINE_CLOSURE_BYTES
            && body_keyword_matches(body, prefix)
        {
            return body.clone();
        }
        let nm: String = self.func_name(fid);
        format!("{prefix} {nm}() {{ /* fn #{fid} */ }}")
    }

    fn is_materialized(&self, r: u32) -> bool {
        self.materialized.contains(&r)
    }

    fn var_name(r: u32) -> String {
        format!("v{r}")
    }

    fn materialize_assignment(&mut self, r: u32, rhs: &str) -> String {
        let name: String = Self::var_name(r);
        let stmt: String = if self.declared.insert(r) {
            format!("var {name} = {rhs};")
        } else {
            format!("{name} = {rhs};")
        };
        self.regs.insert(r, name);
        stmt
    }

    fn set_env(&mut self, reg: u32, level: u32) {
        self.env_levels.insert(reg, level);
    }

    fn env_level(&self, reg: u32) -> u32 {
        self.env_levels.get(&reg).copied().unwrap_or(0)
    }

    fn reg_expr(&self, r: u32) -> String {
        if self.is_materialized(r)
            && let Some(expr) = self.regs.get(&r)
        {
            return expr.clone();
        }
        self.regs
            .get(&r)
            .cloned()
            .unwrap_or_else(|| format!("r{r}"))
    }

    fn set_reg(&mut self, r: u32, expr: String) {
        if expr.len() > MAX_REG_EXPR_BYTES {
            self.regs.insert(r, format!("r{r}"));
        } else {
            self.regs.insert(r, expr);
        }
    }

    fn set_reg_closure(&mut self, r: u32, expr: String) {
        self.regs.insert(r, expr);
    }

    fn string_lit(&self, id: u32) -> String {
        match self.module.string_by_global_id(id) {
            Some(s) => js_string_literal(s),
            None => format!("$str{id}"),
        }
    }

    fn ident_or_string(&self, id: u32) -> String {
        match self.module.string_by_global_id(id) {
            Some(s) => s.to_owned(),
            None => format!("$str{id}"),
        }
    }

    fn func_name(&self, id: u32) -> String {
        self.module
            .functions
            .get(id as usize)
            .and_then(|f: &SmallFunctionHeader| {
                self.module
                    .string_by_global_id(f.function_name_id)
                    .map(str::to_owned)
            })
            .filter(|s: &String| !s.is_empty())
            .unwrap_or_else(|| format!("$func{id}"))
    }

    fn object_literal(&self, num_literals: usize, key_idx: usize, val_idx: usize) -> String {
        let keys: Vec<LiteralValue> = decode_literals(
            &self.module.obj_key_buffer,
            key_idx,
            num_literals,
            BufferKind::Key,
        );
        let vals: Vec<LiteralValue> = decode_literals(
            &self.module.obj_value_buffer,
            val_idx,
            num_literals,
            BufferKind::Value,
        );
        if keys.is_empty() {
            return "{}".to_owned();
        }
        let resolve_ident = |id: u32| self.string_or_ident_name(id);
        let resolve_str = |id: u32| self.string_lit_by_id(id);
        let mut out: String = String::with_capacity(keys.len().saturating_mul(8).saturating_add(2));
        out.push_str("{ ");
        for (i, key) in keys.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            let key_text: String = render_object_key(key, &resolve_ident);
            out.push_str(&key_text);
            out.push_str(": ");
            match vals.get(i) {
                Some(v) => out.push_str(&render_value(v, &resolve_str)),
                None => out.push_str("undefined"),
            }
        }
        out.push_str(" }");
        out
    }

    fn array_literal(&self, num_elems: usize, val_idx: usize) -> String {
        let vals: Vec<LiteralValue> = decode_literals(
            &self.module.array_buffer,
            val_idx,
            num_elems,
            BufferKind::Value,
        );
        if vals.is_empty() {
            return "[]".to_owned();
        }
        let resolve_str = |id: u32| self.string_lit_by_id(id);
        let mut out: String = String::with_capacity(vals.len().saturating_mul(4).saturating_add(2));
        out.push('[');
        for (i, v) in vals.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(&render_value(v, &resolve_str));
        }
        out.push(']');
        out
    }

    fn string_lit_by_id(&self, id: u32) -> String {
        match self.module.string_by_global_id(id) {
            Some(s) => js_string_literal(s),
            None => format!("$str{id}"),
        }
    }

    fn string_or_ident_name(&self, id: u32) -> String {
        match self.module.string_by_global_id(id) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => format!("$str{id}"),
        }
    }

    fn raw_string(&self, id: u32) -> String {
        self.module
            .string_by_global_id(id)
            .map(str::to_owned)
            .unwrap_or_default()
    }

    fn bigint_lit(&self, id: u32) -> String {
        let Some(id_usize): Option<usize> = usize::try_from(id).ok() else {
            return format!("$bigint{id}n");
        };
        let Some(entry): Option<&super::BigIntTableEntry> = self.module.big_int_table.get(id_usize)
        else {
            return format!("$bigint{id}n");
        };
        let Some(start): Option<usize> = usize::try_from(entry.offset).ok() else {
            return format!("$bigint{id}n");
        };
        let Some(length): Option<usize> = usize::try_from(entry.length).ok() else {
            return format!("$bigint{id}n");
        };
        let Some(end): Option<usize> = start.checked_add(length) else {
            return format!("$bigint{id}n");
        };
        match self.module.big_int_storage.get(start..end) {
            Some(slice) if !slice.is_empty() => super::bigint::bigint_literal(slice),
            _ => format!("$bigint{id}n"),
        }
    }

    fn regexp_literal(&self, pattern_id: u32, flags_id: u32, index: u32) -> String {
        let recovered_index: usize = match usize::try_from(index) {
            Ok(index) => index,
            Err(_) => return format!("/(?:regexp #{index})/"),
        };
        let recovered: Option<super::regex::RecoveredRegExp> = super::regex::recover_regexp(
            &self.module.reg_exp_table,
            &self.module.reg_exp_storage,
            recovered_index,
        );
        let stored_pattern: String = self.raw_string(pattern_id);
        let pattern: String = if stored_pattern.is_empty() {
            match recovered.as_ref().filter(|r| !r.pattern.is_empty()) {
                Some(rx) => rx.pattern.clone(),
                None => return format!("/(?:regexp #{index})/"),
            }
        } else {
            stored_pattern
        };
        let stored_flags: String = self.raw_string(flags_id);
        let flags: String = if stored_flags.is_empty() {
            recovered.map(|r| r.flags).unwrap_or_default()
        } else {
            stored_flags
        };
        format!("/{pattern}/{flags}")
    }

    fn switch_cases(
        &self,
        inst_offset: usize,
        table_offset: u64,
        min_val: u64,
        max_val: u64,
    ) -> Vec<(i64, usize)> {
        if max_val < min_val {
            return Vec::new();
        }
        let entry_count: u64 = max_val - min_val + 1;
        if entry_count > MAX_SWITCH_CASES {
            return Vec::new();
        }
        let Some(table_offset_usize): Option<usize> = usize::try_from(table_offset).ok() else {
            return Vec::new();
        };
        let Some(table_base): Option<usize> = inst_offset.checked_add(table_offset_usize) else {
            return Vec::new();
        };
        let Some(aligned_base): Option<usize> =
            table_base.checked_add(3).map(|base: usize| base & !3usize)
        else {
            return Vec::new();
        };
        let Some(entry_count_usize): Option<usize> = usize::try_from(entry_count).ok() else {
            return Vec::new();
        };
        let Ok(inst_offset_raw): Result<i128, _> = i128::try_from(inst_offset) else {
            return Vec::new();
        };
        let mut cases: Vec<(i64, usize)> = Vec::with_capacity(entry_count_usize);
        for k in 0..entry_count_usize {
            let Some(entry_delta): Option<usize> = k.checked_mul(core::mem::size_of::<u32>())
            else {
                break;
            };
            let Some(entry_at): Option<usize> = aligned_base.checked_add(entry_delta) else {
                break;
            };
            let Some(entry_end): Option<usize> = entry_at.checked_add(core::mem::size_of::<u32>())
            else {
                break;
            };
            let Some(raw): Option<&[u8]> = self.code.get(entry_at..entry_end) else {
                break;
            };
            let rel: i32 = i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
            let target_raw: i128 = (inst_offset_raw + i128::from(rel)).max(0);
            let Ok(target): Result<usize, _> = usize::try_from(target_raw) else {
                break;
            };
            let Ok(k_u64): Result<u64, _> = u64::try_from(k) else {
                break;
            };
            let Some(case_value_raw): Option<u64> = min_val.checked_add(k_u64) else {
                break;
            };
            let Ok(case_value): Result<i64, _> = i64::try_from(case_value_raw) else {
                break;
            };
            cases.push((case_value, target));
        }
        cases
    }
}

#[must_use]
fn render_object_key<F>(key: &LiteralValue, resolve_ident: &F) -> String
where
    F: Fn(u32) -> String,
{
    match key {
        LiteralValue::StringId(id) => {
            let name: String = resolve_ident(*id);
            if is_valid_js_identifier(&name) {
                name
            } else {
                js_string_literal(&name)
            }
        }
        other => render_key(other, resolve_ident),
    }
}

#[must_use]
fn is_valid_js_identifier(s: &str) -> bool {
    let mut chars: core::str::Chars<'_> = s.chars();
    match chars.next() {
        Some(c) if c == '_' || c == '$' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c: char| c == '_' || c == '$' || c.is_ascii_alphanumeric())
}

#[must_use]
fn body_keyword_matches(body: &str, prefix: &str) -> bool {
    let trimmed: &str = body.trim_start();
    match prefix {
        "function*" => trimmed.starts_with("function*"),
        "async function" => trimmed.starts_with("async function"),
        _ => trimmed.starts_with("function") && !trimmed.starts_with("function*"),
    }
}

#[must_use]
fn captured_var(level: u32, slot: u64) -> String {
    if level == 0 {
        format!("cvar{slot}")
    } else {
        format!("cvar{level}_{slot}")
    }
}

#[must_use]
fn js_string_literal(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                push_text!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[must_use]
fn reg_of(v: Option<&OperandValue>) -> u32 {
    match v {
        Some(OperandValue::Reg(r)) => *r,
        _ => 0,
    }
}

#[must_use]
fn uint_of(v: Option<&OperandValue>) -> u64 {
    match v {
        Some(OperandValue::UInt(u)) => *u,
        _ => 0,
    }
}

#[must_use]
fn strid_of(v: Option<&OperandValue>) -> u32 {
    match v {
        Some(OperandValue::StringId(s)) => *s,
        _ => 0,
    }
}

#[must_use]
fn binop_symbol(name: &str) -> Option<&'static str> {
    Some(match name {
        "Add" | "AddN" => "+",
        "Sub" | "SubN" => "-",
        "Mul" | "MulN" => "*",
        "Div" | "DivN" => "/",
        "Mod" => "%",
        "Eq" => "==",
        "Neq" => "!=",
        "StrictEq" => "===",
        "StrictNeq" => "!==",
        "Less" => "<",
        "LessEq" => "<=",
        "Greater" => ">",
        "GreaterEq" => ">=",
        "LShift" => "<<",
        "RShift" => ">>",
        "URshift" => ">>>",
        "BitAnd" => "&",
        "BitOr" => "|",
        "BitXor" => "^",
        "InstanceOf" => "instanceof",
        "IsIn" => "in",
        _ => return None,
    })
}

#[must_use]
fn unop_symbol(name: &str) -> Option<&'static str> {
    Some(match name {
        "Negate" => "-",
        "Not" => "!",
        "BitNot" => "~",
        "TypeOf" => "typeof ",
        "Inc" => "++",
        "Dec" => "--",
        _ => return None,
    })
}

#[must_use]
fn jump_condition(name: &str) -> Option<(&'static str, bool)> {
    let base: &str = name.trim_end_matches("Long").trim_end_matches('N');
    Some(match base {
        "JLess" => ("<", false),
        "JNotLess" => ("<", true),
        "JLessEqual" => ("<=", false),
        "JNotLessEqual" => ("<=", true),
        "JGreater" => (">", false),
        "JNotGreater" => (">", true),
        "JGreaterEqual" => (">=", false),
        "JNotGreaterEqual" => (">=", true),
        "JEqual" => ("==", false),
        "JNotEqual" => ("==", true),
        "JStrictEqual" => ("===", false),
        "JStrictNotEqual" => ("===", true),
        _ => return None,
    })
}

#[derive(Debug, Clone)]
pub(crate) enum BlockStmt {
    Line(String),
    Return(String),
    Throw(String),
    CondJump {
        cond: String,
        target: usize,
        fallthrough: Option<usize>,
    },
    Jump(usize),
    Switch {
        scrutinee: String,
        cases: Vec<(i64, usize)>,
        default: usize,
    },
}

#[derive(Debug, Clone)]
struct LiftedBlock {
    start: usize,
    stmts: Vec<BlockStmt>,
}

fn lift_block(
    ctx: &mut LiftCtx<'_>,
    instructions: &[Instruction],
    block: &BasicBlock,
    cfg: &Cfg,
) -> LiftedBlock {
    let (s, e): (usize, usize) = block.instr_range;
    let mut stmts: Vec<BlockStmt> = Vec::new();
    for inst in &instructions[s..e] {
        lift_instruction(ctx, inst, instructions, cfg, &mut stmts);
    }
    LiftedBlock {
        start: block.start,
        stmts,
    }
}

fn lift_instruction(
    ctx: &mut LiftCtx<'_>,
    inst: &Instruction,
    instructions: &[Instruction],
    cfg: &Cfg,
    stmts: &mut Vec<BlockStmt>,
) {
    lift_instruction_inner(ctx, inst, instructions, cfg, stmts);
    flush_materialized_value(ctx, inst, stmts);
}

fn flush_materialized_value(ctx: &mut LiftCtx<'_>, inst: &Instruction, stmts: &mut Vec<BlockStmt>) {
    let name: &str = &inst.name;
    if is_call_like(name) {
        return;
    }
    if !(is_value_producer(name) || matches!(name, "Mov" | "MovLong")) {
        return;
    }
    let Some(d): Option<u32> = inst_dest(inst) else {
        return;
    };
    if !ctx.is_materialized(d) {
        return;
    }
    let rhs: String = ctx.reg_expr(d);
    if rhs == LiftCtx::var_name(d) {
        return;
    }
    let stmt: String = ctx.materialize_assignment(d, &rhs);
    stmts.push(BlockStmt::Line(stmt));
}

fn lift_instruction_inner(
    ctx: &mut LiftCtx<'_>,
    inst: &Instruction,
    instructions: &[Instruction],
    cfg: &Cfg,
    stmts: &mut Vec<BlockStmt>,
) {
    let ops: &[OperandValue] = &inst.operands;
    let name: &str = &inst.name;

    if let Some(sym) = binop_symbol(name) {
        let d: u32 = reg_of(ops.first());
        let a: String = ctx.reg_expr(reg_of(ops.get(1)));
        let b: String = ctx.reg_expr(reg_of(ops.get(2)));
        ctx.set_reg(d, format!("({a} {sym} {b})"));
        ctx.reconstructed += 1;
        return;
    }
    if let Some(sym) = unop_symbol(name) {
        let d: u32 = reg_of(ops.first());
        let a: String = ctx.reg_expr(reg_of(ops.get(1)));
        let expr: String = if matches!(name, "Inc" | "Dec") {
            format!("({a} {} 1)", if name == "Inc" { "+" } else { "-" })
        } else {
            format!("{sym}{a}")
        };
        ctx.set_reg(d, expr);
        ctx.reconstructed += 1;
        return;
    }

    match name {
        "LoadConstUInt8" => {
            let d: u32 = reg_of(ops.first());
            ctx.set_reg(d, uint_of(ops.get(1)).to_string());
            ctx.reconstructed += 1;
        }
        "LoadConstInt" => {
            let d: u32 = reg_of(ops.first());
            let v: i64 = match ops.get(1) {
                Some(OperandValue::Imm(i)) => *i,
                _ => 0,
            };
            ctx.set_reg(d, v.to_string());
            ctx.reconstructed += 1;
        }
        "LoadConstDouble" => {
            let d: u32 = reg_of(ops.first());
            let bits: u64 = match ops.get(1) {
                Some(OperandValue::Float(f)) => *f,
                _ => 0,
            };
            let v: f64 = f64::from_bits(bits);
            ctx.set_reg(d, format_f64(v));
            ctx.reconstructed += 1;
        }
        "LoadConstZero" => {
            ctx.set_reg(reg_of(ops.first()), "0".to_owned());
            ctx.reconstructed += 1;
        }
        "LoadConstString" | "LoadConstStringLongIndex" => {
            let d: u32 = reg_of(ops.first());
            let lit: String = ctx.string_lit(strid_of(ops.get(1)));
            ctx.set_reg(d, lit);
            ctx.reconstructed += 1;
        }
        "LoadConstUndefined" | "LoadConstEmpty" => {
            ctx.set_reg(reg_of(ops.first()), "undefined".to_owned());
            ctx.reconstructed += 1;
        }
        "LoadConstNull" => {
            ctx.set_reg(reg_of(ops.first()), "null".to_owned());
            ctx.reconstructed += 1;
        }
        "LoadConstTrue" => {
            ctx.set_reg(reg_of(ops.first()), "true".to_owned());
            ctx.reconstructed += 1;
        }
        "LoadConstFalse" => {
            ctx.set_reg(reg_of(ops.first()), "false".to_owned());
            ctx.reconstructed += 1;
        }
        "LoadParam" | "LoadParamLong" => {
            let d: u32 = reg_of(ops.first());
            let idx: u64 = uint_of(ops.get(1));
            let expr: String = if idx == 0 {
                "this".to_owned()
            } else {
                format!("arg{}", idx - 1)
            };
            ctx.set_reg(d, expr);
            ctx.reconstructed += 1;
        }
        "LoadThisNS" | "CoerceThisNS" => {
            ctx.set_reg(reg_of(ops.first()), "this".to_owned());
            ctx.reconstructed += 1;
        }
        "Mov" | "MovLong" => {
            let d: u32 = reg_of(ops.first());
            let src: String = ctx.reg_expr(reg_of(ops.get(1)));
            ctx.set_reg(d, src);
            if let Some(level) = ctx.env_levels.get(&reg_of(ops.get(1))).copied() {
                ctx.set_env(d, level);
            }
            ctx.reconstructed += 1;
        }
        "CreateEnvironment" => {
            let d: u32 = reg_of(ops.first());
            ctx.set_reg(d, "$env".to_owned());
            ctx.set_env(d, 0);
            ctx.reconstructed += 1;
        }
        "CreateInnerEnvironment" => {
            let d: u32 = reg_of(ops.first());
            let parent: u32 = reg_of(ops.get(1));
            ctx.set_reg(d, "$env".to_owned());
            ctx.set_env(d, ctx.env_level(parent));
            ctx.reconstructed += 1;
        }
        "GetEnvironment" => {
            let d: u32 = reg_of(ops.first());
            let levels: u32 = uint_of(ops.get(1)) as u32;
            ctx.set_reg(d, "$env".to_owned());
            ctx.set_env(d, levels);
            ctx.reconstructed += 1;
        }
        "LoadFromEnvironment" | "LoadFromEnvironmentL" => {
            let d: u32 = reg_of(ops.first());
            let env_reg: u32 = reg_of(ops.get(1));
            let slot: u64 = uint_of(ops.get(2));
            let level: u32 = ctx.env_level(env_reg);
            ctx.set_reg(d, captured_var(level, slot));
            ctx.reconstructed += 1;
        }
        "StoreToEnvironment"
        | "StoreToEnvironmentL"
        | "StoreNPToEnvironment"
        | "StoreNPToEnvironmentL" => {
            let env_reg: u32 = reg_of(ops.first());
            let slot: u64 = uint_of(ops.get(1));
            let value: String = ctx.reg_expr(reg_of(ops.get(2)));
            let level: u32 = ctx.env_level(env_reg);
            let name: String = captured_var(level, slot);
            stmts.push(BlockStmt::Line(format!("{name} = {value};")));
            ctx.reconstructed += 1;
        }
        "GetGlobalObject" => {
            ctx.set_reg(reg_of(ops.first()), "globalThis".to_owned());
            ctx.reconstructed += 1;
        }
        "IteratorBegin" => {
            let d: u32 = reg_of(ops.first());
            let src: String = ctx.reg_expr(reg_of(ops.get(1)));
            ctx.set_reg(d, format!("{src}[Symbol.iterator]()"));
            ctx.reconstructed += 1;
        }
        "IteratorNext" => {
            let d: u32 = reg_of(ops.first());
            let it: String = ctx.reg_expr(reg_of(ops.get(1)));
            ctx.set_reg(d, format!("{it}.next().value"));
            ctx.reconstructed += 1;
        }
        "IteratorClose" => {
            let it: String = ctx.reg_expr(reg_of(ops.first()));
            stmts.push(BlockStmt::Line(format!("{it}.return?.();")));
            ctx.reconstructed += 1;
        }
        "GetPNameList" => {
            let d: u32 = reg_of(ops.first());
            let obj: String = ctx.reg_expr(reg_of(ops.get(1)));
            ctx.set_reg(d, format!("Object.keys({obj})"));
            ctx.reconstructed += 1;
        }
        "GetNextPName" => {
            let d: u32 = reg_of(ops.first());
            let props: String = ctx.reg_expr(reg_of(ops.get(1)));
            let idx: String = ctx.reg_expr(reg_of(ops.get(3)));
            ctx.set_reg(d, format!("{props}[{idx}]"));
            ctx.reconstructed += 1;
        }
        "StartGenerator" | "CompleteGenerator" => {
            stmts.push(BlockStmt::Line(format!("{};", fallback_disasm(inst))));
            ctx.fallback += 1;
        }
        "SaveGenerator" | "SaveGeneratorLong" => {
            stmts.push(BlockStmt::Line("yield;".to_owned()));
            ctx.reconstructed += 1;
        }
        "ResumeGenerator" => {
            let d: u32 = reg_of(ops.first());
            ctx.set_reg(d, "$resumed".to_owned());
            ctx.reconstructed += 1;
        }
        "CreateGenerator" | "CreateGeneratorLongIndex" => {
            let d: u32 = reg_of(ops.first());
            let fid: u32 = match ops.get(2) {
                Some(OperandValue::FunctionId(f)) => *f,
                _ => 0,
            };
            let nm: String = ctx.func_name(fid);
            ctx.set_reg(d, format!("function* {nm}() {{ /* fn #{fid} */ }}"));
            ctx.reconstructed += 1;
        }
        "ToNumber" => {
            let d: u32 = reg_of(ops.first());
            let src: String = ctx.reg_expr(reg_of(ops.get(1)));
            ctx.set_reg(d, format!("+{src}"));
            ctx.reconstructed += 1;
        }
        "ToNumeric" => {
            let d: u32 = reg_of(ops.first());
            let src: String = ctx.reg_expr(reg_of(ops.get(1)));
            ctx.set_reg(d, src);
            ctx.reconstructed += 1;
        }
        "ToInt32" => {
            let d: u32 = reg_of(ops.first());
            let src: String = ctx.reg_expr(reg_of(ops.get(1)));
            ctx.set_reg(d, format!("({src} | 0)"));
            ctx.reconstructed += 1;
        }
        "AddEmptyString" => {
            let d: u32 = reg_of(ops.first());
            let src: String = ctx.reg_expr(reg_of(ops.get(1)));
            ctx.set_reg(d, format!("(\"\" + {src})"));
            ctx.reconstructed += 1;
        }
        "GetNewTarget" => {
            ctx.set_reg(reg_of(ops.first()), "new.target".to_owned());
            ctx.reconstructed += 1;
        }
        "ReifyArguments" | "GetArgumentsLength" | "GetArgumentsPropByVal" => {
            let d: u32 = reg_of(ops.first());
            let expr: String = match name {
                "GetArgumentsLength" => "arguments.length".to_owned(),
                "GetArgumentsPropByVal" => {
                    let key: String = ctx.reg_expr(reg_of(ops.get(1)));
                    format!("arguments[{key}]")
                }
                _ => "arguments".to_owned(),
            };
            ctx.set_reg(d, expr);
            ctx.reconstructed += 1;
        }
        "DirectEval" => {
            let d: u32 = reg_of(ops.first());
            let src: String = ctx.reg_expr(reg_of(ops.get(1)));
            ctx.set_reg(d, format!("eval({src})"));
            ctx.reconstructed += 1;
        }
        "DeclareGlobalVar" | "ThrowIfHasRestrictedGlobalProperty" => {
            let nm: String = ctx.ident_or_string(strid_of(ops.first()));
            stmts.push(BlockStmt::Line(format!("var {nm};")));
            ctx.reconstructed += 1;
        }
        "ThrowIfEmpty" => {
            let d: u32 = reg_of(ops.first());
            let src: String = ctx.reg_expr(reg_of(ops.get(1)));
            ctx.set_reg(d, src);
            ctx.reconstructed += 1;
        }
        "CallDirect" | "CallDirectLongIndex" => {
            let d: u32 = reg_of(ops.first());
            let argc: u64 = uint_of(ops.get(1)).saturating_sub(1);
            let fid: u32 = match ops.get(2) {
                Some(OperandValue::FunctionId(f)) => *f,
                _ => 0,
            };
            let callee: String = ctx.func_name(fid);
            let args: String = unrecovered_arg_list(argc);
            ctx.set_reg(d, format!("{callee}({args})"));
            ctx.reconstructed += 1;
        }
        "GetByIdShort" | "GetById" | "GetByIdLong" | "TryGetById" | "TryGetByIdLong" => {
            let d: u32 = reg_of(ops.first());
            let obj: String = ctx.reg_expr(reg_of(ops.get(1)));
            let prop: String = ctx.ident_or_string(strid_of(ops.get(3)));
            ctx.set_reg(d, format!("{obj}.{prop}"));
            ctx.reconstructed += 1;
        }
        "PutById"
        | "PutByIdLong"
        | "TryPutById"
        | "TryPutByIdLong"
        | "PutNewOwnById"
        | "PutNewOwnByIdLong"
        | "PutNewOwnByIdShort"
        | "PutNewOwnNEById"
        | "PutNewOwnNEByIdLong" => {
            let obj: String = ctx.reg_expr(reg_of(ops.first()));
            let val: String = ctx.reg_expr(reg_of(ops.get(1)));
            let prop: String = ctx.ident_or_string(strid_of(ops.get(2)).max(strid_of(ops.get(3))));
            stmts.push(BlockStmt::Line(format!("{obj}.{prop} = {val};")));
            ctx.reconstructed += 1;
        }
        "GetBuiltinClosure" => {
            let d: u32 = reg_of(ops.first());
            let builtin_id: u64 = uint_of(ops.get(1));
            ctx.set_reg(d, super::builtins::builtin_name(builtin_id));
            ctx.reconstructed += 1;
        }
        "Debugger" => {
            stmts.push(BlockStmt::Line("debugger;".to_owned()));
            ctx.reconstructed += 1;
        }
        "AsyncBreakCheck" | "ProfilePoint" | "Unreachable" => {
            stmts.push(BlockStmt::Line(format!("{};", fallback_disasm(inst))));
            ctx.fallback += 1;
        }
        "GetByVal" => {
            let d: u32 = reg_of(ops.first());
            let obj: String = ctx.reg_expr(reg_of(ops.get(1)));
            let key: String = ctx.reg_expr(reg_of(ops.get(2)));
            ctx.set_reg(d, format!("{obj}[{key}]"));
            ctx.reconstructed += 1;
        }
        "PutByVal" => {
            let obj: String = ctx.reg_expr(reg_of(ops.first()));
            let key: String = ctx.reg_expr(reg_of(ops.get(1)));
            let val: String = ctx.reg_expr(reg_of(ops.get(2)));
            stmts.push(BlockStmt::Line(format!("{obj}[{key}] = {val};")));
            ctx.reconstructed += 1;
        }
        "PutOwnByIndex" | "PutOwnByIndexL" => {
            let obj: String = ctx.reg_expr(reg_of(ops.first()));
            let val: String = ctx.reg_expr(reg_of(ops.get(1)));
            let idx: u64 = uint_of(ops.get(2));
            stmts.push(BlockStmt::Line(format!("{obj}[{idx}] = {val};")));
            ctx.reconstructed += 1;
        }
        "PutOwnByVal" => {
            let obj: String = ctx.reg_expr(reg_of(ops.first()));
            let val: String = ctx.reg_expr(reg_of(ops.get(1)));
            let key: String = ctx.reg_expr(reg_of(ops.get(2)));
            stmts.push(BlockStmt::Line(format!("{obj}[{key}] = {val};")));
            ctx.reconstructed += 1;
        }
        "PutOwnGetterSetterByVal" => {
            let obj: String = ctx.reg_expr(reg_of(ops.first()));
            let key: String = ctx.reg_expr(reg_of(ops.get(1)));
            stmts.push(BlockStmt::Line(format!(
                "Object.defineProperty({obj}, {key}, {{ get, set }});"
            )));
            ctx.reconstructed += 1;
        }
        "DelById" | "DelByIdLong" => {
            let d: u32 = reg_of(ops.first());
            let obj: String = ctx.reg_expr(reg_of(ops.get(1)));
            let prop: String = ctx.ident_or_string(strid_of(ops.get(2)));
            let expr: String = format!("delete {obj}.{prop}");
            if reg_read_later(d, inst, instructions) {
                ctx.set_reg(d, expr);
            } else {
                stmts.push(BlockStmt::Line(format!("{expr};")));
                ctx.set_reg(d, format!("r{d}"));
            }
            ctx.reconstructed += 1;
        }
        "DelByVal" => {
            let d: u32 = reg_of(ops.first());
            let obj: String = ctx.reg_expr(reg_of(ops.get(1)));
            let key: String = ctx.reg_expr(reg_of(ops.get(2)));
            let expr: String = format!("delete {obj}[{key}]");
            if reg_read_later(d, inst, instructions) {
                ctx.set_reg(d, expr);
            } else {
                stmts.push(BlockStmt::Line(format!("{expr};")));
                ctx.set_reg(d, format!("r{d}"));
            }
            ctx.reconstructed += 1;
        }
        "NewObjectWithParent" => {
            let d: u32 = reg_of(ops.first());
            let parent: String = ctx.reg_expr(reg_of(ops.get(1)));
            ctx.set_reg(d, format!("Object.create({parent})"));
            ctx.reconstructed += 1;
        }
        "NewObject" => {
            ctx.set_reg(reg_of(ops.first()), "{}".to_owned());
            ctx.reconstructed += 1;
        }
        "NewObjectWithBuffer" | "NewObjectWithBufferLong" => {
            let d: u32 = reg_of(ops.first());
            let num_literals: usize = uint_of(ops.get(2)) as usize;
            let key_idx: usize = uint_of(ops.get(3)) as usize;
            let val_idx: usize = uint_of(ops.get(4)) as usize;
            let lit: String = ctx.object_literal(num_literals, key_idx, val_idx);
            ctx.set_reg(d, lit);
            ctx.reconstructed += 1;
        }
        "NewArray" => {
            ctx.set_reg(reg_of(ops.first()), "[]".to_owned());
            ctx.reconstructed += 1;
        }
        "NewArrayWithBuffer" | "NewArrayWithBufferLong" => {
            let d: u32 = reg_of(ops.first());
            let num_elems: usize = uint_of(ops.get(2)) as usize;
            let val_idx: usize = uint_of(ops.get(3)) as usize;
            let lit: String = ctx.array_literal(num_elems, val_idx);
            ctx.set_reg(d, lit);
            ctx.reconstructed += 1;
        }
        "CreateThis" => {
            ctx.set_reg(reg_of(ops.first()), "this".to_owned());
            ctx.reconstructed += 1;
        }
        "SelectObject" => {
            let d: u32 = reg_of(ops.first());
            let a: String = ctx.reg_expr(reg_of(ops.get(2)));
            ctx.set_reg(d, a);
            ctx.reconstructed += 1;
        }
        "CreateClosure"
        | "CreateClosureLongIndex"
        | "CreateGeneratorClosure"
        | "CreateGeneratorClosureLongIndex"
        | "CreateAsyncClosure"
        | "CreateAsyncClosureLongIndex" => {
            let d: u32 = reg_of(ops.first());
            let fid: u32 = match ops.get(2) {
                Some(OperandValue::FunctionId(f)) => *f,
                _ => 0,
            };
            let prefix: &str = if name.contains("Async") {
                "async function"
            } else if name.contains("Generator") {
                "function*"
            } else {
                "function"
            };
            let closure: String = ctx.closure_expr(fid, prefix);
            ctx.set_reg_closure(d, closure);
            ctx.reconstructed += 1;
        }
        "CreateRegExp" => {
            let d: u32 = reg_of(ops.first());
            let pattern_id: u32 = strid_of(ops.get(1));
            let flags_id: u32 = strid_of(ops.get(2));
            let index: u32 = uint_of(ops.get(3)) as u32;
            let literal: String = ctx.regexp_literal(pattern_id, flags_id, index);
            ctx.set_reg(d, literal);
            ctx.reconstructed += 1;
        }
        "SwitchImm" => {
            let scrutinee: String = ctx.reg_expr(reg_of(ops.first()));
            let table_offset: u64 = uint_of(ops.get(1));
            let default: usize = match ops.get(2) {
                Some(OperandValue::Target(t)) => *t,
                _ => 0,
            };
            let min_val: u64 = uint_of(ops.get(3));
            let max_val: u64 = uint_of(ops.get(4));
            let cases: Vec<(i64, usize)> =
                ctx.switch_cases(inst.offset, table_offset, min_val, max_val);
            stmts.push(BlockStmt::Switch {
                scrutinee,
                cases,
                default,
            });
            ctx.reconstructed += 1;
        }
        "CallBuiltin" | "CallBuiltinLong" => {
            let d: u32 = reg_of(ops.first());
            let builtin_id: u64 = uint_of(ops.get(1));
            let argc: u64 = uint_of(ops.get(2)).saturating_sub(1);
            if super::builtins::is_template_object_builtin(builtin_id) {
                ctx.set_reg(d, "`${/* template */}`".to_owned());
                ctx.reconstructed += 1;
                return;
            }
            let callee: String = super::builtins::builtin_name(builtin_id);
            let args: String = unrecovered_arg_list(argc);
            ctx.set_reg(d, format!("{callee}({args})"));
            ctx.reconstructed += 1;
        }
        "LoadConstBigInt" | "LoadConstBigIntLongIndex" => {
            let d: u32 = reg_of(ops.first());
            let bid: u32 = match ops.get(1) {
                Some(OperandValue::BigIntId(b)) => *b,
                _ => 0,
            };
            ctx.set_reg(d, ctx.bigint_lit(bid));
            ctx.reconstructed += 1;
        }
        "Call" | "CallLong" | "Construct" | "ConstructLong" => {
            let d: u32 = reg_of(ops.first());
            let callee: String = ctx.reg_expr(reg_of(ops.get(1)));
            let argc: u64 = uint_of(ops.get(2)).saturating_sub(1);
            let new_kw: &str = if name.starts_with("Construct") {
                "new "
            } else {
                ""
            };
            let args: String = match recover_call_arguments(ctx, inst, instructions, argc) {
                Some(recovered) => recovered.join(", "),
                None => unrecovered_arg_list(argc),
            };
            let call_expr: String = format!("{new_kw}{callee}({args})");
            emit_call_result(ctx, d, call_expr, inst, instructions, stmts);
            ctx.reconstructed += 1;
        }
        "Call1" | "Call2" | "Call3" | "Call4" => {
            let d: u32 = reg_of(ops.first());
            let callee: String = ctx.reg_expr(reg_of(ops.get(1)));
            let args: Vec<String> = ops[3..]
                .iter()
                .map(|o: &OperandValue| match o {
                    OperandValue::Reg(r) => ctx.reg_expr(*r),
                    _ => "?".to_owned(),
                })
                .collect();
            let call_expr: String = format!("{callee}({})", args.join(", "));
            emit_call_result(ctx, d, call_expr, inst, instructions, stmts);
            ctx.reconstructed += 1;
        }
        "Ret" => {
            let v: String = ctx.reg_expr(reg_of(ops.first()));
            stmts.push(BlockStmt::Return(v));
            ctx.reconstructed += 1;
        }
        "Throw" => {
            let v: String = ctx.reg_expr(reg_of(ops.first()));
            stmts.push(BlockStmt::Throw(v));
            ctx.reconstructed += 1;
        }
        "Catch" => {
            let d: u32 = reg_of(ops.first());
            ctx.set_reg(d, "$exc".to_owned());
            stmts.push(BlockStmt::Line("/* catch ($exc) */".to_owned()));
            ctx.reconstructed += 1;
        }
        "Jmp" | "JmpLong" => {
            if let Some(OperandValue::Target(t)) = ops.first() {
                ctx.reconstructed += 1;
                stmts.push(BlockStmt::Jump(*t));
            }
        }
        "JmpTrue" | "JmpTrueLong" => {
            let cond: String = ctx.reg_expr(reg_of(ops.get(1)));
            push_cond_jump(ops, cond, inst, instructions, cfg, stmts);
            ctx.reconstructed += 1;
        }
        "JmpFalse" | "JmpFalseLong" => {
            let cond: String = format!("!{}", ctx.reg_expr(reg_of(ops.get(1))));
            push_cond_jump(ops, cond, inst, instructions, cfg, stmts);
            ctx.reconstructed += 1;
        }
        "JmpUndefined" | "JmpUndefinedLong" => {
            let cond: String = format!("{} === undefined", ctx.reg_expr(reg_of(ops.get(1))));
            push_cond_jump(ops, cond, inst, instructions, cfg, stmts);
            ctx.reconstructed += 1;
        }
        _ if jump_condition(name).is_some() => {
            let (sym, negate): (&'static str, bool) = jump_condition(name).unwrap_or(("==", false));
            let a: String = ctx.reg_expr(reg_of(ops.get(1)));
            let b: String = ctx.reg_expr(reg_of(ops.get(2)));
            let raw: String = format!("{a} {sym} {b}");
            let cond: String = if negate { format!("!({raw})") } else { raw };
            push_cond_jump(ops, cond, inst, instructions, cfg, stmts);
            ctx.reconstructed += 1;
        }
        _ => {
            stmts.push(BlockStmt::Line(format!("{};", fallback_disasm(inst))));
            ctx.fallback += 1;
        }
    }
}

fn push_cond_jump(
    ops: &[OperandValue],
    cond: String,
    inst: &Instruction,
    instructions: &[Instruction],
    cfg: &Cfg,
    stmts: &mut Vec<BlockStmt>,
) {
    let target: usize = match ops.first() {
        Some(OperandValue::Target(t)) => *t,
        _ => 0,
    };
    let next_off: Option<usize> = next_offset_after(inst, instructions);
    let fallthrough: Option<usize> =
        next_off.filter(|o: &usize| cfg.offset_to_block.contains_key(o));
    stmts.push(BlockStmt::CondJump {
        cond,
        target,
        fallthrough,
    });
}

#[must_use]
fn reg_read_later(d: u32, inst: &Instruction, instructions: &[Instruction]) -> bool {
    const WINDOW: usize = 64;
    let Some(pos): Option<usize> = instructions
        .iter()
        .position(|i: &Instruction| i.offset == inst.offset)
    else {
        return true;
    };
    let end: usize = (pos + 1 + WINDOW).min(instructions.len());
    for later in &instructions[pos + 1..end] {
        if inst_read_regs(later).contains(&d) {
            return true;
        }
        if inst_dest(later) == Some(d) {
            return false;
        }
    }
    false
}

#[must_use]
fn writes_first_operand(name: &str) -> bool {
    !(is_terminator(name)
        || name.starts_with("Put")
        || name.starts_with("Store")
        || name.starts_with("Def")
        || matches!(name, "Throw" | "Ret" | "Catch" | "Debugger"))
}

#[must_use]
fn next_offset_after(inst: &Instruction, instructions: &[Instruction]) -> Option<usize> {
    let end: usize = inst.offset + inst.size;
    instructions
        .iter()
        .find(|i: &&Instruction| i.offset == end)
        .map(|i: &Instruction| i.offset)
}

#[must_use]
fn call_window_registers(
    instructions: &[Instruction],
    call_index: usize,
    argc: u64,
) -> Option<Vec<u32>> {
    if argc == 0 {
        return Some(Vec::new());
    }
    let argc: usize = usize::try_from(argc).ok()?;
    let scan_start: usize = call_index.saturating_sub(64);
    let this_reg: u32 =
        instructions[scan_start..call_index]
            .iter()
            .rev()
            .find_map(|prior: &Instruction| match &*prior.name {
                "Mov" | "MovLong" => match prior.operands.first() {
                    Some(OperandValue::Reg(r)) => Some(*r),
                    _ => None,
                },
                _ => None,
            })?;
    if (this_reg as usize) < argc {
        return None;
    }
    let mut window: Vec<u32> = Vec::with_capacity(argc);
    for offset in 1..=argc {
        window.push(this_reg - offset as u32);
    }
    Some(window)
}

fn recover_call_arguments(
    ctx: &LiftCtx<'_>,
    inst: &Instruction,
    instructions: &[Instruction],
    argc: u64,
) -> Option<Vec<String>> {
    if argc == 0 {
        return Some(Vec::new());
    }
    let call_index: usize = instructions
        .iter()
        .position(|i: &Instruction| i.offset == inst.offset)?;
    let window: Vec<u32> = call_window_registers(instructions, call_index, argc)?;
    let args: Vec<String> = window.iter().map(|r: &u32| ctx.reg_expr(*r)).collect();
    if args
        .iter()
        .any(|a: &String| a.starts_with('r') && a[1..].chars().all(|c: char| c.is_ascii_digit()))
    {
        return None;
    }
    Some(args)
}

#[must_use]
fn call_window_consumed(instructions: &[Instruction]) -> BTreeSet<u32> {
    let mut consumed: BTreeSet<u32> = BTreeSet::new();
    for (i, inst) in instructions.iter().enumerate() {
        if !matches!(
            &*inst.name,
            "Call" | "CallLong" | "Construct" | "ConstructLong"
        ) {
            continue;
        }
        let argc: u64 = uint_of(inst.operands.get(2)).saturating_sub(1);
        if let Some(window) = call_window_registers(instructions, i, argc) {
            for r in window {
                consumed.insert(r);
            }
        }
    }
    consumed
}

fn emit_call_result(
    ctx: &mut LiftCtx<'_>,
    d: u32,
    call_expr: String,
    inst: &Instruction,
    instructions: &[Instruction],
    stmts: &mut Vec<BlockStmt>,
) {
    if ctx.is_materialized(d) {
        let stmt: String = ctx.materialize_assignment(d, &call_expr);
        stmts.push(BlockStmt::Line(stmt));
        return;
    }
    if reg_read_later(d, inst, instructions) || ctx.window_consumed.contains(&d) {
        ctx.set_reg(d, call_expr);
    } else {
        stmts.push(BlockStmt::Line(format!("{call_expr};")));
        ctx.set_reg(d, format!("r{d}"));
    }
}

#[must_use]
fn unrecovered_arg_list(argc: u64) -> String {
    if argc == 0 {
        return String::new();
    }
    let rendered: u64 = argc.min(MAX_RENDERED_CALL_ARGS);
    let mut out: String = String::with_capacity(rendered as usize * (UNRECOVERED_ARG.len() + 2));
    for i in 0..rendered {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(UNRECOVERED_ARG);
    }
    if argc > rendered {
        push_text!(out, ", /* +{} more */", argc - rendered);
    }
    out
}

#[must_use]
fn format_f64(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

#[must_use]
fn fallback_disasm(inst: &Instruction) -> String {
    let mut out: String = String::new();
    push_text!(out, "{}(", inst.name);
    for (i, op) in inst.operands.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        match op {
            OperandValue::Reg(r) => {
                push_text!(out, "r{r}");
            }
            OperandValue::UInt(u) => {
                push_text!(out, "{u}");
            }
            OperandValue::Imm(i) => {
                push_text!(out, "{i}");
            }
            OperandValue::Float(f) => {
                push_text!(out, "{}", f64::from_bits(*f));
            }
            OperandValue::Target(t) => {
                push_text!(out, "@{t}");
            }
            OperandValue::StringId(s) => {
                push_text!(out, "str#{s}");
            }
            OperandValue::FunctionId(f) => {
                push_text!(out, "fn#{f}");
            }
            OperandValue::BigIntId(b) => {
                push_text!(out, "bigint#{b}");
            }
        }
    }
    out.push(')');
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompiledFunction {
    pub index: usize,
    pub name: String,
    pub param_count: u32,
    pub frame_size: u32,
    pub bytecode_size: u32,
    pub instruction_count: usize,
    pub block_count: usize,
    pub reconstructed_ops: usize,
    pub fallback_ops: usize,
    pub has_if: bool,
    pub has_loop: bool,
    pub has_try_catch: bool,
    pub is_generator: bool,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompileReport {
    pub hermes_version: u32,
    pub function_count: usize,
    pub functions_with_body: usize,
    pub total_reconstructed_ops: usize,
    pub total_fallback_ops: usize,
    pub functions: Vec<DecompiledFunction>,
    pub regexps: Vec<super::regex::RecoveredRegExp>,
}

#[must_use]
pub fn disassemble_function_instructions(module: &HermesModule, index: usize) -> Vec<String> {
    let code: &[u8] = module.function_code(index);
    decode_instructions(code)
        .iter()
        .map(|i: &Instruction| format!("{:#06x}: {}", i.offset, fallback_disasm(i)))
        .collect()
}

#[must_use]
pub fn decompile_function(module: &HermesModule, index: usize) -> DecompiledFunction {
    let empty: BTreeMap<u32, String> = BTreeMap::new();
    decompile_function_inlined(module, index, &empty)
}

#[must_use]
fn decompile_function_inlined(
    module: &HermesModule,
    index: usize,
    inline_bodies: &BTreeMap<u32, String>,
) -> DecompiledFunction {
    let header: SmallFunctionHeader =
        module
            .functions
            .get(index)
            .copied()
            .unwrap_or(SmallFunctionHeader {
                offset: 0,
                param_count: 0,
                bytecode_size_bytes: 0,
                function_name_id: 0,
                info_offset: 0,
                frame_size: 0,
                env_size: 0,
                highest_read_cache_index: 0,
                highest_write_cache_index: 0,
                prohibit_invoke: 0,
                strict_mode: false,
                has_exception_handler: false,
                has_debug_info: false,
                overflowed: false,
            });
    let name: String = module
        .string_by_global_id(header.function_name_id)
        .filter(|s: &&str| !s.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("$func{index}"));
    let code: &[u8] = module.function_code(index);
    let instructions: Vec<Instruction> = decode_instructions(code);
    let cfg: Cfg = build_cfg(&instructions);

    let window_consumed: BTreeSet<u32> = call_window_consumed(&instructions);
    let materialized: BTreeSet<u32> = compute_materialized(&instructions);
    let mut ctx: LiftCtx<'_> =
        LiftCtx::new(module, code, materialized, window_consumed, inline_bodies);
    let lifted: Vec<LiftedBlock> = cfg
        .blocks
        .iter()
        .map(|b: &BasicBlock| lift_block(&mut ctx, &instructions, b, &cfg))
        .collect();

    let body: String = render_structured(&lifted, &cfg, &instructions);
    let has_loop: bool = cfg_has_back_edge(&cfg);
    let has_if: bool = lifted
        .iter()
        .flat_map(|b: &LiftedBlock| b.stmts.iter())
        .any(|s: &BlockStmt| matches!(s, BlockStmt::CondJump { .. }));
    let has_try_catch: bool = header.has_exception_handler
        || instructions.iter().any(|i: &Instruction| i.name == "Catch");
    let is_generator: bool = instructions.iter().any(|i: &Instruction| {
        matches!(
            &*i.name,
            "StartGenerator"
                | "SaveGenerator"
                | "SaveGeneratorLong"
                | "ResumeGenerator"
                | "CompleteGenerator"
        )
    });

    let params: Vec<String> = (0..header.param_count.saturating_sub(1))
        .map(|p: u32| format!("arg{p}"))
        .collect();
    let strict: &str = if header.strict_mode {
        "\n  \"use strict\";"
    } else {
        ""
    };
    let fn_keyword: &str = if is_generator {
        "function*"
    } else {
        "function"
    };
    let source: String = format!(
        "{fn_keyword} {name}({}) {{{strict}\n{body}}}",
        params.join(", ")
    );

    DecompiledFunction {
        index,
        name,
        param_count: header.param_count,
        frame_size: header.frame_size,
        bytecode_size: header.bytecode_size_bytes,
        instruction_count: instructions.len(),
        block_count: cfg.blocks.len(),
        reconstructed_ops: ctx.reconstructed,
        fallback_ops: ctx.fallback,
        has_if,
        has_loop,
        has_try_catch,
        is_generator,
        source,
    }
}

#[must_use]
fn cfg_has_back_edge(cfg: &Cfg) -> bool {
    cfg.blocks
        .iter()
        .enumerate()
        .any(|(i, b): (usize, &BasicBlock)| b.successors.iter().any(|s: &usize| *s <= i))
}

#[must_use]
fn is_value_producer(name: &str) -> bool {
    writes_first_operand(name)
        && !is_call_like(name)
        && name != "Mov"
        && name != "MovLong"
        && !name.starts_with("Jmp")
}

#[must_use]
fn is_call_like(name: &str) -> bool {
    matches!(
        name,
        "Call"
            | "CallLong"
            | "Construct"
            | "ConstructLong"
            | "Call1"
            | "Call2"
            | "Call3"
            | "Call4"
            | "CallBuiltin"
            | "CallBuiltinLong"
            | "CallDirect"
            | "CallDirectLongIndex"
    )
}

#[must_use]
fn inst_dest(inst: &Instruction) -> Option<u32> {
    if !writes_first_operand(&inst.name) {
        return None;
    }
    match inst.operands.first() {
        Some(OperandValue::Reg(r)) => Some(*r),
        _ => None,
    }
}

fn inst_read_regs(inst: &Instruction) -> Vec<u32> {
    let writes_dest: bool = writes_first_operand(&inst.name);
    inst.operands
        .iter()
        .enumerate()
        .filter_map(|(i, o): (usize, &OperandValue)| match o {
            OperandValue::Reg(r) if !(i == 0 && writes_dest) => Some(*r),
            _ => None,
        })
        .collect()
}

#[must_use]
fn back_edge_regions(instructions: &[Instruction]) -> Vec<(usize, usize)> {
    let mut regions: Vec<(usize, usize)> = Vec::new();
    let offset_to_index: BTreeMap<usize, usize> = instructions
        .iter()
        .enumerate()
        .map(|(i, inst): (usize, &Instruction)| (inst.offset, i))
        .collect();
    for (li, inst) in instructions.iter().enumerate() {
        if !is_terminator(&inst.name) {
            continue;
        }
        for t in instruction_targets(inst) {
            if t <= inst.offset
                && let Some(hi) = offset_to_index.get(&t)
            {
                regions.push((*hi, li));
            }
        }
    }
    regions
}

#[must_use]
fn compute_materialized(instructions: &[Instruction]) -> BTreeSet<u32> {
    let mut materialized: BTreeSet<u32> = BTreeSet::new();

    for (header, latch) in back_edge_regions(instructions) {
        let region: &[Instruction] = &instructions[header..=latch];
        let mut written: BTreeSet<u32> = BTreeSet::new();
        let mut read: BTreeSet<u32> = BTreeSet::new();
        for inst in region {
            if let Some(d) = inst_dest(inst) {
                written.insert(d);
            }
            for r in inst_read_regs(inst) {
                read.insert(r);
            }
        }
        for r in &written {
            if read.contains(r) {
                materialized.insert(*r);
            }
        }
    }

    for (i, inst) in instructions.iter().enumerate() {
        if !is_call_like(&inst.name) {
            continue;
        }
        let Some(d): Option<u32> = inst_dest(inst) else {
            continue;
        };
        let is_construct: bool = matches!(&*inst.name, "Construct" | "ConstructLong");
        let mut read_count: usize = 0;
        for later in &instructions[i + 1..] {
            if inst_read_regs(later).contains(&d) {
                read_count += 1;
            }
            let redefined: bool = inst_dest(later) == Some(d);
            let passthrough: bool = matches!(&*later.name, "SelectObject" | "Mov" | "MovLong")
                && inst_read_regs(later).contains(&d);
            if redefined && !passthrough {
                break;
            }
        }
        let threshold: usize = if is_construct { 1 } else { 2 };
        if read_count >= threshold {
            materialized.insert(d);
        }
    }

    materialized
}

#[must_use]
fn negate_cond(cond: &str) -> String {
    if let Some(inner) = cond.strip_prefix("!(")
        && let Some(inner) = inner.strip_suffix(')')
        && is_balanced(inner)
    {
        return inner.to_owned();
    }
    format!("!({cond})")
}

#[must_use]
fn is_balanced(s: &str) -> bool {
    let mut depth: i32 = 0;
    for c in s.chars() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0
}

struct SingleLoop {
    header: usize,
    latch: usize,
    enter_cond: String,
    continue_cond: String,
    exit: usize,
}

#[must_use]
fn detect_single_loop(lifted: &[LiftedBlock], cfg: &Cfg) -> Option<SingleLoop> {
    let mut back_edges: Vec<(usize, usize)> = Vec::new();
    for (bi, block) in cfg.blocks.iter().enumerate() {
        for succ in &block.successors {
            if *succ <= bi {
                back_edges.push((*succ, bi));
            }
        }
    }
    let [(header, latch)]: [(usize, usize); 1] = back_edges.as_slice().try_into().ok()?;
    if header == 0 {
        return None;
    }

    let preheader: usize = header - 1;
    let (pre_cond, pre_target, pre_fallthrough): (&String, usize, usize) =
        match lifted.get(preheader)?.stmts.last()? {
            BlockStmt::CondJump {
                cond,
                target,
                fallthrough: Some(ft),
            } => (
                cond,
                *cfg.offset_to_block.get(target)?,
                *cfg.offset_to_block.get(ft)?,
            ),
            _ => return None,
        };
    let (latch_cond, latch_target, latch_fallthrough): (&String, usize, usize) =
        match lifted.get(latch)?.stmts.last()? {
            BlockStmt::CondJump {
                cond,
                target,
                fallthrough: Some(ft),
            } => (
                cond,
                *cfg.offset_to_block.get(target)?,
                *cfg.offset_to_block.get(ft)?,
            ),
            _ => return None,
        };

    let enter_cond: String = if pre_fallthrough == header {
        negate_cond(pre_cond)
    } else if pre_target == header {
        pre_cond.clone()
    } else {
        return None;
    };
    let pre_exit: usize = if pre_fallthrough == header {
        pre_target
    } else {
        pre_fallthrough
    };

    let continue_cond: String = if latch_target == header {
        latch_cond.clone()
    } else if latch_fallthrough == header {
        negate_cond(latch_cond)
    } else {
        return None;
    };
    let latch_exit: usize = if latch_target == header {
        latch_fallthrough
    } else {
        latch_target
    };

    if pre_exit != latch_exit || pre_exit <= latch {
        return None;
    }
    for body in header..=latch {
        for (bi, block) in cfg.blocks.iter().enumerate() {
            if (bi < header || bi > latch)
                && bi != preheader
                && block.successors.contains(&body)
                && body == header
            {
                return None;
            }
        }
    }

    Some(SingleLoop {
        header,
        latch,
        enter_cond,
        continue_cond,
        exit: pre_exit,
    })
}

#[must_use]
fn render_structured(lifted: &[LiftedBlock], cfg: &Cfg, _instructions: &[Instruction]) -> String {
    let block_index: BTreeMap<usize, usize> = lifted
        .iter()
        .enumerate()
        .map(|(i, b): (usize, &LiftedBlock)| (b.start, i))
        .collect();
    if let Some(loop_info) = detect_single_loop(lifted, cfg)
        && let Some(rendered) = render_with_loop(lifted, &block_index, &loop_info)
    {
        return rendered;
    }
    let mut out: String = String::new();
    for (bi, block) in lifted.iter().enumerate() {
        if out.len() >= MAX_RENDER_BYTES {
            let omitted: usize = lifted.len() - bi;
            push_line!(out, "  /* ... {omitted} blocks omitted */");
            break;
        }
        let is_loop_head: bool = cfg
            .blocks
            .iter()
            .enumerate()
            .any(|(j, b): (usize, &BasicBlock)| j >= bi && b.successors.contains(&bi));
        if is_loop_head && block.stmts.len() > 1 {
            push_line!(out, "  L{bi}: for (;;) {{");
            render_block_stmts(&mut out, block, &block_index, "    ");
            push_line!(out, "  }}");
        } else {
            if cfg.blocks.len() > 1 {
                push_line!(out, "  // L{bi} @ {:#06x}", block.start);
            }
            render_block_stmts(&mut out, block, &block_index, "  ");
        }
    }
    out
}

#[must_use]
fn render_with_loop(
    lifted: &[LiftedBlock],
    block_index: &BTreeMap<usize, usize>,
    loop_info: &SingleLoop,
) -> Option<String> {
    let mut out: String = String::new();
    let preheader: usize = loop_info.header.checked_sub(1)?;

    for block in &lifted[..preheader] {
        render_block_stmts(&mut out, block, block_index, "  ");
    }

    let pre_block: &LiftedBlock = lifted.get(preheader)?;
    render_block_body(&mut out, pre_block, block_index, "  ", true);

    push_line!(out, "  if ({}) {{", loop_info.enter_cond);
    push_line!(out, "    do {{");
    for bi in loop_info.header..=loop_info.latch {
        let body_block: &LiftedBlock = lifted.get(bi)?;
        let drop_terminator: bool = bi == loop_info.latch;
        render_block_body(&mut out, body_block, block_index, "      ", drop_terminator);
    }
    push_line!(out, "    }} while ({});", loop_info.continue_cond);
    push_line!(out, "  }}");

    for block in &lifted[loop_info.exit..] {
        render_block_stmts(&mut out, block, block_index, "  ");
    }
    Some(out)
}

fn render_block_body(
    out: &mut String,
    block: &LiftedBlock,
    block_index: &BTreeMap<usize, usize>,
    indent: &str,
    drop_trailing_condjump: bool,
) {
    let limit: usize = if drop_trailing_condjump
        && matches!(block.stmts.last(), Some(BlockStmt::CondJump { .. }))
    {
        block.stmts.len() - 1
    } else {
        block.stmts.len()
    };
    let trimmed: LiftedBlock = LiftedBlock {
        start: block.start,
        stmts: block.stmts[..limit].to_vec(),
    };
    render_block_stmts(out, &trimmed, block_index, indent);
}

fn render_block_stmts(
    mut out: &mut String,
    block: &LiftedBlock,
    block_index: &BTreeMap<usize, usize>,
    indent: &str,
) {
    for (si, stmt) in block.stmts.iter().enumerate() {
        if out.len() >= MAX_RENDER_BYTES {
            let omitted: usize = block.stmts.len() - si;
            push_line!(out, "{indent}/* ... {omitted} ops omitted */");
            break;
        }
        match stmt {
            BlockStmt::Line(s) => {
                push_line!(out, "{indent}{s}");
            }
            BlockStmt::Return(v) => {
                if v == "undefined" {
                    push_line!(out, "{indent}return;");
                } else {
                    push_line!(out, "{indent}return {v};");
                }
            }
            BlockStmt::Throw(v) => {
                push_line!(out, "{indent}throw {v};");
            }
            BlockStmt::Jump(t) => {
                let label: String = block_index
                    .get(t)
                    .map_or_else(|| format!("@{t:#06x}"), |b: &usize| format!("L{b}"));
                push_line!(out, "{indent}// goto {label}");
            }
            BlockStmt::CondJump {
                cond,
                target,
                fallthrough,
            } => {
                let tlabel: String = block_index
                    .get(target)
                    .map_or_else(|| format!("@{target:#06x}"), |b: &usize| format!("L{b}"));
                let flabel: String = fallthrough
                    .and_then(|f: usize| block_index.get(&f))
                    .map_or_else(String::new, |b: &usize| format!(" else goto L{b};"));
                push_line!(out, "{indent}if ({cond}) goto {tlabel};{flabel}");
            }
            BlockStmt::Switch {
                scrutinee,
                cases,
                default,
            } => {
                push_line!(out, "{indent}switch ({scrutinee}) {{");
                for (value, target) in cases {
                    let tlabel: String = block_index
                        .get(target)
                        .map_or_else(|| format!("@{target:#06x}"), |b: &usize| format!("L{b}"));
                    push_line!(out, "{indent}  case {value}: goto {tlabel};");
                }
                let dlabel: String = block_index
                    .get(default)
                    .map_or_else(|| format!("@{default:#06x}"), |b: &usize| format!("L{b}"));
                push_line!(out, "{indent}  default: goto {dlabel};");
                push_line!(out, "{indent}}}");
            }
        }
    }
}

#[must_use]
fn closure_targets(module: &HermesModule, index: usize) -> Vec<u32> {
    let code: &[u8] = module.function_code(index);
    let mut targets: Vec<u32> = Vec::new();
    for inst in decode_instructions(code) {
        if !inst.name.starts_with("Create") || !inst.name.contains("Closure") {
            continue;
        }
        if let Some(OperandValue::FunctionId(fid)) = inst.operands.get(2) {
            targets.push(*fid);
        }
    }
    targets
}

fn inlined_closure_bodies(
    module: &HermesModule,
    index: usize,
    visiting: &mut BTreeSet<usize>,
    cache: &mut BTreeMap<usize, String>,
    depth: usize,
) -> BTreeMap<u32, String> {
    let mut bodies: BTreeMap<u32, String> = BTreeMap::new();
    if depth >= MAX_INLINE_CLOSURE_DEPTH {
        return bodies;
    }
    for fid in closure_targets(module, index) {
        let Some(child): Option<usize> = usize::try_from(fid).ok() else {
            continue;
        };
        if child >= module.functions.len() || child == index || visiting.contains(&child) {
            continue;
        }
        let source: String = inlined_source(module, child, visiting, cache, depth + 1);
        bodies.insert(fid, source);
    }
    bodies
}

fn inlined_source(
    module: &HermesModule,
    index: usize,
    visiting: &mut BTreeSet<usize>,
    cache: &mut BTreeMap<usize, String>,
    depth: usize,
) -> String {
    if let Some(cached) = cache.get(&index) {
        return cached.clone();
    }
    visiting.insert(index);
    let child_bodies: BTreeMap<u32, String> =
        inlined_closure_bodies(module, index, visiting, cache, depth);
    let decompiled: DecompiledFunction = decompile_function_inlined(module, index, &child_bodies);
    visiting.remove(&index);
    cache.insert(index, decompiled.source.clone());
    decompiled.source
}

#[must_use]
pub fn decompile_module(module: &HermesModule) -> DecompileReport {
    let mut functions: Vec<DecompiledFunction> = Vec::with_capacity(module.functions.len());
    let mut total_reconstructed: usize = 0;
    let mut total_fallback: usize = 0;
    let mut with_body: usize = 0;
    let mut cache: BTreeMap<usize, String> = BTreeMap::new();
    for i in 0..module.functions.len() {
        let mut visiting: BTreeSet<usize> = BTreeSet::new();
        visiting.insert(i);
        let child_bodies: BTreeMap<u32, String> =
            inlined_closure_bodies(module, i, &mut visiting, &mut cache, 0);
        let f: DecompiledFunction = decompile_function_inlined(module, i, &child_bodies);
        total_reconstructed += f.reconstructed_ops;
        total_fallback += f.fallback_ops;
        if f.instruction_count > 0 {
            with_body += 1;
        }
        functions.push(f);
    }
    let regexps: Vec<super::regex::RecoveredRegExp> =
        super::regex::recover_regexps(&module.reg_exp_table, &module.reg_exp_storage);
    DecompileReport {
        hermes_version: module.header.version,
        function_count: module.functions.len(),
        functions_with_body: with_body,
        total_reconstructed_ops: total_reconstructed,
        total_fallback_ops: total_fallback,
        functions,
        regexps,
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::vec_init_then_push
)]
mod tests {
    use super::*;
    use crate::hermes::{HERMES_MAGIC, HermesHeader, HermesStringKind};

    fn opcode_byte(name: &str) -> u8 {
        OPCODES
            .iter()
            .position(|s: &OpcodeSpec| s.name == name)
            .map(|p: usize| p as u8)
            .unwrap_or_else(|| panic!("opcode {name} not found"))
    }

    fn module_with(
        idents: &[&str],
        strings: &[&str],
        code: Vec<u8>,
        param_count: u32,
    ) -> HermesModule {
        let header: HermesHeader = HermesHeader {
            version: 96,
            source_hash: [0u8; 20],
            file_length: 0,
            global_code_index: 0,
            function_count: 1,
            string_kind_count: 2,
            identifier_count: idents.len() as u32,
            string_count: (idents.len() + strings.len()) as u32,
            overflow_string_count: 0,
            string_storage_size: 0,
            big_int_count: 0,
            big_int_storage_size: 0,
            reg_exp_count: 0,
            reg_exp_storage_size: 0,
            array_buffer_size: 0,
            obj_key_buffer_size: 0,
            obj_value_buffer_size: 0,
            segment_id: 0,
            cjs_module_count: 0,
            function_source_count: 0,
            debug_info_offset: 0,
            flags: 0,
        };
        let func: SmallFunctionHeader = SmallFunctionHeader {
            offset: 0,
            param_count,
            bytecode_size_bytes: code.len() as u32,
            function_name_id: 0,
            info_offset: 0,
            frame_size: 16,
            env_size: 0,
            highest_read_cache_index: 0,
            highest_write_cache_index: 0,
            prohibit_invoke: 0,
            strict_mode: false,
            has_exception_handler: false,
            has_debug_info: false,
            overflowed: false,
        };
        let _ = HERMES_MAGIC;
        HermesModule {
            header,
            functions: vec![func],
            identifiers: idents.iter().map(|s: &&str| (*s).to_owned()).collect(),
            strings: strings.iter().map(|s: &&str| (*s).to_owned()).collect(),
            string_kinds: vec![HermesStringKind::Identifier, HermesStringKind::String],
            overflow_resolved: 0,
            utf16_strings: 0,
            raw_bytecode_size: code.len(),
            array_buffer: Vec::new(),
            obj_key_buffer: Vec::new(),
            obj_value_buffer: Vec::new(),
            big_int_table: Vec::new(),
            big_int_storage: Vec::new(),
            reg_exp_table: Vec::new(),
            reg_exp_storage: Vec::new(),
            raw_image: code,
        }
    }

    #[test]
    fn opcode_table_anchors() {
        assert_eq!(OPCODES[0].name, "Unreachable");
        assert_eq!(opcode_byte("Add"), 22);
        assert_eq!(opcode_byte("Ret"), 92);
        assert_eq!(opcode_byte("LoadParam"), 108);
        assert_eq!(opcode_byte("GetByIdShort"), 54);
        assert_eq!(opcode_byte("Jmp"), 142);
        assert_eq!(opcode_byte("JStrictNotEqualLong"), 191);
        assert_eq!(OPCODES.len(), 192);
    }

    #[test]
    fn decompile_add_function() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("LoadParam"));
        code.extend_from_slice(&[1u8, 1u8]);
        code.push(opcode_byte("LoadParam"));
        code.extend_from_slice(&[2u8, 2u8]);
        code.push(opcode_byte("Add"));
        code.extend_from_slice(&[0u8, 1u8, 2u8]);
        code.push(opcode_byte("Ret"));
        code.push(0u8);
        let module: HermesModule = module_with(&["add"], &[], code, 3);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert_eq!(f.name, "add");
        assert_eq!(f.fallback_ops, 0);
        assert!(
            f.source.contains("function add(arg0, arg1)"),
            "src: {}",
            f.source
        );
        assert!(
            f.source.contains("return (arg0 + arg1);"),
            "src: {}",
            f.source
        );
    }

    #[test]
    fn decompile_member_call() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("GetGlobalObject"));
        code.push(0u8);
        code.push(opcode_byte("GetByIdShort"));
        code.extend_from_slice(&[1u8, 0u8, 0u8, 2u8]);
        code.push(opcode_byte("LoadConstString"));
        code.extend_from_slice(&[3u8, 0u8, 0u8]);
        code.push(opcode_byte("Call1"));
        code.extend_from_slice(&[3u8, 1u8, 2u8]);
        code.push(opcode_byte("Ret"));
        code.push(3u8);
        let module: HermesModule = module_with(&["main"], &["console", "log", "hi"], code, 1);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(f.source.contains("globalThis.log"), "src: {}", f.source);
        assert_eq!(f.fallback_ops, 0, "src: {}", f.source);
    }

    #[test]
    fn decompile_conditional_branch() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("LoadParam"));
        code.extend_from_slice(&[1u8, 1u8]);
        code.push(opcode_byte("LoadConstZero"));
        code.push(2u8);
        let jbase: usize = code.len();
        code.push(opcode_byte("JNotLess"));
        let after_target: i8 = 6;
        code.push(after_target as u8);
        code.extend_from_slice(&[1u8, 2u8]);
        code.push(opcode_byte("Ret"));
        code.push(1u8);
        code.push(opcode_byte("Ret"));
        code.push(2u8);
        let _ = jbase;
        let module: HermesModule = module_with(&["cmp"], &[], code, 2);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(f.has_if, "expected if; src: {}", f.source);
        assert!(f.block_count >= 2, "blocks: {}", f.block_count);
        assert!(f.source.contains("if ("), "src: {}", f.source);
    }

    #[test]
    fn unknown_opcode_falls_back() {
        let code: Vec<u8> = vec![0xfeu8, 0xffu8];
        let module: HermesModule = module_with(&["weird"], &[], code, 1);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(f.source.contains("Unknown_0x"), "src: {}", f.source);
        assert!(f.fallback_ops >= 1);
    }

    #[test]
    fn cfg_splits_on_jump() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("Jmp"));
        code.push(2u8);
        code.push(opcode_byte("LoadConstNull"));
        code.push(0u8);
        code.push(opcode_byte("Ret"));
        code.push(0u8);
        let instructions: Vec<Instruction> = decode_instructions(&code);
        let cfg: Cfg = build_cfg(&instructions);
        assert!(cfg.blocks.len() >= 2, "blocks: {}", cfg.blocks.len());
    }

    #[test]
    fn calllong_with_huge_argc_is_bounded() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("GetGlobalObject"));
        code.push(0u8);
        code.push(opcode_byte("CallLong"));
        code.push(1u8);
        code.push(0u8);
        code.extend_from_slice(&u32::MAX.to_le_bytes());
        code.push(opcode_byte("Ret"));
        code.push(1u8);
        let module: HermesModule = module_with(&["main"], &[], code, 1);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(
            f.source.len() < 8192,
            "huge argc must not balloon source, got {} bytes",
            f.source.len()
        );
        assert!(
            f.source.contains("more */"),
            "expected truncation marker; src: {}",
            f.source
        );
        assert!(
            !f.source.contains("a0"),
            "huge argc must not fabricate arg names; src: {}",
            f.source
        );
    }

    #[test]
    fn constructlong_with_huge_argc_is_bounded() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("GetGlobalObject"));
        code.push(0u8);
        code.push(opcode_byte("ConstructLong"));
        code.push(1u8);
        code.push(0u8);
        code.extend_from_slice(&(u32::MAX - 1).to_le_bytes());
        code.push(opcode_byte("Ret"));
        code.push(1u8);
        let module: HermesModule = module_with(&["main"], &[], code, 1);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(f.source.len() < 8192, "src bytes: {}", f.source.len());
        assert!(f.source.contains("new "), "src: {}", f.source);
    }

    #[test]
    fn truncated_operand_stream_terminates() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("CallLong"));
        code.push(1u8);
        let instructions: Vec<Instruction> = decode_instructions(&code);
        assert_eq!(instructions.len(), 1);
        assert!(instructions[0].name.ends_with("<truncated>"));
    }

    #[test]
    fn unknown_opcode_run_decodes_in_bounded_time() {
        let code: Vec<u8> = vec![0xffu8; 100_000];
        let instructions: Vec<Instruction> = decode_instructions(&code);
        assert_eq!(instructions.len(), 100_000);
        let module: HermesModule = module_with(&["x"], &[], code, 1);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert_eq!(f.fallback_ops, 100_000);
    }

    #[test]
    fn negative_jump_target_wraps_without_panic() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("Jmp"));
        code.push(0x80u8);
        code.push(opcode_byte("Ret"));
        code.push(0u8);
        let instructions: Vec<Instruction> = decode_instructions(&code);
        let target: usize = match instructions[0].operands.first() {
            Some(OperandValue::Target(t)) => *t,
            other => panic!("expected target operand, got {other:?}"),
        };
        assert_eq!(target, 0);
        let cfg: Cfg = build_cfg(&instructions);
        assert!(!cfg.blocks.is_empty());
    }

    #[test]
    fn relative_target_saturates_at_bounds() {
        assert_eq!(relative_target(3, -8), 0);
        assert_eq!(relative_target(usize::MAX - 2, 8), usize::MAX);
    }

    fn module_with_buffers(
        idents: &[&str],
        strings: &[&str],
        code: Vec<u8>,
        param_count: u32,
        key_buffer: Vec<u8>,
        value_buffer: Vec<u8>,
        array_buffer: Vec<u8>,
    ) -> HermesModule {
        let mut module: HermesModule = module_with(idents, strings, code, param_count);
        module.obj_key_buffer = key_buffer;
        module.obj_value_buffer = value_buffer;
        module.array_buffer = array_buffer;
        module
    }

    #[test]
    fn decompile_object_literal_from_buffers() {
        let mut key_buffer: Vec<u8> = Vec::new();
        key_buffer.push(0x50 | 2);
        key_buffer.extend_from_slice(&1u16.to_le_bytes());
        key_buffer.extend_from_slice(&2u16.to_le_bytes());
        let mut value_buffer: Vec<u8> = Vec::new();
        value_buffer.push(0x70 | 1);
        value_buffer.extend_from_slice(&42i32.to_le_bytes());
        value_buffer.push(0x10 | 1);

        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("NewObjectWithBuffer"));
        code.push(0u8);
        code.extend_from_slice(&2u16.to_le_bytes());
        code.extend_from_slice(&2u16.to_le_bytes());
        code.extend_from_slice(&0u16.to_le_bytes());
        code.extend_from_slice(&0u16.to_le_bytes());
        code.push(opcode_byte("Ret"));
        code.push(0u8);

        let module: HermesModule = module_with_buffers(
            &["build", "count", "enabled"],
            &[],
            code,
            1,
            key_buffer,
            value_buffer,
            Vec::new(),
        );
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(
            f.source.contains("{ count: 42, enabled: true }"),
            "expected object literal; src: {}",
            f.source
        );
        assert_eq!(f.fallback_ops, 0, "src: {}", f.source);
    }

    #[test]
    fn decompile_array_literal_from_buffer() {
        let mut array_buffer: Vec<u8> = Vec::new();
        array_buffer.push(0x70 | 3);
        array_buffer.extend_from_slice(&1i32.to_le_bytes());
        array_buffer.extend_from_slice(&2i32.to_le_bytes());
        array_buffer.extend_from_slice(&3i32.to_le_bytes());

        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("NewArrayWithBuffer"));
        code.push(0u8);
        code.extend_from_slice(&3u16.to_le_bytes());
        code.extend_from_slice(&3u16.to_le_bytes());
        code.extend_from_slice(&0u16.to_le_bytes());
        code.push(opcode_byte("Ret"));
        code.push(0u8);

        let module: HermesModule = module_with_buffers(
            &["build"],
            &[],
            code,
            1,
            Vec::new(),
            Vec::new(),
            array_buffer,
        );
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(
            f.source.contains("[1, 2, 3]"),
            "expected array literal; src: {}",
            f.source
        );
        assert_eq!(f.fallback_ops, 0, "src: {}", f.source);
    }

    #[test]
    fn object_literal_quotes_non_identifier_keys() {
        let mut key_buffer: Vec<u8> = Vec::new();
        key_buffer.push(0x50 | 1);
        key_buffer.extend_from_slice(&0u16.to_le_bytes());
        let mut value_buffer: Vec<u8> = Vec::new();
        value_buffer.push(0x70 | 1);
        value_buffer.extend_from_slice(&1i32.to_le_bytes());

        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("NewObjectWithBuffer"));
        code.push(0u8);
        code.extend_from_slice(&1u16.to_le_bytes());
        code.extend_from_slice(&1u16.to_le_bytes());
        code.extend_from_slice(&0u16.to_le_bytes());
        code.extend_from_slice(&0u16.to_le_bytes());
        code.push(opcode_byte("Ret"));
        code.push(0u8);

        let module: HermesModule = module_with_buffers(
            &["data-id"],
            &[],
            code,
            1,
            key_buffer,
            value_buffer,
            Vec::new(),
        );
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(
            f.source.contains("\"data-id\": 1"),
            "expected quoted key; src: {}",
            f.source
        );
    }

    #[test]
    fn buffer_literal_capacity_ignores_oversized_raw_count() {
        let mut key_buffer: Vec<u8> = Vec::new();
        key_buffer.push(0x50 | 1);
        key_buffer.extend_from_slice(&0u16.to_le_bytes());
        let mut value_buffer: Vec<u8> = Vec::new();
        value_buffer.push(0x70 | 1);
        value_buffer.extend_from_slice(&7i32.to_le_bytes());
        let mut array_buffer: Vec<u8> = Vec::new();
        array_buffer.push(0x70 | 1);
        array_buffer.extend_from_slice(&7i32.to_le_bytes());

        let module: HermesModule = module_with_buffers(
            &["a"],
            &[],
            Vec::new(),
            1,
            key_buffer,
            value_buffer,
            array_buffer,
        );
        let code: Vec<u8> = Vec::new();
        let no_inline: BTreeMap<u32, String> = BTreeMap::new();
        let ctx: LiftCtx<'_> =
            LiftCtx::new(&module, &code, BTreeSet::new(), BTreeSet::new(), &no_inline);

        let bomb_count: usize = u32::MAX as usize;
        let obj: String = ctx.object_literal(bomb_count, 0, 0);
        assert_eq!(obj, "{ a: 7 }", "decoded output unchanged by raw count");
        assert!(
            obj.capacity() <= 64,
            "object capacity must follow decoded keys.len(), not raw count: {}",
            obj.capacity()
        );

        let arr: String = ctx.array_literal(bomb_count, 0);
        assert_eq!(arr, "[7]", "decoded output unchanged by raw count");
        assert!(
            arr.capacity() <= 64,
            "array capacity must follow decoded vals.len(), not raw count: {}",
            arr.capacity()
        );

        let empty: HermesModule = module_with_buffers(
            &["a"],
            &[],
            Vec::new(),
            1,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let empty_ctx: LiftCtx<'_> =
            LiftCtx::new(&empty, &code, BTreeSet::new(), BTreeSet::new(), &no_inline);
        assert_eq!(empty_ctx.object_literal(bomb_count, 0, 0), "{}");
        assert_eq!(empty_ctx.array_literal(bomb_count, 0), "[]");
    }

    #[test]
    fn decompile_create_regexp_exact_pattern() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("CreateRegExp"));
        code.push(0u8);
        code.extend_from_slice(&0u32.to_le_bytes());
        code.extend_from_slice(&1u32.to_le_bytes());
        code.extend_from_slice(&0u32.to_le_bytes());
        code.push(opcode_byte("Ret"));
        code.push(0u8);
        let module: HermesModule = module_with(&[], &["\\d+[a-z]*", "gi"], code, 1);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(
            f.source.contains("/\\d+[a-z]*/gi"),
            "expected exact regex literal; src: {}",
            f.source
        );
        assert_eq!(f.fallback_ops, 0, "src: {}", f.source);
    }

    #[test]
    fn decompile_callbuiltin_resolves_native_name() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("CallBuiltin"));
        code.push(0u8);
        code.push(34u8);
        code.push(2u8);
        code.push(opcode_byte("Ret"));
        code.push(0u8);
        let module: HermesModule = module_with(&[], &[], code, 1);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(
            f.source.contains("Object.keys("),
            "expected Object.keys; src: {}",
            f.source
        );
        assert_eq!(f.fallback_ops, 0, "src: {}", f.source);
    }

    #[test]
    fn decompile_callbuiltin_template_object_marks_template_literal() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("CallBuiltin"));
        code.push(0u8);
        code.push(39u8);
        code.push(2u8);
        code.push(opcode_byte("Ret"));
        code.push(0u8);
        let module: HermesModule = module_with(&[], &[], code, 1);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(
            f.source.contains("template"),
            "expected template literal marker; src: {}",
            f.source
        );
    }

    #[test]
    fn decompile_environment_capture() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("CreateEnvironment"));
        code.push(0u8);
        code.push(opcode_byte("LoadConstUInt8"));
        code.extend_from_slice(&[1u8, 42u8]);
        code.push(opcode_byte("StoreToEnvironment"));
        code.extend_from_slice(&[0u8, 3u8, 1u8]);
        code.push(opcode_byte("LoadFromEnvironment"));
        code.extend_from_slice(&[2u8, 0u8, 3u8]);
        code.push(opcode_byte("Ret"));
        code.push(2u8);
        let module: HermesModule = module_with(&["outer"], &[], code, 1);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(
            f.source.contains("cvar3 = 42;"),
            "expected captured-var store; src: {}",
            f.source
        );
        assert!(
            f.source.contains("return cvar3;"),
            "expected captured-var load; src: {}",
            f.source
        );
        assert_eq!(f.fallback_ops, 0, "src: {}", f.source);
    }

    #[test]
    fn decompile_environment_scope_levels() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("GetEnvironment"));
        code.extend_from_slice(&[0u8, 2u8]);
        code.push(opcode_byte("LoadFromEnvironment"));
        code.extend_from_slice(&[1u8, 0u8, 5u8]);
        code.push(opcode_byte("Ret"));
        code.push(1u8);
        let module: HermesModule = module_with(&["f"], &[], code, 1);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(
            f.source.contains("return cvar2_5;"),
            "expected level-2 captured var; src: {}",
            f.source
        );
        assert_eq!(f.fallback_ops, 0, "src: {}", f.source);
    }

    #[test]
    fn decompile_iterator_for_of() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("LoadParam"));
        code.extend_from_slice(&[1u8, 1u8]);
        code.push(opcode_byte("IteratorBegin"));
        code.extend_from_slice(&[2u8, 1u8]);
        code.push(opcode_byte("IteratorNext"));
        code.extend_from_slice(&[3u8, 2u8, 1u8]);
        code.push(opcode_byte("Ret"));
        code.push(3u8);
        let module: HermesModule = module_with(&["iter"], &[], code, 2);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(
            f.source.contains("arg0[Symbol.iterator]().next().value"),
            "expected iterator protocol; src: {}",
            f.source
        );
        assert_eq!(f.fallback_ops, 0, "src: {}", f.source);
    }

    #[test]
    fn decompile_for_in_pname() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("LoadParam"));
        code.extend_from_slice(&[1u8, 1u8]);
        code.push(opcode_byte("GetPNameList"));
        code.extend_from_slice(&[2u8, 1u8, 3u8, 4u8]);
        code.push(opcode_byte("GetNextPName"));
        code.extend_from_slice(&[5u8, 2u8, 1u8, 3u8, 4u8]);
        code.push(opcode_byte("Ret"));
        code.push(5u8);
        let module: HermesModule = module_with(&["loop"], &[], code, 2);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(
            f.source.contains("Object.keys(arg0)"),
            "expected for-in prop list; src: {}",
            f.source
        );
        assert_eq!(f.fallback_ops, 0, "src: {}", f.source);
    }

    #[test]
    fn decompile_generator_function() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("StartGenerator"));
        code.push(opcode_byte("LoadConstUInt8"));
        code.extend_from_slice(&[0u8, 1u8]);
        code.push(opcode_byte("SaveGenerator"));
        code.push(2u8);
        code.push(opcode_byte("ResumeGenerator"));
        code.extend_from_slice(&[1u8, 2u8]);
        code.push(opcode_byte("CompleteGenerator"));
        code.push(opcode_byte("Ret"));
        code.push(1u8);
        let module: HermesModule = module_with(&["gen"], &[], code, 1);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(f.is_generator, "expected generator flag; src: {}", f.source);
        assert!(
            f.source.contains("function* gen("),
            "expected function* keyword; src: {}",
            f.source
        );
        assert!(
            f.source.contains("yield;"),
            "expected yield point; src: {}",
            f.source
        );
        assert_eq!(
            f.fallback_ops, 2,
            "StartGenerator and CompleteGenerator are skeleton markers that emit no JS \
             and count as fallback, not reconstruction; src: {}",
            f.source
        );
        assert!(
            f.source.contains("$resumed"),
            "ResumeGenerator value should still be recovered; src: {}",
            f.source
        );
    }

    #[test]
    fn decompile_delete_and_coercion() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("LoadParam"));
        code.extend_from_slice(&[1u8, 1u8]);
        code.push(opcode_byte("DelById"));
        code.extend_from_slice(&[2u8, 1u8, 0u8, 0u8]);
        code.push(opcode_byte("ToNumber"));
        code.extend_from_slice(&[3u8, 1u8]);
        code.push(opcode_byte("ToInt32"));
        code.extend_from_slice(&[4u8, 1u8]);
        code.push(opcode_byte("Ret"));
        code.push(4u8);
        let module: HermesModule = module_with(&["prop"], &[], code, 2);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(
            f.source.contains("delete arg0.prop"),
            "expected delete; src: {}",
            f.source
        );
        assert!(
            f.source.contains("(arg0 | 0)"),
            "expected ToInt32 coercion; src: {}",
            f.source
        );
        assert_eq!(f.fallback_ops, 0, "src: {}", f.source);
    }

    #[test]
    fn decompile_variadic_call_marks_args_unrecovered() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("GetGlobalObject"));
        code.push(1u8);
        code.push(opcode_byte("GetByIdShort"));
        code.extend_from_slice(&[2u8, 1u8, 0u8, 0u8]);
        let argc_with_this: u8 = 4;
        code.push(opcode_byte("Call"));
        code.extend_from_slice(&[0u8, 2u8, argc_with_this]);
        code.push(opcode_byte("Ret"));
        code.push(0u8);
        let module: HermesModule = module_with(&["f"], &[], code.clone(), 1);

        let decoded: Vec<Instruction> = decode_instructions(&code);
        let call: &Instruction = decoded
            .iter()
            .find(|i: &&Instruction| i.name == "Call")
            .expect("Call decoded");
        let raw_argc: u64 = match call.operands.get(2) {
            Some(OperandValue::UInt(u)) => *u,
            other => panic!("expected UInt argc operand, got {other:?}"),
        };
        assert_eq!(raw_argc, u64::from(argc_with_this));
        let expected_displayed_args: u64 = raw_argc - 1;
        let callee_reg: u32 = match call.operands.get(1) {
            Some(OperandValue::Reg(r)) => *r,
            other => panic!("expected callee register operand, got {other:?}"),
        };
        assert_eq!(callee_reg, 2);

        let f: DecompiledFunction = decompile_function(&module, 0);
        let placeholder_count: usize = f.source.matches(UNRECOVERED_ARG).count();
        assert_eq!(
            placeholder_count, expected_displayed_args as usize,
            "expected {expected_displayed_args} unrecovered-arg markers matching raw argc; src: {}",
            f.source
        );
        assert!(
            !f.source.contains("a0") && !f.source.contains("a1"),
            "variadic Call must not fabricate a0/a1 argument names; src: {}",
            f.source
        );
        assert!(
            f.source.contains("globalThis.f("),
            "callee should be recovered even when args are not; src: {}",
            f.source
        );
    }

    #[test]
    fn decompile_construct_marks_args_unrecovered() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("GetGlobalObject"));
        code.push(1u8);
        code.push(opcode_byte("GetByIdShort"));
        code.extend_from_slice(&[2u8, 1u8, 0u8, 0u8]);
        code.push(opcode_byte("Construct"));
        code.extend_from_slice(&[0u8, 2u8, 3u8]);
        code.push(opcode_byte("Ret"));
        code.push(0u8);
        let module: HermesModule = module_with(&["Ctor"], &[], code, 1);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(
            f.source.contains("new globalThis.Ctor("),
            "expected new with recovered callee; src: {}",
            f.source
        );
        assert_eq!(
            f.source.matches(UNRECOVERED_ARG).count(),
            2,
            "expected 2 unrecovered-arg markers (argc 3 minus this); src: {}",
            f.source
        );
        assert!(
            !f.source.contains("a0"),
            "must not fabricate arg names; src: {}",
            f.source
        );
    }

    #[test]
    fn decompile_call_direct_marks_args_unrecovered() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("CallDirect"));
        code.push(0u8);
        code.push(3u8);
        code.extend_from_slice(&0u16.to_le_bytes());
        code.push(opcode_byte("Ret"));
        code.push(0u8);
        let module: HermesModule = module_with(&[], &[], code, 1);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert_eq!(
            f.source.matches(UNRECOVERED_ARG).count(),
            2,
            "CallDirect args must be explicitly unrecovered; src: {}",
            f.source
        );
        assert!(
            !f.source.contains("a0"),
            "CallDirect must not fabricate arg names; src: {}",
            f.source
        );
    }

    #[test]
    fn profile_point_does_not_inflate_reconstruction_count() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("ProfilePoint"));
        code.extend_from_slice(&0u16.to_le_bytes());
        code.push(opcode_byte("Ret"));
        code.push(0u8);
        let module: HermesModule = module_with(&[], &[], code, 1);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert_eq!(
            f.reconstructed_ops, 1,
            "only Ret should count as reconstructed; src: {}",
            f.source
        );
        assert_eq!(
            f.fallback_ops, 1,
            "ProfilePoint produces no recovered output and must count as fallback; src: {}",
            f.source
        );
    }

    #[test]
    fn decompile_arguments_and_new_target() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("GetNewTarget"));
        code.push(0u8);
        code.push(opcode_byte("GetArgumentsLength"));
        code.extend_from_slice(&[1u8, 0u8]);
        code.push(opcode_byte("Ret"));
        code.push(1u8);
        let module: HermesModule = module_with(&["f"], &[], code, 1);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(
            f.source.contains("arguments.length"),
            "expected arguments.length; src: {}",
            f.source
        );
        assert_eq!(f.fallback_ops, 0, "src: {}", f.source);
    }

    #[test]
    fn decompile_object_create_parent() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("LoadParam"));
        code.extend_from_slice(&[1u8, 1u8]);
        code.push(opcode_byte("NewObjectWithParent"));
        code.extend_from_slice(&[2u8, 1u8]);
        code.push(opcode_byte("Ret"));
        code.push(2u8);
        let module: HermesModule = module_with(&["mk"], &[], code, 2);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(
            f.source.contains("Object.create(arg0)"),
            "expected Object.create; src: {}",
            f.source
        );
        assert_eq!(f.fallback_ops, 0, "src: {}", f.source);
    }

    #[test]
    fn decompile_bigint_literal_synthesis() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("LoadConstBigInt"));
        code.push(0u8);
        code.extend_from_slice(&0u16.to_le_bytes());
        code.push(opcode_byte("Ret"));
        code.push(0u8);
        let mut module: HermesModule = module_with(&["x"], &[], code, 1);
        module.big_int_storage = 123_456_789u64.to_le_bytes().to_vec();
        module.big_int_table = vec![crate::hermes::BigIntTableEntry {
            offset: 0,
            length: 8,
        }];
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(
            f.source.contains("return 123456789n;"),
            "expected bigint literal; src: {}",
            f.source
        );
        assert_eq!(f.fallback_ops, 0, "src: {}", f.source);
    }

    #[test]
    fn decompile_switch_imm_dense_table() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("LoadParam"));
        code.extend_from_slice(&[1u8, 1u8]);
        let switch_off: usize = code.len();
        code.push(opcode_byte("SwitchImm"));
        let header_len: usize = 1 + 1 + 4 + 4 + 4 + 4;
        let default_target_rel: i32 = 100;
        let table_offset: u32 = header_len as u32;
        code.push(1u8);
        code.extend_from_slice(&table_offset.to_le_bytes());
        code.extend_from_slice(&default_target_rel.to_le_bytes());
        code.extend_from_slice(&0u32.to_le_bytes());
        code.extend_from_slice(&2u32.to_le_bytes());
        while (code.len()) % 4 != 0 {
            code.push(opcode_byte("Debugger"));
        }
        let table_at: usize = code.len();
        for k in 0i32..3 {
            let rel: i32 = 200 + k * 4 - switch_off as i32;
            code.extend_from_slice(&rel.to_le_bytes());
        }
        let _ = table_at;
        let module: HermesModule = module_with(&[], &[], code, 2);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(
            f.source.contains("switch ("),
            "expected switch; src: {}",
            f.source
        );
        assert!(
            f.source.contains("case 0:") && f.source.contains("case 2:"),
            "expected dense cases 0..2; src: {}",
            f.source
        );
        assert!(
            f.source.contains("default:"),
            "expected default; src: {}",
            f.source
        );
    }

    #[test]
    fn decode_respects_instruction_cap() {
        const { assert!(MAX_DECODED_INSTRUCTIONS >= 1 << 20) };
        let code: Vec<u8> = vec![opcode_byte("Debugger"); MAX_DECODED_INSTRUCTIONS + 50_000];
        let instructions: Vec<Instruction> = decode_instructions(&code);
        assert_eq!(instructions.len(), MAX_DECODED_INSTRUCTIONS);
    }

    #[test]
    fn opcode_table_coverage_excludes_only_instrumentation() {
        let mut unhandled: Vec<&str> = Vec::new();
        for spec in OPCODES {
            let n: &str = spec.name;
            let handled: bool = binop_symbol(n).is_some()
                || unop_symbol(n).is_some()
                || jump_condition(n).is_some()
                || HANDLED_OPCODES.contains(&n);
            if !handled {
                unhandled.push(n);
            }
        }
        assert!(
            unhandled.is_empty(),
            "every non-jump opcode must resugar or be a documented no-op; missing: {unhandled:?}"
        );
    }

    const HANDLED_OPCODES: &[&str] = &[
        "LoadConstUInt8",
        "LoadConstInt",
        "LoadConstDouble",
        "LoadConstZero",
        "LoadConstString",
        "LoadConstStringLongIndex",
        "LoadConstUndefined",
        "LoadConstEmpty",
        "LoadConstNull",
        "LoadConstTrue",
        "LoadConstFalse",
        "LoadConstBigInt",
        "LoadConstBigIntLongIndex",
        "LoadParam",
        "LoadParamLong",
        "LoadThisNS",
        "CoerceThisNS",
        "Mov",
        "MovLong",
        "CreateEnvironment",
        "CreateInnerEnvironment",
        "GetEnvironment",
        "LoadFromEnvironment",
        "LoadFromEnvironmentL",
        "StoreToEnvironment",
        "StoreToEnvironmentL",
        "StoreNPToEnvironment",
        "StoreNPToEnvironmentL",
        "GetGlobalObject",
        "IteratorBegin",
        "IteratorNext",
        "IteratorClose",
        "GetPNameList",
        "GetNextPName",
        "GetByIdShort",
        "GetById",
        "GetByIdLong",
        "TryGetById",
        "TryGetByIdLong",
        "PutById",
        "PutByIdLong",
        "TryPutById",
        "TryPutByIdLong",
        "PutNewOwnById",
        "PutNewOwnByIdLong",
        "PutNewOwnByIdShort",
        "PutNewOwnNEById",
        "PutNewOwnNEByIdLong",
        "GetBuiltinClosure",
        "Debugger",
        "AsyncBreakCheck",
        "ProfilePoint",
        "Unreachable",
        "GetByVal",
        "PutByVal",
        "PutOwnByIndex",
        "PutOwnByIndexL",
        "PutOwnByVal",
        "PutOwnGetterSetterByVal",
        "DelById",
        "DelByIdLong",
        "DelByVal",
        "NewObjectWithParent",
        "NewObject",
        "NewObjectWithBuffer",
        "NewObjectWithBufferLong",
        "NewArray",
        "NewArrayWithBuffer",
        "NewArrayWithBufferLong",
        "CreateThis",
        "SelectObject",
        "CreateClosure",
        "CreateClosureLongIndex",
        "CreateGeneratorClosure",
        "CreateGeneratorClosureLongIndex",
        "CreateAsyncClosure",
        "CreateAsyncClosureLongIndex",
        "CreateRegExp",
        "SwitchImm",
        "CallBuiltin",
        "CallBuiltinLong",
        "StartGenerator",
        "CompleteGenerator",
        "SaveGenerator",
        "SaveGeneratorLong",
        "ResumeGenerator",
        "CreateGenerator",
        "CreateGeneratorLongIndex",
        "ToNumber",
        "ToNumeric",
        "ToInt32",
        "AddEmptyString",
        "GetNewTarget",
        "ReifyArguments",
        "GetArgumentsLength",
        "GetArgumentsPropByVal",
        "DirectEval",
        "DeclareGlobalVar",
        "ThrowIfHasRestrictedGlobalProperty",
        "ThrowIfEmpty",
        "CallDirect",
        "CallDirectLongIndex",
        "Call",
        "CallLong",
        "Construct",
        "ConstructLong",
        "Call1",
        "Call2",
        "Call3",
        "Call4",
        "Ret",
        "Throw",
        "Catch",
        "Jmp",
        "JmpLong",
        "JmpTrue",
        "JmpTrueLong",
        "JmpFalse",
        "JmpFalseLong",
        "JmpUndefined",
        "JmpUndefinedLong",
    ];

    #[test]
    fn all_families_oracle_low_fallback() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("CreateEnvironment"));
        code.push(0u8);
        code.push(opcode_byte("LoadParam"));
        code.extend_from_slice(&[1u8, 1u8]);
        code.push(opcode_byte("StoreToEnvironment"));
        code.extend_from_slice(&[0u8, 2u8, 1u8]);
        code.push(opcode_byte("IteratorBegin"));
        code.extend_from_slice(&[2u8, 1u8]);
        code.push(opcode_byte("IteratorNext"));
        code.extend_from_slice(&[3u8, 2u8, 1u8]);
        code.push(opcode_byte("ToInt32"));
        code.extend_from_slice(&[4u8, 3u8]);
        code.push(opcode_byte("DelByVal"));
        code.extend_from_slice(&[6u8, 1u8, 4u8]);
        code.push(opcode_byte("Ret"));
        code.push(6u8);
        let module: HermesModule = module_with(&["mix"], &[], code, 2);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert_eq!(
            f.fallback_ops, 0,
            "all-families function must have zero fallback; src: {}",
            f.source
        );
        for expected in [
            "cvar2 = arg0;",
            "[Symbol.iterator]()",
            ".next().value",
            "delete arg0[",
        ] {
            assert!(
                f.source.contains(expected),
                "expected `{expected}` in recovered source; src: {}",
                f.source
            );
        }
    }
}
