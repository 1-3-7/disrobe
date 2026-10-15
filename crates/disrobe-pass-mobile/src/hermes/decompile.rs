use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use serde::{Deserialize, Serialize};

use super::lift::{
    self, CLOSURE_MARK, EnvRefName, FunctionInput, Helper, MetroModule, ModuleScope, Outcome,
    lift_function, render_dispatcher,
};
use super::opcodes::{OPCODES_HBC96, OpcodeSpec, Operand, opcode_label_in, opcode_specs};

pub(crate) fn lift_specs(version: u32) -> Option<&'static [OpcodeSpec]> {
    if HERMES_LIFTED_VERSIONS.contains(&version) {
        opcode_specs(version)
    } else {
        None
    }
}

fn lifted_instructions(
    module: &HermesModule,
    code: &[u8],
    specs: &'static [OpcodeSpec],
    exceptions: &[HermesExceptionEntry],
) -> Vec<Instruction> {
    let instructions: Vec<Instruction> = decode_instructions(code, specs);
    if !super::modern::uses_modern_instructions(module.header.version) {
        return instructions;
    }
    let handlers: BTreeSet<usize> = exceptions
        .iter()
        .filter_map(|entry: &HermesExceptionEntry| usize::try_from(entry.target).ok())
        .collect();
    super::modern::normalize(module, &handlers, instructions)
}

pub(crate) fn decode_for_lift(
    module: &HermesModule,
    index: usize,
    specs: &'static [OpcodeSpec],
) -> Vec<Instruction> {
    let exceptions: Vec<HermesExceptionEntry> = module.exception_table(index).unwrap_or_default();
    lifted_instructions(module, module.function_code(index), specs, &exceptions)
}
use super::structure::{StructureDecline, Structured, Structuring, structure_function};
use super::{
    HERMES_LIFTED_VERSIONS, HermesExceptionEntry, HermesFunctionKind, HermesModule,
    SmallFunctionHeader,
};

const MAX_DECODED_INSTRUCTIONS: usize = 1 << 20;
const MAX_SWITCH_CASES: u64 = 4096;

const OPCODE_SLOTS: usize = 256;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct OpcodeTally {
    reconstructed: u32,
    declined: u32,
    unaccounted: u32,
}

#[derive(Debug, Clone)]
struct OpcodeHistogram {
    slots: Box<[OpcodeTally; OPCODE_SLOTS]>,
}

impl OpcodeHistogram {
    fn new() -> Self {
        Self {
            slots: Box::new([OpcodeTally::default(); OPCODE_SLOTS]),
        }
    }

    fn slot_mut(&mut self, opcode: u8) -> &mut OpcodeTally {
        &mut self.slots[opcode as usize]
    }

    fn merge(&mut self, other: &Self) {
        for (into, from) in self.slots.iter_mut().zip(other.slots.iter()) {
            into.reconstructed = into.reconstructed.saturating_add(from.reconstructed);
            into.declined = into.declined.saturating_add(from.declined);
            into.unaccounted = into.unaccounted.saturating_add(from.unaccounted);
        }
    }

    fn counts(
        &self,
        pick: fn(&OpcodeTally) -> u32,
        specs: &'static [OpcodeSpec],
    ) -> Vec<OpcodeCount> {
        let mut out: Vec<OpcodeCount> = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(index, tally): (usize, &OpcodeTally)| {
                let occurrences: u32 = pick(tally);
                if occurrences == 0 {
                    return None;
                }
                let opcode: u8 = u8::try_from(index).ok()?;
                Some(OpcodeCount {
                    opcode: opcode_label_in(specs, opcode).into_owned(),
                    occurrences: occurrences as usize,
                })
            })
            .collect();
        out.sort_by(|left: &OpcodeCount, right: &OpcodeCount| {
            right
                .occurrences
                .cmp(&left.occurrences)
                .then_with(|| left.opcode.cmp(&right.opcode))
        });
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpcodeCount {
    pub opcode: String,
    pub occurrences: usize,
}

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
pub(crate) fn decode_instructions(code: &[u8], specs: &'static [OpcodeSpec]) -> Vec<Instruction> {
    let cap: usize = (code.len() / 3).min(MAX_DECODED_INSTRUCTIONS);
    let mut out: Vec<Instruction> = Vec::with_capacity(cap);
    let mut pc: usize = 0;
    while pc < code.len() && out.len() < MAX_DECODED_INSTRUCTIONS {
        let opcode: u8 = code[pc];
        let spec: Option<&OpcodeSpec> = specs.get(opcode as usize);
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
pub(crate) fn is_switch(name: &str) -> bool {
    matches!(name, "SwitchImm" | "StringSwitchImm")
}

#[must_use]
pub(crate) fn is_terminator(name: &str) -> bool {
    matches!(name, "Ret" | "Throw" | "Unreachable")
        || is_unconditional_jump(name)
        || is_conditional_jump(name)
        || is_switch(name)
}

#[must_use]
fn switch_case_targets(image: &[u8], code_base: usize, inst: &Instruction) -> Vec<(i64, usize)> {
    if inst.name == "StringSwitchImm" {
        return string_switch_entries(image, code_base, inst)
            .into_iter()
            .enumerate()
            .map(|(index, (_, target)): (usize, (u32, usize))| {
                (i64::try_from(index).unwrap_or(i64::MAX), target)
            })
            .collect();
    }
    if !is_switch(&inst.name) {
        return Vec::new();
    }
    let table_offset: u64 = uint_of(inst.operands.get(1));
    let min_val: u64 = uint_of(inst.operands.get(3));
    let max_val: u64 = uint_of(inst.operands.get(4));
    switch_table_entries(
        image,
        code_base,
        inst.offset,
        table_offset,
        min_val,
        max_val,
    )
}

#[must_use]
pub(crate) fn block_edges(inst: &Instruction, image: &[u8], code_base: usize) -> Vec<usize> {
    if !is_switch(&inst.name) {
        return instruction_targets(inst);
    }
    let mut edges: Vec<usize> = switch_case_targets(image, code_base, inst)
        .into_iter()
        .map(|(_, target): (i64, usize)| target)
        .collect();
    edges.extend(instruction_targets(inst));
    edges
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
pub(crate) fn build_cfg(
    instructions: &[Instruction],
    image: &[u8],
    code_base: usize,
    exception_entries: &[HermesExceptionEntry],
) -> Cfg {
    if instructions.is_empty() {
        return Cfg {
            blocks: Vec::new(),
            offset_to_block: BTreeMap::new(),
        };
    }
    let mut leaders: BTreeSet<usize> = BTreeSet::new();
    leaders.insert(instructions[0].offset);
    for entry in exception_entries {
        if let Ok(start) = usize::try_from(entry.start) {
            leaders.insert(start);
        }
        if let Ok(end) = usize::try_from(entry.end) {
            leaders.insert(end);
        }
        if let Ok(target) = usize::try_from(entry.target) {
            leaders.insert(target);
        }
    }
    for (i, inst) in instructions.iter().enumerate() {
        if is_terminator(&inst.name) {
            for t in block_edges(inst, image, code_base) {
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
            if is_switch(&last.name) {
                for t in block_edges(last, image, code_base) {
                    if let Some(b) = offset_to_block.get(&t)
                        && !succ.contains(b)
                    {
                        succ.push(*b);
                    }
                }
            } else if is_unconditional_jump(&last.name) {
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

#[must_use]
fn uint_of(v: Option<&OperandValue>) -> u64 {
    match v {
        Some(OperandValue::UInt(u)) => *u,
        _ => 0,
    }
}

const STRING_SWITCH_CASE_SIZE: usize = 8;

#[must_use]
pub(crate) fn string_switch_entries(
    image: &[u8],
    code_base: usize,
    inst: &Instruction,
) -> Vec<(u32, usize)> {
    let table_offset: u64 = uint_of(inst.operands.get(2));
    let count: u64 = uint_of(inst.operands.get(4));
    if count > MAX_SWITCH_CASES {
        return Vec::new();
    }
    let Some(aligned_base): Option<usize> = usize::try_from(table_offset)
        .ok()
        .and_then(|offset: usize| inst.offset.checked_add(offset))
        .and_then(|relative: usize| code_base.checked_add(relative))
        .and_then(|absolute: usize| absolute.checked_add(3))
        .map(|base: usize| base & !3usize)
    else {
        return Vec::new();
    };
    let mut out: Vec<(u32, usize)> = Vec::new();
    for index in 0..usize::try_from(count).unwrap_or(0) {
        let Some(at): Option<usize> = index
            .checked_mul(STRING_SWITCH_CASE_SIZE)
            .and_then(|delta: usize| aligned_base.checked_add(delta))
        else {
            break;
        };
        let Some(raw): Option<&[u8]> = image.get(at..at + STRING_SWITCH_CASE_SIZE) else {
            break;
        };
        let label: u32 = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let relative: i64 = i64::from(i32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]));
        out.push((label, relative_target(inst.offset, relative)));
    }
    out
}

#[must_use]
pub(crate) fn switch_table_entries(
    image: &[u8],
    code_base: usize,
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
    let Some(absolute_base): Option<usize> = code_base.checked_add(table_base) else {
        return Vec::new();
    };
    let Some(aligned_base): Option<usize> = absolute_base
        .checked_add(3)
        .map(|base: usize| base & !3usize)
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
        let Some(entry_delta): Option<usize> = k.checked_mul(core::mem::size_of::<u32>()) else {
            break;
        };
        let Some(entry_at): Option<usize> = aligned_base.checked_add(entry_delta) else {
            break;
        };
        let Some(entry_end): Option<usize> = entry_at.checked_add(core::mem::size_of::<u32>())
        else {
            break;
        };
        let Some(raw): Option<&[u8]> = image.get(entry_at..entry_end) else {
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
pub(crate) struct LiftedBlock {
    pub stmts: Vec<BlockStmt>,
}

#[must_use]
fn fallback_disasm(inst: &Instruction) -> String {
    let rendered: Vec<String> = inst
        .operands
        .iter()
        .map(|op: &OperandValue| match op {
            OperandValue::Reg(r) => format!("r{r}"),
            OperandValue::UInt(u) => u.to_string(),
            OperandValue::Imm(i) => i.to_string(),
            OperandValue::Float(f) => f64::from_bits(*f).to_string(),
            OperandValue::Target(t) => format!("@{t}"),
            OperandValue::StringId(s) => format!("str#{s}"),
            OperandValue::FunctionId(f) => format!("fn#{f}"),
            OperandValue::BigIntId(b) => format!("bigint#{b}"),
        })
        .collect();
    format!("{}({})", inst.name, rendered.join(", "))
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
    pub unaccounted_ops: usize,
    pub has_if: bool,
    pub has_loop: bool,
    pub has_try_catch: bool,
    pub is_generator: bool,
    pub structured: bool,
    pub structure_decline: Option<StructureDecline>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeclineCount {
    pub reason: StructureDecline,
    pub functions: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompileReport {
    pub hermes_version: u32,
    pub lift_supported: bool,
    pub function_count: usize,
    pub functions_with_body: usize,
    pub total_reconstructed_ops: usize,
    pub total_fallback_ops: usize,
    pub total_unaccounted_ops: usize,
    pub structured_functions: usize,
    pub structure_declines: Vec<DeclineCount>,
    pub reconstructed_opcodes: Vec<OpcodeCount>,
    pub declined_opcodes: Vec<OpcodeCount>,
    pub unaccounted_opcodes: Vec<OpcodeCount>,
    pub functions: Vec<DecompiledFunction>,
    pub regexps: Vec<super::regex::RecoveredRegExp>,
    pub program: String,
    pub metro_modules: Vec<MetroModule>,
}

#[must_use]
pub fn disassemble_function_instructions(module: &HermesModule, index: usize) -> Vec<String> {
    let version: u32 = module.header.version;
    let Some(specs): Option<&'static [OpcodeSpec]> = opcode_specs(version) else {
        return vec![format!(
            "hbc v{version}: no opcode table, instructions are not decoded at this bytecode version"
        )];
    };
    let code: &[u8] = module.function_code(index);
    decode_instructions(code, specs)
        .iter()
        .map(|i: &Instruction| format!("{:#06x}: {}", i.offset, fallback_disasm(i)))
        .collect()
}

#[must_use]
pub(crate) fn negate_cond(cond: &str) -> String {
    if let Some(inner) = cond.strip_prefix("!(")
        && let Some(inner) = inner.strip_suffix(')')
        && is_balanced(inner)
    {
        return inner.to_owned();
    }
    if let Some(operand) = cond.strip_prefix('!')
        && operand
            .chars()
            .next()
            .is_some_and(|c: char| c.is_ascii_alphabetic() || c == '_' || c == '$')
        && operand
            .chars()
            .all(|c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '.'))
    {
        return operand.to_owned();
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

#[must_use]
fn declined_function(module: &HermesModule, index: usize) -> DecompiledFunction {
    let header: Option<&SmallFunctionHeader> = module.functions.get(index);
    let name: String = header
        .and_then(|h: &SmallFunctionHeader| module.string_by_global_id(h.function_name_id))
        .filter(|s: &&str| !s.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("$func{index}"));
    let version: u32 = module.header.version;
    DecompiledFunction {
        index,
        source: format!(
            "/* hbc v{version}: bodies are not lifted at this bytecode version (lifting covers \
             v{HERMES_LIFTED_VERSIONS:?}) */"
        ),
        name,
        param_count: header.map_or(0, |h: &SmallFunctionHeader| h.param_count),
        frame_size: header.map_or(0, |h: &SmallFunctionHeader| h.frame_size),
        bytecode_size: header.map_or(0, |h: &SmallFunctionHeader| h.bytecode_size_bytes),
        instruction_count: 0,
        block_count: 0,
        reconstructed_ops: 0,
        fallback_ops: 0,
        unaccounted_ops: 0,
        has_if: false,
        has_loop: false,
        has_try_catch: header.is_some_and(|h: &SmallFunctionHeader| h.has_exception_handler),
        is_generator: false,
        structured: false,
        structure_decline: Some(StructureDecline::UnsupportedBytecodeVersion),
    }
}

const MAX_INLINE_CLOSURE_BYTES: usize = 1 << 16;
const MAX_INLINE_CLOSURE_DEPTH: usize = 8;
const MAX_PROGRAM_DEPTH: usize = 512;
const MAX_PROGRAM_BYTES: usize = 1 << 29;

#[derive(Debug, Clone)]
struct Rendered {
    decompiled: DecompiledFunction,
    histogram: OpcodeHistogram,
    helpers: BTreeSet<Helper>,
    signature_name: String,
    keyword: &'static str,
    params: String,
    strict: bool,
    declarations: Vec<String>,
    body: String,
    merged_generator: Option<u32>,
    prelude: Option<String>,
}

fn empty_header() -> SmallFunctionHeader {
    SmallFunctionHeader {
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
        kind: HermesFunctionKind::Normal,
    }
}

fn function_name(module: &HermesModule, header: &SmallFunctionHeader, index: usize) -> String {
    module
        .string_by_global_id(header.function_name_id)
        .filter(|s: &&str| !s.is_empty())
        .map_or_else(|| format!("$func{index}"), str::to_owned)
}

fn render_function(
    module: &HermesModule,
    scope: &ModuleScope,
    index: usize,
    specs: &'static [OpcodeSpec],
) -> Rendered {
    let header: SmallFunctionHeader = module
        .functions
        .get(index)
        .copied()
        .unwrap_or_else(empty_header);
    let name: String = function_name(module, &header, index);
    let code: &[u8] = module.function_code(index);
    let code_base: usize = usize::try_from(header.offset).unwrap_or(0);
    let exceptions: Vec<HermesExceptionEntry> = module.exception_table(index).unwrap_or_default();
    let instructions: Vec<Instruction> = lifted_instructions(module, code, specs, &exceptions);
    let mut cfg: Cfg = build_cfg(&instructions, &module.raw_image, code_base, &exceptions);
    let async_body: bool =
        u32::try_from(index).is_ok_and(|fid: u32| scope.async_bodies.contains(&fid));
    link_generator_resumes(&mut cfg, &instructions, async_body);
    let merged_generator: Option<u32> = wrapper_target(&instructions, &cfg);
    let own_fid: u32 = u32::try_from(index).unwrap_or(u32::MAX);
    let lift_header: SmallFunctionHeader = SmallFunctionHeader {
        frame_size: lift::call_frame_size(module, &header),
        env_size: scope
            .env_sizes
            .get(&own_fid)
            .copied()
            .unwrap_or(header.env_size),
        ..header
    };
    let input: FunctionInput<'_> = FunctionInput {
        module,
        scope,
        index,
        header: &lift_header,
        instructions: &instructions,
        cfg: &cfg,
        exceptions: &exceptions,
        code_base,
        merged_generator,
    };
    let mut histogram: OpcodeHistogram = OpcodeHistogram::new();
    let signature_name: String = module
        .string_by_global_id(header.function_name_id)
        .filter(|declared: &&str| lift::is_binding_identifier(declared))
        .map_or_else(String::new, str::to_owned);
    let params: String = (0..header.param_count.saturating_sub(1))
        .map(|p: u32| scope.param_name_of(index, p))
        .collect::<Vec<String>>()
        .join(", ");
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
    let has_loop: bool = cfg_has_back_edge(&cfg);
    let keyword: &'static str = if is_generator {
        "function*"
    } else {
        "function"
    };
    let Some(lifted) = lift_function(&input) else {
        for inst in &instructions {
            let slot: &mut OpcodeTally = histogram.slot_mut(inst.opcode);
            slot.declined = slot.declined.saturating_add(1);
        }
        let body: String = format!(
            "  throw new Error(\"hermes: fn #{index} uses more registers than the lifter tracks\");\n"
        );
        let decompiled: DecompiledFunction = DecompiledFunction {
            index,
            name,
            param_count: header.param_count,
            frame_size: header.frame_size,
            bytecode_size: header.bytecode_size_bytes,
            instruction_count: instructions.len(),
            block_count: cfg.blocks.len(),
            reconstructed_ops: 0,
            fallback_ops: instructions.len(),
            unaccounted_ops: 0,
            has_if: false,
            has_loop,
            has_try_catch,
            is_generator,
            structured: false,
            structure_decline: Some(StructureDecline::RegisterBudgetExceeded),
            source: String::new(),
        };
        return Rendered {
            decompiled,
            histogram,
            helpers: BTreeSet::new(),
            signature_name,
            keyword,
            params,
            strict: header.strict_mode,
            declarations: Vec::new(),
            body,
            merged_generator: None,
            prelude: None,
        };
    };
    let mut reconstructed: usize = 0;
    let mut fallback: usize = 0;
    for (inst, outcome) in instructions.iter().zip(&lifted.outcomes) {
        let slot: &mut OpcodeTally = histogram.slot_mut(inst.opcode);
        match outcome {
            Outcome::Reconstructed => {
                reconstructed += 1;
                slot.reconstructed = slot.reconstructed.saturating_add(1);
            }
            Outcome::Declined => {
                fallback += 1;
                slot.declined = slot.declined.saturating_add(1);
            }
        }
    }
    let has_if: bool = lifted
        .blocks
        .iter()
        .flat_map(|b: &LiftedBlock| b.stmts.iter())
        .any(|s: &BlockStmt| matches!(s, BlockStmt::CondJump { .. }));
    let structured_body: Result<Structured, StructureDecline> = match structure_function(
        &lifted.blocks,
        &cfg,
        &exceptions,
        &lifted.handler_of_block,
        scope.structuring,
    ) {
        Ok(structured) if !structured.body.contains("goto ") => Ok(structured),
        Ok(_) => Err(StructureDecline::IncompleteCover),
        Err(reason) => Err(reason),
    };
    let mut declared: Vec<String> = lifted
        .var_regs
        .iter()
        .map(|reg: &u32| scope.reg_name(*reg))
        .collect();
    let own: u32 = u32::try_from(index).unwrap_or(u32::MAX);
    if scope.is_boxed(own) {
        declared.push(ModuleScope::boxed_env_name(own));
    } else if !scope.is_hosted_elsewhere(own) {
        for slot in 0..lifted.env_slots {
            declared.push(scope.env_name(EnvRefName::Owned(own), u64::from(slot)));
        }
    }
    for hosted in scope.hosted_by(own) {
        let size: u32 = scope
            .env_sizes
            .get(&hosted)
            .copied()
            .unwrap_or(0)
            .min(1 << 16);
        for slot in 0..size {
            declared.push(scope.env_name(EnvRefName::Owned(hosted), u64::from(slot)));
        }
    }
    let (body, structure_decline): (String, Option<StructureDecline>) = match structured_body {
        Ok(structured) => {
            if structured.exit_selector {
                declared.push("$exit".to_owned());
            }
            if structured.exception_binding {
                declared.push("$exc".to_owned());
            }
            if structured.handler_test {
                declared.push("$test".to_owned());
            }
            (structured.body, None)
        }
        Err(reason) => {
            if lifted.handler_of_block.iter().any(Option::is_some) {
                declared.push("$exc".to_owned());
            }
            let mut body: String = format!(
                "  /* unstructured ({}): dispatcher form */\n",
                reason.as_str()
            );
            body.push_str(&render_dispatcher(
                &lifted.blocks,
                &cfg,
                &lifted.handler_of_block,
                "  ",
            ));
            (body, Some(reason))
        }
    };
    let prelude: Option<String> = merged_generator
        .filter(|_| lifted.var_regs.is_empty())
        .and_then(|inner: u32| wrapper_prelude(&lifted.blocks, inner));
    let decompiled: DecompiledFunction = DecompiledFunction {
        index,
        name,
        param_count: header.param_count,
        frame_size: header.frame_size,
        bytecode_size: header.bytecode_size_bytes,
        instruction_count: instructions.len(),
        block_count: cfg.blocks.len(),
        reconstructed_ops: reconstructed,
        fallback_ops: fallback,
        unaccounted_ops: 0,
        has_if,
        has_loop,
        has_try_catch,
        is_generator,
        structured: structure_decline.is_none(),
        structure_decline,
        source: String::new(),
    };
    Rendered {
        decompiled,
        histogram,
        helpers: lifted.helpers,
        signature_name,
        keyword,
        params,
        strict: header.strict_mode,
        declarations: declared,
        merged_generator: prelude.as_ref().and(merged_generator),
        prelude,
        body,
    }
}

fn link_generator_resumes(cfg: &mut Cfg, instructions: &[Instruction], async_body: bool) {
    let mut return_edges: Vec<(usize, usize)> = Vec::new();
    for (index, block) in cfg.blocks.iter().enumerate() {
        let (start, end): (usize, usize) = block.instr_range;
        let Some(last) = end.checked_sub(1).and_then(|l: usize| instructions.get(l)) else {
            continue;
        };
        if !matches!(
            &*last.name,
            "JmpTrue" | "JmpTrueLong" | "JmpFalse" | "JmpFalseLong"
        ) {
            continue;
        }
        let dead_offset: Option<usize> = (start..end)
            .filter(|position: &usize| instructions[*position].name == "ResumeGenerator")
            .find_map(|position: usize| {
                if async_body {
                    lift::resume_return_offset(instructions, position)
                } else {
                    lift::resume_return_path(instructions, cfg, position)
                }
            });
        if let Some(dead) = dead_offset.and_then(|offset: usize| cfg.offset_to_block.get(&offset)) {
            return_edges.push((index, *dead));
        }
    }
    for (index, dead) in return_edges {
        cfg.blocks[index]
            .successors
            .retain(|succ: &usize| *succ != dead);
    }
    for block in &mut cfg.blocks {
        let (start, end): (usize, usize) = block.instr_range;
        if end < start + 2 {
            continue;
        }
        let save: &Instruction = &instructions[end - 2];
        if !matches!(&*save.name, "SaveGenerator" | "SaveGeneratorLong")
            || instructions[end - 1].name != "Ret"
        {
            continue;
        }
        if let Some(OperandValue::Target(target)) = save.operands.first()
            && let Some(resume) = cfg.offset_to_block.get(target)
            && block.successors.is_empty()
        {
            block.successors.push(*resume);
        }
    }
}

fn wrapper_target(instructions: &[Instruction], cfg: &Cfg) -> Option<u32> {
    if cfg.blocks.len() != 1 {
        return None;
    }
    let mut target: Option<(u32, u32)> = None;
    for inst in instructions {
        let name: &str = &inst.name;
        match name {
            "CreateGenerator" | "CreateGeneratorLongIndex" => {
                let Some(OperandValue::FunctionId(fid)) = inst.operands.get(2) else {
                    return None;
                };
                let Some(OperandValue::Reg(dest)) = inst.operands.first() else {
                    return None;
                };
                if target.is_some() {
                    return None;
                }
                target = Some((*fid, *dest));
            }
            "CreateEnvironment"
            | "LoadParam"
            | "LoadParamLong"
            | "Mov"
            | "MovLong"
            | "StoreToEnvironment"
            | "StoreToEnvironmentL"
            | "StoreNPToEnvironment"
            | "StoreNPToEnvironmentL"
            | "GetEnvironment"
            | "CreateClosure"
            | "CreateClosureLongIndex"
            | "LoadThisNS"
            | "ReifyArguments"
            | "Ret" => {}
            _ if name.starts_with("LoadConst") => {}
            _ => return None,
        }
    }
    let (fid, dest): (u32, u32) = target?;
    let last: &Instruction = instructions.last()?;
    (last.name == "Ret" && last.operands.first() == Some(&OperandValue::Reg(dest))).then_some(fid)
}

fn wrapper_prelude(blocks: &[LiftedBlock], inner: u32) -> Option<String> {
    let [block] = blocks else {
        return None;
    };
    let (last, lines): (&BlockStmt, &[BlockStmt]) = block.stmts.split_last()?;
    if !matches!(last, BlockStmt::Return(value) if *value == lift::closure_marker(inner)) {
        return None;
    }
    let mut prelude: String = String::new();
    for line in lines {
        let BlockStmt::Line(text) = line else {
            return None;
        };
        prelude.push_str("  ");
        prelude.push_str(text);
        prelude.push('\n');
    }
    Some(prelude)
}

fn template(own: &Rendered, inner: Option<&Rendered>) -> String {
    let merged: Option<(&String, &Rendered)> =
        own.prelude
            .as_ref()
            .zip(inner)
            .and_then(|(prelude, inner): (&String, &Rendered)| {
                own.merged_generator
                    .is_some_and(|fid: u32| fid as usize == inner.decompiled.index)
                    .then_some((prelude, inner))
            });
    let (keyword, declarations, body): (&str, Vec<String>, String) = match merged {
        Some((prelude, inner)) => {
            let mut declarations: Vec<String> = own.declarations.clone();
            for name in &inner.declarations {
                if !declarations.contains(name) {
                    declarations.push(name.clone());
                }
            }
            (
                "function*",
                declarations,
                format!("{prelude}{}", inner.body),
            )
        }
        None => (own.keyword, own.declarations.clone(), own.body.clone()),
    };
    let name: String = if own.signature_name.is_empty() {
        String::new()
    } else {
        format!(" {}", own.signature_name)
    };
    let strict: &str = if own.strict {
        "\n  \"use strict\";"
    } else {
        ""
    };
    let declarations: String = if declarations.is_empty() {
        String::new()
    } else {
        format!("  var {};\n", declarations.join(", "))
    };
    format!(
        "{keyword}{name}({}) {{{strict}\n{declarations}{body}}}",
        own.params
    )
}

#[must_use]
fn cfg_has_back_edge(cfg: &Cfg) -> bool {
    cfg.blocks
        .iter()
        .enumerate()
        .any(|(i, b): (usize, &BasicBlock)| b.successors.iter().any(|s: &usize| *s <= i))
}

const MAX_NAME_SCAN_FUNCTIONS: usize = 4096;

fn references_name(templates: &[String], root: usize, name: &str) -> bool {
    let mut pending: Vec<usize> = vec![root];
    let mut seen: BTreeSet<usize> = BTreeSet::new();
    while let Some(index) = pending.pop() {
        if !seen.insert(index) || seen.len() > MAX_NAME_SCAN_FUNCTIONS {
            continue;
        }
        let Some(text) = templates.get(index) else {
            continue;
        };
        let body: &str = text
            .find('{')
            .map_or(text.as_str(), |at: usize| &text[at..]);
        if bare_identifier_in(body, name) {
            return true;
        }
        pending.extend(
            markers(text)
                .into_iter()
                .map(|(_, _, fid): (usize, usize, u32)| fid as usize),
        );
    }
    false
}

fn bare_identifier_in(text: &str, name: &str) -> bool {
    let continues = |c: char| -> bool { c.is_ascii_alphanumeric() || c == '_' || c == '$' };
    text.match_indices(name).any(|(at, _): (usize, &str)| {
        let before: Option<char> = text[..at].chars().next_back();
        let after: Option<char> = text[at + name.len()..].chars().next();
        !before.is_some_and(|c: char| continues(c) || c == '.') && !after.is_some_and(continues)
    })
}

fn markers(text: &str) -> Vec<(usize, usize, u32)> {
    let mut out: Vec<(usize, usize, u32)> = Vec::new();
    let mut search: usize = 0;
    while let Some(found) = text[search..].find(CLOSURE_MARK) {
        let start: usize = search + found;
        let body_start: usize = start + CLOSURE_MARK.len_utf8();
        let Some(close) = text[body_start..].find(CLOSURE_MARK) else {
            break;
        };
        let body_end: usize = body_start + close;
        let end: usize = body_end + CLOSURE_MARK.len_utf8();
        if let Some(fid) = text[body_start..body_end]
            .strip_prefix('F')
            .and_then(|digits: &str| digits.parse::<u32>().ok())
        {
            out.push((start, end, fid));
        }
        search = end;
    }
    out
}

fn placeholder(name: &str, fid: u32) -> String {
    if lift::is_binding_identifier(name) {
        format!("function {name}() {{ /* fn #{fid} */ }}")
    } else {
        format!("function () {{ /* fn #{fid} */ }}")
    }
}

fn line_indent(out: &str) -> String {
    let line_start: usize = out.rfind('\n').map_or(0, |p: usize| p + 1);
    out[line_start..]
        .chars()
        .take_while(|c: &char| *c == ' ')
        .collect()
}

struct Expander<'a> {
    templates: &'a [String],
    names: &'a [String],
    sizes: Vec<Option<usize>>,
    cache: BTreeMap<u32, String>,
}

impl Expander<'_> {
    fn subtree_size(&mut self, fid: u32, visiting: &mut BTreeSet<u32>) -> usize {
        let index: usize = fid as usize;
        if let Some(Some(size)) = self.sizes.get(index) {
            return *size;
        }
        let Some(text) = self.templates.get(index) else {
            return 0;
        };
        if !visiting.insert(fid) {
            return usize::MAX;
        }
        let mut size: usize = text.len();
        for (_, _, child) in markers(text) {
            size = size.saturating_add(self.subtree_size(child, visiting));
            if size > MAX_PROGRAM_BYTES {
                size = usize::MAX;
                break;
            }
        }
        visiting.remove(&fid);
        if let Some(slot) = self.sizes.get_mut(index) {
            *slot = Some(size);
        }
        size
    }

    fn expand_capped(&mut self, fid: u32, depth: usize, visiting: &mut BTreeSet<u32>) -> String {
        if let Some(cached) = self.cache.get(&fid) {
            return cached.clone();
        }
        let Some(text) = self.templates.get(fid as usize) else {
            return String::new();
        };
        let text: String = text.clone();
        visiting.insert(fid);
        let mut out: String = String::with_capacity(text.len());
        let mut cursor: usize = 0;
        for (start, end, child) in markers(&text) {
            out.push_str(&text[cursor..start]);
            cursor = end;
            let fits: bool = depth < MAX_INLINE_CLOSURE_DEPTH
                && !visiting.contains(&child)
                && (child as usize) < self.templates.len()
                && self.subtree_size(child, &mut BTreeSet::new()) <= MAX_INLINE_CLOSURE_BYTES;
            if fits {
                let indent: String = line_indent(&out);
                let expanded: String = self.expand_capped(child, depth + 1, visiting);
                out.push_str(&expanded.replace('\n', &format!("\n{indent}")));
            } else {
                out.push_str(&placeholder(
                    self.names.get(child as usize).map_or("", String::as_str),
                    child,
                ));
            }
        }
        out.push_str(&text[cursor..]);
        visiting.remove(&fid);
        if depth > 0 {
            self.cache.insert(fid, out.clone());
        }
        out
    }

    fn expand_full(
        &self,
        text: &str,
        depth: usize,
        visiting: &mut BTreeSet<u32>,
        out: &mut String,
    ) {
        let mut cursor: usize = 0;
        for (start, end, child) in markers(text) {
            out.push_str(&text[cursor..start]);
            cursor = end;
            let allowed: bool = depth < MAX_PROGRAM_DEPTH
                && out.len() < MAX_PROGRAM_BYTES
                && !visiting.contains(&child)
                && (child as usize) < self.templates.len();
            if allowed {
                let indent: String = line_indent(out);
                let mut child_out: String = String::new();
                visiting.insert(child);
                self.expand_full(
                    &self.templates[child as usize],
                    depth + 1,
                    visiting,
                    &mut child_out,
                );
                visiting.remove(&child);
                out.push_str(&child_out.replace('\n', &format!("\n{indent}")));
            } else {
                out.push_str(&placeholder(
                    self.names.get(child as usize).map_or("", String::as_str),
                    child,
                ));
            }
        }
        out.push_str(&text[cursor..]);
    }
}

fn helper_prelude(helpers: &BTreeSet<Helper>) -> String {
    let mut out: String = String::new();
    for helper in helpers {
        out.push_str(helper.definition());
        out.push('\n');
    }
    out
}

fn global_declarations(scope: &ModuleScope) -> String {
    let names: Vec<&str> = scope
        .declared_globals
        .iter()
        .map(String::as_str)
        .filter(|name: &&str| lift::is_binding_identifier(name))
        .collect();
    if names.is_empty() {
        String::new()
    } else {
        format!("var {};\n", names.join(", "))
    }
}

#[must_use]
pub fn decompile_function(module: &HermesModule, index: usize) -> DecompiledFunction {
    decompile_functions(module, index..index.saturating_add(1))
        .pop()
        .unwrap_or_else(|| declined_function(module, index))
}

#[must_use]
pub fn decompile_functions(module: &HermesModule, range: Range<usize>) -> Vec<DecompiledFunction> {
    let Some(specs): Option<&'static [OpcodeSpec]> = lift_specs(module.header.version) else {
        return range
            .map(|index: usize| declined_function(module, index))
            .collect();
    };
    let decode = |i: usize| -> Vec<Instruction> { decode_for_lift(module, i, specs) };
    let scope: ModuleScope = ModuleScope::analyze(module, &decode, false);
    range
        .map(|index: usize| standalone_function(module, &scope, index, specs))
        .collect()
}

fn standalone_function(
    module: &HermesModule,
    scope: &ModuleScope,
    index: usize,
    specs: &'static [OpcodeSpec],
) -> DecompiledFunction {
    let own: Rendered = render_function(module, scope, index, specs);
    let inner: Option<Rendered> = own
        .merged_generator
        .map(|fid: u32| render_function(module, scope, fid as usize, specs));
    let text: String = template(&own, inner.as_ref());
    let mut source: String = String::with_capacity(text.len());
    let mut cursor: usize = 0;
    for (start, end, child) in markers(&text) {
        source.push_str(&text[cursor..start]);
        let name: String = module
            .functions
            .get(child as usize)
            .map_or_else(String::new, |h: &SmallFunctionHeader| {
                function_name(module, h, child as usize)
            });
        source.push_str(&placeholder(&name, child));
        cursor = end;
    }
    source.push_str(&text[cursor..]);
    let mut decompiled: DecompiledFunction = own.decompiled;
    decompiled.source = listing_source(source, &decompiled.name, index);
    decompiled
}

fn listing_source(source: String, name: &str, index: usize) -> String {
    let keyword: &str = if source.starts_with("function*(") {
        "function*"
    } else if source.starts_with("function(") {
        "function"
    } else {
        return source;
    };
    let label: String = if lift::is_binding_identifier(name) {
        name.to_owned()
    } else {
        format!("$func{index}")
    };
    format!("{keyword} {label}{}", &source[keyword.len()..])
}

#[must_use]
pub fn decompile_module(module: &HermesModule) -> DecompileReport {
    decompile_module_with(module, Structuring::Regions)
}

#[must_use]
pub fn decompile_module_with(module: &HermesModule, structuring: Structuring) -> DecompileReport {
    let specs: Option<&'static [OpcodeSpec]> = lift_specs(module.header.version);
    let lift_supported: bool = specs.is_some();
    let histogram_specs: &'static [OpcodeSpec] =
        opcode_specs(module.header.version).unwrap_or(OPCODES_HBC96);
    let mut functions: Vec<DecompiledFunction> = Vec::with_capacity(module.functions.len());
    let mut histogram: OpcodeHistogram = OpcodeHistogram::new();
    let mut program: String = String::new();
    let mut metro_modules: Vec<MetroModule> = Vec::new();
    if let Some(specs) = specs {
        let decode = |i: usize| -> Vec<Instruction> { decode_for_lift(module, i, specs) };
        let mut scope: ModuleScope = ModuleScope::analyze(module, &decode, true);
        scope.structuring = structuring;
        metro_modules.clone_from(&scope.metro_modules);
        let rendered: Vec<Rendered> = (0..module.functions.len())
            .map(|i: usize| render_function(module, &scope, i, specs))
            .collect();
        let mut templates: Vec<String> = rendered
            .iter()
            .map(|own: &Rendered| {
                let inner: Option<&Rendered> = own
                    .merged_generator
                    .and_then(|fid: u32| rendered.get(fid as usize));
                template(own, inner)
            })
            .collect();
        for (index, own) in rendered.iter().enumerate() {
            let name: &str = &own.signature_name;
            if index == scope.global_index as usize
                || name.is_empty()
                || !references_name(&templates, index, name)
            {
                continue;
            }
            let Some(text) = templates.get_mut(index) else {
                continue;
            };
            for keyword in ["function*", "function"] {
                let named: String = format!("{keyword} {name}(");
                if text.starts_with(&named) {
                    *text = format!("({{ {name}: {keyword} ({} }}).{name}", &text[named.len()..]);
                    break;
                }
            }
        }
        let names: Vec<String> = rendered
            .iter()
            .map(|r: &Rendered| r.decompiled.name.clone())
            .collect();
        let mut helpers: BTreeSet<Helper> = BTreeSet::new();
        for r in &rendered {
            helpers.extend(r.helpers.iter().copied());
            histogram.merge(&r.histogram);
        }
        let mut expander: Expander<'_> = Expander {
            templates: &templates,
            names: &names,
            sizes: vec![None; templates.len()],
            cache: BTreeMap::new(),
        };
        let global: usize = scope.global_index as usize;
        let prelude: String = format!(
            "{}{}",
            helper_prelude(&helpers),
            global_declarations(&scope)
        );
        for (index, r) in rendered.into_iter().enumerate() {
            let fid: u32 = u32::try_from(index).unwrap_or(u32::MAX);
            let mut visiting: BTreeSet<u32> = BTreeSet::new();
            let source: String = expander.expand_capped(fid, 0, &mut visiting);
            let mut decompiled: DecompiledFunction = r.decompiled;
            decompiled.source = listing_source(source, &decompiled.name, index);
            functions.push(decompiled);
        }
        if let Some(global_template) = templates.get(global) {
            let anonymous: String = global_template.strip_prefix("function global").map_or_else(
                || global_template.clone(),
                |rest: &str| format!("function {rest}"),
            );
            let mut body: String = String::with_capacity(anonymous.len());
            let mut visiting: BTreeSet<u32> = BTreeSet::new();
            visiting.insert(scope.global_index);
            expander.expand_full(&anonymous, 0, &mut visiting, &mut body);
            program = format!("{prelude}({body}).call(this);\n");
        }
    } else {
        for i in 0..module.functions.len() {
            functions.push(declined_function(module, i));
        }
    }
    let mut total_reconstructed: usize = 0;
    let mut total_fallback: usize = 0;
    let mut with_body: usize = 0;
    let mut structured_functions: usize = 0;
    let mut declines: BTreeMap<StructureDecline, usize> = BTreeMap::new();
    for f in &functions {
        total_reconstructed += f.reconstructed_ops;
        total_fallback += f.fallback_ops;
        if f.instruction_count > 0 {
            with_body += 1;
            if f.structured {
                structured_functions += 1;
            }
        }
        if let Some(reason) = f.structure_decline {
            *declines.entry(reason).or_insert(0) += 1;
        }
    }
    let regexps: Vec<super::regex::RecoveredRegExp> =
        super::regex::recover_regexps(&module.reg_exp_table, &module.reg_exp_storage);
    DecompileReport {
        hermes_version: module.header.version,
        lift_supported,
        function_count: module.functions.len(),
        functions_with_body: with_body,
        total_reconstructed_ops: total_reconstructed,
        total_fallback_ops: total_fallback,
        total_unaccounted_ops: 0,
        structured_functions,
        structure_declines: declines
            .into_iter()
            .map(
                |(reason, functions): (StructureDecline, usize)| DeclineCount { reason, functions },
            )
            .collect(),
        reconstructed_opcodes: histogram
            .counts(|tally: &OpcodeTally| tally.reconstructed, histogram_specs),
        declined_opcodes: histogram.counts(|tally: &OpcodeTally| tally.declined, histogram_specs),
        unaccounted_opcodes: histogram
            .counts(|tally: &OpcodeTally| tally.unaccounted, histogram_specs),
        functions,
        regexps,
        program,
        metro_modules,
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
    use crate::hermes::{HERMES_LIFT_VERSION, HERMES_MAGIC, HermesHeader, HermesStringKind};

    fn opcode_byte(name: &str) -> u8 {
        OPCODES_HBC96
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
            obj_shape_table_count: 0,
            string_switch_imm_count: 0,
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
            kind: HermesFunctionKind::Normal,
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
            obj_shape_table: Vec::new(),
            big_int_table: Vec::new(),
            big_int_storage: Vec::new(),
            reg_exp_table: Vec::new(),
            reg_exp_storage: Vec::new(),
            raw_image: code,
        }
    }

    #[test]
    fn opcode_table_anchors() {
        assert_eq!(OPCODES_HBC96[0].name, "Unreachable");
        assert_eq!(opcode_byte("Add"), 22);
        assert_eq!(opcode_byte("Ret"), 92);
        assert_eq!(opcode_byte("LoadParam"), 108);
        assert_eq!(opcode_byte("GetByIdShort"), 54);
        assert_eq!(opcode_byte("Jmp"), 142);
        assert_eq!(opcode_byte("JStrictNotEqualLong"), 191);
        assert_eq!(OPCODES_HBC96.len(), 192);
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
        code.push(opcode_byte("JNotLess"));
        let after_target: i8 = 6;
        code.push(after_target as u8);
        code.extend_from_slice(&[1u8, 2u8]);
        code.push(opcode_byte("Ret"));
        code.push(1u8);
        code.push(opcode_byte("Ret"));
        code.push(2u8);
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
        let instructions: Vec<Instruction> = decode_instructions(&code, OPCODES_HBC96);
        let cfg: Cfg = build_cfg(&instructions, &code, 0, &[]);
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
            f.source.contains("$unrecovered(\"call\""),
            "a call whose argument window cannot fit the frame is refused by name; src: {}",
            f.source
        );
        assert_eq!(f.fallback_ops, 1, "src: {}", f.source);
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
        assert!(
            f.source.contains("$unrecovered(\"ConstructLong\""),
            "src: {}",
            f.source
        );
    }

    #[test]
    fn truncated_operand_stream_terminates() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("CallLong"));
        code.push(1u8);
        let instructions: Vec<Instruction> = decode_instructions(&code, OPCODES_HBC96);
        assert_eq!(instructions.len(), 1);
        assert!(instructions[0].name.ends_with("<truncated>"));
    }

    #[test]
    fn unknown_opcode_run_decodes_in_bounded_time() {
        let code: Vec<u8> = vec![0xffu8; 100_000];
        let instructions: Vec<Instruction> = decode_instructions(&code, OPCODES_HBC96);
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
        let instructions: Vec<Instruction> = decode_instructions(&code, OPCODES_HBC96);
        let target: usize = match instructions[0].operands.first() {
            Some(OperandValue::Target(t)) => *t,
            other => panic!("expected target operand, got {other:?}"),
        };
        assert_eq!(target, 0);
        let cfg: Cfg = build_cfg(&instructions, &code, 0, &[]);
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
            f.source.contains("$getTemplateObject("),
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
            f.source.contains("c0_3 = 42;"),
            "expected captured-var store; src: {}",
            f.source
        );
        assert!(
            f.source.contains("return c0_3;"),
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
            f.source.contains("return $envUp2_5;"),
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
            f.source.contains("arg0[Symbol.iterator]()") && f.source.contains(" = r3.value;"),
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
            f.source.contains("for (var $key in arg0)"),
            "expected for-in prop list; src: {}",
            f.source
        );
        assert_eq!(f.fallback_ops, 0, "src: {}", f.source);
    }

    #[test]
    fn the_opcode_histogram_accounts_for_every_decoded_instruction() {
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
        let report: DecompileReport = decompile_module(&module);
        let instructions: usize = report
            .functions
            .iter()
            .map(|f: &DecompiledFunction| f.instruction_count)
            .sum();
        assert_eq!(instructions, 4);
        assert_eq!(
            report.total_reconstructed_ops
                + report.total_fallback_ops
                + report.total_unaccounted_ops,
            instructions,
            "every decoded instruction lands in exactly one column, so a lifting rule that silently \
             counts nothing cannot inflate the coverage ratio"
        );
        assert!(report.declined_opcodes.is_empty());
        assert!(report.unaccounted_opcodes.is_empty());
        let named: Vec<&str> = report
            .reconstructed_opcodes
            .iter()
            .map(|count: &OpcodeCount| count.opcode.as_str())
            .collect();
        assert_eq!(named, ["LoadParam", "Add", "Ret"]);
        assert_eq!(
            report.reconstructed_opcodes[0].occurrences, 2,
            "the histogram is ordered by descending occurrences so the long tail reads from the end"
        );
    }

    #[test]
    fn an_opcode_outside_the_table_is_named_by_its_byte_and_counted_as_declined() {
        let unknown: u8 =
            u8::try_from(OPCODES_HBC96.len()).expect("the table is shorter than 256 entries");
        let code: Vec<u8> = vec![unknown, opcode_byte("Ret"), 0u8];
        let module: HermesModule = module_with(&["odd"], &[], code, 1);
        let report: DecompileReport = decompile_module(&module);
        assert_eq!(
            report.declined_opcodes,
            vec![OpcodeCount {
                opcode: format!("Unknown_0x{unknown:02x}"),
                occurrences: 1,
            }],
            "an opcode the table does not carry must be enumerated by its byte rather than vanish \
             from the report"
        );
        assert_eq!(report.total_fallback_ops, 1);
        assert_eq!(report.total_unaccounted_ops, 0);
    }

    fn loop_module(shape: &str) -> HermesModule {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("LoadParam"));
        code.extend_from_slice(&[1u8, 1u8]);
        code.push(opcode_byte("LoadConstZero"));
        code.push(0u8);
        match shape {
            "head-test" => {
                code.push(opcode_byte("JNotLess"));
                code.extend_from_slice(&[9u8, 0u8, 1u8]);
                code.push(opcode_byte("Inc"));
                code.extend_from_slice(&[0u8, 0u8]);
                code.push(opcode_byte("Jmp"));
                code.push(0xf9u8);
            }
            "tail-test" => {
                code.push(opcode_byte("Inc"));
                code.extend_from_slice(&[0u8, 0u8]);
                code.push(opcode_byte("JNotLess"));
                code.extend_from_slice(&[6u8, 0u8, 1u8]);
                code.push(opcode_byte("Jmp"));
                code.push(0xf9u8);
            }
            _ => {
                code.push(opcode_byte("Inc"));
                code.extend_from_slice(&[0u8, 0u8]);
                code.push(opcode_byte("JNotLess"));
                code.extend_from_slice(&[9u8, 0u8, 1u8]);
                code.push(opcode_byte("Inc"));
                code.extend_from_slice(&[0u8, 0u8]);
                code.push(opcode_byte("Jmp"));
                code.push(0xf6u8);
            }
        }
        code.push(opcode_byte("Ret"));
        code.push(0u8);
        module_with(&["counted"], &[], code, 2)
    }

    #[test]
    fn a_head_tested_loop_recovers_as_a_while_loop() {
        let module: HermesModule = loop_module("head-test");
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert_eq!(f.structure_decline, None, "src: {}", f.source);
        assert!(
            f.source.contains("while (r0 < arg0) {"),
            "a loop whose only exit test sits at the header is a while loop, so that is the form \
             recovery must produce rather than an infinite loop with an inner break; src: {}",
            f.source
        );
        assert!(
            !f.source.contains("for (;;)") && !f.source.contains("break;"),
            "the unsugared infinite-loop form must not survive when the guard is recoverable; \
             src: {}",
            f.source
        );
        assert_eq!(f.fallback_ops, 0, "src: {}", f.source);
    }

    #[test]
    fn a_tail_tested_loop_recovers_as_a_do_while_loop() {
        let module: HermesModule = loop_module("tail-test");
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert_eq!(f.structure_decline, None, "src: {}", f.source);
        assert!(
            f.source.contains("do {") && f.source.contains("} while (r0 < arg0);"),
            "a loop whose only exit test sits after the body is a do-while; src: {}",
            f.source
        );
        assert!(!f.source.contains("for (;;)"), "src: {}", f.source);
        assert_eq!(f.fallback_ops, 0, "src: {}", f.source);
    }

    #[test]
    fn a_mid_tested_loop_stays_an_infinite_loop_with_a_named_break() {
        let module: HermesModule = loop_module("mid-test");
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert_eq!(f.structure_decline, None, "src: {}", f.source);
        assert!(
            f.source.contains("for (;;) {") && f.source.contains("break;"),
            "a loop whose exit test sits between two halves of the body is neither a while nor a \
             do-while, so it must keep the infinite-loop form with an explicit break rather than \
             be resugared into a guard it does not have; src: {}",
            f.source
        );
        assert!(
            !f.source.contains("while (r0 < arg0) {"),
            "resugaring this shape into a head guard would drop the pre-test half of the body; \
             src: {}",
            f.source
        );
        assert_eq!(f.fallback_ops, 0, "src: {}", f.source);
    }

    #[test]
    fn decompile_generator_function() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("StartGenerator"));
        code.push(opcode_byte("ResumeGenerator"));
        code.extend_from_slice(&[0u8, 1u8]);
        code.push(opcode_byte("JmpTrue"));
        code.extend_from_slice(&[19u8, 1u8]);
        code.push(opcode_byte("LoadConstUInt8"));
        code.extend_from_slice(&[2u8, 1u8]);
        code.push(opcode_byte("SaveGenerator"));
        code.push(4u8);
        code.push(opcode_byte("Ret"));
        code.push(2u8);
        code.push(opcode_byte("ResumeGenerator"));
        code.extend_from_slice(&[3u8, 4u8]);
        code.push(opcode_byte("JmpTrue"));
        code.extend_from_slice(&[9u8, 4u8]);
        code.push(opcode_byte("CompleteGenerator"));
        code.push(opcode_byte("Ret"));
        code.push(3u8);
        code.push(opcode_byte("CompleteGenerator"));
        code.push(opcode_byte("Ret"));
        code.push(0u8);
        code.push(opcode_byte("CompleteGenerator"));
        code.push(opcode_byte("Ret"));
        code.push(3u8);
        let module: HermesModule = module_with(&["gen"], &[], code, 1);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(f.is_generator, "expected generator flag; src: {}", f.source);
        assert!(
            f.source.contains("function* gen("),
            "expected function* keyword; src: {}",
            f.source
        );
        assert!(
            f.source.contains("r3 = yield 1;") && f.source.contains("return r3;"),
            "the save/return/resume triple is one yield whose sent value lands in the resume \
             register; src: {}",
            f.source
        );
        assert_eq!(
            f.fallback_ops, 0,
            "StartGenerator and CompleteGenerator carry no statement of their own and a resume \
             whose return request only returns is the native yield; src: {}",
            f.source
        );
        assert!(
            !f.source.contains("StartGenerator") && !f.source.contains("Resume"),
            "a raw opcode mnemonic is not JavaScript; src: {}",
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
            f.source.contains("{ __proto__: arg0 }"),
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
        for k in 0i32..3 {
            let rel: i32 = 200 + k * 4 - switch_off as i32;
            code.extend_from_slice(&rel.to_le_bytes());
        }
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
        let instructions: Vec<Instruction> = decode_instructions(&code, OPCODES_HBC96);
        assert_eq!(instructions.len(), MAX_DECODED_INSTRUCTIONS);
    }

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
            "c0_2 = arg0;",
            "[Symbol.iterator]()",
            ".call(r2)",
            "delete r1[",
        ] {
            assert!(
                f.source.contains(expected),
                "expected `{expected}` in recovered source; src: {}",
                f.source
            );
        }
    }

    #[test]
    fn structured_counted_loop_recovers_a_loop_keyword() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("LoadParam"));
        code.extend_from_slice(&[1u8, 1u8]);
        code.push(opcode_byte("LoadConstZero"));
        code.push(0u8);
        code.push(opcode_byte("JNotLess"));
        code.extend_from_slice(&[9u8, 0u8, 1u8]);
        code.push(opcode_byte("Inc"));
        code.extend_from_slice(&[0u8, 0u8]);
        code.push(opcode_byte("Jmp"));
        code.push((-7i8) as u8);
        code.push(opcode_byte("Ret"));
        code.push(0u8);
        let module: HermesModule = module_with(&["counted"], &[], code, 2);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(
            f.structured,
            "declined: {:?}; src: {}",
            f.structure_decline, f.source
        );
        assert!(
            f.source.contains("while (") || f.source.contains("for (;;)"),
            "counted loop must recover a loop keyword; src: {}",
            f.source
        );
        assert!(
            !f.source.contains("goto "),
            "a structured body carries no goto edges; src: {}",
            f.source
        );
    }

    #[test]
    fn structured_branch_recovers_an_if_without_goto_edges() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("LoadParam"));
        code.extend_from_slice(&[1u8, 1u8]);
        code.push(opcode_byte("LoadConstZero"));
        code.push(2u8);
        code.push(opcode_byte("JNotLess"));
        code.extend_from_slice(&[6u8, 1u8, 2u8]);
        code.push(opcode_byte("Ret"));
        code.push(1u8);
        code.push(opcode_byte("Ret"));
        code.push(2u8);
        let module: HermesModule = module_with(&["cmp"], &[], code, 2);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(
            f.structured,
            "declined: {:?}; src: {}",
            f.structure_decline, f.source
        );
        assert!(f.source.contains("if ("), "src: {}", f.source);
        assert!(
            !f.source.contains("goto "),
            "a structured body carries no goto edges; src: {}",
            f.source
        );
    }

    fn switch_imm_fixture(code_base: usize) -> Vec<u8> {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("LoadParam"));
        code.extend_from_slice(&[1u8, 1u8]);
        let switch_at: i64 = code.len() as i64;
        code.push(opcode_byte("SwitchImm"));
        code.push(1u8);
        code.extend_from_slice(&30u32.to_le_bytes());
        code.extend_from_slice(&28i32.to_le_bytes());
        code.extend_from_slice(&0u32.to_le_bytes());
        code.extend_from_slice(&1u32.to_le_bytes());
        code.push(opcode_byte("LoadConstUInt8"));
        code.extend_from_slice(&[0u8, 10u8]);
        code.push(opcode_byte("Jmp"));
        code.push(7u8);
        code.push(opcode_byte("LoadConstUInt8"));
        code.extend_from_slice(&[0u8, 20u8]);
        code.push(opcode_byte("Jmp"));
        code.push(2u8);
        code.push(opcode_byte("Ret"));
        code.push(0u8);
        while (code_base + code.len()) % 4 != 0 {
            code.push(opcode_byte("Debugger"));
        }
        for target in [21i64, 26] {
            let rel: i32 = (target - switch_at) as i32;
            code.extend_from_slice(&rel.to_le_bytes());
        }
        code
    }

    #[test]
    fn switch_imm_case_targets_become_block_leaders() {
        for code_base in [0usize, 1, 2, 3, 0x4f5] {
            let code: Vec<u8> = switch_imm_fixture(code_base);
            let mut image: Vec<u8> = vec![0u8; code_base];
            image.extend_from_slice(&code);
            let instructions: Vec<Instruction> = decode_instructions(&code, OPCODES_HBC96);
            let cfg: Cfg = build_cfg(&instructions, &image, code_base, &[]);
            for leader in [21usize, 26, 31] {
                assert!(
                    cfg.offset_to_block.contains_key(&leader),
                    "code base {code_base:#x}: switch edge {leader:#x} must start a block. The \
                     jump table is aligned at its absolute position in the bytecode, so a decoder \
                     that aligns the function-relative offset instead reads a table of garbage for \
                     every function whose code does not begin on a four byte boundary; leaders: \
                     {:?}",
                    cfg.offset_to_block.keys().collect::<Vec<&usize>>()
                );
            }
            let switch_block: usize = cfg.offset_to_block[&0];
            assert_eq!(
                cfg.blocks[switch_block].successors.len(),
                3,
                "code base {code_base:#x}: two case targets plus the default are three edges; got \
                 {:?}",
                cfg.blocks[switch_block].successors
            );
        }
    }

    #[test]
    fn structured_switch_imm_recovers_a_switch_statement() {
        let module: HermesModule = module_with(&["dispatch"], &[], switch_imm_fixture(0), 2);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(
            f.structured,
            "declined: {:?}; src: {}",
            f.structure_decline, f.source
        );
        for expected in ["switch (", "case 0:", "case 1:", "default:", "break;"] {
            assert!(
                f.source.contains(expected),
                "expected `{expected}`; src: {}",
                f.source
            );
        }
        assert!(
            !f.source.contains("goto "),
            "a structured switch carries no goto edges; src: {}",
            f.source
        );
    }

    #[test]
    fn irreducible_control_flow_is_declined_by_name() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("LoadParam"));
        code.extend_from_slice(&[1u8, 1u8]);
        code.push(opcode_byte("JmpTrue"));
        code.extend_from_slice(&[8u8, 1u8]);
        code.push(opcode_byte("Inc"));
        code.extend_from_slice(&[0u8, 0u8]);
        code.push(opcode_byte("Jmp"));
        code.push(2u8);
        code.push(opcode_byte("JmpTrue"));
        code.extend_from_slice(&[5u8, 1u8]);
        code.push(opcode_byte("Jmp"));
        code.push((-8i8) as u8);
        code.push(opcode_byte("Ret"));
        code.push(0u8);
        let module: HermesModule = module_with(&["twoentry"], &[], code, 2);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert_eq!(
            f.structure_decline,
            Some(StructureDecline::Irreducible),
            "a two-entry cycle must be declined by name; src: {}",
            f.source
        );
        assert!(!f.structured);
        assert!(
            f.source.contains("unstructured (irreducible)"),
            "a declined body must say so rather than read as JavaScript; src: {}",
            f.source
        );
    }

    #[test]
    fn a_bytecode_version_without_an_opcode_table_is_declined_by_number() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("LoadParam"));
        code.extend_from_slice(&[1u8, 1u8]);
        code.push(opcode_byte("Ret"));
        code.push(1u8);
        let mut module: HermesModule = module_with(&["add"], &[], code, 2);
        let uncovered: u32 = 87;
        assert!(!HERMES_LIFTED_VERSIONS.contains(&uncovered));
        module.header.version = uncovered;
        let report: DecompileReport = decompile_module(&module);
        assert!(!report.lift_supported);
        assert_eq!(report.function_count, 1);
        assert_eq!(report.functions_with_body, 0);
        assert_eq!(report.total_reconstructed_ops, 0);
        assert_eq!(report.total_fallback_ops, 0);
        assert_eq!(report.structured_functions, 0);
        assert_eq!(
            report.functions[0].structure_decline,
            Some(StructureDecline::UnsupportedBytecodeVersion)
        );
        assert!(
            report.functions[0].source.contains("hbc v87")
                && report.functions[0].source.contains("not lifted"),
            "a version the opcode table does not cover states so; src: {}",
            report.functions[0].source
        );
        assert_eq!(report.functions[0].name, "add", "names still resolve");

        module.header.version = HERMES_LIFT_VERSION;
        let lifted: DecompileReport = decompile_module(&module);
        assert!(lifted.lift_supported);
        assert_eq!(lifted.functions_with_body, 1);
        assert_eq!(lifted.structured_functions, 1);
        assert!(lifted.structure_declines.is_empty());
    }

    #[test]
    fn the_call_window_sits_where_the_frame_layout_puts_it() {
        assert_eq!(lift::call_window(36, 3), Some(vec![29, 28, 27]));
        assert_eq!(lift::call_window(17, 2), Some(vec![10, 9]));
        assert_eq!(lift::call_window(15, 1), Some(vec![8]));
        assert_eq!(lift::call_window(15, 0), None);
        for frame_size in 0u32..7 {
            assert_eq!(lift::call_window(frame_size, 1), None);
        }
        assert_eq!(lift::call_window(9, 4), None);
        assert!(lift::call_window(u32::MAX, 4097).is_none());
        assert_eq!(
            lift::call_window(u32::MAX, 4096).map(|w: Vec<u32>| w.len()),
            Some(4096)
        );
    }

    #[test]
    fn an_oversized_literal_count_follows_the_decoded_buffer() {
        let mut array_buffer: Vec<u8> = Vec::new();
        array_buffer.push(0x70 | 1);
        array_buffer.extend_from_slice(&7i32.to_le_bytes());
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("NewArrayWithBuffer"));
        code.push(0u8);
        code.extend_from_slice(&u16::MAX.to_le_bytes());
        code.extend_from_slice(&u16::MAX.to_le_bytes());
        code.extend_from_slice(&0u16.to_le_bytes());
        code.push(opcode_byte("Ret"));
        code.push(0u8);
        let module: HermesModule =
            module_with_buffers(&["a"], &[], code, 1, Vec::new(), Vec::new(), array_buffer);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(f.source.contains("return [7];"), "src: {}", f.source);
        assert!(f.source.len() < 512, "src bytes: {}", f.source.len());
    }

    #[test]
    fn a_call_with_a_frame_window_recovers_this_and_every_argument() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("LoadParam"));
        code.extend_from_slice(&[0u8, 1u8]);
        code.push(opcode_byte("LoadConstUndefined"));
        code.push(9u8);
        code.push(opcode_byte("LoadConstUInt8"));
        code.extend_from_slice(&[8u8, 4u8]);
        code.push(opcode_byte("LoadConstUInt8"));
        code.extend_from_slice(&[7u8, 5u8]);
        code.push(opcode_byte("Call"));
        code.extend_from_slice(&[1u8, 0u8, 3u8]);
        code.push(opcode_byte("Ret"));
        code.push(1u8);
        let module: HermesModule = module_with(&["f"], &[], code, 2);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert!(f.source.contains("return arg0(4, 5);"), "src: {}", f.source);
        assert_eq!(f.fallback_ops, 0, "src: {}", f.source);
    }

    #[test]
    fn a_construct_without_its_create_this_pair_is_declined_by_name() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("GetGlobalObject"));
        code.push(0u8);
        code.push(opcode_byte("Construct"));
        code.extend_from_slice(&[1u8, 0u8, 1u8]);
        code.push(opcode_byte("Ret"));
        code.push(1u8);
        let module: HermesModule = module_with(&["main"], &[], code, 1);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert_eq!(f.fallback_ops, 1, "src: {}", f.source);
        assert!(
            f.source.contains("$unrecovered(\"Construct\""),
            "src: {}",
            f.source
        );
    }

    #[test]
    fn a_direct_call_is_declined_by_name_rather_than_guessed() {
        let mut code: Vec<u8> = Vec::new();
        code.push(opcode_byte("LoadConstUndefined"));
        code.push(9u8);
        code.push(opcode_byte("CallDirect"));
        code.push(0u8);
        code.push(1u8);
        code.extend_from_slice(&0u16.to_le_bytes());
        code.push(opcode_byte("Ret"));
        code.push(0u8);
        let module: HermesModule = module_with(&["main"], &[], code, 1);
        let f: DecompiledFunction = decompile_function(&module, 0);
        assert_eq!(f.fallback_ops, 1, "src: {}", f.source);
        assert!(
            f.source.contains("$unrecovered(\"CallDirect\""),
            "src: {}",
            f.source
        );
    }

    #[test]
    fn only_the_documented_opcodes_decline_when_lifted_alone() {
        const DECLINED_BY_DESIGN: &[&str] = &[
            "Unreachable",
            "CreateInnerEnvironment",
            "CreateThis",
            "SelectObject",
            "Construct",
            "ConstructLong",
            "CallDirect",
            "CallDirectLongIndex",
            "ProfilePoint",
            "ResumeGenerator",
            "GetBuiltinClosure",
            "CallBuiltin",
            "CallBuiltinLong",
        ];
        const DECLINED_ON_ZEROED_OPERANDS: &[&str] = &[
            "StoreToEnvironment",
            "StoreToEnvironmentL",
            "StoreNPToEnvironment",
            "StoreNPToEnvironmentL",
            "LoadFromEnvironment",
            "LoadFromEnvironmentL",
            "Call",
            "CallLong",
            "LoadConstBigInt",
            "LoadConstBigIntLongIndex",
            "SaveGenerator",
            "SaveGeneratorLong",
        ];
        let mut declined: Vec<&str> = Vec::new();
        for (byte, spec) in OPCODES_HBC96.iter().enumerate() {
            let mut code: Vec<u8> = vec![u8::try_from(byte).expect("the table has 192 rows")];
            for operand in spec.operands {
                code.extend(std::iter::repeat_n(0u8, operand.width()));
            }
            code.push(opcode_byte("Ret"));
            code.push(0u8);
            let module: HermesModule = module_with(&["probe"], &["s"], code, 1);
            let f: DecompiledFunction = decompile_function(&module, 0);
            if f.fallback_ops > 0 {
                declined.push(spec.name);
            }
        }
        let unexpected: Vec<&&str> = declined
            .iter()
            .filter(|name: &&&str| {
                !DECLINED_BY_DESIGN.contains(name) && !DECLINED_ON_ZEROED_OPERANDS.contains(name)
            })
            .collect();
        assert!(
            unexpected.is_empty(),
            "only the opcodes the lifter refuses by design, or whose zeroed operands name no \
             environment, no argument window, no bigint entry or no resume point, may decline \
             when lifted alone; unexpected {unexpected:?}"
        );
    }
}
