use std::collections::{BTreeMap, BTreeSet};

use disrobe_nir::{NirBlock, NirInstr, NirOp, ValueOp};

use super::types::CffAbstain;

pub(crate) const MIN_CASES: usize = 3;
pub(crate) const MIN_INDEGREE: usize = 3;
pub(crate) const MAX_CFF_BLOCKS: usize = 4_096;
pub(crate) const MAX_REGION_NODES: u32 = 512;
const SLICE_DEPTH: u32 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SvWidth {
    bits: u32,
}

impl SvWidth {
    pub(crate) const QWORD: Self = Self { bits: 64 };

    pub(crate) const fn from_bytes(bytes: u32) -> Option<Self> {
        match bytes {
            1..=8 => Some(Self { bits: bytes * 8 }),
            _ => None,
        }
    }

    pub(crate) const fn bits(self) -> u32 {
        self.bits
    }

    pub(crate) const fn mask(self) -> u64 {
        if self.bits >= 64 {
            u64::MAX
        } else {
            (1u64 << self.bits) - 1
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Plan {
    pub(crate) head: u64,
    pub(crate) entry_block: u64,
    pub(crate) state_var: String,
    pub(crate) sv_width: SvWidth,
    pub(crate) casemap: BTreeMap<u64, u64>,
    pub(crate) scaffolding: BTreeSet<u64>,
}

pub(crate) fn detect(
    blocks: &BTreeMap<u64, NirBlock>,
    entry_block: u64,
) -> Result<Plan, CffAbstain> {
    let mut indegree: BTreeMap<u64, usize> = blocks.keys().map(|start: &u64| (*start, 0)).collect();
    for block in blocks.values() {
        for successor in &block.successors {
            if let Some(count) = indegree.get_mut(successor) {
                *count = count.saturating_add(1);
            }
        }
    }
    let mut head: Option<(u64, usize)> = None;
    for (&start, block) in blocks {
        if classify_compare(block).is_none() {
            continue;
        }
        let degree: usize = indegree.get(&start).copied().unwrap_or(0);
        if degree < MIN_INDEGREE {
            continue;
        }
        match head {
            Some((_, best)) if best >= degree => {}
            Some(_) | None => head = Some((start, degree)),
        }
    }
    let Some((head, _)): Option<(u64, usize)> = head else {
        return Err(CffAbstain::DispatcherNotFound);
    };
    let chain: ChainResult = follow_chain(blocks, head)?;
    if chain.casemap.len() < MIN_CASES {
        return Err(CffAbstain::CaseMapTooSmall);
    }
    let writing: usize = chain
        .casemap
        .values()
        .filter(|target: &&u64| {
            region_writes_sv(blocks, **target, head, &chain.case_heads, &chain.state_var)
        })
        .count();
    if writing < 2 || writing.saturating_mul(2) < chain.casemap.len() {
        return Err(CffAbstain::NotFlattened);
    }
    let mut scaffolding: BTreeSet<u64> = chain.blocks.clone();
    if !chain.case_heads.contains(&entry_block) {
        scaffolding.insert(entry_block);
    }
    Ok(Plan {
        head,
        entry_block,
        state_var: chain.state_var,
        sv_width: chain.sv_width,
        casemap: chain.casemap,
        scaffolding,
    })
}

#[derive(Debug)]
struct ChainResult {
    state_var: String,
    sv_width: SvWidth,
    casemap: BTreeMap<u64, u64>,
    case_heads: BTreeSet<u64>,
    blocks: BTreeSet<u64>,
}

fn follow_chain(blocks: &BTreeMap<u64, NirBlock>, head: u64) -> Result<ChainResult, CffAbstain> {
    let mut casemap: BTreeMap<u64, u64> = BTreeMap::new();
    let mut chain_blocks: BTreeSet<u64> = BTreeSet::new();
    let mut sv_root: Option<String> = None;
    let mut sv_width: Option<SvWidth> = None;
    let mut cursor: u64 = head;
    for _ in 0..blocks.len().saturating_add(1) {
        if !chain_blocks.insert(cursor) {
            break;
        }
        let Some(block): Option<&NirBlock> = blocks.get(&cursor) else {
            break;
        };
        let Some(info): Option<CompareInfo> = classify_compare(block) else {
            chain_blocks.remove(&cursor);
            break;
        };
        match &sv_root {
            Some(root) if *root != info.sv_root => return Err(CffAbstain::StateVarNotUnique),
            Some(_) => {}
            None => {
                sv_root = Some(info.sv_root.clone());
                sv_width = Some(info.width);
            }
        }
        if casemap.insert(info.c, info.case_target).is_some() {
            break;
        }
        cursor = info.continue_target;
        if chain_blocks.contains(&cursor) {
            break;
        }
    }
    let (Some(state_var), Some(width)): (Option<String>, Option<SvWidth>) = (sv_root, sv_width)
    else {
        return Err(CffAbstain::DispatcherNotFound);
    };
    let case_heads: BTreeSet<u64> = casemap.values().copied().collect();
    Ok(ChainResult {
        state_var,
        sv_width: width,
        casemap,
        case_heads,
        blocks: chain_blocks,
    })
}

#[derive(Debug)]
struct CompareInfo {
    sv_root: String,
    c: u64,
    case_target: u64,
    continue_target: u64,
    width: SvWidth,
}

fn classify_compare(block: &NirBlock) -> Option<CompareInfo> {
    let terminator: &NirInstr = block.instructions.last()?;
    let NirOp::CondBranch {
        target: Some(taken),
    } = &terminator.op
    else {
        return None;
    };
    let taken: u64 = *taken;
    if !block.successors.contains(&taken) {
        return None;
    }
    let cond: &str = terminator.operands.first()?.trim();
    let defs: BTreeMap<&str, &NirInstr> = block_defs(block);
    let (equal, lhs, rhs, width): (bool, String, String, SvWidth) = trace_compare(&defs, cond)?;
    let continue_target: u64 = block
        .successors
        .iter()
        .copied()
        .find(|s: &u64| *s != taken)?;
    let (constant, variable): (u64, String) = split_const(&lhs, &rhs, width)?;
    let sv_root: String = slice_root(&defs, &variable)?;
    let (case_target, next): (u64, u64) = if equal {
        (taken, continue_target)
    } else {
        (continue_target, taken)
    };
    Some(CompareInfo {
        sv_root,
        c: constant,
        case_target,
        continue_target: next,
        width,
    })
}

pub(crate) fn block_defs(block: &NirBlock) -> BTreeMap<&str, &NirInstr> {
    let mut defs: BTreeMap<&str, &NirInstr> = BTreeMap::new();
    for instr in &block.instructions {
        if let Some(name) = dest_name(instr) {
            defs.insert(name, instr);
        }
    }
    defs
}

fn trace_compare(
    defs: &BTreeMap<&str, &NirInstr>,
    name: &str,
) -> Option<(bool, String, String, SvWidth)> {
    let mut cursor: String = name.trim().to_owned();
    for _ in 0..SLICE_DEPTH {
        let instr: &&NirInstr = defs.get(cursor.as_str())?;
        match &instr.op {
            NirOp::Value {
                op: ValueOp::IntEqual,
                inputs,
                input_sizes,
                ..
            } if inputs.len() == 2 => {
                let width: SvWidth = input_sizes
                    .first()
                    .copied()
                    .and_then(SvWidth::from_bytes)
                    .unwrap_or(SvWidth::QWORD);
                return Some((true, inputs[0].clone(), inputs[1].clone(), width));
            }
            NirOp::Value {
                op: ValueOp::IntNotEqual,
                inputs,
                input_sizes,
                ..
            } if inputs.len() == 2 => {
                let width: SvWidth = input_sizes
                    .first()
                    .copied()
                    .and_then(SvWidth::from_bytes)
                    .unwrap_or(SvWidth::QWORD);
                return Some((false, inputs[0].clone(), inputs[1].clone(), width));
            }
            NirOp::Copy { src, .. } => src.trim().clone_into(&mut cursor),
            NirOp::Value {
                op: ValueOp::BoolNegate,
                inputs,
                ..
            } if inputs.len() == 1 => {
                let (equal, lhs, rhs, width): (bool, String, String, SvWidth) =
                    trace_compare(defs, inputs[0].trim())?;
                return Some((!equal, lhs, rhs, width));
            }
            _ => return None,
        }
    }
    None
}

fn split_const(lhs: &str, rhs: &str, width: SvWidth) -> Option<(u64, String)> {
    let lhs_const: Option<u64> = parse_immediate(lhs.trim(), width.mask());
    let rhs_const: Option<u64> = parse_immediate(rhs.trim(), width.mask());
    match (lhs_const, rhs_const) {
        (Some(_), Some(_)) | (None, None) => None,
        (Some(value), None) => Some((value, rhs.trim().to_owned())),
        (None, Some(value)) => Some((value, lhs.trim().to_owned())),
    }
}

fn slice_root(defs: &BTreeMap<&str, &NirInstr>, name: &str) -> Option<String> {
    let mut cursor: String = name.trim().to_owned();
    for _ in 0..SLICE_DEPTH {
        if parse_immediate(&cursor, u64::MAX).is_some() {
            return None;
        }
        let Some(instr): Option<&&NirInstr> = defs.get(cursor.as_str()) else {
            return Some(cursor);
        };
        match &instr.op {
            NirOp::Copy { src, .. } | NirOp::Subpiece { src, .. } => {
                src.trim().clone_into(&mut cursor);
            }
            NirOp::Value {
                op: ValueOp::IntZext | ValueOp::IntSext,
                inputs,
                ..
            } if inputs.len() == 1 => inputs[0].trim().clone_into(&mut cursor),
            NirOp::RawLoad { .. } | NirOp::Load => return None,
            _ => return Some(cursor),
        }
    }
    None
}

fn region_writes_sv(
    blocks: &BTreeMap<u64, NirBlock>,
    start: u64,
    stop: u64,
    case_heads: &BTreeSet<u64>,
    state_var: &str,
) -> bool {
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    let mut stack: Vec<u64> = vec![start];
    while let Some(current) = stack.pop() {
        if current == stop || !seen.insert(current) {
            continue;
        }
        if current != start && case_heads.contains(&current) {
            continue;
        }
        let Some(block): Option<&NirBlock> = blocks.get(&current) else {
            continue;
        };
        if block
            .instructions
            .iter()
            .any(|instr: &NirInstr| dest_is(instr, state_var))
        {
            return true;
        }
        for successor in &block.successors {
            stack.push(*successor);
        }
    }
    false
}

pub(crate) fn dest_is(instr: &NirInstr, name: &str) -> bool {
    dest_name(instr).is_some_and(|dest: &str| dest == name.trim())
}

pub(crate) fn dest_name(instr: &NirInstr) -> Option<&str> {
    match &instr.op {
        NirOp::Deposit { cell, .. } => Some(cell.trim()),
        NirOp::Const
        | NirOp::BinOp { .. }
        | NirOp::Load
        | NirOp::Phi
        | NirOp::Copy { .. }
        | NirOp::Subpiece { .. }
        | NirOp::Value { .. }
        | NirOp::Piece { .. }
        | NirOp::RawLoad { .. } => instr.operands.first().map(|name: &String| name.trim()),
        NirOp::Nop
        | NirOp::Store
        | NirOp::RawStore { .. }
        | NirOp::Call { .. }
        | NirOp::IndirectCall
        | NirOp::ExternCall { .. }
        | NirOp::NoReturnCall { .. }
        | NirOp::TailCall { .. }
        | NirOp::CallOther { .. }
        | NirOp::Branch { .. }
        | NirOp::CondBranch { .. }
        | NirOp::Return
        | NirOp::Interrupt
        | NirOp::Unmodeled { .. } => None,
    }
}

pub(crate) fn parse_immediate(operand: &str, mask: u64) -> Option<u64> {
    let trimmed: &str = operand.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (negative, body): (bool, &str) = trimmed
        .strip_prefix('-')
        .map_or((false, trimmed), |rest: &str| (true, rest));
    let hex: Option<&str> = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X"));
    let (radix, digits): (u32, &str) = hex.map_or((10, body), |rest: &str| (16, rest));
    let magnitude: u64 = u64::from_str_radix(digits, radix).ok()?;
    let value: u64 = if negative {
        magnitude.wrapping_neg()
    } else {
        magnitude
    };
    Some(value & mask)
}
