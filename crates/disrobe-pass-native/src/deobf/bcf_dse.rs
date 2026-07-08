use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use disrobe_mba::{CmpOp, Expr, Predicate, SmtBudget, SmtVerdict, Width, check_unsat};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};

use super::bcf::{BogusBranch, OpaqueResult};
use super::mba_lift::{RegFile, operand_expr};

type PathCondition = Vec<(Predicate, bool, Width)>;

const MAX_DECODE_INSNS: usize = 8192;
const DEFAULT_MAX_BACKWARD_BLOCKS: usize = 24;
const DEFAULT_MAX_BACKWARD_INSNS: usize = 768;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackwardBudget {
    pub max_blocks: usize,
    pub max_instructions: usize,
    pub solver_timeout: Duration,
    pub solver_max_conflicts: u64,
    pub solver_max_decisions: u64,
}

impl BackwardBudget {
    #[must_use]
    pub const fn bounded_default() -> Self {
        let smt: SmtBudget = SmtBudget::bounded_default();
        Self {
            max_blocks: DEFAULT_MAX_BACKWARD_BLOCKS,
            max_instructions: DEFAULT_MAX_BACKWARD_INSNS,
            solver_timeout: smt.timeout,
            solver_max_conflicts: smt.max_conflicts,
            solver_max_decisions: smt.max_decisions,
        }
    }

    const fn smt_budget(self) -> SmtBudget {
        let defaults: SmtBudget = SmtBudget::bounded_default();
        SmtBudget {
            timeout: self.solver_timeout,
            max_conflicts: self.solver_max_conflicts,
            max_decisions: self.solver_max_decisions,
            max_encode_nodes: defaults.max_encode_nodes,
        }
    }
}

impl Default for BackwardBudget {
    fn default() -> Self {
        Self::bounded_default()
    }
}

#[derive(Debug, Clone, Copy)]
struct Block {
    start: usize,
    end: usize,
}

#[must_use]
pub fn locate_containing_block(
    bitness: u32,
    base: u64,
    code: &[u8],
    branch_address: u64,
) -> Option<(u64, std::ops::Range<usize>)> {
    let insns: Vec<Instruction> = decode_all(bitness, base, code);
    let index: BTreeMap<u64, usize> = insns
        .iter()
        .enumerate()
        .map(|(i, insn): (usize, &Instruction)| (insn.ip(), i))
        .collect();
    let blocks: Vec<Block> = split_blocks(&insns, &index);
    let branch_index: usize = *index.get(&branch_address)?;
    let containing: usize = find_block(&blocks, branch_index)?;
    if blocks[containing].end != branch_index {
        return None;
    }
    let block: Block = blocks[containing];
    let start_addr: u64 = insns[block.start].ip();
    let last: Instruction = insns[block.end];
    let end_addr: u64 = last.ip().saturating_add(last.len() as u64);
    let start_off: usize = usize::try_from(start_addr.checked_sub(base)?).ok()?;
    let end_off: usize = usize::try_from(end_addr.checked_sub(base)?).ok()?;
    if end_off > code.len() || start_off > end_off {
        return None;
    }
    Some((start_addr, start_off..end_off))
}

#[must_use]
pub fn analyze_branch_backward(
    bitness: u32,
    base: u64,
    code: &[u8],
    branch_address: u64,
) -> Option<BogusBranch> {
    analyze_branch_backward_bounded(
        bitness,
        base,
        code,
        branch_address,
        BackwardBudget::default(),
    )
}

#[must_use]
pub fn analyze_branch_backward_bounded(
    bitness: u32,
    base: u64,
    code: &[u8],
    branch_address: u64,
    budget: BackwardBudget,
) -> Option<BogusBranch> {
    let insns: Vec<Instruction> = decode_all(bitness, base, code);
    let index: BTreeMap<u64, usize> = insns
        .iter()
        .enumerate()
        .map(|(i, insn): (usize, &Instruction)| (insn.ip(), i))
        .collect();
    let blocks: Vec<Block> = split_blocks(&insns, &index);
    let branch_index: usize = *index.get(&branch_address)?;
    let branch_insn: Instruction = *insns.get(branch_index)?;
    if branch_insn.flow_control() != FlowControl::ConditionalBranch {
        return None;
    }
    let containing: usize = find_block(&blocks, branch_index)?;
    if blocks[containing].end != branch_index {
        return None;
    }
    let cmp_index: usize = branch_index.checked_sub(1)?;
    if cmp_index < blocks[containing].start {
        return None;
    }

    let predecessors: Vec<Vec<usize>> = compute_predecessors(&insns, &blocks, &index);
    let has_unresolved_edges: bool = section_has_unresolved_edges(&insns, &index);
    let chain: Vec<usize> = backward_chain(
        containing,
        &predecessors,
        &blocks,
        budget.max_blocks,
        budget.max_instructions,
        has_unresolved_edges,
    );

    let (path, mut regs): (PathCondition, RegFile) =
        resimulate_chain(&insns, &blocks, &chain, cmp_index)?;

    let (final_predicate, final_width): (Predicate, Width) =
        build_predicate(&mut regs, &insns[cmp_index], branch_insn.mnemonic())?;

    let mut taken_query: PathCondition = path.clone();
    taken_query.push((final_predicate.clone(), true, final_width));
    let mut fallthrough_query: PathCondition = path;
    fallthrough_query.push((final_predicate, false, final_width));

    let smt_budget: SmtBudget = budget.smt_budget();
    let taken_verdict: SmtVerdict = check_unsat(&taken_query, smt_budget);
    let fallthrough_verdict: SmtVerdict = check_unsat(&fallthrough_query, smt_budget);

    let taken_addr: u64 = branch_insn.near_branch_target();
    let fallthrough_addr: u64 = branch_insn.ip().saturating_add(branch_insn.len() as u64);

    Some(match (taken_verdict, fallthrough_verdict) {
        (SmtVerdict::Unsat, SmtVerdict::Sat) => BogusBranch {
            branch_address,
            result: OpaqueResult::AlwaysNotTaken,
            dead_target: Some(taken_addr),
            live_target: Some(fallthrough_addr),
        },
        (SmtVerdict::Sat, SmtVerdict::Unsat) => BogusBranch {
            branch_address,
            result: OpaqueResult::AlwaysTaken,
            dead_target: Some(fallthrough_addr),
            live_target: Some(taken_addr),
        },
        (SmtVerdict::Sat, SmtVerdict::Sat) => BogusBranch {
            branch_address,
            result: OpaqueResult::DataDependent,
            dead_target: None,
            live_target: None,
        },
        _ => BogusBranch {
            branch_address,
            result: OpaqueResult::NotAnalyzable,
            dead_target: None,
            live_target: None,
        },
    })
}

fn resimulate_chain(
    insns: &[Instruction],
    blocks: &[Block],
    chain: &[usize],
    cmp_index: usize,
) -> Option<(PathCondition, RegFile)> {
    let mut regs: RegFile = RegFile::new();
    let mut path: PathCondition = Vec::new();
    for (position, &block_idx) in chain.iter().enumerate() {
        let block: Block = blocks[block_idx];
        let is_last_block: bool = position + 1 == chain.len();
        let terminator: Instruction = insns[block.end];
        let (body_end, has_conditional_edge): (usize, bool) = if is_last_block {
            (cmp_index, false)
        } else {
            match terminator.flow_control() {
                FlowControl::ConditionalBranch => {
                    let terminator_cmp: usize = block.end.checked_sub(1)?;
                    if terminator_cmp < block.start {
                        return None;
                    }
                    (terminator_cmp, true)
                }
                FlowControl::UnconditionalBranch => (block.end, false),
                _ => (block.end + 1, false),
            }
        };
        for insn in insns.get(block.start..body_end.min(insns.len()))? {
            if !regs.apply_insn(insn) || regs.is_capped() {
                return None;
            }
        }
        if has_conditional_edge {
            let terminator_cmp_index: usize = block.end.checked_sub(1)?;
            let (predicate, width): (Predicate, Width) = build_predicate(
                &mut regs,
                &insns[terminator_cmp_index],
                terminator.mnemonic(),
            )?;
            let taken_target: u64 = terminator.near_branch_target();
            let fallthrough_target: u64 = terminator.ip().saturating_add(terminator.len() as u64);
            let next_block_start_addr: u64 = insns[blocks[chain[position + 1]].start].ip();
            let expect: bool = if next_block_start_addr == taken_target {
                true
            } else if next_block_start_addr == fallthrough_target {
                false
            } else {
                return None;
            };
            path.push((predicate, expect, width));
        }
    }
    Some((path, regs))
}

fn backward_chain(
    start_block: usize,
    predecessors: &[Vec<usize>],
    blocks: &[Block],
    max_blocks: usize,
    max_instructions: usize,
    has_unresolved_edges: bool,
) -> Vec<usize> {
    let mut chain_reversed: Vec<usize> = vec![start_block];
    let mut visited: BTreeSet<usize> = BTreeSet::from([start_block]);
    let mut instruction_total: usize = block_len(blocks[start_block]);
    let mut current: usize = start_block;
    while !has_unresolved_edges && chain_reversed.len() < max_blocks {
        let preds: &Vec<usize> = &predecessors[current];
        let [only_pred]: [usize; 1] = match preds.as_slice() {
            [single] => [*single],
            _ => break,
        };
        if !visited.insert(only_pred) {
            break;
        }
        let added_len: usize = block_len(blocks[only_pred]);
        let Some(candidate_total): Option<usize> = instruction_total.checked_add(added_len) else {
            break;
        };
        if candidate_total > max_instructions {
            break;
        }
        instruction_total = candidate_total;
        chain_reversed.push(only_pred);
        current = only_pred;
    }
    chain_reversed.reverse();
    chain_reversed
}

const fn block_len(block: Block) -> usize {
    block.end - block.start + 1
}

fn split_blocks(insns: &[Instruction], index: &BTreeMap<u64, usize>) -> Vec<Block> {
    if insns.is_empty() {
        return Vec::new();
    }
    let mut leaders: BTreeSet<usize> = BTreeSet::from([0]);
    for (i, insn) in insns.iter().enumerate() {
        match insn.flow_control() {
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                if let Some(&target_idx) = index.get(&insn.near_branch_target()) {
                    leaders.insert(target_idx);
                }
                if i + 1 < insns.len() {
                    leaders.insert(i + 1);
                }
            }
            FlowControl::Return
            | FlowControl::IndirectBranch
            | FlowControl::IndirectCall
            | FlowControl::Interrupt
            | FlowControl::Exception
                if i + 1 < insns.len() =>
            {
                leaders.insert(i + 1);
            }
            _ => {}
        }
    }
    let ordered: Vec<usize> = leaders.into_iter().collect();
    let mut blocks: Vec<Block> = Vec::with_capacity(ordered.len());
    for (position, &start) in ordered.iter().enumerate() {
        let end: usize = ordered
            .get(position + 1)
            .copied()
            .unwrap_or(insns.len())
            .saturating_sub(1);
        blocks.push(Block { start, end });
    }
    blocks
}

fn find_block(blocks: &[Block], instr_index: usize) -> Option<usize> {
    blocks
        .iter()
        .position(|block: &Block| instr_index >= block.start && instr_index <= block.end)
}

fn compute_predecessors(
    insns: &[Instruction],
    blocks: &[Block],
    index: &BTreeMap<u64, usize>,
) -> Vec<Vec<usize>> {
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); blocks.len()];
    for (block_idx, block) in blocks.iter().enumerate() {
        for succ in successors(insns, blocks, index, *block) {
            if !preds[succ].contains(&block_idx) {
                preds[succ].push(block_idx);
            }
        }
    }
    preds
}

fn successors(
    insns: &[Instruction],
    blocks: &[Block],
    index: &BTreeMap<u64, usize>,
    block: Block,
) -> Vec<usize> {
    let last: Instruction = insns[block.end];
    let mut out: Vec<usize> = Vec::new();
    match last.flow_control() {
        FlowControl::ConditionalBranch => {
            if let Some(&target_idx) = index.get(&last.near_branch_target())
                && let Some(target_block) = find_block(blocks, target_idx)
            {
                out.push(target_block);
            }
            if block.end + 1 < insns.len()
                && let Some(fallthrough_block) = find_block(blocks, block.end + 1)
            {
                out.push(fallthrough_block);
            }
        }
        FlowControl::UnconditionalBranch => {
            if let Some(&target_idx) = index.get(&last.near_branch_target())
                && let Some(target_block) = find_block(blocks, target_idx)
            {
                out.push(target_block);
            }
        }
        FlowControl::Return
        | FlowControl::IndirectBranch
        | FlowControl::IndirectCall
        | FlowControl::Interrupt
        | FlowControl::Exception => {}
        _ => {
            if block.end + 1 < insns.len()
                && let Some(fallthrough_block) = find_block(blocks, block.end + 1)
            {
                out.push(fallthrough_block);
            }
        }
    }
    out
}

fn section_has_unresolved_edges(insns: &[Instruction], index: &BTreeMap<u64, usize>) -> bool {
    insns
        .iter()
        .any(|insn: &Instruction| match insn.flow_control() {
            FlowControl::IndirectBranch | FlowControl::IndirectCall => true,
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                !index.contains_key(&insn.near_branch_target())
            }
            _ => false,
        })
}

fn build_predicate(
    regs: &mut RegFile,
    cmp: &Instruction,
    branch: Mnemonic,
) -> Option<(Predicate, Width)> {
    match cmp.mnemonic() {
        Mnemonic::Cmp => {
            if cmp.op0_kind() != OpKind::Register {
                return None;
            }
            let width: Width = register_width(cmp.op0_register());
            let left: Expr = regs.current(cmp.op0_register());
            let right: Expr = operand_expr(regs, cmp, 1)?;
            let op: CmpOp = branch_to_cmp(branch)?;
            Some((Predicate::Compare { op, left, right }, width))
        }
        Mnemonic::Test => {
            if cmp.op0_kind() != OpKind::Register {
                return None;
            }
            let width: Width = register_width(cmp.op0_register());
            let left: Expr = regs.current(cmp.op0_register());
            let right: Expr = operand_expr(regs, cmp, 1)?;
            let masked: Expr = Expr::and(left, right);
            let predicate: Predicate = match branch {
                Mnemonic::Je => Predicate::eq(masked, Expr::konst(0)),
                Mnemonic::Jne => Predicate::nonzero(masked),
                _ => return None,
            };
            Some((predicate, width))
        }
        _ => None,
    }
}

fn register_width(reg: Register) -> Width {
    match reg.size() {
        1 => Width::W8,
        2 => Width::W16,
        4 => Width::W32,
        _ => Width::W64,
    }
}

const fn branch_to_cmp(branch: Mnemonic) -> Option<CmpOp> {
    match branch {
        Mnemonic::Je => Some(CmpOp::Eq),
        Mnemonic::Jne => Some(CmpOp::Ne),
        Mnemonic::Jb => Some(CmpOp::UnsignedLt),
        Mnemonic::Jbe => Some(CmpOp::UnsignedLe),
        Mnemonic::Ja => Some(CmpOp::UnsignedGt),
        Mnemonic::Jae => Some(CmpOp::UnsignedGe),
        Mnemonic::Jl => Some(CmpOp::SignedLt),
        Mnemonic::Jle => Some(CmpOp::SignedLe),
        Mnemonic::Jg => Some(CmpOp::SignedGt),
        Mnemonic::Jge => Some(CmpOp::SignedGe),
        _ => None,
    }
}

fn decode_all(bitness: u32, base: u64, bytes: &[u8]) -> Vec<Instruction> {
    let mut decoder: Decoder<'_> = Decoder::with_ip(bitness, bytes, base, DecoderOptions::NONE);
    let mut out: Vec<Instruction> = Vec::new();
    while decoder.can_decode() && out.len() < MAX_DECODE_INSNS {
        let mut insn: Instruction = Instruction::default();
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            break;
        }
        out.push(insn);
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests;
