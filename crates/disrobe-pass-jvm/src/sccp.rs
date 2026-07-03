use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::bytecode::{Instruction, Operands};
use crate::decompile_struct::{BasicBlock, BlockId, Cfg, Edge, EdgeKind};

const MAX_DISPATCH_RESOLVE_STEPS: usize = 65_536;
const MIN_DISPATCHER_PREDECESSORS: usize = 2;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SccpReport {
    pub changed: bool,
    pub dispatchers_unflattened: usize,
    pub edges_redirected: usize,
    pub dead_branches_folded: usize,
    pub dispatcher_blocks_bypassed: usize,
}

#[inline]
#[must_use]
const fn iconst_value(insn: &Instruction) -> Option<i32> {
    match insn.opcode {
        0x02 => Some(-1),
        0x03 => Some(0),
        0x04 => Some(1),
        0x05 => Some(2),
        0x06 => Some(3),
        0x07 => Some(4),
        0x08 => Some(5),
        0x10 | 0x11 => match insn.operands {
            Operands::Byte(v) | Operands::Short(v) => Some(v),
            _ => None,
        },
        _ => None,
    }
}

#[inline]
#[must_use]
const fn istore_local(insn: &Instruction) -> Option<u16> {
    match insn.opcode {
        0x3B => Some(0),
        0x3C => Some(1),
        0x3D => Some(2),
        0x3E => Some(3),
        0x36 => match insn.operands {
            Operands::Local(i) => Some(i),
            _ => None,
        },
        _ => None,
    }
}

#[inline]
#[must_use]
const fn iload_local(insn: &Instruction) -> Option<u16> {
    match insn.opcode {
        0x1A => Some(0),
        0x1B => Some(1),
        0x1C => Some(2),
        0x1D => Some(3),
        0x15 => match insn.operands {
            Operands::Local(i) => Some(i),
            _ => None,
        },
        _ => None,
    }
}

#[inline]
#[must_use]
const fn is_goto(insn: &Instruction) -> bool {
    matches!(insn.opcode, 0xA7 | 0xC8)
}

#[inline]
#[must_use]
const fn is_int_conditional_branch(op: u8) -> bool {
    matches!(op, 0x99..=0xA4 | 0xC6 | 0xC7)
}

#[inline]
#[must_use]
const fn iinc_targets(insn: &Instruction) -> Option<u16> {
    if insn.opcode == 0x84
        && let Operands::Iinc { index, .. } = insn.operands
    {
        return Some(index);
    }
    None
}

#[derive(Debug, Clone)]
struct Dispatcher {
    block: BlockId,
    state_local: u16,
    cases: BTreeMap<i32, BlockId>,
    default: Option<BlockId>,
}

#[must_use]
fn find_dispatchers(cfg: &Cfg, insns: &[Instruction]) -> Vec<Dispatcher> {
    let mut out: Vec<Dispatcher> = Vec::new();
    for block in &cfg.blocks {
        if block.predecessors.len() < MIN_DISPATCHER_PREDECESSORS {
            continue;
        }
        let Some(dispatcher): Option<Dispatcher> = dispatcher_at_block(cfg, block, insns) else {
            continue;
        };
        out.push(dispatcher);
    }
    out
}

#[must_use]
fn dispatcher_at_block(cfg: &Cfg, block: &BasicBlock, insns: &[Instruction]) -> Option<Dispatcher> {
    let (start_idx, end_idx): (usize, usize) = block.insn_range;
    if end_idx.checked_sub(start_idx) != Some(2) {
        return None;
    }
    let last: &Instruction = insns.get(end_idx - 1)?;
    if !matches!(last.opcode, 0xAA | 0xAB) {
        return None;
    }
    let load: &Instruction = insns.get(end_idx - 2)?;
    let state_local: u16 = iload_local(load)?;

    let mut cases: BTreeMap<i32, BlockId> = BTreeMap::new();
    let default: Option<BlockId> = match &last.operands {
        Operands::TableSwitch {
            default,
            low,
            offsets,
            ..
        } => {
            for (i, off) in offsets.iter().enumerate() {
                let tpc: u32 = (i64::from(last.pc) + i64::from(*off)) as u32;
                let &bid: &BlockId = cfg.pc_to_block.get(&tpc)?;
                let key: i32 = low.checked_add(i as i32)?;
                cases.insert(key, bid);
            }
            let dpc: u32 = (i64::from(last.pc) + i64::from(*default)) as u32;
            cfg.pc_to_block.get(&dpc).copied()
        }
        Operands::LookupSwitch { default, pairs } => {
            for (k, off) in pairs {
                let tpc: u32 = (i64::from(last.pc) + i64::from(*off)) as u32;
                let &bid: &BlockId = cfg.pc_to_block.get(&tpc)?;
                cases.insert(*k, bid);
            }
            let dpc: u32 = (i64::from(last.pc) + i64::from(*default)) as u32;
            cfg.pc_to_block.get(&dpc).copied()
        }
        _ => return None,
    };
    if cases.is_empty() {
        return None;
    }
    Some(Dispatcher {
        block: block.id,
        state_local,
        cases,
        default,
    })
}

#[derive(Debug, Clone, Copy)]
struct StateTail {
    const_value: i32,
    push_idx: usize,
}

#[must_use]
fn block_tail_state(
    block: &BasicBlock,
    insns: &[Instruction],
    state_local: u16,
) -> Option<StateTail> {
    let (start_idx, end_idx): (usize, usize) = block.insn_range;
    if end_idx <= start_idx {
        return None;
    }
    let last: &Instruction = insns.get(end_idx - 1)?;
    if !is_goto(last) {
        return None;
    }
    let store_idx: usize = end_idx.checked_sub(2)?;
    if store_idx < start_idx {
        return None;
    }
    if istore_local(insns.get(store_idx)?) != Some(state_local) {
        return None;
    }
    let push_idx: usize = store_idx.checked_sub(1)?;
    if push_idx < start_idx {
        return None;
    }
    let const_value: i32 = iconst_value(insns.get(push_idx)?)?;
    if reassigns_state_before(block, insns, state_local, push_idx) {
        return None;
    }
    Some(StateTail {
        const_value,
        push_idx,
    })
}

#[must_use]
fn reassigns_state_before(
    block: &BasicBlock,
    insns: &[Instruction],
    state_local: u16,
    push_idx: usize,
) -> bool {
    let (start_idx, _): (usize, usize) = block.insn_range;
    insns
        .get(start_idx..push_idx)
        .into_iter()
        .flatten()
        .any(|ins: &Instruction| {
            istore_local(ins) == Some(state_local) || iinc_targets(ins) == Some(state_local)
        })
}

fn rebuild_predecessors(cfg: &mut Cfg) {
    for block in &mut cfg.blocks {
        block.predecessors.clear();
    }
    let edges: Vec<(BlockId, BlockId)> = cfg
        .blocks
        .iter()
        .flat_map(|b: &BasicBlock| b.successors.iter().map(move |e: &Edge| (b.id, e.target)))
        .collect();
    for (src, dst) in edges {
        let preds: &mut Vec<BlockId> = &mut cfg.blocks[dst.0 as usize].predecessors;
        if !preds.contains(&src) {
            preds.push(src);
        }
    }
}

#[must_use]
fn reachable_from_entry(cfg: &Cfg) -> BTreeSet<BlockId> {
    let mut seen: BTreeSet<BlockId> = BTreeSet::new();
    let mut stack: Vec<BlockId> = vec![cfg.entry];
    seen.insert(cfg.entry);
    while let Some(b) = stack.pop() {
        for edge in &cfg.blocks[b.0 as usize].successors {
            if seen.insert(edge.target) {
                stack.push(edge.target);
            }
        }
    }
    seen
}

fn unflatten_dispatcher(
    cfg: &mut Cfg,
    insns: &[Instruction],
    dispatcher: &Dispatcher,
    report: &mut SccpReport,
) -> bool {
    let predecessors: Vec<BlockId> = cfg.blocks[dispatcher.block.0 as usize].predecessors.clone();
    let mut redirects: Vec<(BlockId, BlockId, usize)> = Vec::new();
    for pred in predecessors {
        if pred == dispatcher.block {
            continue;
        }
        let pred_block: &BasicBlock = &cfg.blocks[pred.0 as usize];
        let only_to_dispatcher: bool = pred_block
            .successors
            .iter()
            .all(|e: &Edge| e.target == dispatcher.block);
        if !only_to_dispatcher {
            continue;
        }
        let Some(tail): Option<StateTail> =
            block_tail_state(pred_block, insns, dispatcher.state_local)
        else {
            continue;
        };
        let target: Option<BlockId> = dispatcher
            .cases
            .get(&tail.const_value)
            .copied()
            .or(dispatcher.default);
        let Some(target): Option<BlockId> = target else {
            continue;
        };
        if target == dispatcher.block {
            continue;
        }
        redirects.push((pred, target, tail.push_idx));
    }

    if redirects.is_empty() {
        return false;
    }

    let redirected_here: usize = redirects.len();
    for (pred, target, push_idx) in redirects {
        let pred_block: &mut BasicBlock = &mut cfg.blocks[pred.0 as usize];
        pred_block.successors = vec![Edge {
            kind: EdgeKind::Jump,
            target,
        }];
        pred_block.insn_range.1 = push_idx;
    }

    report.edges_redirected += redirected_here;
    report.dispatchers_unflattened += 1;
    report.changed = true;
    true
}

fn fold_dead_conditional_branches(cfg: &mut Cfg, insns: &[Instruction], report: &mut SccpReport) {
    let mut folds: Vec<(BlockId, BlockId, usize)> = Vec::new();
    for block in &cfg.blocks {
        let (_, end_idx): (usize, usize) = block.insn_range;
        let Some(branch): Option<&Instruction> = end_idx.checked_sub(1).and_then(|i| insns.get(i))
        else {
            continue;
        };
        if !is_int_conditional_branch(branch.opcode) {
            continue;
        }
        let Some(taken): Option<bool> = const_condition_outcome(block, insns) else {
            continue;
        };
        let true_target: Option<BlockId> = block
            .successors
            .iter()
            .find(|e: &&Edge| matches!(e.kind, EdgeKind::CondTrue))
            .map(|e: &Edge| e.target);
        let false_target: Option<BlockId> = block
            .successors
            .iter()
            .find(|e: &&Edge| matches!(e.kind, EdgeKind::CondFalse))
            .map(|e: &Edge| e.target);
        let live: Option<BlockId> = if taken { true_target } else { false_target };
        let Some(live_target): Option<BlockId> = live else {
            continue;
        };
        folds.push((block.id, live_target, end_idx - 1));
    }

    if folds.is_empty() {
        return;
    }

    for (bid, live_target, branch_idx) in folds {
        let block: &mut BasicBlock = &mut cfg.blocks[bid.0 as usize];
        block.successors = vec![Edge {
            kind: EdgeKind::Jump,
            target: live_target,
        }];
        block.insn_range.1 = branch_idx;
        report.dead_branches_folded += 1;
        report.changed = true;
    }
}

#[must_use]
fn const_condition_outcome(block: &BasicBlock, insns: &[Instruction]) -> Option<bool> {
    let (start_idx, end_idx): (usize, usize) = block.insn_range;
    let branch: &Instruction = insns.get(end_idx.checked_sub(1)?)?;
    match branch.opcode {
        0x99..=0x9E => {
            let operand_idx: usize = end_idx.checked_sub(2)?;
            if operand_idx < start_idx {
                return None;
            }
            let operand: i32 = iconst_value(insns.get(operand_idx)?)?;
            Some(unary_compare(branch.opcode, operand))
        }
        0x9F..=0xA4 => {
            let rhs_idx: usize = end_idx.checked_sub(2)?;
            let lhs_idx: usize = end_idx.checked_sub(3)?;
            if lhs_idx < start_idx {
                return None;
            }
            let rhs: i32 = iconst_value(insns.get(rhs_idx)?)?;
            let lhs: i32 = iconst_value(insns.get(lhs_idx)?)?;
            Some(binary_compare(branch.opcode, lhs, rhs))
        }
        _ => None,
    }
}

#[inline]
#[must_use]
const fn unary_compare(op: u8, v: i32) -> bool {
    match op {
        0x99 => v == 0,
        0x9A => v != 0,
        0x9B => v < 0,
        0x9C => v >= 0,
        0x9D => v > 0,
        0x9E => v <= 0,
        _ => false,
    }
}

#[inline]
#[must_use]
const fn binary_compare(op: u8, a: i32, b: i32) -> bool {
    match op {
        0x9F => a == b,
        0xA0 => a != b,
        0xA1 => a < b,
        0xA2 => a >= b,
        0xA3 => a > b,
        0xA4 => a <= b,
        _ => false,
    }
}

fn prune_unreachable(cfg: &mut Cfg, report: &mut SccpReport) {
    let reachable: BTreeSet<BlockId> = reachable_from_entry(cfg);
    let mut bypassed: usize = 0;
    for block in &mut cfg.blocks {
        if reachable.contains(&block.id) {
            continue;
        }
        if !block.successors.is_empty() || !block.predecessors.is_empty() {
            bypassed += 1;
        }
        block.successors.clear();
        block.predecessors.clear();
    }
    if bypassed > 0 {
        report.dispatcher_blocks_bypassed += bypassed;
        report.changed = true;
    }
}

#[must_use]
pub fn simplify_flattened_cfg(cfg: &mut Cfg, insns: &[Instruction]) -> SccpReport {
    let mut report: SccpReport = SccpReport::default();
    fold_dead_conditional_branches(cfg, insns, &mut report);
    if report.changed {
        rebuild_predecessors(cfg);
    }

    let mut steps: usize = 0;
    loop {
        steps += 1;
        if steps > MAX_DISPATCH_RESOLVE_STEPS {
            break;
        }
        let dispatchers: Vec<Dispatcher> = find_dispatchers(cfg, insns);
        if dispatchers.is_empty() {
            break;
        }
        let mut any: bool = false;
        for dispatcher in &dispatchers {
            if unflatten_dispatcher(cfg, insns, dispatcher, &mut report) {
                any = true;
            }
        }
        if !any {
            break;
        }
        rebuild_predecessors(cfg);
    }

    if report.changed {
        prune_unreachable(cfg, &mut report);
        rebuild_predecessors(cfg);
    }
    report
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::bytecode::{CodeAttribute, disassemble};
    use crate::decompile_struct::{
        Dominators, NaturalLoop, Region, Structurer, build_cfg, compute_dominators,
        find_natural_loops,
    };

    fn code_attr(body: Vec<u8>) -> CodeAttribute {
        CodeAttribute {
            max_stack: 8,
            max_locals: 8,
            code: body,
            exception_table: Vec::new(),
            dropped_exception_entries: 0,
        }
    }

    fn count_irreducible(region: &Region) -> usize {
        match region {
            Region::Irreducible { blocks } => blocks.len(),
            Region::Sequence(items) => items.iter().map(count_irreducible).sum(),
            Region::IfThen { then_body, .. } => count_irreducible(then_body),
            Region::IfThenElse {
                then_body,
                else_body,
                ..
            } => count_irreducible(then_body) + count_irreducible(else_body),
            Region::While { body, .. } | Region::DoWhile { body, .. } => count_irreducible(body),
            Region::Switch { cases, default, .. } => {
                cases
                    .iter()
                    .map(|(_, r)| count_irreducible(r))
                    .sum::<usize>()
                    + default.as_ref().map_or(0, |d| count_irreducible(d))
            }
            Region::Try { try_body, handlers }
            | Region::TryFinally {
                try_body, handlers, ..
            } => {
                count_irreducible(try_body)
                    + handlers
                        .iter()
                        .map(|(_, r)| count_irreducible(r))
                        .sum::<usize>()
            }
            Region::TryWithResources { try_body, .. } => count_irreducible(try_body),
            Region::Synchronized { body, .. } | Region::LabeledLoop { body, .. } => {
                count_irreducible(body)
            }
            Region::Block(_) | Region::Break { .. } | Region::Continue { .. } => 0,
        }
    }

    fn count_switch_regions(region: &Region) -> usize {
        match region {
            Region::Switch { cases, default, .. } => {
                1 + cases
                    .iter()
                    .map(|(_, r)| count_switch_regions(r))
                    .sum::<usize>()
                    + default.as_ref().map_or(0, |d| count_switch_regions(d))
            }
            Region::Sequence(items) => items.iter().map(count_switch_regions).sum(),
            Region::IfThen { then_body, .. } => count_switch_regions(then_body),
            Region::IfThenElse {
                then_body,
                else_body,
                ..
            } => count_switch_regions(then_body) + count_switch_regions(else_body),
            Region::While { body, .. } | Region::DoWhile { body, .. } => count_switch_regions(body),
            Region::Try { try_body, handlers }
            | Region::TryFinally {
                try_body, handlers, ..
            } => {
                count_switch_regions(try_body)
                    + handlers
                        .iter()
                        .map(|(_, r)| count_switch_regions(r))
                        .sum::<usize>()
            }
            Region::TryWithResources { try_body, .. } => count_switch_regions(try_body),
            Region::Synchronized { body, .. } | Region::LabeledLoop { body, .. } => {
                count_switch_regions(body)
            }
            Region::Block(_)
            | Region::Break { .. }
            | Region::Continue { .. }
            | Region::Irreducible { .. } => 0,
        }
    }

    enum Item {
        Op(u8),
        Goto(usize),
        IfIcmpeq(usize),
        LookupSwitch {
            default: usize,
            pairs: Vec<(i32, usize)>,
        },
    }

    fn assemble(items: &[Item]) -> Vec<u8> {
        let mut pcs: Vec<u32> = Vec::with_capacity(items.len());
        let mut pc: usize = 0;
        for item in items {
            pcs.push(pc as u32);
            let size: usize = match item {
                Item::Op(_) => 1,
                Item::Goto(_) | Item::IfIcmpeq(_) => 3,
                Item::LookupSwitch { pairs, .. } => {
                    let after_op: usize = pc + 1;
                    let pad: usize = (4 - (after_op % 4)) % 4;
                    1 + pad + 4 + 4 + pairs.len() * 8
                }
            };
            pc += size;
        }

        let mut out: Vec<u8> = Vec::with_capacity(pc);
        for (i, item) in items.iter().enumerate() {
            let here: i32 = pcs[i] as i32;
            match item {
                Item::Op(op) => out.push(*op),
                Item::Goto(target) => {
                    out.push(0xA7);
                    let rel: i32 = pcs[*target] as i32 - here;
                    out.extend_from_slice(&(rel as i16).to_be_bytes());
                }
                Item::IfIcmpeq(target) => {
                    out.push(0x9F);
                    let rel: i32 = pcs[*target] as i32 - here;
                    out.extend_from_slice(&(rel as i16).to_be_bytes());
                }
                Item::LookupSwitch { default, pairs } => {
                    out.push(0xAB);
                    let pad: usize = (4 - (out.len() % 4)) % 4;
                    out.extend(std::iter::repeat_n(0x00u8, pad));
                    let default_rel: i32 = pcs[*default] as i32 - here;
                    out.extend_from_slice(&default_rel.to_be_bytes());
                    out.extend_from_slice(&(pairs.len() as i32).to_be_bytes());
                    for (k, target) in pairs {
                        out.extend_from_slice(&k.to_be_bytes());
                        let rel: i32 = pcs[*target] as i32 - here;
                        out.extend_from_slice(&rel.to_be_bytes());
                    }
                }
            }
        }
        out
    }

    fn flattened_two_state_method() -> Vec<u8> {
        const DISPATCHER: usize = 3;
        const CASE0: usize = 5;
        const CASE1: usize = 10;
        const DEFAULT: usize = 12;
        let items: Vec<Item> = vec![
            Item::Op(0x03),
            Item::Op(0x3D),
            Item::Goto(DISPATCHER),
            Item::Op(0x1C),
            Item::LookupSwitch {
                default: DEFAULT,
                pairs: vec![(0, CASE0), (1, CASE1)],
            },
            Item::Op(0x05),
            Item::Op(0x3C),
            Item::Op(0x04),
            Item::Op(0x3D),
            Item::Goto(DISPATCHER),
            Item::Op(0x1B),
            Item::Op(0xAC),
            Item::Op(0x04),
            Item::Op(0xAC),
        ];
        assemble(&items)
    }

    fn dispatcher_block_id(cfg: &Cfg, insns: &[Instruction]) -> BlockId {
        for block in &cfg.blocks {
            let (_, end_idx): (usize, usize) = block.insn_range;
            if let Some(last) = end_idx.checked_sub(1).and_then(|i| insns.get(i))
                && matches!(last.opcode, 0xAA | 0xAB)
            {
                return block.id;
            }
        }
        panic!("fixture must contain a switch dispatcher block");
    }

    #[test]
    fn flattened_dispatcher_unflattens_and_structures() {
        let body: Vec<u8> = flattened_two_state_method();
        let insns: Vec<Instruction> = disassemble(&body).expect("disassemble");

        let code: CodeAttribute = code_attr(body);
        let mut cfg: Cfg = build_cfg(&insns, &code, |_| None).expect("cfg");
        let dispatcher: BlockId = dispatcher_block_id(&cfg, &insns);

        assert!(
            reachable_from_entry(&cfg).contains(&dispatcher),
            "precondition: dispatcher switch must be reachable in the flattened CFG"
        );

        let report: SccpReport = simplify_flattened_cfg(&mut cfg, &insns);
        assert!(report.changed, "expected the dispatcher to be unflattened");
        assert!(report.edges_redirected >= 1, "expected redirected edges");

        assert!(
            !reachable_from_entry(&cfg).contains(&dispatcher),
            "dispatcher switch must be unreachable after unflattening"
        );

        let dom: Dominators = compute_dominators(&cfg).expect("dom after");
        let loops: Vec<NaturalLoop> = find_natural_loops(&cfg, &dom);
        let mut s: Structurer<'_> = Structurer::new(&cfg, &dom, &loops, &insns);
        let after: Region = s.structure();
        assert_eq!(
            count_switch_regions(&after),
            0,
            "dispatcher switch must be gone after unflattening"
        );
        assert_eq!(
            count_irreducible(&after),
            0,
            "unflattened CFG must be fully reducible"
        );
        assert!(!s.had_irreducible, "structurer must not flag irreducible");
    }

    #[test]
    fn clean_method_is_left_untouched() {
        let b: Vec<u8> = vec![0x04, 0xAC];
        let insns: Vec<Instruction> = disassemble(&b).expect("disassemble");
        let code: CodeAttribute = code_attr(b);
        let mut cfg: Cfg = build_cfg(&insns, &code, |_| None).expect("cfg");
        let before_len: usize = cfg.blocks.len();
        let report: SccpReport = simplify_flattened_cfg(&mut cfg, &insns);
        assert!(!report.changed, "clean method must be left untouched");
        assert_eq!(before_len, cfg.blocks.len());
    }

    #[test]
    fn dead_opaque_branch_is_folded() {
        const TAKEN: usize = 5;
        let items: Vec<Item> = vec![
            Item::Op(0x04),
            Item::Op(0x04),
            Item::IfIcmpeq(TAKEN),
            Item::Op(0x03),
            Item::Op(0xAC),
            Item::Op(0x04),
            Item::Op(0xAC),
        ];
        let b: Vec<u8> = assemble(&items);
        let insns: Vec<Instruction> = disassemble(&b).expect("disassemble");
        let code: CodeAttribute = code_attr(b);
        let mut cfg: Cfg = build_cfg(&insns, &code, |_| None).expect("cfg");
        let report: SccpReport = simplify_flattened_cfg(&mut cfg, &insns);
        assert!(report.changed, "constant if_icmpeq should be folded");
        assert_eq!(report.dead_branches_folded, 1);
        let entry_block: &BasicBlock = &cfg.blocks[cfg.entry.0 as usize];
        assert_eq!(
            entry_block.successors.len(),
            1,
            "folded branch should leave a single successor"
        );
    }
}
