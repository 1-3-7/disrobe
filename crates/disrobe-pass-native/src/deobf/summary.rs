use std::collections::{BTreeMap, BTreeSet};

use disrobe_cfg::{Flow, FlowGraph};
use disrobe_mba::{CmpOp, Expr, Predicate, Simplification, Width, equivalent_exhaustive, simplify};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};

use super::mba_lift::{RegFile, StackCell, operand_expr};

const VERIFY_ARITY_CAP: u32 = 12;
const VERIFY_BUDGET_LOG2: u32 = 22;

const MAX_DECODE_INSNS: usize = 4096;
const MAX_BLOCK_INSNS: usize = 256;
const MAX_OUTPUT_REGISTERS: usize = 32;
const MAX_OUTPUT_STACK_CELLS: usize = 32;
const MAX_REGION_BLOCKS: usize = 64;
const MAX_REGION_INSNS: usize = 2048;
const MAX_JOINS: usize = 64;
const MAX_UNROLL: usize = 8;
const MAX_LOOPS: usize = 1;
const MAX_UNROLLED_BLOCKS: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchFact {
    pub predicate: Predicate,
    pub condition_var: u32,
    pub branch_address: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSummary {
    pub outputs: BTreeMap<Register, Expr>,
    pub stack_outputs: BTreeMap<StackKey, Expr>,
    pub width: Width,
    pub branches: Vec<BranchFact>,
    pub predicate: Predicate,
    pub condition_var: u32,
    pub branch_address: u64,
    pub input_seeds: BTreeMap<Register, u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct StackKey {
    pub base: Register,
    pub disp: i64,
}

impl From<StackCell> for StackKey {
    fn from(cell: StackCell) -> Self {
        Self {
            base: cell.base,
            disp: cell.disp,
        }
    }
}

impl FunctionSummary {
    #[must_use]
    pub fn condition_value(&self, env: &[u64]) -> bool {
        self.predicate.evaluate(env, self.width)
    }

    #[must_use]
    pub fn branch_condition(&self, branch: &BranchFact, env: &[u64]) -> bool {
        branch.predicate.evaluate(env, self.width)
    }

    #[must_use]
    pub fn simplified_effects(&self) -> BTreeMap<String, String> {
        let mut effects: BTreeMap<String, String> = BTreeMap::new();
        for (reg, expr) in &self.outputs {
            effects.insert(register_label(*reg), verified_simplify(expr));
        }
        for (cell, expr) in &self.stack_outputs {
            effects.insert(stack_label(*cell), verified_simplify(expr));
        }
        effects
    }
}

fn register_label(reg: Register) -> String {
    format!("{reg:?}").to_ascii_lowercase()
}

fn stack_label(cell: StackKey) -> String {
    let base: String = format!("{:?}", cell.base).to_ascii_lowercase();
    format!("[{base}{:+}]", cell.disp)
}

#[must_use]
pub fn verified_simplify(expr: &Expr) -> String {
    verified_simplify_expr(expr).0.to_string()
}

#[must_use]
pub fn verified_simplify_expr(expr: &Expr) -> (Expr, BTreeMap<u32, u32>) {
    let Some((dense, arity, remap)): Option<(Expr, u32, BTreeMap<u32, u32>)> = densify(expr) else {
        return (expr.clone(), BTreeMap::new());
    };
    (simplify_and_verify(&dense, arity), remap)
}

fn simplify_and_verify(dense: &Expr, arity: u32) -> Expr {
    let Some(verify_width): Option<Width> = verifiable_width(arity) else {
        return dense.clone();
    };
    let result: Simplification = simplify(dense, verify_width);
    if !result.changed() {
        return dense.clone();
    }
    if equivalent_exhaustive(dense, &result.simplified, verify_width, arity) {
        result.simplified
    } else {
        dense.clone()
    }
}

fn densify(expr: &Expr) -> Option<(Expr, u32, BTreeMap<u32, u32>)> {
    let vars: BTreeSet<u32> = expr.vars();
    if vars.len() as u32 > VERIFY_ARITY_CAP {
        return None;
    }
    let remap: BTreeMap<u32, u32> = vars
        .iter()
        .enumerate()
        .map(|(dense, original): (usize, &u32)| (*original, dense as u32))
        .collect();
    Some((expr.remap_vars(&remap), vars.len() as u32, remap))
}

fn verifiable_width(arity: u32) -> Option<Width> {
    let count: u32 = arity.max(1);
    for width in [Width::W16, Width::W8, Width::W4, Width::W2, Width::W1] {
        let total_log2: u64 = u64::from(width.bits()) * u64::from(count);
        if total_log2 <= u64::from(VERIFY_BUDGET_LOG2) {
            return Some(width);
        }
    }
    None
}

#[derive(Debug, Clone)]
enum Terminator {
    Fallthrough(usize),
    Conditional {
        cmp_index: usize,
        branch_mnemonic: Mnemonic,
        taken: usize,
        fallthrough: usize,
    },
    Jump(usize),
    Return,
}

#[derive(Debug, Clone, Default)]
struct WidenSet {
    registers: BTreeSet<Register>,
    cells: BTreeSet<StackCell>,
}

#[derive(Debug, Clone)]
struct Block {
    body: std::ops::Range<usize>,
    terminator: Terminator,
    widen: Option<WidenSet>,
}

#[derive(Debug, Clone, Copy)]
enum Side {
    Taken,
    Fallthrough,
}

#[derive(Debug, Clone)]
struct MergePlan {
    controller: usize,
    taken_pred: usize,
    fallthrough_pred: usize,
}

#[must_use]
pub fn summarize(bitness: u32, base: u64, code: &[u8], entry: u64) -> Option<FunctionSummary> {
    let insns: Vec<Instruction> = decode_all(bitness, base, code);
    if insns.is_empty() {
        return None;
    }
    let index: BTreeMap<u64, usize> = insns
        .iter()
        .enumerate()
        .map(|(i, insn): (usize, &Instruction)| (insn.ip(), i))
        .collect();
    let start: usize = *index.get(&entry)?;

    let region: Region = build_region(&insns, &index, start)?;
    let region: Region = match topological_order(&region) {
        Some(order) => return summarize_region(&insns, &region, &order),
        None => unroll_natural_loops(&insns, region)?,
    };
    let order: Vec<usize> = topological_order(&region)?;

    summarize_region(&insns, &region, &order)
}

#[derive(Debug, Clone)]
struct Region {
    blocks: Vec<Block>,
    entry_block: usize,
}

fn build_region(
    insns: &[Instruction],
    index: &BTreeMap<u64, usize>,
    start: usize,
) -> Option<Region> {
    let leaders: BTreeSet<usize> = collect_leaders(insns, index, start)?;
    let leader_vec: Vec<usize> = leaders.iter().copied().collect();
    let leader_to_block: BTreeMap<usize, usize> = leader_vec
        .iter()
        .enumerate()
        .map(|(i, leader): (usize, &usize)| (*leader, i))
        .collect();

    let mut blocks: Vec<Block> = Vec::with_capacity(leader_vec.len());
    let mut total_insns: usize = 0;
    for (i, &leader) in leader_vec.iter().enumerate() {
        let next_leader: usize = leader_vec.get(i + 1).copied().unwrap_or(insns.len());
        let block: Block = build_block(insns, index, leader, next_leader, &leader_to_block)?;
        total_insns += block.body.end - block.body.start;
        if total_insns > MAX_REGION_INSNS {
            return None;
        }
        blocks.push(block);
    }
    if blocks.len() > MAX_REGION_BLOCKS {
        return None;
    }

    let entry_block: usize = *leader_to_block.get(&start)?;
    Some(Region {
        blocks,
        entry_block,
    })
}

fn collect_leaders(
    insns: &[Instruction],
    index: &BTreeMap<u64, usize>,
    start: usize,
) -> Option<BTreeSet<usize>> {
    let mut leaders: BTreeSet<usize> = BTreeSet::new();
    let mut worklist: Vec<usize> = vec![start];
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    leaders.insert(start);

    while let Some(leader) = worklist.pop() {
        if !visited.insert(leader) {
            continue;
        }
        if visited.len() > MAX_REGION_BLOCKS {
            return None;
        }
        let mut cursor: usize = leader;
        let limit: usize = leader + MAX_BLOCK_INSNS;
        loop {
            if cursor >= insns.len() || cursor > limit {
                return None;
            }
            let insn: &Instruction = &insns[cursor];
            match insn.flow_control() {
                FlowControl::Next => {
                    if insn.has_lock_prefix() {
                        return None;
                    }
                    cursor += 1;
                }
                FlowControl::Return => break,
                FlowControl::ConditionalBranch => {
                    let cmp_index: usize = cursor.checked_sub(1)?;
                    if !matches!(insns[cmp_index].mnemonic(), Mnemonic::Cmp | Mnemonic::Test) {
                        return None;
                    }
                    let taken: usize = *index.get(&insn.near_branch_target())?;
                    let fallthrough: usize = cursor + 1;
                    if fallthrough >= insns.len() {
                        return None;
                    }
                    leaders.insert(taken);
                    leaders.insert(fallthrough);
                    worklist.push(taken);
                    worklist.push(fallthrough);
                    break;
                }
                FlowControl::UnconditionalBranch => {
                    let target: usize = *index.get(&insn.near_branch_target())?;
                    leaders.insert(target);
                    worklist.push(target);
                    break;
                }
                _ => return None,
            }
        }
    }
    Some(leaders)
}

fn build_block(
    insns: &[Instruction],
    index: &BTreeMap<u64, usize>,
    leader: usize,
    next_leader: usize,
    leader_to_block: &BTreeMap<usize, usize>,
) -> Option<Block> {
    let mut cursor: usize = leader;
    let limit: usize = leader + MAX_BLOCK_INSNS;
    loop {
        if cursor >= insns.len() || cursor > limit {
            return None;
        }
        let insn: &Instruction = &insns[cursor];
        match insn.flow_control() {
            FlowControl::Next => {
                if insn.has_lock_prefix() {
                    return None;
                }
                if cursor + 1 == next_leader {
                    let to: usize = *leader_to_block.get(&next_leader)?;
                    return Some(Block {
                        body: leader..cursor + 1,
                        terminator: Terminator::Fallthrough(to),
                        widen: None,
                    });
                }
                cursor += 1;
            }
            FlowControl::Return => {
                return Some(Block {
                    body: leader..cursor,
                    terminator: Terminator::Return,
                    widen: None,
                });
            }
            FlowControl::ConditionalBranch => {
                let cmp_index: usize = cursor.checked_sub(1)?;
                let taken_insn: usize = *index.get(&insn.near_branch_target())?;
                let fallthrough_insn: usize = cursor + 1;
                let taken: usize = *leader_to_block.get(&taken_insn)?;
                let fallthrough: usize = *leader_to_block.get(&fallthrough_insn)?;
                return Some(Block {
                    body: leader..cmp_index,
                    terminator: Terminator::Conditional {
                        cmp_index,
                        branch_mnemonic: insn.mnemonic(),
                        taken,
                        fallthrough,
                    },
                    widen: None,
                });
            }
            FlowControl::UnconditionalBranch => {
                let target_insn: usize = *index.get(&insn.near_branch_target())?;
                let to: usize = *leader_to_block.get(&target_insn)?;
                return Some(Block {
                    body: leader..cursor,
                    terminator: Terminator::Jump(to),
                    widen: None,
                });
            }
            _ => return None,
        }
    }
}

fn successors(block: &Block) -> Vec<usize> {
    match &block.terminator {
        Terminator::Fallthrough(to) | Terminator::Jump(to) => vec![*to],
        Terminator::Conditional {
            taken, fallthrough, ..
        } => vec![*taken, *fallthrough],
        Terminator::Return => Vec::new(),
    }
}

fn retarget(terminator: &Terminator, remap: &dyn Fn(usize) -> usize) -> Terminator {
    match terminator {
        Terminator::Fallthrough(to) => Terminator::Fallthrough(remap(*to)),
        Terminator::Jump(to) => Terminator::Jump(remap(*to)),
        Terminator::Conditional {
            cmp_index,
            branch_mnemonic,
            taken,
            fallthrough,
        } => Terminator::Conditional {
            cmp_index: *cmp_index,
            branch_mnemonic: *branch_mnemonic,
            taken: remap(*taken),
            fallthrough: remap(*fallthrough),
        },
        Terminator::Return => Terminator::Return,
    }
}

fn region_flow(region: &Region) -> Option<FlowGraph<usize>> {
    FlowGraph::build(
        0..region.blocks.len(),
        region.entry_block,
        |node: usize, emit: &mut dyn FnMut(Flow<usize>)| {
            let Some(block): Option<&Block> = region.blocks.get(node) else {
                return;
            };
            let targets: Vec<usize> = successors(block);
            if targets.is_empty() {
                emit(Flow::Exit);
            }
            for target in targets {
                emit(Flow::To(target));
            }
        },
    )
    .ok()
}

#[derive(Debug, Clone)]
struct NaturalLoop {
    header: usize,
    latch: usize,
    body: BTreeSet<usize>,
    exit_target: usize,
}

fn detect_single_loop(region: &Region) -> Option<NaturalLoop> {
    let dom: FlowGraph<usize> = region_flow(region)?;
    let edges: Vec<(usize, usize)> = dom.back_edges();
    if edges.len() != 1 {
        return None;
    }
    let (latch, header): (usize, usize) = edges[0];

    for (from, block) in region.blocks.iter().enumerate() {
        for succ in successors(block) {
            if succ == header && from != latch && !dom.dominates(from, succ) {
                return None;
            }
        }
    }

    let body: BTreeSet<usize> = dom.natural_loop_body(header, &[latch]);

    let mut exits: BTreeSet<usize> = BTreeSet::new();
    for &node in &body {
        for succ in successors(&region.blocks[node]) {
            if !body.contains(&succ) {
                exits.insert(succ);
            }
        }
    }
    if exits.len() != 1 {
        return None;
    }
    let exit_target: usize = exits.into_iter().next()?;

    if !matches!(region.blocks[latch].terminator, Terminator::Jump(_)) {
        return None;
    }

    Some(NaturalLoop {
        header,
        latch,
        body,
        exit_target,
    })
}

fn loop_variant_widen(insns: &[Instruction], region: &Region, lp: &NaturalLoop) -> WidenSet {
    let mut widen: WidenSet = WidenSet::default();
    for &node in &lp.body {
        let block: &Block = &region.blocks[node];
        for insn in &insns[block.body.clone()] {
            collect_written(insn, &mut widen);
        }
    }
    widen
}

fn collect_written(insn: &Instruction, widen: &mut WidenSet) {
    if insn.op_count() == 0 {
        return;
    }
    match insn.op0_kind() {
        OpKind::Register => {
            let full: Register = insn.op0_register().full_register();
            let reg: Register = if full == Register::None {
                insn.op0_register()
            } else {
                full
            };
            widen.registers.insert(reg);
        }
        OpKind::Memory
            if insn.memory_index() == Register::None
                && matches!(
                    insn.memory_base(),
                    Register::RSP | Register::RBP | Register::ESP | Register::EBP
                ) =>
        {
            widen.cells.insert(StackCell {
                base: insn.memory_base().full_register(),
                disp: insn.memory_displacement64().cast_signed(),
            });
        }
        _ => {}
    }
}

fn unroll_natural_loops(insns: &[Instruction], region: Region) -> Option<Region> {
    let mut current: Region = region;
    for _ in 0..MAX_LOOPS {
        if topological_order(&current).is_some() {
            return Some(current);
        }
        let lp: NaturalLoop = detect_single_loop(&current)?;
        current = unroll_one(insns, &current, &lp)?;
    }
    if topological_order(&current).is_some() {
        Some(current)
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy)]
enum ContinueSide {
    Taken,
    Fallthrough,
}

fn unroll_one(insns: &[Instruction], region: &Region, lp: &NaturalLoop) -> Option<Region> {
    let Terminator::Conditional {
        cmp_index,
        branch_mnemonic,
        taken,
        fallthrough,
    } = region.blocks[lp.header].terminator
    else {
        return None;
    };
    let continue_side: ContinueSide = if lp.body.contains(&taken) && fallthrough == lp.exit_target {
        ContinueSide::Taken
    } else if lp.body.contains(&fallthrough) && taken == lp.exit_target {
        ContinueSide::Fallthrough
    } else {
        return None;
    };

    let widen: WidenSet = loop_variant_widen(insns, region, lp);

    let outside: Vec<usize> = (0..region.blocks.len())
        .filter(|node: &usize| !lp.body.contains(node))
        .collect();
    let outside_map: BTreeMap<usize, usize> = outside
        .iter()
        .enumerate()
        .map(|(new, old): (usize, &usize)| (*old, new))
        .collect();

    let body_order: Vec<usize> = lp.body.iter().copied().collect();
    let body_index: BTreeMap<usize, usize> = body_order
        .iter()
        .enumerate()
        .map(|(i, old): (usize, &usize)| (*old, i))
        .collect();

    let outside_count: usize = outside.len();
    let copy_stride: usize = body_order.len();
    let copies_base: usize = outside_count;
    let joins_base: usize = copies_base + MAX_UNROLL * copy_stride;
    let widen_block_id: usize = joins_base + MAX_UNROLL;
    let total_blocks: usize = widen_block_id + 1;
    if total_blocks > MAX_UNROLLED_BLOCKS {
        return None;
    }

    let body_clone_id =
        |copy: usize, old: usize| -> usize { copies_base + copy * copy_stride + body_index[&old] };
    let join_id = |copy: usize| -> usize { joins_base + copy };
    let exit_id: usize = *outside_map.get(&lp.exit_target)?;

    let mut blocks: Vec<Option<Block>> = vec![None; total_blocks];

    for &old in &outside {
        let block: &Block = &region.blocks[old];
        let remap = |target: usize| -> usize {
            outside_map
                .get(&target)
                .copied()
                .unwrap_or_else(|| body_clone_id(0, target))
        };
        blocks[outside_map[&old]] = Some(Block {
            body: block.body.clone(),
            terminator: retarget(&block.terminator, &remap),
            widen: block.widen.clone(),
        });
    }

    for copy in 0..MAX_UNROLL {
        for &old in &body_order {
            let block: &Block = &region.blocks[old];
            let exit_to: usize = join_id(copy);
            let continue_to = |target: usize| -> usize {
                if old == lp.latch && target == lp.header {
                    if copy + 1 < MAX_UNROLL {
                        body_clone_id(copy + 1, lp.header)
                    } else {
                        widen_block_id
                    }
                } else {
                    body_clone_id(copy, target)
                }
            };
            let terminator: Terminator = if old == lp.header {
                let (taken_to, fallthrough_to): (usize, usize) = match continue_side {
                    ContinueSide::Taken => (continue_to(taken), exit_to),
                    ContinueSide::Fallthrough => (exit_to, continue_to(fallthrough)),
                };
                Terminator::Conditional {
                    cmp_index,
                    branch_mnemonic,
                    taken: taken_to,
                    fallthrough: fallthrough_to,
                }
            } else {
                let remap = |target: usize| -> usize {
                    if lp.body.contains(&target) {
                        continue_to(target)
                    } else {
                        outside_map
                            .get(&target)
                            .copied()
                            .unwrap_or_else(|| body_clone_id(0, target))
                    }
                };
                retarget(&block.terminator, &remap)
            };
            blocks[body_clone_id(copy, old)] = Some(Block {
                body: block.body.clone(),
                terminator,
                widen: block.widen.clone(),
            });
        }
    }

    let header_body: std::ops::Range<usize> = region.blocks[lp.header].body.clone();
    let empty: std::ops::Range<usize> = header_body.start..header_body.start;

    for copy in 0..MAX_UNROLL {
        let outward: usize = if copy == 0 {
            exit_id
        } else {
            join_id(copy - 1)
        };
        blocks[join_id(copy)] = Some(Block {
            body: empty.clone(),
            terminator: Terminator::Jump(outward),
            widen: None,
        });
    }

    blocks[widen_block_id] = Some(Block {
        body: empty,
        terminator: Terminator::Jump(join_id(MAX_UNROLL - 1)),
        widen: Some(widen),
    });

    let entry_block: usize = if lp.body.contains(&region.entry_block) {
        body_clone_id(0, region.entry_block)
    } else {
        *outside_map.get(&region.entry_block)?
    };

    let blocks: Vec<Block> = blocks.into_iter().collect::<Option<Vec<Block>>>()?;

    Some(Region {
        blocks,
        entry_block,
    })
}

fn topological_order(region: &Region) -> Option<Vec<usize>> {
    let count: usize = region.blocks.len();
    let mut indegree: Vec<usize> = vec![0usize; count];
    for block in &region.blocks {
        for succ in successors(block) {
            if succ >= count {
                return None;
            }
            indegree[succ] += 1;
        }
    }
    if indegree[region.entry_block] != 0 {
        return None;
    }
    let mut ready: Vec<usize> = vec![region.entry_block];
    let mut order: Vec<usize> = Vec::with_capacity(count);
    let mut remaining: Vec<usize> = indegree.clone();
    let mut seen: BTreeSet<usize> = BTreeSet::new();
    while let Some(node) = ready.pop() {
        if !seen.insert(node) {
            continue;
        }
        order.push(node);
        for succ in successors(&region.blocks[node]) {
            remaining[succ] -= 1;
            if remaining[succ] == 0 {
                ready.push(succ);
            }
        }
    }
    if order.len() != count {
        return None;
    }
    Some(order)
}

fn predecessors(region: &Region) -> Vec<Vec<usize>> {
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); region.blocks.len()];
    for (from, block) in region.blocks.iter().enumerate() {
        for succ in successors(block) {
            preds[succ].push(from);
        }
    }
    preds
}

fn merge_plan(
    region: &Region,
    join: Option<usize>,
    preds: &[usize],
    dom: &FlowGraph<usize>,
) -> Option<MergePlan> {
    if preds.len() != 2 {
        return None;
    }
    let controller: usize = dom
        .dominator_set(preds[0])
        .into_iter()
        .filter(|node: &usize| dom.dominates(*node, preds[1]))
        .max()?;
    let Terminator::Conditional {
        taken, fallthrough, ..
    } = region.blocks[controller].terminator
    else {
        return None;
    };
    let on_side = |pred: usize, head: usize| -> bool {
        pred == head || dom.dominates(head, pred) || (Some(head) == join && pred == controller)
    };
    let side_of = |pred: usize| -> Option<Side> {
        if on_side(pred, taken) {
            Some(Side::Taken)
        } else if on_side(pred, fallthrough) {
            Some(Side::Fallthrough)
        } else {
            None
        }
    };
    let (taken_pred, fallthrough_pred): (usize, usize) =
        match (side_of(preds[0])?, side_of(preds[1])?) {
            (Side::Taken, Side::Fallthrough) => (preds[0], preds[1]),
            (Side::Fallthrough, Side::Taken) => (preds[1], preds[0]),
            _ => return None,
        };
    Some(MergePlan {
        controller,
        taken_pred,
        fallthrough_pred,
    })
}

fn summarize_region(
    insns: &[Instruction],
    region: &Region,
    order: &[usize],
) -> Option<FunctionSummary> {
    let preds: Vec<Vec<usize>> = predecessors(region);
    let dom: FlowGraph<usize> = region_flow(region)?;
    let mut exit_states: Vec<Option<RegFile>> = vec![None; region.blocks.len()];
    let mut branch_facts: BTreeMap<usize, BranchFact> = BTreeMap::new();
    let mut width: Width = Width::W64;
    let mut input_seeds: RegFile = RegFile::new();
    let mut join_count: usize = 0;

    for &block_id in order {
        let block: &Block = &region.blocks[block_id];
        let incoming: &[usize] = &preds[block_id];

        let mut state: RegFile = if block_id == region.entry_block {
            let mut entry: RegFile = RegFile::new();
            for reg in CANDIDATE_REGISTERS {
                let _: u32 = entry.seed_or_create(reg);
            }
            entry
        } else if incoming.len() == 1 {
            exit_states[incoming[0]].clone()?
        } else {
            join_count += 1;
            if join_count > MAX_JOINS {
                return None;
            }
            let plan: MergePlan = merge_plan(region, Some(block_id), incoming, &dom)?;
            merge_states(&plan, &exit_states)?
        };

        if let Some(widen) = &block.widen {
            apply_widen(&mut state, widen);
        }

        for insn in &insns[block.body.clone()] {
            if !straight_line(insn) || !state.apply_insn(insn) || state.is_capped() {
                return None;
            }
        }

        if let Terminator::Conditional {
            cmp_index,
            branch_mnemonic,
            ..
        } = block.terminator
        {
            let cmp: &Instruction = &insns[cmp_index];
            let (predicate, branch_width): (Predicate, Width) =
                build_predicate(&mut state, cmp, branch_mnemonic)?;
            if state.is_capped() {
                return None;
            }
            width = branch_width;
            let condition_var: u32 = CONDITION_VAR_BASE + block_id as u32;
            branch_facts.insert(
                block_id,
                BranchFact {
                    predicate,
                    condition_var,
                    branch_address: insns[cmp_index + 1].ip(),
                },
            );
        }

        if block_id == region.entry_block {
            input_seeds = state.clone();
        } else {
            input_seeds.adopt_next_var(state.next_var());
        }

        exit_states[block_id] = Some(state);
    }

    finalize_summary(
        region,
        &dom,
        &exit_states,
        &branch_facts,
        &input_seeds,
        width,
    )
}

fn merge_states(plan: &MergePlan, exit_states: &[Option<RegFile>]) -> Option<RegFile> {
    let taken_state: &RegFile = exit_states[plan.taken_pred].as_ref()?;
    let fallback_state: &RegFile = exit_states[plan.fallthrough_pred].as_ref()?;

    let cond: Expr = condition_expr_for(plan.controller as u32);
    let mut merged: RegFile = fallback_state.clone();
    merged.adopt_next_var(taken_state.next_var());

    let mut reg_keys: BTreeSet<Register> = BTreeSet::new();
    for reg in taken_state.bound_registers() {
        reg_keys.insert(reg);
    }
    for reg in fallback_state.bound_registers() {
        reg_keys.insert(reg);
    }
    for reg in reg_keys {
        let then_expr: Expr = binding_or_seed(taken_state, &mut merged, reg);
        let else_expr: Expr = binding_or_seed(fallback_state, &mut merged, reg);
        let value: Expr = if then_expr == else_expr {
            then_expr
        } else {
            Expr::ite(cond.clone(), then_expr, else_expr)
        };
        merged.set_reg_binding(reg, value);
    }

    let mut cell_keys: BTreeSet<StackCell> = BTreeSet::new();
    for cell in taken_state.bound_stack_cells() {
        cell_keys.insert(cell);
    }
    for cell in fallback_state.bound_stack_cells() {
        cell_keys.insert(cell);
    }
    for cell in cell_keys {
        let then_expr: Expr = stack_binding_or_seed(taken_state, &mut merged, cell);
        let else_expr: Expr = stack_binding_or_seed(fallback_state, &mut merged, cell);
        let value: Expr = if then_expr == else_expr {
            then_expr
        } else {
            Expr::ite(cond.clone(), then_expr, else_expr)
        };
        merged.set_stack_binding(cell, value);
    }

    Some(merged)
}

fn binding_or_seed(source: &RegFile, merged: &mut RegFile, reg: Register) -> Expr {
    source
        .binding(reg)
        .map_or_else(|| merged.current(reg), Clone::clone)
}

fn stack_binding_or_seed(source: &RegFile, merged: &mut RegFile, cell: StackCell) -> Expr {
    if let Some(expr) = source.stack_binding(cell) {
        return expr.clone();
    }
    if let Some(expr) = merged.stack_binding(cell) {
        return expr.clone();
    }
    Expr::var(merged.fresh_var())
}

fn condition_expr_for(controller: u32) -> Expr {
    Expr::var(CONDITION_VAR_BASE + controller)
}

fn apply_widen(state: &mut RegFile, widen: &WidenSet) {
    for &reg in &widen.registers {
        let fresh: u32 = state.fresh_var();
        state.set_reg_binding(reg, Expr::var(fresh));
    }
    for &cell in &widen.cells {
        let fresh: u32 = state.fresh_var();
        state.set_stack_binding(cell, Expr::var(fresh));
    }
}

const CONDITION_VAR_BASE: u32 = 100_000;

fn finalize_summary(
    region: &Region,
    dom: &FlowGraph<usize>,
    exit_states: &[Option<RegFile>],
    branch_facts: &BTreeMap<usize, BranchFact>,
    input_seeds: &RegFile,
    width: Width,
) -> Option<FunctionSummary> {
    let return_blocks: Vec<usize> = region
        .blocks
        .iter()
        .enumerate()
        .filter_map(|(i, block): (usize, &Block)| {
            matches!(block.terminator, Terminator::Return).then_some(i)
        })
        .collect();
    if return_blocks.is_empty() {
        return None;
    }

    let merged: RegFile = if return_blocks.len() == 1 {
        exit_states[return_blocks[0]].clone()?
    } else {
        if return_blocks.len() != 2 {
            return None;
        }
        let plan: MergePlan = merge_plan(region, None, &return_blocks, dom)?;
        merge_states(&plan, exit_states)?
    };

    let mut outputs: BTreeMap<Register, Expr> = BTreeMap::new();
    for reg in merged.bound_registers() {
        if let Some(expr) = merged.binding(reg) {
            outputs.insert(reg, expr.clone());
        }
    }
    if outputs.len() > MAX_OUTPUT_REGISTERS {
        return None;
    }

    let mut stack_outputs: BTreeMap<StackKey, Expr> = BTreeMap::new();
    for cell in merged.bound_stack_cells() {
        if let Some(expr) = merged.stack_binding(cell) {
            stack_outputs.insert(StackKey::from(cell), expr.clone());
        }
    }
    if stack_outputs.len() > MAX_OUTPUT_STACK_CELLS {
        return None;
    }

    let branches: Vec<BranchFact> = branch_facts.values().cloned().collect();
    let primary: &BranchFact = branches.first()?;
    let input_seed_map: BTreeMap<Register, u32> = collect_input_seeds(input_seeds);

    Some(FunctionSummary {
        outputs,
        stack_outputs,
        width,
        predicate: primary.predicate.clone(),
        condition_var: primary.condition_var,
        branch_address: primary.branch_address,
        branches,
        input_seeds: input_seed_map,
    })
}

fn build_predicate(
    regs: &mut RegFile,
    cmp: &Instruction,
    branch: Mnemonic,
) -> Option<(Predicate, Width)> {
    if cmp.op0_kind() != OpKind::Register {
        return None;
    }
    let width: Width = register_width(cmp.op0_register());
    match cmp.mnemonic() {
        Mnemonic::Cmp => {
            let left: Expr = regs.current(cmp.op0_register());
            let right: Expr = operand_expr(regs, cmp, 1)?;
            let op: CmpOp = branch_to_cmp(branch)?;
            Some((Predicate::Compare { op, left, right }, width))
        }
        Mnemonic::Test => {
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

fn collect_input_seeds(regs: &RegFile) -> BTreeMap<Register, u32> {
    let mut seeds: BTreeMap<Register, u32> = BTreeMap::new();
    for reg in CANDIDATE_REGISTERS {
        if let Some(index) = regs.seed_index(reg) {
            seeds.insert(reg, index);
        }
    }
    seeds
}

const CANDIDATE_REGISTERS: [Register; 8] = [
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::RBX,
    Register::RSI,
    Register::RDI,
    Register::R8,
    Register::R9,
];

fn straight_line(insn: &Instruction) -> bool {
    matches!(insn.flow_control(), FlowControl::Next) && !insn.has_lock_prefix()
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
mod tests {
    use super::*;
    use crate::deobf::mba_lift::RegFile as MemRegFile;
    use crate::stub_emu::cpu::NoopHost;
    use crate::stub_emu::{Cpu, CpuMode, ExitReason, Perm, Reg};
    use disrobe_mba::Width as MbaWidth;
    use iced_x86::code_asm::{
        CodeAssembler, CodeLabel, dword_ptr, eax, ecx, edi, edx, esi, rdi, rsi, rsp,
    };
    use iced_x86::{Decoder, DecoderOptions};

    const BASE: u64 = 0x1_4000;
    const STACK_TOP: u64 = 0x2_0FF0;
    const RET_SENTINEL: u64 = 0xDEAD_0000;
    const SCRATCH_DISP: i64 = -8;

    #[derive(Debug, Clone, Copy)]
    struct Outcome {
        eax: u64,
        scratch: u64,
    }

    fn diamond_bytes() -> Vec<u8> {
        let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
        let mut else_arm: CodeLabel = asm.create_label();
        let mut join: CodeLabel = asm.create_label();
        asm.cmp(edi, esi).unwrap();
        asm.jg(else_arm).unwrap();
        asm.mov(eax, edi).unwrap();
        asm.add(eax, esi).unwrap();
        asm.jmp(join).unwrap();
        asm.set_label(&mut else_arm).unwrap();
        asm.mov(eax, edi).unwrap();
        asm.sub(eax, esi).unwrap();
        asm.set_label(&mut join).unwrap();
        asm.add(eax, 1u32).unwrap();
        asm.ret().unwrap();
        asm.assemble(BASE).expect("assemble diamond")
    }

    fn sequential_bytes() -> Vec<u8> {
        let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
        let mut skip_first: CodeLabel = asm.create_label();
        let mut skip_second: CodeLabel = asm.create_label();
        asm.mov(eax, edi).unwrap();
        asm.cmp(edi, esi).unwrap();
        asm.jle(skip_first).unwrap();
        asm.add(eax, 100u32).unwrap();
        asm.set_label(&mut skip_first).unwrap();
        asm.cmp(edx, ecx).unwrap();
        asm.jle(skip_second).unwrap();
        asm.add(eax, 7u32).unwrap();
        asm.set_label(&mut skip_second).unwrap();
        asm.mov(dword_ptr(rsp - 8), eax).unwrap();
        asm.ret().unwrap();
        asm.assemble(BASE).expect("assemble sequential")
    }

    fn nested_bytes() -> Vec<u8> {
        let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
        let mut outer_else: CodeLabel = asm.create_label();
        let mut inner_else: CodeLabel = asm.create_label();
        let mut inner_join: CodeLabel = asm.create_label();
        let mut outer_join: CodeLabel = asm.create_label();
        asm.cmp(edi, esi).unwrap();
        asm.jle(outer_else).unwrap();
        asm.cmp(edi, edx).unwrap();
        asm.jle(inner_else).unwrap();
        asm.mov(eax, edi).unwrap();
        asm.add(eax, edx).unwrap();
        asm.jmp(inner_join).unwrap();
        asm.set_label(&mut inner_else).unwrap();
        asm.mov(eax, edi).unwrap();
        asm.sub(eax, edx).unwrap();
        asm.set_label(&mut inner_join).unwrap();
        asm.jmp(outer_join).unwrap();
        asm.set_label(&mut outer_else).unwrap();
        asm.mov(eax, esi).unwrap();
        asm.add(eax, 1u32).unwrap();
        asm.set_label(&mut outer_join).unwrap();
        asm.mov(dword_ptr(rsp - 8), eax).unwrap();
        asm.ret().unwrap();
        asm.assemble(BASE).expect("assemble nested")
    }

    fn run_concrete(bytes: &[u8], inputs: [u32; 4]) -> Outcome {
        let mut cpu: Cpu = Cpu::new(CpuMode::Bits64);
        cpu.mem.map(BASE, 0x1000, Perm::RWX).expect("map code");
        cpu.mem.write_unchecked(BASE, bytes);
        cpu.mem.map(0x2_0000, 0x1000, Perm::RW).expect("map stack");
        cpu.mem
            .write_u64(STACK_TOP, RET_SENTINEL)
            .expect("seed return address");
        cpu.regs.set(Reg::Rsp, STACK_TOP);
        cpu.regs.set(Reg::Rdi, u64::from(inputs[0]));
        cpu.regs.set(Reg::Rsi, u64::from(inputs[1]));
        cpu.regs.set(Reg::Rdx, u64::from(inputs[2]));
        cpu.regs.set(Reg::Rcx, u64::from(inputs[3]));
        cpu.regs.rip = BASE;
        let mut host: NoopHost = NoopHost;
        let exit: ExitReason = cpu.run(&mut host, 1000).expect("run");
        match exit {
            ExitReason::JumpedOutOfRange { to, .. } if to == RET_SENTINEL => {}
            other => panic!("expected clean return to sentinel, got {other:?}"),
        }
        let scratch: u64 = u64::from(
            cpu.mem
                .read_u32(STACK_TOP.wrapping_add(SCRATCH_DISP as u64))
                .expect("read scratch cell"),
        );
        Outcome {
            eax: cpu.regs.read_sized(Reg::Rax, 32),
            scratch,
        }
    }

    fn build_env(summary: &FunctionSummary, inputs: [u32; 4], extent: u32) -> Vec<u64> {
        let mut span: u32 = extent;
        for branch in &summary.branches {
            span = span.max(branch.condition_var + 1);
        }
        let mut env: Vec<u64> = vec![0u64; span as usize];
        let pairs: [(Register, u32); 4] = [
            (Register::RDI, inputs[0]),
            (Register::RSI, inputs[1]),
            (Register::RDX, inputs[2]),
            (Register::RCX, inputs[3]),
        ];
        for (reg, value) in pairs {
            if let Some(seed) = summary.input_seeds.get(&reg) {
                env[*seed as usize] = u64::from(value);
            }
        }
        for branch in &summary.branches {
            let truth: bool = summary.branch_condition(branch, &env);
            env[branch.condition_var as usize] = u64::from(truth);
        }
        env
    }

    fn concretize(summary: &FunctionSummary, output: &Expr, inputs: [u32; 4]) -> u64 {
        let extent: u32 = output.max_var().map_or(0, |v: u32| v + 1);
        let env: Vec<u64> = build_env(summary, inputs, extent);
        output.eval(&env, summary.width)
    }

    fn concretize_surfaced(summary: &FunctionSummary, output: &Expr, inputs: [u32; 4]) -> u64 {
        let extent: u32 = output.max_var().map_or(0, |v: u32| v + 1);
        let sparse_env: Vec<u64> = build_env(summary, inputs, extent);
        let (surfaced, remap): (Expr, BTreeMap<u32, u32>) = verified_simplify_expr(output);
        let dense_len: u32 = remap.values().copied().max().map_or(0, |v: u32| v + 1);
        let mut dense_env: Vec<u64> = vec![0u64; dense_len as usize];
        for (original, dense) in &remap {
            dense_env[*dense as usize] = sparse_env.get(*original as usize).copied().unwrap_or(0);
        }
        surfaced.eval(&dense_env, summary.width)
    }

    #[test]
    fn surfaced_simplified_summary_matches_stub_emu_diamond() {
        let bytes: Vec<u8> = diamond_bytes();
        let summary: FunctionSummary =
            summarize(64, BASE, &bytes, BASE).expect("diamond must summarize");
        let eax_expr: Expr = summary
            .outputs
            .get(&Register::RAX)
            .expect("eax output")
            .clone();
        let vectors: [(u32, u32); 6] = [(0, 0), (5, 3), (3, 5), (255, 1), (1, 255), (200, 100)];
        for (edi_in, esi_in) in vectors {
            let inputs: [u32; 4] = [edi_in, esi_in, 0, 0];
            let concrete: u64 = run_concrete(&bytes, inputs).eax;
            let surfaced: u64 = concretize_surfaced(&summary, &eax_expr, inputs);
            assert_eq!(
                surfaced, concrete,
                "surfaced simplified eax disagrees with stub_emu at edi={edi_in:#x} esi={esi_in:#x}"
            );
        }
    }

    #[test]
    fn surfaced_simplified_summary_matches_stub_emu_sequential_stack_cell() {
        let bytes: Vec<u8> = sequential_bytes();
        let summary: FunctionSummary =
            summarize(64, BASE, &bytes, BASE).expect("sequential region must summarize");
        let scratch_key: StackKey = StackKey {
            base: Register::RSP,
            disp: SCRATCH_DISP,
        };
        let scratch_expr: Expr = summary
            .stack_outputs
            .get(&scratch_key)
            .expect("scratch stack cell output")
            .clone();
        let vectors: [[u32; 4]; 5] = [
            [5, 3, 9, 2],
            [3, 5, 2, 9],
            [9, 1, 1, 1],
            [10, 10, 10, 10],
            [2, 1, 1, 2],
        ];
        for inputs in vectors {
            let concrete: u64 = run_concrete(&bytes, inputs).scratch;
            let surfaced: u64 = concretize_surfaced(&summary, &scratch_expr, inputs);
            assert_eq!(
                surfaced, concrete,
                "surfaced simplified stack cell disagrees with stub_emu at inputs {inputs:?}"
            );
        }
    }

    #[test]
    fn verified_simplify_preserves_semantics_on_outputs() {
        for bytes in [diamond_bytes(), sequential_bytes(), nested_bytes()] {
            let summary: FunctionSummary =
                summarize(64, BASE, &bytes, BASE).expect("fixture must summarize");
            for expr in summary
                .outputs
                .values()
                .chain(summary.stack_outputs.values())
            {
                let (surfaced, remap): (Expr, BTreeMap<u32, u32>) = verified_simplify_expr(expr);
                let dense_original: Expr = expr.remap_vars(&remap);
                if surfaced == dense_original {
                    continue;
                }
                let arity: u32 = remap.len() as u32;
                let width: Width = verifiable_width(arity).expect("arity within budget");
                assert!(
                    equivalent_exhaustive(&dense_original, &surfaced, width, arity),
                    "verified-simplify must preserve semantics: {dense_original} != {surfaced}"
                );
            }
        }
    }

    #[test]
    fn verified_simplify_reduces_linear_mba_and_proves_equivalent() {
        let obfuscated: Expr = Expr::add(
            Expr::xor(Expr::var(7), Expr::var(9)),
            Expr::mul(Expr::konst(2), Expr::and(Expr::var(7), Expr::var(9))),
        );
        let (surfaced, remap): (Expr, BTreeMap<u32, u32>) = verified_simplify_expr(&obfuscated);
        let dense_original: Expr = obfuscated.remap_vars(&remap);
        assert_ne!(
            surfaced, dense_original,
            "the canonical MBA identity (x ^ y) + 2*(x & y) must reduce to x + y"
        );
        assert!(
            equivalent_exhaustive(&dense_original, &surfaced, Width::W8, 2),
            "reduced form `{surfaced}` must be exhaustively equal to the obfuscated input"
        );
        let expected: Expr = Expr::add(Expr::var(0), Expr::var(1));
        assert!(
            equivalent_exhaustive(&surfaced, &expected, Width::W8, 2),
            "reduced form `{surfaced}` must equal x + y after densify"
        );
    }

    #[test]
    fn verified_simplify_renders_dense_var_names() {
        let expr: Expr = Expr::add(Expr::var(100), Expr::var(200));
        let rendered: String = verified_simplify(&expr);
        assert_eq!(rendered, "(v0 + v1)");
    }

    #[test]
    fn summarizes_single_diamond_into_ite() {
        let bytes: Vec<u8> = diamond_bytes();
        let summary: FunctionSummary =
            summarize(64, BASE, &bytes, BASE).expect("diamond must summarize");
        let eax_expr: &Expr = summary.outputs.get(&Register::RAX).expect("eax output");
        assert!(
            contains_ite(eax_expr),
            "the join-merged output register must carry a path-dependent Ite, got {eax_expr}"
        );
    }

    fn contains_ite(expr: &Expr) -> bool {
        match expr {
            Expr::Ite(_, _, _) => true,
            Expr::Const(_) | Expr::Var(_) => false,
            Expr::Unary(_, inner) | Expr::Slice(inner, _, _) | Expr::Mem(inner, _) => {
                contains_ite(inner)
            }
            Expr::Binary(_, left, right) | Expr::Compose(left, right, _) => {
                contains_ite(left) || contains_ite(right)
            }
        }
    }

    #[test]
    fn symbolic_summary_matches_stub_emu_both_branches() {
        let bytes: Vec<u8> = diamond_bytes();
        let summary: FunctionSummary =
            summarize(64, BASE, &bytes, BASE).expect("diamond must summarize");
        let eax_expr: Expr = summary
            .outputs
            .get(&Register::RAX)
            .expect("eax output")
            .clone();

        let vectors: [(u32, u32); 12] = [
            (0, 0),
            (5, 3),
            (3, 5),
            (10, 10),
            (1, 2),
            (255, 1),
            (1, 255),
            (0xFFFF_FFFF, 1),
            (7, 7),
            (100, 200),
            (200, 100),
            (0x8000_0000, 0x7FFF_FFFF),
        ];

        let mut saw_then: bool = false;
        let mut saw_else: bool = false;
        for (edi_in, esi_in) in vectors {
            let inputs: [u32; 4] = [edi_in, esi_in, 0, 0];
            let concrete: u64 = run_concrete(&bytes, inputs).eax;
            let symbolic: u64 = concretize(&summary, &eax_expr, inputs);
            assert_eq!(
                symbolic, concrete,
                "summary disagrees with stub_emu at edi={edi_in:#x} esi={esi_in:#x}"
            );
            if (edi_in as i32) > (esi_in as i32) {
                saw_else = true;
            } else {
                saw_then = true;
            }
        }
        assert!(
            saw_then && saw_else,
            "the oracle must cover both branch directions"
        );
    }

    #[test]
    fn sequential_conditionals_match_stub_emu_all_paths() {
        let bytes: Vec<u8> = sequential_bytes();
        let summary: FunctionSummary =
            summarize(64, BASE, &bytes, BASE).expect("sequential region must summarize");
        assert_eq!(summary.branches.len(), 2, "two sequential conditionals");
        let eax_expr: Expr = summary
            .outputs
            .get(&Register::RAX)
            .expect("eax output")
            .clone();
        let scratch_key: StackKey = StackKey {
            base: Register::RSP,
            disp: SCRATCH_DISP,
        };
        let scratch_expr: Expr = summary
            .stack_outputs
            .get(&scratch_key)
            .expect("scratch stack cell output")
            .clone();

        let vectors: [[u32; 4]; 8] = [
            [5, 3, 9, 2],
            [3, 5, 2, 9],
            [9, 1, 1, 1],
            [1, 9, 9, 1],
            [1, 9, 1, 9],
            [10, 10, 10, 10],
            [0xFFFF_FFFF, 1, 0xFFFF_FFFF, 1],
            [2, 1, 1, 2],
        ];

        let mut paths: BTreeSet<(bool, bool)> = BTreeSet::new();
        for inputs in vectors {
            let outcome: Outcome = run_concrete(&bytes, inputs);
            let eax_sym: u64 = concretize(&summary, &eax_expr, inputs);
            let scratch_sym: u64 = concretize(&summary, &scratch_expr, inputs);
            assert_eq!(
                eax_sym, outcome.eax,
                "eax mismatch at inputs {inputs:?}: symbolic {eax_sym:#x} vs concrete {:#x}",
                outcome.eax
            );
            assert_eq!(
                scratch_sym, outcome.scratch,
                "stack-cell mismatch at inputs {inputs:?}: symbolic {scratch_sym:#x} vs concrete {:#x}",
                outcome.scratch
            );
            let first: bool = (inputs[0] as i32) > (inputs[1] as i32);
            let second: bool = (inputs[2] as i32) > (inputs[3] as i32);
            paths.insert((first, second));
        }
        assert_eq!(
            paths.len(),
            4,
            "the oracle must exercise all four sequential-conditional paths, saw {paths:?}"
        );
    }

    #[test]
    fn nested_conditional_matches_stub_emu_all_paths() {
        let bytes: Vec<u8> = nested_bytes();
        let summary: FunctionSummary =
            summarize(64, BASE, &bytes, BASE).expect("nested region must summarize");
        assert_eq!(summary.branches.len(), 2, "outer plus inner conditional");
        let eax_expr: Expr = summary
            .outputs
            .get(&Register::RAX)
            .expect("eax output")
            .clone();
        let scratch_key: StackKey = StackKey {
            base: Register::RSP,
            disp: SCRATCH_DISP,
        };
        let scratch_expr: Expr = summary
            .stack_outputs
            .get(&scratch_key)
            .expect("scratch stack cell output")
            .clone();

        let vectors: [[u32; 4]; 9] = [
            [9, 1, 5, 0],
            [9, 1, 50, 0],
            [1, 9, 5, 0],
            [9, 1, 9, 0],
            [10, 5, 3, 0],
            [10, 5, 40, 0],
            [5, 10, 1, 0],
            [0xFFFF_FFFF, 1, 2, 0],
            [2, 3, 9, 0],
        ];

        let mut paths: BTreeSet<u8> = BTreeSet::new();
        for inputs in vectors {
            let outcome: Outcome = run_concrete(&bytes, inputs);
            let eax_sym: u64 = concretize(&summary, &eax_expr, inputs);
            let scratch_sym: u64 = concretize(&summary, &scratch_expr, inputs);
            assert_eq!(
                eax_sym, outcome.eax,
                "eax mismatch at inputs {inputs:?}: symbolic {eax_sym:#x} vs concrete {:#x}",
                outcome.eax
            );
            assert_eq!(
                scratch_sym, outcome.scratch,
                "stack-cell mismatch at inputs {inputs:?}: symbolic {scratch_sym:#x} vs concrete {:#x}",
                outcome.scratch
            );
            let outer: bool = (inputs[0] as i32) > (inputs[1] as i32);
            let inner: bool = (inputs[0] as i32) > (inputs[2] as i32);
            let label: u8 = if !outer {
                0
            } else if inner {
                1
            } else {
                2
            };
            paths.insert(label);
        }
        assert_eq!(
            paths.len(),
            3,
            "the oracle must exercise all three nested paths, saw {paths:?}"
        );
    }

    #[test]
    fn stack_cell_merges_into_ite() {
        let bytes: Vec<u8> = sequential_bytes();
        let summary: FunctionSummary =
            summarize(64, BASE, &bytes, BASE).expect("sequential region must summarize");
        let scratch_key: StackKey = StackKey {
            base: Register::RSP,
            disp: SCRATCH_DISP,
        };
        let scratch_expr: &Expr = summary
            .stack_outputs
            .get(&scratch_key)
            .expect("scratch stack cell output");
        assert!(
            matches!(scratch_expr, Expr::Ite(_, _, _)),
            "the merged stack cell must be path-dependent, got {scratch_expr}"
        );
    }

    #[test]
    fn bails_on_non_diamond_straight_line() {
        let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
        asm.mov(eax, edi).unwrap();
        asm.add(eax, esi).unwrap();
        asm.ret().unwrap();
        let bytes: Vec<u8> = asm.assemble(BASE).expect("assemble straight line");
        assert!(
            summarize(64, BASE, &bytes, BASE).is_none(),
            "a function with no conditional branch is not a diamond"
        );
    }

    fn sum_loop_bytes() -> Vec<u8> {
        let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
        let mut top: CodeLabel = asm.create_label();
        let mut done: CodeLabel = asm.create_label();
        asm.xor(eax, eax).unwrap();
        asm.xor(edx, edx).unwrap();
        asm.set_label(&mut top).unwrap();
        asm.cmp(edx, edi).unwrap();
        asm.jge(done).unwrap();
        asm.add(eax, edx).unwrap();
        asm.add(edx, 1u32).unwrap();
        asm.jmp(top).unwrap();
        asm.set_label(&mut done).unwrap();
        asm.ret().unwrap();
        asm.assemble(BASE).expect("assemble sum loop")
    }

    fn xor_loop_bytes() -> Vec<u8> {
        let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
        let mut top: CodeLabel = asm.create_label();
        let mut done: CodeLabel = asm.create_label();
        asm.xor(eax, eax).unwrap();
        asm.xor(edx, edx).unwrap();
        asm.set_label(&mut top).unwrap();
        asm.cmp(edx, edi).unwrap();
        asm.jge(done).unwrap();
        asm.mov(ecx, edx).unwrap();
        asm.add(ecx, 0x55u32).unwrap();
        asm.xor(eax, ecx).unwrap();
        asm.add(edx, 1u32).unwrap();
        asm.jmp(top).unwrap();
        asm.set_label(&mut done).unwrap();
        asm.ret().unwrap();
        asm.assemble(BASE).expect("assemble xor loop")
    }

    fn free_vars(summary: &FunctionSummary, expr: &Expr) -> BTreeSet<u32> {
        let seeded: BTreeSet<u32> = summary.input_seeds.values().copied().collect();
        expr.vars()
            .into_iter()
            .filter(|v: &u32| *v < CONDITION_VAR_BASE && !seeded.contains(v))
            .collect()
    }

    fn concretize_filled(
        summary: &FunctionSummary,
        output: &Expr,
        inputs: [u32; 4],
        fill: u64,
    ) -> u64 {
        let extent: u32 = output.max_var().map_or(0, |v: u32| v + 1);
        let mut env: Vec<u64> = build_env(summary, inputs, extent);
        for free in free_vars(summary, output) {
            if (free as usize) < env.len() {
                env[free as usize] = fill;
            }
        }
        output.eval(&env, summary.width)
    }

    fn run_loop_concrete(bytes: &[u8], n: u32) -> u64 {
        let mut cpu: Cpu = Cpu::new(CpuMode::Bits64);
        cpu.mem.map(BASE, 0x1000, Perm::RWX).expect("map code");
        cpu.mem.write_unchecked(BASE, bytes);
        cpu.mem.map(0x2_0000, 0x1000, Perm::RW).expect("map stack");
        cpu.mem
            .write_u64(STACK_TOP, RET_SENTINEL)
            .expect("seed return address");
        cpu.regs.set(Reg::Rsp, STACK_TOP);
        cpu.regs.set(Reg::Rdi, u64::from(n));
        cpu.regs.rip = BASE;
        let mut host: NoopHost = NoopHost;
        let budget: u64 = 16 + u64::from(n) * 16;
        let exit: ExitReason = cpu.run(&mut host, budget).expect("run");
        match exit {
            ExitReason::JumpedOutOfRange { to, .. } if to == RET_SENTINEL => {}
            other => panic!("expected clean return to sentinel, got {other:?}"),
        }
        cpu.regs.read_sized(Reg::Rax, 32)
    }

    #[test]
    fn counted_sum_loop_unrolls_exact_under_cap() {
        let bytes: Vec<u8> = sum_loop_bytes();
        let summary: FunctionSummary =
            summarize(64, BASE, &bytes, BASE).expect("counted loop must summarize via unroll");
        let eax_expr: Expr = summary
            .outputs
            .get(&Register::RAX)
            .expect("eax output")
            .clone();

        let mut saw_exact: bool = false;
        for n in 0u32..(MAX_UNROLL as u32) {
            let concrete: u64 = run_loop_concrete(&bytes, n);
            let symbolic: u64 = concretize(&summary, &eax_expr, [n, 0, 0, 0]);
            assert_eq!(
                symbolic, concrete,
                "unrolled summary must equal stub_emu exactly for trip count n={n} (< K)"
            );
            assert_eq!(
                concretize_filled(&summary, &eax_expr, [n, 0, 0, 0], 0xDEAD),
                symbolic,
                "for n={n} (< K) the selected value must not depend on a widened free var"
            );
            saw_exact = true;
        }
        assert!(saw_exact, "the <K exact regime must be exercised");
    }

    #[test]
    fn counted_sum_loop_widens_beyond_cap() {
        let bytes: Vec<u8> = sum_loop_bytes();
        let summary: FunctionSummary =
            summarize(64, BASE, &bytes, BASE).expect("counted loop must summarize via unroll");
        let eax_expr: Expr = summary
            .outputs
            .get(&Register::RAX)
            .expect("eax output")
            .clone();

        let mut saw_widened: bool = false;
        for n in [MAX_UNROLL as u32, (MAX_UNROLL as u32) + 1, 20, 200] {
            let with_zero: u64 = concretize_filled(&summary, &eax_expr, [n, 0, 0, 0], 0);
            let with_sentinel: u64 = concretize_filled(&summary, &eax_expr, [n, 0, 0, 0], 0xABCD);
            assert_ne!(
                with_zero, with_sentinel,
                "for n={n} (>= K) the output must be a free widened var, not a concrete claim"
            );
            let concrete: u64 = run_loop_concrete(&bytes, n);
            assert!(
                with_zero != concrete || with_sentinel != concrete,
                "for n={n} the summary must never pin the loop output to a single concrete value"
            );
            saw_widened = true;
        }
        assert!(saw_widened, "the >=K widened regime must be exercised");
    }

    #[test]
    fn xor_accumulate_loop_unrolls_exact_under_cap() {
        let bytes: Vec<u8> = xor_loop_bytes();
        let summary: FunctionSummary =
            summarize(64, BASE, &bytes, BASE).expect("xor loop must summarize via unroll");
        let eax_expr: Expr = summary
            .outputs
            .get(&Register::RAX)
            .expect("eax output")
            .clone();

        for n in 0u32..(MAX_UNROLL as u32) {
            let concrete: u64 = run_loop_concrete(&bytes, n);
            let symbolic: u64 = concretize(&summary, &eax_expr, [n, 0, 0, 0]);
            assert_eq!(
                symbolic, concrete,
                "xor-accumulate unroll must equal stub_emu exactly for n={n} (< K)"
            );
        }
    }

    #[test]
    fn xor_accumulate_loop_widens_beyond_cap() {
        let bytes: Vec<u8> = xor_loop_bytes();
        let summary: FunctionSummary =
            summarize(64, BASE, &bytes, BASE).expect("xor loop must summarize via unroll");
        let eax_expr: Expr = summary
            .outputs
            .get(&Register::RAX)
            .expect("eax output")
            .clone();

        for n in [MAX_UNROLL as u32, (MAX_UNROLL as u32) + 1, 32] {
            let with_zero: u64 = concretize_filled(&summary, &eax_expr, [n, 0, 0, 0], 0);
            let with_sentinel: u64 = concretize_filled(&summary, &eax_expr, [n, 0, 0, 0], 0x1234);
            assert_ne!(
                with_zero, with_sentinel,
                "for n={n} (>= K) the xor-loop output must be widened to a free var"
            );
        }
    }

    #[test]
    fn bails_on_irreducible_two_entry_loop() {
        let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
        let mut head_a: CodeLabel = asm.create_label();
        let mut head_b: CodeLabel = asm.create_label();
        let mut done: CodeLabel = asm.create_label();
        asm.cmp(edi, esi).unwrap();
        asm.jge(head_b).unwrap();
        asm.set_label(&mut head_a).unwrap();
        asm.add(eax, edi).unwrap();
        asm.cmp(eax, esi).unwrap();
        asm.jge(done).unwrap();
        asm.set_label(&mut head_b).unwrap();
        asm.add(eax, esi).unwrap();
        asm.cmp(eax, edi).unwrap();
        asm.jl(head_a).unwrap();
        asm.set_label(&mut done).unwrap();
        asm.ret().unwrap();
        let bytes: Vec<u8> = asm.assemble(BASE).expect("assemble irreducible");
        assert!(
            summarize(64, BASE, &bytes, BASE).is_none(),
            "an irreducible two-entry loop must bail, not be summarized"
        );
    }

    const MEM_BUFFER: u64 = 0x3_0000;
    const MEM_BUFFER_LEN: u64 = 0x1000;

    fn decode_seq(bytes: &[u8]) -> Vec<Instruction> {
        let mut decoder: Decoder<'_> = Decoder::with_ip(64, bytes, BASE, DecoderOptions::NONE);
        let mut out: Vec<Instruction> = Vec::new();
        while decoder.can_decode() {
            let mut insn: Instruction = Instruction::default();
            decoder.decode_out(&mut insn);
            if insn.is_invalid() {
                break;
            }
            out.push(insn);
        }
        out
    }

    fn lift_mem_eax(bytes: &[u8]) -> (MemRegFile, Expr, u32, u32) {
        let insns: Vec<Instruction> = decode_seq(bytes);
        let mut regs: MemRegFile = MemRegFile::new();
        let rdi_seed: u32 = regs.seed_or_create(Register::RDI);
        let rsi_seed: u32 = regs.seed_or_create(Register::RSI);
        for insn in &insns {
            assert!(
                regs.apply_insn(insn),
                "the symbolic memory model must accept {insn}"
            );
            assert!(!regs.is_capped(), "memory lift must not cap on the oracle");
        }
        let eax_value: Expr = regs.current(Register::RAX);
        (regs, eax_value, rdi_seed, rsi_seed)
    }

    fn run_mem_concrete(bytes: &[u8], base: u64, i: u32) -> (Cpu, u64) {
        let mut cpu: Cpu = Cpu::new(CpuMode::Bits64);
        cpu.mem.map(BASE, 0x1000, Perm::RWX).expect("map code");
        cpu.mem.write_unchecked(BASE, bytes);
        cpu.mem.map(0x2_0000, 0x1000, Perm::RW).expect("map stack");
        cpu.mem
            .map(MEM_BUFFER, MEM_BUFFER_LEN, Perm::RW)
            .expect("map scratch buffer");
        cpu.mem
            .write_u64(STACK_TOP, RET_SENTINEL)
            .expect("seed return address");
        cpu.regs.set(Reg::Rsp, STACK_TOP);
        cpu.regs.set(Reg::Rdi, base);
        cpu.regs.set(Reg::Rsi, u64::from(i));
        cpu.regs.rip = BASE;
        let mut host: NoopHost = NoopHost;
        let exit: ExitReason = cpu.run(&mut host, 1000).expect("run");
        match exit {
            ExitReason::JumpedOutOfRange { to, .. } if to == RET_SENTINEL => {}
            other => panic!("expected clean return to sentinel, got {other:?}"),
        }
        let eax_out: u64 = cpu.regs.read_sized(Reg::Rax, 32);
        (cpu, eax_out)
    }

    fn concretize_mem(
        expr: &Expr,
        rdi_seed: u32,
        rsi_seed: u32,
        base: u64,
        i: u32,
        cpu: &Cpu,
        width: MbaWidth,
    ) -> u64 {
        let extent: u32 = expr
            .max_var()
            .map_or(0, |v: u32| v + 1)
            .max(rdi_seed + 1)
            .max(rsi_seed + 1);
        let mut env: Vec<u64> = vec![0u64; extent as usize];
        env[rdi_seed as usize] = base;
        env[rsi_seed as usize] = u64::from(i);
        let mem = |addr: u64, w: MbaWidth| -> u64 {
            match w {
                MbaWidth::W8 => u64::from(cpu.mem.read_u8(addr).unwrap_or(0)),
                MbaWidth::W16 => u64::from(cpu.mem.read_u16(addr).unwrap_or(0)),
                MbaWidth::W32 => u64::from(cpu.mem.read_u32(addr).unwrap_or(0)),
                _ => cpu.mem.read_u64(addr).unwrap_or(0),
            }
        };
        expr.eval_with_mem(&env, &mem, width)
    }

    fn store_then_load_bytes() -> Vec<u8> {
        let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
        asm.lea(eax, dword_ptr(esi + 7)).unwrap();
        asm.mov(dword_ptr(rdi + rsi * 4), eax).unwrap();
        asm.mov(eax, dword_ptr(rdi + rsi * 4)).unwrap();
        asm.ret().unwrap();
        asm.assemble(BASE).expect("assemble store-then-load")
    }

    fn load_input_ptr_bytes() -> Vec<u8> {
        let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
        asm.mov(eax, dword_ptr(rdi + rsi * 4)).unwrap();
        asm.add(eax, 3u32).unwrap();
        asm.ret().unwrap();
        asm.assemble(BASE).expect("assemble load-input-ptr")
    }

    #[test]
    fn computed_store_then_load_matches_stub_emu_memory() {
        let bytes: Vec<u8> = store_then_load_bytes();
        let (_, eax_expr, rdi_seed, rsi_seed): (MemRegFile, Expr, u32, u32) = lift_mem_eax(&bytes);
        for i in [0u32, 1, 2, 3, 7, 16, 100] {
            let (cpu, concrete): (Cpu, u64) = run_mem_concrete(&bytes, MEM_BUFFER, i);
            let symbolic: u64 = concretize_mem(
                &eax_expr,
                rdi_seed,
                rsi_seed,
                MEM_BUFFER,
                i,
                &cpu,
                MbaWidth::W32,
            );
            assert_eq!(
                symbolic, concrete,
                "computed-address store-then-load disagrees with stub_emu at i={i}"
            );
            assert_eq!(
                concrete,
                u64::from(i.wrapping_add(7)),
                "concrete eax must equal the value written through [rdi+rsi*4]"
            );
        }
    }

    #[test]
    fn load_of_input_pointer_matches_stub_emu_memory() {
        let bytes: Vec<u8> = load_input_ptr_bytes();
        let (_, eax_expr, rdi_seed, rsi_seed): (MemRegFile, Expr, u32, u32) = lift_mem_eax(&bytes);
        assert!(
            matches!(eax_expr, Expr::Binary(_, _, _)),
            "a load with no prior store must surface a Mem read inside the result, got {eax_expr}"
        );
        for (i, seeded) in [(0u32, 0x1111_2222u32), (3, 0xDEAD_BEEF), (5, 7)] {
            let (mut cpu, _): (Cpu, u64) = run_mem_concrete(&bytes, MEM_BUFFER, i);
            let slot: u64 = MEM_BUFFER + u64::from(i) * 4;
            cpu.mem.write_u32(slot, seeded).expect("seed memory cell");
            let symbolic: u64 = concretize_mem(
                &eax_expr,
                rdi_seed,
                rsi_seed,
                MEM_BUFFER,
                i,
                &cpu,
                MbaWidth::W32,
            );
            let concrete: u64 = u64::from(seeded.wrapping_add(3));
            assert_eq!(
                symbolic, concrete,
                "load-of-input-pointer disagrees with the concrete memory image at i={i}"
            );
        }
    }

    #[test]
    fn distinct_concrete_reads_are_not_collapsed() {
        let mut regs: MemRegFile = MemRegFile::new();
        let _: u32 = regs.seed_or_create(Register::RDI);
        let bytes: Vec<u8> = {
            let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
            asm.mov(eax, dword_ptr(rdi)).unwrap();
            asm.mov(ecx, dword_ptr(rdi + 4)).unwrap();
            asm.sub(eax, ecx).unwrap();
            asm.ret().unwrap();
            asm.assemble(BASE).expect("assemble two-read")
        };
        for insn in &decode_seq(&bytes) {
            assert!(regs.apply_insn(insn));
        }
        let diff: Expr = regs.current(Register::RAX);
        let mut nonzero_seen: bool = false;
        for (a, b) in [(10u32, 3u32), (0, 0), (255, 1)] {
            let mut cpu: Cpu = Cpu::new(CpuMode::Bits64);
            cpu.mem
                .map(MEM_BUFFER, MEM_BUFFER_LEN, Perm::RW)
                .expect("map buffer");
            cpu.mem.write_u32(MEM_BUFFER, a).expect("write first cell");
            cpu.mem
                .write_u32(MEM_BUFFER + 4, b)
                .expect("write second cell");
            let rdi_seed: u32 = regs.seed_index(Register::RDI).expect("rdi seed");
            let extent: u32 = diff.max_var().map_or(0, |v: u32| v + 1).max(rdi_seed + 1);
            let mut env: Vec<u64> = vec![0u64; extent as usize];
            env[rdi_seed as usize] = MEM_BUFFER;
            let mem = |addr: u64, w: MbaWidth| -> u64 {
                match w {
                    MbaWidth::W32 => u64::from(cpu.mem.read_u32(addr).unwrap_or(0)),
                    _ => cpu.mem.read_u64(addr).unwrap_or(0),
                }
            };
            let got: u64 = diff.eval_with_mem(&env, &mem, MbaWidth::W32);
            let expected: u64 = u64::from(a.wrapping_sub(b));
            assert_eq!(
                got, expected,
                "two reads from distinct cells [rdi] and [rdi+4] must stay independent (a={a} b={b})"
            );
            if a != b {
                nonzero_seen = true;
            }
        }
        assert!(
            nonzero_seen,
            "the soundness oracle must exercise a case where the two cells differ"
        );
    }
}
