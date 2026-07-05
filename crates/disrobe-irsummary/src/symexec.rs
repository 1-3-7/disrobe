use std::collections::{BTreeMap, BTreeSet};

use disrobe_core::DiGraph;
use disrobe_mba::{BinOp, CmpOp, Expr, Predicate, Width};
use disrobe_nir::{BinaryOp, NirFunction, NirInstr, NirOp, SourceLang};

const MAX_BLOCKS: usize = 64;
const MAX_INSNS: usize = 2048;
const MAX_BLOCK_INSNS: usize = 256;
const MAX_JOINS: usize = 64;
const MAX_OUTPUTS: usize = 64;
const CONDITION_VAR_BASE: u32 = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Location {
    Register(String),
    Memory(String),
}

impl Location {
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Register(name) => name.clone(),
            Self::Memory(cell) => cell.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchFact {
    pub predicate: Predicate,
    pub condition_var: u32,
    pub branch_address: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NirSummary {
    pub outputs: BTreeMap<Location, Expr>,
    pub branches: Vec<BranchFact>,
    pub width: Width,
    pub input_seeds: BTreeMap<String, u32>,
}

impl NirSummary {
    #[must_use]
    pub fn output_labels(&self) -> BTreeSet<String> {
        self.outputs
            .keys()
            .map(Location::label)
            .collect::<BTreeSet<String>>()
    }

    #[must_use]
    pub fn const_values(&self) -> BTreeSet<u64> {
        let mut values: BTreeSet<u64> = BTreeSet::new();
        for expr in self.outputs.values() {
            collect_consts(expr, &mut values);
        }
        for branch in &self.branches {
            collect_pred_consts(&branch.predicate, &mut values);
        }
        values
    }
}

#[derive(Debug, Clone)]
enum Terminator {
    Fallthrough(usize),
    Conditional {
        predicate_index: Option<usize>,
        branch_mnemonic: String,
        branch_address: u64,
        taken: usize,
        fallthrough: usize,
    },
    Jump(usize),
    Return,
}

#[derive(Debug, Clone)]
struct Block {
    body: std::ops::Range<usize>,
    terminator: Terminator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Frontend {
    Register,
    Stack,
}

impl Frontend {
    const fn of(lang: SourceLang) -> Self {
        match lang {
            SourceLang::Wasm
            | SourceLang::Jvm
            | SourceLang::Cil
            | SourceLang::Avm2
            | SourceLang::Yarv
            | SourceLang::Lua
            | SourceLang::Beam
            | SourceLang::Python => Self::Stack,
            SourceLang::Unknown
            | SourceLang::NativeX86
            | SourceLang::NativeArm
            | SourceLang::Dalvik => Self::Register,
        }
    }
}

#[derive(Debug, Clone)]
struct Region {
    blocks: Vec<Block>,
    entry_block: usize,
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

const MAX_STACK_DEPTH: usize = 256;

#[derive(Debug, Clone, Default)]
struct State {
    bindings: BTreeMap<Location, Expr>,
    stack: Vec<Expr>,
    next_var: u32,
}

impl State {
    const fn fresh(&mut self) -> u32 {
        let var: u32 = self.next_var;
        self.next_var += 1;
        var
    }

    fn read(&mut self, loc: &Location) -> Expr {
        if let Some(expr) = self.bindings.get(loc) {
            return expr.clone();
        }
        let var: u32 = self.fresh();
        let expr: Expr = Expr::var(var);
        self.bindings.insert(loc.clone(), expr.clone());
        expr
    }

    fn write(&mut self, loc: Location, expr: Expr) {
        self.bindings.insert(loc, expr);
    }

    fn push(&mut self, expr: Expr) -> Option<()> {
        if self.stack.len() >= MAX_STACK_DEPTH {
            return None;
        }
        self.stack.push(expr);
        Some(())
    }

    fn pop(&mut self) -> Expr {
        self.stack.pop().unwrap_or_else(|| {
            let var: u32 = self.fresh();
            Expr::var(var)
        })
    }
}

#[must_use]
pub fn summarize_function(function: &NirFunction) -> Option<NirSummary> {
    if function.instructions.is_empty() || function.instructions.len() > MAX_INSNS {
        return None;
    }
    let index: BTreeMap<u64, usize> = function
        .instructions
        .iter()
        .enumerate()
        .map(|(i, insn): (usize, &NirInstr)| (insn.address, i))
        .collect();

    let mode: Frontend = Frontend::of(function.source.lang);
    let region: Region = build_region(&function.instructions, &index)?;
    let order: Vec<usize> = topological_order(&region)?;
    summarize_region(function, &region, &order, mode)
}

fn build_region(insns: &[NirInstr], index: &BTreeMap<u64, usize>) -> Option<Region> {
    let leaders: BTreeSet<usize> = collect_leaders(insns, index)?;
    let leader_vec: Vec<usize> = leaders.iter().copied().collect();
    let leader_to_block: BTreeMap<usize, usize> = leader_vec
        .iter()
        .enumerate()
        .map(|(i, leader): (usize, &usize)| (*leader, i))
        .collect();

    let mut blocks: Vec<Block> = Vec::with_capacity(leader_vec.len());
    for (i, &leader) in leader_vec.iter().enumerate() {
        let next_leader: usize = leader_vec.get(i + 1).copied().unwrap_or(insns.len());
        let block: Block = build_block(insns, index, leader, next_leader, &leader_to_block)?;
        blocks.push(block);
    }
    if blocks.len() > MAX_BLOCKS {
        return None;
    }
    let entry_block: usize = *leader_to_block.get(&0)?;
    Some(Region {
        blocks,
        entry_block,
    })
}

fn collect_leaders(insns: &[NirInstr], index: &BTreeMap<u64, usize>) -> Option<BTreeSet<usize>> {
    let mut leaders: BTreeSet<usize> = BTreeSet::from([0usize]);
    let mut worklist: Vec<usize> = vec![0usize];
    let mut visited: BTreeSet<usize> = BTreeSet::new();

    while let Some(leader) = worklist.pop() {
        if !visited.insert(leader) {
            continue;
        }
        if visited.len() > MAX_BLOCKS {
            return None;
        }
        let mut cursor: usize = leader;
        let limit: usize = leader + MAX_BLOCK_INSNS;
        loop {
            if cursor >= insns.len() || cursor > limit {
                return None;
            }
            let insn: &NirInstr = &insns[cursor];
            match &insn.op {
                NirOp::Return => break,
                NirOp::Interrupt => return None,
                NirOp::CondBranch { target } => {
                    let taken: usize = *index.get(&target.as_ref().copied()?)?;
                    let fallthrough: usize = cursor + 1;
                    if fallthrough >= insns.len() {
                        return None;
                    }
                    for entry in [taken, fallthrough] {
                        leaders.insert(entry);
                        worklist.push(entry);
                    }
                    break;
                }
                NirOp::Branch { target } => {
                    let to: usize = *index.get(&target.as_ref().copied()?)?;
                    leaders.insert(to);
                    worklist.push(to);
                    break;
                }
                _ => {
                    if cursor + 1 == insns.len() {
                        break;
                    }
                    cursor += 1;
                }
            }
        }
    }
    Some(leaders)
}

fn build_block(
    insns: &[NirInstr],
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
        let insn: &NirInstr = &insns[cursor];
        match &insn.op {
            NirOp::Return => {
                return Some(Block {
                    body: leader..cursor,
                    terminator: Terminator::Return,
                });
            }
            NirOp::Interrupt => return None,
            NirOp::CondBranch { target } => {
                let taken_insn: usize = *index.get(&target.as_ref().copied()?)?;
                let fallthrough_insn: usize = cursor + 1;
                let taken: usize = *leader_to_block.get(&taken_insn)?;
                let fallthrough: usize = *leader_to_block.get(&fallthrough_insn)?;
                let predicate_index: Option<usize> = predicate_source(insns, leader, cursor);
                return Some(Block {
                    body: leader..cursor,
                    terminator: Terminator::Conditional {
                        predicate_index,
                        branch_mnemonic: insn.mnemonic.trim().to_ascii_lowercase(),
                        branch_address: insn.address,
                        taken,
                        fallthrough,
                    },
                });
            }
            NirOp::Branch { target } => {
                let target_insn: usize = *index.get(&target.as_ref().copied()?)?;
                let to: usize = *leader_to_block.get(&target_insn)?;
                return Some(Block {
                    body: leader..cursor,
                    terminator: Terminator::Jump(to),
                });
            }
            _ => {
                if cursor + 1 == insns.len() {
                    return Some(Block {
                        body: leader..cursor + 1,
                        terminator: Terminator::Return,
                    });
                }
                if cursor + 1 == next_leader {
                    let to: usize = *leader_to_block.get(&next_leader)?;
                    return Some(Block {
                        body: leader..cursor + 1,
                        terminator: Terminator::Fallthrough(to),
                    });
                }
                cursor += 1;
            }
        }
    }
}

fn predicate_source(insns: &[NirInstr], leader: usize, branch: usize) -> Option<usize> {
    let mut cursor: usize = branch;
    while cursor > leader {
        cursor -= 1;
        let mnemonic: String = insns[cursor].mnemonic.trim().to_ascii_lowercase();
        if matches!(mnemonic.as_str(), "cmp" | "test") {
            return Some(cursor);
        }
    }
    None
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
    let mut remaining: Vec<usize> = indegree;
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

struct RegionGraph<'a> {
    region: &'a Region,
}

impl DiGraph for RegionGraph<'_> {
    fn node_count(&self) -> usize {
        self.region.blocks.len()
    }

    fn entry(&self) -> u32 {
        self.region.entry_block as u32
    }

    fn for_each_successor(&self, node: u32, visit: &mut dyn FnMut(u32)) {
        for succ in successors(&self.region.blocks[node as usize]) {
            visit(succ as u32);
        }
    }
}

fn dominator_sets(region: &Region) -> Vec<BTreeSet<usize>> {
    let graph: RegionGraph<'_> = RegionGraph { region };
    disrobe_core::dominator_sets(&graph)
        .into_iter()
        .map(|set: BTreeSet<u32>| set.into_iter().map(|id: u32| id as usize).collect())
        .collect()
}

fn merge_plan(
    region: &Region,
    join: Option<usize>,
    preds: &[usize],
    dom: &[BTreeSet<usize>],
) -> Option<MergePlan> {
    if preds.len() != 2 {
        return None;
    }
    let controller: usize = {
        let mut common: BTreeSet<usize> = dom[preds[0]].clone();
        common.retain(|node: &usize| dom[preds[1]].contains(node));
        common.into_iter().max()?
    };
    let Terminator::Conditional {
        taken, fallthrough, ..
    } = region.blocks[controller].terminator
    else {
        return None;
    };
    let on_side = |pred: usize, head: usize| -> bool {
        pred == head || dom[pred].contains(&head) || (Some(head) == join && pred == controller)
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
    function: &NirFunction,
    region: &Region,
    order: &[usize],
    mode: Frontend,
) -> Option<NirSummary> {
    let insns: &[NirInstr] = &function.instructions;
    let preds: Vec<Vec<usize>> = predecessors(region);
    let dom: Vec<BTreeSet<usize>> = dominator_sets(region);
    let mut exit_states: Vec<Option<State>> = vec![None; region.blocks.len()];
    let mut branch_facts: BTreeMap<usize, BranchFact> = BTreeMap::new();
    let mut next_var: u32 = 0;
    let mut input_seeds: BTreeMap<String, u32> = BTreeMap::new();
    let mut width: Width = Width::W64;
    let mut join_count: usize = 0;

    for &block_id in order {
        let block: &Block = &region.blocks[block_id];
        let incoming: &[usize] = &preds[block_id];

        let mut state: State = if block_id == region.entry_block {
            State {
                bindings: BTreeMap::new(),
                stack: Vec::new(),
                next_var,
            }
        } else if incoming.len() == 1 {
            let mut prior: State = exit_states[incoming[0]].clone()?;
            prior.next_var = prior.next_var.max(next_var);
            prior
        } else {
            join_count += 1;
            if join_count > MAX_JOINS {
                return None;
            }
            let plan: MergePlan = merge_plan(region, Some(block_id), incoming, &dom)?;
            merge_states(&plan, &exit_states, next_var)?
        };

        for insn in &insns[block.body.clone()] {
            apply_instr(&mut state, insn, &mut input_seeds, mode)?;
        }

        if let Terminator::Conditional {
            predicate_index,
            branch_mnemonic,
            branch_address,
            ..
        } = &block.terminator
        {
            let predicate: Predicate = build_predicate(
                &mut state,
                insns,
                *predicate_index,
                branch_mnemonic,
                &mut input_seeds,
            )?;
            width = predicate_width(insns, *predicate_index);
            let condition_var: u32 = condition_var_id(block_id)?;
            branch_facts.insert(
                block_id,
                BranchFact {
                    predicate,
                    condition_var,
                    branch_address: *branch_address,
                },
            );
        }

        next_var = next_var.max(state.next_var);
        exit_states[block_id] = Some(state);
    }

    finalize(
        region,
        &dom,
        &exit_states,
        &branch_facts,
        input_seeds,
        width,
        mode,
    )
}

fn merge_states(plan: &MergePlan, exit_states: &[Option<State>], next_var: u32) -> Option<State> {
    let taken_state: &State = exit_states[plan.taken_pred].as_ref()?;
    let fallback_state: &State = exit_states[plan.fallthrough_pred].as_ref()?;
    let cond: Expr = Expr::var(condition_var_id(plan.controller)?);

    let mut merged: State = State {
        bindings: BTreeMap::new(),
        stack: Vec::new(),
        next_var: next_var
            .max(taken_state.next_var)
            .max(fallback_state.next_var),
    };

    let mut keys: BTreeSet<Location> = BTreeSet::new();
    keys.extend(taken_state.bindings.keys().cloned());
    keys.extend(fallback_state.bindings.keys().cloned());

    for key in keys {
        let then_expr: Expr = binding_or_fresh(taken_state, &mut merged, &key);
        let else_expr: Expr = binding_or_fresh(fallback_state, &mut merged, &key);
        let value: Expr = if then_expr == else_expr {
            then_expr
        } else {
            Expr::ite(cond.clone(), then_expr, else_expr)
        };
        merged.write(key, value);
    }

    if taken_state.stack.len() == fallback_state.stack.len() {
        for (then_expr, else_expr) in taken_state.stack.iter().zip(&fallback_state.stack) {
            let value: Expr = if then_expr == else_expr {
                then_expr.clone()
            } else {
                Expr::ite(cond.clone(), then_expr.clone(), else_expr.clone())
            };
            merged.stack.push(value);
        }
    }
    Some(merged)
}

fn condition_var_id(block_id: usize) -> Option<u32> {
    CONDITION_VAR_BASE.checked_add(u32::try_from(block_id).ok()?)
}

fn binding_or_fresh(source: &State, merged: &mut State, key: &Location) -> Expr {
    source.bindings.get(key).cloned().unwrap_or_else(|| {
        let var: u32 = merged.fresh();
        Expr::var(var)
    })
}

fn apply_instr(
    state: &mut State,
    insn: &NirInstr,
    seeds: &mut BTreeMap<String, u32>,
    mode: Frontend,
) -> Option<()> {
    match &insn.op {
        NirOp::Nop => apply_nop(state, insn, seeds),
        NirOp::Const => apply_const(state, insn, mode),
        NirOp::BinOp { op } => apply_binop(state, insn, *op, seeds, mode),
        NirOp::Load => apply_load(state, insn, mode),
        NirOp::Store => apply_store(state, insn, seeds, mode),
        NirOp::Call { .. } | NirOp::IndirectCall | NirOp::ExternCall { .. } => {
            apply_call(state, insn, mode)
        }
        NirOp::Phi => Some(()),
        NirOp::Branch { .. } | NirOp::CondBranch { .. } | NirOp::Return | NirOp::Interrupt => None,
    }
}

fn apply_nop(state: &mut State, insn: &NirInstr, seeds: &mut BTreeMap<String, u32>) -> Option<()> {
    let mnemonic: String = insn.mnemonic.trim().to_ascii_lowercase();
    if matches!(mnemonic.as_str(), "cmp" | "test") {
        return Some(());
    }
    if matches!(
        mnemonic.as_str(),
        "nop" | "endbr64" | "endbr32" | "end" | "block" | "drop"
    ) {
        if mnemonic == "drop" {
            let _: Expr = state.pop();
        }
        return Some(());
    }
    if matches!(
        mnemonic.as_str(),
        "mov" | "movzx" | "movsx" | "movsxd" | "lea"
    ) {
        let dest: &str = insn.operands.first()?;
        let src: &str = insn.operands.get(1)?;
        let dest_loc: Location = location_of(dest)?;
        let value: Expr = if matches!(mnemonic.as_str(), "lea") {
            Expr::var(state.fresh())
        } else {
            operand_value(state, src, seeds)
        };
        state.write(dest_loc, value);
        return Some(());
    }
    if matches!(mnemonic.as_str(), "local.get" | "global.get") {
        let name: &str = insn.operands.first()?;
        let value: Expr = read_location(state, &Location::Register(name.to_owned()), seeds);
        return state.push(value);
    }
    if matches!(mnemonic.as_str(), "local.set" | "global.set" | "local.tee") {
        let name: &str = insn.operands.first()?;
        let value: Expr = state.pop();
        if mnemonic == "local.tee" {
            state.push(value.clone())?;
        }
        state.write(Location::Register(name.to_owned()), value);
        return Some(());
    }
    Some(())
}

fn apply_const(state: &mut State, insn: &NirInstr, mode: Frontend) -> Option<()> {
    let first: &str = insn.operands.first()?;
    if mode == Frontend::Stack {
        let value: u64 = parse_immediate(first)?;
        return state.push(Expr::konst(value));
    }
    let dest: &str = first;
    let src: &str = insn.operands.get(1)?;
    let dest_loc: Location = location_of(dest)?;
    let value: u64 = parse_immediate(src)?;
    state.write(dest_loc, Expr::konst(value));
    Some(())
}

fn apply_binop(
    state: &mut State,
    insn: &NirInstr,
    op: BinaryOp,
    seeds: &mut BTreeMap<String, u32>,
    mode: Frontend,
) -> Option<()> {
    if mode == Frontend::Register {
        let dest: &str = insn.operands.first()?;
        let dest_loc: Location = location_of(dest)?;
        let left: Expr = read_location(state, &dest_loc, seeds);
        let value: Expr = match insn.operands.get(1) {
            Some(rhs) => {
                let right: Expr = operand_value(state, rhs, seeds);
                apply_binary(op, left, right)?
            }
            None => apply_unary(op, left)?,
        };
        state.write(dest_loc, value);
        return Some(());
    }
    if matches!(op, BinaryOp::Not | BinaryOp::Neg) {
        let operand: Expr = state.pop();
        return state.push(apply_unary(op, operand)?);
    }
    let right: Expr = state.pop();
    let left: Expr = state.pop();
    state.push(apply_binary(op, left, right)?)
}

fn apply_load(state: &mut State, insn: &NirInstr, mode: Frontend) -> Option<()> {
    if mode == Frontend::Register {
        let dest: &str = insn.operands.first()?;
        let src: &str = insn.operands.get(1)?;
        let dest_loc: Location = location_of(dest)?;
        let cell: Location = location_of(src)?;
        let value: Expr = match &cell {
            Location::Memory(_) => state.read(&cell),
            Location::Register(_) => return None,
        };
        state.write(dest_loc, value);
        return Some(());
    }
    if let Some(cell_op) = insn.operands.first()
        && let Some(cell) = location_of(cell_op)
        && matches!(cell, Location::Memory(_))
    {
        let value: Expr = state.read(&cell);
        return state.push(value);
    }
    let _: Expr = state.pop();
    let var: u32 = state.fresh();
    state.push(Expr::var(var))
}

fn apply_store(
    state: &mut State,
    insn: &NirInstr,
    seeds: &mut BTreeMap<String, u32>,
    mode: Frontend,
) -> Option<()> {
    if mode == Frontend::Register {
        let dest: &str = insn.operands.first()?;
        let src: &str = insn.operands.get(1)?;
        let cell: Location = location_of(dest)?;
        if !matches!(cell, Location::Memory(_)) {
            return None;
        }
        let value: Expr = operand_value(state, src, seeds);
        state.write(cell, value);
        return Some(());
    }
    let value: Expr = state.pop();
    if let Some(cell_op) = insn.operands.first()
        && let Some(cell) = location_of(cell_op)
        && matches!(cell, Location::Memory(_))
    {
        state.write(cell, value);
    }
    Some(())
}

fn apply_call(state: &mut State, _insn: &NirInstr, mode: Frontend) -> Option<()> {
    let result: u32 = state.fresh();
    match mode {
        Frontend::Register => {
            state.write(Location::Register("rax".to_owned()), Expr::var(result));
            Some(())
        }
        Frontend::Stack => state.push(Expr::var(result)),
    }
}

fn build_predicate(
    state: &mut State,
    insns: &[NirInstr],
    predicate_index: Option<usize>,
    branch_mnemonic: &str,
    seeds: &mut BTreeMap<String, u32>,
) -> Option<Predicate> {
    let cmp: &NirInstr = &insns[predicate_index?];
    let left_op: &str = cmp.operands.first()?;
    let right_op: &str = cmp.operands.get(1)?;
    let left: Expr = operand_value(state, left_op, seeds);
    let right: Expr = operand_value(state, right_op, seeds);
    let mnemonic: String = cmp.mnemonic.trim().to_ascii_lowercase();
    match mnemonic.as_str() {
        "cmp" => {
            let op: CmpOp = branch_to_cmp(branch_mnemonic)?;
            Some(Predicate::Compare { op, left, right })
        }
        "test" => {
            let masked: Expr = Expr::and(left, right);
            match branch_mnemonic {
                "je" | "jz" => Some(Predicate::eq(masked, Expr::konst(0))),
                "jne" | "jnz" => Some(Predicate::nonzero(masked)),
                _ => None,
            }
        }
        _ => None,
    }
}

fn predicate_width(insns: &[NirInstr], predicate_index: Option<usize>) -> Width {
    let Some(idx): Option<usize> = predicate_index else {
        return Width::W64;
    };
    let cmp: &NirInstr = &insns[idx];
    if cmp.byte_width {
        return Width::W8;
    }
    cmp.operands
        .first()
        .and_then(|op: &String| register_width(op))
        .unwrap_or(Width::W64)
}

fn finalize(
    region: &Region,
    dom: &[BTreeSet<usize>],
    exit_states: &[Option<State>],
    branch_facts: &BTreeMap<usize, BranchFact>,
    input_seeds: BTreeMap<String, u32>,
    width: Width,
    mode: Frontend,
) -> Option<NirSummary> {
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

    let merged: State = if return_blocks.len() == 1 {
        exit_states[return_blocks[0]].clone()?
    } else {
        if return_blocks.len() != 2 {
            return None;
        }
        let plan: MergePlan = merge_plan(region, None, &return_blocks, dom)?;
        let next_var: u32 = exit_states
            .iter()
            .flatten()
            .map(|s: &State| s.next_var)
            .max()
            .unwrap_or(0);
        merge_states(&plan, exit_states, next_var)?
    };

    let mut outputs: BTreeMap<Location, Expr> = BTreeMap::new();
    for (loc, expr) in &merged.bindings {
        outputs.insert(loc.clone(), expr.clone());
    }
    if mode == Frontend::Stack {
        for (depth, expr) in merged.stack.iter().rev().enumerate() {
            outputs.insert(Location::Register(format!("result{depth}")), expr.clone());
        }
    }
    if outputs.len() > MAX_OUTPUTS {
        return None;
    }

    let branches: Vec<BranchFact> = branch_facts.values().cloned().collect();
    Some(NirSummary {
        outputs,
        branches,
        width,
        input_seeds,
    })
}

fn read_location(state: &mut State, loc: &Location, seeds: &mut BTreeMap<String, u32>) -> Expr {
    if let Location::Register(name) = loc
        && !state.bindings.contains_key(loc)
    {
        let var: u32 = state.fresh();
        seeds.entry(name.clone()).or_insert(var);
        let expr: Expr = Expr::var(var);
        state.bindings.insert(loc.clone(), expr.clone());
        return expr;
    }
    state.read(loc)
}

fn operand_value(state: &mut State, operand: &str, seeds: &mut BTreeMap<String, u32>) -> Expr {
    let trimmed: &str = operand.trim();
    if let Some(value) = parse_immediate(trimmed) {
        return Expr::konst(value);
    }
    if let Some(loc) = location_of(trimmed) {
        read_location(state, &loc, seeds)
    } else {
        let var: u32 = state.fresh();
        Expr::var(var)
    }
}

fn location_of(operand: &str) -> Option<Location> {
    let trimmed: &str = operand.trim();
    if trimmed.is_empty() {
        return None;
    }
    if is_memory_operand(trimmed) {
        return Some(Location::Memory(memory_cell(trimmed).to_owned()));
    }
    if parse_immediate(trimmed).is_some() {
        return None;
    }
    Some(Location::Register(canonical_register(trimmed)))
}

fn is_memory_operand(operand: &str) -> bool {
    operand.contains('[') && operand.contains(']')
}

fn memory_cell(operand: &str) -> &str {
    let start: usize = operand.find('[').map_or(0, |i: usize| i);
    let end: usize = operand.rfind(']').map_or(operand.len(), |i: usize| i + 1);
    operand.get(start..end).unwrap_or(operand)
}

fn parse_immediate(operand: &str) -> Option<u64> {
    let trimmed: &str = operand.trim();
    if trimmed.is_empty() || is_memory_operand(trimmed) {
        return None;
    }
    let (negative, body): (bool, &str) = trimmed
        .strip_prefix('-')
        .map_or((false, trimmed), |rest: &str| (true, rest.trim()));
    let value: u64 = match body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok()?,
        None => {
            if let Some(hex) = body.strip_suffix('h').or_else(|| body.strip_suffix('H')) {
                u64::from_str_radix(hex, 16).ok()?
            } else if body.bytes().all(|b: u8| b.is_ascii_digit()) && !body.is_empty() {
                body.parse::<u64>().ok()?
            } else {
                return None;
            }
        }
    };
    Some(if negative {
        value.wrapping_neg()
    } else {
        value
    })
}

fn collect_consts(expr: &Expr, into: &mut BTreeSet<u64>) {
    match expr {
        Expr::Const(value) => {
            into.insert(*value);
        }
        Expr::Var(_) => {}
        Expr::Unary(_, inner) | Expr::Slice(inner, _, _) | Expr::Mem(inner, _) => {
            collect_consts(inner, into);
        }
        Expr::Binary(_, left, right) | Expr::Compose(left, right, _) => {
            collect_consts(left, into);
            collect_consts(right, into);
        }
        Expr::Ite(cond, then, otherwise) => {
            collect_consts(cond, into);
            collect_consts(then, into);
            collect_consts(otherwise, into);
        }
    }
}

fn collect_pred_consts(predicate: &Predicate, into: &mut BTreeSet<u64>) {
    match predicate {
        Predicate::Nonzero(inner) => collect_consts(inner, into),
        Predicate::Compare { left, right, .. } => {
            collect_consts(left, into);
            collect_consts(right, into);
        }
        Predicate::Or(left, right) | Predicate::And(left, right) => {
            collect_pred_consts(left, into);
            collect_pred_consts(right, into);
        }
    }
}

fn apply_binary(op: BinaryOp, left: Expr, right: Expr) -> Option<Expr> {
    let expr: Expr = match op {
        BinaryOp::Add => Expr::Binary(BinOp::Add, Box::new(left), Box::new(right)),
        BinaryOp::Sub => Expr::Binary(BinOp::Sub, Box::new(left), Box::new(right)),
        BinaryOp::Mul => Expr::Binary(BinOp::Mul, Box::new(left), Box::new(right)),
        BinaryOp::And => Expr::Binary(BinOp::And, Box::new(left), Box::new(right)),
        BinaryOp::Or => Expr::Binary(BinOp::Or, Box::new(left), Box::new(right)),
        BinaryOp::Xor => Expr::Binary(BinOp::Xor, Box::new(left), Box::new(right)),
        BinaryOp::Shl => Expr::Binary(BinOp::Shl, Box::new(left), Box::new(right)),
        BinaryOp::Shr => Expr::Binary(BinOp::Shr, Box::new(left), Box::new(right)),
        BinaryOp::Div
        | BinaryOp::Rem
        | BinaryOp::Rol
        | BinaryOp::Ror
        | BinaryOp::Not
        | BinaryOp::Neg => return None,
    };
    Some(expr)
}

fn apply_unary(op: BinaryOp, value: Expr) -> Option<Expr> {
    match op {
        BinaryOp::Not => Some(Expr::not(value)),
        BinaryOp::Neg => Some(Expr::neg(value)),
        _ => None,
    }
}

const fn branch_to_cmp(branch: &str) -> Option<CmpOp> {
    Some(match branch.as_bytes() {
        b"je" | b"jz" => CmpOp::Eq,
        b"jne" | b"jnz" => CmpOp::Ne,
        b"jb" | b"jc" | b"jnae" => CmpOp::UnsignedLt,
        b"jbe" | b"jna" => CmpOp::UnsignedLe,
        b"ja" | b"jnbe" => CmpOp::UnsignedGt,
        b"jae" | b"jnb" | b"jnc" => CmpOp::UnsignedGe,
        b"jl" | b"jnge" => CmpOp::SignedLt,
        b"jle" | b"jng" => CmpOp::SignedLe,
        b"jg" | b"jnle" => CmpOp::SignedGt,
        b"jge" | b"jnl" => CmpOp::SignedGe,
        _ => return None,
    })
}

fn register_width(operand: &str) -> Option<Width> {
    let name: String = operand.trim().to_ascii_lowercase();
    if is_memory_operand(&name) {
        return None;
    }
    let bits: u32 = match name.as_str() {
        "al" | "bl" | "cl" | "dl" | "ah" | "bh" | "ch" | "dh" | "sil" | "dil" | "bpl" | "spl"
        | "r8b" | "r9b" | "r10b" | "r11b" | "r12b" | "r13b" | "r14b" | "r15b" => 8,
        "ax" | "bx" | "cx" | "dx" | "si" | "di" | "bp" | "sp" | "r8w" | "r9w" | "r10w" | "r11w"
        | "r12w" | "r13w" | "r14w" | "r15w" => 16,
        "eax" | "ebx" | "ecx" | "edx" | "esi" | "edi" | "ebp" | "esp" | "r8d" | "r9d" | "r10d"
        | "r11d" | "r12d" | "r13d" | "r14d" | "r15d" => 32,
        "rax" | "rbx" | "rcx" | "rdx" | "rsi" | "rdi" | "rbp" | "rsp" | "r8" | "r9" | "r10"
        | "r11" | "r12" | "r13" | "r14" | "r15" => 64,
        _ => return None,
    };
    Width::from_bits(bits)
}

fn canonical_register(name: &str) -> String {
    let lower: String = name.trim().to_ascii_lowercase();
    match lower.as_str() {
        "rax" | "eax" | "ax" | "al" | "ah" => "rax",
        "rbx" | "ebx" | "bx" | "bl" | "bh" => "rbx",
        "rcx" | "ecx" | "cx" | "cl" | "ch" => "rcx",
        "rdx" | "edx" | "dx" | "dl" | "dh" => "rdx",
        "rsi" | "esi" | "si" | "sil" => "rsi",
        "rdi" | "edi" | "di" | "dil" => "rdi",
        "rbp" | "ebp" | "bp" | "bpl" => "rbp",
        "rsp" | "esp" | "sp" | "spl" => "rsp",
        "r8" | "r8d" | "r8w" | "r8b" => "r8",
        "r9" | "r9d" | "r9w" | "r9b" => "r9",
        "r10" | "r10d" | "r10w" | "r10b" => "r10",
        "r11" | "r11d" | "r11w" | "r11b" => "r11",
        "r12" | "r12d" | "r12w" | "r12b" => "r12",
        "r13" | "r13d" | "r13w" | "r13b" => "r13",
        "r14" | "r14d" | "r14w" | "r14b" => "r14",
        "r15" | "r15d" | "r15w" | "r15b" => "r15",
        _ => return lower,
    }
    .to_owned()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use disrobe_nir::{SourceRef, SymbolKind};

    fn instr(
        address: u64,
        op: NirOp,
        mnemonic: &str,
        operands: &[&str],
        lang: SourceLang,
    ) -> NirInstr {
        let _ = SymbolKind::Function;
        NirInstr {
            address,
            op,
            mnemonic: mnemonic.to_owned(),
            operands: operands.iter().map(|s: &&str| (*s).to_owned()).collect(),
            reads_memory: operands.iter().any(|o: &&str| o.contains('[')),
            writes_memory: false,
            byte_width: false,
            source: SourceRef::new(lang, address),
        }
    }

    fn function(lang: SourceLang, instrs: Vec<NirInstr>) -> NirFunction {
        let end: u64 = instrs.last().map_or(0, |i: &NirInstr| i.address + 1);
        NirFunction {
            name: "t".to_owned(),
            address: instrs.first().map_or(0, |i: &NirInstr| i.address),
            end,
            is_export: false,
            instructions: instrs,
            source: SourceRef::labelled(lang, 0, "t"),
        }
    }

    #[test]
    fn register_sequence_folds_into_an_arithmetic_expr() {
        let lang: SourceLang = SourceLang::NativeX86;
        let function: NirFunction = function(
            lang,
            vec![
                instr(0, NirOp::Nop, "mov", &["eax", "edi"], lang),
                instr(
                    1,
                    NirOp::BinOp { op: BinaryOp::Add },
                    "add",
                    &["eax", "esi"],
                    lang,
                ),
                instr(2, NirOp::Return, "ret", &[], lang),
            ],
        );
        let summary: NirSummary = summarize_function(&function).expect("summary");
        let rax: &Expr = summary
            .outputs
            .get(&Location::Register("rax".to_owned()))
            .expect("rax output");
        let rdi: u32 = *summary.input_seeds.get("rdi").expect("rdi seed");
        let rsi: u32 = *summary.input_seeds.get("rsi").expect("rsi seed");
        let env: Vec<u64> = {
            let mut env: Vec<u64> = vec![0u64; rdi.max(rsi) as usize + 1];
            env[rdi as usize] = 9;
            env[rsi as usize] = 4;
            env
        };
        assert_eq!(rax.eval(&env, Width::W32), 13);
    }

    #[test]
    fn stack_frontend_const_fold_pushes_a_result_output() {
        let lang: SourceLang = SourceLang::Wasm;
        let function: NirFunction = function(
            lang,
            vec![
                instr(0, NirOp::Const, "i32.const", &["6"], lang),
                instr(1, NirOp::Const, "i32.const", &["7"], lang),
                instr(2, NirOp::BinOp { op: BinaryOp::Mul }, "mul", &[], lang),
                instr(3, NirOp::Nop, "end", &[], lang),
            ],
        );
        let summary: NirSummary = summarize_function(&function).expect("summary");
        let result: &Expr = summary
            .outputs
            .get(&Location::Register("result0".to_owned()))
            .expect("result0 output");
        assert_eq!(result.eval(&[], Width::W32), 42);
        assert!(summary.const_values().contains(&6));
        assert!(summary.const_values().contains(&7));
    }

    #[test]
    fn loops_bail_to_none() {
        let lang: SourceLang = SourceLang::NativeX86;
        let function: NirFunction = function(
            lang,
            vec![
                instr(0, NirOp::Nop, "mov", &["eax", "edi"], lang),
                instr(1, NirOp::Branch { target: Some(0) }, "jmp", &["0x0"], lang),
            ],
        );
        assert!(summarize_function(&function).is_none());
    }

    #[test]
    fn empty_function_is_none() {
        let function: NirFunction = function(SourceLang::NativeX86, Vec::new());
        assert!(summarize_function(&function).is_none());
    }
}
