use super::super::{
    Cond, CondKind, Flags, Item, ItemKind, LoopCond, Node, Reg, Stmt, Structured, VecStmt,
    condition_is_sound, flag_operand_regs, stmt_dest_regs,
};
use super::{ITEM_STRIDE, TrackedFlags};
use crate::arch::DisasmInsn;
use disrobe_cfg as structuring;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
pub(super) enum Attempt {
    NotCandidate,
    RejectedNzcv,
    Structured(Structured),
}

#[derive(Debug, Clone)]
struct IndexedStmt {
    instruction: usize,
    stmt: Stmt,
}

#[derive(Debug, Clone)]
enum RawTerm {
    Return,
    Goto(usize),
    Branch {
        kind: CondKind,
        flags: Flags,
        target: usize,
    },
}

#[derive(Debug, Clone)]
enum Aarch64Term {
    Return,
    Goto(usize),
    Branch {
        kind: CondKind,
        flags: Flags,
        taken: usize,
        not_taken: usize,
    },
}

#[derive(Debug, Clone)]
struct Aarch64Block {
    start: usize,
    end: usize,
    stmts: Vec<IndexedStmt>,
    term: Aarch64Term,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlagState {
    None,
    One(usize),
    Many,
}

pub(super) fn structure(
    items: &[Item],
    insns: &[DisasmInsn],
    base: u64,
    flag_definitions: &BTreeMap<usize, TrackedFlags>,
) -> Attempt {
    let blocks: Option<Vec<Aarch64Block>> = build_blocks(items, insns, base);
    let Some(mut blocks): Option<Vec<Aarch64Block>> = blocks else {
        return Attempt::NotCandidate;
    };
    let branch_count: usize = blocks
        .iter()
        .filter(|block: &&Aarch64Block| matches!(&block.term, Aarch64Term::Branch { .. }))
        .count();
    if branch_count == 0 {
        return Attempt::NotCandidate;
    }
    if !synthesize_nzcv_conditions(&mut blocks, insns, flag_definitions) {
        return Attempt::RejectedNzcv;
    }
    let cfg: Option<structuring::Cfg> = cfg_from_blocks(&blocks);
    let Some(cfg): Option<structuring::Cfg> = cfg else {
        return Attempt::NotCandidate;
    };
    let forest: structuring::LoopForest = structuring::loop_forest(&cfg);
    let result: structuring::StructureResult = structuring::structure(&cfg);
    if !result.is_complete()
        || !structuring::multi_entry_irreducible_sccs(&cfg).is_empty()
        || !result.regions.iter().all(|region: &structuring::Region| {
            matches!(
                region.kind,
                structuring::RegionKind::Block
                    | structuring::RegionKind::IfThen
                    | structuring::RegionKind::IfThenElse
                    | structuring::RegionKind::While
                    | structuring::RegionKind::DoWhile
                    | structuring::RegionKind::NaturalLoop
                    | structuring::RegionKind::SelfLoop
            )
        })
        || !result
            .regions
            .iter()
            .filter_map(|region: &structuring::Region| region.cond)
            .all(|cond: structuring::CondId| condition_is_supported(&blocks, &result.conds, cond))
    {
        return Attempt::NotCandidate;
    }
    let has_loop_region: bool = result.regions.iter().any(|region: &structuring::Region| {
        matches!(
            region.kind,
            structuring::RegionKind::While
                | structuring::RegionKind::DoWhile
                | structuring::RegionKind::NaturalLoop
                | structuring::RegionKind::SelfLoop
        )
    });
    if !has_loop_region {
        let if_then_else_count: usize = result
            .regions
            .iter()
            .filter(|region: &&structuring::Region| {
                region.kind == structuring::RegionKind::IfThenElse
            })
            .count();
        if if_then_else_count != 1 {
            return Attempt::NotCandidate;
        }
        let if_then_else: Option<&structuring::Region> =
            result.regions.iter().find(|region: &&structuring::Region| {
                region.kind == structuring::RegionKind::IfThenElse
            });
        let Some(if_then_else): Option<&structuring::Region> = if_then_else else {
            return Attempt::NotCandidate;
        };
        if if_then_else.exits.len() != 1 {
            return Attempt::NotCandidate;
        }
    }
    let relowered: Option<(structuring::Cfg, BTreeMap<u32, u32>)> =
        relowered_cfg_from_blocks(&blocks);
    let Some((relowered_cfg, residual)): Option<(structuring::Cfg, BTreeMap<u32, u32>)> = relowered
    else {
        return Attempt::NotCandidate;
    };
    if !structuring::relowered_matches_original(&cfg, &relowered_cfg, &residual) {
        return Attempt::NotCandidate;
    }
    let root: Option<structuring::RegionId> = result.root;
    let Some(root): Option<structuring::RegionId> = root else {
        return Attempt::NotCandidate;
    };
    let sinks: BTreeMap<usize, LoopSink> = BTreeMap::new();
    let mut renderer: Renderer<'_> = Renderer {
        blocks: &blocks,
        result: &result,
        forest: &forest,
        sinks: &sinks,
        consumed: BTreeSet::new(),
    };
    let mut body: Vec<Node> = Vec::new();
    if !renderer.render(root, &mut body)
        || renderer.consumed != reachable_blocks(&blocks)
        || block_contains_goto(&body)
    {
        return Attempt::NotCandidate;
    }
    Attempt::Structured(Structured {
        body,
        lifted_split_return: false,
        lifted_loop: has_loop_region,
    })
}

fn build_blocks(items: &[Item], insns: &[DisasmInsn], base: u64) -> Option<Vec<Aarch64Block>> {
    if insns.is_empty() {
        return None;
    }
    let mut statements: Vec<Vec<Stmt>> = vec![Vec::new(); insns.len()];
    let mut terms: Vec<Option<RawTerm>> = vec![None; insns.len()];
    for item in items {
        let instruction: usize = item_instruction_index(base, item.address, insns.len())?;
        match &item.kind {
            ItemKind::Stmt(statement) => statements[instruction].push(statement.clone()),
            ItemKind::Ret => {
                if terms[instruction].is_some() {
                    return None;
                }
                terms[instruction] = Some(RawTerm::Return);
            }
            ItemKind::Jmp { target } => {
                if terms[instruction].is_some() {
                    return None;
                }
                let target: usize = target_instruction_index(base, *target, insns.len())?;
                terms[instruction] = Some(RawTerm::Goto(target));
            }
            ItemKind::Branch {
                kind,
                flags,
                target,
            } => {
                if terms[instruction].is_some() {
                    return None;
                }
                let target: usize = target_instruction_index(base, *target, insns.len())?;
                terms[instruction] = Some(RawTerm::Branch {
                    kind: *kind,
                    flags: flags.clone(),
                    target,
                });
            }
        }
    }
    let mut leaders: Vec<bool> = vec![false; insns.len()];
    leaders[0] = true;
    for (index, term) in terms.iter().enumerate() {
        match term {
            Some(RawTerm::Return) => {
                if index + 1 < insns.len() {
                    leaders[index + 1] = true;
                }
            }
            Some(RawTerm::Goto(target) | RawTerm::Branch { target, .. }) => {
                leaders[*target] = true;
                if index + 1 < insns.len() {
                    leaders[index + 1] = true;
                }
            }
            None => {}
        }
    }
    let leader_indices: Vec<usize> = (0..insns.len())
        .filter(|index: &usize| leaders[*index])
        .collect();
    let mut instruction_blocks: Vec<usize> = vec![0; insns.len()];
    for (block, start) in leader_indices.iter().enumerate() {
        let end: usize = leader_indices
            .get(block + 1)
            .copied()
            .unwrap_or(insns.len());
        for instruction_block in instruction_blocks.iter_mut().take(end).skip(*start) {
            *instruction_block = block;
        }
    }
    let mut blocks: Vec<Aarch64Block> = Vec::with_capacity(leader_indices.len());
    for (block, start) in leader_indices.iter().enumerate() {
        let end: usize = leader_indices
            .get(block + 1)
            .copied()
            .unwrap_or(insns.len());
        if terms[*start..end.saturating_sub(1)]
            .iter()
            .any(Option::is_some)
        {
            return None;
        }
        let terminal: Option<&RawTerm> = terms[end - 1].as_ref();
        let term: Aarch64Term = match terminal {
            Some(RawTerm::Return) => Aarch64Term::Return,
            Some(RawTerm::Goto(target)) => Aarch64Term::Goto(instruction_blocks[*target]),
            Some(RawTerm::Branch {
                kind,
                flags,
                target,
            }) => {
                let not_taken: usize = block.checked_add(1)?;
                if not_taken >= leader_indices.len() {
                    return None;
                }
                Aarch64Term::Branch {
                    kind: *kind,
                    flags: flags.clone(),
                    taken: instruction_blocks[*target],
                    not_taken,
                }
            }
            None => {
                let next: usize = block.checked_add(1)?;
                if next >= leader_indices.len() {
                    return None;
                }
                Aarch64Term::Goto(next)
            }
        };
        let mut block_stmts: Vec<IndexedStmt> = Vec::new();
        for (instruction, instruction_statements) in
            statements.iter().enumerate().take(end).skip(*start)
        {
            for statement in instruction_statements {
                block_stmts.push(IndexedStmt {
                    instruction,
                    stmt: statement.clone(),
                });
            }
        }
        blocks.push(Aarch64Block {
            start: *start,
            end,
            stmts: block_stmts,
            term,
        });
    }
    Some(blocks)
}

fn item_instruction_index(base: u64, address: u64, count: usize) -> Option<usize> {
    let offset: u64 = address.checked_sub(base)?;
    let index: usize = usize::try_from(offset / ITEM_STRIDE).ok()?;
    (index < count).then_some(index)
}

fn target_instruction_index(base: u64, target: u64, count: usize) -> Option<usize> {
    let offset: u64 = target.checked_sub(base)?;
    if offset % ITEM_STRIDE != 0 {
        return None;
    }
    item_instruction_index(base, target, count)
}

fn synthesize_nzcv_conditions(
    blocks: &mut [Aarch64Block],
    insns: &[DisasmInsn],
    flag_definitions: &BTreeMap<usize, TrackedFlags>,
) -> bool {
    let predecessors: Vec<Vec<usize>> = block_predecessors(blocks);
    let mut entries: Vec<FlagState> = vec![FlagState::None; blocks.len()];
    let mut exits: Vec<FlagState> = vec![FlagState::None; blocks.len()];
    let pass_limit: Option<usize> = blocks
        .len()
        .checked_mul(2)
        .and_then(|n: usize| n.checked_add(1));
    let Some(pass_limit): Option<usize> = pass_limit else {
        return false;
    };
    let mut changed: bool = true;
    let mut pass: usize = 0;
    while changed {
        if pass == pass_limit {
            return false;
        }
        changed = false;
        pass += 1;
        for index in 0..blocks.len() {
            let incoming: FlagState = incoming_flag_state(index, &predecessors, &exits);
            if entries[index] != incoming {
                entries[index] = incoming;
                changed = true;
            }
            let outgoing: FlagState =
                transfer_flag_state(entries[index], &blocks[index], insns, flag_definitions);
            if exits[index] != outgoing {
                exits[index] = outgoing;
                changed = true;
            }
        }
    }
    for index in 0..blocks.len() {
        let mnemonic: &str = insns[blocks[index].end - 1].mnemonic.as_str();
        if !mnemonic.starts_with("b.") {
            continue;
        }
        let definition_index: usize = match exits[index] {
            FlagState::One(value) => value,
            FlagState::None | FlagState::Many => return false,
        };
        let definition: Option<&TrackedFlags> = flag_definitions.get(&definition_index);
        let Some(definition): Option<&TrackedFlags> = definition else {
            return false;
        };
        let condition_kind: CondKind = match &blocks[index].term {
            Aarch64Term::Branch { kind, .. } => *kind,
            Aarch64Term::Return | Aarch64Term::Goto(_) => return false,
        };
        if (definition.nz_only && !condition_kind.sign_zero_only())
            || !condition_is_sound(condition_kind, &definition.value)
        {
            return false;
        }
        match &mut blocks[index].term {
            Aarch64Term::Branch { kind, flags, .. } => {
                *kind = condition_kind;
                *flags = definition.value.clone();
            }
            Aarch64Term::Return | Aarch64Term::Goto(_) => return false,
        }
    }
    true
}

fn incoming_flag_state(
    block: usize,
    predecessors: &[Vec<usize>],
    exits: &[FlagState],
) -> FlagState {
    let mut state: FlagState = FlagState::None;
    let mut initialized: bool = block == 0;
    for predecessor in &predecessors[block] {
        if initialized {
            state = merge_flag_states(state, exits[*predecessor]);
        } else {
            state = exits[*predecessor];
            initialized = true;
        }
    }
    state
}

fn merge_flag_states(left: FlagState, right: FlagState) -> FlagState {
    match (left, right) {
        (FlagState::Many, _) | (_, FlagState::Many) => FlagState::Many,
        (FlagState::None, FlagState::None) => FlagState::None,
        (FlagState::One(left), FlagState::One(right)) if left == right => FlagState::One(left),
        (FlagState::None | FlagState::One(_), FlagState::One(_))
        | (FlagState::One(_), FlagState::None) => FlagState::Many,
    }
}

fn transfer_flag_state(
    entry: FlagState,
    block: &Aarch64Block,
    insns: &[DisasmInsn],
    flag_definitions: &BTreeMap<usize, TrackedFlags>,
) -> FlagState {
    let mut state: FlagState = entry;
    for (instruction, insn) in insns.iter().enumerate().take(block.end).skip(block.start) {
        if flag_definitions.contains_key(&instruction) {
            state = FlagState::One(instruction);
        } else if sets_nzcv(insn)
            || insn.mnemonic == "bl"
            || flag_operands_are_written(state, block, instruction, flag_definitions)
        {
            state = FlagState::None;
        }
    }
    state
}

fn sets_nzcv(insn: &DisasmInsn) -> bool {
    matches!(
        insn.mnemonic.as_str(),
        "adds" | "subs" | "cmp" | "cmn" | "tst"
    )
}

fn flag_operands_are_written(
    state: FlagState,
    block: &Aarch64Block,
    instruction: usize,
    flag_definitions: &BTreeMap<usize, TrackedFlags>,
) -> bool {
    let definition: usize = match state {
        FlagState::One(definition) => definition,
        FlagState::None | FlagState::Many => return false,
    };
    let flags: Option<&TrackedFlags> = flag_definitions.get(&definition);
    let Some(flags): Option<&TrackedFlags> = flags else {
        return true;
    };
    let operands: Vec<Reg> = flag_operand_regs(&flags.value);
    block
        .stmts
        .iter()
        .filter(|statement: &&IndexedStmt| statement.instruction == instruction)
        .flat_map(|statement: &IndexedStmt| stmt_dest_regs(&statement.stmt))
        .any(|destination: Reg| operands.contains(&destination))
}

fn cfg_from_blocks(blocks: &[Aarch64Block]) -> Option<structuring::Cfg> {
    cfg_from_blocks_with_entry(blocks, 0)
}

fn cfg_from_blocks_with_entry(blocks: &[Aarch64Block], entry: usize) -> Option<structuring::Cfg> {
    let count: usize = blocks.len();
    if entry >= count {
        return None;
    }
    let mut nodes: Vec<structuring::CfgNode> = Vec::with_capacity(count);
    for (index, block) in blocks.iter().enumerate() {
        let node_id: u32 = u32::try_from(index).ok()?;
        let term: structuring::Terminator = match &block.term {
            Aarch64Term::Return => structuring::Terminator::Return,
            Aarch64Term::Goto(target) => {
                if *target >= count {
                    return None;
                }
                structuring::Terminator::Goto(u32::try_from(*target).ok()?)
            }
            Aarch64Term::Branch {
                taken, not_taken, ..
            } => {
                if *taken >= count || *not_taken >= count {
                    return None;
                }
                structuring::Terminator::Branch {
                    atom: node_id,
                    taken: u32::try_from(*taken).ok()?,
                    not_taken: u32::try_from(*not_taken).ok()?,
                }
            }
        };
        let pure: bool = block_is_pure(block);
        nodes.push(structuring::CfgNode { term, pure });
    }
    structuring::Cfg::new(u32::try_from(entry).ok()?, nodes).ok()
}

fn relowered_cfg_from_blocks(
    blocks: &[Aarch64Block],
) -> Option<(structuring::Cfg, BTreeMap<u32, u32>)> {
    let original_count: u32 = u32::try_from(blocks.len()).ok()?;
    let mut edge_targets: Vec<usize> = Vec::new();
    let mut terms: Vec<structuring::Terminator> = Vec::with_capacity(blocks.len());
    for (index, block) in blocks.iter().enumerate() {
        let node_id: u32 = u32::try_from(index).ok()?;
        let term: structuring::Terminator = match &block.term {
            Aarch64Term::Return => structuring::Terminator::Return,
            Aarch64Term::Goto(target) => structuring::Terminator::Goto(relowered_edge(
                *target,
                original_count,
                &mut edge_targets,
            )?),
            Aarch64Term::Branch {
                taken, not_taken, ..
            } => structuring::Terminator::Branch {
                atom: node_id,
                taken: relowered_edge(*taken, original_count, &mut edge_targets)?,
                not_taken: relowered_edge(*not_taken, original_count, &mut edge_targets)?,
            },
        };
        terms.push(term);
    }
    let mut nodes: Vec<structuring::CfgNode> =
        Vec::with_capacity(blocks.len().checked_add(edge_targets.len())?);
    for (index, term) in terms.into_iter().enumerate() {
        let pure: bool = block_is_pure(&blocks[index]);
        nodes.push(structuring::CfgNode { term, pure });
    }
    let mut residual: BTreeMap<u32, u32> = BTreeMap::new();
    for (offset, target) in edge_targets.into_iter().enumerate() {
        let target_id: u32 = u32::try_from(target).ok()?;
        let stub_id: u32 = original_count.checked_add(u32::try_from(offset).ok()?)?;
        nodes.push(structuring::CfgNode {
            term: structuring::Terminator::Goto(target_id),
            pure: true,
        });
        residual.insert(stub_id, target_id);
    }
    let cfg: structuring::Cfg = structuring::Cfg::new(0, nodes).ok()?;
    Some((cfg, residual))
}

fn relowered_edge(
    target: usize,
    original_count: u32,
    edge_targets: &mut Vec<usize>,
) -> Option<u32> {
    let offset: u32 = u32::try_from(edge_targets.len()).ok()?;
    let stub_id: u32 = original_count.checked_add(offset)?;
    edge_targets.push(target);
    Some(stub_id)
}

fn condition_is_supported(
    blocks: &[Aarch64Block],
    conds: &structuring::CondPool,
    id: structuring::CondId,
) -> bool {
    let require_empty_blocks: bool = matches!(
        conds.nodes().get(id as usize),
        Some(structuring::Cond::And(_, _) | structuring::Cond::Or(_, _))
    );
    condition_is_supported_inner(blocks, conds, id, require_empty_blocks)
}

fn condition_is_supported_inner(
    blocks: &[Aarch64Block],
    conds: &structuring::CondPool,
    id: structuring::CondId,
    require_empty_blocks: bool,
) -> bool {
    match conds.nodes().get(id as usize) {
        Some(structuring::Cond::Leaf(atom) | structuring::Cond::NotLeaf(atom)) => {
            let block: &Aarch64Block = match blocks.get(*atom as usize) {
                Some(block) => block,
                None => return false,
            };
            matches!(&block.term, Aarch64Term::Branch { .. })
                && (!require_empty_blocks || block.stmts.is_empty())
        }
        Some(structuring::Cond::And(left, right) | structuring::Cond::Or(left, right)) => {
            condition_is_supported_inner(blocks, conds, *left, true)
                && condition_is_supported_inner(blocks, conds, *right, true)
        }
        None => false,
    }
}

fn block_is_pure(block: &Aarch64Block) -> bool {
    !block
        .stmts
        .iter()
        .any(|statement: &IndexedStmt| statement_has_side_effect(&statement.stmt))
}

fn statement_has_side_effect(statement: &Stmt) -> bool {
    matches!(
        statement,
        Stmt::Store { .. }
            | Stmt::MemRmw { .. }
            | Stmt::FpStore { .. }
            | Stmt::BlockMove { .. }
            | Stmt::BlockFill { .. }
            | Stmt::Call { .. }
            | Stmt::Vector(VecStmt::Store { .. })
    )
}

fn block_predecessors(blocks: &[Aarch64Block]) -> Vec<Vec<usize>> {
    let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); blocks.len()];
    for (index, block) in blocks.iter().enumerate() {
        for successor in block.successors() {
            if successor >= blocks.len() || predecessors[successor].contains(&index) {
                continue;
            }
            predecessors[successor].push(index);
        }
    }
    predecessors
}

fn reachable_blocks(blocks: &[Aarch64Block]) -> BTreeSet<usize> {
    reachable_blocks_from(blocks, 0)
}

fn reachable_blocks_from(blocks: &[Aarch64Block], entry: usize) -> BTreeSet<usize> {
    if entry >= blocks.len() {
        return BTreeSet::new();
    }
    let mut seen: BTreeSet<usize> = BTreeSet::from([entry]);
    let mut pending: Vec<usize> = vec![entry];
    while let Some(block) = pending.pop() {
        for successor in blocks[block].successors() {
            if successor < blocks.len() && seen.insert(successor) {
                pending.push(successor);
            }
        }
    }
    seen
}

impl Aarch64Block {
    fn successors(&self) -> Vec<usize> {
        match &self.term {
            Aarch64Term::Return => Vec::new(),
            Aarch64Term::Goto(target) => vec![*target],
            Aarch64Term::Branch {
                taken, not_taken, ..
            } => vec![*taken, *not_taken],
        }
    }
}

fn atom_branch(blocks: &[Aarch64Block], atom: structuring::Atom) -> Option<(CondKind, Flags)> {
    match &blocks.get(atom as usize)?.term {
        Aarch64Term::Branch { kind, flags, .. } => Some((*kind, flags.clone())),
        Aarch64Term::Return | Aarch64Term::Goto(_) => None,
    }
}

fn cond_from_region(
    blocks: &[Aarch64Block],
    conds: &structuring::CondPool,
    id: structuring::CondId,
) -> Option<Cond> {
    match conds.nodes().get(id as usize)? {
        structuring::Cond::Leaf(atom) => {
            let (kind, flags): (CondKind, Flags) = atom_branch(blocks, *atom)?;
            Some(Cond::leaf(kind, flags))
        }
        structuring::Cond::NotLeaf(atom) => {
            let (kind, flags): (CondKind, Flags) = atom_branch(blocks, *atom)?;
            Some(Cond::leaf(kind.negate(), flags))
        }
        structuring::Cond::And(left, right) => {
            let lhs: Cond = cond_from_region(blocks, conds, *left)?;
            let rhs: Cond = cond_from_region(blocks, conds, *right)?;
            Some(Cond::And(Box::new(lhs), Box::new(rhs)))
        }
        structuring::Cond::Or(left, right) => {
            let lhs: Cond = cond_from_region(blocks, conds, *left)?;
            let rhs: Cond = cond_from_region(blocks, conds, *right)?;
            Some(Cond::Or(Box::new(lhs), Box::new(rhs)))
        }
    }
}

fn normalize_compound_condition(
    condition: Cond,
    taken: structuring::RegionId,
    not_taken: structuring::RegionId,
) -> (Cond, structuring::RegionId, structuring::RegionId) {
    if !matches!(&condition, Cond::And(_, _) | Cond::Or(_, _)) {
        return (condition, taken, not_taken);
    }
    let negated: Cond = negate_condition(condition.clone());
    if non_strict_condition_count(&negated) < non_strict_condition_count(&condition) {
        (negated, not_taken, taken)
    } else {
        (condition, taken, not_taken)
    }
}

fn negate_condition(condition: Cond) -> Cond {
    match condition {
        Cond::Leaf { kind, flags } => Cond::leaf(kind.negate(), flags),
        Cond::And(left, right) => Cond::Or(
            Box::new(negate_condition(*left)),
            Box::new(negate_condition(*right)),
        ),
        Cond::Or(left, right) => Cond::And(
            Box::new(negate_condition(*left)),
            Box::new(negate_condition(*right)),
        ),
    }
}

fn non_strict_condition_count(condition: &Cond) -> usize {
    match condition {
        Cond::Leaf { kind, .. } => usize::from(matches!(
            kind,
            CondKind::Ge | CondKind::Le | CondKind::Ae | CondKind::Be
        )),
        Cond::And(left, right) | Cond::Or(left, right) => {
            non_strict_condition_count(left) + non_strict_condition_count(right)
        }
    }
}

fn loop_cond_from_region(condition: Cond) -> Option<LoopCond> {
    let Cond::Leaf { kind, flags } = condition else {
        return None;
    };
    Some(LoopCond::Direct { cond: kind, flags })
}

fn block_contains_goto(body: &[Node]) -> bool {
    body.iter().any(|node: &Node| match node {
        Node::If {
            then_body,
            else_body,
            ..
        } => {
            block_contains_goto(then_body)
                || else_body
                    .as_ref()
                    .is_some_and(|else_body: &Vec<Node>| block_contains_goto(else_body))
        }
        Node::DoWhile { body, .. } | Node::While { body, .. } => block_contains_goto(body),
        Node::Goto(_) => true,
        Node::Stmt(_)
        | Node::CondSnapshot { .. }
        | Node::Switch { .. }
        | Node::Break
        | Node::Continue
        | Node::Return
        | Node::Label(_) => false,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoopSink {
    Break,
    Continue,
    Fallthrough,
}

#[derive(Debug, Clone)]
enum LoopForm {
    While(LoopCond),
    DoWhile(LoopCond),
}

#[derive(Debug, Clone)]
struct LoopPlan {
    form: LoopForm,
    entry: usize,
    continue_targets: BTreeSet<usize>,
    canonical_continue_sources: BTreeSet<usize>,
    fallthrough_targets: BTreeSet<usize>,
    canonical_fallthrough_sources: BTreeSet<usize>,
    terminal_latch: Option<usize>,
}

#[derive(Debug, Clone)]
struct LoopBody {
    blocks: Vec<Aarch64Block>,
    entry: usize,
    sinks: BTreeMap<usize, LoopSink>,
}

struct Renderer<'a> {
    blocks: &'a [Aarch64Block],
    result: &'a structuring::StructureResult,
    forest: &'a structuring::LoopForest,
    sinks: &'a BTreeMap<usize, LoopSink>,
    consumed: BTreeSet<usize>,
}

impl Renderer<'_> {
    fn render_sink(&self, entry: usize, out: &mut Vec<Node>) -> bool {
        if let Some(sink) = self.sinks.get(&entry) {
            match sink {
                LoopSink::Break => out.push(Node::Break),
                LoopSink::Continue => out.push(Node::Continue),
                LoopSink::Fallthrough => {}
            }
            return true;
        }
        match &self.blocks[entry].term {
            Aarch64Term::Return => {
                out.push(Node::Return);
                true
            }
            Aarch64Term::Goto(_) | Aarch64Term::Branch { .. } => false,
        }
    }

    fn natural_loop(&self, header: usize) -> Option<structuring::NaturalLoop> {
        let header_id: u32 = u32::try_from(header).ok()?;
        self.forest
            .loops
            .iter()
            .find(|loop_info: &&structuring::NaturalLoop| loop_info.header == header_id)
            .cloned()
    }

    fn natural_loop_body(natural: &structuring::NaturalLoop) -> BTreeSet<usize> {
        natural
            .body
            .iter()
            .map(|node: &u32| *node as usize)
            .collect()
    }

    fn has_nested_loop(&self, natural: &structuring::NaturalLoop) -> bool {
        self.forest
            .loops
            .iter()
            .any(|candidate: &structuring::NaturalLoop| {
                candidate.header != natural.header && candidate.body.is_subset(&natural.body)
            })
    }

    fn loop_follow(&self, body: &BTreeSet<usize>) -> Option<usize> {
        let mut follow: Option<usize> = None;
        for node in body {
            let block: &Aarch64Block = self.blocks.get(*node)?;
            for successor in block.successors() {
                if body.contains(&successor) {
                    continue;
                }
                match follow {
                    None => follow = Some(successor),
                    Some(existing) if existing == successor => {}
                    Some(_) => return None,
                }
            }
        }
        follow
    }

    fn loop_exit_is_current_level(
        &self,
        natural: &structuring::NaturalLoop,
        follow: usize,
    ) -> bool {
        let Some(parent_index): Option<usize> = natural.parent else {
            return true;
        };
        let Some(parent): Option<&structuring::NaturalLoop> = self.forest.loops.get(parent_index)
        else {
            return false;
        };
        let Some(follow_id): Option<u32> = u32::try_from(follow).ok() else {
            return false;
        };
        parent.body.contains(&follow_id)
            && follow_id != parent.header
            && !parent.latches.contains(&follow_id)
    }

    fn condition_from_branch(&self, entry: usize) -> Option<Cond> {
        let block: &Aarch64Block = self.blocks.get(entry)?;
        let Aarch64Term::Branch { kind, flags, .. } = &block.term else {
            return None;
        };
        Some(Cond::leaf(*kind, flags.clone()))
    }

    fn loop_condition_for_edge(
        &self,
        entry: usize,
        repeat_target: usize,
        exit_target: usize,
    ) -> Option<LoopCond> {
        let block: &Aarch64Block = self.blocks.get(entry)?;
        let mut condition: Cond = self.condition_from_branch(entry)?;
        match &block.term {
            Aarch64Term::Branch {
                taken, not_taken, ..
            } if *taken == repeat_target && *not_taken == exit_target => {}
            Aarch64Term::Branch {
                taken, not_taken, ..
            } if *not_taken == repeat_target && *taken == exit_target => {
                condition = negate_condition(condition);
            }
            Aarch64Term::Return | Aarch64Term::Goto(_) | Aarch64Term::Branch { .. } => {
                return None;
            }
        }
        loop_cond_from_region(condition)
    }

    fn latch_is_empty_continue_target(&self, latch: usize, header: usize) -> bool {
        matches!(
            self.blocks.get(latch),
            Some(Aarch64Block {
                stmts,
                term: Aarch64Term::Goto(target),
                ..
            }) if stmts.is_empty() && *target == header
        )
    }

    fn pretested_loop_plan(
        &self,
        natural: &structuring::NaturalLoop,
        body: &BTreeSet<usize>,
        follow: usize,
    ) -> Option<LoopPlan> {
        let header: usize = natural.header as usize;
        let header_block: &Aarch64Block = self.blocks.get(header)?;
        if !header_block.stmts.is_empty() {
            return None;
        }
        let (taken, not_taken): (usize, usize) = match &header_block.term {
            Aarch64Term::Branch {
                taken, not_taken, ..
            } => (*taken, *not_taken),
            Aarch64Term::Return | Aarch64Term::Goto(_) => return None,
        };
        let body_entry: usize = if body.contains(&taken) && not_taken == follow {
            taken
        } else if body.contains(&not_taken) && taken == follow {
            not_taken
        } else {
            return None;
        };
        if body_entry == header {
            return None;
        }
        let condition: LoopCond = self.loop_condition_for_edge(header, body_entry, follow)?;
        let mut continue_targets: BTreeSet<usize> = BTreeSet::from([header]);
        let mut canonical_continue_sources: BTreeSet<usize> = BTreeSet::new();
        for latch_id in &natural.latches {
            let latch: usize = *latch_id as usize;
            if matches!(
                self.blocks.get(latch),
                Some(Aarch64Block {
                    term: Aarch64Term::Goto(target),
                    ..
                }) if *target == header
            ) {
                canonical_continue_sources.insert(latch);
            }
            if self.latch_is_empty_continue_target(latch, header) {
                continue_targets.insert(latch);
            }
        }
        Some(LoopPlan {
            form: LoopForm::While(condition),
            entry: body_entry,
            continue_targets,
            canonical_continue_sources,
            fallthrough_targets: BTreeSet::new(),
            canonical_fallthrough_sources: BTreeSet::new(),
            terminal_latch: None,
        })
    }

    fn posttested_loop_plan(
        &self,
        natural: &structuring::NaturalLoop,
        body: &BTreeSet<usize>,
        follow: usize,
    ) -> Option<LoopPlan> {
        let header: usize = natural.header as usize;
        let header_block: &Aarch64Block = self.blocks.get(header)?;
        if !header_block.stmts.is_empty() {
            return None;
        }
        let body_entry: usize = match &header_block.term {
            Aarch64Term::Goto(target) => *target,
            Aarch64Term::Return | Aarch64Term::Branch { .. } => return None,
        };
        if body_entry == header {
            return None;
        }
        let mut chosen: Option<(usize, LoopCond)> = None;
        for latch_id in &natural.latches {
            let latch: usize = *latch_id as usize;
            let condition: Option<LoopCond> = self.loop_condition_for_edge(latch, header, follow);
            let Some(condition): Option<LoopCond> = condition else {
                continue;
            };
            if chosen.is_some() {
                return None;
            }
            chosen = Some((latch, condition));
        }
        let (latch, condition): (usize, LoopCond) = chosen?;
        let continue_targets: BTreeSet<usize> = BTreeSet::new();
        let mut fallthrough_targets: BTreeSet<usize> = BTreeSet::new();
        let mut canonical_fallthrough_sources: BTreeSet<usize> = BTreeSet::new();
        if self
            .blocks
            .get(latch)
            .is_some_and(|block: &Aarch64Block| block.stmts.is_empty())
        {
            fallthrough_targets.insert(latch);
            for node in body {
                if matches!(
                    self.blocks.get(*node),
                    Some(Aarch64Block {
                        term: Aarch64Term::Goto(target),
                        ..
                    }) if *target == latch
                ) {
                    canonical_fallthrough_sources.insert(*node);
                }
            }
        }
        Some(LoopPlan {
            form: LoopForm::DoWhile(condition),
            entry: body_entry,
            continue_targets,
            canonical_continue_sources: BTreeSet::new(),
            fallthrough_targets,
            canonical_fallthrough_sources,
            terminal_latch: Some(latch),
        })
    }

    fn build_loop_body(
        &self,
        natural: &structuring::NaturalLoop,
        body: &BTreeSet<usize>,
        follow: usize,
        plan: &LoopPlan,
    ) -> Option<LoopBody> {
        let header: usize = natural.header as usize;
        let order: Vec<usize> = body
            .iter()
            .copied()
            .filter(|node: &usize| *node != header)
            .collect();
        let sub_of: BTreeMap<usize, usize> = order
            .iter()
            .enumerate()
            .map(|(index, node): (usize, &usize)| (*node, index))
            .collect();
        let entry: usize = sub_of.get(&plan.entry).copied()?;
        let sink_for_target = |target: usize| -> Option<LoopSink> {
            if plan.continue_targets.contains(&target) {
                Some(LoopSink::Continue)
            } else if plan.fallthrough_targets.contains(&target) {
                Some(LoopSink::Fallthrough)
            } else if target == follow {
                Some(LoopSink::Break)
            } else {
                None
            }
        };
        let mut special_sinks: BTreeMap<(usize, u8), LoopSink> = BTreeMap::new();
        for node in &order {
            let source: &Aarch64Block = self.blocks.get(*node)?;
            if plan.terminal_latch == Some(*node) {
                special_sinks.insert((*node, 0), LoopSink::Fallthrough);
                continue;
            }
            match &source.term {
                Aarch64Term::Return => {}
                Aarch64Term::Goto(target) => match sink_for_target(*target) {
                    Some(LoopSink::Continue) if plan.canonical_continue_sources.contains(node) => {
                        special_sinks.insert((*node, 0), LoopSink::Continue);
                    }
                    Some(LoopSink::Fallthrough)
                        if plan.canonical_fallthrough_sources.contains(node) =>
                    {
                        special_sinks.insert((*node, 0), LoopSink::Fallthrough);
                    }
                    Some(LoopSink::Break | LoopSink::Continue | LoopSink::Fallthrough) => {
                        return None;
                    }
                    None => {
                        sub_of.get(target)?;
                    }
                },
                Aarch64Term::Branch {
                    taken, not_taken, ..
                } => {
                    let taken_sink: Option<LoopSink> = sink_for_target(*taken);
                    let not_taken_sink: Option<LoopSink> = sink_for_target(*not_taken);
                    match (taken_sink, not_taken_sink) {
                        (Some(LoopSink::Fallthrough), _) | (_, Some(LoopSink::Fallthrough)) => {
                            return None;
                        }
                        (Some(_), Some(_)) => return None,
                        (Some(sink), None) => {
                            sub_of.get(not_taken)?;
                            special_sinks.insert((*node, 1), sink);
                        }
                        (None, Some(sink)) => {
                            sub_of.get(taken)?;
                            special_sinks.insert((*node, 2), sink);
                        }
                        (None, None) => {
                            sub_of.get(taken)?;
                            sub_of.get(not_taken)?;
                        }
                    }
                }
            }
        }
        let total_blocks: usize = order.len().checked_add(special_sinks.len())?;
        let mut blocks: Vec<Aarch64Block> = Vec::with_capacity(total_blocks);
        let mut sink_indices: BTreeMap<(usize, u8), usize> = BTreeMap::new();
        let mut sinks: BTreeMap<usize, LoopSink> = BTreeMap::new();
        for (offset, (edge, sink)) in special_sinks.iter().enumerate() {
            let index: usize = order.len().checked_add(offset)?;
            sink_indices.insert(*edge, index);
            sinks.insert(index, *sink);
        }
        let sink_index =
            |node: usize, arm: u8| -> Option<usize> { sink_indices.get(&(node, arm)).copied() };
        for node in &order {
            let source: &Aarch64Block = self.blocks.get(*node)?;
            let term: Aarch64Term = if plan.terminal_latch == Some(*node) {
                Aarch64Term::Goto(sink_index(*node, 0)?)
            } else {
                match &source.term {
                    Aarch64Term::Return => Aarch64Term::Return,
                    Aarch64Term::Goto(target) => {
                        let target: usize = match sink_for_target(*target) {
                            Some(LoopSink::Continue)
                                if plan.canonical_continue_sources.contains(node) =>
                            {
                                sink_index(*node, 0)?
                            }
                            Some(LoopSink::Fallthrough)
                                if plan.canonical_fallthrough_sources.contains(node) =>
                            {
                                sink_index(*node, 0)?
                            }
                            Some(LoopSink::Break | LoopSink::Continue | LoopSink::Fallthrough) => {
                                return None;
                            }
                            None => sub_of.get(target).copied()?,
                        };
                        Aarch64Term::Goto(target)
                    }
                    Aarch64Term::Branch {
                        kind,
                        flags,
                        taken,
                        not_taken,
                    } => {
                        let taken: usize = match sink_for_target(*taken) {
                            Some(LoopSink::Break | LoopSink::Continue) => sink_index(*node, 1)?,
                            Some(LoopSink::Fallthrough) => return None,
                            None => sub_of.get(taken).copied()?,
                        };
                        let not_taken: usize = match sink_for_target(*not_taken) {
                            Some(LoopSink::Break | LoopSink::Continue) => sink_index(*node, 2)?,
                            Some(LoopSink::Fallthrough) => return None,
                            None => sub_of.get(not_taken).copied()?,
                        };
                        Aarch64Term::Branch {
                            kind: *kind,
                            flags: flags.clone(),
                            taken,
                            not_taken,
                        }
                    }
                }
            };
            blocks.push(Aarch64Block {
                start: source.start,
                end: source.end,
                stmts: source.stmts.clone(),
                term,
            });
        }
        for _ in &special_sinks {
            blocks.push(Aarch64Block {
                start: 0,
                end: 0,
                stmts: Vec::new(),
                term: Aarch64Term::Return,
            });
        }
        Some(LoopBody {
            blocks,
            entry,
            sinks,
        })
    }

    fn render_natural_loop(&mut self, region: &structuring::Region, out: &mut Vec<Node>) -> bool {
        let header: usize = region.entry as usize;
        let natural: structuring::NaturalLoop = match self.natural_loop(header) {
            Some(natural) => natural,
            None => return false,
        };
        if self.has_nested_loop(&natural) {
            return false;
        }
        let body: BTreeSet<usize> = Self::natural_loop_body(&natural);
        let follow: usize = match self.loop_follow(&body) {
            Some(follow) => follow,
            None => return false,
        };
        if !self.loop_exit_is_current_level(&natural, follow) {
            return false;
        }
        let plan: LoopPlan = match self.pretested_loop_plan(&natural, &body, follow) {
            Some(plan) => plan,
            None => match self.posttested_loop_plan(&natural, &body, follow) {
                Some(plan) => plan,
                None => return false,
            },
        };
        let loop_body: LoopBody = match self.build_loop_body(&natural, &body, follow, &plan) {
            Some(loop_body) => loop_body,
            None => return false,
        };
        let rendered: bool = {
            let cfg: structuring::Cfg =
                match cfg_from_blocks_with_entry(&loop_body.blocks, loop_body.entry) {
                    Some(cfg) => cfg,
                    None => return false,
                };
            let result: structuring::StructureResult = structuring::structure(&cfg);
            if !result.is_complete()
                || !structuring::multi_entry_irreducible_sccs(&cfg).is_empty()
                || !result.regions.iter().all(|nested: &structuring::Region| {
                    matches!(
                        nested.kind,
                        structuring::RegionKind::Block
                            | structuring::RegionKind::IfThen
                            | structuring::RegionKind::IfThenElse
                    )
                })
                || !result
                    .regions
                    .iter()
                    .filter_map(|nested: &structuring::Region| nested.cond)
                    .all(|cond: structuring::CondId| {
                        condition_is_supported(&loop_body.blocks, &result.conds, cond)
                    })
            {
                return false;
            }
            let root: structuring::RegionId = match result.root {
                Some(root) => root,
                None => return false,
            };
            let forest: structuring::LoopForest = structuring::loop_forest(&cfg);
            let mut nested_renderer: Renderer<'_> = Renderer {
                blocks: &loop_body.blocks,
                result: &result,
                forest: &forest,
                sinks: &loop_body.sinks,
                consumed: BTreeSet::new(),
            };
            let mut loop_nodes: Vec<Node> = Vec::new();
            if !nested_renderer.render(root, &mut loop_nodes)
                || nested_renderer.consumed
                    != reachable_blocks_from(&loop_body.blocks, loop_body.entry)
                || block_contains_goto(&loop_nodes)
            {
                return false;
            }
            match &plan.form {
                LoopForm::While(condition) => out.push(Node::While {
                    body: loop_nodes,
                    cond: Some(condition.clone()),
                }),
                LoopForm::DoWhile(condition) => out.push(Node::DoWhile {
                    body: loop_nodes,
                    cond: condition.clone(),
                }),
            }
            true
        };
        if !rendered {
            return false;
        }
        for node in body {
            if !self.consumed.insert(node) {
                return false;
            }
        }
        true
    }

    fn region_entry(&self, id: structuring::RegionId) -> Option<usize> {
        Some(self.result.regions.get(id as usize)?.entry as usize)
    }

    fn is_leaf_block(&self, id: structuring::RegionId, entry: usize) -> bool {
        let Some(region): Option<&structuring::Region> = self.result.regions.get(id as usize)
        else {
            return false;
        };
        region.kind == structuring::RegionKind::Block
            && region.children.is_empty()
            && region.entry as usize == entry
    }

    fn consume_empty_branch_header(&mut self, id: structuring::RegionId, entry: usize) -> bool {
        if !self.is_leaf_block(id, entry)
            || !self.blocks[entry].stmts.is_empty()
            || !matches!(&self.blocks[entry].term, Aarch64Term::Branch { .. })
        {
            return false;
        }
        self.consumed.insert(entry)
    }

    fn consume_empty_goto_header(
        &mut self,
        id: structuring::RegionId,
        entry: usize,
        target: usize,
    ) -> bool {
        if !self.is_leaf_block(id, entry)
            || !self.blocks[entry].stmts.is_empty()
            || !matches!(&self.blocks[entry].term, Aarch64Term::Goto(actual) if *actual == target)
        {
            return false;
        }
        self.consumed.insert(entry)
    }

    fn loop_condition(
        &self,
        region: &structuring::Region,
        branch_entry: usize,
        repeat_target: usize,
    ) -> Option<LoopCond> {
        let exit: usize = *region.exits.as_slice().first()? as usize;
        if region.exits.len() != 1 {
            return None;
        }
        let cond_id: structuring::CondId = region.cond?;
        let mut condition: Cond = cond_from_region(self.blocks, &self.result.conds, cond_id)?;
        match &self.blocks.get(branch_entry)?.term {
            Aarch64Term::Branch {
                taken, not_taken, ..
            } if *taken == repeat_target && *not_taken == exit => {}
            Aarch64Term::Branch {
                taken, not_taken, ..
            } if *not_taken == repeat_target && *taken == exit => {
                condition = negate_condition(condition);
            }
            Aarch64Term::Return | Aarch64Term::Goto(_) | Aarch64Term::Branch { .. } => {
                return None;
            }
        }
        loop_cond_from_region(condition)
    }

    fn render_while(&mut self, region: &structuring::Region, out: &mut Vec<Node>) -> bool {
        let (head, body_id): (structuring::RegionId, structuring::RegionId) =
            match region.children.as_slice() {
                [head, body] => (*head, *body),
                _ => return false,
            };
        let header_entry: usize = region.entry as usize;
        let body_entry: usize = match self.region_entry(body_id) {
            Some(entry) => entry,
            None => return false,
        };
        let condition: LoopCond = match self.loop_condition(region, header_entry, body_entry) {
            Some(condition) => condition,
            None => return false,
        };
        if !self.consume_empty_branch_header(head, header_entry) {
            return false;
        }
        let mut body: Vec<Node> = Vec::new();
        if !self.render(body_id, &mut body) {
            return false;
        }
        out.push(Node::While {
            body,
            cond: Some(condition),
        });
        true
    }

    fn render_do_while(&mut self, region: &structuring::Region, out: &mut Vec<Node>) -> bool {
        let (head, latch): (structuring::RegionId, structuring::RegionId) =
            match region.children.as_slice() {
                [head, latch] => (*head, *latch),
                _ => return false,
            };
        let header_entry: usize = region.entry as usize;
        let latch_entry: usize = match self.region_entry(latch) {
            Some(entry) => entry,
            None => return false,
        };
        if !self.is_leaf_block(latch, latch_entry) {
            return false;
        }
        let condition: LoopCond = match self.loop_condition(region, latch_entry, header_entry) {
            Some(condition) => condition,
            None => return false,
        };
        if !self.consume_empty_goto_header(head, header_entry, latch_entry) {
            return false;
        }
        let mut body: Vec<Node> = Vec::new();
        if !self.render(latch, &mut body) {
            return false;
        }
        out.push(Node::DoWhile {
            body,
            cond: condition,
        });
        true
    }

    fn render(&mut self, id: structuring::RegionId, out: &mut Vec<Node>) -> bool {
        let region: &structuring::Region = match self.result.regions.get(id as usize) {
            Some(region) => region,
            None => return false,
        };
        match region.kind {
            structuring::RegionKind::Block if region.children.is_empty() => {
                let entry: usize = region.entry as usize;
                if entry >= self.blocks.len() || !self.consumed.insert(entry) {
                    return false;
                }
                for statement in &self.blocks[entry].stmts {
                    out.push(Node::Stmt(statement.stmt.clone()));
                }
                if matches!(&self.blocks[entry].term, Aarch64Term::Return) {
                    return self.render_sink(entry, out);
                }
                true
            }
            structuring::RegionKind::Block => region
                .children
                .iter()
                .all(|child: &structuring::RegionId| self.render(*child, out)),
            structuring::RegionKind::IfThen => {
                let head: structuring::RegionId = match region.head {
                    Some(head) => head,
                    None => return false,
                };
                let cond_id: structuring::CondId = match region.cond {
                    Some(cond) => cond,
                    None => return false,
                };
                let arm: structuring::RegionId = match region.children.as_slice() {
                    [arm] => *arm,
                    _ => return false,
                };
                if !self.render(head, out) {
                    return false;
                }
                let cond: Option<Cond> = cond_from_region(self.blocks, &self.result.conds, cond_id);
                let Some(cond): Option<Cond> = cond else {
                    return false;
                };
                let mut then_body: Vec<Node> = Vec::new();
                if !self.render(arm, &mut then_body) {
                    return false;
                }
                out.push(Node::If {
                    cond,
                    then_body,
                    else_body: None,
                });
                true
            }
            structuring::RegionKind::IfThenElse => {
                let head: structuring::RegionId = match region.head {
                    Some(head) => head,
                    None => return false,
                };
                let cond_id: structuring::CondId = match region.cond {
                    Some(cond) => cond,
                    None => return false,
                };
                let (taken, not_taken): (structuring::RegionId, structuring::RegionId) =
                    match region.children.as_slice() {
                        [taken, not_taken] => (*taken, *not_taken),
                        _ => return false,
                    };
                if !self.render(head, out) {
                    return false;
                }
                let cond: Option<Cond> = cond_from_region(self.blocks, &self.result.conds, cond_id);
                let Some(cond): Option<Cond> = cond else {
                    return false;
                };
                let (guard, then_id, else_id): (
                    Cond,
                    structuring::RegionId,
                    structuring::RegionId,
                ) = normalize_compound_condition(cond, taken, not_taken);
                let mut then_body: Vec<Node> = Vec::new();
                if !self.render(then_id, &mut then_body) {
                    return false;
                }
                let mut else_body: Vec<Node> = Vec::new();
                if !self.render(else_id, &mut else_body) {
                    return false;
                }
                out.push(Node::If {
                    cond: guard,
                    then_body,
                    else_body: Some(else_body),
                });
                true
            }
            structuring::RegionKind::While => self.render_while(region, out),
            structuring::RegionKind::DoWhile => self.render_do_while(region, out),
            structuring::RegionKind::NaturalLoop => self.render_natural_loop(region, out),
            structuring::RegionKind::Switch
            | structuring::RegionKind::SelfLoop
            | structuring::RegionKind::Proper
            | structuring::RegionKind::Irreducible => false,
        }
    }
}
