use std::collections::{BTreeMap, BTreeSet};

use disrobe_core::{AdjGraph, dominator_sets, immediate_post_dominators};

use super::{BasicBlock, BlockId, Budget, DvIr, IrInstruction, Terminator, ValueId};

const MAX_STRUCTURE_DEPTH: usize = 128;
const MAX_STRUCTURE_BLOCKS: usize = 4_096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StructuredAst {
    Structured(Vec<StructuredNode>),
    Fallback { reason: String },
}

impl StructuredAst {
    #[must_use]
    pub fn fallback_reason(&self) -> Option<&str> {
        match self {
            Self::Structured(_) => None,
            Self::Fallback { reason } => Some(reason),
        }
    }

    #[must_use]
    pub fn nodes(&self) -> Option<&[StructuredNode]> {
        match self {
            Self::Structured(nodes) => Some(nodes),
            Self::Fallback { .. } => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StructuredNode {
    Instructions(Vec<IrInstruction>),
    Assignments(Vec<IrInstruction>),
    Return(Option<ValueId>),
    If {
        condition: ValueId,
        when_true: Vec<Self>,
        when_false: Vec<Self>,
    },
    While {
        condition: ValueId,
        continues_when_true: bool,
        header: Vec<IrInstruction>,
        body: Vec<Self>,
    },
    DoWhile {
        condition: ValueId,
        continues_when_true: bool,
        body: Vec<Self>,
    },
    Break,
    Continue,
}

#[derive(Clone, Debug)]
struct StructureError {
    reason: String,
}

impl StructureError {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    fn from_budget(budget: &mut Budget) -> Result<(), Self> {
        budget
            .spend(1)
            .map_err(|error| Self::new(format!("analysis budget exhausted: {error}")))
    }
}

#[derive(Clone, Debug)]
enum LoopShape {
    While {
        body_entry: usize,
        exit: usize,
        condition: ValueId,
        continues_when_true: bool,
    },
    DoWhile {
        body_entry: usize,
        latch: usize,
        exit: usize,
        condition: ValueId,
        continues_when_true: bool,
    },
}

#[derive(Clone, Debug)]
struct LoopInfo {
    header: usize,
    body: BTreeSet<usize>,
    shape: LoopShape,
}

#[derive(Debug)]
struct Cfg {
    blocks: Vec<BasicBlock>,
    indices: BTreeMap<BlockId, usize>,
    post_dominators: Vec<Option<usize>>,
    loops: BTreeMap<usize, LoopInfo>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegionExit {
    Stop,
    Return,
    Continue,
    Break,
    Complete,
}

pub fn structure(ir: &DvIr, budget: &mut Budget) -> StructuredAst {
    let result: Result<StructuredAst, StructureError> = structure_impl(ir, budget);
    match result {
        Ok(ast) => ast,
        Err(error) => StructuredAst::Fallback {
            reason: error.reason,
        },
    }
}

fn structure_impl(ir: &DvIr, budget: &mut Budget) -> Result<StructuredAst, StructureError> {
    match ir.verify(budget) {
        Ok(()) => {}
        Err(error) if error.reason.contains("step cap") || error.reason.contains("deadline") => {
            return Err(StructureError::new("analysis budget exhausted"));
        }
        Err(error) => {
            return Err(StructureError::new(format!(
                "invalid DvIr: {}",
                error.reason
            )));
        }
    }
    let cfg: Cfg = Cfg::new(ir, budget)?;
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    let stop: BTreeSet<usize> = BTreeSet::new();
    let (nodes, _exit): (Vec<StructuredNode>, RegionExit) =
        build_region(&cfg, 0, &stop, None, &mut visited, 0, budget)?;
    if visited.len() != cfg.blocks.len() {
        return Err(StructureError::new(
            "control flow leaves blocks outside the structured region",
        ));
    }
    let mut visible_values: BTreeSet<ValueId> = BTreeSet::new();
    validate_structured_scopes(&nodes, &mut visible_values, None, None, 0, budget)?;
    Ok(StructuredAst::Structured(nodes))
}

impl Cfg {
    fn new(ir: &DvIr, budget: &mut Budget) -> Result<Self, StructureError> {
        if ir.blocks.len() > MAX_STRUCTURE_BLOCKS {
            return Err(StructureError::new(
                "control-flow graph exceeds structure block cap",
            ));
        }
        let mut by_id: BTreeMap<BlockId, BasicBlock> = BTreeMap::new();
        for block in &ir.blocks {
            StructureError::from_budget(budget)?;
            if by_id.insert(block.id, block.clone()).is_some() {
                return Err(StructureError::new("IR has duplicate block identifiers"));
            }
        }
        let entry: BasicBlock = by_id
            .remove(&ir.entry)
            .ok_or_else(|| StructureError::new("IR entry block is absent"))?;
        let mut blocks: Vec<BasicBlock> = Vec::with_capacity(ir.blocks.len());
        blocks.push(entry);
        blocks.extend(by_id.into_values());
        let mut indices: BTreeMap<BlockId, usize> = BTreeMap::new();
        for (index, block) in blocks.iter().enumerate() {
            StructureError::from_budget(budget)?;
            indices.insert(block.id, index);
        }
        let mut successors: Vec<Vec<usize>> = Vec::with_capacity(blocks.len());
        for block in &blocks {
            StructureError::from_budget(budget)?;
            let mut targets: Vec<usize> = Vec::new();
            for target in terminator_targets(&block.terminator) {
                StructureError::from_budget(budget)?;
                let index: usize = indices
                    .get(&target)
                    .copied()
                    .ok_or_else(|| StructureError::new("IR branch target is absent"))?;
                targets.push(index);
            }
            targets.sort_unstable();
            targets.dedup();
            successors.push(targets);
        }
        let predecessors: Vec<Vec<usize>> = predecessors(&successors, budget)?;
        let reachable: BTreeSet<usize> = reachable_nodes(&successors, budget)?;
        if reachable.len() != blocks.len() {
            return Err(StructureError::new(
                "unreachable block prevents whole-function structuring",
            ));
        }
        reject_irreducible(&successors, &predecessors, budget)?;
        let dominators: Vec<BTreeSet<usize>> = dominators(&successors, budget)?;
        validate_value_dominance(&blocks, &dominators, budget)?;
        let loops: BTreeMap<usize, LoopInfo> = detect_loops(
            &blocks,
            &indices,
            &successors,
            &predecessors,
            &dominators,
            budget,
        )?;
        let post_dominators: Vec<Option<usize>> = post_dominators(&successors, budget)?;
        Ok(Self {
            blocks,
            indices,
            post_dominators,
            loops,
        })
    }
}

fn terminator_targets(terminator: &Terminator) -> Vec<BlockId> {
    match terminator {
        Terminator::Br(target) => vec![*target],
        Terminator::CondBr {
            when_true,
            when_false,
            ..
        } => vec![*when_true, *when_false],
        Terminator::Ret(_) => Vec::new(),
    }
}

fn predecessors(
    successors: &[Vec<usize>],
    budget: &mut Budget,
) -> Result<Vec<Vec<usize>>, StructureError> {
    let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); successors.len()];
    for (from, targets) in successors.iter().enumerate() {
        StructureError::from_budget(budget)?;
        for target in targets {
            StructureError::from_budget(budget)?;
            let entries: &mut Vec<usize> = predecessors
                .get_mut(*target)
                .ok_or_else(|| StructureError::new("successor index is out of range"))?;
            entries.push(from);
        }
    }
    for entries in &mut predecessors {
        StructureError::from_budget(budget)?;
        entries.sort_unstable();
        entries.dedup();
    }
    Ok(predecessors)
}

fn reachable_nodes(
    successors: &[Vec<usize>],
    budget: &mut Budget,
) -> Result<BTreeSet<usize>, StructureError> {
    let mut reachable: BTreeSet<usize> = BTreeSet::new();
    let mut pending: Vec<usize> = vec![0];
    while let Some(node) = pending.pop() {
        StructureError::from_budget(budget)?;
        if !reachable.insert(node) {
            continue;
        }
        let targets: &Vec<usize> = successors
            .get(node)
            .ok_or_else(|| StructureError::new("successor index is out of range"))?;
        for target in targets.iter().rev() {
            StructureError::from_budget(budget)?;
            pending.push(*target);
        }
    }
    Ok(reachable)
}

fn dominators(
    successors: &[Vec<usize>],
    budget: &mut Budget,
) -> Result<Vec<BTreeSet<usize>>, StructureError> {
    charge_shared_graph_analysis(successors.len(), budget)?;
    let mut graph_successors: Vec<Vec<u32>> = Vec::with_capacity(successors.len());
    for targets in successors {
        StructureError::from_budget(budget)?;
        let mut converted: Vec<u32> = Vec::with_capacity(targets.len());
        for target in targets {
            StructureError::from_budget(budget)?;
            let value: u32 = u32::try_from(*target).map_err(|_| {
                StructureError::new("control-flow index exceeds dominator capacity")
            })?;
            converted.push(value);
        }
        graph_successors.push(converted);
    }
    let graph: AdjGraph = AdjGraph::new(0, graph_successors);
    StructureError::from_budget(budget)?;
    let raw_sets: Vec<BTreeSet<u32>> = dominator_sets(&graph);
    let mut converted_sets: Vec<BTreeSet<usize>> = Vec::with_capacity(raw_sets.len());
    for raw_set in raw_sets {
        StructureError::from_budget(budget)?;
        let mut converted_set: BTreeSet<usize> = BTreeSet::new();
        for node in raw_set {
            StructureError::from_budget(budget)?;
            let value: usize = usize::try_from(node)
                .map_err(|_| StructureError::new("dominator index cannot be represented"))?;
            converted_set.insert(value);
        }
        converted_sets.push(converted_set);
    }
    Ok(converted_sets)
}

fn validate_value_dominance(
    blocks: &[BasicBlock],
    dominators: &[BTreeSet<usize>],
    budget: &mut Budget,
) -> Result<(), StructureError> {
    let mut definitions: BTreeMap<ValueId, usize> = BTreeMap::new();
    for (block_index, block) in blocks.iter().enumerate() {
        StructureError::from_budget(budget)?;
        for instruction in &block.instructions {
            StructureError::from_budget(budget)?;
            if let Some(destination) = instruction_destination(instruction)
                && definitions.insert(destination, block_index).is_some()
            {
                return Err(StructureError::new("IR value has multiple definitions"));
            }
        }
    }
    for (block_index, block) in blocks.iter().enumerate() {
        StructureError::from_budget(budget)?;
        for instruction in &block.instructions {
            StructureError::from_budget(budget)?;
            validate_value_uses(
                instruction_uses(instruction),
                block_index,
                &definitions,
                dominators,
            )?;
        }
        validate_value_uses(
            terminator_uses(&block.terminator),
            block_index,
            &definitions,
            dominators,
        )?;
    }
    Ok(())
}

const fn instruction_destination(instruction: &IrInstruction) -> Option<ValueId> {
    match instruction {
        IrInstruction::Const { destination, .. }
        | IrInstruction::LoadArgument { destination, .. }
        | IrInstruction::LoadLocal { destination, .. }
        | IrInstruction::Binary { destination, .. } => Some(*destination),
        IrInstruction::StoreArgument { .. } | IrInstruction::StoreLocal { .. } => None,
    }
}

fn instruction_uses(instruction: &IrInstruction) -> Vec<ValueId> {
    match instruction {
        IrInstruction::Const { .. }
        | IrInstruction::LoadArgument { .. }
        | IrInstruction::LoadLocal { .. } => Vec::new(),
        IrInstruction::StoreArgument { value, .. } | IrInstruction::StoreLocal { value, .. } => {
            vec![*value]
        }
        IrInstruction::Binary { left, right, .. } => vec![*left, *right],
    }
}

fn terminator_uses(terminator: &Terminator) -> Vec<ValueId> {
    match terminator {
        Terminator::Br(_) | Terminator::Ret(None) => Vec::new(),
        Terminator::CondBr { condition, .. } => vec![*condition],
        Terminator::Ret(Some(value)) => vec![*value],
    }
}

fn validate_value_uses(
    uses: Vec<ValueId>,
    block_index: usize,
    definitions: &BTreeMap<ValueId, usize>,
    dominators: &[BTreeSet<usize>],
) -> Result<(), StructureError> {
    let dominators_of_block: &BTreeSet<usize> = dominators
        .get(block_index)
        .ok_or_else(|| StructureError::new("dominator set is absent"))?;
    for value in uses {
        let definition: usize = definitions
            .get(&value)
            .copied()
            .ok_or_else(|| StructureError::new("IR use precedes its definition"))?;
        if definition != block_index && !dominators_of_block.contains(&definition) {
            return Err(StructureError::new(
                "IR value definition does not dominate its use",
            ));
        }
    }
    Ok(())
}

fn validate_structured_scopes(
    nodes: &[StructuredNode],
    visible_values: &mut BTreeSet<ValueId>,
    forced_assignment: Option<ValueId>,
    continue_assignments: Option<&[IrInstruction]>,
    depth: usize,
    budget: &mut Budget,
) -> Result<(), StructureError> {
    if depth > MAX_STRUCTURE_DEPTH {
        return Err(StructureError::new(
            "structured scope nesting exceeds depth cap",
        ));
    }
    for node in nodes {
        StructureError::from_budget(budget)?;
        match node {
            StructuredNode::Instructions(instructions) => {
                for instruction in instructions {
                    validate_structured_instruction(
                        instruction,
                        visible_values,
                        forced_assignment,
                        false,
                        budget,
                    )?;
                }
            }
            StructuredNode::Assignments(instructions) => {
                for instruction in instructions {
                    validate_structured_instruction(
                        instruction,
                        visible_values,
                        forced_assignment,
                        true,
                        budget,
                    )?;
                }
            }
            StructuredNode::Return(Some(value)) => {
                validate_structured_value(*value, visible_values)?;
            }
            StructuredNode::Return(None) | StructuredNode::Break => {}
            StructuredNode::If {
                condition,
                when_true,
                when_false,
            } => {
                validate_structured_value(*condition, visible_values)?;
                let mut true_values: BTreeSet<ValueId> = visible_values.clone();
                validate_structured_scopes(
                    when_true,
                    &mut true_values,
                    forced_assignment,
                    continue_assignments,
                    depth.saturating_add(1),
                    budget,
                )?;
                let mut false_values: BTreeSet<ValueId> = visible_values.clone();
                validate_structured_scopes(
                    when_false,
                    &mut false_values,
                    forced_assignment,
                    continue_assignments,
                    depth.saturating_add(1),
                    budget,
                )?;
            }
            StructuredNode::While {
                condition,
                header,
                body,
                ..
            } => {
                for instruction in header {
                    validate_structured_instruction(
                        instruction,
                        visible_values,
                        None,
                        false,
                        budget,
                    )?;
                }
                validate_structured_value(*condition, visible_values)?;
                let mut body_values: BTreeSet<ValueId> = visible_values.clone();
                validate_structured_scopes(
                    body,
                    &mut body_values,
                    forced_assignment,
                    Some(header),
                    depth.saturating_add(1),
                    budget,
                )?;
            }
            StructuredNode::DoWhile {
                condition, body, ..
            } => {
                if !visible_values.insert(*condition) {
                    return Err(StructureError::new(
                        "structured rendering redeclares a loop predicate value",
                    ));
                }
                let mut body_values: BTreeSet<ValueId> = visible_values.clone();
                validate_structured_scopes(
                    body,
                    &mut body_values,
                    Some(*condition),
                    None,
                    depth.saturating_add(1),
                    budget,
                )?;
            }
            StructuredNode::Continue => {
                if let Some(instructions) = continue_assignments {
                    for instruction in instructions {
                        validate_structured_instruction(
                            instruction,
                            visible_values,
                            forced_assignment,
                            true,
                            budget,
                        )?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_structured_instruction(
    instruction: &IrInstruction,
    visible_values: &mut BTreeSet<ValueId>,
    forced_assignment: Option<ValueId>,
    assignment: bool,
    budget: &mut Budget,
) -> Result<(), StructureError> {
    for value in instruction_uses(instruction) {
        StructureError::from_budget(budget)?;
        validate_structured_value(value, visible_values)?;
    }
    if let Some(destination) = instruction_destination(instruction) {
        if assignment || forced_assignment == Some(destination) {
            return validate_structured_value(destination, visible_values);
        }
        if !visible_values.insert(destination) {
            return Err(StructureError::new(
                "structured rendering redeclares an in-scope value",
            ));
        }
    }
    Ok(())
}

fn validate_structured_value(
    value: ValueId,
    visible_values: &BTreeSet<ValueId>,
) -> Result<(), StructureError> {
    if visible_values.contains(&value) {
        return Ok(());
    }
    Err(StructureError::new(
        "structured rendering would use a value outside its lexical scope",
    ))
}

fn post_dominators(
    successors: &[Vec<usize>],
    budget: &mut Budget,
) -> Result<Vec<Option<usize>>, StructureError> {
    let node_count: usize = successors.len();
    charge_shared_graph_analysis(node_count, budget)?;
    let exit: u32 = u32::try_from(node_count)
        .map_err(|_| StructureError::new("control-flow graph exceeds post-dominator capacity"))?;
    let mut converted: Vec<Vec<u32>> = Vec::with_capacity(node_count);
    for targets in successors {
        StructureError::from_budget(budget)?;
        let mut values: Vec<u32> = Vec::with_capacity(targets.len());
        for target in targets {
            StructureError::from_budget(budget)?;
            let value: u32 = u32::try_from(*target).map_err(|_| {
                StructureError::new("control-flow index exceeds post-dominator capacity")
            })?;
            values.push(value);
        }
        converted.push(values);
    }
    StructureError::from_budget(budget)?;
    let raw: Vec<Option<u32>> = immediate_post_dominators(node_count, |node, visit| {
        let index: Option<usize> = usize::try_from(node).ok();
        match index.and_then(|value: usize| converted.get(value)) {
            Some(targets) if targets.is_empty() => visit(exit),
            Some(targets) => {
                for target in targets {
                    visit(*target);
                }
            }
            None => {}
        }
    });
    let mut post_dominators: Vec<Option<usize>> = Vec::with_capacity(raw.len());
    for candidate in raw {
        StructureError::from_budget(budget)?;
        let converted_candidate: Option<usize> =
            match candidate {
                Some(value) if value == exit => None,
                Some(value) => Some(usize::try_from(value).map_err(|_| {
                    StructureError::new("post-dominator index cannot be represented")
                })?),
                None => None,
            };
        post_dominators.push(converted_candidate);
    }
    Ok(post_dominators)
}

fn charge_shared_graph_analysis(
    node_count: usize,
    budget: &mut Budget,
) -> Result<(), StructureError> {
    let count: u64 = u64::try_from(node_count)
        .map_err(|_| StructureError::new("control-flow graph size cannot be budgeted"))?;
    let square: u64 = count
        .checked_mul(count)
        .ok_or_else(|| StructureError::new("control-flow graph budget cost overflowed"))?;
    let cost: u64 = square
        .checked_mul(count)
        .ok_or_else(|| StructureError::new("control-flow graph budget cost overflowed"))?;
    budget
        .spend(cost)
        .map_err(|error| StructureError::new(format!("analysis budget exhausted: {error}")))
}

fn reject_irreducible(
    successors: &[Vec<usize>],
    predecessors: &[Vec<usize>],
    budget: &mut Budget,
) -> Result<(), StructureError> {
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    let mut finish: Vec<usize> = Vec::with_capacity(successors.len());
    for start in 0..successors.len() {
        StructureError::from_budget(budget)?;
        if visited.contains(&start) {
            continue;
        }
        let mut stack: Vec<(usize, bool)> = vec![(start, false)];
        while let Some((node, complete)) = stack.pop() {
            StructureError::from_budget(budget)?;
            if complete {
                finish.push(node);
                continue;
            }
            if !visited.insert(node) {
                continue;
            }
            stack.push((node, true));
            let targets: &Vec<usize> = successors
                .get(node)
                .ok_or_else(|| StructureError::new("successor index is out of range"))?;
            for target in targets.iter().rev() {
                StructureError::from_budget(budget)?;
                if !visited.contains(target) {
                    stack.push((*target, false));
                }
            }
        }
    }
    let mut assigned: BTreeSet<usize> = BTreeSet::new();
    for start in finish.iter().rev() {
        StructureError::from_budget(budget)?;
        if assigned.contains(start) {
            continue;
        }
        let mut component: BTreeSet<usize> = BTreeSet::new();
        let mut stack: Vec<usize> = vec![*start];
        while let Some(node) = stack.pop() {
            StructureError::from_budget(budget)?;
            if !assigned.insert(node) {
                continue;
            }
            component.insert(node);
            let entries: &Vec<usize> = predecessors
                .get(node)
                .ok_or_else(|| StructureError::new("predecessor index is out of range"))?;
            for predecessor in entries.iter().rev() {
                StructureError::from_budget(budget)?;
                if !assigned.contains(predecessor) {
                    stack.push(*predecessor);
                }
            }
        }
        let has_self_edge: bool = component.iter().any(|node: &usize| {
            successors
                .get(*node)
                .is_some_and(|targets: &Vec<usize>| targets.contains(node))
        });
        if component.len() == 1 && !has_self_edge {
            continue;
        }
        let mut entries: BTreeSet<usize> = BTreeSet::new();
        for node in &component {
            StructureError::from_budget(budget)?;
            let incoming: &Vec<usize> = predecessors
                .get(*node)
                .ok_or_else(|| StructureError::new("predecessor index is out of range"))?;
            for predecessor in incoming {
                StructureError::from_budget(budget)?;
                if !component.contains(predecessor) {
                    entries.insert(*node);
                }
            }
        }
        if entries.len() > 1 {
            return Err(StructureError::new("irreducible control flow"));
        }
    }
    Ok(())
}

fn detect_loops(
    blocks: &[BasicBlock],
    indices: &BTreeMap<BlockId, usize>,
    successors: &[Vec<usize>],
    predecessors: &[Vec<usize>],
    dominators: &[BTreeSet<usize>],
    budget: &mut Budget,
) -> Result<BTreeMap<usize, LoopInfo>, StructureError> {
    let mut latches_by_header: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for (from, targets) in successors.iter().enumerate() {
        StructureError::from_budget(budget)?;
        let dominators_of_from: &BTreeSet<usize> = dominators
            .get(from)
            .ok_or_else(|| StructureError::new("dominator set is absent"))?;
        for target in targets {
            StructureError::from_budget(budget)?;
            if dominators_of_from.contains(target) {
                latches_by_header.entry(*target).or_default().insert(from);
            }
        }
    }
    let mut loops: BTreeMap<usize, LoopInfo> = BTreeMap::new();
    for (header, latches) in latches_by_header {
        StructureError::from_budget(budget)?;
        let body: BTreeSet<usize> = natural_loop_body(header, &latches, predecessors, budget)?;
        validate_loop_entries(header, &body, predecessors, budget)?;
        let shape: LoopShape =
            classify_loop(blocks, indices, successors, &body, header, &latches, budget)?;
        loops.insert(
            header,
            LoopInfo {
                header,
                body,
                shape,
            },
        );
    }
    let values: Vec<&LoopInfo> = loops.values().collect();
    for (index, left) in values.iter().enumerate() {
        StructureError::from_budget(budget)?;
        for right in values.iter().skip(index.saturating_add(1)) {
            StructureError::from_budget(budget)?;
            if !left.body.is_disjoint(&right.body)
                && !left.body.is_subset(&right.body)
                && !right.body.is_subset(&left.body)
            {
                return Err(StructureError::new(
                    "overlapping loop regions cannot be structured",
                ));
            }
        }
    }
    Ok(loops)
}

fn natural_loop_body(
    header: usize,
    latches: &BTreeSet<usize>,
    predecessors: &[Vec<usize>],
    budget: &mut Budget,
) -> Result<BTreeSet<usize>, StructureError> {
    let mut body: BTreeSet<usize> = BTreeSet::from([header]);
    let mut pending: Vec<usize> = Vec::new();
    for latch in latches {
        StructureError::from_budget(budget)?;
        if body.insert(*latch) {
            pending.push(*latch);
        }
    }
    while let Some(node) = pending.pop() {
        StructureError::from_budget(budget)?;
        let entries: &Vec<usize> = predecessors
            .get(node)
            .ok_or_else(|| StructureError::new("predecessor index is out of range"))?;
        for predecessor in entries {
            StructureError::from_budget(budget)?;
            if body.insert(*predecessor) {
                pending.push(*predecessor);
            }
        }
    }
    Ok(body)
}

fn validate_loop_entries(
    header: usize,
    body: &BTreeSet<usize>,
    predecessors: &[Vec<usize>],
    budget: &mut Budget,
) -> Result<(), StructureError> {
    for node in body {
        StructureError::from_budget(budget)?;
        let entries: &Vec<usize> = predecessors
            .get(*node)
            .ok_or_else(|| StructureError::new("predecessor index is out of range"))?;
        for predecessor in entries {
            StructureError::from_budget(budget)?;
            if !body.contains(predecessor) && *node != header {
                return Err(StructureError::new("irreducible control flow"));
            }
        }
    }
    Ok(())
}

fn classify_loop(
    blocks: &[BasicBlock],
    indices: &BTreeMap<BlockId, usize>,
    successors: &[Vec<usize>],
    body: &BTreeSet<usize>,
    header: usize,
    latches: &BTreeSet<usize>,
    budget: &mut Budget,
) -> Result<LoopShape, StructureError> {
    let exits: BTreeSet<usize> = loop_exits(successors, body, budget)?;
    if exits.len() != 1 {
        return Err(StructureError::new("loop has no unique follow block"));
    }
    let exit: usize = exits
        .iter()
        .next()
        .copied()
        .ok_or_else(|| StructureError::new("loop follow block is absent"))?;
    let header_block: &BasicBlock = blocks
        .get(header)
        .ok_or_else(|| StructureError::new("loop header is absent"))?;
    match &header_block.terminator {
        Terminator::CondBr {
            condition,
            when_true,
            when_false,
        } => {
            let true_target: usize = block_index(indices, *when_true)?;
            let false_target: usize = block_index(indices, *when_false)?;
            let true_inside: bool = body.contains(&true_target);
            let false_inside: bool = body.contains(&false_target);
            let (body_entry, continues_when_true): (usize, bool) = match (true_inside, false_inside)
            {
                (true, false) if false_target == exit => (true_target, true),
                (false, true) if true_target == exit => (false_target, false),
                _ => {
                    return Err(StructureError::new(
                        "loop header is not a pre-test predicate",
                    ));
                }
            };
            Ok(LoopShape::While {
                body_entry,
                exit,
                condition: *condition,
                continues_when_true,
            })
        }
        Terminator::Br(body_entry_id) => {
            let body_entry: usize = block_index(indices, *body_entry_id)?;
            if !body.contains(&body_entry) {
                return Err(StructureError::new("loop header jumps outside its body"));
            }
            if latches.len() != 1 {
                return Err(StructureError::new("do-while loop has multiple latches"));
            }
            let latch: usize = latches
                .iter()
                .next()
                .copied()
                .ok_or_else(|| StructureError::new("do-while latch is absent"))?;
            let latch_block: &BasicBlock = blocks
                .get(latch)
                .ok_or_else(|| StructureError::new("do-while latch is absent"))?;
            match &latch_block.terminator {
                Terminator::CondBr {
                    condition,
                    when_true,
                    when_false,
                } => {
                    let true_target: usize = block_index(indices, *when_true)?;
                    let false_target: usize = block_index(indices, *when_false)?;
                    let continues_when_true: bool =
                        match (true_target == header, false_target == header) {
                            (true, false) if false_target == exit => true,
                            (false, true) if true_target == exit => false,
                            _ => {
                                return Err(StructureError::new(
                                    "do-while latch does not branch to its header and follow",
                                ));
                            }
                        };
                    Ok(LoopShape::DoWhile {
                        body_entry,
                        latch,
                        exit,
                        condition: *condition,
                        continues_when_true,
                    })
                }
                Terminator::Br(_) | Terminator::Ret(_) => {
                    Err(StructureError::new("loop has no predicate latch"))
                }
            }
        }
        Terminator::Ret(_) => Err(StructureError::new("loop header returns")),
    }
}

fn loop_exits(
    successors: &[Vec<usize>],
    body: &BTreeSet<usize>,
    budget: &mut Budget,
) -> Result<BTreeSet<usize>, StructureError> {
    let mut exits: BTreeSet<usize> = BTreeSet::new();
    for node in body {
        StructureError::from_budget(budget)?;
        let targets: &Vec<usize> = successors
            .get(*node)
            .ok_or_else(|| StructureError::new("successor index is out of range"))?;
        for target in targets {
            StructureError::from_budget(budget)?;
            if !body.contains(target) {
                exits.insert(*target);
            }
        }
    }
    Ok(exits)
}

fn block_index(indices: &BTreeMap<BlockId, usize>, id: BlockId) -> Result<usize, StructureError> {
    indices
        .get(&id)
        .copied()
        .ok_or_else(|| StructureError::new("loop references a missing block"))
}

fn build_region(
    cfg: &Cfg,
    start: usize,
    stop: &BTreeSet<usize>,
    active_loop: Option<usize>,
    visited: &mut BTreeSet<usize>,
    depth: usize,
    budget: &mut Budget,
) -> Result<(Vec<StructuredNode>, RegionExit), StructureError> {
    if depth >= MAX_STRUCTURE_DEPTH {
        return Err(StructureError::new("structure nesting exceeds depth cap"));
    }
    let mut nodes: Vec<StructuredNode> = Vec::new();
    let mut current: usize = start;
    loop {
        StructureError::from_budget(budget)?;
        if stop.contains(&current) {
            return Ok((nodes, RegionExit::Stop));
        }
        let active: Option<&LoopInfo> = match active_loop {
            Some(header) => Some(
                cfg.loops
                    .get(&header)
                    .ok_or_else(|| StructureError::new("active loop is absent"))?,
            ),
            None => None,
        };
        if let Some(loop_info) = active {
            if current == loop_info.header {
                return Ok((nodes, RegionExit::Continue));
            }
            if loop_exit(&loop_info.shape) == current {
                return Ok((nodes, RegionExit::Break));
            }
            if let LoopShape::DoWhile { latch, .. } = loop_info.shape
                && current == latch
            {
                if !visited.insert(current) {
                    return Err(StructureError::new("loop latch was reached more than once"));
                }
                let block: &BasicBlock = cfg
                    .blocks
                    .get(current)
                    .ok_or_else(|| StructureError::new("loop latch is absent"))?;
                if !block.instructions.is_empty() {
                    nodes.push(StructuredNode::Instructions(block.instructions.clone()));
                }
                return Ok((nodes, RegionExit::Continue));
            }
            if !loop_info.body.contains(&current) {
                return Err(StructureError::new(
                    "control flow leaves the active loop body",
                ));
            }
        }
        if cfg.loops.contains_key(&current) && active_loop != Some(current) {
            let (loop_node, follow): (StructuredNode, usize) =
                build_loop(cfg, current, visited, depth.saturating_add(1), budget)?;
            nodes.push(loop_node);
            current = follow;
            continue;
        }
        if !visited.insert(current) {
            return Err(StructureError::new(
                "control-flow cycle cannot be structured",
            ));
        }
        let block: &BasicBlock = cfg
            .blocks
            .get(current)
            .ok_or_else(|| StructureError::new("control-flow block is absent"))?;
        if !block.instructions.is_empty() {
            nodes.push(StructuredNode::Instructions(block.instructions.clone()));
        }
        match &block.terminator {
            Terminator::Ret(value) => {
                nodes.push(StructuredNode::Return(*value));
                return Ok((nodes, RegionExit::Return));
            }
            Terminator::Br(target) => {
                let next: usize = block_index(&cfg.indices, *target)?;
                if stop.contains(&next) {
                    return Ok((nodes, RegionExit::Stop));
                }
                if active_loop.is_some_and(|header: usize| header == next) {
                    return Ok((nodes, RegionExit::Continue));
                }
                if active.is_some_and(|loop_info: &LoopInfo| loop_exit(&loop_info.shape) == next) {
                    return Ok((nodes, RegionExit::Break));
                }
                current = next;
            }
            Terminator::CondBr {
                condition,
                when_true,
                when_false,
            } => {
                let true_start: usize = block_index(&cfg.indices, *when_true)?;
                let false_start: usize = block_index(&cfg.indices, *when_false)?;
                let join: Option<usize> = cfg.post_dominators.get(current).copied().flatten();
                let mut branch_stop: BTreeSet<usize> = stop.clone();
                if let Some(target) = join {
                    branch_stop.insert(target);
                }
                let (mut true_nodes, true_exit): (Vec<StructuredNode>, RegionExit) = build_region(
                    cfg,
                    true_start,
                    &branch_stop,
                    active_loop,
                    visited,
                    depth.saturating_add(1),
                    budget,
                )?;
                append_region_exit(&mut true_nodes, true_exit);
                let (mut false_nodes, false_exit): (Vec<StructuredNode>, RegionExit) =
                    build_region(
                        cfg,
                        false_start,
                        &branch_stop,
                        active_loop,
                        visited,
                        depth.saturating_add(1),
                        budget,
                    )?;
                append_region_exit(&mut false_nodes, false_exit);
                nodes.push(StructuredNode::If {
                    condition: *condition,
                    when_true: true_nodes,
                    when_false: false_nodes,
                });
                match join {
                    Some(target) if !both_terminal(true_exit, false_exit) => current = target,
                    Some(_) => return Ok((nodes, RegionExit::Complete)),
                    None if both_terminal(true_exit, false_exit) => {
                        return Ok((nodes, RegionExit::Complete));
                    }
                    None => {
                        return Err(StructureError::new(
                            "conditional branch has no safe post-dominator join",
                        ));
                    }
                }
            }
        }
    }
}

fn build_loop(
    cfg: &Cfg,
    header: usize,
    visited: &mut BTreeSet<usize>,
    depth: usize,
    budget: &mut Budget,
) -> Result<(StructuredNode, usize), StructureError> {
    let loop_info: &LoopInfo = cfg
        .loops
        .get(&header)
        .ok_or_else(|| StructureError::new("loop header is absent"))?;
    if !visited.insert(header) {
        return Err(StructureError::new(
            "loop header was reached more than once",
        ));
    }
    let header_block: &BasicBlock = cfg
        .blocks
        .get(header)
        .ok_or_else(|| StructureError::new("loop header is absent"))?;
    match &loop_info.shape {
        LoopShape::While {
            body_entry,
            exit,
            condition,
            continues_when_true,
        } => {
            let stop: BTreeSet<usize> = BTreeSet::new();
            let (mut body, exit_kind): (Vec<StructuredNode>, RegionExit) = build_region(
                cfg,
                *body_entry,
                &stop,
                Some(header),
                visited,
                depth,
                budget,
            )?;
            let repeats: bool = match exit_kind {
                RegionExit::Continue => true,
                RegionExit::Break => {
                    body.push(StructuredNode::Break);
                    false
                }
                RegionExit::Return | RegionExit::Complete => false,
                RegionExit::Stop => {
                    return Err(StructureError::new("loop body stopped outside its region"));
                }
            };
            if repeats {
                body.push(StructuredNode::Assignments(
                    header_block.instructions.clone(),
                ));
            }
            Ok((
                StructuredNode::While {
                    condition: *condition,
                    continues_when_true: *continues_when_true,
                    header: header_block.instructions.clone(),
                    body,
                },
                *exit,
            ))
        }
        LoopShape::DoWhile {
            body_entry,
            latch: _,
            exit,
            condition,
            continues_when_true,
        } => {
            let stop: BTreeSet<usize> = BTreeSet::new();
            let (mut body, exit_kind): (Vec<StructuredNode>, RegionExit) = build_region(
                cfg,
                *body_entry,
                &stop,
                Some(header),
                visited,
                depth,
                budget,
            )?;
            body.insert(
                0,
                StructuredNode::Instructions(header_block.instructions.clone()),
            );
            match exit_kind {
                RegionExit::Continue => {}
                RegionExit::Break => body.push(StructuredNode::Break),
                RegionExit::Return | RegionExit::Complete => {
                    return Err(StructureError::new(
                        "do-while body does not reach its predicate latch",
                    ));
                }
                RegionExit::Stop => {
                    return Err(StructureError::new("loop body stopped outside its region"));
                }
            }
            Ok((
                StructuredNode::DoWhile {
                    condition: *condition,
                    continues_when_true: *continues_when_true,
                    body,
                },
                *exit,
            ))
        }
    }
}

const fn loop_exit(shape: &LoopShape) -> usize {
    match shape {
        LoopShape::While { exit, .. } | LoopShape::DoWhile { exit, .. } => *exit,
    }
}

fn append_region_exit(nodes: &mut Vec<StructuredNode>, exit: RegionExit) {
    match exit {
        RegionExit::Continue => nodes.push(StructuredNode::Continue),
        RegionExit::Break => nodes.push(StructuredNode::Break),
        RegionExit::Stop | RegionExit::Return | RegionExit::Complete => {}
    }
}

const fn both_terminal(left: RegionExit, right: RegionExit) -> bool {
    !matches!(left, RegionExit::Stop) && !matches!(right, RegionExit::Stop)
}
