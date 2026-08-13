use std::collections::{BTreeMap, BTreeSet};

use disrobe_cfg::{Flow, FlowGraph};
use serde::Serialize;

use crate::cfg::{BlockKind, NirBlock, basic_blocks};
use crate::reducible::{
    HirDecline, SplitBudget, SplitRefusal, StructureFailure, split_irreducible,
};
use crate::types::{
    BinaryOp, NirClass, NirFunction, NirInstr, NirModule, NirOp, NirSymbol, SourceLang, SourceRef,
    ValueOp,
};

const MAX_REGION_DEPTH: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HirExpr {
    Const {
        text: String,
    },
    Var {
        name: String,
    },
    Mem {
        cell: String,
    },
    Unary {
        op: BinaryOp,
        operand: Box<Self>,
    },
    Binary {
        op: BinaryOp,
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    Call {
        target: Option<String>,
        args: Vec<Self>,
    },
    Unknown {
        text: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "stmt", rename_all = "kebab-case")]
pub enum HirInstrStmt {
    Assign {
        dst: HirExpr,
        value: HirExpr,
    },
    Store {
        cell: HirExpr,
        value: HirExpr,
    },
    Call {
        target: Option<String>,
        args: Vec<HirExpr>,
    },
    Effect {
        expr: HirExpr,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HirLeafStmt {
    pub instr: NirInstr,
    pub stmt: HirInstrStmt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HirDispatchCase {
    pub block_start: u64,
    pub stmts: Vec<HirLeafStmt>,
    pub successors: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "node", rename_all = "kebab-case")]
pub enum HirStmt {
    Seq {
        body: Vec<Self>,
    },
    Leaf {
        block_start: u64,
        stmts: Vec<HirLeafStmt>,
    },
    If {
        cond: HirCond,
        then_branch: Box<Self>,
        else_branch: Box<Self>,
    },
    Loop {
        label: u64,
        body: Box<Self>,
    },
    Break {
        label: u64,
    },
    Continue {
        label: u64,
    },
    Return {
        value: Option<HirExpr>,
    },
    Dispatch {
        entry: u64,
        cases: Vec<HirDispatchCase>,
    },
    GotoGraph {
        entry: u64,
        blocks: Vec<HirDispatchCase>,
    },
    Empty,
}

impl HirExpr {
    fn unlink_children(&mut self, pending: &mut Vec<Self>) {
        match self {
            Self::Unary { operand, .. } => {
                let operand: Self = std::mem::replace(
                    operand.as_mut(),
                    Self::Unknown {
                        text: String::new(),
                    },
                );
                pending.push(operand);
            }
            Self::Binary { lhs, rhs, .. } => {
                let lhs: Self = std::mem::replace(
                    lhs.as_mut(),
                    Self::Unknown {
                        text: String::new(),
                    },
                );
                let rhs: Self = std::mem::replace(
                    rhs.as_mut(),
                    Self::Unknown {
                        text: String::new(),
                    },
                );
                pending.push(lhs);
                pending.push(rhs);
            }
            Self::Call { args, .. } => pending.extend(std::mem::take(args)),
            Self::Const { .. } | Self::Var { .. } | Self::Mem { .. } | Self::Unknown { .. } => {}
        }
    }
}

impl Drop for HirExpr {
    fn drop(&mut self) {
        let mut pending: Vec<Self> = Vec::new();
        self.unlink_children(&mut pending);
        while let Some(mut expression) = pending.pop() {
            expression.unlink_children(&mut pending);
        }
    }
}

impl HirStmt {
    fn unlink_children(&mut self, pending: &mut Vec<Self>) {
        match self {
            Self::Seq { body } => pending.extend(std::mem::take(body)),
            Self::If {
                then_branch,
                else_branch,
                ..
            } => {
                let then_branch: Self = std::mem::replace(then_branch.as_mut(), Self::Empty);
                let else_branch: Self = std::mem::replace(else_branch.as_mut(), Self::Empty);
                pending.push(then_branch);
                pending.push(else_branch);
            }
            Self::Loop { body, .. } => {
                let body: Self = std::mem::replace(body.as_mut(), Self::Empty);
                pending.push(body);
            }
            Self::Leaf { .. }
            | Self::Break { .. }
            | Self::Continue { .. }
            | Self::Return { .. }
            | Self::Dispatch { .. }
            | Self::GotoGraph { .. }
            | Self::Empty => {}
        }
    }
}

impl Drop for HirStmt {
    fn drop(&mut self) {
        let mut pending: Vec<Self> = Vec::new();
        self.unlink_children(&mut pending);
        while let Some(mut statement) = pending.pop() {
            statement.unlink_children(&mut pending);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HirCond {
    pub at: u64,
    pub mnemonic: String,
    pub operands: Vec<String>,
    pub taken_target: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HirFunction {
    pub name: String,
    pub address: u64,
    pub end: u64,
    pub is_export: bool,
    pub body: HirStmt,
    pub structured: bool,
    pub decline: Option<HirDecline>,
    pub source: SourceRef,
}

impl HirFunction {
    #[must_use]
    pub fn block_starts(&self) -> BTreeSet<u64> {
        let mut out: BTreeSet<u64> = BTreeSet::new();
        collect_block_starts(&self.body, &mut out);
        out
    }

    #[must_use]
    pub fn instruction_addresses(&self) -> BTreeSet<u64> {
        let mut out: BTreeSet<u64> = BTreeSet::new();
        collect_instruction_addresses(&self.body, &mut out);
        out
    }

    #[must_use]
    pub fn to_nir_function(&self) -> NirFunction {
        let mut instructions: Vec<NirInstr> = Vec::new();
        collect_instructions(&self.body, &mut instructions);
        instructions.sort_by_key(|i: &NirInstr| i.address);
        NirFunction {
            name: self.name.clone(),
            address: self.address,
            end: self.end,
            is_export: self.is_export,
            instructions,
            source: self.source.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HirModule {
    pub source_hash: [u8; 32],
    pub lang: SourceLang,
    pub functions: Vec<HirFunction>,
    pub symbols: Vec<NirSymbol>,
}

impl HirModule {
    #[must_use]
    pub fn to_nir_module(&self) -> NirModule {
        NirModule {
            source_hash: self.source_hash,
            lang: self.lang,
            functions: self
                .functions
                .iter()
                .map(HirFunction::to_nir_function)
                .collect(),
            symbols: self.symbols.clone(),
        }
    }

    #[must_use]
    pub fn fully_structured(&self) -> bool {
        self.functions.iter().all(|f: &HirFunction| f.structured)
    }
}

#[must_use]
pub fn structurize_module(module: &NirModule) -> HirModule {
    HirModule {
        source_hash: module.source_hash,
        lang: module.lang,
        functions: module.functions.iter().map(structurize_function).collect(),
        symbols: module.symbols.clone(),
    }
}

#[must_use]
pub fn structurize_function(function: &NirFunction) -> HirFunction {
    structurize_function_with_budget(function, SplitBudget::TightForGraph)
}

#[must_use]
pub fn structurize_function_with_budget(
    function: &NirFunction,
    budget: SplitBudget,
) -> HirFunction {
    let blocks: Vec<NirBlock> = basic_blocks(function);
    let lang: SourceLang = function.source.lang;
    if blocks.is_empty() {
        return HirFunction {
            name: function.name.clone(),
            address: function.address,
            end: function.end,
            is_export: function.is_export,
            body: HirStmt::Empty,
            structured: true,
            decline: None,
            source: function.source.clone(),
        };
    }
    let entry: u64 = blocks[0].start;
    let (body, structured, decline): (HirStmt, bool, Option<HirDecline>) =
        match structure_blocks(&blocks, entry, lang) {
            Ok(structured_body) => (structured_body, true, None),
            Err(failure) => refine_by_splitting(function, &blocks, entry, lang, budget, failure),
        };
    HirFunction {
        name: function.name.clone(),
        address: function.address,
        end: function.end,
        is_export: function.is_export,
        body,
        structured,
        decline,
        source: function.source.clone(),
    }
}

fn structure_blocks(
    blocks: &[NirBlock],
    entry: u64,
    lang: SourceLang,
) -> Result<HirStmt, StructureFailure> {
    let index: BlockIndex<'_> = BlockIndex::build(blocks);
    let mut structurer: Structurer<'_> = Structurer::new(&index, lang);
    let body: HirStmt = structurer.region(entry, &Bounds::default(), 0);
    let reachable: BTreeSet<u64> = index.reachable_from(entry);
    if let Some(failure) = structurer.failure {
        return Err(failure);
    }
    if structurer.placed != reachable.len() {
        return Err(StructureFailure::IncompleteCover);
    }
    Ok(append_unreachable_blocks(body, &index, &reachable, lang))
}

fn refine_by_splitting(
    function: &NirFunction,
    blocks: &[NirBlock],
    entry: u64,
    lang: SourceLang,
    budget: SplitBudget,
    failure: StructureFailure,
) -> (HirStmt, bool, Option<HirDecline>) {
    let (refusal, after_split): (SplitRefusal, Option<StructureFailure>) =
        match split_irreducible(blocks, entry, budget) {
            Ok(split) => match structure_blocks(&split, entry, lang) {
                Ok(body) => return (body, true, None),
                Err(still) => (SplitRefusal::StillUnstructured, Some(still)),
            },
            Err(reason) => (reason, None),
        };
    let index: BlockIndex<'_> = BlockIndex::build(blocks);
    (
        fallback_from_index(function, &index),
        false,
        Some(HirDecline {
            failure,
            refusal,
            after_split,
        }),
    )
}

pub(crate) fn complete_fallback_body(function: &NirFunction) -> HirStmt {
    let blocks: Vec<NirBlock> = basic_blocks(function);
    if blocks.is_empty() {
        return HirStmt::Empty;
    }
    let index: BlockIndex<'_> = BlockIndex::build(&blocks);
    fallback_from_index(function, &index)
}

fn fallback_from_index(function: &NirFunction, index: &BlockIndex<'_>) -> HirStmt {
    if uses_goto_fallback(function) {
        goto_graph_all(index, function.source.lang)
    } else {
        dispatch_all(index, function.source.lang)
    }
}

struct BlockIndex<'a> {
    blocks: BTreeMap<u64, &'a NirBlock>,
    order: Vec<u64>,
    predecessors: BTreeMap<u64, Vec<u64>>,
    flow: Option<FlowGraph<u64>>,
    natural_loops: BTreeMap<u64, BTreeSet<u64>>,
}

impl<'a> BlockIndex<'a> {
    fn build(blocks: &'a [NirBlock]) -> Self {
        let mut by_start: BTreeMap<u64, &'a NirBlock> = BTreeMap::new();
        let mut order: Vec<u64> = Vec::with_capacity(blocks.len());
        for block in blocks {
            by_start.insert(block.start, block);
            order.push(block.start);
        }
        order.sort_unstable();
        let mut predecessors: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        for block in blocks {
            for succ in &block.successors {
                if by_start.contains_key(succ) {
                    predecessors.entry(*succ).or_default().push(block.start);
                }
            }
        }
        for preds in predecessors.values_mut() {
            preds.sort_unstable();
            preds.dedup();
        }
        let flow: Option<FlowGraph<u64>> = order.first().copied().and_then(|entry: u64| {
            FlowGraph::build(
                order.iter().copied(),
                entry,
                |start: u64, emit: &mut dyn FnMut(Flow<u64>)| {
                    let targets: Vec<u64> =
                        by_start
                            .get(&start)
                            .map_or_else(Vec::new, |block: &&NirBlock| {
                                block
                                    .successors
                                    .iter()
                                    .copied()
                                    .filter(|successor: &u64| by_start.contains_key(successor))
                                    .collect()
                            });
                    if targets.is_empty() {
                        emit(Flow::Exit);
                    }
                    for target in targets {
                        emit(Flow::To(target));
                    }
                },
            )
            .ok()
        });
        let mut index: Self = Self {
            blocks: by_start,
            order,
            predecessors,
            flow,
            natural_loops: BTreeMap::new(),
        };
        let headers: Vec<u64> = index
            .order
            .iter()
            .copied()
            .filter(|start: &u64| index.has_dominating_predecessor(*start))
            .collect();
        for header in headers {
            let nodes: BTreeSet<u64> = index.compute_natural_loop(header);
            index.natural_loops.insert(header, nodes);
        }
        index
    }

    fn block(&self, start: u64) -> Option<&'a NirBlock> {
        self.blocks.get(&start).copied()
    }

    fn predecessors(&self, start: u64) -> &[u64] {
        self.predecessors
            .get(&start)
            .map_or(&[][..], |v: &Vec<u64>| v.as_slice())
    }

    fn is_loop_header(&self, start: u64) -> bool {
        self.natural_loops.contains_key(&start)
    }

    fn natural_loop(&self, start: u64) -> Option<&BTreeSet<u64>> {
        self.natural_loops.get(&start)
    }

    fn has_dominating_predecessor(&self, start: u64) -> bool {
        self.predecessors(start)
            .iter()
            .any(|predecessor: &u64| self.dominates(start, *predecessor))
    }

    fn dominates(&self, candidate: u64, node: u64) -> bool {
        self.flow
            .as_ref()
            .is_some_and(|flow: &FlowGraph<u64>| flow.dominates(candidate, node))
    }

    fn immediate_post_dominator(&self, start: u64) -> Option<u64> {
        self.flow.as_ref()?.immediate_post_dominator(start).node()
    }

    fn compute_natural_loop(&self, header: u64) -> BTreeSet<u64> {
        let Some(flow): Option<&FlowGraph<u64>> = self.flow.as_ref() else {
            return BTreeSet::from([header]);
        };
        let latches: Vec<u64> = self
            .predecessors(header)
            .iter()
            .copied()
            .filter(|predecessor: &u64| flow.dominates(header, *predecessor))
            .collect();
        flow.natural_loop_body(header, &latches)
    }

    fn reachable_from(&self, entry: u64) -> BTreeSet<u64> {
        let mut seen: BTreeSet<u64> = BTreeSet::new();
        let mut stack: Vec<u64> = vec![entry];
        while let Some(current) = stack.pop() {
            if !seen.insert(current) {
                continue;
            }
            let Some(block): Option<&'a NirBlock> = self.block(current) else {
                continue;
            };
            for succ in &block.successors {
                if self.blocks.contains_key(succ) {
                    stack.push(*succ);
                }
            }
        }
        seen
    }
}

#[derive(Default, Clone)]
struct Bounds {
    follows: Vec<u64>,
    loop_headers: Vec<u64>,
    loop_follows: Vec<(u64, u64)>,
}

impl Bounds {
    fn is_follow(&self, target: u64) -> bool {
        self.follows.contains(&target)
    }

    fn with_follow(&self, target: u64) -> Self {
        let mut next: Self = self.clone();
        if !next.follows.contains(&target) {
            next.follows.push(target);
        }
        next
    }

    fn enter_loop(&self, header: u64, follow: Option<u64>) -> Self {
        let mut next: Self = self.clone();
        next.loop_headers.push(header);
        if let Some(follow_block) = follow {
            next.loop_follows.push((follow_block, header));
            if !next.follows.contains(&follow_block) {
                next.follows.push(follow_block);
            }
        }
        next
    }

    fn loop_label_for(&self, target: u64) -> Option<u64> {
        self.loop_headers
            .iter()
            .rev()
            .find(|h: &&u64| **h == target)
            .copied()
    }

    fn loop_follow_label(&self, target: u64) -> Option<u64> {
        self.loop_follows
            .iter()
            .rev()
            .find(|(follow, _label): &&(u64, u64)| *follow == target)
            .map(|(_follow, label): &(u64, u64)| *label)
    }
}

struct Structurer<'a> {
    index: &'a BlockIndex<'a>,
    lang: SourceLang,
    visited: BTreeSet<u64>,
    failure: Option<StructureFailure>,
    placed: usize,
}

impl<'a> Structurer<'a> {
    const fn new(index: &'a BlockIndex<'a>, lang: SourceLang) -> Self {
        Self {
            index,
            lang,
            visited: BTreeSet::new(),
            failure: None,
            placed: 0,
        }
    }

    const fn fail(&mut self, failure: StructureFailure) {
        if self.failure.is_none() {
            self.failure = Some(failure);
        }
    }

    fn region(&mut self, start: u64, bounds: &Bounds, depth: usize) -> HirStmt {
        if depth >= MAX_REGION_DEPTH {
            self.fail(StructureFailure::RegionDepthExceeded);
            return HirStmt::Empty;
        }
        if let Some(label) = bounds.loop_follow_label(start) {
            return HirStmt::Break { label };
        }
        if bounds.is_follow(start) {
            return HirStmt::Empty;
        }
        if let Some(label) = bounds.loop_label_for(start) {
            return HirStmt::Continue { label };
        }
        let Some(block): Option<&'a NirBlock> = self.index.block(start) else {
            self.fail(StructureFailure::MissingBlock);
            return HirStmt::Empty;
        };
        if !self.visited.insert(start) {
            self.fail(StructureFailure::BlockReachedTwice);
            return HirStmt::Empty;
        }
        self.placed += 1;

        if self.index.is_loop_header(start) {
            return self.loop_region(block, bounds, depth);
        }
        self.acyclic_region(block, bounds, depth)
    }

    fn loop_region(&mut self, block: &'a NirBlock, bounds: &Bounds, depth: usize) -> HirStmt {
        let header: u64 = block.start;
        let follow: Option<u64> = match loop_follow(self.index, header) {
            LoopFollow::None => None,
            LoopFollow::Single(target) => Some(target),
            LoopFollow::Multiple => {
                self.fail(StructureFailure::LoopHasManyExits);
                return HirStmt::Empty;
            }
        };
        let inner_bounds: Bounds = bounds.enter_loop(header, follow);
        let body: HirStmt = self.acyclic_region(block, &inner_bounds, depth + 1);
        let loop_stmt: HirStmt = HirStmt::Loop {
            label: header,
            body: Box::new(body),
        };
        match follow {
            Some(follow_block) if !bounds.is_follow(follow_block) => {
                let after: HirStmt = self.region(follow_block, bounds, depth + 1);
                sequence(vec![loop_stmt, after])
            }
            _ => loop_stmt,
        }
    }

    fn acyclic_region(&mut self, block: &'a NirBlock, bounds: &Bounds, depth: usize) -> HirStmt {
        let leaf: HirStmt = leaf_statement(block, self.lang);
        let tail: HirStmt = match block.kind {
            BlockKind::Conditional => self.conditional_tail(block, bounds, depth),
            BlockKind::Jump => self.jump_tail(block, bounds, depth),
            BlockKind::FallThrough => self.fallthrough_tail(block, bounds, depth),
            BlockKind::Return => terminal_tail(block, self.lang),
            BlockKind::Indirect => {
                self.fail(StructureFailure::IndirectTransfer);
                HirStmt::Empty
            }
        };
        sequence(vec![leaf, tail])
    }

    fn conditional_tail(&mut self, block: &'a NirBlock, bounds: &Bounds, depth: usize) -> HirStmt {
        let Some(last): Option<&NirInstr> = block.instructions.last() else {
            self.fail(StructureFailure::MissingTerminator);
            return HirStmt::Empty;
        };
        let taken: Option<u64> = last.direct_target();
        let fallthrough: Option<u64> = block
            .successors
            .iter()
            .copied()
            .find(|s: &u64| Some(*s) != taken);
        let cond: HirCond = HirCond {
            at: last.address,
            mnemonic: last.mnemonic.clone(),
            operands: last.operands.clone(),
            taken_target: taken,
        };
        let (then_target, else_target): (Option<u64>, Option<u64>) = (taken, fallthrough);
        let follow: Option<u64> = conditional_follow(self.index, block);
        let branch_bounds: Bounds = follow.map_or_else(
            || bounds.clone(),
            |follow_block: u64| bounds.with_follow(follow_block),
        );
        let then_branch: HirStmt = self.branch_arm(then_target, &branch_bounds, depth + 1);
        let else_branch: HirStmt = self.branch_arm(else_target, &branch_bounds, depth + 1);
        let if_stmt: HirStmt = HirStmt::If {
            cond,
            then_branch: Box::new(then_branch),
            else_branch: Box::new(else_branch),
        };
        match follow {
            Some(follow_block) if !bounds.is_follow(follow_block) => {
                let after: HirStmt = self.region(follow_block, bounds, depth + 1);
                sequence(vec![if_stmt, after])
            }
            _ => if_stmt,
        }
    }

    fn branch_arm(&mut self, target: Option<u64>, bounds: &Bounds, depth: usize) -> HirStmt {
        target.map_or(HirStmt::Empty, |t: u64| self.region(t, bounds, depth))
    }

    fn jump_tail(&mut self, block: &'a NirBlock, bounds: &Bounds, depth: usize) -> HirStmt {
        let Some(target): Option<u64> = block.successors.first().copied() else {
            self.fail(StructureFailure::JumpWithoutTarget);
            return HirStmt::Empty;
        };
        self.region(target, bounds, depth + 1)
    }

    fn fallthrough_tail(&mut self, block: &'a NirBlock, bounds: &Bounds, depth: usize) -> HirStmt {
        block
            .successors
            .first()
            .copied()
            .map_or(HirStmt::Empty, |target: u64| {
                self.region(target, bounds, depth + 1)
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoopFollow {
    None,
    Single(u64),
    Multiple,
}

fn loop_follow(index: &BlockIndex<'_>, header: u64) -> LoopFollow {
    let Some(nodes): Option<&BTreeSet<u64>> = index.natural_loop(header) else {
        return LoopFollow::None;
    };
    let mut exits: BTreeSet<u64> = BTreeSet::new();
    for node in nodes {
        let Some(block): Option<&NirBlock> = index.block(*node) else {
            continue;
        };
        for successor in &block.successors {
            if index.block(*successor).is_some() && !nodes.contains(successor) {
                exits.insert(*successor);
            }
        }
    }
    match exits.len() {
        0 => LoopFollow::None,
        1 => exits
            .first()
            .copied()
            .map_or(LoopFollow::None, LoopFollow::Single),
        _ => match index.immediate_post_dominator(header) {
            Some(follow) if !nodes.contains(&follow) => LoopFollow::Single(follow),
            _ => LoopFollow::Multiple,
        },
    }
}

fn conditional_follow(index: &BlockIndex<'_>, block: &NirBlock) -> Option<u64> {
    if block.successors.len() < 2 {
        return None;
    }
    if let Some(follow) = post_dominator_follow(index, block.start) {
        return Some(follow);
    }
    heuristic_follow(index, block)
}

fn post_dominator_follow(index: &BlockIndex<'_>, header: u64) -> Option<u64> {
    let follow: u64 = index.immediate_post_dominator(header)?;
    (follow != header).then_some(follow)
}

fn heuristic_follow(index: &BlockIndex<'_>, block: &NirBlock) -> Option<u64> {
    let mut shared: Option<u64> = None;
    for &candidate in &index.order {
        if candidate <= block.start {
            continue;
        }
        let preds: &[u64] = index.predecessors(candidate);
        let reached_from: usize = block
            .successors
            .iter()
            .filter(|s: &&u64| reaches(index, **s, candidate, block.start))
            .count();
        if reached_from >= 2 && preds.len() >= 2 {
            shared = Some(candidate);
            break;
        }
    }
    shared
}

fn reaches(index: &BlockIndex<'_>, from: u64, goal: u64, forbidden: u64) -> bool {
    let mut stack: Vec<u64> = vec![from];
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    while let Some(current) = stack.pop() {
        if current == goal {
            return true;
        }
        if current == forbidden || !seen.insert(current) {
            continue;
        }
        if current < forbidden {
            continue;
        }
        let Some(block): Option<&NirBlock> = index.block(current) else {
            continue;
        };
        for succ in &block.successors {
            if *succ >= forbidden || *succ == goal {
                stack.push(*succ);
            }
        }
    }
    false
}

fn append_unreachable_blocks(
    body: HirStmt,
    index: &BlockIndex<'_>,
    reachable: &BTreeSet<u64>,
    lang: SourceLang,
) -> HirStmt {
    let dead: Vec<HirStmt> = index
        .order
        .iter()
        .filter(|start: &&u64| !reachable.contains(start))
        .filter_map(|start: &u64| index.block(*start))
        .map(|block: &NirBlock| leaf_statement(block, lang))
        .collect();
    if dead.is_empty() {
        return body;
    }
    let mut parts: Vec<HirStmt> = Vec::with_capacity(dead.len() + 1);
    parts.push(body);
    parts.extend(dead);
    sequence(parts)
}

fn uses_goto_fallback(function: &NirFunction) -> bool {
    matches!(
        function.source.lang,
        SourceLang::NativeX86 | SourceLang::NativeArm | SourceLang::NativeMips
    ) || function.instructions.iter().any(|instruction: &NirInstr| {
        matches!(
            instruction.op,
            NirOp::RawLoad { .. }
                | NirOp::RawStore { .. }
                | NirOp::Subpiece { .. }
                | NirOp::Deposit { .. }
                | NirOp::CallOther { .. }
                | NirOp::Copy { .. }
                | NirOp::Value { .. }
                | NirOp::Piece { .. }
                | NirOp::NoReturnCall { .. }
                | NirOp::TailCall { .. }
        )
    })
}

fn dispatch_all(index: &BlockIndex<'_>, lang: SourceLang) -> HirStmt {
    let entry: u64 = index.order.first().copied().unwrap_or(0);
    let cases: Vec<HirDispatchCase> = index
        .order
        .iter()
        .filter_map(|start: &u64| index.block(*start))
        .map(|block: &NirBlock| HirDispatchCase {
            block_start: block.start,
            stmts: leaf_stmts(block, lang),
            successors: block.successors.clone(),
        })
        .collect();
    HirStmt::Dispatch { entry, cases }
}

fn goto_graph_all(index: &BlockIndex<'_>, lang: SourceLang) -> HirStmt {
    let entry: u64 = index.order.first().copied().unwrap_or(0);
    let cases: Vec<HirDispatchCase> = index
        .order
        .iter()
        .filter_map(|start: &u64| index.block(*start))
        .map(|block: &NirBlock| HirDispatchCase {
            block_start: block.start,
            stmts: leaf_stmts(block, lang),
            successors: block.successors.clone(),
        })
        .collect();
    HirStmt::GotoGraph {
        entry,
        blocks: cases,
    }
}

fn leaf_statement(block: &NirBlock, lang: SourceLang) -> HirStmt {
    HirStmt::Leaf {
        block_start: block.start,
        stmts: leaf_stmts(block, lang),
    }
}

fn leaf_stmts(block: &NirBlock, lang: SourceLang) -> Vec<HirLeafStmt> {
    block
        .instructions
        .iter()
        .map(|instr: &NirInstr| HirLeafStmt {
            instr: instr.clone(),
            stmt: lower_instr(instr, lang),
        })
        .collect()
}

fn return_value(block: &NirBlock, lang: SourceLang) -> Option<HirExpr> {
    let last: &NirInstr = block.instructions.last()?;
    if last.class() != NirClass::Return {
        return None;
    }
    last.operands
        .first()
        .map(|operand: &String| operand_expr(operand, lang))
}

fn terminal_tail(block: &NirBlock, lang: SourceLang) -> HirStmt {
    let Some(last): Option<&NirInstr> = block.instructions.last() else {
        return HirStmt::Return { value: None };
    };
    match last.op {
        NirOp::NoReturnCall { .. } => HirStmt::Empty,
        NirOp::TailCall { .. } => {
            let (target, args): (Option<String>, Vec<HirExpr>) = call_parts(last, lang);
            HirStmt::Return {
                value: Some(HirExpr::Call { target, args }),
            }
        }
        _ => HirStmt::Return {
            value: return_value(block, lang),
        },
    }
}

fn lower_instr(instr: &NirInstr, lang: SourceLang) -> HirInstrStmt {
    match &instr.op {
        NirOp::Call { .. }
        | NirOp::NoReturnCall { .. }
        | NirOp::IndirectCall
        | NirOp::ExternCall { .. } => {
            let (target, args): (Option<String>, Vec<HirExpr>) = call_parts(instr, lang);
            HirInstrStmt::Call { target, args }
        }
        NirOp::Store => HirInstrStmt::Store {
            cell: instr.operands.first().map_or_else(
                || HirExpr::Mem {
                    cell: String::new(),
                },
                |operand: &String| operand_expr(operand, lang),
            ),
            value: instr.operands.get(1).map_or(
                HirExpr::Unknown {
                    text: String::new(),
                },
                |operand: &String| operand_expr(operand, lang),
            ),
        },
        NirOp::BinOp { op } => binop_assign(instr, *op, lang),
        NirOp::Copy { .. } | NirOp::Const | NirOp::Load => simple_assign(instr, lang),
        NirOp::RawLoad { addr, size } => HirInstrStmt::Assign {
            dst: destination_expr(instr, lang),
            value: HirExpr::Mem {
                cell: format!("{addr}:u{}", size.saturating_mul(8)),
            },
        },
        NirOp::RawStore { addr, value, size } => HirInstrStmt::Store {
            cell: HirExpr::Mem {
                cell: format!("{addr}:u{}", size.saturating_mul(8)),
            },
            value: operand_expr(value, lang),
        },
        NirOp::Subpiece { src, offset, size } => native_assign(
            instr,
            "subpiece",
            vec![
                operand_expr(src, lang),
                HirExpr::Const {
                    text: offset.to_string(),
                },
                HirExpr::Const {
                    text: size.to_string(),
                },
            ],
            lang,
        ),
        NirOp::Deposit {
            cell,
            value,
            offset,
            size,
            cell_size,
            zero_upper,
        } => {
            let target: HirExpr = operand_expr(cell, lang);
            let name: &str = if *zero_upper {
                "zero_upper_deposit"
            } else {
                "deposit"
            };
            let mut args: Vec<HirExpr> = vec![
                operand_expr(value, lang),
                HirExpr::Const {
                    text: offset.to_string(),
                },
                HirExpr::Const {
                    text: size.to_string(),
                },
                HirExpr::Const {
                    text: cell_size.to_string(),
                },
            ];
            if !*zero_upper {
                args.insert(0, target.clone());
            }
            HirInstrStmt::Assign {
                dst: target,
                value: intrinsic(name, args),
            }
        }
        NirOp::CallOther { effect } => {
            let args: Vec<HirExpr> = effect
                .reads
                .iter()
                .map(|value: &String| operand_expr(value, lang))
                .collect();
            match effect.writes.first() {
                Some(destination) => HirInstrStmt::Assign {
                    dst: operand_expr(destination, lang),
                    value: intrinsic(&effect.name, args),
                },
                None => HirInstrStmt::Call {
                    target: Some(effect.name.clone()),
                    args,
                },
            }
        }
        NirOp::Value { op, inputs, .. } => value_assign(instr, *op, inputs, lang),
        NirOp::Piece {
            high,
            low,
            high_size,
            low_size,
            size,
        } => native_assign(
            instr,
            "piece",
            vec![
                operand_expr(high, lang),
                operand_expr(low, lang),
                HirExpr::Const {
                    text: high_size.to_string(),
                },
                HirExpr::Const {
                    text: low_size.to_string(),
                },
                HirExpr::Const {
                    text: size.to_string(),
                },
            ],
            lang,
        ),
        NirOp::Nop
        | NirOp::TailCall { .. }
        | NirOp::Phi
        | NirOp::Interrupt
        | NirOp::Branch { .. }
        | NirOp::CondBranch { .. }
        | NirOp::Return
        | NirOp::Unmodeled { .. } => HirInstrStmt::Effect {
            expr: HirExpr::Unknown {
                text: if matches!(
                    lang,
                    SourceLang::NativeX86 | SourceLang::NativeArm | SourceLang::NativeMips
                ) {
                    String::new()
                } else {
                    instr.mnemonic.clone()
                },
            },
        },
    }
}

fn value_assign(
    instr: &NirInstr,
    op: ValueOp,
    inputs: &[String],
    lang: SourceLang,
) -> HirInstrStmt {
    let values: Vec<HirExpr> = inputs
        .iter()
        .map(|value: &String| operand_expr(value, lang))
        .collect();
    let value: HirExpr = match (value_binary_op(op), values.as_slice()) {
        (Some(binary), [left, right]) => HirExpr::Binary {
            op: binary,
            lhs: Box::new(left.clone()),
            rhs: Box::new(right.clone()),
        },
        (_, [operand]) if op == ValueOp::IntNegate => HirExpr::Unary {
            op: BinaryOp::Not,
            operand: Box::new(operand.clone()),
        },
        _ => intrinsic(&op.mnemonic().to_ascii_lowercase(), values),
    };
    HirInstrStmt::Assign {
        dst: destination_expr(instr, lang),
        value,
    }
}

const fn value_binary_op(op: ValueOp) -> Option<BinaryOp> {
    match op {
        ValueOp::IntAdd | ValueOp::FloatAdd => Some(BinaryOp::Add),
        ValueOp::IntSub | ValueOp::FloatSub => Some(BinaryOp::Sub),
        ValueOp::IntMult | ValueOp::FloatMult => Some(BinaryOp::Mul),
        ValueOp::IntDiv | ValueOp::FloatDiv => Some(BinaryOp::Div),
        ValueOp::IntRem => Some(BinaryOp::Rem),
        ValueOp::IntAnd | ValueOp::BoolAnd => Some(BinaryOp::And),
        ValueOp::IntOr | ValueOp::BoolOr => Some(BinaryOp::Or),
        ValueOp::IntXor | ValueOp::BoolXor => Some(BinaryOp::Xor),
        ValueOp::IntLeft => Some(BinaryOp::Shl),
        ValueOp::IntRight => Some(BinaryOp::Shr),
        ValueOp::BoolNegate
        | ValueOp::FloatEqual
        | ValueOp::FloatLess
        | ValueOp::FloatLessEqual
        | ValueOp::FloatSqrt
        | ValueOp::FloatToFloat
        | ValueOp::FloatTrunc
        | ValueOp::IntToFloat
        | ValueOp::IntCarry
        | ValueOp::IntEqual
        | ValueOp::IntLess
        | ValueOp::IntLessEqual
        | ValueOp::IntNegate
        | ValueOp::IntNotEqual
        | ValueOp::IntSignedBorrow
        | ValueOp::IntSignedCarry
        | ValueOp::IntSignedDiv
        | ValueOp::IntSignedLess
        | ValueOp::IntSignedLessEqual
        | ValueOp::IntSignedRem
        | ValueOp::IntSignedRight
        | ValueOp::IntSext
        | ValueOp::IntZext => None,
    }
}

fn native_assign(
    instr: &NirInstr,
    name: &str,
    args: Vec<HirExpr>,
    lang: SourceLang,
) -> HirInstrStmt {
    HirInstrStmt::Assign {
        dst: destination_expr(instr, lang),
        value: intrinsic(name, args),
    }
}

fn intrinsic(name: &str, args: Vec<HirExpr>) -> HirExpr {
    HirExpr::Call {
        target: Some(name.to_owned()),
        args,
    }
}

fn destination_expr(instr: &NirInstr, lang: SourceLang) -> HirExpr {
    instr.operands.first().map_or(
        HirExpr::Unknown {
            text: String::new(),
        },
        |operand: &String| operand_expr(operand, lang),
    )
}

fn binop_assign(instr: &NirInstr, op: BinaryOp, lang: SourceLang) -> HirInstrStmt {
    let dst: HirExpr = instr.operands.first().map_or(
        HirExpr::Unknown {
            text: String::new(),
        },
        |operand: &String| operand_expr(operand, lang),
    );
    let lhs: HirExpr = dst.clone();
    let value: HirExpr = match instr.operands.get(1) {
        Some(rhs_operand) => HirExpr::Binary {
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(operand_expr(rhs_operand, lang)),
        },
        None => HirExpr::Unary {
            op,
            operand: Box::new(lhs),
        },
    };
    HirInstrStmt::Assign { dst, value }
}

fn simple_assign(instr: &NirInstr, lang: SourceLang) -> HirInstrStmt {
    let dst: HirExpr = instr.operands.first().map_or(
        HirExpr::Unknown {
            text: String::new(),
        },
        |operand: &String| operand_expr(operand, lang),
    );
    let value: HirExpr = instr.operands.get(1).map_or_else(
        || dst.clone(),
        |operand: &String| operand_expr(operand, lang),
    );
    HirInstrStmt::Assign { dst, value }
}

fn call_parts(instr: &NirInstr, lang: SourceLang) -> (Option<String>, Vec<HirExpr>) {
    let target: Option<String> = match &instr.op {
        NirOp::ExternCall { symbol } => Some(symbol.clone()),
        NirOp::Call { .. } | NirOp::NoReturnCall { .. } | NirOp::TailCall { .. } => {
            instr.operands.first().cloned()
        }
        _ => None,
    };
    let direct: bool = matches!(
        instr.op,
        NirOp::Call { .. } | NirOp::NoReturnCall { .. } | NirOp::TailCall { .. }
    );
    let arg_start: usize = usize::from(direct && target.is_some());
    let args: Vec<HirExpr> = instr
        .operands
        .iter()
        .skip(arg_start)
        .map(|operand: &String| operand_expr(operand, lang))
        .collect();
    (target, args)
}

fn operand_expr(operand: &str, _lang: SourceLang) -> HirExpr {
    let trimmed: &str = operand.trim();
    if trimmed.is_empty() {
        return HirExpr::Unknown {
            text: String::new(),
        };
    }
    if trimmed.contains('[') && trimmed.contains(']') {
        return HirExpr::Mem {
            cell: trimmed.to_owned(),
        };
    }
    if is_constant_literal(trimmed) {
        return HirExpr::Const {
            text: trimmed.to_owned(),
        };
    }
    HirExpr::Var {
        name: trimmed.to_owned(),
    }
}

fn is_constant_literal(operand: &str) -> bool {
    let body: &str = operand.strip_prefix('-').unwrap_or(operand);
    if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        return !hex.is_empty() && hex.bytes().all(|byte: u8| byte.is_ascii_hexdigit());
    }
    !body.is_empty() && body.bytes().all(|byte: u8| byte.is_ascii_digit())
}

fn sequence(parts: Vec<HirStmt>) -> HirStmt {
    let mut flat: Vec<HirStmt> = Vec::with_capacity(parts.len());
    for mut part in parts {
        match &mut part {
            HirStmt::Empty => {}
            HirStmt::Seq { body } => flat.extend(std::mem::take(body)),
            _ => flat.push(part),
        }
    }
    match flat.len() {
        0 => HirStmt::Empty,
        1 => flat.into_iter().next().unwrap_or(HirStmt::Empty),
        _ => HirStmt::Seq { body: flat },
    }
}

fn collect_block_starts(stmt: &HirStmt, out: &mut BTreeSet<u64>) {
    let mut pending: Vec<&HirStmt> = vec![stmt];
    while let Some(current) = pending.pop() {
        match current {
            HirStmt::Leaf { block_start, .. } => {
                out.insert(*block_start);
            }
            HirStmt::Seq { body } => pending.extend(body),
            HirStmt::If {
                then_branch,
                else_branch,
                ..
            } => {
                pending.push(then_branch);
                pending.push(else_branch);
            }
            HirStmt::Loop { body, .. } => pending.push(body),
            HirStmt::Dispatch { cases, .. } => {
                for case in cases {
                    out.insert(case.block_start);
                }
            }
            HirStmt::GotoGraph { blocks, .. } => {
                for block in blocks {
                    out.insert(block.block_start);
                }
            }
            HirStmt::Break { .. }
            | HirStmt::Continue { .. }
            | HirStmt::Return { .. }
            | HirStmt::Empty => {}
        }
    }
}

fn collect_instruction_addresses(stmt: &HirStmt, out: &mut BTreeSet<u64>) {
    let mut instructions: Vec<NirInstr> = Vec::new();
    collect_instructions(stmt, &mut instructions);
    for instr in instructions {
        out.insert(instr.address);
    }
}

fn collect_instructions(stmt: &HirStmt, out: &mut Vec<NirInstr>) {
    let mut pending: Vec<&HirStmt> = vec![stmt];
    while let Some(current) = pending.pop() {
        match current {
            HirStmt::Leaf { stmts, .. } => {
                for leaf in stmts {
                    out.push(leaf.instr.clone());
                }
            }
            HirStmt::Seq { body } => pending.extend(body),
            HirStmt::If {
                then_branch,
                else_branch,
                ..
            } => {
                pending.push(then_branch);
                pending.push(else_branch);
            }
            HirStmt::Loop { body, .. } => pending.push(body),
            HirStmt::Dispatch { cases, .. } => {
                for case in cases {
                    for leaf in &case.stmts {
                        out.push(leaf.instr.clone());
                    }
                }
            }
            HirStmt::GotoGraph { blocks, .. } => {
                for block in blocks {
                    for leaf in &block.stmts {
                        out.push(leaf.instr.clone());
                    }
                }
            }
            HirStmt::Break { .. }
            | HirStmt::Continue { .. }
            | HirStmt::Return { .. }
            | HirStmt::Empty => {}
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::reducible::CnsBudget;
    use crate::types::{NirOp, SourceLang, SourceRef};

    fn instr(address: u64, op: NirOp, mnemonic: &str, operands: &[&str]) -> NirInstr {
        NirInstr {
            address,
            op,
            mnemonic: mnemonic.to_owned(),
            operands: operands.iter().map(|s: &&str| (*s).to_owned()).collect(),
            reads_memory: false,
            writes_memory: false,
            byte_width: false,
            source: SourceRef::new(SourceLang::NativeX86, address),
        }
    }

    fn function(instructions: Vec<NirInstr>, end: u64) -> NirFunction {
        NirFunction {
            name: "f".to_owned(),
            address: instructions.first().map_or(0, |i: &NirInstr| i.address),
            end,
            is_export: false,
            instructions,
            source: SourceRef::new(SourceLang::NativeX86, 0),
        }
    }

    #[test]
    fn straight_line_returns_a_single_leaf_then_return() {
        let f: NirFunction = function(
            vec![
                instr(0x0, NirOp::Const, "mov", &["eax", "0x1"]),
                instr(0x1, NirOp::Return, "ret", &[]),
            ],
            0x2,
        );
        let hir: HirFunction = structurize_function(&f);
        assert!(hir.structured);
        let blocks: BTreeSet<u64> = hir.block_starts();
        assert_eq!(blocks, BTreeSet::from([0x0]));
    }

    #[test]
    fn if_then_recovers_branch_structure() {
        let f: NirFunction = function(
            vec![
                instr(0x0, NirOp::CondBranch { target: Some(0x4) }, "je", &["0x4"]),
                instr(0x2, NirOp::Const, "mov", &["eax", "0x1"]),
                instr(0x4, NirOp::Return, "ret", &[]),
            ],
            0x5,
        );
        let hir: HirFunction = structurize_function(&f);
        assert!(hir.structured, "diamond-free if must structurize: {hir:?}");
        assert!(
            matches!(first_control(&hir.body), Some(HirStmt::If { .. })),
            "body should contain an if: {:?}",
            hir.body
        );
    }

    fn first_control(stmt: &HirStmt) -> Option<&HirStmt> {
        match stmt {
            HirStmt::Seq { body } => body.iter().find_map(first_control),
            HirStmt::If { .. } | HirStmt::Loop { .. } => Some(stmt),
            _ => None,
        }
    }

    #[test]
    fn loop_back_edge_becomes_a_loop() {
        let f: NirFunction = function(
            vec![
                instr(0x0, NirOp::Const, "mov", &["ecx", "0x0"]),
                instr(
                    0x2,
                    NirOp::BinOp { op: BinaryOp::Add },
                    "add",
                    &["ecx", "0x1"],
                ),
                instr(0x4, NirOp::CondBranch { target: Some(0x2) }, "jl", &["0x2"]),
                instr(0x6, NirOp::Return, "ret", &[]),
            ],
            0x7,
        );
        let hir: HirFunction = structurize_function(&f);
        assert!(hir.structured, "self-loop must structurize: {hir:?}");
        let mut has_loop: bool = false;
        find_loop(&hir.body, &mut has_loop);
        assert!(
            has_loop,
            "a back edge must yield a Loop node: {:?}",
            hir.body
        );
    }

    fn find_loop(stmt: &HirStmt, found: &mut bool) {
        match stmt {
            HirStmt::Loop { .. } => *found = true,
            HirStmt::Seq { body } => body.iter().for_each(|s: &HirStmt| find_loop(s, found)),
            HirStmt::If {
                then_branch,
                else_branch,
                ..
            } => {
                find_loop(then_branch, found);
                find_loop(else_branch, found);
            }
            _ => {}
        }
    }

    #[test]
    fn cycle_has_only_its_dominating_header() {
        let blocks: Vec<NirBlock> = vec![
            NirBlock {
                start: 0,
                end: 2,
                instructions: Vec::new(),
                successors: vec![2],
                kind: BlockKind::FallThrough,
            },
            NirBlock {
                start: 2,
                end: 4,
                instructions: Vec::new(),
                successors: vec![4, 8],
                kind: BlockKind::Conditional,
            },
            NirBlock {
                start: 4,
                end: 6,
                instructions: Vec::new(),
                successors: vec![6],
                kind: BlockKind::FallThrough,
            },
            NirBlock {
                start: 6,
                end: 8,
                instructions: Vec::new(),
                successors: vec![2],
                kind: BlockKind::Jump,
            },
            NirBlock {
                start: 8,
                end: 10,
                instructions: Vec::new(),
                successors: Vec::new(),
                kind: BlockKind::Return,
            },
        ];
        let index: BlockIndex<'_> = BlockIndex::build(&blocks);
        assert!(index.is_loop_header(2));
        assert!(!index.is_loop_header(4));
        assert!(!index.is_loop_header(6));
    }

    fn first_loop_body(stmt: &HirStmt) -> Option<&HirStmt> {
        match stmt {
            HirStmt::Loop { body, .. } => Some(body),
            HirStmt::Seq { body } => body.iter().find_map(first_loop_body),
            HirStmt::If {
                then_branch,
                else_branch,
                ..
            } => first_loop_body(then_branch).or_else(|| first_loop_body(else_branch)),
            _ => None,
        }
    }

    fn has_loop_transfer(stmt: &HirStmt, break_transfer: bool) -> bool {
        match stmt {
            HirStmt::Break { .. } => break_transfer,
            HirStmt::Continue { .. } => !break_transfer,
            HirStmt::Seq { body } => body
                .iter()
                .any(|child: &HirStmt| has_loop_transfer(child, break_transfer)),
            HirStmt::If {
                then_branch,
                else_branch,
                ..
            } => {
                has_loop_transfer(then_branch, break_transfer)
                    || has_loop_transfer(else_branch, break_transfer)
            }
            HirStmt::Loop { body, .. } => has_loop_transfer(body, break_transfer),
            _ => false,
        }
    }

    fn assert_pretest_loop(f: &NirFunction, expected_body: u64, exit: u64) {
        let hir: HirFunction = structurize_function(f);
        assert!(hir.structured, "pre-test loop must structurize: {hir:?}");
        let loop_body: &HirStmt = first_loop_body(&hir.body).expect("find loop body");
        let mut starts: BTreeSet<u64> = BTreeSet::new();
        collect_block_starts(loop_body, &mut starts);
        assert!(starts.contains(&0));
        assert!(starts.contains(&expected_body));
        assert!(!starts.contains(&exit));
        assert!(has_loop_transfer(loop_body, true));
        assert!(has_loop_transfer(loop_body, false));
    }

    #[test]
    fn pretest_loop_with_taken_exit_keeps_body_inside() {
        let f: NirFunction = function(
            vec![
                instr(0, NirOp::CondBranch { target: Some(4) }, "jz", &["zf"]),
                instr(2, NirOp::BinOp { op: BinaryOp::Add }, "add", &["rax", "1"]),
                instr(3, NirOp::Branch { target: Some(0) }, "jmp", &["0"]),
                instr(4, NirOp::Return, "ret", &["rax"]),
            ],
            5,
        );
        assert_pretest_loop(&f, 2, 4);
    }

    #[test]
    fn pretest_loop_with_fallthrough_exit_keeps_body_inside() {
        let f: NirFunction = function(
            vec![
                instr(0, NirOp::CondBranch { target: Some(4) }, "jnz", &["zf"]),
                instr(2, NirOp::Return, "ret", &["rax"]),
                instr(4, NirOp::BinOp { op: BinaryOp::Add }, "add", &["rax", "1"]),
                instr(6, NirOp::Branch { target: Some(0) }, "jmp", &["0"]),
            ],
            7,
        );
        assert_pretest_loop(&f, 4, 2);
    }

    #[test]
    fn unresolved_indirect_control_uses_explicit_goto_graph() {
        let f: NirFunction = function(
            vec![instr(0x0, NirOp::Branch { target: None }, "jmp", &["rax"])],
            0x1,
        );
        let hir: HirFunction = structurize_function(&f);
        assert!(!hir.structured);
        assert!(matches!(hir.body, HirStmt::GotoGraph { entry: 0, .. }));
    }

    #[test]
    fn non_native_unstructured_control_retains_dispatch_fallback() {
        let mut f: NirFunction = function(
            vec![instr(
                0x0,
                NirOp::Branch { target: None },
                "jump",
                &["dynamic"],
            )],
            0x1,
        );
        f.source = SourceRef::new(SourceLang::Jvm, 0);
        let hir: HirFunction = structurize_function(&f);
        assert!(!hir.structured);
        assert!(matches!(hir.body, HirStmt::Dispatch { entry: 0, .. }));
    }

    #[test]
    fn non_native_control_effect_retains_its_mnemonic() {
        let legacy: NirInstr = instr(0, NirOp::Nop, "legacy_nop", &[]);
        let lowered: HirInstrStmt = lower_instr(&legacy, SourceLang::Jvm);
        assert!(matches!(
            lowered,
            HirInstrStmt::Effect {
                expr: HirExpr::Unknown { ref text }
            } if text == "legacy_nop"
        ));
    }

    fn two_entry_irreducible_loop() -> NirFunction {
        function(
            vec![
                instr(0, NirOp::CondBranch { target: Some(4) }, "je", &["4"]),
                instr(2, NirOp::Branch { target: Some(4) }, "jmp", &["4"]),
                instr(4, NirOp::CondBranch { target: Some(2) }, "je", &["2"]),
                instr(6, NirOp::Return, "ret", &[]),
            ],
            7,
        )
    }

    fn loop_labels(stmt: &HirStmt, found: &mut Vec<u64>) {
        match stmt {
            HirStmt::Loop { label, body } => {
                found.push(*label);
                loop_labels(body, found);
            }
            HirStmt::Seq { body } => {
                for child in body {
                    loop_labels(child, found);
                }
            }
            HirStmt::If {
                then_branch,
                else_branch,
                ..
            } => {
                loop_labels(then_branch, found);
                loop_labels(else_branch, found);
            }
            HirStmt::Leaf { .. }
            | HirStmt::Break { .. }
            | HirStmt::Continue { .. }
            | HirStmt::Return { .. }
            | HirStmt::Dispatch { .. }
            | HirStmt::GotoGraph { .. }
            | HirStmt::Empty => {}
        }
    }

    #[test]
    fn a_two_entry_irreducible_loop_recovers_as_a_real_loop_rather_than_a_goto_graph() {
        let hir: HirFunction = structurize_function(&two_entry_irreducible_loop());
        assert!(
            hir.structured,
            "capped splitting must make a two-entry loop reducible: {:?}",
            hir.decline
        );
        assert_eq!(hir.decline, None, "a structured function declines nothing");
        assert!(
            !matches!(
                hir.body,
                HirStmt::GotoGraph { .. } | HirStmt::Dispatch { .. }
            ),
            "the flat fallback must not be reached: {:?}",
            hir.body
        );
        let mut labels: Vec<u64> = Vec::new();
        loop_labels(&hir.body, &mut labels);
        assert_eq!(
            labels,
            vec![4],
            "the shared header becomes a single reducible loop"
        );
        assert_eq!(
            hir.instruction_addresses(),
            BTreeSet::from([0, 2, 4, 6]),
            "splitting must not drop or invent an instruction"
        );
        let starts: BTreeSet<u64> = hir.block_starts();
        assert!(
            starts.is_superset(&BTreeSet::from([0, 2, 4, 6])),
            "every original block keeps its own address: {starts:?}"
        );
        assert_eq!(
            starts.len(),
            5,
            "exactly one secondary entry is cloned, at an address no original block owns: {starts:?}"
        );
    }

    #[test]
    fn disabling_the_split_budget_restores_the_goto_graph_and_names_the_reason() {
        let hir: HirFunction =
            structurize_function_with_budget(&two_entry_irreducible_loop(), SplitBudget::Disabled);
        assert!(!hir.structured);
        assert_eq!(
            hir.decline,
            Some(HirDecline {
                failure: StructureFailure::BlockReachedTwice,
                refusal: SplitRefusal::Disabled,
                after_split: None,
            }),
            "the decline names both what the structurer hit and why splitting did not run"
        );
        let HirStmt::GotoGraph { entry, blocks }: &HirStmt = &hir.body else {
            panic!(
                "an unsplit irreducible graph must fall back to a goto graph: {:?}",
                hir.body
            );
        };
        assert_eq!(*entry, 0);
        let starts: Vec<u64> = blocks
            .iter()
            .map(|case: &HirDispatchCase| case.block_start)
            .collect();
        assert_eq!(
            starts,
            vec![0, 2, 4, 6],
            "the fallback must emit every reachable block exactly once, in address order"
        );
        let followed: Vec<Vec<u64>> = blocks
            .iter()
            .map(|case: &HirDispatchCase| case.successors.clone())
            .collect();
        assert_eq!(
            followed,
            vec![vec![2, 4], vec![4], vec![2, 6], Vec::<u64>::new()],
            "the fallback must preserve each block's successor edges verbatim"
        );
        assert_eq!(
            hir.instruction_addresses(),
            BTreeSet::from([0, 2, 4, 6]),
            "no instruction may be dropped by the fallback path"
        );
    }

    #[test]
    fn an_exhausted_split_budget_falls_back_and_records_that_the_budget_ran_out() {
        let hir: HirFunction = structurize_function_with_budget(
            &two_entry_irreducible_loop(),
            SplitBudget::Explicit(CnsBudget {
                max_cloned_blocks: 0,
                max_iterations: 4,
            }),
        );
        assert!(!hir.structured);
        assert_eq!(
            hir.decline.map(|decline: HirDecline| decline.refusal),
            Some(SplitRefusal::BudgetExhausted)
        );
        assert!(matches!(hir.body, HirStmt::GotoGraph { entry: 0, .. }));
    }

    #[test]
    fn a_dense_multi_entry_region_terminates_inside_its_budget() {
        const WIDTH: u64 = 24;
        let mut instructions: Vec<NirInstr> = Vec::new();
        instructions.push(instr(
            0,
            NirOp::CondBranch { target: Some(2) },
            "je",
            &["2"],
        ));
        for index in 0..WIDTH {
            let address: u64 = 2 + index * 2;
            let target: u64 = 2 + ((index + 1) % WIDTH) * 2;
            let text: String = target.to_string();
            instructions.push(instr(
                address,
                NirOp::CondBranch {
                    target: Some(target),
                },
                "je",
                &[text.as_str()],
            ));
        }
        let tail: u64 = 2 + WIDTH * 2;
        instructions.push(instr(tail, NirOp::Return, "ret", &[]));
        let dense: NirFunction = function(instructions, tail + 1);
        let hir: HirFunction = structurize_function(&dense);
        assert_eq!(
            hir.instruction_addresses().len(),
            usize::try_from(WIDTH).expect("width fits") + 2,
            "a dense region must keep every instruction whichever path it takes"
        );
        if hir.structured {
            assert_eq!(hir.decline, None);
        } else {
            assert!(
                hir.decline.is_some(),
                "a dense region that cannot be split must name why"
            );
        }
    }

    #[test]
    fn structuring_the_same_function_twice_produces_byte_identical_hir() {
        let function: NirFunction = two_entry_irreducible_loop();
        let first: HirFunction = structurize_function(&function);
        let second: HirFunction = structurize_function(&function);
        assert_eq!(first.body, second.body);
        assert_eq!(first.structured, second.structured);
        assert_eq!(first.decline, second.decline);
    }

    fn branch_chain(depth: usize) -> NirFunction {
        let mut instructions: Vec<NirInstr> = Vec::with_capacity(depth + 1);
        for index in 0..depth {
            let address: u64 = u64::try_from(index).expect("chain address");
            let target: u64 = address + 1;
            let target_text: String = target.to_string();
            instructions.push(instr(
                address,
                NirOp::Branch {
                    target: Some(target),
                },
                "jmp",
                &[&target_text],
            ));
        }
        let end: u64 = u64::try_from(depth).expect("chain end");
        instructions.push(instr(end, NirOp::Return, "ret", &[]));
        function(instructions, end + 1)
    }

    #[test]
    fn region_past_bound_uses_complete_graph_fallback() {
        let input: NirFunction = branch_chain(MAX_REGION_DEPTH);
        let expected: BTreeSet<u64> = input
            .instructions
            .iter()
            .map(|instruction: &NirInstr| instruction.address)
            .collect();
        let hir: HirFunction = structurize_function(&input);
        assert!(!hir.structured);
        assert!(matches!(hir.body, HirStmt::GotoGraph { entry: 0, .. }));
        assert_eq!(hir.instruction_addresses(), expected);
    }

    #[test]
    fn maximum_bounded_region_builds_successfully() {
        let input: NirFunction = branch_chain(MAX_REGION_DEPTH - 1);
        let hir: HirFunction = structurize_function(&input);
        assert!(hir.structured);
        assert_eq!(hir.instruction_addresses().len(), 128);
    }

    #[test]
    fn deep_hir_expression_drop_does_not_use_tree_depth_as_call_depth() {
        let handle: std::thread::JoinHandle<()> = std::thread::Builder::new()
            .stack_size(1_048_576)
            .spawn(|| {
                let mut expression: HirExpr = HirExpr::Const {
                    text: "1".to_owned(),
                };
                for _index in 0..100_000 {
                    expression = HirExpr::Unary {
                        op: BinaryOp::Neg,
                        operand: Box::new(expression),
                    };
                }
                std::hint::black_box(&expression);
            })
            .expect("spawn hir expression drop thread");
        handle.join().expect("hir expression drop thread");
    }

    #[test]
    fn deep_hir_region_drop_does_not_use_tree_depth_as_call_depth() {
        let handle: std::thread::JoinHandle<()> = std::thread::Builder::new()
            .stack_size(1_048_576)
            .spawn(|| {
                let mut statement: HirStmt = HirStmt::Empty;
                for index in 0..100_000 {
                    statement = HirStmt::Loop {
                        label: u64::try_from(index).expect("loop label"),
                        body: Box::new(statement),
                    };
                }
                std::hint::black_box(&statement);
            })
            .expect("spawn hir region drop thread");
        handle.join().expect("hir region drop thread");
    }
}
