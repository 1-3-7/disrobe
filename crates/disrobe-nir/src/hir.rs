use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::cfg::{BlockKind, NirBlock, basic_blocks};
use crate::types::{
    BinaryOp, NirClass, NirFunction, NirInstr, NirModule, NirOp, NirSymbol, SourceLang, SourceRef,
};

const MAX_REGION_DEPTH: usize = 4096;

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
    Empty,
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
            source: function.source.clone(),
        };
    }
    let index: BlockIndex = BlockIndex::build(&blocks);
    let mut structurer: Structurer<'_> = Structurer::new(&index, lang);
    let entry: u64 = blocks[0].start;
    let body: HirStmt = structurer.region(entry, &Bounds::default(), 0);
    let reachable: BTreeSet<u64> = index.reachable_from(entry);
    let structured: bool = structurer.structured && structurer.placed == reachable.len();
    let body: HirStmt = if structured {
        append_unreachable_blocks(body, &index, &reachable, lang)
    } else {
        dispatch_all(&index, lang)
    };
    HirFunction {
        name: function.name.clone(),
        address: function.address,
        end: function.end,
        is_export: function.is_export,
        body,
        structured,
        source: function.source.clone(),
    }
}

struct BlockIndex<'a> {
    blocks: BTreeMap<u64, &'a NirBlock>,
    order: Vec<u64>,
    predecessors: BTreeMap<u64, Vec<u64>>,
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
        Self {
            blocks: by_start,
            order,
            predecessors,
        }
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
        self.predecessors(start)
            .iter()
            .any(|pred: &u64| *pred >= start)
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
    loop_follows: Vec<u64>,
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
            next.loop_follows.push(follow_block);
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
        let position: usize = self.loop_follows.iter().rposition(|f: &u64| *f == target)?;
        self.loop_headers.get(position).copied()
    }
}

struct Structurer<'a> {
    index: &'a BlockIndex<'a>,
    lang: SourceLang,
    visited: BTreeSet<u64>,
    structured: bool,
    placed: usize,
}

impl<'a> Structurer<'a> {
    const fn new(index: &'a BlockIndex<'a>, lang: SourceLang) -> Self {
        Self {
            index,
            lang,
            visited: BTreeSet::new(),
            structured: true,
            placed: 0,
        }
    }

    fn region(&mut self, start: u64, bounds: &Bounds, depth: usize) -> HirStmt {
        if depth >= MAX_REGION_DEPTH {
            self.structured = false;
            return HirStmt::Empty;
        }
        if bounds.is_follow(start) {
            return HirStmt::Empty;
        }
        if let Some(label) = bounds.loop_label_for(start) {
            return HirStmt::Continue { label };
        }
        if let Some(label) = bounds.loop_follow_label(start) {
            return HirStmt::Break { label };
        }
        let Some(block): Option<&'a NirBlock> = self.index.block(start) else {
            self.structured = false;
            return HirStmt::Empty;
        };
        if !self.visited.insert(start) {
            self.structured = false;
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
        let follow: Option<u64> = loop_follow(self.index, header);
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
            BlockKind::Return => HirStmt::Return {
                value: return_value(block, self.lang),
            },
            BlockKind::Indirect => {
                self.structured = false;
                HirStmt::Empty
            }
        };
        sequence(vec![leaf, tail])
    }

    fn conditional_tail(&mut self, block: &'a NirBlock, bounds: &Bounds, depth: usize) -> HirStmt {
        let Some(last): Option<&NirInstr> = block.instructions.last() else {
            self.structured = false;
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
            self.structured = false;
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

fn loop_follow(index: &BlockIndex<'_>, header: u64) -> Option<u64> {
    let block: &NirBlock = index.block(header)?;
    if block.kind == BlockKind::Conditional {
        let taken: Option<u64> = block.instructions.last().and_then(NirInstr::direct_target);
        for succ in &block.successors {
            if *succ > header && Some(*succ) != taken {
                return Some(*succ);
            }
        }
        for succ in &block.successors {
            if *succ > header {
                return Some(*succ);
            }
        }
    }
    let latches: Vec<u64> = index
        .predecessors(header)
        .iter()
        .copied()
        .filter(|p: &u64| *p >= header)
        .collect();
    let mut candidate: Option<u64> = None;
    for latch in latches {
        let latch_block: Option<&NirBlock> = index.block(latch);
        if let Some(latch_block) = latch_block {
            for succ in &latch_block.successors {
                if *succ != header
                    && index.block(*succ).is_some()
                    && candidate.is_none_or(|c: u64| *succ < c)
                {
                    candidate = Some(*succ);
                }
            }
        }
    }
    candidate
}

fn conditional_follow(index: &BlockIndex<'_>, block: &NirBlock) -> Option<u64> {
    if block.successors.len() < 2 {
        return None;
    }
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

fn lower_instr(instr: &NirInstr, lang: SourceLang) -> HirInstrStmt {
    match &instr.op {
        NirOp::Call { .. } | NirOp::IndirectCall | NirOp::ExternCall { .. } => {
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
        NirOp::Const | NirOp::Load => simple_assign(instr, lang),
        NirOp::Nop
        | NirOp::Phi
        | NirOp::Interrupt
        | NirOp::Branch { .. }
        | NirOp::CondBranch { .. }
        | NirOp::Return
        | NirOp::Unmodeled { .. } => HirInstrStmt::Effect {
            expr: HirExpr::Unknown {
                text: instr.mnemonic.clone(),
            },
        },
    }
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
        NirOp::Call { .. } => instr.operands.first().cloned(),
        _ => None,
    };
    let arg_start: usize = usize::from(matches!(instr.op, NirOp::Call { .. }) && target.is_some());
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
    let hex: &str = body
        .strip_prefix("0x")
        .or_else(|| body.strip_prefix("0X"))
        .unwrap_or(body);
    if !hex.is_empty() && hex.bytes().all(|b: u8| b.is_ascii_hexdigit()) {
        return true;
    }
    !body.is_empty() && body.bytes().all(|b: u8| b.is_ascii_digit())
}

fn sequence(parts: Vec<HirStmt>) -> HirStmt {
    let mut flat: Vec<HirStmt> = Vec::with_capacity(parts.len());
    for part in parts {
        match part {
            HirStmt::Empty => {}
            HirStmt::Seq { body } => flat.extend(body),
            other => flat.push(other),
        }
    }
    match flat.len() {
        0 => HirStmt::Empty,
        1 => flat.into_iter().next().unwrap_or(HirStmt::Empty),
        _ => HirStmt::Seq { body: flat },
    }
}

fn collect_block_starts(stmt: &HirStmt, out: &mut BTreeSet<u64>) {
    match stmt {
        HirStmt::Leaf { block_start, .. } => {
            out.insert(*block_start);
        }
        HirStmt::Seq { body } => {
            for child in body {
                collect_block_starts(child, out);
            }
        }
        HirStmt::If {
            then_branch,
            else_branch,
            ..
        } => {
            collect_block_starts(then_branch, out);
            collect_block_starts(else_branch, out);
        }
        HirStmt::Loop { body, .. } => collect_block_starts(body, out),
        HirStmt::Dispatch { cases, .. } => {
            for case in cases {
                out.insert(case.block_start);
            }
        }
        HirStmt::Break { .. }
        | HirStmt::Continue { .. }
        | HirStmt::Return { .. }
        | HirStmt::Empty => {}
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
    match stmt {
        HirStmt::Leaf { stmts, .. } => {
            for leaf in stmts {
                out.push(leaf.instr.clone());
            }
        }
        HirStmt::Seq { body } => {
            for child in body {
                collect_instructions(child, out);
            }
        }
        HirStmt::If {
            then_branch,
            else_branch,
            ..
        } => {
            collect_instructions(then_branch, out);
            collect_instructions(else_branch, out);
        }
        HirStmt::Loop { body, .. } => collect_instructions(body, out),
        HirStmt::Dispatch { cases, .. } => {
            for case in cases {
                for leaf in &case.stmts {
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
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
}
