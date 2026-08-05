use std::collections::{BTreeMap, BTreeSet};

use disrobe_cfg as structuring;
use serde::{Deserialize, Serialize};

use super::decompile::{BlockStmt, Cfg, LiftedBlock, negate_cond};

const MAX_STRUCTURE_BLOCKS: usize = 4096;
const MAX_REGION_DEPTH: usize = 64;
const MAX_STRUCTURE_STATEMENTS: usize = 1 << 16;
const INDENT_STEP: &str = "  ";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StructureDecline {
    BlockBudgetExceeded,
    ControlFlowMidBlock,
    UnresolvedEdge,
    GraphRejected,
    Irreducible,
    UnsupportedRegion,
    LoopHasManyExits,
    IncompleteCover,
    DepthExceeded,
    StatementBudgetExceeded,
    UnsupportedBytecodeVersion,
}

impl StructureDecline {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BlockBudgetExceeded => "block-budget-exceeded",
            Self::ControlFlowMidBlock => "control-flow-mid-block",
            Self::UnresolvedEdge => "unresolved-edge",
            Self::GraphRejected => "graph-rejected",
            Self::Irreducible => "irreducible",
            Self::UnsupportedRegion => "unsupported-region",
            Self::LoopHasManyExits => "loop-has-many-exits",
            Self::IncompleteCover => "incomplete-cover",
            Self::DepthExceeded => "depth-exceeded",
            Self::StatementBudgetExceeded => "statement-budget-exceeded",
            Self::UnsupportedBytecodeVersion => "unsupported-bytecode-version",
        }
    }
}

#[derive(Debug, Clone)]
enum Term {
    Exit,
    Return(String),
    Throw(String),
    Goto(usize),
    Branch {
        cond: String,
        taken: usize,
        not_taken: usize,
    },
    Switch {
        scrutinee: String,
        cases: Vec<(i64, usize)>,
        default: usize,
    },
}

#[derive(Debug, Clone)]
struct SBlock {
    body: Vec<String>,
    term: Term,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sink {
    Exit,
    Break,
    Continue,
}

#[derive(Debug, Clone)]
enum JsStmt {
    Raw(String),
    Return(String),
    Throw(String),
    Break,
    Continue,
    If {
        cond: String,
        then: Vec<Self>,
        els: Vec<Self>,
    },
    Forever(Vec<Self>),
    While {
        cond: String,
        body: Vec<Self>,
    },
    DoWhile {
        body: Vec<Self>,
        cond: String,
    },
    Switch {
        scrutinee: String,
        arms: Vec<SwitchArm>,
    },
}

#[derive(Debug, Clone)]
struct SwitchArm {
    labels: Vec<i64>,
    is_default: bool,
    body: Vec<JsStmt>,
}

pub(crate) fn structure_function(
    lifted: &[LiftedBlock],
    cfg: &Cfg,
) -> Result<String, StructureDecline> {
    if lifted.is_empty() {
        return Ok(String::new());
    }
    if lifted.len() > MAX_STRUCTURE_BLOCKS {
        return Err(StructureDecline::BlockBudgetExceeded);
    }
    let blocks: Vec<SBlock> = lower_blocks(lifted, cfg)?;
    let sinks: BTreeMap<usize, Sink> = BTreeMap::new();
    let program: Vec<JsStmt> = structure_program(&blocks, &sinks, 0)?;
    let mut out: String = String::new();
    let mut budget: usize = MAX_STRUCTURE_STATEMENTS;
    render_stmts(&program, INDENT_STEP, &mut out, &mut budget)?;
    Ok(out)
}

fn lower_blocks(lifted: &[LiftedBlock], cfg: &Cfg) -> Result<Vec<SBlock>, StructureDecline> {
    if lifted.len() != cfg.blocks.len() {
        return Err(StructureDecline::UnresolvedEdge);
    }
    let block_of = |offset: usize| -> Result<usize, StructureDecline> {
        cfg.offset_to_block
            .get(&offset)
            .copied()
            .ok_or(StructureDecline::UnresolvedEdge)
    };
    let mut blocks: Vec<SBlock> = Vec::with_capacity(lifted.len());
    for (index, block) in lifted.iter().enumerate() {
        let mut body: Vec<String> = Vec::with_capacity(block.stmts.len());
        let mut term: Option<Term> = None;
        let last: usize = block.stmts.len().saturating_sub(1);
        for (position, stmt) in block.stmts.iter().enumerate() {
            let terminal: bool = position == last;
            match stmt {
                BlockStmt::Line(text) => body.push(text.clone()),
                BlockStmt::Return(value) if terminal => term = Some(Term::Return(value.clone())),
                BlockStmt::Throw(value) if terminal => term = Some(Term::Throw(value.clone())),
                BlockStmt::Jump(target) if terminal => term = Some(Term::Goto(block_of(*target)?)),
                BlockStmt::CondJump {
                    cond,
                    target,
                    fallthrough: Some(fallthrough),
                } if terminal => {
                    let taken: usize = block_of(*target)?;
                    let not_taken: usize = block_of(*fallthrough)?;
                    if taken == not_taken {
                        body.push(format!("{cond};"));
                        term = Some(Term::Goto(taken));
                    } else {
                        term = Some(Term::Branch {
                            cond: cond.clone(),
                            taken,
                            not_taken,
                        });
                    }
                }
                BlockStmt::Switch {
                    scrutinee,
                    cases,
                    default,
                } if terminal => {
                    let mut mapped: Vec<(i64, usize)> = Vec::with_capacity(cases.len());
                    for (value, target) in cases {
                        mapped.push((*value, block_of(*target)?));
                    }
                    term = Some(Term::Switch {
                        scrutinee: scrutinee.clone(),
                        cases: mapped,
                        default: block_of(*default)?,
                    });
                }
                _ => return Err(StructureDecline::ControlFlowMidBlock),
            }
        }
        let term: Term = match term {
            Some(term) => term,
            None => match cfg.blocks[index].successors.as_slice() {
                [] => Term::Exit,
                [single] => Term::Goto(*single),
                _ => return Err(StructureDecline::UnresolvedEdge),
            },
        };
        blocks.push(SBlock { body, term });
    }
    Ok(blocks)
}

fn successors_of(block: &SBlock) -> Vec<usize> {
    match &block.term {
        Term::Exit | Term::Return(_) | Term::Throw(_) => Vec::new(),
        Term::Goto(target) => vec![*target],
        Term::Branch {
            taken, not_taken, ..
        } => vec![*taken, *not_taken],
        Term::Switch { cases, default, .. } => {
            let mut out: Vec<usize> = Vec::with_capacity(cases.len() + 1);
            for (_, target) in cases {
                if !out.contains(target) {
                    out.push(*target);
                }
            }
            if !out.contains(default) {
                out.push(*default);
            }
            out
        }
    }
}

fn node_id(index: usize) -> Option<structuring::NodeId> {
    structuring::NodeId::try_from(index).ok()
}

fn cfg_from(blocks: &[SBlock]) -> Option<structuring::Cfg> {
    let count: usize = blocks.len();
    let mut nodes: Vec<structuring::CfgNode> = Vec::with_capacity(count);
    for (index, block) in blocks.iter().enumerate() {
        let term: structuring::Terminator = match &block.term {
            Term::Exit | Term::Return(_) | Term::Throw(_) => structuring::Terminator::Return,
            Term::Goto(target) => {
                if *target >= count {
                    return None;
                }
                structuring::Terminator::Goto(node_id(*target)?)
            }
            Term::Branch {
                taken, not_taken, ..
            } => {
                if *taken >= count || *not_taken >= count {
                    return None;
                }
                structuring::Terminator::Branch {
                    atom: node_id(index)?,
                    taken: node_id(*taken)?,
                    not_taken: node_id(*not_taken)?,
                }
            }
            Term::Switch { cases, default, .. } => {
                if *default >= count {
                    return None;
                }
                let mut mapped: Vec<(i64, structuring::NodeId)> = Vec::with_capacity(cases.len());
                for (value, target) in cases {
                    if *target >= count {
                        return None;
                    }
                    mapped.push((*value, node_id(*target)?));
                }
                structuring::Terminator::Switch {
                    atom: node_id(index)?,
                    cases: mapped,
                    default: Some(node_id(*default)?),
                }
            }
        };
        nodes.push(structuring::CfgNode {
            term,
            pure: block.body.is_empty(),
        });
    }
    structuring::Cfg::new(0, nodes).ok()
}

fn reachable_blocks(blocks: &[SBlock]) -> BTreeSet<usize> {
    let mut seen: BTreeSet<usize> = BTreeSet::new();
    if blocks.is_empty() {
        return seen;
    }
    let mut stack: Vec<usize> = vec![0];
    seen.insert(0);
    while let Some(node) = stack.pop() {
        let Some(block): Option<&SBlock> = blocks.get(node) else {
            continue;
        };
        for successor in successors_of(block) {
            if successor < blocks.len() && seen.insert(successor) {
                stack.push(successor);
            }
        }
    }
    seen
}

fn structure_program(
    blocks: &[SBlock],
    sinks: &BTreeMap<usize, Sink>,
    depth: usize,
) -> Result<Vec<JsStmt>, StructureDecline> {
    if depth >= MAX_REGION_DEPTH {
        return Err(StructureDecline::DepthExceeded);
    }
    let Some(cfg): Option<structuring::Cfg> = cfg_from(blocks) else {
        return Err(StructureDecline::GraphRejected);
    };
    let result: structuring::StructureResult = structuring::structure(&cfg);
    if !result.is_complete() {
        return Err(StructureDecline::Irreducible);
    }
    let Some(root): Option<structuring::RegionId> = result.root else {
        return Err(StructureDecline::Irreducible);
    };
    let forest: structuring::LoopForest = structuring::loop_forest(&cfg);
    let mut renderer: Renderer<'_> = Renderer {
        blocks,
        result: &result,
        forest: &forest,
        sinks,
        consumed: BTreeSet::new(),
        depth,
        failure: None,
    };
    let mut out: Vec<JsStmt> = Vec::new();
    if !renderer.render(root, &mut out) {
        return Err(renderer
            .failure
            .unwrap_or(StructureDecline::UnsupportedRegion));
    }
    if renderer.consumed != reachable_blocks(blocks) {
        return Err(StructureDecline::IncompleteCover);
    }
    Ok(out)
}

struct Renderer<'a> {
    blocks: &'a [SBlock],
    result: &'a structuring::StructureResult,
    forest: &'a structuring::LoopForest,
    sinks: &'a BTreeMap<usize, Sink>,
    consumed: BTreeSet<usize>,
    depth: usize,
    failure: Option<StructureDecline>,
}

impl Renderer<'_> {
    fn fail(&mut self, reason: StructureDecline) -> bool {
        if self.failure.is_none() {
            self.failure = Some(reason);
        }
        false
    }

    fn cond_text(&self, id: structuring::CondId) -> Option<String> {
        let node: &structuring::Cond = self.result.conds.nodes().get(id as usize)?;
        match node {
            structuring::Cond::Leaf(atom) => self.atom_text(*atom),
            structuring::Cond::NotLeaf(atom) => {
                self.atom_text(*atom).map(|c: String| negate_cond(&c))
            }
            structuring::Cond::And(left, right) => Some(format!(
                "({} && {})",
                self.cond_text(*left)?,
                self.cond_text(*right)?
            )),
            structuring::Cond::Or(left, right) => Some(format!(
                "({} || {})",
                self.cond_text(*left)?,
                self.cond_text(*right)?
            )),
        }
    }

    fn atom_text(&self, atom: structuring::Atom) -> Option<String> {
        let index: usize = usize::try_from(atom).ok()?;
        match &self.blocks.get(index)?.term {
            Term::Branch { cond, .. } => Some(cond.clone()),
            _ => None,
        }
    }

    fn render_sink(&self, entry: usize, out: &mut Vec<JsStmt>) {
        match self.sinks.get(&entry).copied().unwrap_or(Sink::Exit) {
            Sink::Break => out.push(JsStmt::Break),
            Sink::Continue => out.push(JsStmt::Continue),
            Sink::Exit => match &self.blocks[entry].term {
                Term::Return(value) => out.push(JsStmt::Return(value.clone())),
                Term::Throw(value) => out.push(JsStmt::Throw(value.clone())),
                _ => {}
            },
        }
    }

    fn render_leaf(&mut self, entry: usize, out: &mut Vec<JsStmt>) -> bool {
        if entry >= self.blocks.len() || !self.consumed.insert(entry) {
            return self.fail(StructureDecline::IncompleteCover);
        }
        for line in &self.blocks[entry].body {
            out.push(JsStmt::Raw(line.clone()));
        }
        if matches!(
            self.blocks[entry].term,
            Term::Exit | Term::Return(_) | Term::Throw(_)
        ) {
            self.render_sink(entry, out);
        }
        true
    }

    fn render_switch(
        &mut self,
        scrutinee_atom: structuring::Atom,
        children: &[structuring::RegionId],
        out: &mut Vec<JsStmt>,
    ) -> bool {
        let Some(head): Option<&structuring::RegionId> = children.first() else {
            return self.fail(StructureDecline::UnsupportedRegion);
        };
        if !self.render(*head, out) {
            return false;
        }
        let Some(node): Option<usize> = usize::try_from(scrutinee_atom).ok() else {
            return self.fail(StructureDecline::UnsupportedRegion);
        };
        let Some(block): Option<&SBlock> = self.blocks.get(node) else {
            return self.fail(StructureDecline::UnsupportedRegion);
        };
        let Term::Switch {
            scrutinee,
            cases,
            default,
        } = block.term.clone()
        else {
            return self.fail(StructureDecline::UnsupportedRegion);
        };

        let mut arm_region: BTreeMap<usize, structuring::RegionId> = BTreeMap::new();
        for child in &children[1..] {
            let Some(region): Option<&structuring::Region> =
                self.result.regions.get(*child as usize)
            else {
                return self.fail(StructureDecline::UnsupportedRegion);
            };
            let Some(target): Option<usize> = usize::try_from(region.entry).ok() else {
                return self.fail(StructureDecline::UnsupportedRegion);
            };
            if arm_region.insert(target, *child).is_some() {
                return self.fail(StructureDecline::UnsupportedRegion);
            }
        }

        let mut targets: Vec<usize> = Vec::with_capacity(cases.len() + 1);
        for (_, target) in &cases {
            if !targets.contains(target) {
                targets.push(*target);
            }
        }
        if !targets.contains(&default) {
            targets.push(default);
        }
        if arm_region
            .keys()
            .any(|target: &usize| !targets.contains(target))
        {
            return self.fail(StructureDecline::UnsupportedRegion);
        }

        let mut arms: Vec<SwitchArm> = Vec::with_capacity(targets.len());
        for target in targets {
            let labels: Vec<i64> = cases
                .iter()
                .filter(|(_, case_target): &&(i64, usize)| *case_target == target)
                .map(|(value, _): &(i64, usize)| *value)
                .collect();
            let mut body: Vec<JsStmt> = Vec::new();
            if let Some(region) = arm_region.get(&target).copied()
                && !self.render(region, &mut body)
            {
                return false;
            }
            arms.push(SwitchArm {
                labels,
                is_default: target == default,
                body,
            });
        }
        out.push(JsStmt::Switch { scrutinee, arms });
        true
    }

    fn render_loop(&mut self, header: usize, out: &mut Vec<JsStmt>) -> bool {
        let Some(natural): Option<&structuring::NaturalLoop> =
            self.forest
                .loops
                .iter()
                .find(|candidate: &&structuring::NaturalLoop| {
                    usize::try_from(candidate.header).ok() == Some(header)
                })
        else {
            return self.fail(StructureDecline::UnsupportedRegion);
        };
        let mut body: BTreeSet<usize> = BTreeSet::new();
        for node in &natural.body {
            let Some(index): Option<usize> = usize::try_from(*node).ok() else {
                return self.fail(StructureDecline::UnsupportedRegion);
            };
            body.insert(index);
        }
        let mut follow: Option<usize> = None;
        for node in &body {
            let Some(block): Option<&SBlock> = self.blocks.get(*node) else {
                return self.fail(StructureDecline::UnsupportedRegion);
            };
            for successor in successors_of(block) {
                if body.contains(&successor) {
                    continue;
                }
                match follow {
                    None => follow = Some(successor),
                    Some(existing) if existing == successor => {}
                    Some(_) => return self.fail(StructureDecline::LoopHasManyExits),
                }
            }
        }

        let mut order: Vec<usize> = vec![header];
        order.extend(body.iter().copied().filter(|node: &usize| *node != header));
        let index_of: BTreeMap<usize, usize> = order
            .iter()
            .enumerate()
            .map(|(position, node): (usize, &usize)| (*node, position))
            .collect();
        let continue_index: usize = order.len();
        let break_index: usize = order.len() + 1;
        let remap = |target: usize| -> Option<usize> {
            if target == header {
                return Some(continue_index);
            }
            if let Some(position) = index_of.get(&target) {
                return Some(*position);
            }
            if Some(target) == follow {
                return Some(break_index);
            }
            None
        };

        let mut sub_blocks: Vec<SBlock> = Vec::with_capacity(order.len() + 2);
        for node in &order {
            let source: &SBlock = &self.blocks[*node];
            let term: Term = match &source.term {
                Term::Exit => Term::Exit,
                Term::Return(value) => Term::Return(value.clone()),
                Term::Throw(value) => Term::Throw(value.clone()),
                Term::Goto(target) => {
                    let Some(mapped): Option<usize> = remap(*target) else {
                        return self.fail(StructureDecline::LoopHasManyExits);
                    };
                    Term::Goto(mapped)
                }
                Term::Branch {
                    cond,
                    taken,
                    not_taken,
                } => {
                    let (Some(mapped_taken), Some(mapped_not_taken)): (
                        Option<usize>,
                        Option<usize>,
                    ) = (remap(*taken), remap(*not_taken)) else {
                        return self.fail(StructureDecline::LoopHasManyExits);
                    };
                    Term::Branch {
                        cond: cond.clone(),
                        taken: mapped_taken,
                        not_taken: mapped_not_taken,
                    }
                }
                Term::Switch {
                    scrutinee,
                    cases,
                    default,
                } => {
                    let mut mapped_cases: Vec<(i64, usize)> = Vec::with_capacity(cases.len());
                    for (value, target) in cases {
                        let Some(mapped): Option<usize> = remap(*target) else {
                            return self.fail(StructureDecline::LoopHasManyExits);
                        };
                        mapped_cases.push((*value, mapped));
                    }
                    let Some(mapped_default): Option<usize> = remap(*default) else {
                        return self.fail(StructureDecline::LoopHasManyExits);
                    };
                    Term::Switch {
                        scrutinee: scrutinee.clone(),
                        cases: mapped_cases,
                        default: mapped_default,
                    }
                }
            };
            sub_blocks.push(SBlock {
                body: source.body.clone(),
                term,
            });
        }
        sub_blocks.push(SBlock {
            body: Vec::new(),
            term: Term::Exit,
        });
        sub_blocks.push(SBlock {
            body: Vec::new(),
            term: Term::Exit,
        });

        let mut sub_sinks: BTreeMap<usize, Sink> = BTreeMap::new();
        sub_sinks.insert(continue_index, Sink::Continue);
        sub_sinks.insert(break_index, Sink::Break);
        for node in &order {
            if let Some(existing) = self.sinks.get(node)
                && matches!(
                    self.blocks[*node].term,
                    Term::Exit | Term::Return(_) | Term::Throw(_)
                )
                && let Some(position) = index_of.get(node)
            {
                sub_sinks.insert(*position, *existing);
            }
        }

        let inner: Vec<JsStmt> = match structure_program(&sub_blocks, &sub_sinks, self.depth + 1) {
            Ok(inner) => inner,
            Err(reason) => return self.fail(reason),
        };
        out.push(resugar_loop(inner));
        for node in body {
            self.consumed.insert(node);
        }
        true
    }

    fn render(&mut self, id: structuring::RegionId, out: &mut Vec<JsStmt>) -> bool {
        if self.failure.is_some() {
            return false;
        }
        let Some(region): Option<&structuring::Region> = self.result.regions.get(id as usize)
        else {
            return self.fail(StructureDecline::UnsupportedRegion);
        };
        let kind: structuring::RegionKind = region.kind;
        let cond_id: Option<structuring::CondId> = region.cond;
        let scrutinee: Option<structuring::Atom> = region.scrutinee;
        let head: Option<structuring::RegionId> = region.head;
        let children: Vec<structuring::RegionId> = region.children.clone();
        let Some(entry): Option<usize> = usize::try_from(region.entry).ok() else {
            return self.fail(StructureDecline::UnsupportedRegion);
        };
        match kind {
            structuring::RegionKind::Block if children.is_empty() => self.render_leaf(entry, out),
            structuring::RegionKind::Block => children
                .iter()
                .all(|child: &structuring::RegionId| self.render(*child, out)),
            structuring::RegionKind::IfThen => {
                let (Some(head), Some(cond_id), Some(arm)): (
                    Option<structuring::RegionId>,
                    Option<structuring::CondId>,
                    Option<&structuring::RegionId>,
                ) = (head, cond_id, children.first()) else {
                    return self.fail(StructureDecline::UnsupportedRegion);
                };
                if !self.render(head, out) {
                    return false;
                }
                let Some(cond): Option<String> = self.cond_text(cond_id) else {
                    return self.fail(StructureDecline::UnsupportedRegion);
                };
                let mut then: Vec<JsStmt> = Vec::new();
                if !self.render(*arm, &mut then) {
                    return false;
                }
                out.push(JsStmt::If {
                    cond,
                    then,
                    els: Vec::new(),
                });
                true
            }
            structuring::RegionKind::IfThenElse => {
                let (Some(head), Some(cond_id)): (
                    Option<structuring::RegionId>,
                    Option<structuring::CondId>,
                ) = (head, cond_id) else {
                    return self.fail(StructureDecline::UnsupportedRegion);
                };
                let [taken, not_taken]: [structuring::RegionId; 2] = match children.as_slice() {
                    [taken, not_taken] => [*taken, *not_taken],
                    _ => return self.fail(StructureDecline::UnsupportedRegion),
                };
                if !self.render(head, out) {
                    return false;
                }
                let Some(cond): Option<String> = self.cond_text(cond_id) else {
                    return self.fail(StructureDecline::UnsupportedRegion);
                };
                let mut then: Vec<JsStmt> = Vec::new();
                if !self.render(taken, &mut then) {
                    return false;
                }
                let mut els: Vec<JsStmt> = Vec::new();
                if !self.render(not_taken, &mut els) {
                    return false;
                }
                out.push(JsStmt::If { cond, then, els });
                true
            }
            structuring::RegionKind::While
            | structuring::RegionKind::DoWhile
            | structuring::RegionKind::NaturalLoop
            | structuring::RegionKind::SelfLoop => self.render_loop(entry, out),
            structuring::RegionKind::Switch => {
                let Some(scrutinee): Option<structuring::Atom> = scrutinee else {
                    return self.fail(StructureDecline::UnsupportedRegion);
                };
                self.render_switch(scrutinee, &children, out)
            }
            structuring::RegionKind::Proper | structuring::RegionKind::Irreducible => {
                self.fail(StructureDecline::UnsupportedRegion)
            }
        }
    }
}

fn binds_break(stmts: &[JsStmt]) -> bool {
    stmts.iter().any(|stmt: &JsStmt| match stmt {
        JsStmt::Break => true,
        JsStmt::If { then, els, .. } => binds_break(then) || binds_break(els),
        JsStmt::Continue
        | JsStmt::Raw(_)
        | JsStmt::Return(_)
        | JsStmt::Throw(_)
        | JsStmt::Forever(_)
        | JsStmt::While { .. }
        | JsStmt::DoWhile { .. }
        | JsStmt::Switch { .. } => false,
    })
}

fn binds_continue(stmts: &[JsStmt]) -> bool {
    stmts.iter().any(|stmt: &JsStmt| match stmt {
        JsStmt::Continue => true,
        JsStmt::If { then, els, .. } => binds_continue(then) || binds_continue(els),
        JsStmt::Switch { arms, .. } => arms.iter().any(|arm: &SwitchArm| binds_continue(&arm.body)),
        JsStmt::Break
        | JsStmt::Raw(_)
        | JsStmt::Return(_)
        | JsStmt::Throw(_)
        | JsStmt::Forever(_)
        | JsStmt::While { .. }
        | JsStmt::DoWhile { .. } => false,
    })
}

fn strip_trailing_continues(mut body: Vec<JsStmt>) -> Vec<JsStmt> {
    while matches!(body.last(), Some(JsStmt::Continue)) {
        body.pop();
    }
    body
}

fn as_while_loop(body: &[JsStmt]) -> Option<JsStmt> {
    let [JsStmt::If { cond, then, els }, rest @ ..] = body else {
        return None;
    };
    let (guard, inner): (String, Vec<JsStmt>) = match (then.as_slice(), els.as_slice()) {
        ([JsStmt::Break], []) => (negate_cond(cond), rest.to_vec()),
        ([], [JsStmt::Break]) => (cond.clone(), rest.to_vec()),
        ([JsStmt::Break], taken) if rest.is_empty() => (negate_cond(cond), taken.to_vec()),
        (taken, [JsStmt::Break]) if rest.is_empty() => (cond.clone(), taken.to_vec()),
        _ => return None,
    };
    Some(JsStmt::While {
        cond: guard,
        body: strip_trailing_continues(inner),
    })
}

fn resugar_loop(body: Vec<JsStmt>) -> JsStmt {
    let body: Vec<JsStmt> = strip_trailing_continues(body);
    if let Some(guarded) = as_while_loop(&body) {
        return guarded;
    }
    if let Some(JsStmt::If { cond, then, els }) = body.last() {
        let repeat: Option<String> = match (then.as_slice(), els.as_slice()) {
            ([JsStmt::Continue], [] | [JsStmt::Break]) => Some(cond.clone()),
            ([JsStmt::Break], [] | [JsStmt::Continue]) => Some(negate_cond(cond)),
            _ => None,
        };
        if let Some(repeat) = repeat {
            let prefix: &[JsStmt] = &body[..body.len() - 1];
            if !binds_break(prefix) && !binds_continue(prefix) {
                return JsStmt::DoWhile {
                    body: prefix.to_vec(),
                    cond: repeat,
                };
            }
        }
    }
    JsStmt::Forever(body)
}

fn terminates(stmts: &[JsStmt]) -> bool {
    matches!(
        stmts.last(),
        Some(JsStmt::Return(_) | JsStmt::Throw(_) | JsStmt::Break | JsStmt::Continue)
    )
}

fn render_stmts(
    stmts: &[JsStmt],
    indent: &str,
    out: &mut String,
    budget: &mut usize,
) -> Result<(), StructureDecline> {
    let nested: String = format!("{indent}{INDENT_STEP}");
    for stmt in stmts {
        if *budget == 0 {
            return Err(StructureDecline::StatementBudgetExceeded);
        }
        *budget -= 1;
        match stmt {
            JsStmt::Raw(text) => push_line(out, indent, text),
            JsStmt::Return(value) => {
                if value == "undefined" {
                    push_line(out, indent, "return;");
                } else {
                    push_line(out, indent, &format!("return {value};"));
                }
            }
            JsStmt::Throw(value) => push_line(out, indent, &format!("throw {value};")),
            JsStmt::Break => push_line(out, indent, "break;"),
            JsStmt::Continue => push_line(out, indent, "continue;"),
            JsStmt::If { cond, then, els } => {
                push_line(out, indent, &format!("if ({cond}) {{"));
                render_stmts(then, &nested, out, budget)?;
                if !els.is_empty() {
                    push_line(out, indent, "} else {");
                    render_stmts(els, &nested, out, budget)?;
                }
                push_line(out, indent, "}");
            }
            JsStmt::Forever(body) => {
                push_line(out, indent, "for (;;) {");
                render_stmts(body, &nested, out, budget)?;
                push_line(out, indent, "}");
            }
            JsStmt::While { cond, body } => {
                push_line(out, indent, &format!("while ({cond}) {{"));
                render_stmts(body, &nested, out, budget)?;
                push_line(out, indent, "}");
            }
            JsStmt::DoWhile { body, cond } => {
                push_line(out, indent, "do {");
                render_stmts(body, &nested, out, budget)?;
                push_line(out, indent, &format!("}} while ({cond});"));
            }
            JsStmt::Switch { scrutinee, arms } => {
                let arm_indent: String = format!("{nested}{INDENT_STEP}");
                push_line(out, indent, &format!("switch ({scrutinee}) {{"));
                for arm in arms {
                    for label in &arm.labels {
                        push_line(out, &nested, &format!("case {label}:"));
                    }
                    if arm.is_default {
                        push_line(out, &nested, "default:");
                    }
                    render_stmts(&arm.body, &arm_indent, out, budget)?;
                    if !terminates(&arm.body) {
                        push_line(out, &arm_indent, "break;");
                    }
                }
                push_line(out, indent, "}");
            }
        }
    }
    Ok(())
}

fn push_line(out: &mut String, indent: &str, text: &str) {
    out.push_str(indent);
    out.push_str(text);
    out.push('\n');
}
