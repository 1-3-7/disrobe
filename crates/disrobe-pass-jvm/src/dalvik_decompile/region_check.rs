use std::collections::{BTreeMap, BTreeSet};

use crate::dalvik::DalvikInsn;
use crate::decompile_struct::{
    BasicBlock, BlockId, Cfg, EdgeKind, PrecomputedSwitch, Region, SwitchKey,
};

const MAX_TRAMPOLINE_STEPS: usize = 64;
const MAX_REGION_DEPTH: usize = 512;
const MAX_REGION_NODES: usize = 100_000;
const MAX_SWITCH_VALUES: usize = 65_536;
const RETURN_VOID: u8 = 0x0E;
const THROWABLE: [&str; 2] = ["Ljava/lang/Throwable;", "java/lang/Throwable"];

pub(super) type Defect = &'static str;

const TOO_LARGE: Defect = "the structured control flow is too large to check against the bytecode";
const UNMODELLED: Defect = "a structured region has no Dalvik source form";
const MISSING_BLOCK: Defect = "a structured region names a block the method does not have";
const EDGE: Defect = "a structured region sends control somewhere the bytecode does not go";
const ENTRY: Defect = "the structured method does not start where the bytecode starts";
const PLACED_TWICE: Defect =
    "a block is placed twice in the structured method, so one copy would lose its statements";
const BRANCH_AS_BLOCK: Defect =
    "a branch is rendered as a straight-line block, so one of its targets is lost";
const NOT_A_BRANCH: Defect = "a structured condition is not a two-way branch in the bytecode";
const HANDLER: Defect =
    "a throwing instruction reaches different catch handlers in the structured method";
const RETHROW: Defect =
    "a rethrown exception reaches a different catch handler than the bytecode jumps to";
const SWITCH: Defect = "a structured switch dispatches a value somewhere the bytecode does not";
const JUMP: Defect = "a break or continue has no enclosing statement it can leave";

pub(super) type HandlerClause = (Option<String>, BlockId);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Block(BlockId),
    Exit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameKind {
    Loop(BlockId),
    Switch,
    Labelled,
}

#[derive(Debug, Clone, Copy)]
struct Frame {
    label: Option<u32>,
    kind: FrameKind,
    exit: Target,
}

type Clause = (Option<String>, Target);

pub(super) struct RegionInputs<'a> {
    pub(super) cfg: &'a Cfg,
    pub(super) insns: &'a [DalvikInsn],
    pub(super) switches: &'a BTreeMap<BlockId, PrecomputedSwitch>,
    pub(super) duplicated: &'a BTreeSet<BlockId>,
    pub(super) split_heads: &'a BTreeSet<BlockId>,
    pub(super) string_switches: &'a BTreeMap<BlockId, BlockId>,
    pub(super) rethrows: &'a BTreeSet<BlockId>,
    pub(super) headless_loops: bool,
}

pub(super) fn region_defect(inputs: &RegionInputs<'_>, root: &Region) -> Option<Defect> {
    let mut check: RegionCheck<'_> = RegionCheck {
        inputs,
        frames: Vec::new(),
        catches: Vec::new(),
        placed: BTreeSet::new(),
        retests: BTreeSet::new(),
        guarded: BTreeSet::new(),
        label: None,
        nodes: 0,
    };
    let entry: Target = match check.entry(root, Target::Exit) {
        Ok(entry) => entry,
        Err(defect) => return Some(defect),
    };
    if check
        .expect(Target::Block(inputs.cfg.entry), entry)
        .is_err()
    {
        return Some(ENTRY);
    }
    check.check(root, Target::Exit, 0).err()
}

pub(super) fn rethrows_caught(
    rethrows: &BTreeSet<BlockId>,
    handlers: &[(Vec<String>, Region)],
) -> bool {
    fn first_block(region: &Region) -> Option<BlockId> {
        match region {
            Region::Block(block) => Some(*block),
            Region::Sequence(items) => items.first().and_then(first_block),
            _ => None,
        }
    }
    handlers.iter().any(|(_, handler): &(Vec<String>, Region)| {
        first_block(handler).is_some_and(|block: BlockId| rethrows.contains(&block))
    })
}

pub(super) fn is_throwable(name: &str) -> bool {
    THROWABLE.contains(&name)
}

pub(super) fn handler_clauses(cfg: &Cfg, pc: u32) -> Vec<HandlerClause> {
    let mut clauses: Vec<HandlerClause> = Vec::new();
    for region in &cfg.exception_regions {
        if pc < region.try_start_pc || pc >= region.try_end_pc {
            continue;
        }
        let Some(&handler): Option<&BlockId> = cfg.pc_to_block.get(&region.handler_pc) else {
            continue;
        };
        match &region.catch_type {
            Some(name) if !is_throwable(name) => {
                if !clauses
                    .iter()
                    .any(|(known, _): &HandlerClause| known.as_ref() == Some(name))
                {
                    clauses.push((Some(name.clone()), handler));
                }
            }
            _ => {
                clauses.push((None, handler));
                return clauses;
            }
        }
    }
    clauses
}

struct RegionCheck<'a> {
    inputs: &'a RegionInputs<'a>,
    frames: Vec<Frame>,
    catches: Vec<Vec<(Vec<String>, Target)>>,
    placed: BTreeSet<BlockId>,
    retests: BTreeSet<BlockId>,
    guarded: BTreeSet<BlockId>,
    label: Option<u32>,
    nodes: usize,
}

impl RegionCheck<'_> {
    fn block(&self, id: BlockId) -> Result<&BasicBlock, Defect> {
        self.inputs
            .cfg
            .blocks
            .get(id.0 as usize)
            .ok_or(MISSING_BLOCK)
    }

    fn body(&self, block: &BasicBlock) -> &[DalvikInsn] {
        self.inputs
            .insns
            .get(block.insn_range.0..block.insn_range.1)
            .unwrap_or_default()
    }

    fn normal_targets(block: &BasicBlock) -> Vec<BlockId> {
        let mut targets: Vec<BlockId> = Vec::new();
        for edge in &block.successors {
            if !matches!(edge.kind, EdgeKind::Exception) && !targets.contains(&edge.target) {
                targets.push(edge.target);
            }
        }
        targets
    }

    fn canonical(&self, target: Target) -> Result<Target, Defect> {
        let Target::Block(mut current) = target else {
            return Ok(Target::Exit);
        };
        for _ in 0..MAX_TRAMPOLINE_STEPS {
            let block: &BasicBlock = self.block(current)?;
            let body: &[DalvikInsn] = self.body(block);
            if let [only] = body
                && only.op == RETURN_VOID
            {
                return Ok(Target::Exit);
            }
            let trampoline: bool = body
                .iter()
                .all(|insn: &DalvikInsn| insn.is_unconditional_goto());
            let targets: Vec<BlockId> = Self::normal_targets(block);
            match targets.as_slice() {
                [next] if trampoline && *next != current => current = *next,
                _ => return Ok(Target::Block(current)),
            }
        }
        Ok(Target::Block(current))
    }

    fn expect(&self, bytecode: Target, structured: Target) -> Result<(), Defect> {
        let bytecode: Target = self.canonical(bytecode)?;
        let structured: Target = self.canonical(structured)?;
        if bytecode == structured {
            Ok(())
        } else {
            Err(EDGE)
        }
    }

    fn frame(&self, label: Option<u32>, continues: bool) -> Result<Frame, Defect> {
        self.frames
            .iter()
            .rev()
            .find(|frame: &&Frame| {
                let kind_fits: bool = match frame.kind {
                    FrameKind::Loop(_) => true,
                    FrameKind::Switch => !continues,
                    FrameKind::Labelled => !continues && label.is_some(),
                };
                kind_fits && (label.is_none() || frame.label == label)
            })
            .copied()
            .ok_or(JUMP)
    }

    fn continue_target(&self, label: Option<u32>) -> Result<BlockId, Defect> {
        match self.frame(label, true)?.kind {
            FrameKind::Loop(header) => Ok(header),
            FrameKind::Switch | FrameKind::Labelled => Err(JUMP),
        }
    }

    fn entry(&self, region: &Region, next: Target) -> Result<Target, Defect> {
        Ok(match region {
            Region::Block(block) => Target::Block(*block),
            Region::Sequence(items) => match items.iter().find(|item: &&Region| !is_empty(item)) {
                Some(first) => self.entry(first, Target::Exit)?,
                None => next,
            },
            Region::IfThen { head, .. }
            | Region::IfThenElse { head, .. }
            | Region::Switch { head, .. } => Target::Block(*head),
            Region::While { header, .. } => Target::Block(*header),
            Region::DoWhile { header, body, .. } => {
                if self.inputs.headless_loops {
                    self.entry(body, Target::Block(*header))?
                } else {
                    Target::Block(*header)
                }
            }
            Region::Try { try_body, .. } => self.entry(try_body, next)?,
            Region::Synchronized { lock_block, .. } => Target::Block(*lock_block),
            Region::LabeledLoop { body, .. } => self.entry(body, next)?,
            Region::Break { label } => self.frame(*label, false)?.exit,
            Region::Continue { label, latch } => {
                Target::Block(latch.map_or_else(|| self.continue_target(*label), Ok)?)
            }
            Region::TryFinally { .. }
            | Region::TryWithResources { .. }
            | Region::Irreducible { .. } => return Err(UNMODELLED),
        })
    }

    fn place(&mut self, block: BlockId) -> Result<(), Defect> {
        if self.placed.insert(block) || self.inputs.duplicated.contains(&block) {
            Ok(())
        } else {
            Err(PLACED_TWICE)
        }
    }

    fn place_head(&mut self, head: BlockId) -> Result<(), Defect> {
        if self.retests.remove(&head) {
            return Ok(());
        }
        if self.placed.insert(head) {
            return self.guard(head);
        }
        let only_branch: bool = self.body(self.block(head)?).len() == 1;
        if self.inputs.duplicated.contains(&head) && only_branch {
            self.guard(head)
        } else {
            Err(PLACED_TWICE)
        }
    }

    fn guard(&self, block: BlockId) -> Result<(), Defect> {
        if self.guarded.contains(&block) {
            return Ok(());
        }
        let structured: Vec<Clause> = self.structured_clauses();
        for insn in self.body(self.block(block)?) {
            if !super::may_throw(insn) {
                continue;
            }
            let bytecode: Vec<HandlerClause> = handler_clauses(self.inputs.cfg, insn.pc);
            let same: bool = bytecode.len() == structured.len()
                && bytecode.iter().zip(&structured).all(
                    |((bytecode_type, handler), (structured_type, entry)): (
                        &HandlerClause,
                        &Clause,
                    )| {
                        bytecode_type == structured_type
                            && self.expect(Target::Block(*handler), *entry).is_ok()
                    },
                );
            if !same {
                return Err(HANDLER);
            }
        }
        Ok(())
    }

    fn structured_clauses(&self) -> Vec<Clause> {
        let mut clauses: Vec<Clause> = Vec::new();
        for frame in self.catches.iter().rev() {
            for (types, entry) in frame {
                let catches_all: bool =
                    types.is_empty() || types.iter().any(|name: &String| is_throwable(name));
                if catches_all {
                    clauses.push((None, *entry));
                    return clauses;
                }
                for name in types {
                    if !clauses
                        .iter()
                        .any(|(known, _): &Clause| known.as_ref() == Some(name))
                    {
                        clauses.push((Some(name.clone()), *entry));
                    }
                }
            }
        }
        clauses
    }

    fn leave_block(&self, block: BlockId, next: Target) -> Result<(), Defect> {
        let found: &BasicBlock = self.block(block)?;
        let last: Option<&DalvikInsn> = self.body(found).last();
        if last.is_some_and(|insn: &DalvikInsn| insn.is_return() || insn.is_throw()) {
            return Ok(());
        }
        if let Some(&index_head) = self.inputs.string_switches.get(&block) {
            return self.expect(Target::Block(index_head), next);
        }
        let targets: Vec<BlockId> = Self::normal_targets(found);
        for target in &targets {
            self.expect(Target::Block(*target), next)
                .map_err(|defect: Defect| {
                    if targets.len() > 1 {
                        BRANCH_AS_BLOCK
                    } else {
                        defect
                    }
                })?;
        }
        Ok(())
    }

    fn rethrow_landings(&self, handlers: &[(Vec<String>, Region)]) -> Result<Vec<Target>, Defect> {
        let outer: Vec<Clause> = self.structured_clauses();
        let mut excluded: Vec<String> = Vec::new();
        let mut landings: Vec<Target> = Vec::with_capacity(handlers.len());
        for (types, _) in handlers {
            let caught: Option<&String> = match types.as_slice() {
                [] => None,
                [name] if is_throwable(name) => None,
                [name] => Some(name),
                _ => return Err(RETHROW),
            };
            let mut landing: Option<Target> = None;
            for (outer_type, entry) in &outer {
                match outer_type {
                    Some(name) if excluded.contains(name) => {}
                    Some(name) if Some(name) == caught => {
                        landing = Some(*entry);
                        break;
                    }
                    None => {
                        landing = Some(*entry);
                        break;
                    }
                    Some(_) => return Err(RETHROW),
                }
            }
            landings.push(landing.ok_or(RETHROW)?);
            excluded.extend(caught.cloned());
        }
        Ok(landings)
    }

    fn branch_targets(&self, head: BlockId) -> Result<(BlockId, BlockId), Defect> {
        let block: &BasicBlock = self.block(head)?;
        let mut taken: Option<BlockId> = None;
        let mut fallthrough: Option<BlockId> = None;
        for edge in &block.successors {
            match edge.kind {
                EdgeKind::CondTrue => taken = Some(edge.target),
                EdgeKind::CondFalse => fallthrough = Some(edge.target),
                _ => {}
            }
        }
        let branches: bool = self
            .body(block)
            .last()
            .is_some_and(DalvikInsn::is_conditional_branch);
        match (taken, fallthrough) {
            (Some(taken), Some(fallthrough)) if branches => Ok((taken, fallthrough)),
            _ => Err(NOT_A_BRANCH),
        }
    }

    fn check(&mut self, region: &Region, next: Target, depth: usize) -> Result<(), Defect> {
        self.nodes += 1;
        if self.nodes > MAX_REGION_NODES || depth > MAX_REGION_DEPTH {
            return Err(TOO_LARGE);
        }
        let label: Option<u32> = self.label.take();
        match region {
            Region::Block(block) => {
                self.place(*block)?;
                self.guard(*block)?;
                self.leave_block(*block, next)
            }
            Region::Sequence(items) => {
                let mut continuations: Vec<Target> = Vec::with_capacity(items.len());
                let mut after: Target = next;
                for item in items.iter().rev() {
                    continuations.push(after);
                    after = self.entry(item, after)?;
                }
                for (item, continuation) in items.iter().zip(continuations.into_iter().rev()) {
                    self.check(item, continuation, depth + 1)?;
                }
                Ok(())
            }
            Region::IfThen {
                head,
                then_body,
                cond_negated,
                ..
            } => {
                self.place_head(*head)?;
                let (taken, fallthrough): (BlockId, BlockId) = self.branch_targets(*head)?;
                let (enters, skips): (BlockId, BlockId) = if *cond_negated {
                    (taken, fallthrough)
                } else {
                    (fallthrough, taken)
                };
                let then_entry: Target = self.entry(then_body, next)?;
                self.expect(Target::Block(enters), then_entry)?;
                self.expect(Target::Block(skips), next)?;
                self.check(then_body, next, depth + 1)
            }
            Region::IfThenElse {
                head,
                then_body,
                else_body,
                ..
            } => {
                self.place_head(*head)?;
                let (taken, fallthrough): (BlockId, BlockId) = self.branch_targets(*head)?;
                let then_entry: Target = self.entry(then_body, next)?;
                let else_entry: Target = self.entry(else_body, next)?;
                self.expect(Target::Block(fallthrough), then_entry)?;
                self.expect(Target::Block(taken), else_entry)?;
                self.check(then_body, next, depth + 1)?;
                self.check(else_body, next, depth + 1)
            }
            Region::While { header, body, exit } => {
                self.place(*header)?;
                self.guard(*header)?;
                let (taken, fallthrough): (BlockId, BlockId) = self.branch_targets(*header)?;
                let (stay, leave): (BlockId, BlockId) = if *exit == Some(taken) {
                    (fallthrough, taken)
                } else {
                    (taken, fallthrough)
                };
                self.expect(Target::Block(leave), next)?;
                self.loop_body(label, *header, body, next, Some(stay), depth)
            }
            Region::DoWhile { header, body, .. } => {
                if self.inputs.headless_loops {
                    return self.headless_loop(label, *header, body, next, depth);
                }
                self.place(*header)?;
                self.guard(*header)?;
                self.loop_body(label, *header, body, next, None, depth)
            }
            Region::Switch {
                head,
                cases,
                default,
                fallthrough,
                default_position,
                ..
            } => {
                self.place_head(*head)?;
                let mut arms: Vec<(Option<usize>, &Region)> = cases
                    .iter()
                    .enumerate()
                    .map(|(index, (_, body)): (usize, &(SwitchKey, Region))| (Some(index), body))
                    .collect();
                if let Some(body) = default {
                    arms.insert((*default_position).min(arms.len()), (None, body));
                }
                let mut continuations: Vec<Target> = vec![next; arms.len()];
                let mut entries: Vec<Target> = vec![next; arms.len()];
                let mut following: Target = next;
                for (index, (position, body)) in arms.iter().enumerate().rev() {
                    let position: usize = position.unwrap_or(cases.len());
                    let breaks: bool = !fallthrough.contains(&position)
                        && super::region_completes(self.inputs.cfg, self.inputs.insns, body);
                    let continuation: Target = if breaks { next } else { following };
                    following = self.entry(body, continuation)?;
                    continuations[index] = continuation;
                    entries[index] = following;
                }
                let mut dispatch: BTreeMap<i32, Target> = BTreeMap::new();
                let mut otherwise: Target = next;
                for ((position, _), entry) in arms.iter().zip(&entries) {
                    match position {
                        Some(index) => {
                            let (key, _): &(SwitchKey, Region) = cases.get(*index).ok_or(SWITCH)?;
                            for value in key_values(key)? {
                                dispatch.insert(value, *entry);
                            }
                        }
                        None => otherwise = *entry,
                    }
                }
                self.switch_dispatch(*head, &dispatch, otherwise)?;
                self.frames.push(Frame {
                    label: None,
                    kind: FrameKind::Switch,
                    exit: next,
                });
                let mut verdict: Result<(), Defect> = Ok(());
                for ((_, body), continuation) in arms.iter().zip(continuations) {
                    verdict = self.check(body, continuation, depth + 1);
                    if verdict.is_err() {
                        break;
                    }
                }
                self.frames.pop();
                verdict
            }
            Region::Try { try_body, handlers } => {
                if let Some(head) = super::leading_branch_head(try_body)
                    && self.inputs.split_heads.contains(&head)
                {
                    self.guard(head)?;
                    self.guarded.insert(head);
                }
                let continuations: Vec<Target> = if rethrows_caught(self.inputs.rethrows, handlers)
                {
                    self.rethrow_landings(handlers)?
                } else {
                    vec![next; handlers.len()]
                };
                let mut clauses: Vec<(Vec<String>, Target)> = Vec::with_capacity(handlers.len());
                for ((types, handler), continuation) in handlers.iter().zip(&continuations) {
                    clauses.push((types.clone(), self.entry(handler, *continuation)?));
                }
                self.catches.push(clauses);
                let verdict: Result<(), Defect> = self.check(try_body, next, depth + 1);
                self.catches.pop();
                verdict?;
                for ((_, handler), continuation) in handlers.iter().zip(continuations) {
                    self.check(handler, continuation, depth + 1)?;
                }
                Ok(())
            }
            Region::Synchronized {
                lock_block, body, ..
            } => {
                let body_entry: Target = self.entry(body, next)?;
                if !self.retests.remove(lock_block) {
                    self.place(*lock_block)?;
                    self.guard(*lock_block)?;
                }
                self.leave_block(*lock_block, body_entry)?;
                self.check(body, next, depth + 1)
            }
            Region::LabeledLoop { label, body } => {
                if matches!(**body, Region::While { .. } | Region::DoWhile { .. }) {
                    self.label = Some(*label);
                    return self.check(body, next, depth + 1);
                }
                self.frames.push(Frame {
                    label: Some(*label),
                    kind: FrameKind::Labelled,
                    exit: next,
                });
                let verdict: Result<(), Defect> = self.check(body, next, depth + 1);
                self.frames.pop();
                verdict
            }
            Region::Break { label } => self.frame(*label, false).map(|_| ()),
            Region::Continue { label, latch } => {
                let header: BlockId = self.continue_target(*label)?;
                if let Some(latch) = latch {
                    self.place(*latch)?;
                    self.guard(*latch)?;
                    self.leave_block(*latch, Target::Block(header))?;
                }
                Ok(())
            }
            Region::TryFinally { .. }
            | Region::TryWithResources { .. }
            | Region::Irreducible { .. } => Err(UNMODELLED),
        }
    }

    fn loop_body(
        &mut self,
        label: Option<u32>,
        header: BlockId,
        body: &Region,
        next: Target,
        stay: Option<BlockId>,
        depth: usize,
    ) -> Result<(), Defect> {
        self.frames.push(Frame {
            label,
            kind: FrameKind::Loop(header),
            exit: next,
        });
        let verdict: Result<(), Defect> = self
            .loop_entry(header, body, stay)
            .and_then(|()| self.check(body, Target::Block(header), depth + 1));
        self.frames.pop();
        self.retests.remove(&header);
        verdict
    }

    fn headless_loop(
        &mut self,
        label: Option<u32>,
        header: BlockId,
        body: &Region,
        next: Target,
        depth: usize,
    ) -> Result<(), Defect> {
        self.frames.push(Frame {
            label,
            kind: FrameKind::Loop(header),
            exit: next,
        });
        let verdict: Result<(), Defect> = self
            .entry(body, Target::Block(header))
            .and_then(|entry: Target| self.expect(Target::Block(header), entry))
            .and_then(|()| self.check(body, Target::Block(header), depth + 1));
        self.frames.pop();
        verdict
    }

    fn loop_entry(
        &mut self,
        header: BlockId,
        body: &Region,
        stay: Option<BlockId>,
    ) -> Result<(), Defect> {
        let body_entry: Target = self.entry(body, Target::Block(header))?;
        if leading_block(body) == Some(header) {
            self.retests.insert(header);
            return Ok(());
        }
        match stay {
            Some(stay) => self.expect(Target::Block(stay), body_entry),
            None => self.leave_block(header, body_entry),
        }
    }

    fn switch_dispatch(
        &self,
        head: BlockId,
        dispatch: &BTreeMap<i32, Target>,
        otherwise: Target,
    ) -> Result<(), Defect> {
        let table: &PrecomputedSwitch = self.inputs.switches.get(&head).ok_or(SWITCH)?;
        let default: BlockId = table.default.ok_or(SWITCH)?;
        self.expect(Target::Block(default), otherwise)
            .map_err(|_| SWITCH)?;
        let mut bytecode: BTreeMap<i32, BlockId> = BTreeMap::new();
        for (key, target) in &table.cases {
            for value in key_values(key)? {
                bytecode.insert(value, *target);
            }
        }
        let values: BTreeSet<i32> = bytecode.keys().chain(dispatch.keys()).copied().collect();
        for value in values {
            let expected: BlockId = bytecode.get(&value).copied().unwrap_or(default);
            let rendered: Target = dispatch.get(&value).copied().unwrap_or(otherwise);
            self.expect(Target::Block(expected), rendered)
                .map_err(|_| SWITCH)?;
        }
        Ok(())
    }
}

fn is_empty(region: &Region) -> bool {
    match region {
        Region::Sequence(items) => items.iter().all(is_empty),
        Region::Try { try_body, .. } => is_empty(try_body),
        Region::LabeledLoop { body, .. } => {
            !matches!(**body, Region::While { .. } | Region::DoWhile { .. }) && is_empty(body)
        }
        _ => false,
    }
}

fn leading_block(region: &Region) -> Option<BlockId> {
    match region {
        Region::Sequence(items) => items.first().and_then(leading_block),
        Region::IfThen { head, .. }
        | Region::IfThenElse { head, .. }
        | Region::Switch { head, .. } => Some(*head),
        Region::Synchronized { lock_block, .. } => Some(*lock_block),
        _ => None,
    }
}

pub(super) fn key_values(key: &SwitchKey) -> Result<Vec<i32>, Defect> {
    match key {
        SwitchKey::Range { low, high } => {
            let span: usize =
                usize::try_from(i64::from(*high) - i64::from(*low)).map_err(|_| SWITCH)?;
            if span >= MAX_SWITCH_VALUES {
                return Err(SWITCH);
            }
            Ok((*low..=*high).collect())
        }
        SwitchKey::Values(values) if !values.is_empty() => Ok(values.clone()),
        SwitchKey::Values(_) => Err(SWITCH),
    }
}
