use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::bytecode::{ExceptionEntry, Instruction, Operands};

const OP_JSR: u8 = 0xA8;
const OP_JSR_W: u8 = 0xC9;
const OP_RET: u8 = 0xA9;
const OP_GOTO: u8 = 0xA7;
const OP_GOTO_W: u8 = 0xC8;
const OP_ASTORE: u8 = 0x3A;
const OP_ASTORE_0: u8 = 0x4B;
const OP_ASTORE_3: u8 = 0x4E;
const OP_POP: u8 = 0x57;
const OP_ATHROW: u8 = 0xBF;
const OP_TABLESWITCH: u8 = 0xAA;
const OP_LOOKUPSWITCH: u8 = 0xAB;
const MAX_INLINE_DEPTH: usize = 64;
const MAX_OUTPUT: usize = 1_000_000;
const MAX_HANDLER_COVERAGE: usize = 4_000_000;
const MAX_REMAP_WORK: usize = 64_000_000;

const JSR_TARGET_UNRESOLVED: &str =
    "a jsr subroutine could not be inlined: a jsr targets a pc that is not an instruction";
const RET_OUTSIDE_SUBROUTINE: &str =
    "a jsr subroutine could not be inlined: a ret is reachable outside every subroutine";
const SHARED_WITH_CALLER: &str =
    "a jsr subroutine could not be inlined: its instructions are also reached without a jsr";
const SHARED_SUBROUTINES: &str =
    "a jsr subroutine could not be inlined: two subroutines share instructions";
const NO_RETURN_ADDRESS_STORE: &str = "a jsr subroutine could not be inlined: it does not store or discard its return address on entry";
const FOREIGN_RET: &str = "a jsr subroutine could not be inlined: a ret returns through a local other than the one its subroutine stored";
const RETURN_ADDRESS_REUSED: &str =
    "a jsr subroutine could not be inlined: it reads or overwrites its return-address local";
const FALLS_OFF_CODE: &str =
    "a jsr subroutine could not be inlined: a path through it falls off the end of the code";
const TOO_DEEP: &str =
    "a jsr subroutine could not be inlined: subroutines nest or recurse past the inlining bound";
const TOO_LARGE: &str =
    "a jsr subroutine could not be inlined: the inlined method exceeds the output bound";
const UNRESOLVED_BRANCH: &str =
    "a jsr subroutine could not be inlined: a branch in the inlined code has no target";
const UNPLACED_HANDLER: &str =
    "a jsr subroutine could not be inlined: an exception handler has no place in the inlined code";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsrInlineReport {
    pub jsr_sites: usize,
    pub subroutines: usize,
    pub inlined_instructions: usize,
    pub bailed: bool,
    pub note: String,
}

#[must_use]
pub fn contains_jsr(insns: &[Instruction]) -> bool {
    insns.iter().any(|i: &Instruction| is_jsr_or_ret(i.opcode))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsrInlined {
    pub insns: Vec<Instruction>,
    pub exception_table: Vec<ExceptionEntry>,
    pub report: JsrInlineReport,
    pub refusal: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Target {
    scope: usize,
    pc: u32,
}

struct Emitted {
    opcode: u8,
    mnemonic: &'static str,
    wide: bool,
    operands: Operands,
    old_pc: u32,
    scope: usize,
    target: Option<Target>,
    switch_targets: Vec<Target>,
    ret_of: Option<usize>,
}

struct Subroutine {
    entry: usize,
    body: BTreeSet<usize>,
}

struct Scope {
    subroutine: Option<usize>,
    parent: usize,
    returns_to: Option<Target>,
    labels: BTreeMap<u32, usize>,
}

const MAIN_SCOPE: usize = 0;

#[must_use]
pub fn inline_jsr_subroutines(
    insns: &[Instruction],
    exception_table: &[ExceptionEntry],
) -> JsrInlined {
    let jsr_sites: usize = insns
        .iter()
        .filter(|i: &&Instruction| i.opcode == OP_JSR || i.opcode == OP_JSR_W)
        .count();
    if !contains_jsr(insns) {
        return JsrInlined {
            insns: insns.to_vec(),
            exception_table: exception_table.to_vec(),
            report: JsrInlineReport {
                jsr_sites: 0,
                subroutines: 0,
                inlined_instructions: insns.len(),
                bailed: false,
                note: "no jsr subroutines present".to_owned(),
            },
            refusal: None,
        };
    }
    match Inliner::plan(insns, exception_table).and_then(|mut inliner: Inliner<'_>| {
        inliner.emit_main()?;
        let out: Vec<Instruction> = inliner.renumber()?;
        let table: Vec<ExceptionEntry> = inliner.remap_exception_table()?;
        Ok((out, table, inliner.subroutines.len()))
    }) {
        Ok((out, table, subroutines)) => {
            let inlined_instructions: usize = out.len();
            JsrInlined {
                insns: out,
                exception_table: table,
                report: JsrInlineReport {
                    jsr_sites,
                    subroutines,
                    inlined_instructions,
                    bailed: false,
                    note: format!(
                        "inlined {jsr_sites} jsr call-site(s) across {subroutines} subroutine(s) into a jsr-free linear stream"
                    ),
                },
                refusal: None,
            }
        }
        Err(reason) => JsrInlined {
            insns: insns.to_vec(),
            exception_table: exception_table.to_vec(),
            report: JsrInlineReport {
                jsr_sites,
                subroutines: distinct_jsr_targets(insns),
                inlined_instructions: insns.len(),
                bailed: true,
                note: reason.to_owned(),
            },
            refusal: Some(reason),
        },
    }
}

fn distinct_jsr_targets(insns: &[Instruction]) -> usize {
    insns
        .iter()
        .filter(|ins: &&Instruction| ins.opcode == OP_JSR || ins.opcode == OP_JSR_W)
        .filter_map(branch_target_old_pc)
        .collect::<BTreeSet<u32>>()
        .len()
}

struct Inliner<'a> {
    insns: &'a [Instruction],
    exception_table: &'a [ExceptionEntry],
    pc_index: BTreeMap<u32, usize>,
    handlers_of: Vec<Vec<usize>>,
    handler_entries: BTreeSet<usize>,
    flow_entries: Vec<usize>,
    subroutines: Vec<Subroutine>,
    subroutine_at: BTreeMap<usize, usize>,
    owner: BTreeMap<usize, usize>,
    emitted: Vec<Emitted>,
    scopes: Vec<Scope>,
}

impl<'a> Inliner<'a> {
    fn plan(
        insns: &'a [Instruction],
        exception_table: &'a [ExceptionEntry],
    ) -> Result<Self, &'static str> {
        let pc_index: BTreeMap<u32, usize> = insns
            .iter()
            .enumerate()
            .map(|(i, ins): (usize, &Instruction)| (ins.pc, i))
            .collect();
        let mut handlers_of: Vec<Vec<usize>> = vec![Vec::new(); insns.len()];
        let mut coverage: usize = 0;
        for entry in exception_table {
            let Some(&handler) = pc_index.get(&u32::from(entry.handler_pc)) else {
                continue;
            };
            let range = u32::from(entry.start_pc)..u32::from(entry.end_pc);
            for (_, &idx) in pc_index.range(range) {
                coverage += 1;
                if coverage > MAX_HANDLER_COVERAGE {
                    return Err(TOO_LARGE);
                }
                if !handlers_of[idx].contains(&handler) {
                    handlers_of[idx].push(handler);
                }
            }
        }
        let handler_entries: BTreeSet<usize> = handlers_of.iter().flatten().copied().collect();
        let mut flow_entries: Vec<usize> = vec![0; insns.len()];
        for (idx, ins) in insns.iter().enumerate() {
            if ins.opcode == OP_RET {
                continue;
            }
            let (targets, falls_through): (Vec<u32>, bool) = flow_of(ins)?;
            let mut successors: BTreeSet<usize> = targets
                .iter()
                .filter_map(|target: &u32| pc_index.get(target).copied())
                .collect();
            if falls_through && idx + 1 < insns.len() {
                successors.insert(idx + 1);
            }
            for successor in successors {
                flow_entries[successor] += 1;
            }
        }
        let mut inliner: Self = Self {
            insns,
            exception_table,
            pc_index,
            handlers_of,
            handler_entries,
            flow_entries,
            subroutines: Vec::new(),
            subroutine_at: BTreeMap::new(),
            owner: BTreeMap::new(),
            emitted: Vec::new(),
            scopes: vec![Scope {
                subroutine: None,
                parent: MAIN_SCOPE,
                returns_to: None,
                labels: BTreeMap::new(),
            }],
        };
        let main: BTreeSet<usize> = inliner.reach(0, None)?;
        let mut entries: BTreeSet<usize> = BTreeSet::new();
        for ins in insns {
            if ins.opcode == OP_JSR || ins.opcode == OP_JSR_W {
                let target: u32 = branch_target_old_pc(ins).ok_or(JSR_TARGET_UNRESOLVED)?;
                entries.insert(*inliner.pc_index.get(&target).ok_or(JSR_TARGET_UNRESOLVED)?);
            }
        }
        for entry in entries {
            let body: BTreeSet<usize> = inliner.reach(entry, Some(&main))?;
            if body.iter().any(|idx: &usize| main.contains(idx)) {
                return Err(SHARED_WITH_CALLER);
            }
            inliner.check_return_address(entry, &body)?;
            let index: usize = inliner.subroutines.len();
            for idx in &body {
                if inliner.owner.insert(*idx, index).is_some() {
                    return Err(SHARED_SUBROUTINES);
                }
            }
            inliner.subroutine_at.insert(entry, index);
            inliner.subroutines.push(Subroutine { entry, body });
        }
        Ok(inliner)
    }

    fn reach(
        &self,
        start: usize,
        caller: Option<&BTreeSet<usize>>,
    ) -> Result<BTreeSet<usize>, &'static str> {
        let mut seen: BTreeSet<usize> = BTreeSet::new();
        let mut pending: Vec<usize> = vec![start];
        while let Some(idx) = pending.pop() {
            if !seen.insert(idx) {
                continue;
            }
            let Some(ins): Option<&Instruction> = self.insns.get(idx) else {
                return Err(FALLS_OFF_CODE);
            };
            for handler in &self.handlers_of[idx] {
                if caller.is_none_or(|main: &BTreeSet<usize>| !main.contains(handler)) {
                    pending.push(*handler);
                }
            }
            if ins.opcode == OP_RET {
                if caller.is_none() {
                    return Err(RET_OUTSIDE_SUBROUTINE);
                }
                continue;
            }
            let (targets, falls_through): (Vec<u32>, bool) = flow_of(ins)?;
            for target in targets {
                pending.push(*self.pc_index.get(&target).ok_or(UNRESOLVED_BRANCH)?);
            }
            if falls_through {
                if idx + 1 >= self.insns.len() {
                    if caller.is_some() {
                        return Err(FALLS_OFF_CODE);
                    }
                    continue;
                }
                pending.push(idx + 1);
            }
        }
        Ok(seen)
    }

    fn check_return_address(
        &self,
        entry: usize,
        body: &BTreeSet<usize>,
    ) -> Result<(), &'static str> {
        let slot: Option<u16> = match return_address_store(&self.insns[entry]) {
            Some(ReturnAddress::Stored(slot)) => Some(slot),
            Some(ReturnAddress::Discarded) => None,
            None => return Err(NO_RETURN_ADDRESS_STORE),
        };
        for idx in body.iter().filter(|idx: &&usize| **idx != entry) {
            let ins: &Instruction = &self.insns[*idx];
            if ins.opcode == OP_RET {
                match (&ins.operands, slot) {
                    (Operands::Local(used), Some(stored)) if *used == stored => {}
                    _ => return Err(FOREIGN_RET),
                }
            } else if slot.is_some() && local_slot(ins) == slot {
                return Err(RETURN_ADDRESS_REUSED);
            }
        }
        Ok(())
    }

    fn emit_main(&mut self) -> Result<(), &'static str> {
        let members: BTreeSet<usize> = (0..self.insns.len())
            .filter(|idx: &usize| !self.owner.contains_key(idx))
            .collect();
        self.emit_sequence(members, MAIN_SCOPE, 0)
    }

    fn emit_copy(
        &mut self,
        subroutine: usize,
        caller: usize,
        return_pc: u32,
        depth: usize,
    ) -> Result<usize, &'static str> {
        if depth > MAX_INLINE_DEPTH {
            return Err(TOO_DEEP);
        }
        let scope: usize = self.scopes.len();
        let entry: usize = self.subroutines[subroutine].entry;
        let mut labels: BTreeMap<u32, usize> = BTreeMap::new();
        labels.insert(self.insns[entry].pc, self.emitted.len());
        self.scopes.push(Scope {
            subroutine: Some(subroutine),
            parent: caller,
            returns_to: Some(Target {
                scope: caller,
                pc: return_pc,
            }),
            labels,
        });
        let members: BTreeSet<usize> = self.subroutines[subroutine]
            .body
            .iter()
            .copied()
            .filter(|idx: &usize| *idx != entry)
            .collect();
        self.emit_sequence(members, scope, depth)?;
        Ok(scope)
    }

    fn emit_sequence(
        &mut self,
        mut pending: BTreeSet<usize>,
        scope: usize,
        depth: usize,
    ) -> Result<(), &'static str> {
        let insns: &'a [Instruction] = self.insns;
        let mut next: Option<usize> = None;
        while let Some(idx) = next.take().or_else(|| pending.first().copied()) {
            pending.remove(&idx);
            let ins: &'a Instruction = &insns[idx];
            let here: usize = self.emitted.len();
            self.scopes[scope].labels.entry(ins.pc).or_insert(here);
            if ins.opcode == OP_JSR || ins.opcode == OP_JSR_W {
                let return_pc: u32 = self.continuation_pc(idx)?;
                let copy: usize =
                    self.emit_copy(self.subroutine_called_by(ins)?, scope, return_pc, depth + 1)?;
                if pending.contains(&(idx + 1)) {
                    self.drop_trailing_ret(copy);
                    next = Some(idx + 1);
                }
            } else if scope == MAIN_SCOPE
                && let Some((jsr, return_pc)) = self.goto_into_main_jsr(ins)
            {
                let subroutine: usize = self.subroutine_called_by(jsr)?;
                self.emit_copy(subroutine, MAIN_SCOPE, return_pc, depth + 1)?;
            } else if ins.opcode == OP_RET {
                let returns_to: Target = self.scopes[scope]
                    .returns_to
                    .ok_or(RET_OUTSIDE_SUBROUTINE)?;
                self.push(Emitted {
                    opcode: OP_GOTO,
                    mnemonic: "goto",
                    wide: false,
                    operands: Operands::Branch(0),
                    old_pc: ins.pc,
                    scope,
                    target: Some(returns_to),
                    switch_targets: Vec::new(),
                    ret_of: Some(scope),
                })?;
            } else if let Some(target) = self.goto_to_sole_entry(ins, &pending) {
                next = Some(target);
            } else {
                self.emit_instruction(ins, scope)?;
                if flow_of(ins)?.1 && pending.contains(&(idx + 1)) {
                    next = Some(idx + 1);
                }
            }
        }
        Ok(())
    }

    fn goto_to_sole_entry(&self, ins: &Instruction, pending: &BTreeSet<usize>) -> Option<usize> {
        if !matches!(ins.opcode, OP_GOTO | OP_GOTO_W) {
            return None;
        }
        let target: usize = *self.pc_index.get(&branch_target_old_pc(ins)?)?;
        (pending.contains(&target)
            && self.flow_entries.get(target) == Some(&1)
            && !self.handler_entries.contains(&target))
        .then_some(target)
    }

    fn emit_instruction(&mut self, ins: &Instruction, scope: usize) -> Result<(), &'static str> {
        let at = |pc: u32| -> Target { Target { scope, pc } };
        let switch_targets: Vec<Target> = switch_target_pcs(ins)?.into_iter().map(at).collect();
        self.push(Emitted {
            opcode: ins.opcode,
            mnemonic: ins.mnemonic,
            wide: ins.wide,
            operands: ins.operands.clone(),
            old_pc: ins.pc,
            scope,
            target: branch_target_old_pc(ins).map(at),
            switch_targets,
            ret_of: None,
        })
    }

    fn push(&mut self, emitted: Emitted) -> Result<(), &'static str> {
        if self.emitted.len() >= MAX_OUTPUT {
            return Err(TOO_LARGE);
        }
        self.emitted.push(emitted);
        Ok(())
    }

    fn drop_trailing_ret(&mut self, copy: usize) {
        if self
            .emitted
            .last()
            .is_some_and(|last: &Emitted| last.ret_of == Some(copy))
        {
            self.emitted.pop();
        }
    }

    fn continuation_pc(&self, idx: usize) -> Result<u32, &'static str> {
        self.insns
            .get(idx + 1)
            .map(|next: &Instruction| next.pc)
            .ok_or(FALLS_OFF_CODE)
    }

    fn subroutine_called_by(&self, jsr: &Instruction) -> Result<usize, &'static str> {
        let target: u32 = branch_target_old_pc(jsr).ok_or(JSR_TARGET_UNRESOLVED)?;
        let entry: usize = *self.pc_index.get(&target).ok_or(JSR_TARGET_UNRESOLVED)?;
        self.subroutine_at
            .get(&entry)
            .copied()
            .ok_or(JSR_TARGET_UNRESOLVED)
    }

    fn goto_into_main_jsr(&self, ins: &Instruction) -> Option<(&'a Instruction, u32)> {
        if !matches!(ins.opcode, OP_GOTO | OP_GOTO_W) {
            return None;
        }
        let index: usize = *self.pc_index.get(&branch_target_old_pc(ins)?)?;
        let jsr: &'a Instruction = self.insns.get(index)?;
        if !matches!(jsr.opcode, OP_JSR | OP_JSR_W) || self.owner.contains_key(&index) {
            return None;
        }
        Some((jsr, self.insns.get(index + 1)?.pc))
    }

    fn resolve(&self, target: Target) -> Option<usize> {
        let mut current: Target = target;
        for _ in 0..=self.scopes.len() {
            let scope: &Scope = self.scopes.get(current.scope)?;
            let at_ret: bool = self
                .pc_index
                .get(&current.pc)
                .is_some_and(|idx: &usize| self.insns[*idx].opcode == OP_RET);
            match scope.returns_to {
                Some(back) if at_ret => current = back,
                _ => return scope.labels.get(&current.pc).copied(),
            }
        }
        None
    }

    fn renumber(&self) -> Result<Vec<Instruction>, &'static str> {
        let mut out: Vec<Instruction> = Vec::with_capacity(self.emitted.len());
        for (idx, e) in self.emitted.iter().enumerate() {
            let new_pc: u32 = u32::try_from(idx).map_err(|_| TOO_LARGE)?;
            let relative = |target: Target| -> Result<i32, &'static str> {
                let target_idx: usize = self.resolve(target).ok_or(UNRESOLVED_BRANCH)?;
                let target_pc: i64 = i64::try_from(target_idx).map_err(|_| TOO_LARGE)?;
                i32::try_from(target_pc - i64::from(new_pc)).map_err(|_| TOO_LARGE)
            };
            let operands: Operands = match (&e.operands, e.target) {
                (_, Some(target)) => Operands::Branch(relative(target)?),
                (Operands::TableSwitch { low, high, .. }, None) => {
                    let (default, offsets): (&Target, &[Target]) =
                        e.switch_targets.split_first().ok_or(UNRESOLVED_BRANCH)?;
                    Operands::TableSwitch {
                        default: relative(*default)?,
                        low: *low,
                        high: *high,
                        offsets: offsets
                            .iter()
                            .map(|target: &Target| relative(*target))
                            .collect::<Result<Vec<i32>, &'static str>>()?,
                    }
                }
                (Operands::LookupSwitch { pairs, .. }, None) => {
                    let (default, offsets): (&Target, &[Target]) =
                        e.switch_targets.split_first().ok_or(UNRESOLVED_BRANCH)?;
                    if offsets.len() != pairs.len() {
                        return Err(UNRESOLVED_BRANCH);
                    }
                    Operands::LookupSwitch {
                        default: relative(*default)?,
                        pairs: pairs
                            .iter()
                            .zip(offsets)
                            .map(|((key, _), target): (&(i32, i32), &Target)| {
                                relative(*target).map(|off: i32| (*key, off))
                            })
                            .collect::<Result<Vec<(i32, i32)>, &'static str>>()?,
                    }
                }
                (operands, None) => operands.clone(),
            };
            out.push(Instruction {
                pc: new_pc,
                opcode: e.opcode,
                mnemonic: e.mnemonic,
                wide: e.wide,
                operands,
            });
        }
        Ok(out)
    }

    fn handler_for(&self, e: &Emitted, handler_pc: u32, owner: Option<usize>) -> Option<usize> {
        let Some(subroutine) = owner else {
            return self.resolve(Target {
                scope: MAIN_SCOPE,
                pc: handler_pc,
            });
        };
        let mut scope: usize = e.scope;
        for _ in 0..=self.scopes.len() {
            let current: &Scope = self.scopes.get(scope)?;
            if current.subroutine == Some(subroutine) {
                return current.labels.get(&handler_pc).copied();
            }
            if scope == MAIN_SCOPE {
                return None;
            }
            scope = current.parent;
        }
        None
    }

    fn remap_exception_table(&self) -> Result<Vec<ExceptionEntry>, &'static str> {
        if self
            .exception_table
            .len()
            .saturating_mul(self.emitted.len())
            > MAX_REMAP_WORK
        {
            return Err(TOO_LARGE);
        }
        let mut out: Vec<ExceptionEntry> = Vec::with_capacity(self.exception_table.len());
        for entry in self.exception_table {
            let protected = u32::from(entry.start_pc)..u32::from(entry.end_pc);
            let handler_pc: u32 = u32::from(entry.handler_pc);
            let owner: Option<usize> = match self.pc_index.get(&handler_pc) {
                Some(idx) => self.owner.get(idx).copied(),
                None => {
                    if self
                        .emitted
                        .iter()
                        .any(|e: &Emitted| protected.contains(&e.old_pc))
                    {
                        return Err(UNPLACED_HANDLER);
                    }
                    continue;
                }
            };
            let mut run: Option<(usize, usize)> = None;
            for (idx, e) in self.emitted.iter().enumerate() {
                let handler: Option<usize> = if protected.contains(&e.old_pc) {
                    Some(
                        self.handler_for(e, handler_pc, owner)
                            .ok_or(UNPLACED_HANDLER)?,
                    )
                } else {
                    None
                };
                match (run, handler) {
                    (Some((_, current)), Some(next)) if current == next => {}
                    (previous, next) => {
                        if let Some((start, current)) = previous {
                            out.push(table_entry(start, idx, current, entry.catch_type)?);
                        }
                        run = next.map(|handler: usize| (idx, handler));
                    }
                }
            }
            if let Some((start, current)) = run {
                out.push(table_entry(
                    start,
                    self.emitted.len(),
                    current,
                    entry.catch_type,
                )?);
            }
        }
        Ok(out)
    }
}

fn table_entry(
    start: usize,
    end: usize,
    handler: usize,
    catch_type: u16,
) -> Result<ExceptionEntry, &'static str> {
    Ok(ExceptionEntry {
        start_pc: u16::try_from(start).map_err(|_| TOO_LARGE)?,
        end_pc: u16::try_from(end).map_err(|_| TOO_LARGE)?,
        handler_pc: u16::try_from(handler).map_err(|_| TOO_LARGE)?,
        catch_type,
    })
}

enum ReturnAddress {
    Stored(u16),
    Discarded,
}

fn return_address_store(ins: &Instruction) -> Option<ReturnAddress> {
    match (ins.opcode, &ins.operands) {
        (OP_ASTORE, Operands::Local(slot)) => Some(ReturnAddress::Stored(*slot)),
        (OP_ASTORE_0..=OP_ASTORE_3, _) => {
            Some(ReturnAddress::Stored(u16::from(ins.opcode - OP_ASTORE_0)))
        }
        (OP_POP, _) => Some(ReturnAddress::Discarded),
        _ => None,
    }
}

fn local_slot(ins: &Instruction) -> Option<u16> {
    match (ins.opcode, &ins.operands) {
        (0x15..=0x19 | 0x36..=0x3A, Operands::Local(slot)) => Some(*slot),
        (0x84, Operands::Iinc { index, .. }) => Some(*index),
        (0x1A..=0x2D, _) => Some(u16::from((ins.opcode - 0x1A) % 4)),
        (0x3B..=0x4E, _) => Some(u16::from((ins.opcode - 0x3B) % 4)),
        _ => None,
    }
}

fn flow_of(ins: &Instruction) -> Result<(Vec<u32>, bool), &'static str> {
    let branch = || -> Result<Vec<u32>, &'static str> {
        branch_target_old_pc(ins)
            .map(|target: u32| vec![target])
            .ok_or(UNRESOLVED_BRANCH)
    };
    Ok(match ins.opcode {
        OP_GOTO | OP_GOTO_W => (branch()?, false),
        0x99..=0xA6 | 0xC6 | 0xC7 => (branch()?, true),
        OP_TABLESWITCH | OP_LOOKUPSWITCH => (switch_target_pcs(ins)?, false),
        0xAC..=0xB1 | OP_ATHROW | OP_RET => (Vec::new(), false),
        _ => (Vec::new(), true),
    })
}

fn switch_target_pcs(ins: &Instruction) -> Result<Vec<u32>, &'static str> {
    let offsets: Vec<i32> = match &ins.operands {
        Operands::TableSwitch {
            default, offsets, ..
        } => std::iter::once(*default)
            .chain(offsets.iter().copied())
            .collect(),
        Operands::LookupSwitch { default, pairs } => std::iter::once(*default)
            .chain(pairs.iter().map(|(_, off): &(i32, i32)| *off))
            .collect(),
        _ => Vec::new(),
    };
    offsets
        .into_iter()
        .map(|off: i32| {
            u32::try_from(i64::from(ins.pc) + i64::from(off)).map_err(|_| UNRESOLVED_BRANCH)
        })
        .collect()
}

fn branch_target_old_pc(ins: &Instruction) -> Option<u32> {
    match ins.operands {
        Operands::Branch(off) => u32::try_from(i64::from(ins.pc) + i64::from(off)).ok(),
        _ => None,
    }
}

const fn is_jsr_or_ret(opcode: u8) -> bool {
    matches!(opcode, OP_JSR | OP_JSR_W | OP_RET)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn ins(pc: u32, opcode: u8, mnemonic: &'static str, operands: Operands) -> Instruction {
        Instruction {
            pc,
            opcode,
            mnemonic,
            wide: false,
            operands,
        }
    }

    #[test]
    fn no_jsr_passes_through() {
        let insns: Vec<Instruction> = vec![
            ins(0, 0x04, "iconst_1", Operands::None),
            ins(1, 0xAC, "ireturn", Operands::None),
        ];
        let JsrInlined {
            insns: out, report, ..
        } = inline_jsr_subroutines(&insns, &[]);
        assert_eq!(out.len(), 2);
        assert_eq!(report.jsr_sites, 0);
        assert!(!report.bailed);
    }

    #[test]
    fn a_subroutine_with_a_second_ret_returns_from_both() {
        let insns: Vec<Instruction> = vec![
            ins(0, OP_JSR, "jsr", Operands::Branch(5)),
            ins(3, 0xB1, "return", Operands::None),
            ins(4, 0x00, "nop", Operands::None),
            ins(5, OP_ASTORE, "astore", Operands::Local(1)),
            ins(7, 0x1A, "iload_0", Operands::None),
            ins(8, 0x99, "ifeq", Operands::Branch(5)),
            ins(11, OP_RET, "ret", Operands::Local(1)),
            ins(13, 0x04, "iconst_1", Operands::None),
            ins(14, 0x3B, "istore_0", Operands::None),
            ins(15, OP_RET, "ret", Operands::Local(1)),
        ];
        let JsrInlined {
            insns: out,
            report,
            refusal,
            ..
        } = inline_jsr_subroutines(&insns, &[]);
        assert!(!report.bailed, "{report:?}");
        assert_eq!(refusal, None);
        assert_eq!(
            out.iter()
                .map(|i: &Instruction| i.opcode)
                .collect::<Vec<u8>>(),
            vec![0x1A, 0x99, OP_GOTO, 0x04, 0x3B, 0xB1, 0x00],
            "{out:?}"
        );
        assert_eq!(
            out[1].operands,
            Operands::Branch(2),
            "the branch past the first ret stays in the copy: {out:?}"
        );
        assert_eq!(
            out[2].operands,
            Operands::Branch(3),
            "the first ret returns to the call site: {out:?}"
        );
    }

    #[test]
    fn each_copy_branches_inside_itself() {
        let insns: Vec<Instruction> = vec![
            ins(0, OP_JSR, "jsr", Operands::Branch(11)),
            ins(3, 0x04, "iconst_1", Operands::None),
            ins(4, 0x3C, "istore_1", Operands::None),
            ins(5, OP_JSR, "jsr", Operands::Branch(6)),
            ins(8, 0x1B, "iload_1", Operands::None),
            ins(9, 0xAC, "ireturn", Operands::None),
            ins(10, 0x00, "nop", Operands::None),
            ins(11, OP_ASTORE, "astore", Operands::Local(2)),
            ins(13, 0x1A, "iload_0", Operands::None),
            ins(14, 0x99, "ifeq", Operands::Branch(6)),
            ins(17, 0x84, "iinc", Operands::Iinc { index: 0, delta: 1 }),
            ins(20, OP_RET, "ret", Operands::Local(2)),
        ];
        let JsrInlined {
            insns: out, report, ..
        } = inline_jsr_subroutines(&insns, &[]);
        assert!(!report.bailed, "{report:?}");
        assert_eq!(
            out.iter()
                .map(|i: &Instruction| i.opcode)
                .collect::<Vec<u8>>(),
            vec![
                0x1A, 0x99, 0x84, 0x04, 0x3C, 0x1A, 0x99, 0x84, 0x1B, 0xAC, 0x00
            ],
            "{out:?}"
        );
        assert_eq!(
            out[1].operands,
            Operands::Branch(2),
            "the first copy's branch to its ret returns to the first call site: {out:?}"
        );
        assert_eq!(
            out[6].operands,
            Operands::Branch(2),
            "the second copy's branch to its ret returns to the second call site: {out:?}"
        );
    }

    #[test]
    fn a_handler_inside_a_subroutine_follows_each_copy() {
        let insns: Vec<Instruction> = vec![
            ins(0, OP_JSR, "jsr", Operands::Branch(10)),
            ins(3, OP_JSR, "jsr", Operands::Branch(7)),
            ins(6, 0xB1, "return", Operands::None),
            ins(7, 0x00, "nop", Operands::None),
            ins(8, 0x00, "nop", Operands::None),
            ins(9, 0x00, "nop", Operands::None),
            ins(10, 0x4C, "astore_1", Operands::None),
            ins(11, 0xB8, "invokestatic", Operands::ConstPool(9)),
            ins(14, OP_GOTO, "goto", Operands::Branch(6)),
            ins(17, 0x57, "pop", Operands::None),
            ins(18, 0x04, "iconst_1", Operands::None),
            ins(19, 0x3B, "istore_0", Operands::None),
            ins(20, OP_RET, "ret", Operands::Local(1)),
        ];
        let table: [ExceptionEntry; 1] = [ExceptionEntry {
            start_pc: 11,
            end_pc: 14,
            handler_pc: 17,
            catch_type: 5,
        }];
        let JsrInlined {
            insns: out,
            exception_table,
            report,
            ..
        } = inline_jsr_subroutines(&insns, &table);
        assert!(!report.bailed, "{report:?}");
        assert_eq!(
            out.iter()
                .map(|i: &Instruction| i.opcode)
                .collect::<Vec<u8>>(),
            vec![
                0xB8, OP_GOTO, 0x57, 0x04, 0x3B, 0xB8, OP_GOTO, 0x57, 0x04, 0x3B, 0xB1, 0x00, 0x00,
                0x00
            ],
            "{out:?}"
        );
        assert_eq!(out[1].operands, Operands::Branch(4), "{out:?}");
        assert_eq!(out[6].operands, Operands::Branch(4), "{out:?}");
        assert_eq!(
            exception_table,
            vec![
                ExceptionEntry {
                    start_pc: 0,
                    end_pc: 1,
                    handler_pc: 2,
                    catch_type: 5,
                },
                ExceptionEntry {
                    start_pc: 5,
                    end_pc: 6,
                    handler_pc: 7,
                    catch_type: 5,
                },
            ],
            "each copy's call is caught by that copy's own handler"
        );
    }

    #[test]
    fn a_subroutine_the_caller_falls_into_is_refused_by_name() {
        let insns: Vec<Instruction> = vec![
            ins(0, OP_JSR, "jsr", Operands::Branch(4)),
            ins(3, 0x00, "nop", Operands::None),
            ins(4, OP_ASTORE, "astore", Operands::Local(1)),
            ins(6, OP_RET, "ret", Operands::Local(1)),
        ];
        let JsrInlined {
            insns: out,
            report,
            refusal,
            ..
        } = inline_jsr_subroutines(&insns, &[]);
        assert!(report.bailed, "{report:?}");
        assert_eq!(refusal, Some(RET_OUTSIDE_SUBROUTINE));
        assert_eq!(out, insns);
    }

    #[test]
    fn a_ret_through_another_local_is_refused_by_name() {
        let insns: Vec<Instruction> = vec![
            ins(0, OP_JSR, "jsr", Operands::Branch(4)),
            ins(3, 0xB1, "return", Operands::None),
            ins(4, OP_ASTORE, "astore", Operands::Local(1)),
            ins(6, OP_RET, "ret", Operands::Local(2)),
        ];
        let JsrInlined { refusal, .. } = inline_jsr_subroutines(&insns, &[]);
        assert_eq!(refusal, Some(FOREIGN_RET));
    }

    #[test]
    fn a_switch_keeps_its_targets_after_inlining() {
        let insns: Vec<Instruction> = vec![
            ins(0, OP_JSR, "jsr", Operands::Branch(28)),
            ins(3, 0x1A, "iload_0", Operands::None),
            ins(
                4,
                0xAB,
                "lookupswitch",
                Operands::LookupSwitch {
                    default: 23,
                    pairs: vec![(1, 23)],
                },
            ),
            ins(27, 0xB1, "return", Operands::None),
            ins(28, OP_ASTORE, "astore", Operands::Local(1)),
            ins(30, OP_RET, "ret", Operands::Local(1)),
        ];
        let JsrInlined {
            insns: out, report, ..
        } = inline_jsr_subroutines(&insns, &[]);
        assert!(!report.bailed, "{report:?}");
        assert_eq!(
            out.iter()
                .map(|i: &Instruction| i.opcode)
                .collect::<Vec<u8>>(),
            vec![0x1A, 0xAB, 0xB1],
            "{out:?}"
        );
        assert_eq!(
            out[1].operands,
            Operands::LookupSwitch {
                default: 1,
                pairs: vec![(1, 1)],
            },
            "the switch must still land on the return it targeted: {out:?}"
        );
    }

    #[test]
    fn a_try_range_protects_only_the_code_it_covered() {
        let insns: Vec<Instruction> = vec![
            ins(0, 0x04, "iconst_1", Operands::None),
            ins(1, 0x3B, "istore_0", Operands::None),
            ins(2, OP_JSR, "jsr", Operands::Branch(10)),
            ins(5, 0xB1, "return", Operands::None),
            ins(6, 0x4C, "astore_1", Operands::None),
            ins(7, OP_JSR, "jsr", Operands::Branch(5)),
            ins(10, 0x2B, "aload_1", Operands::None),
            ins(11, 0xBF, "athrow", Operands::None),
            ins(12, 0x4D, "astore_2", Operands::None),
            ins(13, 0x05, "iconst_2", Operands::None),
            ins(14, 0x3B, "istore_0", Operands::None),
            ins(15, OP_RET, "ret", Operands::Local(2)),
        ];
        let table: [ExceptionEntry; 1] = [ExceptionEntry {
            start_pc: 0,
            end_pc: 6,
            handler_pc: 6,
            catch_type: 0,
        }];
        let JsrInlined {
            insns: out,
            exception_table,
            report,
            ..
        } = inline_jsr_subroutines(&insns, &table);
        assert!(!report.bailed, "{report:?}");
        assert_eq!(
            out.iter()
                .map(|i: &Instruction| i.opcode)
                .collect::<Vec<u8>>(),
            vec![0x04, 0x3B, 0x05, 0x3B, 0xB1, 0x4C, 0x05, 0x3B, 0x2B, 0xBF],
            "{out:?}"
        );
        assert_eq!(
            exception_table,
            vec![
                ExceptionEntry {
                    start_pc: 0,
                    end_pc: 2,
                    handler_pc: 5,
                    catch_type: 0,
                },
                ExceptionEntry {
                    start_pc: 4,
                    end_pc: 5,
                    handler_pc: 5,
                    catch_type: 0,
                },
            ],
            "the inlined finally copy stays outside the try range and the handler follows its code"
        );
    }

    #[test]
    fn inlines_single_subroutine() {
        let insns: Vec<Instruction> = vec![
            ins(0, OP_JSR, "jsr", Operands::Branch(5)),
            ins(3, 0xB1, "return", Operands::None),
            ins(4, 0x00, "nop", Operands::None),
            ins(5, OP_ASTORE, "astore", Operands::Local(1)),
            ins(7, 0x04, "iconst_1", Operands::None),
            ins(8, OP_RET, "ret", Operands::Local(1)),
        ];
        let JsrInlined {
            insns: out, report, ..
        } = inline_jsr_subroutines(&insns, &[]);
        assert!(!report.bailed, "{report:?}");
        assert_eq!(report.jsr_sites, 1);
        assert_eq!(report.subroutines, 1);
        assert!(
            out.iter().all(|i: &Instruction| i.opcode != OP_JSR
                && i.opcode != OP_JSR_W
                && i.opcode != OP_RET),
            "output must be jsr/ret-free: {out:?}"
        );
        assert!(
            out.iter().any(|i: &Instruction| i.mnemonic == "iconst_1"),
            "subroutine body must be inlined"
        );
        assert_eq!(
            out.iter()
                .map(|i: &Instruction| i.opcode)
                .collect::<Vec<u8>>(),
            vec![0x04, 0xB1, 0x00],
            "a ret whose return site follows the copy falls through without a goto: {out:?}"
        );
    }

    #[test]
    fn output_is_pc_monotonic_with_resolvable_targets() {
        let insns: Vec<Instruction> = vec![
            ins(0, OP_JSR, "jsr", Operands::Branch(8)),
            ins(3, 0x1b, "iload_1", Operands::None),
            ins(4, 0xac, "ireturn", Operands::None),
            ins(5, 0x00, "nop", Operands::None),
            ins(6, 0x00, "nop", Operands::None),
            ins(7, 0x00, "nop", Operands::None),
            ins(8, OP_ASTORE, "astore", Operands::Local(2)),
            ins(10, 0x1a, "iload_0", Operands::None),
            ins(11, 0x1a, "iload_0", Operands::None),
            ins(12, 0x60, "iadd", Operands::None),
            ins(13, 0x3c, "istore_1", Operands::None),
            ins(14, OP_RET, "ret", Operands::Local(2)),
        ];
        let JsrInlined {
            insns: out, report, ..
        } = inline_jsr_subroutines(&insns, &[]);
        assert!(!report.bailed, "{report:?}");
        for w in out.windows(2) {
            assert!(w[0].pc < w[1].pc, "pcs must be strictly monotonic: {out:?}");
        }
        for (idx, i) in out.iter().enumerate() {
            assert_eq!(i.pc, idx as u32, "stride-1 pc renumbering: {out:?}");
        }
        let pcs: BTreeSet<u32> = out.iter().map(|i: &Instruction| i.pc).collect();
        for i in &out {
            if let Operands::Branch(off) = i.operands {
                let target: i64 = i64::from(i.pc) + i64::from(off);
                let target: u32 = u32::try_from(target).expect("target in range");
                assert!(
                    pcs.contains(&target),
                    "branch at pc {} targets {target} which is not a real instruction pc; pcs={pcs:?}",
                    i.pc
                );
            }
        }
        let body: Vec<&'static str> = out.iter().map(|i: &Instruction| i.mnemonic).collect();
        assert_eq!(
            &body[..6],
            &[
                "iload_0", "iload_0", "iadd", "istore_1", "iload_1", "ireturn"
            ][..],
            "the computation must be inlined straight before the return tail: {body:?}"
        );
    }

    #[test]
    fn a_branch_to_a_ret_lands_on_the_return_site() {
        let insns: Vec<Instruction> = vec![
            ins(0, OP_JSR, "jsr", Operands::Branch(5)),
            ins(3, 0xB1, "return", Operands::None),
            ins(4, 0x00, "nop", Operands::None),
            ins(5, OP_ASTORE, "astore", Operands::Local(1)),
            ins(7, 0x1A, "iload_0", Operands::None),
            ins(8, 0x99, "ifeq", Operands::Branch(5)),
            ins(11, 0x04, "iconst_1", Operands::None),
            ins(12, 0x3B, "istore_0", Operands::None),
            ins(13, OP_RET, "ret", Operands::Local(1)),
        ];
        let JsrInlined {
            insns: out, report, ..
        } = inline_jsr_subroutines(&insns, &[]);
        assert!(!report.bailed, "{report:?}");
        assert_eq!(
            out.iter()
                .map(|i: &Instruction| i.opcode)
                .collect::<Vec<u8>>(),
            vec![0x1A, 0x99, 0x04, 0x3B, 0xB1, 0x00],
            "{out:?}"
        );
        assert_eq!(
            out[1].operands,
            Operands::Branch(3),
            "the branch to the ret lands on the return site: {out:?}"
        );
    }

    #[test]
    fn shared_subroutine_two_sites_each_inlines_a_copy() {
        let insns: Vec<Instruction> = vec![
            ins(0, OP_JSR, "jsr", Operands::Branch(9)),
            ins(3, OP_JSR, "jsr", Operands::Branch(6)),
            ins(6, 0xb1, "return", Operands::None),
            ins(7, 0x00, "nop", Operands::None),
            ins(8, 0x00, "nop", Operands::None),
            ins(9, OP_ASTORE, "astore", Operands::Local(0)),
            ins(11, 0x05, "iconst_2", Operands::None),
            ins(12, 0x57, "pop", Operands::None),
            ins(13, OP_RET, "ret", Operands::Local(0)),
        ];
        let JsrInlined {
            insns: out, report, ..
        } = inline_jsr_subroutines(&insns, &[]);
        assert!(!report.bailed, "{report:?}");
        let copies: usize = out
            .iter()
            .filter(|i: &&Instruction| i.mnemonic == "iconst_2")
            .count();
        assert_eq!(
            copies, 2,
            "each jsr site must receive its own subroutine copy: {out:?}"
        );
        for (idx, i) in out.iter().enumerate() {
            assert_eq!(i.pc, idx as u32);
        }
        let pcs: BTreeSet<u32> = out.iter().map(|i: &Instruction| i.pc).collect();
        for i in &out {
            if let Operands::Branch(off) = i.operands {
                let target: u32 = (i64::from(i.pc) + i64::from(off)) as u32;
                assert!(pcs.contains(&target), "unresolved target {target}: {out:?}");
            }
        }
    }

    #[test]
    fn a_goto_into_a_jsr_receives_its_own_subroutine_copy() {
        let insns: Vec<Instruction> = vec![
            ins(0, 0x1A, "iload_0", Operands::None),
            ins(1, 0x99, "ifeq", Operands::Branch(8)),
            ins(4, 0x04, "iconst_1", Operands::None),
            ins(5, 0x3B, "istore_0", Operands::None),
            ins(6, OP_GOTO, "goto", Operands::Branch(5)),
            ins(9, 0x05, "iconst_2", Operands::None),
            ins(10, 0x3B, "istore_0", Operands::None),
            ins(11, OP_JSR, "jsr", Operands::Branch(5)),
            ins(14, 0x1A, "iload_0", Operands::None),
            ins(15, 0xAC, "ireturn", Operands::None),
            ins(16, 0x4C, "astore_1", Operands::None),
            ins(17, 0x1A, "iload_0", Operands::None),
            ins(18, 0x04, "iconst_1", Operands::None),
            ins(19, 0x60, "iadd", Operands::None),
            ins(20, 0x3B, "istore_0", Operands::None),
            ins(21, OP_RET, "ret", Operands::Local(1)),
        ];
        let JsrInlined {
            insns: out, report, ..
        } = inline_jsr_subroutines(&insns, &[]);
        assert!(!report.bailed, "{report:?}");
        assert_eq!(
            out.iter()
                .map(|i: &Instruction| i.opcode)
                .collect::<Vec<u8>>(),
            vec![
                0x1A, 0x99, 0x04, 0x3B, 0x1A, 0x04, 0x60, 0x3B, OP_GOTO, 0x05, 0x3B, 0x1A, 0x04,
                0x60, 0x3B, 0x1A, 0xAC
            ],
            "{out:?}"
        );
        assert_eq!(out[1].operands, Operands::Branch(8), "{out:?}");
        assert_eq!(
            out[8].operands,
            Operands::Branch(7),
            "the duplicated copy returns to the shared tail: {out:?}"
        );
    }

    #[test]
    fn contains_jsr_detects() {
        let with: Vec<Instruction> = vec![ins(0, OP_JSR, "jsr", Operands::Branch(3))];
        let without: Vec<Instruction> = vec![ins(0, 0x04, "iconst_1", Operands::None)];
        assert!(contains_jsr(&with));
        assert!(!contains_jsr(&without));
    }
}
