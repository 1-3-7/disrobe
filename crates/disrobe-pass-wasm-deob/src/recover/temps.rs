use std::collections::{BTreeMap, BTreeSet};

use walrus::ir::{Instr, InstrLocId, InstrSeqId};
use walrus::{LocalFunction, LocalId};

type Body = Vec<(Instr, InstrLocId)>;

const MAX_ROUNDS: usize = 8;
const MAX_SEQUENCES: usize = 4096;

pub(super) struct Snapshot {
    sequences: Vec<(InstrSeqId, Body)>,
}

impl Snapshot {
    pub(super) fn take(func: &LocalFunction) -> Option<Self> {
        let layout: Layout = Layout::of(func)?;
        Some(Self {
            sequences: layout
                .sequences
                .iter()
                .map(|id: &InstrSeqId| (*id, func.block(*id).instrs.clone()))
                .collect(),
        })
    }

    pub(super) fn restore(self, func: &mut LocalFunction) {
        for (id, body) in self.sequences {
            func.block_mut(id).instrs = body;
        }
    }
}

#[derive(Debug, Default)]
struct LocalUse {
    sets: Vec<(InstrSeqId, usize)>,
    tees: usize,
    gets: Vec<(InstrSeqId, usize)>,
}

struct Layout {
    sequences: Vec<InstrSeqId>,
    parents: BTreeMap<InstrSeqId, (InstrSeqId, usize)>,
    uses: BTreeMap<LocalId, LocalUse>,
    looped_switch: bool,
}

impl Layout {
    fn of(func: &LocalFunction) -> Option<Self> {
        let mut layout: Self = Self {
            sequences: Vec::new(),
            parents: BTreeMap::new(),
            uses: BTreeMap::new(),
            looped_switch: false,
        };
        let mut pending: Vec<(InstrSeqId, bool)> = vec![(func.entry_block(), false)];
        while let Some((sequence, in_loop)) = pending.pop() {
            if layout.sequences.len() >= MAX_SEQUENCES {
                return None;
            }
            layout.sequences.push(sequence);
            for (index, (instr, _location)) in func.block(sequence).instrs.iter().enumerate() {
                let children: [Option<(InstrSeqId, bool)>; 2] = match instr {
                    Instr::Block(block) => [Some((block.seq, in_loop)), None],
                    Instr::Loop(looped) => [Some((looped.seq, true)), None],
                    Instr::IfElse(if_else) => [
                        Some((if_else.consequent, in_loop)),
                        Some((if_else.alternative, in_loop)),
                    ],
                    Instr::Try(_) | Instr::TryTable(_) => return None,
                    Instr::BrTable(_) => {
                        layout.looped_switch |= in_loop;
                        [None, None]
                    }
                    Instr::LocalSet(set) => {
                        layout
                            .uses
                            .entry(set.local)
                            .or_default()
                            .sets
                            .push((sequence, index));
                        [None, None]
                    }
                    Instr::LocalTee(tee) => {
                        layout.uses.entry(tee.local).or_default().tees += 1;
                        [None, None]
                    }
                    Instr::LocalGet(get) => {
                        layout
                            .uses
                            .entry(get.local)
                            .or_default()
                            .gets
                            .push((sequence, index));
                        [None, None]
                    }
                    _ => [None, None],
                };
                for (child, child_in_loop) in children.into_iter().flatten() {
                    layout.parents.insert(child, (sequence, index));
                    pending.push((child, child_in_loop));
                }
            }
        }
        Some(layout)
    }

    fn executes_after(&self, set: (InstrSeqId, usize), get: (InstrSeqId, usize)) -> bool {
        let mut at: (InstrSeqId, usize) = get;
        for _ in 0..MAX_SEQUENCES {
            if at.0 == set.0 {
                return at.1 > set.1;
            }
            let Some(parent): Option<&(InstrSeqId, usize)> = self.parents.get(&at.0) else {
                return false;
            };
            at = *parent;
        }
        false
    }
}

pub(super) fn has_looped_switch(func: &LocalFunction) -> bool {
    Layout::of(func).is_some_and(|layout: Layout| layout.looped_switch)
}

pub(super) fn forward_compiler_temporaries(func: &mut LocalFunction) -> bool {
    let params: BTreeSet<LocalId> = func.args.iter().copied().collect();
    let mut changed: bool = false;
    for _ in 0..MAX_ROUNDS {
        match forward_round(func, &params) {
            Some(true) => changed = true,
            Some(false) | None => break,
        }
    }
    changed
}

fn forward_round(func: &mut LocalFunction, params: &BTreeSet<LocalId>) -> Option<bool> {
    let layout: Layout = Layout::of(func)?;
    let mut replacements: Vec<(InstrSeqId, usize, Instr)> = Vec::new();
    let mut removals: BTreeMap<InstrSeqId, BTreeSet<usize>> = BTreeMap::new();
    for (local, uses) in &layout.uses {
        if params.contains(local) || uses.tees != 0 {
            continue;
        }
        let [set]: &[(InstrSeqId, usize)] = uses.sets.as_slice() else {
            continue;
        };
        if let [get] = uses.gets.as_slice()
            && get.0 == set.0
            && Some(get.1) == set.1.checked_add(1)
        {
            removals.entry(set.0).or_default().extend([set.1, get.1]);
            continue;
        }
        let Some(constant_index): Option<usize> = set.1.checked_sub(1) else {
            continue;
        };
        let Some((Instr::Const(constant), _location)) =
            func.block(set.0).instrs.get(constant_index)
        else {
            continue;
        };
        if !uses
            .gets
            .iter()
            .all(|get: &(InstrSeqId, usize)| layout.executes_after(*set, *get))
        {
            continue;
        }
        for get in &uses.gets {
            replacements.push((get.0, get.1, Instr::Const(constant.clone())));
        }
        removals
            .entry(set.0)
            .or_default()
            .extend([constant_index, set.1]);
    }
    if replacements.is_empty() && removals.is_empty() {
        return Some(false);
    }
    for (sequence, index, instr) in replacements {
        if let Some(slot) = func.block_mut(sequence).instrs.get_mut(index) {
            slot.0 = instr;
        }
    }
    for (sequence, indices) in removals {
        let body: &mut Body = &mut func.block_mut(sequence).instrs;
        for index in indices.into_iter().rev() {
            if index < body.len() {
                body.remove(index);
            }
        }
    }
    Some(true)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use walrus::{FunctionKind, Module};

    fn single_function(text: &str) -> Module {
        let bytes: Vec<u8> = wat::parse_str(text).expect("assemble");
        Module::from_buffer(&bytes).expect("parse")
    }

    fn local_function(module: &mut Module) -> &mut LocalFunction {
        let id: walrus::FunctionId = module
            .funcs
            .iter_local()
            .map(|(id, _)| id)
            .next()
            .expect("one local function");
        let FunctionKind::Local(func) = &mut module.funcs.get_mut(id).kind else {
            panic!("local function");
        };
        func
    }

    fn entry_text(func: &LocalFunction) -> Vec<String> {
        func.block(func.entry_block())
            .instrs
            .iter()
            .map(|(instr, _)| format!("{instr:?}"))
            .collect()
    }

    fn every_sequence_text(func: &LocalFunction) -> Vec<String> {
        let layout: Layout = Layout::of(func).expect("layout");
        layout
            .sequences
            .iter()
            .flat_map(|id: &InstrSeqId| func.block(*id).instrs.iter())
            .map(|(instr, _)| format!("{instr:?}"))
            .collect()
    }

    #[test]
    fn single_use_temporaries_collapse_into_stack_form() {
        let mut module: Module = single_function(
            r#"(module (memory 1) (global (mut i32) (i32.const 1024))
              (func (export "f") (result i32) (local i32 i32 i32)
                global.get 0
                local.set 0
                i32.const 16
                local.set 1
                local.get 0
                local.get 1
                i32.sub
                local.set 2
                local.get 2
                i32.const 7
                i32.store
                local.get 2
                i32.load))"#,
        );
        let func: &mut LocalFunction = local_function(&mut module);
        assert!(forward_compiler_temporaries(func));
        let text: Vec<String> = entry_text(func);
        assert_eq!(text.len(), 9, "{text:#?}");
        assert!(text[0].starts_with("GlobalGet"), "{text:#?}");
        assert!(text[1].contains("I32(16)"), "{text:#?}");
        assert!(text[2].contains("I32Sub"), "{text:#?}");
        assert!(text[3].starts_with("LocalSet"), "{text:#?}");
        let bytes: Vec<u8> = module.emit_wasm();
        wasmparser::Validator::new()
            .validate_all(&bytes)
            .expect("the rewritten function validates");
    }

    #[test]
    fn a_constant_read_before_its_definition_is_left_alone() {
        let mut module: Module = single_function(
            r#"(module
              (func (export "f") (param i32) (result i32) (local i32)
                block
                  local.get 0
                  br_if 0
                  local.get 1
                  return
                end
                i32.const 5
                local.set 1
                local.get 1
                local.get 1
                i32.add))"#,
        );
        let func: &mut LocalFunction = local_function(&mut module);
        let before: Vec<String> = entry_text(func);
        assert!(!forward_compiler_temporaries(func));
        assert_eq!(entry_text(func), before);
    }

    #[test]
    fn a_temporary_written_twice_or_teed_is_not_forwarded() {
        let mut module: Module = single_function(
            r#"(module
              (func (export "f") (result i32) (local i32 i32)
                i32.const 1
                local.set 0
                i32.const 2
                local.set 0
                i32.const 3
                local.tee 1
                local.get 1
                i32.add
                local.get 0
                i32.add))"#,
        );
        let func: &mut LocalFunction = local_function(&mut module);
        let before: Vec<String> = entry_text(func);
        assert!(!forward_compiler_temporaries(func));
        assert_eq!(entry_text(func), before);
    }

    #[test]
    fn a_function_above_the_sequence_cap_is_left_alone() {
        let depth: usize = MAX_SEQUENCES + 8;
        let mut text: String = String::from(
            "(module (func (export \"f\") (result i32) (local i32) i32.const 3 local.set 0",
        );
        for _ in 0..depth {
            text.push_str(" block");
        }
        text.push_str(" local.get 0 drop");
        for _ in 0..depth {
            text.push_str(" end");
        }
        text.push_str(" i32.const 0))");
        let mut module: Module = single_function(&text);
        let func: &mut LocalFunction = local_function(&mut module);
        assert!(Snapshot::take(func).is_none());
        assert!(!has_looped_switch(func));
        assert!(!forward_compiler_temporaries(func));
    }

    #[test]
    fn a_snapshot_restores_every_sequence() {
        let mut module: Module = single_function(
            r#"(module
              (func (export "f") (result i32) (local i32)
                loop (result i32)
                  i32.const 4
                  local.set 0
                  local.get 0
                end))"#,
        );
        let func: &mut LocalFunction = local_function(&mut module);
        let snapshot: Snapshot = Snapshot::take(func).expect("snapshot");
        let before: Vec<String> = every_sequence_text(func);
        assert!(forward_compiler_temporaries(func));
        assert_ne!(every_sequence_text(func), before);
        snapshot.restore(func);
        assert_eq!(every_sequence_text(func), before);
        assert!(!has_looped_switch(func));
    }
}
