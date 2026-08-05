use std::collections::BTreeMap;

use crate::cil::{Instruction, OperandValue, SlotAccess, SlotDecodeError, decode_slot};

use super::blocks::{BlockGraph, Dispatcher, absolute_target, int_literal};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sym {
    Const(i64),
    State,
    Opaque,
}

pub trait KeyOracle: std::fmt::Debug {
    fn decode(&self, method_token: u32, input: i64) -> Option<i64>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NoOracle;

impl KeyOracle for NoOracle {
    fn decode(&self, _method_token: u32, _input: i64) -> Option<i64> {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveError {
    StepLimit,
    StackUnderflow,
    NoBackEdge,
    UnresolvedKey,
    UndecodableSlot,
    BadShape,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    pub offset: u32,
    pub key: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Successors {
    One(Target),
    Two {
        taken: Target,
        fallthrough: Target,
        predicate: Predicate,
    },
    Terminal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Predicate {
    pub opcode: String,
}

const STEP_LIMIT: u32 = 8192;

struct Interp<'g> {
    graph: &'g BlockGraph,
    oracle: &'g dyn KeyOracle,
    state: i64,
    stack: Vec<Sym>,
    locals: BTreeMap<u32, Sym>,
    steps: u32,
    captured_key: Option<i64>,
}

impl<'g> Interp<'g> {
    fn new(graph: &'g BlockGraph, oracle: &'g dyn KeyOracle, state: i64) -> Self {
        Self {
            graph,
            oracle,
            state,
            stack: Vec::with_capacity(16),
            locals: BTreeMap::new(),
            steps: 0,
            captured_key: None,
        }
    }

    fn pop(&mut self) -> Result<Sym, ResolveError> {
        self.stack.pop().ok_or(ResolveError::StackUnderflow)
    }

    const fn dispatcher(&self) -> &Dispatcher {
        &self.graph.dispatcher
    }

    fn load_local(&self, slot: u32) -> Sym {
        match self.locals.get(&slot) {
            Some(sym) => *sym,
            None if slot == self.dispatcher().state_local => Sym::State,
            None => Sym::Opaque,
        }
    }

    fn store_local(&mut self, slot: u32, value: Sym) {
        if slot == self.dispatcher().state_local
            && let Sym::Const(key) = value
        {
            self.captured_key = Some(key);
        }
        self.locals.insert(slot, value);
    }

    fn target_at_index(&self, index_value: i64) -> Result<Target, ResolveError> {
        let count: u32 = self.dispatcher().case_count;
        if count == 0 {
            return Err(ResolveError::BadShape);
        }
        let index: usize = ((index_value as u64 & 0xFFFF_FFFF) as u32 % count) as usize;
        let offset: u32 = self
            .dispatcher()
            .switch_targets
            .get(index)
            .copied()
            .ok_or(ResolveError::UnresolvedKey)?;
        let key: i64 = self.captured_key.unwrap_or(index_value);
        Ok(Target { offset, key })
    }
}

#[must_use]
pub fn is_conditional_branch(name: &str) -> bool {
    matches!(
        name,
        "brtrue"
            | "brtrue.s"
            | "brfalse"
            | "brfalse.s"
            | "beq"
            | "beq.s"
            | "bne.un"
            | "bne.un.s"
            | "bgt"
            | "bgt.s"
            | "bgt.un"
            | "bgt.un.s"
            | "bge"
            | "bge.s"
            | "bge.un"
            | "bge.un.s"
            | "blt"
            | "blt.s"
            | "blt.un"
            | "blt.un.s"
            | "ble"
            | "ble.s"
            | "ble.un"
            | "ble.un.s"
    )
}

#[must_use]
pub fn is_unconditional_branch(name: &str) -> bool {
    matches!(name, "br" | "br.s" | "leave" | "leave.s")
}

#[must_use]
pub fn is_terminal(name: &str) -> bool {
    matches!(
        name,
        "ret" | "throw" | "rethrow" | "endfinally" | "endfilter"
    )
}

#[must_use]
pub fn resolve_header_key(
    graph: &BlockGraph,
    oracle: &dyn KeyOracle,
    instrs: &[Instruction],
    code_size: u32,
) -> Option<i64> {
    let entry: &super::blocks::Block = graph.blocks.first()?;
    let header_idx: usize = ins_index(instrs, graph.dispatcher.header_entry)?;
    let mut interp: Interp<'_> = Interp::new(graph, oracle, 0);
    let mut idx: usize = entry.first;
    loop {
        interp.steps += 1;
        if interp.steps > STEP_LIMIT {
            return None;
        }
        if idx == header_idx {
            break;
        }
        let ins: &Instruction = instrs.get(idx)?;
        let name: &str = ins.name.as_str();
        if is_unconditional_branch(name) {
            let OperandValue::BrTarget(rel) = ins.operand else {
                return None;
            };
            let target: u32 = absolute_target(ins, rel, next_off(instrs, idx, code_size));
            idx = ins_index(instrs, target)?;
            continue;
        }
        if is_conditional_branch(name) || is_terminal(name) || name == "switch" {
            return None;
        }
        step_data(&mut interp, ins).ok()?;
        idx += 1;
    }
    match interp.stack.last().copied() {
        Some(Sym::Const(v)) => Some(v),
        _ => None,
    }
}

pub fn resolve_block(
    graph: &BlockGraph,
    oracle: &dyn KeyOracle,
    instrs: &[Instruction],
    code_size: u32,
    block_first: usize,
    block_last: usize,
    entry_key: i64,
) -> Result<Successors, ResolveError> {
    let mut interp: Interp<'_> = Interp::new(graph, oracle, entry_key);
    run_segment(&mut interp, instrs, code_size, block_first, block_last)
}

fn next_off(instrs: &[Instruction], idx: usize, code_size: u32) -> u32 {
    instrs
        .get(idx + 1)
        .map_or(code_size, |n: &Instruction| n.offset)
}

#[allow(clippy::too_many_lines)]
fn run_segment(
    interp: &mut Interp<'_>,
    instrs: &[Instruction],
    code_size: u32,
    first: usize,
    last: usize,
) -> Result<Successors, ResolveError> {
    let header_entry: u32 = interp.dispatcher().header_entry;
    let mut idx: usize = first;
    let mut in_header: bool = false;
    loop {
        interp.steps += 1;
        if interp.steps > STEP_LIMIT {
            return Err(ResolveError::StepLimit);
        }
        if idx > last && !in_header {
            let fallthrough: u32 = next_off(instrs, last, code_size);
            if fallthrough == header_entry {
                idx = ins_index(instrs, header_entry).ok_or(ResolveError::BadShape)?;
                in_header = true;
                continue;
            }
            return Ok(Successors::One(Target {
                offset: fallthrough,
                key: interp.state,
            }));
        }
        let ins: &Instruction = instrs.get(idx).ok_or(ResolveError::BadShape)?;
        let name: &str = ins.name.as_str();
        if !in_header && is_terminal(name) {
            return Ok(Successors::Terminal);
        }
        if !in_header && is_unconditional_branch(name) {
            let OperandValue::BrTarget(rel) = ins.operand else {
                return Err(ResolveError::BadShape);
            };
            let target: u32 = absolute_target(ins, rel, next_off(instrs, idx, code_size));
            if target == header_entry {
                idx = ins_index(instrs, header_entry).ok_or(ResolveError::BadShape)?;
                in_header = true;
                continue;
            }
            if interp.graph.start_to_block.contains_key(&target) {
                return Ok(Successors::One(Target {
                    offset: target,
                    key: interp.state,
                }));
            }
            idx = ins_index(instrs, target).ok_or(ResolveError::BadShape)?;
            continue;
        }
        if !in_header && is_conditional_branch(name) {
            let OperandValue::BrTarget(rel) = ins.operand else {
                return Err(ResolveError::BadShape);
            };
            let target: u32 = absolute_target(ins, rel, next_off(instrs, idx, code_size));
            return resolve_conditional(interp, instrs, code_size, ins, idx, target);
        }
        if name == "switch" {
            let index_sym: Sym = interp.pop()?;
            let index_value: i64 = resolve_key(index_sym, interp.state)?;
            let target: Target = interp.target_at_index(index_value)?;
            return Ok(Successors::One(target));
        }
        step_data(interp, ins)?;
        idx += 1;
    }
}

fn resolve_conditional(
    interp: &mut Interp<'_>,
    instrs: &[Instruction],
    code_size: u32,
    cond: &Instruction,
    cond_idx: usize,
    taken_target: u32,
) -> Result<Successors, ResolveError> {
    let fallthrough_off: u32 = next_off(instrs, cond_idx, code_size);
    let predicate: Predicate = Predicate {
        opcode: cond.name.clone(),
    };
    consume_predicate_operands(interp, cond.name.as_str())?;

    let taken: Target = resolve_target(
        interp.graph,
        interp.oracle,
        instrs,
        code_size,
        interp.state,
        taken_target,
    )?;
    let fallthrough: Target = resolve_target(
        interp.graph,
        interp.oracle,
        instrs,
        code_size,
        interp.state,
        fallthrough_off,
    )?;

    if taken.offset == fallthrough.offset {
        return Ok(Successors::One(taken));
    }
    Ok(Successors::Two {
        taken,
        fallthrough,
        predicate,
    })
}

fn resolve_target(
    graph: &BlockGraph,
    oracle: &dyn KeyOracle,
    instrs: &[Instruction],
    code_size: u32,
    state: i64,
    target: u32,
) -> Result<Target, ResolveError> {
    if graph.start_to_block.contains_key(&target) && target != graph.dispatcher.header_entry {
        return Ok(Target {
            offset: target,
            key: state,
        });
    }
    let start_idx: usize = ins_index(instrs, target).ok_or(ResolveError::BadShape)?;
    run_key_path(graph, oracle, instrs, code_size, state, start_idx)
}

fn run_key_path(
    graph: &BlockGraph,
    oracle: &dyn KeyOracle,
    instrs: &[Instruction],
    code_size: u32,
    state: i64,
    start_idx: usize,
) -> Result<Target, ResolveError> {
    let mut interp: Interp<'_> = Interp::new(graph, oracle, state);
    let header_entry: u32 = graph.dispatcher.header_entry;
    let mut idx: usize = start_idx;
    let mut in_header: bool = idx == ins_index(instrs, header_entry).unwrap_or(usize::MAX);
    loop {
        interp.steps += 1;
        if interp.steps > STEP_LIMIT {
            return Err(ResolveError::StepLimit);
        }
        let ins: &Instruction = instrs.get(idx).ok_or(ResolveError::BadShape)?;
        let name: &str = ins.name.as_str();
        if !in_header && is_unconditional_branch(name) {
            let OperandValue::BrTarget(rel) = ins.operand else {
                return Err(ResolveError::BadShape);
            };
            let target: u32 = absolute_target(ins, rel, next_off(instrs, idx, code_size));
            if target == header_entry {
                idx = ins_index(instrs, header_entry).ok_or(ResolveError::BadShape)?;
                in_header = true;
                continue;
            }
            idx = ins_index(instrs, target).ok_or(ResolveError::BadShape)?;
            continue;
        }
        if name == "switch" {
            let index_sym: Sym = interp.pop()?;
            let index_value: i64 = resolve_key(index_sym, interp.state)?;
            return interp.target_at_index(index_value);
        }
        if !in_header && (is_terminal(name) || is_conditional_branch(name)) {
            return Err(ResolveError::BadShape);
        }
        step_data(&mut interp, ins)?;
        idx += 1;
    }
}

fn consume_predicate_operands(interp: &mut Interp<'_>, name: &str) -> Result<(), ResolveError> {
    interp.pop()?;
    let binary: bool = !matches!(name, "brtrue" | "brtrue.s" | "brfalse" | "brfalse.s");
    if binary {
        interp.pop()?;
    }
    Ok(())
}

const fn resolve_key(sym: Sym, state: i64) -> Result<i64, ResolveError> {
    match sym {
        Sym::Const(v) => Ok(v),
        Sym::State => Ok(state),
        Sym::Opaque => Err(ResolveError::UnresolvedKey),
    }
}

fn ins_index(instrs: &[Instruction], offset: u32) -> Option<usize> {
    instrs
        .binary_search_by_key(&offset, |i: &Instruction| i.offset)
        .ok()
}

fn step_data(interp: &mut Interp<'_>, ins: &Instruction) -> Result<(), ResolveError> {
    let name: &str = ins.name.as_str();
    if let Some(v) = int_literal(ins) {
        interp.stack.push(Sym::Const(v));
        return Ok(());
    }
    match name {
        "nop" | "break" | "conv.i4" | "conv.u4" | "conv.i" | "conv.u" | "conv.u2" | "conv.i2"
        | "conv.u1" | "conv.i1" => {}
        "dup" => {
            let top: Sym = interp.stack.last().copied().unwrap_or(Sym::Opaque);
            interp.stack.push(top);
        }
        "pop" => {
            let _ = interp.stack.pop();
        }
        "call" | "call.s" => {
            apply_call(interp, ins);
        }
        n if n.starts_with("ldloc") => {
            let slot: u32 = decoded_slot(ins)?;
            let value: Sym = interp.load_local(slot);
            interp.stack.push(value);
        }
        n if n.starts_with("ldarg")
            || n.starts_with("ldsfld")
            || n.starts_with("ldfld")
            || n == "ldlen"
            || n.starts_with("ldelem")
            || n.starts_with("ldind")
            || n == "ldnull"
            || n == "ldstr"
            || n == "ldtoken" =>
        {
            interp.stack.push(Sym::Opaque);
        }
        "mul" | "mul.ovf" | "mul.ovf.un" => bin(interp, i64::wrapping_mul),
        "add" | "add.ovf" | "add.ovf.un" => bin(interp, i64::wrapping_add),
        "sub" | "sub.ovf" | "sub.ovf.un" => bin(interp, i64::wrapping_sub),
        "xor" => bin(interp, |a: i64, b: i64| a ^ b),
        "and" => bin(interp, |a: i64, b: i64| a & b),
        "or" => bin(interp, |a: i64, b: i64| a | b),
        "shl" => bin(interp, |a: i64, b: i64| a.wrapping_shl(b as u32)),
        "shr" => bin(interp, |a: i64, b: i64| {
            (a as i32).wrapping_shr(b as u32) as i64
        }),
        "shr.un" => bin(interp, |a: i64, b: i64| {
            i64::from((a as u32).wrapping_shr(b as u32))
        }),
        "rem.un" => {
            let b: Sym = interp.stack.pop().unwrap_or(Sym::Opaque);
            let a: Sym = interp.stack.pop().unwrap_or(Sym::Opaque);
            let folded: Sym = match (lower_sym(a, interp.state), lower_sym(b, interp.state)) {
                (Some(x), Some(y)) if y != 0 => {
                    let xu: u32 = (x as u64 & 0xFFFF_FFFF) as u32;
                    let yu: u32 = (y as u64 & 0xFFFF_FFFF) as u32;
                    Sym::Const(i64::from(xu % yu))
                }
                _ => Sym::Opaque,
            };
            interp.stack.push(folded);
        }
        "div" | "div.un" | "rem" | "ceq" | "cgt" | "cgt.un" | "clt" | "clt.un" => {
            let _ = interp.stack.pop();
            let _ = interp.stack.pop();
            interp.stack.push(Sym::Opaque);
        }
        n if n.starts_with("stloc") => {
            let slot: u32 = decoded_slot(ins)?;
            let v: Sym = interp.stack.pop().unwrap_or(Sym::Opaque);
            interp.store_local(slot, v);
        }
        n if n.starts_with("starg") || n.starts_with("stsfld") => {
            let _ = interp.stack.pop();
        }
        n if n.starts_with("stfld") || n.starts_with("stelem") || n.starts_with("stind") => {
            let _ = interp.stack.pop();
            let _ = interp.stack.pop();
        }
        "neg" | "not" => {
            let v: Sym = interp.stack.pop().unwrap_or(Sym::Opaque);
            interp.stack.push(if let Sym::Const(c) = v {
                Sym::Const(if name == "neg" { c.wrapping_neg() } else { !c })
            } else {
                Sym::Opaque
            });
        }
        "newarr" => {
            let _ = interp.stack.pop();
            interp.stack.push(Sym::Opaque);
        }
        _ => {
            interp.stack.push(Sym::Opaque);
        }
    }
    Ok(())
}

fn apply_call(interp: &mut Interp<'_>, ins: &Instruction) {
    let OperandValue::Token(token) = ins.operand else {
        interp.stack.push(Sym::Opaque);
        return;
    };
    let arg: Sym = interp.stack.pop().unwrap_or(Sym::Opaque);
    let folded: Sym = lower_sym(arg, interp.state)
        .and_then(|input: i64| interp.oracle.decode(token, input))
        .map_or(Sym::Opaque, Sym::Const);
    interp.stack.push(folded);
}

fn decoded_slot(ins: &Instruction) -> Result<u32, ResolveError> {
    decode_slot(ins)
        .map(|access: SlotAccess| u32::from(access.index))
        .map_err(|_: SlotDecodeError| ResolveError::UndecodableSlot)
}

const fn lower_sym(s: Sym, state: i64) -> Option<i64> {
    match s {
        Sym::Const(v) => Some(v),
        Sym::State => Some(state),
        Sym::Opaque => None,
    }
}

fn bin(interp: &mut Interp<'_>, op: fn(i64, i64) -> i64) {
    let b: Sym = interp.stack.pop().unwrap_or(Sym::Opaque);
    let a: Sym = interp.stack.pop().unwrap_or(Sym::Opaque);
    let state: i64 = interp.state;
    let folded: Sym = match (lower_sym(a, state), lower_sym(b, state)) {
        (Some(x), Some(y)) => Sym::Const(op(x, y)),
        _ => Sym::Opaque,
    };
    interp.stack.push(folded);
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn conditional_branch_detection() {
        assert!(is_conditional_branch("blt.s"));
        assert!(is_conditional_branch("brtrue"));
        assert!(!is_conditional_branch("br"));
        assert!(is_unconditional_branch("br.s"));
        assert!(is_terminal("ret"));
    }

    fn ins(offset: u32, name: &str, operand: OperandValue) -> Instruction {
        Instruction {
            offset,
            opcode: 0,
            name: name.to_owned(),
            operand,
            flow: crate::cil::FlowControl::Next,
        }
    }

    fn single_block_graph(instrs: &[Instruction]) -> BlockGraph {
        BlockGraph {
            blocks: vec![super::super::blocks::Block {
                start: 0,
                first: 0,
                last: instrs.len().saturating_sub(1),
            }],
            start_to_block: BTreeMap::new(),
            dispatcher: Dispatcher {
                state_local: 0,
                case_count: 1,
                switch_index: 0,
                switch_targets: vec![0],
                header_entry: u32::MAX,
            },
        }
    }

    fn resolve_only_block(instrs: &[Instruction]) -> Result<Successors, ResolveError> {
        let graph: BlockGraph = single_block_graph(instrs);
        resolve_block(
            &graph,
            &NoOracle,
            instrs,
            u32::try_from(instrs.len()).unwrap_or(u32::MAX),
            0,
            instrs.len() - 1,
            0,
        )
    }

    #[test]
    fn a_negative_load_operand_abstains_instead_of_reading_slot_zero() {
        let instrs: Vec<Instruction> = vec![
            ins(0, "ldloc", OperandValue::I32(-1)),
            ins(1, "ret", OperandValue::None),
        ];
        assert_eq!(
            resolve_only_block(&instrs),
            Err(ResolveError::UndecodableSlot)
        );
    }

    #[test]
    fn a_negative_store_operand_abstains_instead_of_writing_slot_zero() {
        let instrs: Vec<Instruction> = vec![
            ins(0, "ldc.i4.5", OperandValue::None),
            ins(1, "stloc", OperandValue::I32(-1)),
            ins(2, "ret", OperandValue::None),
        ];
        assert_eq!(
            resolve_only_block(&instrs),
            Err(ResolveError::UndecodableSlot)
        );
    }

    #[test]
    fn every_encodable_local_form_still_resolves() {
        for (name, operand, slot) in [
            ("ldloc.0", OperandValue::None, 0_u32),
            ("ldloc.3", OperandValue::None, 3),
            ("ldloc.s", OperandValue::U8(255), 255),
            ("ldloc", OperandValue::U16(65535), 65535),
        ] {
            let instrs: Vec<Instruction> =
                vec![ins(0, name, operand), ins(1, "ret", OperandValue::None)];
            let graph: BlockGraph = single_block_graph(&instrs);
            let mut interp: Interp<'_> = Interp::new(&graph, &NoOracle, 7);
            interp.locals.insert(slot, Sym::Const(i64::from(slot) + 1));
            assert_eq!(
                step_data(&mut interp, &instrs[0]),
                Ok(()),
                "{name} must decode"
            );
            assert_eq!(
                interp.stack.last().copied(),
                Some(Sym::Const(i64::from(slot) + 1)),
                "{name} must read slot {slot}"
            );
        }
    }
}
