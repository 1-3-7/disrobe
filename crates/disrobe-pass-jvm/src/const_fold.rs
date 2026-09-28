use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::bytecode::{Instruction, Operands};
use crate::classfile::{ClassFile, ConstantPoolEntry};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstFoldReport {
    pub values_folded: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lattice {
    Const(i32),
    Unknown,
}

const NOP: u8 = 0x00;

#[must_use]
pub fn fold_constants(
    cf: &ClassFile,
    insns: &[Instruction],
    handler_pcs: &[u32],
) -> (Vec<Instruction>, ConstFoldReport) {
    let mut out: Vec<Instruction> = insns.to_vec();
    let mut report: ConstFoldReport = ConstFoldReport::default();
    let mut block_starts: std::collections::BTreeSet<u32> = branch_target_pcs(insns);
    block_starts.extend(handler_pcs.iter().copied());
    let entry_states: BTreeMap<usize, LocalConstants> =
        local_constants_at_block_entries(cf, insns, &block_starts, handler_pcs);
    fold_with_locals(cf, &mut out, &block_starts, &entry_states, &mut report);
    (out, report)
}

type LocalConstants = BTreeMap<u16, i32>;

const MAX_DATAFLOW_VISITS_PER_INSTRUCTION: usize = 16;

fn local_constants_at_block_entries(
    cf: &ClassFile,
    insns: &[Instruction],
    block_starts: &std::collections::BTreeSet<u32>,
    handler_pcs: &[u32],
) -> BTreeMap<usize, LocalConstants> {
    let mut entries: BTreeMap<usize, LocalConstants> = BTreeMap::new();
    if insns.is_empty()
        || insns
            .iter()
            .any(|insn: &Instruction| matches!(insn.opcode, 0xA8 | 0xA9 | 0xC9))
    {
        return entries;
    }
    let index_of: BTreeMap<u32, usize> = insns
        .iter()
        .enumerate()
        .map(|(index, insn): (usize, &Instruction)| (insn.pc, index))
        .collect();
    let handlers: std::collections::BTreeSet<usize> = handler_pcs
        .iter()
        .filter_map(|pc: &u32| index_of.get(pc).copied())
        .collect();
    let mut worklist: Vec<usize> = vec![0];
    entries.insert(0, LocalConstants::new());
    for handler in &handlers {
        entries.insert(*handler, LocalConstants::new());
        worklist.push(*handler);
    }
    let budget: usize = insns
        .len()
        .saturating_mul(MAX_DATAFLOW_VISITS_PER_INSTRUCTION);
    let mut visits: usize = 0;
    while let Some(start) = worklist.pop() {
        visits += 1;
        if visits > budget {
            return BTreeMap::new();
        }
        let Some(mut locals): Option<LocalConstants> = entries.get(&start).cloned() else {
            continue;
        };
        let mut stack: Vec<Lattice> = Vec::new();
        let mut index: usize = start;
        loop {
            let insn: &Instruction = &insns[index];
            step_constants(cf, insn, &mut stack, &mut locals);
            let mut successors: Vec<usize> = branch_targets_of(insn)
                .into_iter()
                .filter_map(|pc: u32| index_of.get(&pc).copied())
                .collect();
            let falls_through: bool = !ends_straight_line(insn.opcode);
            let next: usize = index + 1;
            let next_starts_block: bool = insns
                .get(next)
                .is_some_and(|following: &Instruction| block_starts.contains(&following.pc));
            if falls_through && next < insns.len() && !next_starts_block {
                if successors.is_empty() {
                    index = next;
                    continue;
                }
                successors.push(next);
            } else if falls_through && next < insns.len() {
                successors.push(next);
            }
            for successor in successors {
                if handlers.contains(&successor) {
                    continue;
                }
                let changed: bool = match entries.get_mut(&successor) {
                    Some(existing) => {
                        let before: usize = existing.len();
                        existing
                            .retain(|slot: &u16, value: &mut i32| locals.get(slot) == Some(value));
                        existing.len() != before
                    }
                    None => {
                        entries.insert(successor, locals.clone());
                        true
                    }
                };
                if changed {
                    worklist.push(successor);
                }
            }
            break;
        }
    }
    entries
}

fn branch_targets_of(insn: &Instruction) -> Vec<u32> {
    let target = |off: i32| -> u32 { (i64::from(insn.pc) + i64::from(off)) as u32 };
    match &insn.operands {
        Operands::Branch(off) => vec![target(*off)],
        Operands::TableSwitch {
            default, offsets, ..
        } => std::iter::once(*default)
            .chain(offsets.iter().copied())
            .map(target)
            .collect(),
        Operands::LookupSwitch { default, pairs } => std::iter::once(*default)
            .chain(pairs.iter().map(|(_, off): &(i32, i32)| *off))
            .map(target)
            .collect(),
        _ => Vec::new(),
    }
}

fn step_constants(
    cf: &ClassFile,
    insn: &Instruction,
    stack: &mut Vec<Lattice>,
    locals: &mut LocalConstants,
) {
    if let Some(local) = istore_local(insn) {
        match stack.pop() {
            Some(Lattice::Const(value)) => {
                locals.insert(local, value);
            }
            _ => {
                locals.remove(&local);
            }
        }
        return;
    }
    for local in written_locals(insn) {
        locals.remove(&local);
    }
    if let Some(value) = const_push_value(cf, insn) {
        stack.push(Lattice::Const(value));
        return;
    }
    if let Some(local) = iload_local(insn) {
        stack.push(
            locals
                .get(&local)
                .copied()
                .map_or(Lattice::Unknown, Lattice::Const),
        );
        return;
    }
    if let Some(op) = binary_kind(insn.opcode) {
        let rhs: Option<Lattice> = stack.pop();
        let lhs: Option<Lattice> = stack.pop();
        stack.push(match (lhs, rhs) {
            (Some(Lattice::Const(a)), Some(Lattice::Const(b))) => {
                Lattice::Const(eval_binary(op, a, b))
            }
            _ => Lattice::Unknown,
        });
        return;
    }
    if let Some(op) = unary_kind(insn.opcode) {
        let operand: Option<Lattice> = stack.pop();
        stack.push(match operand {
            Some(Lattice::Const(a)) => Lattice::Const(eval_unary(op, a)),
            _ => Lattice::Unknown,
        });
        return;
    }
    apply_generic_effect(insn, stack);
    for slot in stack.iter_mut() {
        *slot = Lattice::Unknown;
    }
}

fn branch_target_pcs(insns: &[Instruction]) -> std::collections::BTreeSet<u32> {
    let mut targets: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    for insn in insns {
        match &insn.operands {
            Operands::Branch(off) => {
                targets.insert((i64::from(insn.pc) + i64::from(*off)) as u32);
            }
            Operands::TableSwitch {
                default, offsets, ..
            } => {
                targets.insert((i64::from(insn.pc) + i64::from(*default)) as u32);
                for off in offsets {
                    targets.insert((i64::from(insn.pc) + i64::from(*off)) as u32);
                }
            }
            Operands::LookupSwitch { default, pairs } => {
                targets.insert((i64::from(insn.pc) + i64::from(*default)) as u32);
                for (_, off) in pairs {
                    targets.insert((i64::from(insn.pc) + i64::from(*off)) as u32);
                }
            }
            _ => {}
        }
    }
    targets
}

fn fold_with_locals(
    cf: &ClassFile,
    insns: &mut [Instruction],
    branch_targets: &std::collections::BTreeSet<u32>,
    entry_states: &BTreeMap<usize, LocalConstants>,
    report: &mut ConstFoldReport,
) {
    let mut stack: Vec<(Lattice, Option<Vec<usize>>)> = Vec::new();
    let mut local_lattice: BTreeMap<u16, Lattice> = BTreeMap::new();
    let mut after_transfer: bool = false;
    for index in 0..insns.len() {
        let insn: &Instruction = &insns[index];
        if after_transfer || branch_targets.contains(&insn.pc) {
            stack.clear();
            local_lattice = entry_states
                .get(&index)
                .map_or_else(BTreeMap::new, |known| {
                    known
                        .iter()
                        .map(|(slot, value): (&u16, &i32)| (*slot, Lattice::Const(*value)))
                        .collect()
                });
        }
        after_transfer = ends_straight_line(insn.opcode);
        if let Some(local) = istore_local(insn) {
            let value: Lattice = stack
                .pop()
                .map_or(Lattice::Unknown, |(l, _): (Lattice, Option<Vec<usize>>)| l);
            local_lattice.insert(local, value);
            continue;
        }
        for local in written_locals(insn) {
            local_lattice.remove(&local);
        }
        if let Some(value) = const_push_value(cf, insn) {
            stack.push((Lattice::Const(value), Some(vec![index])));
            continue;
        }
        if let Some(local) = iload_local(insn) {
            let value: Lattice = local_lattice
                .get(&local)
                .copied()
                .unwrap_or(Lattice::Unknown);
            stack.push((value, Some(vec![index])));
            continue;
        }
        if let Some(op) = binary_kind(insn.opcode) {
            let rhs: Option<(Lattice, Option<Vec<usize>>)> = stack.pop();
            let lhs: Option<(Lattice, Option<Vec<usize>>)> = stack.pop();
            let folded: (Lattice, Option<Vec<usize>>) = match (lhs, rhs) {
                (Some((Lattice::Const(a), lp)), Some((Lattice::Const(b), rp))) => {
                    let value: i32 = eval_binary(op, a, b);
                    let chain: Option<Vec<usize>> =
                        lp.zip(rp)
                            .map(|(mut left, right): (Vec<usize>, Vec<usize>)| {
                                left.extend(right);
                                left
                            });
                    fold_chain(insns, chain, index, value, report)
                }
                _ => (Lattice::Unknown, None),
            };
            stack.push(folded);
            continue;
        }
        if let Some(op) = unary_kind(insn.opcode) {
            let operand: Option<(Lattice, Option<Vec<usize>>)> = stack.pop();
            let folded: (Lattice, Option<Vec<usize>>) = match operand {
                Some((Lattice::Const(a), chain)) => {
                    let value: i32 = eval_unary(op, a);
                    fold_chain(insns, chain, index, value, report)
                }
                _ => (Lattice::Unknown, None),
            };
            stack.push(folded);
            continue;
        }
        let mut effect_stack: Vec<Lattice> = stack
            .iter()
            .map(|(l, _): &(Lattice, Option<Vec<usize>>)| *l)
            .collect();
        apply_generic_effect(insn, &mut effect_stack);
        stack = effect_stack
            .into_iter()
            .map(|_: Lattice| (Lattice::Unknown, None))
            .collect();
    }
}

const fn ends_straight_line(opcode: u8) -> bool {
    matches!(
        opcode,
        0xA7 | 0xA8 | 0xA9 | 0xAA | 0xAB | 0xAC..=0xB1 | 0xBF | 0xC8 | 0xC9
    )
}

fn written_locals(insn: &Instruction) -> Vec<u16> {
    let slot: Option<u16> = match insn.opcode {
        0x36..=0x3A => match insn.operands {
            Operands::Local(i) => Some(i),
            _ => None,
        },
        0x3B..=0x4E => Some(u16::from((insn.opcode - 0x3B) % 4)),
        0x84 => match insn.operands {
            Operands::Iinc { index, .. } => Some(index),
            _ => None,
        },
        _ => None,
    };
    let wide: bool = matches!(insn.opcode, 0x37 | 0x39 | 0x3F..=0x42 | 0x47..=0x4A);
    match slot {
        Some(slot) if wide => vec![slot, slot.saturating_add(1)],
        Some(slot) => vec![slot],
        None => Vec::new(),
    }
}

fn fold_chain(
    insns: &mut [Instruction],
    chain: Option<Vec<usize>>,
    index: usize,
    value: i32,
    report: &mut ConstFoldReport,
) -> (Lattice, Option<Vec<usize>>) {
    let Some(mut chain): Option<Vec<usize>> = chain else {
        return (Lattice::Const(value), None);
    };
    if rewrite_range(insns, &chain, index, value) {
        report.values_folded += 1;
        return (Lattice::Const(value), Some(vec![index]));
    }
    chain.push(index);
    (Lattice::Const(value), Some(chain))
}

fn rewrite_range(
    insns: &mut [Instruction],
    producers: &[usize],
    result: usize,
    value: i32,
) -> bool {
    if !representable_without_pool(value) {
        return false;
    }
    for slot in producers {
        if let Some(insn) = insns.get_mut(*slot) {
            blank(insn);
        }
    }
    if let Some(insn) = insns.get_mut(result) {
        set_push_const(insn, value);
    }
    true
}

const fn representable_without_pool(value: i32) -> bool {
    value >= -32768 && value <= 32767
}

fn blank(insn: &mut Instruction) {
    insn.opcode = NOP;
    insn.mnemonic = "nop";
    insn.operands = Operands::None;
}

fn set_push_const(insn: &mut Instruction, value: i32) {
    match value {
        -1 => set_simple(insn, 0x02, "iconst_m1"),
        0..=5 => set_simple(insn, 0x03 + value as u8, iconst_mnemonic(value)),
        -128..=127 => {
            insn.opcode = 0x10;
            insn.mnemonic = "bipush";
            insn.operands = Operands::Byte(value);
        }
        -32768..=32767 => {
            insn.opcode = 0x11;
            insn.mnemonic = "sipush";
            insn.operands = Operands::Short(value);
        }
        _ => {
            insn.opcode = 0x12;
            insn.mnemonic = "ldc";
            insn.operands = Operands::Byte(value);
        }
    }
}

fn set_simple(insn: &mut Instruction, opcode: u8, mnemonic: &'static str) {
    insn.opcode = opcode;
    insn.mnemonic = mnemonic;
    insn.operands = Operands::None;
}

const fn iconst_mnemonic(value: i32) -> &'static str {
    match value {
        0 => "iconst_0",
        1 => "iconst_1",
        2 => "iconst_2",
        3 => "iconst_3",
        4 => "iconst_4",
        _ => "iconst_5",
    }
}

#[derive(Debug, Clone, Copy)]
enum BinKind {
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    UShr,
}

#[derive(Debug, Clone, Copy)]
enum UnaryKind {
    Neg,
    I2b,
    I2c,
    I2s,
}

const fn binary_kind(opcode: u8) -> Option<BinKind> {
    match opcode {
        0x60 => Some(BinKind::Add),
        0x64 => Some(BinKind::Sub),
        0x68 => Some(BinKind::Mul),
        0x7E => Some(BinKind::And),
        0x80 => Some(BinKind::Or),
        0x82 => Some(BinKind::Xor),
        0x78 => Some(BinKind::Shl),
        0x7A => Some(BinKind::Shr),
        0x7C => Some(BinKind::UShr),
        _ => None,
    }
}

const fn unary_kind(opcode: u8) -> Option<UnaryKind> {
    match opcode {
        0x74 => Some(UnaryKind::Neg),
        0x91 => Some(UnaryKind::I2b),
        0x92 => Some(UnaryKind::I2c),
        0x93 => Some(UnaryKind::I2s),
        _ => None,
    }
}

const fn eval_binary(op: BinKind, a: i32, b: i32) -> i32 {
    match op {
        BinKind::Add => a.wrapping_add(b),
        BinKind::Sub => a.wrapping_sub(b),
        BinKind::Mul => a.wrapping_mul(b),
        BinKind::And => a & b,
        BinKind::Or => a | b,
        BinKind::Xor => a ^ b,
        BinKind::Shl => a.wrapping_shl((b & 0x1F) as u32),
        BinKind::Shr => a.wrapping_shr((b & 0x1F) as u32),
        BinKind::UShr => ((a as u32).wrapping_shr((b & 0x1F) as u32)) as i32,
    }
}

const fn eval_unary(op: UnaryKind, a: i32) -> i32 {
    match op {
        UnaryKind::Neg => a.wrapping_neg(),
        UnaryKind::I2b => a as i8 as i32,
        UnaryKind::I2c => a as u16 as i32,
        UnaryKind::I2s => a as i16 as i32,
    }
}

fn const_push_value(cf: &ClassFile, insn: &Instruction) -> Option<i32> {
    match insn.opcode {
        0x02 => Some(-1),
        0x03..=0x08 => Some(i32::from(insn.opcode) - 0x03),
        0x10 | 0x11 => match insn.operands {
            Operands::Byte(v) | Operands::Short(v) => Some(v),
            _ => None,
        },
        0x12..=0x14 => match insn.operands {
            Operands::ConstPool(idx) => match cf.constant_pool.get(usize::from(idx)) {
                Some(ConstantPoolEntry::Integer(v)) => Some(*v),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

const fn istore_local(insn: &Instruction) -> Option<u16> {
    match insn.opcode {
        0x3B..=0x3E => Some((insn.opcode - 0x3B) as u16),
        0x36 => match insn.operands {
            Operands::Local(i) => Some(i),
            _ => None,
        },
        _ => None,
    }
}

const fn iload_local(insn: &Instruction) -> Option<u16> {
    match insn.opcode {
        0x1A..=0x1D => Some((insn.opcode - 0x1A) as u16),
        0x15 => match insn.operands {
            Operands::Local(i) => Some(i),
            _ => None,
        },
        _ => None,
    }
}

fn apply_generic_effect(insn: &Instruction, stack: &mut Vec<Lattice>) {
    let (pops, pushes): (usize, usize) = stack_effect(insn);
    for _ in 0..pops.min(stack.len()) {
        stack.pop();
    }
    for _ in 0..pushes {
        stack.push(Lattice::Unknown);
    }
}

const fn stack_effect(insn: &Instruction) -> (usize, usize) {
    match insn.opcode {
        0x00 | 0xA7 | 0xC8 => (0, 0),
        0x57 => (1, 0),
        0x58 => (2, 0),
        0x59 => (1, 2),
        0x99..=0x9E | 0xC6 | 0xC7 => (1, 0),
        0x9F..=0xA4 => (2, 0),
        0xAC | 0xB0 => (1, 0),
        0xB1 => (0, 0),
        _ => (0, 1),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::bytecode::disassemble;

    fn empty_class() -> ClassFile {
        ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool: vec![ConstantPoolEntry::Placeholder],
            access_flags: 0,
            this_class: 0,
            super_class: 0,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            attributes: Vec::new(),
        }
    }

    fn folded_opcodes(code: &[u8]) -> Vec<u8> {
        let insns: Vec<Instruction> = disassemble(code).expect("disassemble");
        let (folded, _): (Vec<Instruction>, ConstFoldReport) =
            fold_constants(&empty_class(), &insns, &[]);
        folded
            .iter()
            .map(|insn: &Instruction| insn.opcode)
            .collect()
    }

    #[test]
    fn folding_a_local_times_a_constant_removes_both_operands() {
        let opcodes: Vec<u8> = folded_opcodes(&[0x04, 0x10, 0x0A, 0x3C, 0x1B, 0x05, 0x68, 0xAC]);
        assert_eq!(opcodes, vec![0x04, 0x10, 0x3C, NOP, NOP, 0x10, 0xAC]);
    }

    #[test]
    fn a_local_equal_on_every_path_into_a_join_still_folds() {
        let opcodes: Vec<u8> = folded_opcodes(&[
            0x1A, 0x99, 0x00, 0x09, 0x10, 0x05, 0x3C, 0xA7, 0x00, 0x06, 0x10, 0x05, 0x3C, 0x1B,
            0x05, 0x68, 0xAC,
        ]);
        assert_eq!(
            opcodes,
            vec![
                0x1A, 0x99, 0x10, 0x3C, 0xA7, 0x10, 0x3C, NOP, NOP, 0x10, 0xAC
            ]
        );
    }

    #[test]
    fn a_local_that_differs_between_paths_is_not_folded_at_the_join() {
        let opcodes: Vec<u8> = folded_opcodes(&[
            0x1A, 0x99, 0x00, 0x09, 0x10, 0x05, 0x3C, 0xA7, 0x00, 0x06, 0x10, 0x06, 0x3C, 0x1B,
            0x05, 0x68, 0xAC,
        ]);
        assert_eq!(
            opcodes,
            vec![
                0x1A, 0x99, 0x10, 0x3C, 0xA7, 0x10, 0x3C, 0x1B, 0x05, 0x68, 0xAC
            ]
        );
    }

    #[test]
    fn iinc_invalidates_the_folded_local() {
        let opcodes: Vec<u8> =
            folded_opcodes(&[0x10, 0x0A, 0x3C, 0x84, 0x01, 0x01, 0x1B, 0x05, 0x68, 0xAC]);
        assert_eq!(opcodes, vec![0x10, 0x3C, 0x84, 0x1B, 0x05, 0x68, 0xAC]);
    }
}
