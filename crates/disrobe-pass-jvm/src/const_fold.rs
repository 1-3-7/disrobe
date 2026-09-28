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
    fold_with_locals(cf, &mut out, &block_starts, &mut report);
    (out, report)
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
    report: &mut ConstFoldReport,
) {
    let mut stack: Vec<(Lattice, Option<usize>)> = Vec::new();
    let mut local_lattice: BTreeMap<u16, Lattice> = BTreeMap::new();
    let mut after_transfer: bool = false;
    for index in 0..insns.len() {
        let insn: &Instruction = &insns[index];
        if after_transfer || branch_targets.contains(&insn.pc) {
            stack.clear();
            local_lattice.clear();
        }
        after_transfer = ends_straight_line(insn.opcode);
        if let Some(local) = istore_local(insn) {
            let value: Lattice = stack
                .pop()
                .map_or(Lattice::Unknown, |(l, _): (Lattice, Option<usize>)| l);
            local_lattice.insert(local, value);
            continue;
        }
        for local in written_locals(insn) {
            local_lattice.remove(&local);
        }
        if let Some(value) = const_push_value(cf, insn) {
            stack.push((Lattice::Const(value), Some(index)));
            continue;
        }
        if let Some(local) = iload_local(insn) {
            let value: Lattice = local_lattice
                .get(&local)
                .copied()
                .unwrap_or(Lattice::Unknown);
            stack.push((value, Some(index)));
            continue;
        }
        if let Some(op) = binary_kind(insn.opcode) {
            let rhs: Option<(Lattice, Option<usize>)> = stack.pop();
            let lhs: Option<(Lattice, Option<usize>)> = stack.pop();
            let folded: Option<i32> = match (lhs, rhs) {
                (Some((Lattice::Const(a), Some(lp))), Some((Lattice::Const(b), Some(rp)))) => {
                    let value: i32 = eval_binary(op, a, b);
                    rewrite_range(insns, &[lp, rp], index, value).then_some(value)
                }
                _ => None,
            };
            if folded.is_some() {
                report.values_folded += 1;
            }
            stack.push((folded.map_or(Lattice::Unknown, Lattice::Const), Some(index)));
            continue;
        }
        if let Some(op) = unary_kind(insn.opcode) {
            let operand: Option<(Lattice, Option<usize>)> = stack.pop();
            let folded: Option<i32> = match operand {
                Some((Lattice::Const(a), Some(p))) => {
                    let value: i32 = eval_unary(op, a);
                    rewrite_range(insns, &[p], index, value).then_some(value)
                }
                _ => None,
            };
            if folded.is_some() {
                report.values_folded += 1;
            }
            stack.push((folded.map_or(Lattice::Unknown, Lattice::Const), Some(index)));
            continue;
        }
        let mut effect_stack: Vec<Lattice> = stack
            .iter()
            .map(|(l, _): &(Lattice, Option<usize>)| *l)
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
    fn iinc_invalidates_the_folded_local() {
        let opcodes: Vec<u8> =
            folded_opcodes(&[0x10, 0x0A, 0x3C, 0x84, 0x01, 0x01, 0x1B, 0x05, 0x68, 0xAC]);
        assert_eq!(opcodes, vec![0x10, 0x3C, 0x84, 0x1B, 0x05, 0x68, 0xAC]);
    }
}
