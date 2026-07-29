use std::collections::{BTreeMap, BTreeSet};

use disrobe_ir::payload::RegAccess;
use iced_x86::{
    ConditionCode, FlowControl, Instruction, InstructionInfo, InstructionInfoFactory, Mnemonic,
    OpKind, Register, UsedRegister,
};

use crate::basic_blocks::Transfer;
use crate::disasm_ir::map_access;

const WINDOW_INSTRUCTION_LIMIT: usize = 64;

const NARROWEST_FULL_WRITE_BITS: u32 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Flags {
    zero: bool,
    sign: bool,
    carry: bool,
    overflow: bool,
    parity: bool,
}

#[derive(Debug, Default)]
struct Constants {
    known: BTreeMap<Register, u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Effect {
    Zeroed {
        full: Option<Register>,
        flags: Flags,
    },
    Loaded {
        full: Register,
        value: u64,
    },
    Flagged(Flags),
}

pub(super) fn fold_constant_conditions(decoded: &[&Instruction], transfers: &mut [Transfer]) {
    let leaders: BTreeSet<u64> = branch_targets(transfers);
    for position in 0..transfers.len() {
        let Some(Transfer::ConditionalBranch { taken }): Option<Transfer> =
            transfers.get(position).copied()
        else {
            continue;
        };
        let Some(holds): Option<bool> = decide(decoded, transfers, &leaders, position) else {
            continue;
        };
        let Some(slot): Option<&mut Transfer> = transfers.get_mut(position) else {
            continue;
        };
        *slot = if holds {
            Transfer::UnconditionalBranch { taken }
        } else {
            Transfer::FallsThrough
        };
    }
}

fn branch_targets(transfers: &[Transfer]) -> BTreeSet<u64> {
    transfers
        .iter()
        .filter_map(|transfer: &Transfer| match *transfer {
            Transfer::ConditionalBranch { taken } | Transfer::UnconditionalBranch { taken } => {
                Some(taken)
            }
            Transfer::FallsThrough | Transfer::Terminal { .. } | Transfer::Unresolved => None,
        })
        .collect()
}

fn decide(
    decoded: &[&Instruction],
    transfers: &[Transfer],
    leaders: &BTreeSet<u64>,
    position: usize,
) -> Option<bool> {
    let condition: ConditionCode = decoded.get(position)?.condition_code();
    if condition == ConditionCode::None {
        return None;
    }
    let start: usize = window_start(decoded, transfers, leaders, position);
    let run: &[&Instruction] = decoded.get(start..position)?;
    if run.is_empty() {
        return None;
    }
    let mut constants: Constants = Constants::default();
    let mut flags: Option<Flags> = None;
    let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
    for insn in run.iter().copied() {
        apply(insn, &mut constants, &mut flags, &mut factory);
    }
    holds(condition, flags?)
}

fn window_start(
    decoded: &[&Instruction],
    transfers: &[Transfer],
    leaders: &BTreeSet<u64>,
    position: usize,
) -> usize {
    let floor: usize = position.saturating_sub(WINDOW_INSTRUCTION_LIMIT);
    let mut start: usize = position;
    while start > floor {
        let entered: bool = decoded
            .get(start)
            .is_some_and(|insn: &&Instruction| leaders.contains(&insn.ip()));
        if entered {
            break;
        }
        let Some(previous): Option<usize> = start.checked_sub(1) else {
            break;
        };
        if transfers.get(previous).copied() != Some(Transfer::FallsThrough) {
            break;
        }
        start = previous;
    }
    start
}

fn apply(
    insn: &Instruction,
    constants: &mut Constants,
    flags: &mut Option<Flags>,
    factory: &mut InstructionInfoFactory,
) {
    match modelled(insn, constants) {
        Some(Effect::Zeroed { full, flags: set }) => {
            match full {
                Some(register) => {
                    constants.known.insert(register, 0);
                }
                None => forget_written(insn, constants, factory),
            }
            *flags = Some(set);
        }
        Some(Effect::Loaded { full, value }) => {
            constants.known.insert(full, value);
        }
        Some(Effect::Flagged(set)) => *flags = Some(set),
        None => clobber(insn, constants, flags, factory),
    }
}

fn clobber(
    insn: &Instruction,
    constants: &mut Constants,
    flags: &mut Option<Flags>,
    factory: &mut InstructionInfoFactory,
) {
    if matches!(
        insn.flow_control(),
        FlowControl::Call | FlowControl::IndirectCall | FlowControl::Interrupt
    ) {
        constants.known.clear();
        *flags = None;
        return;
    }
    forget_written(insn, constants, factory);
    if insn.rflags_modified() != 0 {
        *flags = None;
    }
}

fn forget_written(
    insn: &Instruction,
    constants: &mut Constants,
    factory: &mut InstructionInfoFactory,
) {
    let info: &InstructionInfo = factory.info(insn);
    for used in info.used_registers() {
        let used: &UsedRegister = used;
        let access: RegAccess = map_access(used.access());
        if access.writes() {
            constants.known.remove(&used.register().full_register());
        }
    }
}

fn modelled(insn: &Instruction, constants: &Constants) -> Option<Effect> {
    match insn.mnemonic() {
        Mnemonic::Xor | Mnemonic::Sub => self_annihilating(insn),
        Mnemonic::Mov => immediate_load(insn),
        Mnemonic::Cmp => difference(insn, constants).map(Effect::Flagged),
        Mnemonic::Test => conjunction(insn, constants).map(Effect::Flagged),
        _ => None,
    }
}

fn self_annihilating(insn: &Instruction) -> Option<Effect> {
    let (register, bits): (Register, u32) = paired_register(insn)?;
    Some(Effect::Zeroed {
        full: (bits >= NARROWEST_FULL_WRITE_BITS).then(|| register.full_register()),
        flags: logical_flags(0, bits),
    })
}

fn paired_register(insn: &Instruction) -> Option<(Register, u32)> {
    if insn.op_count() != 2
        || insn.op_kind(0) != OpKind::Register
        || insn.op_kind(1) != OpKind::Register
    {
        return None;
    }
    let register: Register = insn.op_register(0);
    if register != insn.op_register(1) {
        return None;
    }
    Some((register, gpr_bits(register)?))
}

fn immediate_load(insn: &Instruction) -> Option<Effect> {
    if insn.op_count() != 2 || insn.op_kind(0) != OpKind::Register {
        return None;
    }
    let register: Register = insn.op_register(0);
    let bits: u32 = gpr_bits(register)?;
    if bits < NARROWEST_FULL_WRITE_BITS || !is_immediate(insn.op_kind(1)) {
        return None;
    }
    Some(Effect::Loaded {
        full: register.full_register(),
        value: insn.immediate(1) & width_mask(bits),
    })
}

fn difference(insn: &Instruction, constants: &Constants) -> Option<Flags> {
    let bits: u32 = comparison_bits(insn)?;
    if let Some((_, same)) = paired_register(insn) {
        let same: u32 = same;
        return (same == bits).then(|| compare_flags(0, 0, bits));
    }
    let left: u64 = known_operand(insn, 0, constants, bits)?;
    let right: u64 = known_operand(insn, 1, constants, bits)?;
    Some(compare_flags(left, right, bits))
}

fn conjunction(insn: &Instruction, constants: &Constants) -> Option<Flags> {
    let bits: u32 = comparison_bits(insn)?;
    let left: u64 = known_operand(insn, 0, constants, bits)?;
    let right: u64 = known_operand(insn, 1, constants, bits)?;
    Some(logical_flags(left & right, bits))
}

fn comparison_bits(insn: &Instruction) -> Option<u32> {
    if insn.op_count() != 2 {
        return None;
    }
    for operand in 0..2 {
        if insn.op_kind(operand) == OpKind::Register {
            return gpr_bits(insn.op_register(operand));
        }
    }
    None
}

fn known_operand(
    insn: &Instruction,
    operand: u32,
    constants: &Constants,
    bits: u32,
) -> Option<u64> {
    let kind: OpKind = insn.op_kind(operand);
    if kind == OpKind::Register {
        let register: Register = insn.op_register(operand);
        if gpr_bits(register)? != bits {
            return None;
        }
        let held: u64 = constants.known.get(&register.full_register()).copied()?;
        return Some(held & width_mask(bits));
    }
    is_immediate(kind).then(|| insn.immediate(operand) & width_mask(bits))
}

fn gpr_bits(register: Register) -> Option<u32> {
    if !register.is_gpr() {
        return None;
    }
    let bits: u32 = u32::try_from(register.size()).ok()?.checked_mul(8)?;
    matches!(bits, 8 | 16 | 32 | 64).then_some(bits)
}

const fn is_immediate(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate32to64
            | OpKind::Immediate64
    )
}

const fn width_mask(bits: u32) -> u64 {
    if bits >= u64::BITS {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

const fn sign_mask(bits: u32) -> u64 {
    1u64 << (bits - 1)
}

const fn compare_flags(left: u64, right: u64, bits: u32) -> Flags {
    let mask: u64 = width_mask(bits);
    let top: u64 = sign_mask(bits);
    let a: u64 = left & mask;
    let b: u64 = right & mask;
    let result: u64 = a.wrapping_sub(b) & mask;
    Flags {
        zero: result == 0,
        sign: result & top != 0,
        carry: a < b,
        overflow: (a ^ b) & (a ^ result) & top != 0,
        parity: even_low_byte(result),
    }
}

const fn logical_flags(value: u64, bits: u32) -> Flags {
    let result: u64 = value & width_mask(bits);
    Flags {
        zero: result == 0,
        sign: result & sign_mask(bits) != 0,
        carry: false,
        overflow: false,
        parity: even_low_byte(result),
    }
}

const fn even_low_byte(result: u64) -> bool {
    (result as u8).count_ones() % 2 == 0
}

const fn holds(condition: ConditionCode, flags: Flags) -> Option<bool> {
    Some(match condition {
        ConditionCode::o => flags.overflow,
        ConditionCode::no => !flags.overflow,
        ConditionCode::b => flags.carry,
        ConditionCode::ae => !flags.carry,
        ConditionCode::e => flags.zero,
        ConditionCode::ne => !flags.zero,
        ConditionCode::be => flags.carry || flags.zero,
        ConditionCode::a => !flags.carry && !flags.zero,
        ConditionCode::s => flags.sign,
        ConditionCode::ns => !flags.sign,
        ConditionCode::p => flags.parity,
        ConditionCode::np => !flags.parity,
        ConditionCode::l => flags.sign != flags.overflow,
        ConditionCode::ge => flags.sign == flags.overflow,
        ConditionCode::le => flags.zero || (flags.sign != flags.overflow),
        ConditionCode::g => !flags.zero && (flags.sign == flags.overflow),
        ConditionCode::None => return None,
    })
}
