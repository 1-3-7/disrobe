use disrobe_sleigh::pcode::{PcodeOp, Space, Varnode};
use iced_x86::{Instruction, Mnemonic, OpKind, Register};

use crate::registers::{CF, OF, PF, SF, UniqueAllocator, ZF, constant, is_gpr, register};

use super::{
    Destination, ShiftKind, destination_width, emit_add_flags, emit_declared_undefined_flags,
    emit_shift_flags, memory_pointer, read_destination, read_operand, snapshot, write_destination,
    write_register,
};

pub(super) fn lift_bit_test(
    instruction: &Instruction,
    allocator: &mut UniqueAllocator,
) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 2 {
        return None;
    }
    match instruction.op_kind(0) {
        OpKind::Register if is_gpr(instruction.op_register(0)) => {
            lift_bit_test_register(instruction, allocator)
        }
        OpKind::Memory => lift_bit_test_memory(instruction, allocator),
        _ => None,
    }
}

fn lift_bit_test_register(
    instruction: &Instruction,
    allocator: &mut UniqueAllocator,
) -> Option<Vec<PcodeOp>> {
    let width: u32 = destination_width(instruction, 0)?;
    let width_bits: u32 = width.checked_mul(8)?;
    let index_mask: u32 = width_bits.checked_sub(1)?;
    let selected: Register = instruction.op_register(0);
    let input: Varnode = register(selected)?;
    let mut ops: Vec<PcodeOp> = Vec::new();
    let raw_index: Varnode = read_operand(instruction, 1, width, allocator, &mut ops)?;
    let index: Varnode = allocator.allocate(width)?;
    let shifted: Varnode = allocator.allocate(width)?;
    let tested: Varnode = allocator.allocate(width)?;
    ops.push(PcodeOp::IntAnd {
        output: index,
        left: raw_index,
        right: constant(u64::from(index_mask), width),
    });
    ops.push(PcodeOp::IntRight {
        output: shifted,
        input,
        amount: index,
    });
    ops.push(PcodeOp::IntAnd {
        output: tested,
        left: shifted,
        right: constant(1, width),
    });
    ops.push(PcodeOp::IntNotEqual {
        output: CF,
        left: tested,
        right: constant(0, width),
    });
    let context: Varnode = match instruction.mnemonic() {
        Mnemonic::Bt => input,
        Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc => {
            let bit: Varnode = allocator.allocate(width)?;
            let result: Varnode = allocator.allocate(width)?;
            ops.push(PcodeOp::IntLeft {
                output: bit,
                input: constant(1, width),
                amount: index,
            });
            match instruction.mnemonic() {
                Mnemonic::Bts => ops.push(PcodeOp::IntOr {
                    output: result,
                    left: input,
                    right: bit,
                }),
                Mnemonic::Btr => {
                    let inverse: Varnode = allocator.allocate(width)?;
                    ops.push(PcodeOp::IntNegate {
                        output: inverse,
                        input: bit,
                    });
                    ops.push(PcodeOp::IntAnd {
                        output: result,
                        left: input,
                        right: inverse,
                    });
                }
                Mnemonic::Btc => ops.push(PcodeOp::IntXor {
                    output: result,
                    left: input,
                    right: bit,
                }),
                _ => return None,
            }
            write_register(selected, result, allocator, &mut ops)?;
            result
        }
        _ => return None,
    };
    emit_declared_undefined_flags(instruction, context, &mut ops)?;
    Some(ops)
}

fn lift_bit_test_memory(
    instruction: &Instruction,
    allocator: &mut UniqueAllocator,
) -> Option<Vec<PcodeOp>> {
    let width: u32 = destination_width(instruction, 0)?;
    let mut ops: Vec<PcodeOp> = Vec::new();
    let base: Varnode = memory_pointer(instruction, allocator, &mut ops)?;
    let context: Varnode = match instruction.op_kind(1) {
        OpKind::Register if is_gpr(instruction.op_register(1)) => {
            bit_test_memory_indexed(instruction, base, allocator, &mut ops)?
        }
        OpKind::Immediate8
        | OpKind::Immediate8_2nd
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => {
            bit_test_memory_immediate(instruction, base, width, allocator, &mut ops)?
        }
        _ => return None,
    };
    emit_declared_undefined_flags(instruction, context, &mut ops)?;
    Some(ops)
}

fn bit_test_memory_indexed(
    instruction: &Instruction,
    base: Varnode,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    let bit_index: Varnode = register(instruction.op_register(1))?;
    let index_width: u32 = bit_index.size_bytes;
    let byte_offset: Varnode = allocator.allocate(index_width)?;
    ops.push(PcodeOp::IntSignedRight {
        output: byte_offset,
        input: bit_index,
        amount: constant(3, 4),
    });
    let pointer: Varnode = allocator.allocate(8)?;
    ops.push(PcodeOp::IntAdd {
        output: pointer,
        left: base,
        right: byte_offset,
    });
    let bit_position: Varnode = allocator.allocate(index_width)?;
    ops.push(PcodeOp::IntAnd {
        output: bit_position,
        left: bit_index,
        right: constant(7, index_width),
    });
    let current: Varnode = allocator.allocate(1)?;
    ops.push(PcodeOp::Load {
        output: current,
        space: Space::Ram,
        pointer,
    });
    let shifted: Varnode = allocator.allocate(1)?;
    ops.push(PcodeOp::IntRight {
        output: shifted,
        input: current,
        amount: bit_position,
    });
    let tested: Varnode = allocator.allocate(1)?;
    ops.push(PcodeOp::IntAnd {
        output: tested,
        left: shifted,
        right: constant(1, 1),
    });
    ops.push(PcodeOp::IntNotEqual {
        output: CF,
        left: tested,
        right: constant(0, 1),
    });
    if !matches!(
        instruction.mnemonic(),
        Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc
    ) {
        return Some(base);
    }
    let reloaded: Varnode = allocator.allocate(1)?;
    ops.push(PcodeOp::Load {
        output: reloaded,
        space: Space::Ram,
        pointer,
    });
    let bit_mask: Varnode = allocator.allocate(1)?;
    ops.push(PcodeOp::IntLeft {
        output: bit_mask,
        input: constant(1, 1),
        amount: bit_position,
    });
    let updated: Varnode = allocator.allocate(1)?;
    apply_bit_update(instruction, reloaded, bit_mask, updated, allocator, ops)?;
    ops.push(PcodeOp::Store {
        space: Space::Ram,
        pointer,
        value: updated,
    });
    Some(updated)
}

fn bit_test_memory_immediate(
    instruction: &Instruction,
    base: Varnode,
    width: u32,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    let raw: u64 = instruction.try_immediate(1).ok()?;
    let width_bits: u32 = width.checked_mul(8)?;
    let mask: u64 = u64::from(width_bits.checked_sub(1)?);
    let index: u64 = raw & mask;
    let current: Varnode = allocator.allocate(width)?;
    ops.push(PcodeOp::Load {
        output: current,
        space: Space::Ram,
        pointer: base,
    });
    let shifted: Varnode = allocator.allocate(width)?;
    ops.push(PcodeOp::IntRight {
        output: shifted,
        input: current,
        amount: constant(index, 4),
    });
    let tested: Varnode = allocator.allocate(width)?;
    ops.push(PcodeOp::IntAnd {
        output: tested,
        left: shifted,
        right: constant(1, width),
    });
    ops.push(PcodeOp::IntNotEqual {
        output: CF,
        left: tested,
        right: constant(0, width),
    });
    if !matches!(
        instruction.mnemonic(),
        Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc
    ) {
        return Some(base);
    }
    let bit_mask: Varnode = allocator.allocate(width)?;
    ops.push(PcodeOp::IntLeft {
        output: bit_mask,
        input: constant(1, width),
        amount: constant(index, 4),
    });
    let reloaded: Varnode = allocator.allocate(width)?;
    ops.push(PcodeOp::Load {
        output: reloaded,
        space: Space::Ram,
        pointer: base,
    });
    let updated: Varnode = allocator.allocate(width)?;
    apply_bit_update(instruction, reloaded, bit_mask, updated, allocator, ops)?;
    ops.push(PcodeOp::Store {
        space: Space::Ram,
        pointer: base,
        value: updated,
    });
    Some(updated)
}

fn apply_bit_update(
    instruction: &Instruction,
    current: Varnode,
    bit_mask: Varnode,
    updated: Varnode,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<()> {
    match instruction.mnemonic() {
        Mnemonic::Bts => ops.push(PcodeOp::IntOr {
            output: updated,
            left: current,
            right: bit_mask,
        }),
        Mnemonic::Btr => {
            let inverse: Varnode = allocator.allocate(bit_mask.size_bytes)?;
            ops.push(PcodeOp::IntNegate {
                output: inverse,
                input: bit_mask,
            });
            ops.push(PcodeOp::IntAnd {
                output: updated,
                left: current,
                right: inverse,
            });
        }
        Mnemonic::Btc => ops.push(PcodeOp::IntXor {
            output: updated,
            left: current,
            right: bit_mask,
        }),
        _ => return None,
    }
    Some(())
}

pub(super) fn lift_bswap(
    instruction: &Instruction,
    allocator: &mut UniqueAllocator,
) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 1
        || instruction.op_kind(0) != OpKind::Register
        || !is_gpr(instruction.op_register(0))
    {
        return None;
    }
    let selected: Register = instruction.op_register(0);
    let input: Varnode = register(selected)?;
    let width: u32 = input.size_bytes;
    if !matches!(width, 4 | 8) {
        return None;
    }
    let mut ops: Vec<PcodeOp> = Vec::new();
    let mut combined: Option<Varnode> = None;
    for source_index in (0_u32..width).rev() {
        let source_bits: u32 = source_index.checked_mul(8)?;
        let target_index: u32 = width.checked_sub(1)?.checked_sub(source_index)?;
        let target_bits: u32 = target_index.checked_mul(8)?;
        let mask_value: u64 = 0xff_u64.checked_shl(source_bits)?;
        let masked: Varnode = allocator.allocate(width)?;
        let shifted: Varnode = allocator.allocate(width)?;
        ops.push(PcodeOp::IntAnd {
            output: masked,
            left: input,
            right: constant(mask_value, width),
        });
        if source_bits > target_bits {
            ops.push(PcodeOp::IntRight {
                output: shifted,
                input: masked,
                amount: constant(u64::from(source_bits.checked_sub(target_bits)?), 4),
            });
        } else {
            ops.push(PcodeOp::IntLeft {
                output: shifted,
                input: masked,
                amount: constant(u64::from(target_bits.checked_sub(source_bits)?), 4),
            });
        }
        combined = match combined {
            Some(previous) => {
                let output: Varnode = allocator.allocate(width)?;
                ops.push(PcodeOp::IntOr {
                    output,
                    left: previous,
                    right: shifted,
                });
                Some(output)
            }
            None => Some(shifted),
        };
    }
    write_register(selected, combined?, allocator, &mut ops)?;
    Some(ops)
}

pub(super) fn lift_xadd(
    instruction: &Instruction,
    allocator: &mut UniqueAllocator,
) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 2
        || instruction.op_kind(1) != OpKind::Register
        || !is_gpr(instruction.op_register(1))
    {
        return None;
    }
    let width: u32 = destination_width(instruction, 0)?;
    let mut ops: Vec<PcodeOp> = Vec::new();
    let (raw_target, left): (Destination, Varnode) =
        read_destination(instruction, 0, allocator, &mut ops)?;
    let target: Destination = match raw_target {
        Destination::Memory(pointer) => {
            Destination::Memory(snapshot(pointer, allocator, &mut ops)?)
        }
        Destination::Register(selected) => Destination::Register(selected),
    };
    let right: Varnode = read_operand(instruction, 1, width, allocator, &mut ops)?;
    let result: Varnode = allocator.allocate(width)?;
    ops.push(PcodeOp::IntAdd {
        output: result,
        left,
        right,
    });
    emit_add_flags(instruction, left, right, result, allocator, &mut ops)?;
    write_register(instruction.op_register(1), left, allocator, &mut ops)?;
    write_destination(target, result, allocator, &mut ops)?;
    Some(ops)
}

pub(super) fn lift_sign_extension(
    instruction: &Instruction,
    allocator: &mut UniqueAllocator,
) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 0 {
        return None;
    }
    let registers: (Register, Register, bool) = match instruction.mnemonic() {
        Mnemonic::Cbw => (Register::AL, Register::AX, false),
        Mnemonic::Cwde => (Register::AX, Register::EAX, false),
        Mnemonic::Cdqe => (Register::EAX, Register::RAX, false),
        Mnemonic::Cwd => (Register::AX, Register::DX, true),
        Mnemonic::Cdq => (Register::EAX, Register::EDX, true),
        Mnemonic::Cqo => (Register::RAX, Register::RDX, true),
        _ => return None,
    };
    let input: Varnode = register(registers.0)?;
    let output: Varnode = register(registers.1)?;
    let extended_width: u32 = if registers.2 {
        input.size_bytes.checked_mul(2)?
    } else {
        output.size_bytes
    };
    let extended: Varnode = allocator.allocate(extended_width)?;
    let mut ops: Vec<PcodeOp> = vec![PcodeOp::IntSext {
        output: extended,
        input,
    }];
    let result: Varnode = if registers.2 {
        let high: Varnode = allocator.allocate(output.size_bytes)?;
        ops.push(PcodeOp::Subpiece {
            output: high,
            input: extended,
            byte_offset: constant(u64::from(input.size_bytes), 4),
        });
        high
    } else {
        extended
    };
    write_register(registers.1, result, allocator, &mut ops)?;
    Some(ops)
}

pub(super) fn lift_double_shift(
    instruction: &Instruction,
    allocator: &mut UniqueAllocator,
) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 3 {
        return None;
    }
    if instruction.op_kind(2) == OpKind::Register {
        return lift_double_shift_dynamic(instruction, allocator);
    }
    let width: u32 = destination_width(instruction, 0)?;
    let width_bits: u32 = width.checked_mul(8)?;
    let raw_count: u64 = instruction.try_immediate(2).ok()?;
    let count_mask: u64 = if width == 8 { 0x3f } else { 0x1f };
    let count: u32 = u32::try_from(raw_count & count_mask).ok()?;
    if count == 0 {
        return (instruction.op_kind(0) == OpKind::Register).then(Vec::new);
    }
    if count > width_bits {
        return None;
    }
    let mut ops: Vec<PcodeOp> = Vec::new();
    let (target, input): (Destination, Varnode) =
        read_destination(instruction, 0, allocator, &mut ops)?;
    let source: Varnode = read_operand(instruction, 1, width, allocator, &mut ops)?;
    let primary: Varnode = allocator.allocate(width)?;
    let secondary: Varnode = allocator.allocate(width)?;
    let result: Varnode = allocator.allocate(width)?;
    let remaining: u32 = width_bits.checked_sub(count)?;
    let kind: ShiftKind = match instruction.mnemonic() {
        Mnemonic::Shld => {
            ops.push(PcodeOp::IntLeft {
                output: primary,
                input,
                amount: constant(u64::from(count), 4),
            });
            ops.push(PcodeOp::IntRight {
                output: secondary,
                input: source,
                amount: constant(u64::from(remaining), 4),
            });
            ShiftKind::Left
        }
        Mnemonic::Shrd => {
            ops.push(PcodeOp::IntRight {
                output: primary,
                input,
                amount: constant(u64::from(count), 4),
            });
            ops.push(PcodeOp::IntLeft {
                output: secondary,
                input: source,
                amount: constant(u64::from(remaining), 4),
            });
            ShiftKind::DoubleRight
        }
        _ => return None,
    };
    ops.push(PcodeOp::IntOr {
        output: result,
        left: primary,
        right: secondary,
    });
    emit_shift_flags(
        instruction,
        kind,
        input,
        result,
        count,
        width_bits,
        allocator,
        &mut ops,
    )?;
    write_destination(target, result, allocator, &mut ops)?;
    Some(ops)
}

pub(super) fn lift_dynamic_shift(
    instruction: &Instruction,
    kind: ShiftKind,
    allocator: &mut UniqueAllocator,
) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 2 || instruction.op_kind(1) != OpKind::Register {
        return None;
    }
    let width: u32 = destination_width(instruction, 0)?;
    let mut ops: Vec<PcodeOp> = Vec::new();
    let (target, input): (Destination, Varnode) =
        read_destination(instruction, 0, allocator, &mut ops)?;
    let count: Varnode =
        masked_shift_count(instruction.op_register(1), width, allocator, &mut ops)?;
    let result: Varnode = allocator.allocate(width)?;
    let operation: PcodeOp = match kind {
        ShiftKind::Left => PcodeOp::IntLeft {
            output: result,
            input,
            amount: count,
        },
        ShiftKind::DoubleRight | ShiftKind::Right => PcodeOp::IntRight {
            output: result,
            input,
            amount: count,
        },
        ShiftKind::SignedRight => PcodeOp::IntSignedRight {
            output: result,
            input,
            amount: count,
        },
    };
    ops.push(operation);
    let carry_out: Varnode = shift_carry_out(kind, count, input, allocator, &mut ops)?;
    let overflow: OverflowEffect = shift_overflow(kind, input, result, allocator, &mut ops)?;
    emit_dynamic_shift_flags(count, carry_out, overflow, result, allocator, &mut ops)?;
    write_destination(target, result, allocator, &mut ops)?;
    Some(ops)
}

fn lift_double_shift_dynamic(
    instruction: &Instruction,
    allocator: &mut UniqueAllocator,
) -> Option<Vec<PcodeOp>> {
    let width: u32 = destination_width(instruction, 0)?;
    let width_bits: u32 = width.checked_mul(8)?;
    let mut ops: Vec<PcodeOp> = Vec::new();
    let (target, input): (Destination, Varnode) =
        read_destination(instruction, 0, allocator, &mut ops)?;
    let source: Varnode = read_operand(instruction, 1, width, allocator, &mut ops)?;
    let count: Varnode =
        masked_shift_count(instruction.op_register(2), width, allocator, &mut ops)?;
    let remaining: Varnode = allocator.allocate(1)?;
    ops.push(PcodeOp::IntSub {
        output: remaining,
        left: constant(u64::from(width_bits), 1),
        right: count,
    });
    let primary: Varnode = allocator.allocate(width)?;
    let secondary: Varnode = allocator.allocate(width)?;
    let result: Varnode = allocator.allocate(width)?;
    let kind: ShiftKind = match instruction.mnemonic() {
        Mnemonic::Shld => {
            ops.push(PcodeOp::IntLeft {
                output: primary,
                input,
                amount: count,
            });
            ops.push(PcodeOp::IntRight {
                output: secondary,
                input: source,
                amount: remaining,
            });
            ShiftKind::Left
        }
        Mnemonic::Shrd => {
            ops.push(PcodeOp::IntRight {
                output: primary,
                input,
                amount: count,
            });
            ops.push(PcodeOp::IntLeft {
                output: secondary,
                input: source,
                amount: remaining,
            });
            ShiftKind::DoubleRight
        }
        _ => return None,
    };
    ops.push(PcodeOp::IntOr {
        output: result,
        left: primary,
        right: secondary,
    });
    let carry_out: Varnode = shift_carry_out(kind, count, input, allocator, &mut ops)?;
    let overflow: OverflowEffect = shift_overflow(kind, input, result, allocator, &mut ops)?;
    emit_dynamic_shift_flags(count, carry_out, overflow, result, allocator, &mut ops)?;
    write_destination(target, result, allocator, &mut ops)?;
    Some(ops)
}

fn masked_shift_count(
    count_register: Register,
    width: u32,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    let source: Varnode = register(count_register)?;
    if source.size_bytes != 1 {
        return None;
    }
    let mask: u64 = if width == 8 { 0x3f } else { 0x1f };
    let count: Varnode = allocator.allocate(1)?;
    ops.push(PcodeOp::IntAnd {
        output: count,
        left: source,
        right: constant(mask, 1),
    });
    Some(count)
}

fn shift_carry_out(
    kind: ShiftKind,
    count: Varnode,
    input: Varnode,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    let width: u32 = input.size_bytes;
    let count_minus_one: Varnode = allocator.allocate(1)?;
    ops.push(PcodeOp::IntSub {
        output: count_minus_one,
        left: count,
        right: constant(1, 1),
    });
    let carry_out: Varnode = allocator.allocate(1)?;
    match kind {
        ShiftKind::Left => {
            let shifted: Varnode = allocator.allocate(width)?;
            ops.push(PcodeOp::IntLeft {
                output: shifted,
                input,
                amount: count_minus_one,
            });
            ops.push(PcodeOp::IntSignedLess {
                output: carry_out,
                left: shifted,
                right: constant(0, width),
            });
        }
        ShiftKind::Right | ShiftKind::DoubleRight => {
            let shifted: Varnode = allocator.allocate(width)?;
            ops.push(PcodeOp::IntRight {
                output: shifted,
                input,
                amount: count_minus_one,
            });
            emit_low_bit_set(shifted, carry_out, width, allocator, ops);
        }
        ShiftKind::SignedRight => {
            let shifted: Varnode = allocator.allocate(width)?;
            ops.push(PcodeOp::IntSignedRight {
                output: shifted,
                input,
                amount: count_minus_one,
            });
            emit_low_bit_set(shifted, carry_out, width, allocator, ops);
        }
    }
    Some(carry_out)
}

fn emit_low_bit_set(
    value: Varnode,
    carry_out: Varnode,
    width: u32,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<()> {
    let masked: Varnode = allocator.allocate(width)?;
    ops.push(PcodeOp::IntAnd {
        output: masked,
        left: value,
        right: constant(1, width),
    });
    ops.push(PcodeOp::IntNotEqual {
        output: carry_out,
        left: masked,
        right: constant(0, width),
    });
    Some(())
}

#[derive(Clone, Copy, Debug)]
enum OverflowEffect {
    Defined(Varnode),
    PreservedWhenMultibit,
}

fn shift_overflow(
    kind: ShiftKind,
    input: Varnode,
    result: Varnode,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<OverflowEffect> {
    match kind {
        ShiftKind::SignedRight => Some(OverflowEffect::PreservedWhenMultibit),
        ShiftKind::Right => {
            let overflow_out: Varnode = allocator.allocate(1)?;
            ops.push(PcodeOp::IntSignedLess {
                output: overflow_out,
                left: input,
                right: constant(0, input.size_bytes),
            });
            Some(OverflowEffect::Defined(overflow_out))
        }
        ShiftKind::Left | ShiftKind::DoubleRight => {
            let input_sign: Varnode = allocator.allocate(1)?;
            let result_sign: Varnode = allocator.allocate(1)?;
            let overflow_out: Varnode = allocator.allocate(1)?;
            ops.push(PcodeOp::IntSignedLess {
                output: input_sign,
                left: input,
                right: constant(0, input.size_bytes),
            });
            ops.push(PcodeOp::IntSignedLess {
                output: result_sign,
                left: result,
                right: constant(0, result.size_bytes),
            });
            ops.push(PcodeOp::BoolXor {
                output: overflow_out,
                left: input_sign,
                right: result_sign,
            });
            Some(OverflowEffect::Defined(overflow_out))
        }
    }
}

fn emit_dynamic_shift_flags(
    count: Varnode,
    carry_out: Varnode,
    overflow: OverflowEffect,
    result: Varnode,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<()> {
    let width: u32 = result.size_bytes;
    let changed: Varnode = allocator.allocate(1)?;
    ops.push(PcodeOp::IntNotEqual {
        output: changed,
        left: count,
        right: constant(0, 1),
    });
    let unchanged: Varnode = allocator.allocate(1)?;
    ops.push(PcodeOp::BoolNegate {
        output: unchanged,
        input: changed,
    });
    combine_conditional_flag(CF, changed, unchanged, carry_out, allocator, ops)?;
    let single: Varnode = allocator.allocate(1)?;
    ops.push(PcodeOp::IntEqual {
        output: single,
        left: count,
        right: constant(1, 1),
    });
    let multiple: Varnode = allocator.allocate(1)?;
    ops.push(PcodeOp::BoolNegate {
        output: multiple,
        input: single,
    });
    match overflow {
        OverflowEffect::Defined(value) => {
            combine_conditional_flag(OF, single, multiple, value, allocator, ops)?;
        }
        OverflowEffect::PreservedWhenMultibit => ops.push(PcodeOp::IntAnd {
            output: OF,
            left: multiple,
            right: OF,
        }),
    }
    let sign: Varnode = allocator.allocate(1)?;
    ops.push(PcodeOp::IntSignedLess {
        output: sign,
        left: result,
        right: constant(0, width),
    });
    combine_conditional_flag(SF, changed, unchanged, sign, allocator, ops)?;
    let zero: Varnode = allocator.allocate(1)?;
    ops.push(PcodeOp::IntEqual {
        output: zero,
        left: result,
        right: constant(0, width),
    });
    combine_conditional_flag(ZF, changed, unchanged, zero, allocator, ops)?;
    let parity: Varnode = allocator.allocate(1)?;
    ops.push(PcodeOp::CallOther {
        name: "x86_parity8_pure_v1".to_owned(),
        output: Some(parity),
        inputs: vec![result],
    });
    combine_conditional_flag(PF, changed, unchanged, parity, allocator, ops)?;
    Some(())
}

fn combine_conditional_flag(
    flag: Varnode,
    gate: Varnode,
    negated_gate: Varnode,
    new_value: Varnode,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<()> {
    let keep: Varnode = allocator.allocate(1)?;
    let take: Varnode = allocator.allocate(1)?;
    ops.push(PcodeOp::IntAnd {
        output: keep,
        left: negated_gate,
        right: flag,
    });
    ops.push(PcodeOp::IntAnd {
        output: take,
        left: gate,
        right: new_value,
    });
    ops.push(PcodeOp::IntOr {
        output: flag,
        left: keep,
        right: take,
    });
    Some(())
}
