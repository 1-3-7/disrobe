use disrobe_sleigh::pcode::{PcodeOp, Varnode};
use iced_x86::{Instruction, Mnemonic, OpKind, Register};

use crate::registers::{CF, UniqueAllocator, constant, is_gpr, register};

use super::{
    Destination, ShiftKind, destination_width, emit_add_flags, emit_declared_undefined_flags,
    emit_shift_flags, read_destination, read_operand, snapshot, write_destination, write_register,
};

pub(super) fn lift_bit_test(
    instruction: &Instruction,
    allocator: &mut UniqueAllocator,
) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 2
        || instruction.op_kind(0) != OpKind::Register
        || !is_gpr(instruction.op_register(0))
    {
        return None;
    }
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
