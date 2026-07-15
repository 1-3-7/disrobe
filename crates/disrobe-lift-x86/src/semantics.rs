use std::collections::BTreeSet;

use disrobe_sleigh::pcode::{DecodeStatus, PcodeOp, Space, Varnode};
use iced_x86::{
    Code, CodeSize, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind,
    Register, RflagsBits, UsedMemory, UsedRegister,
};

use crate::registers::{
    AF, CF, OF, PF, SF, UniqueAllocator, ZF, constant, full_gpr, is_gpr, ram_address, register,
    segment_base,
};

#[derive(Clone, Copy, Debug)]
enum Destination {
    Memory(Varnode),
    Register(Register),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FlagAction {
    Cleared,
    Set,
    Undefined,
    Unmodified,
    Written,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LogicKind {
    And,
    Or,
    Xor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShiftKind {
    Left,
    Right,
    SignedRight,
}

pub(crate) fn lift_instruction(
    instruction: &Instruction,
    mnemonic: &str,
    allocator: &mut UniqueAllocator,
    information: &mut InstructionInfoFactory,
) -> (DecodeStatus, Vec<PcodeOp>) {
    if instruction.has_lock_prefix() {
        return fallback(instruction, mnemonic, allocator, information);
    }
    let lifted: Option<Vec<PcodeOp>> = match instruction.mnemonic() {
        Mnemonic::Mov => lift_mov(instruction, allocator),
        Mnemonic::Movzx => lift_extension(instruction, false, allocator),
        Mnemonic::Movsx | Mnemonic::Movsxd => lift_extension(instruction, true, allocator),
        Mnemonic::Lea => lift_lea(instruction, allocator),
        Mnemonic::Push => lift_push(instruction, allocator),
        Mnemonic::Pop => lift_pop(instruction, allocator),
        Mnemonic::Xchg => lift_xchg(instruction, allocator),
        Mnemonic::Add => lift_add(instruction, allocator),
        Mnemonic::Sub => lift_sub(instruction, true, allocator),
        Mnemonic::Adc => lift_with_carry(instruction, false, allocator),
        Mnemonic::Sbb => lift_with_carry(instruction, true, allocator),
        Mnemonic::And => lift_logic(instruction, LogicKind::And, true, allocator),
        Mnemonic::Or => lift_logic(instruction, LogicKind::Or, true, allocator),
        Mnemonic::Xor => lift_logic(instruction, LogicKind::Xor, true, allocator),
        Mnemonic::Cmp => lift_sub(instruction, false, allocator),
        Mnemonic::Test => lift_logic(instruction, LogicKind::And, false, allocator),
        Mnemonic::Inc => lift_increment(instruction, false, allocator),
        Mnemonic::Dec => lift_increment(instruction, true, allocator),
        Mnemonic::Neg => lift_negate(instruction, allocator),
        Mnemonic::Not => lift_not(instruction, allocator),
        Mnemonic::Shl | Mnemonic::Sal => lift_shift(instruction, ShiftKind::Left, allocator),
        Mnemonic::Shr => lift_shift(instruction, ShiftKind::Right, allocator),
        Mnemonic::Sar => lift_shift(instruction, ShiftKind::SignedRight, allocator),
        Mnemonic::Mul => lift_multiply(instruction, false, allocator),
        Mnemonic::Imul => lift_multiply(instruction, true, allocator),
        Mnemonic::Jmp => lift_jump(instruction, allocator),
        Mnemonic::Ja
        | Mnemonic::Jae
        | Mnemonic::Jb
        | Mnemonic::Jbe
        | Mnemonic::Je
        | Mnemonic::Jg
        | Mnemonic::Jge
        | Mnemonic::Jl
        | Mnemonic::Jle
        | Mnemonic::Jne
        | Mnemonic::Jno
        | Mnemonic::Jnp
        | Mnemonic::Jns
        | Mnemonic::Jo
        | Mnemonic::Jp
        | Mnemonic::Js => lift_conditional_branch(instruction, allocator),
        Mnemonic::Call => lift_call(instruction, allocator),
        Mnemonic::Ret => lift_return(instruction, allocator),
        Mnemonic::Leave if instruction.code() == Code::Leaveq => lift_leave(instruction, allocator),
        Mnemonic::Nop | Mnemonic::Endbr64 => Some(Vec::new()),
        _ => None,
    };
    if matches!(instruction.mnemonic(), Mnemonic::Div | Mnemonic::Idiv) {
        let division: Option<(DecodeStatus, Vec<PcodeOp>)> = lift_division(
            instruction,
            instruction.mnemonic() == Mnemonic::Idiv,
            allocator,
        );
        let Some(result): Option<(DecodeStatus, Vec<PcodeOp>)> = division else {
            return fallback(instruction, mnemonic, allocator, information);
        };
        return result;
    }
    lifted.map_or_else(
        || fallback(instruction, mnemonic, allocator, information),
        |ops: Vec<PcodeOp>| (DecodeStatus::Supported, ops),
    )
}

fn lift_mov(instruction: &Instruction, allocator: &mut UniqueAllocator) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 2 {
        return None;
    }
    let width: u32 = destination_width(instruction, 0)?;
    let mut ops: Vec<PcodeOp> = Vec::new();
    let destination: Destination = destination(instruction, 0, allocator, &mut ops)?;
    let source: Varnode = read_operand(instruction, 1, width, allocator, &mut ops)?;
    write_destination(destination, source, allocator, &mut ops)?;
    Some(ops)
}

fn lift_lea(instruction: &Instruction, allocator: &mut UniqueAllocator) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 2
        || instruction.op_kind(0) != OpKind::Register
        || instruction.op_kind(1) != OpKind::Memory
        || !is_gpr(instruction.op_register(0))
    {
        return None;
    }
    let mut ops: Vec<PcodeOp> = Vec::new();
    let pointer: Varnode = effective_address(instruction, false, allocator, &mut ops)?;
    write_register(instruction.op_register(0), pointer, allocator, &mut ops)?;
    Some(ops)
}

fn lift_extension(
    instruction: &Instruction,
    signed: bool,
    allocator: &mut UniqueAllocator,
) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 2
        || instruction.op_kind(0) != OpKind::Register
        || !is_gpr(instruction.op_register(0))
    {
        return None;
    }
    let destination_size: u32 = destination_width(instruction, 0)?;
    let source_size: u32 = operand_width(instruction, 1)?;
    if source_size >= destination_size {
        return None;
    }
    let mut ops: Vec<PcodeOp> = Vec::new();
    let source: Varnode = read_operand(instruction, 1, source_size, allocator, &mut ops)?;
    let extended: Varnode = allocator.allocate(destination_size)?;
    if signed {
        ops.push(PcodeOp::IntSext {
            output: extended,
            input: source,
        });
    } else {
        ops.push(PcodeOp::IntZext {
            output: extended,
            input: source,
        });
    }
    write_register(instruction.op_register(0), extended, allocator, &mut ops)?;
    Some(ops)
}

fn lift_push(instruction: &Instruction, allocator: &mut UniqueAllocator) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 1 {
        return None;
    }
    let increment: i32 = instruction.stack_pointer_increment();
    let positive_width: i32 = increment.checked_neg()?;
    let width: u32 = u32::try_from(positive_width).ok()?;
    if !matches!(width, 2 | 8) {
        return None;
    }
    let mut ops: Vec<PcodeOp> = Vec::new();
    let source: Varnode = read_operand(instruction, 0, width, allocator, &mut ops)?;
    let snapshot: Varnode = allocator.allocate(width)?;
    ops.push(PcodeOp::Copy {
        output: snapshot,
        input: source,
    });
    let stack: Varnode = register(Register::RSP)?;
    ops.push(PcodeOp::IntSub {
        output: stack,
        left: stack,
        right: constant(u64::from(width), 8),
    });
    ops.push(PcodeOp::Store {
        space: Space::Ram,
        pointer: stack,
        value: snapshot,
    });
    Some(ops)
}

fn lift_pop(instruction: &Instruction, allocator: &mut UniqueAllocator) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 1 {
        return None;
    }
    let increment: i32 = instruction.stack_pointer_increment();
    let width: u32 = u32::try_from(increment).ok()?;
    if !matches!(width, 2 | 8) {
        return None;
    }
    let mut ops: Vec<PcodeOp> = Vec::new();
    let stack: Varnode = register(Register::RSP)?;
    let loaded: Varnode = allocator.allocate(width)?;
    ops.push(PcodeOp::Load {
        output: loaded,
        space: Space::Ram,
        pointer: stack,
    });
    ops.push(PcodeOp::IntAdd {
        output: stack,
        left: stack,
        right: constant(u64::from(width), 8),
    });
    match instruction.op_kind(0) {
        OpKind::Register if is_gpr(instruction.op_register(0)) => {
            write_register(instruction.op_register(0), loaded, allocator, &mut ops)?;
        }
        OpKind::Memory => {
            let pointer: Varnode = memory_pointer(instruction, allocator, &mut ops)?;
            ops.push(PcodeOp::Store {
                space: Space::Ram,
                pointer,
                value: loaded,
            });
        }
        _ => return None,
    }
    Some(ops)
}

fn lift_xchg(instruction: &Instruction, allocator: &mut UniqueAllocator) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 2
        || instruction.op_kind(0) != OpKind::Register
        || instruction.op_kind(1) != OpKind::Register
        || !is_gpr(instruction.op_register(0))
        || !is_gpr(instruction.op_register(1))
    {
        return None;
    }
    let left: Varnode = register(instruction.op_register(0))?;
    let right: Varnode = register(instruction.op_register(1))?;
    if left.size_bytes != right.size_bytes {
        return None;
    }
    if left == right {
        if left.size_bytes != 4 {
            return Some(Vec::new());
        }
        let mut ops: Vec<PcodeOp> = Vec::new();
        write_register(instruction.op_register(0), left, allocator, &mut ops)?;
        return Some(ops);
    }
    let mut ops: Vec<PcodeOp> = Vec::new();
    let snapshot: Varnode = allocator.allocate(left.size_bytes)?;
    ops.push(PcodeOp::Copy {
        output: snapshot,
        input: left,
    });
    write_register(instruction.op_register(0), right, allocator, &mut ops)?;
    write_register(instruction.op_register(1), snapshot, allocator, &mut ops)?;
    Some(ops)
}

fn lift_add(instruction: &Instruction, allocator: &mut UniqueAllocator) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 2 {
        return None;
    }
    let width: u32 = destination_width(instruction, 0)?;
    let mut ops: Vec<PcodeOp> = Vec::new();
    let (destination, left): (Destination, Varnode) =
        read_destination(instruction, 0, allocator, &mut ops)?;
    let right: Varnode = read_operand(instruction, 1, width, allocator, &mut ops)?;
    if left.size_bytes != width || right.size_bytes != width {
        return None;
    }
    let result: Varnode = allocator.allocate(width)?;
    ops.push(PcodeOp::IntAdd {
        output: result,
        left,
        right,
    });
    emit_add_flags(instruction, left, right, result, allocator, &mut ops)?;
    write_destination(destination, result, allocator, &mut ops)?;
    Some(ops)
}

fn lift_sub(
    instruction: &Instruction,
    writes_destination: bool,
    allocator: &mut UniqueAllocator,
) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 2 {
        return None;
    }
    let width: u32 = destination_width(instruction, 0)?;
    let mut ops: Vec<PcodeOp> = Vec::new();
    let (destination, left): (Destination, Varnode) =
        read_destination(instruction, 0, allocator, &mut ops)?;
    let right: Varnode = read_operand(instruction, 1, width, allocator, &mut ops)?;
    let result: Varnode = allocator.allocate(width)?;
    ops.push(PcodeOp::IntSub {
        output: result,
        left,
        right,
    });
    emit_sub_flags(instruction, left, right, result, allocator, &mut ops)?;
    if writes_destination {
        write_destination(destination, result, allocator, &mut ops)?;
    }
    Some(ops)
}

fn lift_with_carry(
    instruction: &Instruction,
    subtracts: bool,
    allocator: &mut UniqueAllocator,
) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 2 {
        return None;
    }
    let width: u32 = destination_width(instruction, 0)?;
    let mut ops: Vec<PcodeOp> = Vec::new();
    let (destination, left): (Destination, Varnode) =
        read_destination(instruction, 0, allocator, &mut ops)?;
    let right: Varnode = read_operand(instruction, 1, width, allocator, &mut ops)?;
    let carry: Varnode = allocator.allocate(width)?;
    ops.push(PcodeOp::IntZext {
        output: carry,
        input: CF,
    });
    let partial: Varnode = allocator.allocate(width)?;
    let result: Varnode = allocator.allocate(width)?;
    let first_carry: Varnode = allocator.allocate(1)?;
    let second_carry: Varnode = allocator.allocate(1)?;
    let first_overflow: Varnode = allocator.allocate(1)?;
    let second_overflow: Varnode = allocator.allocate(1)?;
    if subtracts {
        ops.push(PcodeOp::IntSub {
            output: partial,
            left,
            right,
        });
        ops.push(PcodeOp::IntSub {
            output: result,
            left: partial,
            right: carry,
        });
        ops.push(PcodeOp::IntLess {
            output: first_carry,
            left,
            right,
        });
        ops.push(PcodeOp::IntLess {
            output: second_carry,
            left: partial,
            right: carry,
        });
        ops.push(PcodeOp::IntSignedBorrow {
            output: first_overflow,
            left,
            right,
        });
        ops.push(PcodeOp::IntSignedBorrow {
            output: second_overflow,
            left: partial,
            right: carry,
        });
    } else {
        ops.push(PcodeOp::IntAdd {
            output: partial,
            left,
            right,
        });
        ops.push(PcodeOp::IntAdd {
            output: result,
            left: partial,
            right: carry,
        });
        ops.push(PcodeOp::IntCarry {
            output: first_carry,
            left,
            right,
        });
        ops.push(PcodeOp::IntCarry {
            output: second_carry,
            left: partial,
            right: carry,
        });
        ops.push(PcodeOp::IntSignedCarry {
            output: first_overflow,
            left,
            right,
        });
        ops.push(PcodeOp::IntSignedCarry {
            output: second_overflow,
            left: partial,
            right: carry,
        });
    }
    emit_combined_flag(
        instruction,
        RflagsBits::CF,
        CF,
        first_carry,
        second_carry,
        false,
        result,
        &mut ops,
    )?;
    emit_combined_flag(
        instruction,
        RflagsBits::OF,
        OF,
        first_overflow,
        second_overflow,
        true,
        result,
        &mut ops,
    )?;
    emit_szap_flags(
        instruction,
        Some((left, right)),
        result,
        allocator,
        &mut ops,
    )?;
    write_destination(destination, result, allocator, &mut ops)?;
    Some(ops)
}

fn lift_logic(
    instruction: &Instruction,
    kind: LogicKind,
    writes_destination: bool,
    allocator: &mut UniqueAllocator,
) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 2 {
        return None;
    }
    let width: u32 = destination_width(instruction, 0)?;
    let mut ops: Vec<PcodeOp> = Vec::new();
    let (destination, left): (Destination, Varnode) =
        read_destination(instruction, 0, allocator, &mut ops)?;
    let right: Varnode = read_operand(instruction, 1, width, allocator, &mut ops)?;
    let result: Varnode = allocator.allocate(width)?;
    let operation: PcodeOp = match kind {
        LogicKind::And => PcodeOp::IntAnd {
            output: result,
            left,
            right,
        },
        LogicKind::Or => PcodeOp::IntOr {
            output: result,
            left,
            right,
        },
        LogicKind::Xor => PcodeOp::IntXor {
            output: result,
            left,
            right,
        },
    };
    ops.push(operation);
    emit_logic_flags(instruction, result, allocator, &mut ops)?;
    if writes_destination {
        write_destination(destination, result, allocator, &mut ops)?;
    }
    Some(ops)
}

fn lift_increment(
    instruction: &Instruction,
    subtracts: bool,
    allocator: &mut UniqueAllocator,
) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 1 {
        return None;
    }
    let mut ops: Vec<PcodeOp> = Vec::new();
    let (destination, input): (Destination, Varnode) =
        read_destination(instruction, 0, allocator, &mut ops)?;
    let one: Varnode = constant(1, input.size_bytes);
    let result: Varnode = allocator.allocate(input.size_bytes)?;
    if subtracts {
        ops.push(PcodeOp::IntSub {
            output: result,
            left: input,
            right: one,
        });
        emit_sub_flags(instruction, input, one, result, allocator, &mut ops)?;
    } else {
        ops.push(PcodeOp::IntAdd {
            output: result,
            left: input,
            right: one,
        });
        emit_add_flags(instruction, input, one, result, allocator, &mut ops)?;
    }
    write_destination(destination, result, allocator, &mut ops)?;
    Some(ops)
}

fn lift_negate(instruction: &Instruction, allocator: &mut UniqueAllocator) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 1 {
        return None;
    }
    let mut ops: Vec<PcodeOp> = Vec::new();
    let (destination, input): (Destination, Varnode) =
        read_destination(instruction, 0, allocator, &mut ops)?;
    let zero: Varnode = constant(0, input.size_bytes);
    let result: Varnode = allocator.allocate(input.size_bytes)?;
    ops.push(PcodeOp::IntSub {
        output: result,
        left: zero,
        right: input,
    });
    emit_negate_flags(instruction, input, result, allocator, &mut ops)?;
    write_destination(destination, result, allocator, &mut ops)?;
    Some(ops)
}

fn lift_not(instruction: &Instruction, allocator: &mut UniqueAllocator) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 1 {
        return None;
    }
    let mut ops: Vec<PcodeOp> = Vec::new();
    let (destination, input): (Destination, Varnode) =
        read_destination(instruction, 0, allocator, &mut ops)?;
    let result: Varnode = allocator.allocate(input.size_bytes)?;
    ops.push(PcodeOp::IntNegate {
        output: result,
        input,
    });
    write_destination(destination, result, allocator, &mut ops)?;
    Some(ops)
}

fn lift_shift(
    instruction: &Instruction,
    kind: ShiftKind,
    allocator: &mut UniqueAllocator,
) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 2 {
        return None;
    }
    let width: u32 = destination_width(instruction, 0)?;
    let width_bits: u32 = width.checked_mul(8)?;
    let raw_count: u64 = instruction.try_immediate(1).ok()?;
    let count_mask: u64 = if width == 8 { 0x3f } else { 0x1f };
    let count: u32 = u32::try_from(raw_count & count_mask).ok()?;
    if count == 0 {
        return (instruction.op_kind(0) == OpKind::Register).then(Vec::new);
    }
    if count > width_bits {
        return None;
    }
    let mut ops: Vec<PcodeOp> = Vec::new();
    let (destination, input): (Destination, Varnode) =
        read_destination(instruction, 0, allocator, &mut ops)?;
    let result: Varnode = allocator.allocate(width)?;
    let amount: Varnode = constant(u64::from(count), 4);
    let operation: PcodeOp = match kind {
        ShiftKind::Left => PcodeOp::IntLeft {
            output: result,
            input,
            amount,
        },
        ShiftKind::Right => PcodeOp::IntRight {
            output: result,
            input,
            amount,
        },
        ShiftKind::SignedRight => PcodeOp::IntSignedRight {
            output: result,
            input,
            amount,
        },
    };
    ops.push(operation);
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
    write_destination(destination, result, allocator, &mut ops)?;
    Some(ops)
}

fn lift_multiply(
    instruction: &Instruction,
    signed: bool,
    allocator: &mut UniqueAllocator,
) -> Option<Vec<PcodeOp>> {
    let operand_count: u32 = instruction.op_count();
    if !matches!(operand_count, 1..=3) || (!signed && operand_count != 1) {
        return None;
    }
    if operand_count == 1 {
        return lift_wide_multiply(instruction, signed, allocator);
    }
    if instruction.op_kind(0) != OpKind::Register || !is_gpr(instruction.op_register(0)) {
        return None;
    }
    let width: u32 = destination_width(instruction, 0)?;
    let mut ops: Vec<PcodeOp> = Vec::new();
    let left: Varnode = if operand_count == 2 {
        register(instruction.op_register(0))?
    } else {
        read_operand(instruction, 1, width, allocator, &mut ops)?
    };
    let right_operand: u32 = if operand_count == 2 { 1 } else { 2 };
    let right: Varnode = read_operand(instruction, right_operand, width, allocator, &mut ops)?;
    let full_width: u32 = width.checked_mul(2)?;
    let full_left: Varnode = extend(left, full_width, true, allocator, &mut ops)?;
    let full_right: Varnode = extend(right, full_width, true, allocator, &mut ops)?;
    let product: Varnode = allocator.allocate(full_width)?;
    ops.push(PcodeOp::IntMult {
        output: product,
        left: full_left,
        right: full_right,
    });
    let low: Varnode = allocator.allocate(width)?;
    ops.push(PcodeOp::Subpiece {
        output: low,
        input: product,
        byte_offset: constant(0, 4),
    });
    let restored: Varnode = extend(low, full_width, true, allocator, &mut ops)?;
    let overflow: Varnode = allocator.allocate(1)?;
    ops.push(PcodeOp::IntNotEqual {
        output: overflow,
        left: product,
        right: restored,
    });
    emit_multiply_flags(instruction, overflow, product, &mut ops)?;
    write_register(instruction.op_register(0), low, allocator, &mut ops)?;
    Some(ops)
}

fn lift_wide_multiply(
    instruction: &Instruction,
    signed: bool,
    allocator: &mut UniqueAllocator,
) -> Option<Vec<PcodeOp>> {
    let width: u32 = operand_width(instruction, 0)?;
    if !matches!(width, 1 | 2 | 4 | 8) {
        return None;
    }
    let (low_register, high_register): (Register, Register) = accumulator_pair(width)?;
    let mut ops: Vec<PcodeOp> = Vec::new();
    let left: Varnode = register(low_register)?;
    let right: Varnode = read_operand(instruction, 0, width, allocator, &mut ops)?;
    let full_width: u32 = width.checked_mul(2)?;
    let full_left: Varnode = extend(left, full_width, signed, allocator, &mut ops)?;
    let full_right: Varnode = extend(right, full_width, signed, allocator, &mut ops)?;
    let product: Varnode = allocator.allocate(full_width)?;
    ops.push(PcodeOp::IntMult {
        output: product,
        left: full_left,
        right: full_right,
    });
    let low: Varnode = allocator.allocate(width)?;
    let high: Varnode = allocator.allocate(width)?;
    ops.push(PcodeOp::Subpiece {
        output: low,
        input: product,
        byte_offset: constant(0, 4),
    });
    ops.push(PcodeOp::Subpiece {
        output: high,
        input: product,
        byte_offset: constant(u64::from(width), 4),
    });
    let overflow: Varnode = allocator.allocate(1)?;
    if signed {
        let restored: Varnode = extend(low, full_width, true, allocator, &mut ops)?;
        ops.push(PcodeOp::IntNotEqual {
            output: overflow,
            left: product,
            right: restored,
        });
    } else {
        ops.push(PcodeOp::IntNotEqual {
            output: overflow,
            left: high,
            right: constant(0, width),
        });
    }
    emit_multiply_flags(instruction, overflow, product, &mut ops)?;
    write_register(high_register, high, allocator, &mut ops)?;
    write_register(low_register, low, allocator, &mut ops)?;
    Some(ops)
}

fn lift_division(
    instruction: &Instruction,
    signed: bool,
    allocator: &mut UniqueAllocator,
) -> Option<(DecodeStatus, Vec<PcodeOp>)> {
    if instruction.op_count() != 1 {
        return None;
    }
    let width: u32 = operand_width(instruction, 0)?;
    if !matches!(width, 1 | 2 | 4 | 8) {
        return None;
    }
    let (low_register, high_register): (Register, Register) = accumulator_pair(width)?;
    let mut ops: Vec<PcodeOp> = Vec::new();
    let divisor: Varnode = read_operand(instruction, 0, width, allocator, &mut ops)?;
    let low: Varnode = register(low_register)?;
    let high: Varnode = register(high_register)?;
    let divisor_input: Varnode = snapshot(divisor, allocator, &mut ops)?;
    let low_input: Varnode = snapshot(low, allocator, &mut ops)?;
    let high_input: Varnode = snapshot(high, allocator, &mut ops)?;
    let name: String = if signed {
        "x86_divide_signed_checked_side_effecting_v1".to_owned()
    } else {
        "x86_divide_unsigned_checked_side_effecting_v1".to_owned()
    };
    let quotient_inputs: Vec<Varnode> = vec![high_input, low_input, divisor_input, constant(0, 1)];
    let remainder_inputs: Vec<Varnode> = vec![high_input, low_input, divisor_input, constant(1, 1)];
    ops.push(PcodeOp::CallOther {
        name: name.clone(),
        output: Some(low),
        inputs: quotient_inputs,
    });
    if width == 4 {
        let low_full: Varnode = full_gpr(low_register)?;
        ops.push(PcodeOp::IntZext {
            output: low_full,
            input: low,
        });
    }
    ops.push(PcodeOp::CallOther {
        name,
        output: Some(high),
        inputs: remainder_inputs,
    });
    if width == 4 {
        let high_full: Varnode = full_gpr(high_register)?;
        ops.push(PcodeOp::IntZext {
            output: high_full,
            input: high,
        });
    }
    emit_declared_undefined_flags(instruction, divisor_input, &mut ops)?;
    Some((DecodeStatus::CallOther, ops))
}

fn lift_jump(instruction: &Instruction, allocator: &mut UniqueAllocator) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 1 {
        return None;
    }
    match instruction.op_kind(0) {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Some(vec![PcodeOp::Branch {
                target: ram_address(instruction.near_branch_target()),
            }])
        }
        OpKind::Register | OpKind::Memory => {
            let mut ops: Vec<PcodeOp> = Vec::new();
            let target: Varnode = read_operand(instruction, 0, 8, allocator, &mut ops)?;
            ops.push(PcodeOp::BranchIndirect { target });
            Some(ops)
        }
        _ => None,
    }
}

fn lift_conditional_branch(
    instruction: &Instruction,
    allocator: &mut UniqueAllocator,
) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 1 {
        return None;
    }
    let mut ops: Vec<PcodeOp> = Vec::new();
    let condition: Varnode = branch_condition(instruction.mnemonic(), allocator, &mut ops)?;
    ops.push(PcodeOp::CBranch {
        target: ram_address(instruction.near_branch_target()),
        condition,
    });
    Some(ops)
}

fn lift_call(instruction: &Instruction, allocator: &mut UniqueAllocator) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 1 || instruction.stack_pointer_increment() != -8 {
        return None;
    }
    let mut ops: Vec<PcodeOp> = Vec::new();
    let direct: bool = matches!(
        instruction.op_kind(0),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    );
    let target: Varnode = if direct {
        ram_address(instruction.near_branch_target())
    } else {
        let source: Varnode = read_operand(instruction, 0, 8, allocator, &mut ops)?;
        let snapshot: Varnode = allocator.allocate(8)?;
        ops.push(PcodeOp::Copy {
            output: snapshot,
            input: source,
        });
        snapshot
    };
    let stack: Varnode = register(Register::RSP)?;
    ops.push(PcodeOp::IntSub {
        output: stack,
        left: stack,
        right: constant(8, 8),
    });
    ops.push(PcodeOp::Store {
        space: Space::Ram,
        pointer: stack,
        value: constant(instruction.next_ip(), 8),
    });
    if direct {
        ops.push(PcodeOp::Call { target });
    } else {
        ops.push(PcodeOp::CallIndirect { target });
    }
    Some(ops)
}

fn lift_return(instruction: &Instruction, allocator: &mut UniqueAllocator) -> Option<Vec<PcodeOp>> {
    let increment: i32 = instruction.stack_pointer_increment();
    let positive: u64 = u64::try_from(increment).ok()?;
    if positive < 8 {
        return None;
    }
    let stack: Varnode = register(Register::RSP)?;
    let target: Varnode = allocator.allocate(8)?;
    Some(vec![
        PcodeOp::Load {
            output: target,
            space: Space::Ram,
            pointer: stack,
        },
        PcodeOp::IntAdd {
            output: stack,
            left: stack,
            right: constant(positive, 8),
        },
        PcodeOp::Return {
            target: Some(target),
        },
    ])
}

fn lift_leave(instruction: &Instruction, allocator: &mut UniqueAllocator) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 0 {
        return None;
    }
    let stack: Varnode = register(Register::RSP)?;
    let frame: Varnode = register(Register::RBP)?;
    let loaded: Varnode = allocator.allocate(8)?;
    Some(vec![
        PcodeOp::Copy {
            output: stack,
            input: frame,
        },
        PcodeOp::Load {
            output: loaded,
            space: Space::Ram,
            pointer: stack,
        },
        PcodeOp::Copy {
            output: frame,
            input: loaded,
        },
        PcodeOp::IntAdd {
            output: stack,
            left: stack,
            right: constant(8, 8),
        },
    ])
}

fn destination_width(instruction: &Instruction, operand: u32) -> Option<u32> {
    match instruction.op_kind(operand) {
        OpKind::Register => u32::try_from(instruction.op_register(operand).size()).ok(),
        OpKind::Memory => u32::try_from(instruction.memory_size().size()).ok(),
        _ => None,
    }
    .filter(|size_bytes: &u32| *size_bytes > 0)
}

fn operand_width(instruction: &Instruction, operand: u32) -> Option<u32> {
    match instruction.op_kind(operand) {
        OpKind::Register => u32::try_from(instruction.op_register(operand).size()).ok(),
        OpKind::Memory => u32::try_from(instruction.memory_size().size()).ok(),
        OpKind::Immediate8 | OpKind::Immediate8_2nd => Some(1),
        OpKind::Immediate16 | OpKind::Immediate8to16 => Some(2),
        OpKind::Immediate32 | OpKind::Immediate8to32 => Some(4),
        OpKind::Immediate64 | OpKind::Immediate8to64 | OpKind::Immediate32to64 => Some(8),
        _ => None,
    }
    .filter(|size_bytes: &u32| *size_bytes > 0)
}

fn destination(
    instruction: &Instruction,
    operand: u32,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Destination> {
    match instruction.op_kind(operand) {
        OpKind::Register if is_gpr(instruction.op_register(operand)) => {
            Some(Destination::Register(instruction.op_register(operand)))
        }
        OpKind::Memory => memory_pointer(instruction, allocator, ops).map(Destination::Memory),
        _ => None,
    }
}

fn read_destination(
    instruction: &Instruction,
    operand: u32,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<(Destination, Varnode)> {
    let target: Destination = destination(instruction, operand, allocator, ops)?;
    let value: Varnode = match target {
        Destination::Register(selected) => register(selected)?,
        Destination::Memory(pointer) => {
            let width: u32 = destination_width(instruction, operand)?;
            let loaded: Varnode = allocator.allocate(width)?;
            ops.push(PcodeOp::Load {
                output: loaded,
                space: Space::Ram,
                pointer,
            });
            loaded
        }
    };
    Some((target, value))
}

fn read_operand(
    instruction: &Instruction,
    operand: u32,
    width: u32,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    match instruction.op_kind(operand) {
        OpKind::Register if is_gpr(instruction.op_register(operand)) => {
            register(instruction.op_register(operand))
        }
        OpKind::Memory => {
            let pointer: Varnode = memory_pointer(instruction, allocator, ops)?;
            let output: Varnode = allocator.allocate(width)?;
            ops.push(PcodeOp::Load {
                output,
                space: Space::Ram,
                pointer,
            });
            Some(output)
        }
        OpKind::Immediate8
        | OpKind::Immediate8_2nd
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => instruction
            .try_immediate(operand)
            .ok()
            .map(|value: u64| constant(value, width)),
        _ => None,
    }
}

fn memory_pointer(
    instruction: &Instruction,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    effective_address(instruction, true, allocator, ops)
}

fn effective_address(
    instruction: &Instruction,
    include_segment: bool,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    if instruction.is_ip_rel_memory_operand() {
        let mut pointer: Varnode = constant(instruction.ip_rel_memory_address(), 8);
        if include_segment && instruction.has_segment_prefix() {
            let base: Option<Varnode> = segment_base(instruction.segment_prefix());
            if let Some(segment) = base {
                let combined: Varnode = allocator.allocate(8)?;
                ops.push(PcodeOp::IntAdd {
                    output: combined,
                    left: segment,
                    right: pointer,
                });
                pointer = combined;
            }
        }
        return Some(pointer);
    }
    let base_register: Register = instruction.memory_base();
    let index_register: Register = instruction.memory_index();
    let address_width: u32 = if matches!(
        base_register,
        Register::EAX
            | Register::ECX
            | Register::EDX
            | Register::EBX
            | Register::ESP
            | Register::EBP
            | Register::ESI
            | Register::EDI
            | Register::R8D
            | Register::R9D
            | Register::R10D
            | Register::R11D
            | Register::R12D
            | Register::R13D
            | Register::R14D
            | Register::R15D
    ) || matches!(
        index_register,
        Register::EAX
            | Register::ECX
            | Register::EDX
            | Register::EBX
            | Register::ESP
            | Register::EBP
            | Register::ESI
            | Register::EDI
            | Register::R8D
            | Register::R9D
            | Register::R10D
            | Register::R11D
            | Register::R12D
            | Register::R13D
            | Register::R14D
            | Register::R15D
    ) {
        4
    } else {
        8
    };
    let mut terms: Vec<Varnode> = Vec::new();
    if base_register != Register::None {
        let base: Varnode = register(base_register)?;
        if base.size_bytes != address_width {
            return None;
        }
        terms.push(base);
    }
    if index_register != Register::None {
        let index: Varnode = register(index_register)?;
        if index.size_bytes != address_width {
            return None;
        }
        let scale: u32 = instruction.memory_index_scale();
        if scale == 1 {
            terms.push(index);
        } else {
            let scaled: Varnode = allocator.allocate(address_width)?;
            ops.push(PcodeOp::IntMult {
                output: scaled,
                left: index,
                right: constant(u64::from(scale), address_width),
            });
            terms.push(scaled);
        }
    }
    let displacement: u64 = instruction.memory_displacement64();
    if displacement != 0 || terms.is_empty() {
        terms.push(constant(displacement, address_width));
    }
    let mut iterator: std::vec::IntoIter<Varnode> = terms.into_iter();
    let first: Varnode = iterator.next()?;
    let mut pointer: Varnode = first;
    for term in iterator {
        let output: Varnode = allocator.allocate(address_width)?;
        ops.push(PcodeOp::IntAdd {
            output,
            left: pointer,
            right: term,
        });
        pointer = output;
    }
    if address_width == 4 {
        let extended: Varnode = allocator.allocate(8)?;
        ops.push(PcodeOp::IntZext {
            output: extended,
            input: pointer,
        });
        pointer = extended;
    }
    if include_segment && instruction.has_segment_prefix() {
        let base: Option<Varnode> = segment_base(instruction.segment_prefix());
        if let Some(segment) = base {
            let combined: Varnode = allocator.allocate(8)?;
            ops.push(PcodeOp::IntAdd {
                output: combined,
                left: segment,
                right: pointer,
            });
            pointer = combined;
        }
    }
    Some(pointer)
}

fn write_destination(
    destination: Destination,
    value: Varnode,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<()> {
    match destination {
        Destination::Register(selected) => write_register(selected, value, allocator, ops),
        Destination::Memory(pointer) => {
            ops.push(PcodeOp::Store {
                space: Space::Ram,
                pointer,
                value,
            });
            Some(())
        }
    }
}

fn write_register(
    selected: Register,
    value: Varnode,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<()> {
    let output: Varnode = register(selected)?;
    let input: Varnode = resize(value, output.size_bytes, allocator, ops)?;
    ops.push(PcodeOp::Copy { output, input });
    if output.size_bytes == 4 {
        let full: Varnode = full_gpr(selected)?;
        ops.push(PcodeOp::IntZext {
            output: full,
            input: output,
        });
    }
    Some(())
}

fn snapshot(
    value: Varnode,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    let output: Varnode = allocator.allocate(value.size_bytes)?;
    ops.push(PcodeOp::Copy {
        output,
        input: value,
    });
    Some(output)
}

fn resize(
    value: Varnode,
    size_bytes: u32,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    if value.size_bytes == size_bytes {
        return Some(value);
    }
    if value.size_bytes < size_bytes {
        let output: Varnode = allocator.allocate(size_bytes)?;
        ops.push(PcodeOp::IntZext {
            output,
            input: value,
        });
        return Some(output);
    }
    let output: Varnode = allocator.allocate(size_bytes)?;
    ops.push(PcodeOp::Subpiece {
        output,
        input: value,
        byte_offset: constant(0, 4),
    });
    Some(output)
}

fn emit_add_flags(
    instruction: &Instruction,
    left: Varnode,
    right: Varnode,
    result: Varnode,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<()> {
    emit_binary_flag(
        instruction,
        RflagsBits::CF,
        CF,
        PcodeOp::IntCarry {
            output: CF,
            left,
            right,
        },
        result,
        ops,
    )?;
    emit_binary_flag(
        instruction,
        RflagsBits::OF,
        OF,
        PcodeOp::IntSignedCarry {
            output: OF,
            left,
            right,
        },
        result,
        ops,
    )?;
    emit_szap_flags(instruction, Some((left, right)), result, allocator, ops)
}

fn emit_sub_flags(
    instruction: &Instruction,
    left: Varnode,
    right: Varnode,
    result: Varnode,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<()> {
    emit_binary_flag(
        instruction,
        RflagsBits::CF,
        CF,
        PcodeOp::IntLess {
            output: CF,
            left,
            right,
        },
        result,
        ops,
    )?;
    emit_binary_flag(
        instruction,
        RflagsBits::OF,
        OF,
        PcodeOp::IntSignedBorrow {
            output: OF,
            left,
            right,
        },
        result,
        ops,
    )?;
    emit_szap_flags(instruction, Some((left, right)), result, allocator, ops)
}

fn emit_combined_flag(
    instruction: &Instruction,
    bit: u32,
    flag: Varnode,
    first: Varnode,
    second: Varnode,
    exclusive: bool,
    context: Varnode,
    ops: &mut Vec<PcodeOp>,
) -> Option<()> {
    match flag_action(instruction, bit) {
        FlagAction::Written => {
            let operation: PcodeOp = if exclusive {
                PcodeOp::BoolXor {
                    output: flag,
                    left: first,
                    right: second,
                }
            } else {
                PcodeOp::BoolOr {
                    output: flag,
                    left: first,
                    right: second,
                }
            };
            ops.push(operation);
        }
        action => emit_nonwritten_flag(action, flag, context, ops)?,
    }
    Some(())
}

fn emit_szap_flags(
    instruction: &Instruction,
    arithmetic_inputs: Option<(Varnode, Varnode)>,
    result: Varnode,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<()> {
    emit_binary_flag(
        instruction,
        RflagsBits::SF,
        SF,
        PcodeOp::IntSignedLess {
            output: SF,
            left: result,
            right: constant(0, result.size_bytes),
        },
        result,
        ops,
    )?;
    emit_binary_flag(
        instruction,
        RflagsBits::ZF,
        ZF,
        PcodeOp::IntEqual {
            output: ZF,
            left: result,
            right: constant(0, result.size_bytes),
        },
        result,
        ops,
    )?;
    match flag_action(instruction, RflagsBits::AF) {
        FlagAction::Written => {
            let (left, right): (Varnode, Varnode) = arithmetic_inputs?;
            let xor_inputs: Varnode = allocator.allocate(result.size_bytes)?;
            let xor_result: Varnode = allocator.allocate(result.size_bytes)?;
            let nibble: Varnode = allocator.allocate(result.size_bytes)?;
            ops.push(PcodeOp::IntXor {
                output: xor_inputs,
                left,
                right,
            });
            ops.push(PcodeOp::IntXor {
                output: xor_result,
                left: xor_inputs,
                right: result,
            });
            ops.push(PcodeOp::IntAnd {
                output: nibble,
                left: xor_result,
                right: constant(0x10, result.size_bytes),
            });
            ops.push(PcodeOp::IntNotEqual {
                output: AF,
                left: nibble,
                right: constant(0, result.size_bytes),
            });
        }
        action => emit_nonwritten_flag(action, AF, result, ops)?,
    }
    match flag_action(instruction, RflagsBits::PF) {
        FlagAction::Written => ops.push(PcodeOp::CallOther {
            name: "x86_parity8_pure_v1".to_owned(),
            output: Some(PF),
            inputs: vec![result],
        }),
        action => emit_nonwritten_flag(action, PF, result, ops)?,
    }
    Some(())
}

fn emit_logic_flags(
    instruction: &Instruction,
    result: Varnode,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<()> {
    emit_nonwritten_flag(flag_action(instruction, RflagsBits::CF), CF, result, ops)?;
    emit_nonwritten_flag(flag_action(instruction, RflagsBits::OF), OF, result, ops)?;
    emit_szap_flags(instruction, None, result, allocator, ops)
}

fn emit_negate_flags(
    instruction: &Instruction,
    input: Varnode,
    result: Varnode,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<()> {
    emit_binary_flag(
        instruction,
        RflagsBits::CF,
        CF,
        PcodeOp::IntNotEqual {
            output: CF,
            left: input,
            right: constant(0, input.size_bytes),
        },
        result,
        ops,
    )?;
    emit_binary_flag(
        instruction,
        RflagsBits::OF,
        OF,
        PcodeOp::IntSignedBorrow {
            output: OF,
            left: constant(0, input.size_bytes),
            right: input,
        },
        result,
        ops,
    )?;
    emit_szap_flags(
        instruction,
        Some((constant(0, input.size_bytes), input)),
        result,
        allocator,
        ops,
    )
}

fn emit_shift_flags(
    instruction: &Instruction,
    kind: ShiftKind,
    input: Varnode,
    result: Varnode,
    count: u32,
    width_bits: u32,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<()> {
    match flag_action(instruction, RflagsBits::CF) {
        FlagAction::Written => {
            let shift_count: u32 = match kind {
                ShiftKind::Left => width_bits.checked_sub(count)?,
                ShiftKind::Right | ShiftKind::SignedRight => count.checked_sub(1)?,
            };
            let shifted: Varnode = allocator.allocate(input.size_bytes)?;
            let low_bit: Varnode = allocator.allocate(input.size_bytes)?;
            ops.push(PcodeOp::IntRight {
                output: shifted,
                input,
                amount: constant(u64::from(shift_count), 4),
            });
            ops.push(PcodeOp::IntAnd {
                output: low_bit,
                left: shifted,
                right: constant(1, input.size_bytes),
            });
            ops.push(PcodeOp::IntNotEqual {
                output: CF,
                left: low_bit,
                right: constant(0, input.size_bytes),
            });
        }
        action => emit_nonwritten_flag(action, CF, result, ops)?,
    }
    if count == 1 {
        match flag_action(instruction, RflagsBits::OF) {
            FlagAction::Written => match kind {
                ShiftKind::Left => {
                    let sign: Varnode = allocator.allocate(1)?;
                    ops.push(PcodeOp::IntSignedLess {
                        output: sign,
                        left: result,
                        right: constant(0, result.size_bytes),
                    });
                    ops.push(PcodeOp::BoolXor {
                        output: OF,
                        left: sign,
                        right: CF,
                    });
                }
                ShiftKind::Right => {
                    let sign: Varnode = allocator.allocate(1)?;
                    ops.push(PcodeOp::IntSignedLess {
                        output: sign,
                        left: input,
                        right: constant(0, input.size_bytes),
                    });
                    ops.push(PcodeOp::Copy {
                        output: OF,
                        input: sign,
                    });
                }
                ShiftKind::SignedRight => ops.push(PcodeOp::Copy {
                    output: OF,
                    input: constant(0, 1),
                }),
            },
            action => emit_nonwritten_flag(action, OF, result, ops)?,
        }
    } else if flag_action(instruction, RflagsBits::OF) != FlagAction::Unmodified {
        emit_nonwritten_flag(FlagAction::Undefined, OF, result, ops)?;
    }
    emit_szap_flags(instruction, None, result, allocator, ops)
}

fn extend(
    input: Varnode,
    size_bytes: u32,
    signed: bool,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    if input.size_bytes == size_bytes {
        return Some(input);
    }
    if input.size_bytes > size_bytes {
        return None;
    }
    let output: Varnode = allocator.allocate(size_bytes)?;
    let operation: PcodeOp = if signed {
        PcodeOp::IntSext { output, input }
    } else {
        PcodeOp::IntZext { output, input }
    };
    ops.push(operation);
    Some(output)
}

const fn accumulator_pair(width: u32) -> Option<(Register, Register)> {
    match width {
        1 => Some((Register::AL, Register::AH)),
        2 => Some((Register::AX, Register::DX)),
        4 => Some((Register::EAX, Register::EDX)),
        8 => Some((Register::RAX, Register::RDX)),
        _ => None,
    }
}

fn emit_multiply_flags(
    instruction: &Instruction,
    overflow: Varnode,
    context: Varnode,
    ops: &mut Vec<PcodeOp>,
) -> Option<()> {
    for (bit, flag) in [(RflagsBits::CF, CF), (RflagsBits::OF, OF)] {
        match flag_action(instruction, bit) {
            FlagAction::Written => ops.push(PcodeOp::Copy {
                output: flag,
                input: overflow,
            }),
            action => emit_nonwritten_flag(action, flag, context, ops)?,
        }
    }
    emit_declared_undefined_flags(instruction, context, ops)
}

fn emit_declared_undefined_flags(
    instruction: &Instruction,
    context: Varnode,
    ops: &mut Vec<PcodeOp>,
) -> Option<()> {
    let tracked: [(u32, Varnode); 6] = [
        (RflagsBits::CF, CF),
        (RflagsBits::PF, PF),
        (RflagsBits::AF, AF),
        (RflagsBits::ZF, ZF),
        (RflagsBits::SF, SF),
        (RflagsBits::OF, OF),
    ];
    for (bit, flag) in tracked {
        if flag_action(instruction, bit) == FlagAction::Undefined {
            emit_nonwritten_flag(FlagAction::Undefined, flag, context, ops)?;
        }
    }
    Some(())
}

fn branch_condition(
    mnemonic: Mnemonic,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    match mnemonic {
        Mnemonic::Jo => Some(OF),
        Mnemonic::Jno => bool_negate(OF, allocator, ops),
        Mnemonic::Jb => Some(CF),
        Mnemonic::Jae => bool_negate(CF, allocator, ops),
        Mnemonic::Je => Some(ZF),
        Mnemonic::Jne => bool_negate(ZF, allocator, ops),
        Mnemonic::Jbe => bool_or(CF, ZF, allocator, ops),
        Mnemonic::Ja => {
            let below_or_equal: Varnode = bool_or(CF, ZF, allocator, ops)?;
            bool_negate(below_or_equal, allocator, ops)
        }
        Mnemonic::Js => Some(SF),
        Mnemonic::Jns => bool_negate(SF, allocator, ops),
        Mnemonic::Jp => Some(PF),
        Mnemonic::Jnp => bool_negate(PF, allocator, ops),
        Mnemonic::Jl => bool_xor(SF, OF, allocator, ops),
        Mnemonic::Jge => {
            let less: Varnode = bool_xor(SF, OF, allocator, ops)?;
            bool_negate(less, allocator, ops)
        }
        Mnemonic::Jle => {
            let less: Varnode = bool_xor(SF, OF, allocator, ops)?;
            bool_or(ZF, less, allocator, ops)
        }
        Mnemonic::Jg => {
            let less: Varnode = bool_xor(SF, OF, allocator, ops)?;
            let less_or_equal: Varnode = bool_or(ZF, less, allocator, ops)?;
            bool_negate(less_or_equal, allocator, ops)
        }
        _ => None,
    }
}

fn bool_negate(
    input: Varnode,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    let output: Varnode = allocator.allocate(1)?;
    ops.push(PcodeOp::BoolNegate { output, input });
    Some(output)
}

fn bool_or(
    left: Varnode,
    right: Varnode,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    let output: Varnode = allocator.allocate(1)?;
    ops.push(PcodeOp::BoolOr {
        output,
        left,
        right,
    });
    Some(output)
}

fn bool_xor(
    left: Varnode,
    right: Varnode,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    let output: Varnode = allocator.allocate(1)?;
    ops.push(PcodeOp::BoolXor {
        output,
        left,
        right,
    });
    Some(output)
}

fn emit_binary_flag(
    instruction: &Instruction,
    bit: u32,
    flag: Varnode,
    operation: PcodeOp,
    context: Varnode,
    ops: &mut Vec<PcodeOp>,
) -> Option<()> {
    match flag_action(instruction, bit) {
        FlagAction::Written => ops.push(operation),
        action => emit_nonwritten_flag(action, flag, context, ops)?,
    }
    Some(())
}

fn emit_nonwritten_flag(
    action: FlagAction,
    flag: Varnode,
    context: Varnode,
    ops: &mut Vec<PcodeOp>,
) -> Option<()> {
    match action {
        FlagAction::Cleared => ops.push(PcodeOp::Copy {
            output: flag,
            input: constant(0, 1),
        }),
        FlagAction::Set => ops.push(PcodeOp::Copy {
            output: flag,
            input: constant(1, 1),
        }),
        FlagAction::Undefined => ops.push(PcodeOp::CallOther {
            name: "x86_undefined_flag_pure_v1".to_owned(),
            output: Some(flag),
            inputs: vec![context],
        }),
        FlagAction::Unmodified => {}
        FlagAction::Written => return None,
    }
    Some(())
}

fn flag_action(instruction: &Instruction, bit: u32) -> FlagAction {
    if instruction.rflags_cleared() & bit != 0 {
        FlagAction::Cleared
    } else if instruction.rflags_set() & bit != 0 {
        FlagAction::Set
    } else if instruction.rflags_undefined() & bit != 0 {
        FlagAction::Undefined
    } else if instruction.rflags_written() & bit != 0 {
        FlagAction::Written
    } else {
        FlagAction::Unmodified
    }
}

fn fallback(
    instruction: &Instruction,
    mnemonic: &str,
    allocator: &mut UniqueAllocator,
    information: &mut InstructionInfoFactory,
) -> (DecodeStatus, Vec<PcodeOp>) {
    let details: &iced_x86::InstructionInfo = information.info(instruction);
    let used: Vec<UsedRegister> = details.used_registers().to_vec();
    let memory: Vec<UsedMemory> = details.used_memory().to_vec();
    let mut inputs: BTreeSet<Varnode> = BTreeSet::new();
    let mut outputs: BTreeSet<Varnode> = BTreeSet::new();
    let mut has_unmapped_register: bool = false;
    for usage in &used {
        let node: Option<Varnode> = register(usage.register());
        let Some(node): Option<Varnode> = node else {
            has_unmapped_register = true;
            inputs.insert(opaque_register_descriptor(usage.register()));
            continue;
        };
        match usage.access() {
            OpAccess::Read | OpAccess::CondRead => {
                inputs.insert(node);
            }
            OpAccess::Write | OpAccess::CondWrite => {
                outputs.insert(node);
            }
            OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
                inputs.insert(node);
                outputs.insert(node);
            }
            OpAccess::None | OpAccess::NoMemAccess => {}
        }
    }
    for operand in 0..instruction.op_count() {
        match instruction.op_kind(operand) {
            OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64 => {
                let width: u32 = operand_width(instruction, operand).map_or(8, |value: u32| value);
                if let Ok(value) = instruction.try_immediate(operand) {
                    inputs.insert(constant(value, width));
                }
            }
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                inputs.insert(ram_address(instruction.near_branch_target()));
            }
            _ => {}
        }
    }
    let mut ops: Vec<PcodeOp> = Vec::new();
    for usage in &memory {
        let pointer: Option<Varnode> = used_memory_pointer(usage, allocator, &mut ops);
        if let Some(node) = pointer {
            inputs.insert(node);
        }
    }
    let has_memory: bool = !memory.is_empty();
    let writes_memory: bool = memory.iter().any(|usage: &UsedMemory| {
        matches!(
            usage.access(),
            OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
        )
    });
    let pure_register_effect: bool = pure_scalar_fallback(instruction.mnemonic());
    let atomic_memory: bool = instruction.mnemonic() == Mnemonic::Xchg && has_memory;
    let summary: &str = if has_unmapped_register
        || instruction.has_lock_prefix()
        || atomic_memory
        || instruction.flow_control() != FlowControl::Next
    {
        "side_effecting"
    } else if writes_memory {
        "writes_mem"
    } else if has_memory {
        "reads_mem"
    } else if pure_register_effect {
        "pure"
    } else {
        "side_effecting"
    };
    let name: String = format!("x86_unmodeled_{mnemonic}_{summary}_v1");
    let input_values: Vec<Varnode> = inputs.into_iter().collect();
    let Some(input_nodes): Option<Vec<Varnode>> =
        snapshot_inputs(&input_values, allocator, &mut ops)
    else {
        ops.push(PcodeOp::CallOther {
            name: "x86_lift_resource_limit_side_effecting_v1".to_owned(),
            output: None,
            inputs: input_values,
        });
        return (DecodeStatus::CallOther, ops);
    };
    let effectful: bool = summary != "pure";
    let mut result_inputs: Vec<Varnode> = input_nodes.clone();
    if effectful {
        let Some(effect_token): Option<Varnode> = allocator.allocate(8) else {
            ops.push(PcodeOp::CallOther {
                name: "x86_lift_resource_limit_side_effecting_v1".to_owned(),
                output: None,
                inputs: input_nodes,
            });
            return (DecodeStatus::CallOther, ops);
        };
        ops.push(PcodeOp::CallOther {
            name: name.clone(),
            output: Some(effect_token),
            inputs: input_nodes,
        });
        result_inputs.insert(0, effect_token);
    } else if outputs.is_empty() {
        ops.push(PcodeOp::CallOther {
            name: name.clone(),
            output: None,
            inputs: input_nodes,
        });
    }
    let result_name: String = if effectful {
        format!("x86_unmodeled_{mnemonic}_result_pure_v1")
    } else {
        name
    };
    for output in outputs {
        ops.push(PcodeOp::CallOther {
            name: result_name.clone(),
            output: Some(output),
            inputs: result_inputs.clone(),
        });
        if output.size_bytes == 4 {
            let partial_register: Register = find_gpr_by_offset(output.offset);
            let full: Option<Varnode> = full_gpr(partial_register);
            if let Some(full_output) = full {
                ops.push(PcodeOp::IntZext {
                    output: full_output,
                    input: output,
                });
            }
        }
    }
    let context: Varnode = result_inputs
        .first()
        .map_or_else(|| constant(instruction.ip(), 8), |value: &Varnode| *value);
    let tracked: [(u32, Varnode); 6] = [
        (RflagsBits::CF, CF),
        (RflagsBits::PF, PF),
        (RflagsBits::AF, AF),
        (RflagsBits::ZF, ZF),
        (RflagsBits::SF, SF),
        (RflagsBits::OF, OF),
    ];
    for (bit, flag) in tracked {
        let action: FlagAction = flag_action(instruction, bit);
        if action == FlagAction::Written {
            ops.push(PcodeOp::CallOther {
                name: result_name.clone(),
                output: Some(flag),
                inputs: result_inputs.clone(),
            });
        } else if action != FlagAction::Unmodified
            && emit_nonwritten_flag(action, flag, context, &mut ops).is_none()
        {
            return (DecodeStatus::CallOther, ops);
        }
    }
    (DecodeStatus::CallOther, ops)
}

fn snapshot_inputs(
    values: &[Varnode],
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Vec<Varnode>> {
    let mut snapshots: Vec<Varnode> = Vec::with_capacity(values.len());
    for value in values {
        let stable: Varnode = if matches!(value.space, Space::Register | Space::Unique) {
            snapshot(*value, allocator, ops)?
        } else {
            *value
        };
        snapshots.push(stable);
    }
    Some(snapshots)
}

fn opaque_register_descriptor(selected: Register) -> Varnode {
    let encoded: u64 = u64::from(selected as u16);
    constant(0x7838_3600_0000_0000_u64 | encoded, 8)
}

const fn pure_scalar_fallback(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Cbw
            | Mnemonic::Cdq
            | Mnemonic::Cdqe
            | Mnemonic::Cmova
            | Mnemonic::Cmovae
            | Mnemonic::Cmovb
            | Mnemonic::Cmovbe
            | Mnemonic::Cmove
            | Mnemonic::Cmovg
            | Mnemonic::Cmovge
            | Mnemonic::Cmovl
            | Mnemonic::Cmovle
            | Mnemonic::Cmovne
            | Mnemonic::Cmovno
            | Mnemonic::Cmovnp
            | Mnemonic::Cmovns
            | Mnemonic::Cmovo
            | Mnemonic::Cmovp
            | Mnemonic::Cmovs
            | Mnemonic::Cqo
            | Mnemonic::Cwd
            | Mnemonic::Cwde
            | Mnemonic::Rcl
            | Mnemonic::Rcr
            | Mnemonic::Rol
            | Mnemonic::Ror
    )
}

fn used_memory_pointer(
    usage: &UsedMemory,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    let address_width: u32 = match usage.address_size() {
        CodeSize::Code16 => 2,
        CodeSize::Code32 => 4,
        CodeSize::Code64 | CodeSize::Unknown => 8,
    };
    let mut terms: Vec<Varnode> = Vec::new();
    if usage.base() != Register::None {
        let base: Varnode = register(usage.base())?;
        terms.push(resize(base, address_width, allocator, ops)?);
    }
    if usage.index() != Register::None {
        let raw_index: Varnode = register(usage.index())?;
        let index: Varnode = resize(raw_index, address_width, allocator, ops)?;
        if usage.scale() == 1 {
            terms.push(index);
        } else {
            let scaled: Varnode = allocator.allocate(address_width)?;
            ops.push(PcodeOp::IntMult {
                output: scaled,
                left: index,
                right: constant(u64::from(usage.scale()), address_width),
            });
            terms.push(scaled);
        }
    }
    if usage.displacement() != 0 || terms.is_empty() {
        terms.push(constant(usage.displacement(), address_width));
    }
    let mut iterator: std::vec::IntoIter<Varnode> = terms.into_iter();
    let first: Varnode = iterator.next()?;
    let mut offset: Varnode = first;
    for term in iterator {
        let combined: Varnode = allocator.allocate(address_width)?;
        ops.push(PcodeOp::IntAdd {
            output: combined,
            left: offset,
            right: term,
        });
        offset = combined;
    }
    let mut pointer: Varnode = resize(offset, 8, allocator, ops)?;
    if let Some(segment) = segment_base(usage.segment()) {
        let combined: Varnode = allocator.allocate(8)?;
        ops.push(PcodeOp::IntAdd {
            output: combined,
            left: segment,
            right: pointer,
        });
        pointer = combined;
    }
    Some(pointer)
}

const fn find_gpr_by_offset(offset: u64) -> Register {
    match offset {
        0x00 => Register::EAX,
        0x08 => Register::ECX,
        0x10 => Register::EDX,
        0x18 => Register::EBX,
        0x20 => Register::ESP,
        0x28 => Register::EBP,
        0x30 => Register::ESI,
        0x38 => Register::EDI,
        0x80 => Register::R8D,
        0x88 => Register::R9D,
        0x90 => Register::R10D,
        0x98 => Register::R11D,
        0xa0 => Register::R12D,
        0xa8 => Register::R13D,
        0xb0 => Register::R14D,
        0xb8 => Register::R15D,
        _ => Register::None,
    }
}
