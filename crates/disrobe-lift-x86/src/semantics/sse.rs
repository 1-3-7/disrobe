use disrobe_sleigh::pcode::{PcodeOp, Space, Varnode};
use iced_x86::{Instruction, Mnemonic, OpKind, Register};

use crate::registers::{UniqueAllocator, constant, is_gpr, register, xmm_lane};

use super::{memory_pointer, write_register};

pub(super) fn lift_move(
    instruction: &Instruction,
    allocator: &mut UniqueAllocator,
) -> Option<Vec<PcodeOp>> {
    match instruction.mnemonic() {
        Mnemonic::Movss => lift_scalar_move(instruction, 4, allocator),
        Mnemonic::Movsd if instruction.op_count() == 2 => {
            lift_scalar_move(instruction, 8, allocator)
        }
        Mnemonic::Movaps | Mnemonic::Movups => lift_vector_move(instruction, allocator),
        Mnemonic::Movd => lift_integer_move(instruction, 4, allocator),
        Mnemonic::Movq => lift_integer_move(instruction, 8, allocator),
        _ => None,
    }
}

pub(super) fn lift_bitwise(
    instruction: &Instruction,
    allocator: &mut UniqueAllocator,
) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 2
        || instruction.op_kind(0) != OpKind::Register
        || !instruction.op_register(0).is_xmm()
    {
        return None;
    }
    let selected: Register = instruction.op_register(0);
    let mut ops: Vec<PcodeOp> = Vec::new();
    let source: VectorSource = vector_source(instruction, 1, allocator, &mut ops)?;
    match instruction.mnemonic() {
        Mnemonic::Pxor => emit_full_binary(selected, source, VectorLogic::Xor, &mut ops)?,
        Mnemonic::Orps => emit_full_binary(selected, source, VectorLogic::Or, &mut ops)?,
        Mnemonic::Xorps => {
            emit_lane_binary(selected, source, 4, VectorLogic::Xor, allocator, &mut ops)?;
        }
        Mnemonic::Xorpd => {
            emit_lane_binary(selected, source, 8, VectorLogic::Xor, allocator, &mut ops)?;
        }
        Mnemonic::Andps => {
            emit_lane_binary(selected, source, 4, VectorLogic::And, allocator, &mut ops)?;
        }
        _ => return None,
    }
    Some(ops)
}

#[derive(Clone, Copy, Debug)]
enum VectorSource {
    Memory(Varnode),
    Register(Register),
}

#[derive(Clone, Copy, Debug)]
enum VectorLogic {
    And,
    Or,
    Xor,
}

fn lift_scalar_move(
    instruction: &Instruction,
    width: u32,
    allocator: &mut UniqueAllocator,
) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 2 {
        return None;
    }
    let mut ops: Vec<PcodeOp> = Vec::new();
    match instruction.op_kind(0) {
        OpKind::Register if instruction.op_register(0).is_xmm() => {
            let selected: Register = instruction.op_register(0);
            let source: Varnode = scalar_source(instruction, 1, width, allocator, &mut ops)?;
            let output: Varnode = xmm_lane(selected, 0, width)?;
            ops.push(PcodeOp::Copy {
                output,
                input: source,
            });
            if instruction.op_kind(1) == OpKind::Memory {
                let mut byte_offset: u32 = width;
                while byte_offset < 16 {
                    let lane: Varnode = xmm_lane(selected, byte_offset, width)?;
                    ops.push(PcodeOp::Copy {
                        output: lane,
                        input: constant(0, width),
                    });
                    byte_offset = byte_offset.checked_add(width)?;
                }
            }
        }
        OpKind::Memory => {
            if instruction.op_kind(1) != OpKind::Register || !instruction.op_register(1).is_xmm() {
                return None;
            }
            let pointer: Varnode = memory_pointer(instruction, allocator, &mut ops)?;
            let value: Varnode = xmm_lane(instruction.op_register(1), 0, width)?;
            ops.push(PcodeOp::Store {
                space: Space::Ram,
                pointer,
                value,
            });
        }
        _ => return None,
    }
    Some(ops)
}

fn lift_vector_move(
    instruction: &Instruction,
    allocator: &mut UniqueAllocator,
) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 2 {
        return None;
    }
    let mut ops: Vec<PcodeOp> = Vec::new();
    match instruction.op_kind(0) {
        OpKind::Register if instruction.op_register(0).is_xmm() => {
            let selected: Register = instruction.op_register(0);
            let source: VectorSource = vector_source(instruction, 1, allocator, &mut ops)?;
            let mut byte_offset: u32 = 0;
            while byte_offset < 16 {
                let output: Varnode = xmm_lane(selected, byte_offset, 4)?;
                let input: Varnode = source_lane(source, byte_offset, 4, allocator, &mut ops)?;
                ops.push(PcodeOp::Copy { output, input });
                byte_offset = byte_offset.checked_add(4)?;
            }
        }
        OpKind::Memory => {
            if instruction.op_kind(1) != OpKind::Register || !instruction.op_register(1).is_xmm() {
                return None;
            }
            let pointer: Varnode = memory_pointer(instruction, allocator, &mut ops)?;
            let value: Varnode = register(instruction.op_register(1))?;
            ops.push(PcodeOp::Store {
                space: Space::Ram,
                pointer,
                value,
            });
        }
        _ => return None,
    }
    Some(ops)
}

fn lift_integer_move(
    instruction: &Instruction,
    width: u32,
    allocator: &mut UniqueAllocator,
) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 2 {
        return None;
    }
    let mut ops: Vec<PcodeOp> = Vec::new();
    match instruction.op_kind(0) {
        OpKind::Register if instruction.op_register(0).is_xmm() => {
            let input: Varnode = integer_or_xmm_source(instruction, 1, width, allocator, &mut ops)?;
            let output: Varnode = register(instruction.op_register(0))?;
            ops.push(PcodeOp::IntZext { output, input });
        }
        OpKind::Register if is_gpr(instruction.op_register(0)) => {
            if instruction.op_kind(1) != OpKind::Register || !instruction.op_register(1).is_xmm() {
                return None;
            }
            let input: Varnode = xmm_lane(instruction.op_register(1), 0, width)?;
            write_register(instruction.op_register(0), input, allocator, &mut ops)?;
        }
        OpKind::Memory => {
            if instruction.op_kind(1) != OpKind::Register || !instruction.op_register(1).is_xmm() {
                return None;
            }
            let pointer: Varnode = memory_pointer(instruction, allocator, &mut ops)?;
            let value: Varnode = xmm_lane(instruction.op_register(1), 0, width)?;
            ops.push(PcodeOp::Store {
                space: Space::Ram,
                pointer,
                value,
            });
        }
        _ => return None,
    }
    Some(ops)
}

fn scalar_source(
    instruction: &Instruction,
    operand: u32,
    width: u32,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    match instruction.op_kind(operand) {
        OpKind::Register if instruction.op_register(operand).is_xmm() => {
            xmm_lane(instruction.op_register(operand), 0, width)
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
        _ => None,
    }
}

fn integer_or_xmm_source(
    instruction: &Instruction,
    operand: u32,
    width: u32,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    match instruction.op_kind(operand) {
        OpKind::Register if instruction.op_register(operand).is_xmm() => {
            xmm_lane(instruction.op_register(operand), 0, width)
        }
        OpKind::Register if is_gpr(instruction.op_register(operand)) => {
            let input: Varnode = register(instruction.op_register(operand))?;
            (input.size_bytes == width).then_some(input)
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
        _ => None,
    }
}

fn vector_source(
    instruction: &Instruction,
    operand: u32,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<VectorSource> {
    match instruction.op_kind(operand) {
        OpKind::Register if instruction.op_register(operand).is_xmm() => {
            Some(VectorSource::Register(instruction.op_register(operand)))
        }
        OpKind::Memory => {
            let pointer: Varnode = memory_pointer(instruction, allocator, ops)?;
            let output: Varnode = allocator.allocate(16)?;
            ops.push(PcodeOp::Load {
                output,
                space: Space::Ram,
                pointer,
            });
            Some(VectorSource::Memory(output))
        }
        _ => None,
    }
}

fn source_lane(
    source: VectorSource,
    byte_offset: u32,
    width: u32,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    match source {
        VectorSource::Register(selected) => xmm_lane(selected, byte_offset, width),
        VectorSource::Memory(input) => {
            let output: Varnode = allocator.allocate(width)?;
            ops.push(PcodeOp::Subpiece {
                output,
                input,
                byte_offset: constant(u64::from(byte_offset), 4),
            });
            Some(output)
        }
    }
}

fn emit_full_binary(
    selected: Register,
    source: VectorSource,
    logic: VectorLogic,
    ops: &mut Vec<PcodeOp>,
) -> Option<()> {
    let output: Varnode = register(selected)?;
    let right: Varnode = match source {
        VectorSource::Register(source_register) => register(source_register)?,
        VectorSource::Memory(value) => value,
    };
    let operation: PcodeOp = binary_operation(logic, output, output, right);
    ops.push(operation);
    Some(())
}

fn emit_lane_binary(
    selected: Register,
    source: VectorSource,
    lane_width: u32,
    logic: VectorLogic,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<()> {
    let mut byte_offset: u32 = 0;
    while byte_offset < 16 {
        let output: Varnode = xmm_lane(selected, byte_offset, lane_width)?;
        let right: Varnode = source_lane(source, byte_offset, lane_width, allocator, ops)?;
        let operation: PcodeOp = binary_operation(logic, output, output, right);
        ops.push(operation);
        byte_offset = byte_offset.checked_add(lane_width)?;
    }
    Some(())
}

const fn binary_operation(
    logic: VectorLogic,
    output: Varnode,
    left: Varnode,
    right: Varnode,
) -> PcodeOp {
    match logic {
        VectorLogic::And => PcodeOp::IntAnd {
            output,
            left,
            right,
        },
        VectorLogic::Or => PcodeOp::IntOr {
            output,
            left,
            right,
        },
        VectorLogic::Xor => PcodeOp::IntXor {
            output,
            left,
            right,
        },
    }
}
