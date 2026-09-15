use disrobe_sleigh::pcode::{PcodeOp, Varnode};
use iced_x86::{ConditionCode, Instruction, OpKind};

use crate::registers::{CF, OF, PF, SF, UniqueAllocator, ZF, constant, is_gpr, register};

use super::{
    Destination, destination, destination_width, read_operand, write_destination, write_register,
};

pub(super) fn lift_set(
    instruction: &Instruction,
    allocator: &mut UniqueAllocator,
) -> Option<Vec<PcodeOp>> {
    if instruction.op_count() != 1 {
        return None;
    }
    let mut ops: Vec<PcodeOp> = Vec::new();
    let target: Destination = destination(instruction, 0, allocator, &mut ops)?;
    let predicate: Varnode = condition(instruction.condition_code(), allocator, &mut ops)?;
    write_destination(target, predicate, allocator, &mut ops)?;
    Some(ops)
}

pub(super) fn lift_cmov(
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
    let selected: iced_x86::Register = instruction.op_register(0);
    let previous: Varnode = register(selected)?;
    let mut ops: Vec<PcodeOp> = Vec::new();
    let source: Varnode = read_operand(instruction, 1, width, allocator, &mut ops)?;
    let predicate: Varnode = condition(instruction.condition_code(), allocator, &mut ops)?;
    let extended: Varnode = allocator.allocate(width)?;
    let mask: Varnode = allocator.allocate(width)?;
    let inverse: Varnode = allocator.allocate(width)?;
    let chosen: Varnode = allocator.allocate(width)?;
    let retained: Varnode = allocator.allocate(width)?;
    let result: Varnode = allocator.allocate(width)?;
    ops.push(PcodeOp::IntZext {
        output: extended,
        input: predicate,
    });
    ops.push(PcodeOp::IntSub {
        output: mask,
        left: constant(0, width),
        right: extended,
    });
    ops.push(PcodeOp::IntNegate {
        output: inverse,
        input: mask,
    });
    ops.push(PcodeOp::IntAnd {
        output: chosen,
        left: source,
        right: mask,
    });
    ops.push(PcodeOp::IntAnd {
        output: retained,
        left: previous,
        right: inverse,
    });
    ops.push(PcodeOp::IntOr {
        output: result,
        left: chosen,
        right: retained,
    });
    write_register(selected, result, allocator, &mut ops)?;
    Some(ops)
}

pub(super) fn condition(
    selected: ConditionCode,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    match selected {
        ConditionCode::o => Some(OF),
        ConditionCode::no => bool_negate(OF, allocator, ops),
        ConditionCode::b => Some(CF),
        ConditionCode::ae => bool_negate(CF, allocator, ops),
        ConditionCode::e => Some(ZF),
        ConditionCode::ne => bool_negate(ZF, allocator, ops),
        ConditionCode::be => bool_or(CF, ZF, allocator, ops),
        ConditionCode::a => {
            let below_or_equal: Varnode = bool_or(CF, ZF, allocator, ops)?;
            bool_negate(below_or_equal, allocator, ops)
        }
        ConditionCode::s => Some(SF),
        ConditionCode::ns => bool_negate(SF, allocator, ops),
        ConditionCode::p => Some(PF),
        ConditionCode::np => bool_negate(PF, allocator, ops),
        ConditionCode::l => bool_xor(SF, OF, allocator, ops),
        ConditionCode::ge => {
            let less: Varnode = bool_xor(SF, OF, allocator, ops)?;
            bool_negate(less, allocator, ops)
        }
        ConditionCode::le => {
            let less: Varnode = bool_xor(SF, OF, allocator, ops)?;
            bool_or(ZF, less, allocator, ops)
        }
        ConditionCode::g => {
            let less: Varnode = bool_xor(SF, OF, allocator, ops)?;
            let less_or_equal: Varnode = bool_or(ZF, less, allocator, ops)?;
            bool_negate(less_or_equal, allocator, ops)
        }
        ConditionCode::None => None,
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
