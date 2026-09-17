use std::collections::BTreeMap;

use crate::cil::{FlowControl, Instruction, MethodBody, OperandValue};
use crate::devirt::{BasicBlock, BinOp, BlockId, DvIr, IrInstruction, Terminator, ValueId};

enum PlannedInstruction {
    Instruction(Instruction),
    Branch(BlockId),
    BranchIfTrue(BlockId),
}

pub fn dvir_to_method_body(ir: &DvIr) -> MethodBody {
    let value_locals: BTreeMap<ValueId, u32> = value_locals(ir);
    let blocks: Vec<&BasicBlock> = ordered_blocks(ir);
    let mut labels: BTreeMap<BlockId, usize> = BTreeMap::new();
    let mut planned: Vec<PlannedInstruction> = Vec::new();
    for block in blocks {
        labels.insert(block.id, planned.len());
        for instruction in &block.instructions {
            lower_instruction(instruction, &value_locals, &mut planned);
        }
        lower_terminator(&block.terminator, &value_locals, &mut planned);
    }
    if matches!(
        planned.last(),
        Some(PlannedInstruction::Branch(_) | PlannedInstruction::BranchIfTrue(_))
    ) {
        planned.push(PlannedInstruction::Instruction(instruction(
            "nop",
            OperandValue::None,
            FlowControl::Next,
        )));
    }
    let offsets: Vec<u32> = (0..planned.len()).map(index_to_offset).collect();
    let instructions: Vec<Instruction> = planned
        .into_iter()
        .enumerate()
        .map(|(index, planned): (usize, PlannedInstruction)| {
            lower_planned_instruction(planned, index, &offsets, &labels)
        })
        .collect();
    MethodBody {
        max_stack: 2,
        code_size: index_to_offset(instructions.len()),
        local_var_sig_tok: 0,
        init_locals: true,
        instructions,
        exception_clauses: Vec::new(),
    }
}

fn ordered_blocks(ir: &DvIr) -> Vec<&BasicBlock> {
    let mut blocks: Vec<&BasicBlock> = Vec::with_capacity(ir.blocks.len());
    for block in &ir.blocks {
        if block.id == ir.entry {
            blocks.push(block);
        }
    }
    for block in &ir.blocks {
        if block.id != ir.entry {
            blocks.push(block);
        }
    }
    blocks
}

fn value_locals(ir: &DvIr) -> BTreeMap<ValueId, u32> {
    let mut locals: BTreeMap<ValueId, u32> = BTreeMap::new();
    let mut next: u32 = u32::from(ir.local_count);
    for value in ir.value_types.keys() {
        locals.insert(*value, next);
        next = next.saturating_add(1);
    }
    locals
}

fn lower_instruction(
    instruction_to_lower: &IrInstruction,
    value_locals: &BTreeMap<ValueId, u32>,
    planned: &mut Vec<PlannedInstruction>,
) {
    match instruction_to_lower {
        IrInstruction::Const { destination, value } => {
            let constant: Instruction = constant_instruction(*value);
            planned.push(PlannedInstruction::Instruction(constant));
            planned.push(PlannedInstruction::Instruction(store_local_instruction(
                value_local(value_locals, *destination),
            )));
        }
        IrInstruction::LoadArgument { destination, index } => {
            planned.push(PlannedInstruction::Instruction(load_argument_instruction(
                u32::from(*index),
            )));
            planned.push(PlannedInstruction::Instruction(store_local_instruction(
                value_local(value_locals, *destination),
            )));
        }
        IrInstruction::StoreArgument { index, value } => {
            planned.push(PlannedInstruction::Instruction(load_local_instruction(
                value_local(value_locals, *value),
            )));
            planned.push(PlannedInstruction::Instruction(store_argument_instruction(
                u32::from(*index),
            )));
        }
        IrInstruction::LoadLocal { destination, index } => {
            planned.push(PlannedInstruction::Instruction(load_local_instruction(
                u32::from(*index),
            )));
            planned.push(PlannedInstruction::Instruction(store_local_instruction(
                value_local(value_locals, *destination),
            )));
        }
        IrInstruction::StoreLocal { index, value } => {
            planned.push(PlannedInstruction::Instruction(load_local_instruction(
                value_local(value_locals, *value),
            )));
            planned.push(PlannedInstruction::Instruction(store_local_instruction(
                u32::from(*index),
            )));
        }
        IrInstruction::Binary {
            destination,
            op,
            left,
            right,
        } => {
            planned.push(PlannedInstruction::Instruction(load_local_instruction(
                value_local(value_locals, *left),
            )));
            planned.push(PlannedInstruction::Instruction(load_local_instruction(
                value_local(value_locals, *right),
            )));
            planned.push(PlannedInstruction::Instruction(instruction(
                binary_name(*op),
                OperandValue::None,
                FlowControl::Next,
            )));
            planned.push(PlannedInstruction::Instruction(store_local_instruction(
                value_local(value_locals, *destination),
            )));
        }
    }
}

fn lower_terminator(
    terminator: &Terminator,
    value_locals: &BTreeMap<ValueId, u32>,
    planned: &mut Vec<PlannedInstruction>,
) {
    match terminator {
        Terminator::Br(target) => planned.push(PlannedInstruction::Branch(*target)),
        Terminator::CondBr {
            condition,
            when_true,
            when_false,
        } => {
            planned.push(PlannedInstruction::Instruction(load_local_instruction(
                value_local(value_locals, *condition),
            )));
            planned.push(PlannedInstruction::BranchIfTrue(*when_true));
            planned.push(PlannedInstruction::Branch(*when_false));
        }
        Terminator::Ret(Some(value)) => {
            planned.push(PlannedInstruction::Instruction(load_local_instruction(
                value_local(value_locals, *value),
            )));
            planned.push(PlannedInstruction::Instruction(instruction(
                "ret",
                OperandValue::None,
                FlowControl::Return,
            )));
        }
        Terminator::Ret(None) => planned.push(PlannedInstruction::Instruction(instruction(
            "ret",
            OperandValue::None,
            FlowControl::Return,
        ))),
    }
}

fn lower_planned_instruction(
    planned: PlannedInstruction,
    index: usize,
    offsets: &[u32],
    labels: &BTreeMap<BlockId, usize>,
) -> Instruction {
    match planned {
        PlannedInstruction::Instruction(mut instruction_to_offset) => {
            instruction_to_offset.offset = offsets[index];
            instruction_to_offset
        }
        PlannedInstruction::Branch(target) => instruction_with_offset(
            offsets[index],
            "br",
            OperandValue::BrTarget(branch_relative(index, target, offsets, labels)),
            FlowControl::Branch,
        ),
        PlannedInstruction::BranchIfTrue(target) => instruction_with_offset(
            offsets[index],
            "brtrue",
            OperandValue::BrTarget(branch_relative(index, target, offsets, labels)),
            FlowControl::CondBranch,
        ),
    }
}

fn branch_relative(
    index: usize,
    target: BlockId,
    offsets: &[u32],
    labels: &BTreeMap<BlockId, usize>,
) -> i32 {
    let next_offset: u32 = offsets
        .get(index.saturating_add(1))
        .copied()
        .map_or(offsets[index], |value: u32| value);
    let target_index: usize = labels
        .get(&target)
        .copied()
        .map_or(index, |value: usize| value);
    let target_offset: u32 = offsets
        .get(target_index)
        .copied()
        .map_or(offsets[index], |value: u32| value);
    let relative: i64 = i64::from(target_offset) - i64::from(next_offset);
    match i32::try_from(relative) {
        Ok(value) => value,
        Err(_) if relative.is_negative() => i32::MIN,
        Err(_) => i32::MAX,
    }
}

fn value_local(value_locals: &BTreeMap<ValueId, u32>, value: ValueId) -> u32 {
    value_locals
        .get(&value)
        .copied()
        .map_or(u32::MAX, |index: u32| index)
}

fn constant_instruction(value: i64) -> Instruction {
    i32::try_from(value).map_or_else(
        |_| instruction("ldc.i8", OperandValue::I64(value), FlowControl::Next),
        |constant: i32| instruction("ldc.i4", OperandValue::I32(constant), FlowControl::Next),
    )
}

fn load_local_instruction(index: u32) -> Instruction {
    instruction("ldloc", slot_operand(index), FlowControl::Next)
}

fn store_local_instruction(index: u32) -> Instruction {
    instruction("stloc", slot_operand(index), FlowControl::Next)
}

fn load_argument_instruction(index: u32) -> Instruction {
    instruction("ldarg", slot_operand(index), FlowControl::Next)
}

fn store_argument_instruction(index: u32) -> Instruction {
    instruction("starg", slot_operand(index), FlowControl::Next)
}

fn slot_operand(index: u32) -> OperandValue {
    u16::try_from(index).map_or_else(
        |_| i32::try_from(index).map_or(OperandValue::I32(-1), OperandValue::I32),
        OperandValue::U16,
    )
}

const fn binary_name(op: BinOp) -> &'static str {
    match op {
        BinOp::Add => "add",
        BinOp::Sub => "sub",
        BinOp::Mul => "mul",
        BinOp::And => "and",
        BinOp::Or => "or",
        BinOp::Xor => "xor",
        BinOp::Ceq => "ceq",
        BinOp::Clt => "clt",
        BinOp::Cgt => "cgt",
    }
}

fn instruction(name: &str, operand: OperandValue, flow: FlowControl) -> Instruction {
    instruction_with_offset(0, name, operand, flow)
}

fn instruction_with_offset(
    offset: u32,
    name: &str,
    operand: OperandValue,
    flow: FlowControl,
) -> Instruction {
    Instruction {
        offset,
        opcode: 0,
        name: name.to_owned(),
        operand,
        flow,
    }
}

fn index_to_offset(index: usize) -> u32 {
    u32::try_from(index).map_or(u32::MAX, std::convert::identity)
}
