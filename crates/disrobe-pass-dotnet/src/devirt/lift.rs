use std::collections::{BTreeMap, BTreeSet, VecDeque, btree_map::Entry};

use super::Reject;
use super::budget::Budget;
use super::handlers::HandlerSummary;
use super::ir::{BasicBlock, BinOp, BlockId, DvIr, IrInstruction, Terminator, ValueId};
use super::microop::MicroOp;
use super::profile::{DecodedOperand, ProtectorProfile, SyntheticHandler, SyntheticVmModel};

const MAX_LIFT_STACK: usize = 1_024;

#[derive(Clone, Debug)]
struct DecodedInstruction {
    op: MicroOp,
    operand: DecodedOperand,
}

#[derive(Clone, Copy, Debug)]
struct BlockPlan {
    id: BlockId,
    start: usize,
    end: usize,
    fallthrough: Option<BlockId>,
}

#[derive(Clone, Debug)]
struct ValueAllocator {
    next: u32,
}

impl ValueAllocator {
    const fn new() -> Self {
        Self { next: 0 }
    }

    fn allocate(&mut self) -> Result<ValueId, Reject> {
        let current: u32 = self.next;
        self.next = match self.next.checked_add(1) {
            Some(value) => value,
            None => {
                return Err(Reject::new(
                    "IR value identifier space is exhausted",
                    Vec::new(),
                ));
            }
        };
        Ok(ValueId::new(current))
    }
}

pub(crate) fn lift(
    model: &SyntheticVmModel,
    profile: &dyn ProtectorProfile,
    budget: &mut Budget,
) -> Result<DvIr, Reject> {
    let decoded: Vec<DecodedInstruction> = decode_program(model, profile, budget)?;
    let (plans, instruction_blocks): (BTreeMap<BlockId, BlockPlan>, Vec<BlockId>) =
        plan_blocks(&decoded, budget)?;
    let mut entry_stacks: BTreeMap<BlockId, Vec<ValueId>> = BTreeMap::new();
    let entry: BlockId = match plans.values().next() {
        Some(plan) => plan.id,
        None => return Err(Reject::new("virtual program is empty", Vec::new())),
    };
    entry_stacks.insert(entry, Vec::new());
    let mut pending: VecDeque<BlockId> = VecDeque::new();
    pending.push_back(entry);
    let mut emitted: BTreeMap<BlockId, BasicBlock> = BTreeMap::new();
    let mut processed: BTreeSet<BlockId> = BTreeSet::new();
    let mut allocator: ValueAllocator = ValueAllocator::new();
    while !pending.is_empty() {
        let block_id: BlockId = pending
            .pop_front()
            .ok_or_else(|| Reject::new("pending block queue changed during lifting", Vec::new()))?;
        budget.spend(1).map_err(Reject::from_budget_error)?;
        if !processed.insert(block_id) {
            continue;
        }
        let plan: BlockPlan = match plans.get(&block_id) {
            Some(value) => *value,
            None => {
                return Err(Reject::new(
                    "control-flow plan references a missing block",
                    vec![block_id.get().to_string()],
                ));
            }
        };
        let mut stack: Vec<ValueId> = match entry_stacks.get(&block_id) {
            Some(value) => value.clone(),
            None => {
                return Err(Reject::new(
                    "reachable block has no incoming virtual stack state",
                    vec![block_id.get().to_string()],
                ));
            }
        };
        let mut instructions: Vec<IrInstruction> = Vec::new();
        let mut terminator: Option<Terminator> = None;
        for instruction_index in plan.start..plan.end {
            budget.spend(1).map_err(Reject::from_budget_error)?;
            let decoded_instruction: &DecodedInstruction = match decoded.get(instruction_index) {
                Some(value) => value,
                None => {
                    return Err(Reject::new(
                        "control-flow plan indexes outside the virtual program",
                        vec![instruction_index.to_string()],
                    ));
                }
            };
            let lowered: Option<Terminator> = lower_instruction(
                decoded_instruction,
                model,
                &instruction_blocks,
                plan.fallthrough,
                &mut stack,
                &mut instructions,
                &mut allocator,
            )?;
            if lowered.is_some() {
                if instruction_index.saturating_add(1) != plan.end {
                    return Err(Reject::new(
                        "virtual control instruction does not end its basic block",
                        vec![instruction_index.to_string()],
                    ));
                }
                terminator = lowered;
            }
        }
        let final_terminator: Terminator = match terminator {
            Some(value) => value,
            None => match plan.fallthrough {
                Some(target) => Terminator::Br(target),
                None => {
                    return Err(Reject::new(
                        "virtual program falls off the final instruction",
                        Vec::new(),
                    ));
                }
            },
        };
        propagate_stack(
            &final_terminator,
            &stack,
            &mut entry_stacks,
            &mut pending,
            &processed,
            budget,
        )?;
        emitted.insert(
            block_id,
            BasicBlock {
                id: block_id,
                instructions,
                terminator: final_terminator,
            },
        );
    }
    let blocks: Vec<BasicBlock> = emitted.into_values().collect();
    let ir: DvIr = DvIr::new(model.argument_count, model.local_count, blocks);
    ir.verify(budget)
        .map_err(|error| Reject::new("recovered IR failed verification", vec![error.reason]))?;
    Ok(ir)
}

fn decode_program(
    model: &SyntheticVmModel,
    profile: &dyn ProtectorProfile,
    budget: &mut Budget,
) -> Result<Vec<DecodedInstruction>, Reject> {
    if model.instructions.is_empty() {
        return Err(Reject::new("virtual program is empty", Vec::new()));
    }
    profile.validate_model(model, budget)?;
    let handler_table: &BTreeMap<u16, SyntheticHandler> = profile.discover_handler_table(model)?;
    let mut summaries: BTreeMap<u16, HandlerSummary> = BTreeMap::new();
    let mut decoded: Vec<DecodedInstruction> = Vec::with_capacity(model.instructions.len());
    for (offset, instruction) in model.instructions.iter().enumerate() {
        budget.spend(1).map_err(Reject::from_budget_error)?;
        let handler: &SyntheticHandler =
            handler_table.get(&instruction.handler_id).ok_or_else(|| {
                Reject::new(
                    "virtual instruction references an unknown handler",
                    vec![instruction.handler_id.to_string(), offset.to_string()],
                )
            })?;
        let summary: HandlerSummary = match summaries.entry(instruction.handler_id) {
            Entry::Occupied(entry) => entry.get().clone(),
            Entry::Vacant(entry) => {
                let computed: HandlerSummary = profile.summarize_handler(handler, budget)?;
                entry.insert(computed.clone());
                computed
            }
        };
        let op: MicroOp = match summary.canonical_op {
            Some(value) => value,
            None => {
                return Err(Reject::new(
                    "virtual instruction has an unknown handler effect",
                    vec![instruction.handler_id.to_string(), offset.to_string()],
                ));
            }
        };
        let operand: DecodedOperand =
            profile.decode_operand(handler, &instruction.operand, budget)?;
        validate_operand(&op, operand, offset)?;
        decoded.push(DecodedInstruction { op, operand });
    }
    Ok(decoded)
}

fn validate_operand(op: &MicroOp, operand: DecodedOperand, offset: usize) -> Result<(), Reject> {
    match (op, operand) {
        (MicroOp::LdcOperand, DecodedOperand::I64(_))
        | (MicroOp::Br | MicroOp::BrTrue | MicroOp::BrFalse, DecodedOperand::Target(_)) => Ok(()),
        (MicroOp::LdcOperand | MicroOp::Br | MicroOp::BrTrue | MicroOp::BrFalse, _) => {
            Err(Reject::new(
                "control or constant handler has an incompatible operand",
                vec![offset.to_string()],
            ))
        }
        (_, DecodedOperand::None) => Ok(()),
        _ => Err(Reject::new(
            "operand was supplied to an operand-free handler",
            vec![offset.to_string()],
        )),
    }
}

fn plan_blocks(
    decoded: &[DecodedInstruction],
    budget: &mut Budget,
) -> Result<(BTreeMap<BlockId, BlockPlan>, Vec<BlockId>), Reject> {
    let mut starts: BTreeSet<usize> = BTreeSet::new();
    starts.insert(0);
    for (offset, instruction) in decoded.iter().enumerate() {
        budget.spend(1).map_err(Reject::from_budget_error)?;
        if is_control(&instruction.op) {
            if is_branch(&instruction.op) {
                let target: usize =
                    branch_target_index(&instruction.operand, decoded.len(), offset)?;
                starts.insert(target);
            }
            let next: usize = offset.saturating_add(1);
            if next < decoded.len() {
                starts.insert(next);
            }
        }
    }
    let ordered_starts: Vec<usize> = starts.into_iter().collect();
    let mut plans: BTreeMap<BlockId, BlockPlan> = BTreeMap::new();
    let mut instruction_blocks: Vec<BlockId> = vec![BlockId::new(0); decoded.len()];
    for (ordinal, start) in ordered_starts.iter().enumerate() {
        budget.spend(1).map_err(Reject::from_budget_error)?;
        let id_value: u32 = match u32::try_from(ordinal) {
            Ok(value) => value,
            Err(_) => {
                return Err(Reject::new(
                    "basic block count exceeds identifier capacity",
                    Vec::new(),
                ));
            }
        };
        let id: BlockId = BlockId::new(id_value);
        let end: usize = ordered_starts
            .get(ordinal.saturating_add(1))
            .map_or(decoded.len(), |value: &usize| *value);
        for block in &mut instruction_blocks[*start..end] {
            budget.spend(1).map_err(Reject::from_budget_error)?;
            *block = id;
        }
        let fallthrough: Option<BlockId> = match ordered_starts.get(ordinal.saturating_add(1)) {
            Some(_) => match id_value.checked_add(1) {
                Some(value) => Some(BlockId::new(value)),
                None => {
                    return Err(Reject::new("basic block identifier overflowed", Vec::new()));
                }
            },
            None => None,
        };
        plans.insert(
            id,
            BlockPlan {
                id,
                start: *start,
                end,
                fallthrough,
            },
        );
    }
    Ok((plans, instruction_blocks))
}

const fn is_control(op: &MicroOp) -> bool {
    matches!(
        op,
        MicroOp::Br | MicroOp::BrTrue | MicroOp::BrFalse | MicroOp::Ret
    )
}

const fn is_branch(op: &MicroOp) -> bool {
    matches!(op, MicroOp::Br | MicroOp::BrTrue | MicroOp::BrFalse)
}

fn branch_target_index(
    operand: &DecodedOperand,
    program_length: usize,
    offset: usize,
) -> Result<usize, Reject> {
    let target_u32: u32 = match operand {
        DecodedOperand::Target(value) => *value,
        _ => {
            return Err(Reject::new(
                "control handler is missing a target operand",
                vec![offset.to_string()],
            ));
        }
    };
    let target: usize = match usize::try_from(target_u32) {
        Ok(value) => value,
        Err(_) => {
            return Err(Reject::new(
                "branch target cannot be represented as an instruction index",
                vec![offset.to_string()],
            ));
        }
    };
    if target >= program_length {
        return Err(Reject::new(
            "branch target is outside the virtual program",
            vec![target.to_string(), program_length.to_string()],
        ));
    }
    Ok(target)
}

fn lower_instruction(
    instruction: &DecodedInstruction,
    model: &SyntheticVmModel,
    instruction_blocks: &[BlockId],
    fallthrough: Option<BlockId>,
    stack: &mut Vec<ValueId>,
    instructions: &mut Vec<IrInstruction>,
    allocator: &mut ValueAllocator,
) -> Result<Option<Terminator>, Reject> {
    match &instruction.op {
        MicroOp::Ldarg(index) => {
            if *index >= model.argument_count {
                return Err(Reject::new(
                    "argument load indexes outside the method signature",
                    vec![index.to_string()],
                ));
            }
            let destination: ValueId = allocator.allocate()?;
            instructions.push(IrInstruction::LoadArgument {
                destination,
                index: *index,
            });
            push_value(stack, destination)?;
            Ok(None)
        }
        MicroOp::Starg(index) => {
            if *index >= model.argument_count {
                return Err(Reject::new(
                    "argument store indexes outside the method signature",
                    vec![index.to_string()],
                ));
            }
            let value: ValueId = pop_value(stack)?;
            instructions.push(IrInstruction::StoreArgument {
                index: *index,
                value,
            });
            Ok(None)
        }
        MicroOp::Ldloc(index) => {
            if *index >= model.local_count {
                return Err(Reject::new(
                    "local load indexes outside the method body",
                    vec![index.to_string()],
                ));
            }
            let destination: ValueId = allocator.allocate()?;
            instructions.push(IrInstruction::LoadLocal {
                destination,
                index: *index,
            });
            push_value(stack, destination)?;
            Ok(None)
        }
        MicroOp::Stloc(index) => {
            if *index >= model.local_count {
                return Err(Reject::new(
                    "local store indexes outside the method body",
                    vec![index.to_string()],
                ));
            }
            let value: ValueId = pop_value(stack)?;
            instructions.push(IrInstruction::StoreLocal {
                index: *index,
                value,
            });
            Ok(None)
        }
        MicroOp::Ldc(value) => {
            let destination: ValueId = allocator.allocate()?;
            instructions.push(IrInstruction::Const {
                destination,
                value: *value,
            });
            push_value(stack, destination)?;
            Ok(None)
        }
        MicroOp::LdcOperand => {
            let value: i64 = match instruction.operand {
                DecodedOperand::I64(value) => value,
                _ => {
                    return Err(Reject::new(
                        "constant handler operand changed after validation",
                        Vec::new(),
                    ));
                }
            };
            let destination: ValueId = allocator.allocate()?;
            instructions.push(IrInstruction::Const { destination, value });
            push_value(stack, destination)?;
            Ok(None)
        }
        MicroOp::Add
        | MicroOp::Sub
        | MicroOp::Mul
        | MicroOp::And
        | MicroOp::Or
        | MicroOp::Xor
        | MicroOp::Ceq
        | MicroOp::Clt
        | MicroOp::Cgt => {
            let right: ValueId = pop_value(stack)?;
            let left: ValueId = pop_value(stack)?;
            let destination: ValueId = allocator.allocate()?;
            let op: BinOp = binary_op(&instruction.op)?;
            instructions.push(IrInstruction::Binary {
                destination,
                op,
                left,
                right,
            });
            push_value(stack, destination)?;
            Ok(None)
        }
        MicroOp::Br => {
            let target: BlockId = branch_target_block(&instruction.operand, instruction_blocks)?;
            Ok(Some(Terminator::Br(target)))
        }
        MicroOp::BrTrue | MicroOp::BrFalse => {
            let condition: ValueId = pop_value(stack)?;
            let target: BlockId = branch_target_block(&instruction.operand, instruction_blocks)?;
            let next: BlockId = match fallthrough {
                Some(value) => value,
                None => {
                    return Err(Reject::new(
                        "conditional branch has no fallthrough block",
                        Vec::new(),
                    ));
                }
            };
            let terminator: Terminator = match instruction.op {
                MicroOp::BrTrue => Terminator::CondBr {
                    condition,
                    when_true: target,
                    when_false: next,
                },
                MicroOp::BrFalse => Terminator::CondBr {
                    condition,
                    when_true: next,
                    when_false: target,
                },
                _ => {
                    return Err(Reject::new(
                        "conditional branch classification changed after dispatch",
                        Vec::new(),
                    ));
                }
            };
            Ok(Some(terminator))
        }
        MicroOp::Ret => {
            let value: ValueId = pop_value(stack)?;
            if !stack.is_empty() {
                return Err(Reject::new(
                    "return leaves values on the virtual stack",
                    vec![stack.len().to_string()],
                ));
            }
            Ok(Some(Terminator::Ret(Some(value))))
        }
    }
}

fn binary_op(op: &MicroOp) -> Result<BinOp, Reject> {
    match op {
        MicroOp::Add => Ok(BinOp::Add),
        MicroOp::Sub => Ok(BinOp::Sub),
        MicroOp::Mul => Ok(BinOp::Mul),
        MicroOp::And => Ok(BinOp::And),
        MicroOp::Or => Ok(BinOp::Or),
        MicroOp::Xor => Ok(BinOp::Xor),
        MicroOp::Ceq => Ok(BinOp::Ceq),
        MicroOp::Clt => Ok(BinOp::Clt),
        MicroOp::Cgt => Ok(BinOp::Cgt),
        _ => Err(Reject::new(
            "non-binary operation reached binary lowering",
            Vec::new(),
        )),
    }
}

fn branch_target_block(
    operand: &DecodedOperand,
    instruction_blocks: &[BlockId],
) -> Result<BlockId, Reject> {
    let target_u32: u32 = match operand {
        DecodedOperand::Target(value) => *value,
        _ => {
            return Err(Reject::new(
                "branch handler operand changed after validation",
                Vec::new(),
            ));
        }
    };
    let target: usize = match usize::try_from(target_u32) {
        Ok(value) => value,
        Err(_) => {
            return Err(Reject::new(
                "branch target cannot be represented as an instruction index",
                Vec::new(),
            ));
        }
    };
    instruction_blocks.get(target).copied().ok_or_else(|| {
        Reject::new(
            "branch target is outside the virtual program",
            vec![target.to_string()],
        )
    })
}

fn propagate_stack(
    terminator: &Terminator,
    stack: &[ValueId],
    entry_stacks: &mut BTreeMap<BlockId, Vec<ValueId>>,
    pending: &mut VecDeque<BlockId>,
    processed: &BTreeSet<BlockId>,
    budget: &mut Budget,
) -> Result<(), Reject> {
    let targets: Vec<BlockId> = match terminator {
        Terminator::Br(target) => vec![*target],
        Terminator::CondBr {
            when_true,
            when_false,
            ..
        } => vec![*when_true, *when_false],
        Terminator::Ret(_) => Vec::new(),
    };
    for target in targets {
        budget.spend(1).map_err(Reject::from_budget_error)?;
        match entry_stacks.get(&target) {
            Some(existing) if existing != stack => {
                return Err(Reject::new(
                    "virtual control-flow merge needs an unsupported stack phi",
                    vec![target.get().to_string()],
                ));
            }
            Some(_) => {}
            None => {
                entry_stacks.insert(target, stack.to_vec());
                if !processed.contains(&target) {
                    pending.push_back(target);
                }
            }
        }
    }
    Ok(())
}

fn push_value(stack: &mut Vec<ValueId>, value: ValueId) -> Result<(), Reject> {
    if stack.len() >= MAX_LIFT_STACK {
        return Err(Reject::new(
            "virtual stack exceeds lift cap",
            vec![MAX_LIFT_STACK.to_string()],
        ));
    }
    stack.push(value);
    Ok(())
}

fn pop_value(stack: &mut Vec<ValueId>) -> Result<ValueId, Reject> {
    stack.pop().map_or_else(
        || Err(Reject::new("virtual stack underflow", Vec::new())),
        |value: ValueId| Ok(value),
    )
}
