use std::collections::{BTreeMap, BTreeSet};

use crate::cil_emulator::{StubInput, StubOutput};
use crate::devirt::{
    BinOp, Budget, OperandEncoding, PrimitiveEffect, SyntheticHandler, SyntheticVmModel, VInstr,
};

use super::SkipCause;

const MODEL_STEP_LIMIT: u64 = 4_000_000;
const MAX_MODEL_STACK: usize = 1_024;

#[derive(Clone, Debug)]
pub(super) enum ModelRun {
    Returned(ModelReturn),
    StepLimit,
    Skipped(SkipCause),
}

#[derive(Clone, Debug)]
pub(super) struct ModelReturn {
    pub(super) value: StubOutput,
    pub(super) branch_outcomes: BTreeMap<usize, BTreeSet<bool>>,
}

pub(super) fn contains_opaque_effect(model: &SyntheticVmModel) -> bool {
    model.handlers.values().any(|handler: &SyntheticHandler| {
        handler
            .effects
            .iter()
            .any(|effect: &PrimitiveEffect| matches!(effect, PrimitiveEffect::Opaque))
    })
}

pub(super) fn run(
    model: &SyntheticVmModel,
    input: &StubInput,
    budget: &mut Budget,
) -> Result<ModelRun, crate::devirt::Reject> {
    let mut args: Vec<i32> = Vec::with_capacity(input.int_args.len());
    for value in &input.int_args {
        let value: i32 = match i32::try_from(*value) {
            Ok(value) => value,
            Err(_) => return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable)),
        };
        args.push(value);
    }
    let mut locals: Vec<i32> = vec![0; usize::from(model.local_count)];
    let mut operand_stack: Vec<i32> = Vec::new();
    let mut pc: usize = 0;
    let mut steps: u64 = 0;
    let mut branch_outcomes: BTreeMap<usize, BTreeSet<bool>> = BTreeMap::new();
    loop {
        steps = match steps.checked_add(1) {
            Some(value) => value,
            None => return Ok(ModelRun::StepLimit),
        };
        if steps > MODEL_STEP_LIMIT {
            return Ok(ModelRun::StepLimit);
        }
        budget
            .spend(1)
            .map_err(crate::devirt::Reject::from_budget_error)?;
        let instruction: &VInstr = match model.instructions.get(pc) {
            Some(value) => value,
            None => return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable)),
        };
        let handler: &SyntheticHandler = match model.handlers.get(&instruction.handler_id) {
            Some(value) => value,
            None => return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable)),
        };
        if handler.effects.is_empty() {
            return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable));
        }
        if validate_operand_shape(handler, instruction).is_err() {
            return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable));
        }
        let mut next_pc: usize = match pc.checked_add(1) {
            Some(value) => value,
            None => return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable)),
        };
        for (effect_index, effect) in handler.effects.iter().enumerate() {
            budget
                .spend(1)
                .map_err(crate::devirt::Reject::from_budget_error)?;
            if is_control(effect) && effect_index.saturating_add(1) != handler.effects.len() {
                return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable));
            }
            match effect {
                PrimitiveEffect::PushArgument(index) => {
                    let value: i32 = match args.get(usize::from(*index)) {
                        Some(value) => *value,
                        None => {
                            return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable));
                        }
                    };
                    if push(&mut operand_stack, value).is_err() {
                        return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable));
                    }
                }
                PrimitiveEffect::StoreArgument(index) => {
                    let value: i32 = match operand_stack.pop() {
                        Some(value) => value,
                        None => {
                            return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable));
                        }
                    };
                    let Some(slot): Option<&mut i32> = args.get_mut(usize::from(*index)) else {
                        return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable));
                    };
                    *slot = value;
                }
                PrimitiveEffect::PushLocal(index) => {
                    let value: i32 = match locals.get(usize::from(*index)) {
                        Some(value) => *value,
                        None => {
                            return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable));
                        }
                    };
                    if push(&mut operand_stack, value).is_err() {
                        return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable));
                    }
                }
                PrimitiveEffect::StoreLocal(index) => {
                    let value: i32 = match operand_stack.pop() {
                        Some(value) => value,
                        None => {
                            return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable));
                        }
                    };
                    let Some(slot): Option<&mut i32> = locals.get_mut(usize::from(*index)) else {
                        return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable));
                    };
                    *slot = value;
                }
                PrimitiveEffect::PushConst(value) => {
                    let value: i32 = match i32::try_from(*value) {
                        Ok(value) => value,
                        Err(_) => {
                            return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable));
                        }
                    };
                    if push(&mut operand_stack, value).is_err() {
                        return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable));
                    }
                }
                PrimitiveEffect::PushOperandI64 => {
                    let value: i32 = match decode_i64_operand(handler, instruction) {
                        Ok(value) => value,
                        Err(()) => {
                            return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable));
                        }
                    };
                    if push(&mut operand_stack, value).is_err() {
                        return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable));
                    }
                }
                PrimitiveEffect::Binary(operation) => {
                    let right: i32 = match operand_stack.pop() {
                        Some(value) => value,
                        None => {
                            return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable));
                        }
                    };
                    let left: i32 = match operand_stack.pop() {
                        Some(value) => value,
                        None => {
                            return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable));
                        }
                    };
                    let value: i32 = evaluate_binary(*operation, left, right);
                    if push(&mut operand_stack, value).is_err() {
                        return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable));
                    }
                }
                PrimitiveEffect::AdvanceIp(_) => {}
                PrimitiveEffect::Branch => {
                    next_pc =
                        match decode_target_operand(handler, instruction, model.instructions.len())
                        {
                            Ok(value) => value,
                            Err(()) => {
                                return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable));
                            }
                        };
                }
                PrimitiveEffect::BranchIfTrue => {
                    let condition: i32 = match operand_stack.pop() {
                        Some(value) => value,
                        None => {
                            return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable));
                        }
                    };
                    let taken: bool = condition != 0;
                    branch_outcomes.entry(pc).or_default().insert(taken);
                    if taken {
                        next_pc = match decode_target_operand(
                            handler,
                            instruction,
                            model.instructions.len(),
                        ) {
                            Ok(value) => value,
                            Err(()) => {
                                return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable));
                            }
                        };
                    }
                }
                PrimitiveEffect::BranchIfFalse => {
                    let condition: i32 = match operand_stack.pop() {
                        Some(value) => value,
                        None => {
                            return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable));
                        }
                    };
                    let taken: bool = condition == 0;
                    branch_outcomes.entry(pc).or_default().insert(taken);
                    if taken {
                        next_pc = match decode_target_operand(
                            handler,
                            instruction,
                            model.instructions.len(),
                        ) {
                            Ok(value) => value,
                            Err(()) => {
                                return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable));
                            }
                        };
                    }
                }
                PrimitiveEffect::Return => {
                    let value: i32 = match operand_stack.pop() {
                        Some(value) => value,
                        None => {
                            return Ok(ModelRun::Skipped(SkipCause::ModelReferenceUnavailable));
                        }
                    };
                    return Ok(ModelRun::Returned(ModelReturn {
                        value: StubOutput::Int(i64::from(value)),
                        branch_outcomes,
                    }));
                }
                PrimitiveEffect::Opaque => return Ok(ModelRun::Skipped(SkipCause::OpaqueEffect)),
            }
        }
        pc = next_pc;
    }
}

const fn validate_operand_shape(
    handler: &SyntheticHandler,
    instruction: &VInstr,
) -> Result<(), ()> {
    match handler.operand_encoding {
        OperandEncoding::None if instruction.operand.is_empty() => Ok(()),
        OperandEncoding::I64 if instruction.operand.len() == 8 => Ok(()),
        OperandEncoding::Target if instruction.operand.len() == 4 => Ok(()),
        OperandEncoding::None | OperandEncoding::I64 | OperandEncoding::Target => Err(()),
    }
}

fn decode_i64_operand(handler: &SyntheticHandler, instruction: &VInstr) -> Result<i32, ()> {
    if handler.operand_encoding != OperandEncoding::I64 {
        return Err(());
    }
    let bytes: [u8; 8] = instruction.operand.as_slice().try_into().map_err(|_| ())?;
    i32::try_from(i64::from_le_bytes(bytes)).map_err(|_| ())
}

fn decode_target_operand(
    handler: &SyntheticHandler,
    instruction: &VInstr,
    program_length: usize,
) -> Result<usize, ()> {
    if handler.operand_encoding != OperandEncoding::Target {
        return Err(());
    }
    let bytes: [u8; 4] = instruction.operand.as_slice().try_into().map_err(|_| ())?;
    let target: usize = usize::try_from(u32::from_le_bytes(bytes)).map_err(|_| ())?;
    if target >= program_length {
        return Err(());
    }
    Ok(target)
}

fn push(stack: &mut Vec<i32>, value: i32) -> Result<(), ()> {
    if stack.len() >= MAX_MODEL_STACK {
        return Err(());
    }
    stack.push(value);
    Ok(())
}

const fn is_control(effect: &PrimitiveEffect) -> bool {
    matches!(
        effect,
        PrimitiveEffect::Branch
            | PrimitiveEffect::BranchIfTrue
            | PrimitiveEffect::BranchIfFalse
            | PrimitiveEffect::Return
    )
}

const fn evaluate_binary(operation: BinOp, left: i32, right: i32) -> i32 {
    match operation {
        BinOp::Add => left.wrapping_add(right),
        BinOp::Sub => left.wrapping_sub(right),
        BinOp::Mul => left.wrapping_mul(right),
        BinOp::And => left & right,
        BinOp::Or => left | right,
        BinOp::Xor => left ^ right,
        BinOp::Ceq => {
            if left == right {
                1
            } else {
                0
            }
        }
        BinOp::Clt => {
            if left < right {
                1
            } else {
                0
            }
        }
        BinOp::Cgt => {
            if left > right {
                1
            } else {
                0
            }
        }
    }
}
