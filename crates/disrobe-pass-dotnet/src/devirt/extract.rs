use std::collections::BTreeMap;

use crate::peel::eazvm::lift::{LiftedBody, LiftedInstr, LiftedOperand};
use crate::peel::eazvm::opcodes::CilOp;
use crate::peel::eazvm::{EazVmError, EazVmMethod, EazVmRecovery, devirtualize};

use super::ir::BinOp;
use super::profile::{OperandEncoding, SyntheticHandler, SyntheticVmModel, VInstr};
use super::state::PrimitiveEffect;

const MAX_EAZVM_MODELS: usize = 1_024;
const MAX_EAZVM_MODEL_INSTRUCTIONS: usize = 4_096;
const MAX_EAZVM_MODEL_INSTRUCTIONS_TOTAL: usize = 65_536;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtractedVmModel {
    pub method_name: String,
    pub model: SyntheticVmModel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtractError {
    Recovery(EazVmError),
    NoMethods,
    ProgramTooLarge,
    HandlerSpaceExhausted,
    BranchTargetUnrepresentable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HandlerSpec {
    effects: Vec<PrimitiveEffect>,
    operand_encoding: OperandEncoding,
}

#[derive(Clone, Debug, Default)]
struct HandlerTableBuilder {
    specs: Vec<HandlerSpec>,
}

impl HandlerTableBuilder {
    fn intern(&mut self, spec: HandlerSpec) -> Result<u16, ExtractError> {
        if let Some(index) = self
            .specs
            .iter()
            .position(|existing: &HandlerSpec| *existing == spec)
        {
            return u16::try_from(index).map_err(|_| ExtractError::HandlerSpaceExhausted);
        }
        let index: u16 =
            u16::try_from(self.specs.len()).map_err(|_| ExtractError::HandlerSpaceExhausted)?;
        self.specs.push(spec);
        Ok(index)
    }

    fn finish(self) -> BTreeMap<u16, SyntheticHandler> {
        let mut handlers: BTreeMap<u16, SyntheticHandler> = BTreeMap::new();
        for (index, spec) in self.specs.into_iter().enumerate() {
            let Ok(id): Result<u16, _> = u16::try_from(index) else {
                continue;
            };
            handlers.insert(
                id,
                SyntheticHandler::new(spec.effects, spec.operand_encoding),
            );
        }
        handlers
    }
}

pub fn models_from_eazvm_image(image: &[u8]) -> Result<Vec<ExtractedVmModel>, ExtractError> {
    let recovery: EazVmRecovery = devirtualize(image).map_err(ExtractError::Recovery)?;
    models_from_eazvm_recovery(&recovery)
}

pub(crate) fn models_from_eazvm_recovery(
    recovery: &EazVmRecovery,
) -> Result<Vec<ExtractedVmModel>, ExtractError> {
    if recovery.methods.is_empty() {
        return Err(ExtractError::NoMethods);
    }
    if recovery.methods.len() > MAX_EAZVM_MODELS {
        return Err(ExtractError::ProgramTooLarge);
    }
    let mut instruction_total: usize = 0;
    for method in &recovery.methods {
        if method.lifted.instrs.len() > MAX_EAZVM_MODEL_INSTRUCTIONS {
            return Err(ExtractError::ProgramTooLarge);
        }
        instruction_total = instruction_total
            .checked_add(method.lifted.instrs.len())
            .ok_or(ExtractError::ProgramTooLarge)?;
        if instruction_total > MAX_EAZVM_MODEL_INSTRUCTIONS_TOTAL {
            return Err(ExtractError::ProgramTooLarge);
        }
    }
    let mut models: Vec<ExtractedVmModel> = Vec::with_capacity(recovery.methods.len());
    for method in &recovery.methods {
        models.push(model_from_method(method)?);
    }
    Ok(models)
}

fn model_from_method(method: &EazVmMethod) -> Result<ExtractedVmModel, ExtractError> {
    let body: &LiftedBody = &method.lifted;
    let program_length: usize = body.instrs.len();
    if program_length > MAX_EAZVM_MODEL_INSTRUCTIONS {
        return Err(ExtractError::ProgramTooLarge);
    }
    let argument_count: u16 =
        u16::try_from(method.info.param_count).map_err(|_| ExtractError::ProgramTooLarge)?;
    let local_count: u16 =
        u16::try_from(method.info.local_count).map_err(|_| ExtractError::ProgramTooLarge)?;
    let mut builder: HandlerTableBuilder = HandlerTableBuilder::default();
    let mut instructions: Vec<VInstr> = Vec::with_capacity(program_length);
    for instruction in &body.instrs {
        let spec: HandlerSpec = handler_spec(instruction);
        let operand: Vec<u8> = operand_bytes(instruction, spec.operand_encoding, program_length)?;
        let handler_id: u16 = builder.intern(spec)?;
        instructions.push(VInstr::new(handler_id, operand));
    }
    Ok(ExtractedVmModel {
        method_name: method.name.clone(),
        model: SyntheticVmModel::new(
            super::profile::VmFlavor::Stack,
            argument_count,
            local_count,
            builder.finish(),
            instructions,
        ),
    })
}

fn operand_bytes(
    instruction: &LiftedInstr,
    encoding: OperandEncoding,
    program_length: usize,
) -> Result<Vec<u8>, ExtractError> {
    match encoding {
        OperandEncoding::None => Ok(Vec::new()),
        OperandEncoding::I64 => match instruction.operand {
            LiftedOperand::I32(value) => Ok(i64::from(value).to_le_bytes().to_vec()),
            LiftedOperand::None
            | LiftedOperand::Var(_)
            | LiftedOperand::BranchTo(_)
            | LiftedOperand::Member(_)
            | LiftedOperand::StringLit(_) => Ok(Vec::new()),
        },
        OperandEncoding::Target => match instruction.operand {
            LiftedOperand::BranchTo(target) if target < program_length => {
                let target: u32 =
                    u32::try_from(target).map_err(|_| ExtractError::BranchTargetUnrepresentable)?;
                Ok(target.to_le_bytes().to_vec())
            }
            LiftedOperand::BranchTo(_)
            | LiftedOperand::None
            | LiftedOperand::I32(_)
            | LiftedOperand::Var(_)
            | LiftedOperand::Member(_)
            | LiftedOperand::StringLit(_) => Err(ExtractError::BranchTargetUnrepresentable),
        },
    }
}

fn handler_spec(instruction: &LiftedInstr) -> HandlerSpec {
    let slot: Option<u16> = match instruction.operand {
        LiftedOperand::Var(index) => Some(index),
        LiftedOperand::None
        | LiftedOperand::I32(_)
        | LiftedOperand::BranchTo(_)
        | LiftedOperand::Member(_)
        | LiftedOperand::StringLit(_) => None,
    };
    match instruction.op {
        CilOp::LdargN(index) => plain(vec![PrimitiveEffect::PushArgument(u16::from(index))]),
        CilOp::LdlocN(index) => plain(vec![PrimitiveEffect::PushLocal(u16::from(index))]),
        CilOp::StlocN(index) => plain(vec![PrimitiveEffect::StoreLocal(u16::from(index))]),
        CilOp::LdargS => slot.map_or_else(opaque, |index: u16| {
            plain(vec![PrimitiveEffect::PushArgument(index)])
        }),
        CilOp::StargS => slot.map_or_else(opaque, |index: u16| {
            plain(vec![PrimitiveEffect::StoreArgument(index)])
        }),
        CilOp::LdlocS => slot.map_or_else(opaque, |index: u16| {
            plain(vec![PrimitiveEffect::PushLocal(index)])
        }),
        CilOp::StlocS => slot.map_or_else(opaque, |index: u16| {
            plain(vec![PrimitiveEffect::StoreLocal(index)])
        }),
        CilOp::LdcI4M1 => plain(vec![PrimitiveEffect::PushConst(-1)]),
        CilOp::LdcI4N(value) => plain(vec![PrimitiveEffect::PushConst(i64::from(value))]),
        CilOp::LdcI4S | CilOp::LdcI4 => HandlerSpec {
            effects: vec![PrimitiveEffect::PushOperandI64],
            operand_encoding: OperandEncoding::I64,
        },
        CilOp::Add => plain(vec![PrimitiveEffect::Binary(BinOp::Add)]),
        CilOp::Sub => plain(vec![PrimitiveEffect::Binary(BinOp::Sub)]),
        CilOp::Mul => plain(vec![PrimitiveEffect::Binary(BinOp::Mul)]),
        CilOp::And => plain(vec![PrimitiveEffect::Binary(BinOp::And)]),
        CilOp::Or => plain(vec![PrimitiveEffect::Binary(BinOp::Or)]),
        CilOp::Xor => plain(vec![PrimitiveEffect::Binary(BinOp::Xor)]),
        CilOp::Ret => plain(vec![PrimitiveEffect::Return]),
        CilOp::BrS => target(vec![PrimitiveEffect::Branch]),
        CilOp::BrtrueS => target(vec![PrimitiveEffect::BranchIfTrue]),
        CilOp::BrfalseS => target(vec![PrimitiveEffect::BranchIfFalse]),
        CilOp::BeqS => target(vec![
            PrimitiveEffect::Binary(BinOp::Ceq),
            PrimitiveEffect::BranchIfTrue,
        ]),
        CilOp::BltS => target(vec![
            PrimitiveEffect::Binary(BinOp::Clt),
            PrimitiveEffect::BranchIfTrue,
        ]),
        CilOp::BgtS => target(vec![
            PrimitiveEffect::Binary(BinOp::Cgt),
            PrimitiveEffect::BranchIfTrue,
        ]),
        CilOp::BgeS => target(vec![
            PrimitiveEffect::Binary(BinOp::Clt),
            PrimitiveEffect::BranchIfFalse,
        ]),
        CilOp::BleS => target(vec![
            PrimitiveEffect::Binary(BinOp::Cgt),
            PrimitiveEffect::BranchIfFalse,
        ]),
        CilOp::Nop
        | CilOp::Ldnull
        | CilOp::Dup
        | CilOp::Pop
        | CilOp::Call
        | CilOp::Div
        | CilOp::Rem
        | CilOp::Ldstr => opaque(),
    }
}

const fn plain(effects: Vec<PrimitiveEffect>) -> HandlerSpec {
    HandlerSpec {
        effects,
        operand_encoding: OperandEncoding::None,
    }
}

const fn target(effects: Vec<PrimitiveEffect>) -> HandlerSpec {
    HandlerSpec {
        effects,
        operand_encoding: OperandEncoding::Target,
    }
}

fn opaque() -> HandlerSpec {
    HandlerSpec {
        effects: vec![PrimitiveEffect::Opaque],
        operand_encoding: OperandEncoding::None,
    }
}
