use std::collections::BTreeMap;

use super::Reject;
use super::budget::Budget;
use super::cil_handler::{BYTE_STACK_CIL_HANDLER_PROFILE, summarize_cil_handler};
use super::handlers::HandlerSummary;
use super::ir::DvIr;
use super::lift::lift;
use super::profile::{
    DecodedOperand, ProtectorProfile, SyntheticHandler, SyntheticVmModel, VmDispatch, VmFlavor,
    decode_standard_operand,
};
use super::state::ControlEffect;

#[derive(Clone, Copy, Debug, Default)]
pub struct ByteStackProfile;

impl ByteStackProfile {
    pub fn devirtualize(
        self,
        model: &SyntheticVmModel,
        budget: &mut Budget,
    ) -> Result<DvIr, Reject> {
        lift(model, &self, budget)
    }
}

impl ProtectorProfile for ByteStackProfile {
    fn validate_model(&self, model: &SyntheticVmModel, budget: &mut Budget) -> Result<(), Reject> {
        if model.flavor != self.flavor() || model.dispatch != VmDispatch::OpcodeByte {
            return Err(Reject::new(
                "VM shape is unsupported by the selected profile",
                Vec::new(),
            ));
        }
        for handler_id in model.handlers.keys() {
            budget.spend(1).map_err(Reject::from_budget_error)?;
            if u8::try_from(*handler_id).is_err() {
                return Err(Reject::new(
                    "byte-dispatch handler opcode exceeds byte width",
                    vec![handler_id.to_string()],
                ));
            }
        }
        for instruction in &model.instructions {
            budget.spend(1).map_err(Reject::from_budget_error)?;
            if u8::try_from(instruction.handler_id).is_err() {
                return Err(Reject::new(
                    "byte-dispatch instruction opcode exceeds byte width",
                    vec![instruction.handler_id.to_string()],
                ));
            }
        }
        Ok(())
    }

    fn discover_handler_table<'a>(
        &self,
        model: &'a SyntheticVmModel,
    ) -> Result<&'a BTreeMap<u16, SyntheticHandler>, Reject> {
        Ok(&model.handlers)
    }

    fn summarize_handler(
        &self,
        handler: &SyntheticHandler,
        budget: &mut Budget,
    ) -> Result<HandlerSummary, Reject> {
        let body: &[u8] = match handler.cil_handler_body() {
            Some(value) => value,
            None => return Ok(unknown_summary()),
        };
        summarize_cil_handler(body, &BYTE_STACK_CIL_HANDLER_PROFILE, budget)
    }

    fn decode_operand(
        &self,
        handler: &SyntheticHandler,
        operand: &[u8],
        budget: &mut Budget,
    ) -> Result<DecodedOperand, Reject> {
        decode_standard_operand(handler, operand, budget)
    }

    fn flavor(&self) -> VmFlavor {
        VmFlavor::Stack
    }
}

const fn unknown_summary() -> HandlerSummary {
    HandlerSummary {
        stack_delta: 0,
        reads: Vec::new(),
        writes: Vec::new(),
        control_effect: ControlEffect::Unknown,
        canonical_op: None,
    }
}
