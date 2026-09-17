use super::Reject;
use super::budget::Budget;
use super::microop::{MicroOp, match_canonical_effect};
use super::state::{AbstractState, ControlEffect, PrimitiveEffect, StateLocation, StateSummary};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandlerSummary {
    pub stack_delta: i16,
    pub reads: Vec<StateLocation>,
    pub writes: Vec<StateLocation>,
    pub control_effect: ControlEffect,
    pub canonical_op: Option<MicroOp>,
}

pub(crate) fn summarize(
    handler_effects: &[PrimitiveEffect],
    budget: &mut Budget,
) -> Result<HandlerSummary, Reject> {
    let mut state: AbstractState = AbstractState::new();
    for effect in handler_effects {
        state.apply(effect, budget)?;
    }
    let state_summary: StateSummary = state.summary()?;
    let canonical_op: Option<MicroOp> = state
        .canonical_effect(budget)?
        .and_then(|effect: super::state::CanonicalEffect| match_canonical_effect(&effect));
    Ok(HandlerSummary {
        stack_delta: state_summary.stack_delta,
        reads: state_summary.reads,
        writes: state_summary.writes,
        control_effect: state_summary.control,
        canonical_op,
    })
}
