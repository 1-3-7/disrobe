mod budget;
pub mod byte_stack;
pub mod cil_handler;
pub mod emit;
mod handlers;
mod ir;
mod lift;
mod microop;
mod profile;
mod state;
pub mod structure;

pub use budget::{Budget, BudgetError};
pub use handlers::HandlerSummary;
pub use ir::{
    BasicBlock, BinOp, BlockId, CilType, DvIr, IrInstruction, IrVerifyError, Terminator, ValueId,
};
pub use microop::{MicroOp, match_canonical_effect};
pub use profile::{
    DecodedOperand, MAX_OPERAND_BYTES, OperandEncoding, ProtectorProfile, SyntheticHandler,
    SyntheticStackProfile, SyntheticVmModel, VInstr, VmDispatch, VmFlavor,
};
pub use state::{
    AbstractState, CanonicalEffect, ControlEffect, Expr, OperandRange, PrimitiveEffect,
    StateLocation,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reject {
    pub reason: String,
    pub evidence: Vec<String>,
}

impl Reject {
    #[must_use]
    pub fn new(reason: &str, evidence: Vec<String>) -> Self {
        Self {
            reason: reason.to_owned(),
            evidence,
        }
    }

    #[must_use]
    pub fn from_budget_error(error: BudgetError) -> Self {
        Self::new("analysis budget exhausted", vec![error.to_string()])
    }
}

impl std::fmt::Display for Reject {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

impl std::error::Error for Reject {}

pub fn devirtualize(model: &SyntheticVmModel, budget: &mut Budget) -> Result<DvIr, Reject> {
    let profile: SyntheticStackProfile = SyntheticStackProfile;
    lift::lift(model, &profile, budget)
}
