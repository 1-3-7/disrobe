use miette::Diagnostic;
use thiserror::Error;

use crate::capability::Capability;

pub type Result<T> = core::result::Result<T, CoreError>;

#[derive(Debug, Error, Diagnostic)]
pub enum CoreError {
    #[error("DR-CORE-0001: capability resolver could not satisfy required: {required:?}")]
    UnsatisfiableRequirement { required: Capability },

    #[error(
        "DR-CORE-0002: capability migration cycle detected starting at {start:?} after {steps} hops"
    )]
    MigrationCycle { start: Capability, steps: usize },

    #[error("DR-CORE-0003: pass returned an unwrapped error: {0}")]
    PassFailure(String),

    #[error(
        "DR-CORE-0004: artifact rung mismatch: pass {pass_id} expects {expected:?}, got {got:?}"
    )]
    RungMismatch {
        pass_id: String,
        expected: String,
        got: String,
    },
}
