use thiserror::Error;

#[derive(Debug, Error)]
pub enum LiftError {
    #[error("source IR unavailable: {0}")]
    Source(String),
    #[error("lift produced no functions")]
    Empty,
    #[error("ast nesting exceeded the lift depth limit of {limit}")]
    DepthExceeded { limit: usize },
    #[error("ast node count exceeded the lift node limit of {limit}")]
    AstSizeExceeded { limit: usize },
    #[error("p-code instruction count exceeded the lift limit of {limit}")]
    PcodeInstructionLimit { limit: usize },
    #[error("p-code operation count exceeded the lift limit of {limit}")]
    PcodeOperationLimit { limit: usize },
    #[error("invalid p-code at {address:#x} in {operation}: {reason}")]
    InvalidPcode {
        address: u64,
        operation: String,
        reason: String,
    },
}

pub type Result<T> = core::result::Result<T, LiftError>;
