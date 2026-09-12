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

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProvenanceLiftError {
    #[error(transparent)]
    Lift(#[from] LiftError),
    #[error("invalid source provenance: {0}")]
    Provenance(#[from] disrobe_nir::NirProvenanceError),
    #[error("multiple source instructions use address {address:#x}")]
    DuplicateSourceAddress { address: u64 },
    #[error(
        "source instruction at {address:#x} declares {declared} bytes but carries {actual} bytes"
    )]
    SourceByteLength {
        address: u64,
        declared: usize,
        actual: usize,
    },
    #[error("source instruction address {actual:#x} is not contiguous with {expected:#x}")]
    SourceAddressGap { expected: u64, actual: u64 },
    #[error("decoded block declares {declared} consumed bytes but carries {actual} source bytes")]
    ConsumedBytes { declared: usize, actual: usize },
    #[error("source byte total exceeds the platform index range")]
    SourceByteTotalOverflow,
    #[error("source provenance is unavailable after delay-slot reordering")]
    DelaySlots,
}

pub type ProvenanceResult<T> = core::result::Result<T, ProvenanceLiftError>;
