use miette::Diagnostic;
use thiserror::Error;

#[derive(Debug, Error, Diagnostic)]
pub enum DecompileError {
    #[error("unsupported python version: {version}")]
    #[diagnostic(code("DR-PYDEC-0001"))]
    UnsupportedVersion { version: String },

    #[error("unsupported runtime: {runtime}")]
    #[diagnostic(code("DR-PYDEC-0002"))]
    UnsupportedRuntime { runtime: String },

    #[error("malformed exception table: {reason}")]
    #[diagnostic(code("DR-PYDEC-0003"))]
    MalformedExceptionTable { reason: String },

    #[error("malformed linetable: {reason}")]
    #[diagnostic(code("DR-PYDEC-0004"))]
    MalformedLineTable { reason: String },

    #[error("frame tree well-formedness violation: {reason}")]
    #[diagnostic(code("DR-PYDEC-0005"))]
    FrameTreeInvariant { reason: String },

    #[error("unrecognized opcode {opcode:#04x} for {version}")]
    #[diagnostic(code("DR-PYDEC-0006"))]
    UnknownOpcode { opcode: u8, version: String },

    #[error("ast builder desync at offset {offset}: {reason}")]
    #[diagnostic(code("DR-PYDEC-0007"))]
    AstDesync { offset: usize, reason: String },

    #[error("structuring recursion depth limit {limit} exceeded (runaway region nesting)")]
    #[diagnostic(code("DR-PYDEC-0012"))]
    StructuringDepthExceeded { limit: usize },

    #[error("structuring block [{lo}, {hi}) out of range for {len} decoded ops")]
    #[diagnostic(code("DR-PYDEC-0013"))]
    BlockOutOfRange { lo: usize, hi: usize, len: usize },

    #[error("codegen failure: {reason}")]
    #[diagnostic(code("DR-PYDEC-0008"))]
    Codegen { reason: String },

    #[error("emit failure: {reason}")]
    #[diagnostic(code("DR-PYDEC-0009"))]
    Emit { reason: String },

    #[error(
        "recovery left an unresolved reconstruction placeholder ({stem}) at line {line} of the \
         emitted source; that placeholder names an internal of the recovery engine and is not \
         python, so this body is refused rather than published"
    )]
    #[diagnostic(code("DR-PYDEC-0014"))]
    UnresolvedMarker { stem: String, line: usize },

    #[error("io error: {0}")]
    #[diagnostic(code("DR-PYDEC-0010"))]
    Io(#[from] std::io::Error),

    #[error("marshal error: {0}")]
    #[diagnostic(code("DR-PYDEC-0011"))]
    Marshal(#[from] disrobe_py_marshal::Error),
}

pub type Result<T> = std::result::Result<T, DecompileError>;
