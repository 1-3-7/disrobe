use thiserror::Error;

#[derive(Debug, Error)]
pub enum GeneratorError {
    #[error("unexpected character {found:?} at byte {offset} of {context}")]
    UnexpectedCharacter {
        found: char,
        offset: usize,
        context: String,
    },
    #[error("unexpected end of input while parsing {context}")]
    UnexpectedEnd { context: String },
    #[error("trailing input at byte {offset} of {context}")]
    TrailingInput { offset: usize, context: String },
    #[error("unknown identifier {name:?} in {context}")]
    UnknownIdentifier { name: String, context: String },
    #[error("unknown operator tag {tag:?} in {context}")]
    UnknownOperator { tag: String, context: String },
    #[error("integer literal {literal:?} does not fit a 64-bit value")]
    LiteralOutOfRange { literal: String },
    #[error("expression exceeds the {limit} node budget")]
    NodeBudget { limit: usize },
    #[error("expression exceeds the {limit} depth budget")]
    DepthBudget { limit: usize },
    #[error("width {bits} is not a supported bit width")]
    UnsupportedWidth { bits: u32 },
    #[error("corpus entry {id:?} is degenerate: the transform left the expression unchanged")]
    DegenerateEntry { id: String },
    #[error("corpus entry {id:?} is not an identity at width {bits}")]
    NotAnIdentity { id: String, bits: u32 },
    #[error("duplicate corpus entry id {id:?}")]
    DuplicateId { id: String },
    #[error("corpus entry {id:?} has a case with no matching original")]
    UnmatchedCase { id: String },
    #[error("malformed record in {path}: {detail}")]
    MalformedRecord { path: String, detail: String },
    #[error("{path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("regenerated {path} does not match the committed bytes")]
    Drift { path: String },
    #[error("{detail}")]
    Invalid { detail: String },
}

pub type GeneratorResult<T> = Result<T, GeneratorError>;
