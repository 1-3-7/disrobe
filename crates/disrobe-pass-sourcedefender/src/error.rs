use miette::Diagnostic;
use thiserror::Error;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("DR-SDEF-0001: input is not a .pye file (missing BEGIN/END markers)")]
    NotPye,

    #[error("DR-SDEF-0002: I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DR-SDEF-0003: filename is empty; cannot derive password from filename")]
    EmptyFilename,

    #[error("DR-SDEF-0004: base85 decode failed for {field}: {message}")]
    Base85 { field: String, message: String },

    #[error("DR-SDEF-0005: IV is not 16 bytes (got {0})")]
    BadIv(usize),

    #[error("DR-SDEF-0006: blake2b internal error: {0}")]
    Blake2(String),

    #[error("DR-SDEF-0007: input must be valid UTF-8 to parse .pye envelope")]
    NotUtf8,

    #[error("DR-SDEF-0008: msgpack envelope decode failed: {0}")]
    Msgpack(String),

    #[error("DR-SDEF-0009: inlined envelope is missing filename hint near offset {0}")]
    InlinedFilename(usize),

    #[error("DR-SDEF-0010: inlined extractor found {0} blocks with no decryptable payload")]
    InlinedNoDecrypt(usize),

    #[error("DR-SDEF-0011: input limit exceeded for {surface}: {observed} bytes > {limit} bytes")]
    InputLimit {
        surface: &'static str,
        observed: usize,
        limit: usize,
    },

    #[error("DR-SDEF-0012: nesting limit exceeded for {surface}: limit {limit}")]
    NestingLimit { surface: &'static str, limit: usize },
}

pub type Result<T> = core::result::Result<T, Error>;
