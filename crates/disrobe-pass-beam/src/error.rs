use miette::Diagnostic;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("DR-BEAM-0001: I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DR-BEAM-0002: invalid IFF magic: expected 'FOR1', got {0:?}")]
    BadIffMagic([u8; 4]),

    #[error("DR-BEAM-0003: invalid form type: expected 'BEAM', got {0:?}")]
    BadFormType([u8; 4]),

    #[error("DR-BEAM-0004: truncated at offset {offset}: needed {needed} bytes, had {had}")]
    Truncated {
        offset: usize,
        needed: usize,
        had: usize,
    },

    #[error("DR-BEAM-0005: declared form length {declared} exceeds available {available}")]
    BadFormLength { declared: usize, available: usize },

    #[error("DR-BEAM-0006: chunk '{tag}' length {len} overflows remaining {remaining}")]
    BadChunkLength {
        tag: String,
        len: usize,
        remaining: usize,
    },

    #[error("DR-BEAM-0007: required chunk '{0}' missing")]
    MissingChunk(&'static str),

    #[error("DR-BEAM-0008: invalid UTF-8 in atom #{index}")]
    BadAtomUtf8 { index: u32 },

    #[error("DR-BEAM-0009: atom index {0} out of range (table size {1})")]
    BadAtomIndex(u32, u32),

    #[error("DR-BEAM-0010: Code chunk sub-header reports size {0} but only {1} bytes available")]
    BadCodeHeader(u32, usize),

    #[error("DR-BEAM-0011: unsupported Code instruction-set version {0}")]
    UnsupportedInstructionSet(u32),

    #[error(
        "DR-BEAM-0012: unsupported opcode {opcode} at code offset {offset} (max known opcode {max_known}; likely a future OTP release - file an issue)"
    )]
    UnknownOpcode {
        opcode: u32,
        offset: usize,
        max_known: u32,
    },

    #[error("DR-BEAM-0013: malformed compact term at code offset {0}")]
    BadCompactTerm(usize),

    #[error("DR-BEAM-0014: ETF magic byte wrong: expected 131, got {0}")]
    BadEtfMagic(u8),

    #[error("DR-BEAM-0015: unsupported ETF tag {tag} at offset {offset}")]
    UnsupportedEtfTag { tag: u8, offset: usize },

    #[error("DR-BEAM-0016: zlib decompression of '{0}' chunk failed: {1}")]
    Zlib(&'static str, String),

    #[error("DR-BEAM-0017: ZIP / EZ archive error: {0}")]
    Zip(String),

    #[error("DR-BEAM-0018: not an Elixir Dbgi payload: backend or version mismatch ({0})")]
    NotElixirDbgi(String),

    #[error("DR-BEAM-0019: not an Erlang abstract_code Dbgi payload")]
    NotErlangAbstractCode,

    #[error("DR-BEAM-0020: integer overflow decoding {0}")]
    IntOverflow(&'static str),

    #[error("DR-BEAM-0021: EZ archive quota exceeded for entry '{entry}': {reason}")]
    EzQuotaExceeded { entry: String, reason: String },

    #[error("DR-BEAM-0022: unsafe EZ entry path '{0}' (path traversal or absolute path)")]
    EzUnsafePath(String),

    #[error("DR-BEAM-0023: nesting depth exceeded {limit} while decoding {kind}")]
    DepthExceeded { kind: &'static str, limit: usize },

    #[error(
        "DR-BEAM-0024: table '{table}' count {count} exceeds {available} bytes at minimum row size {min_record_size}"
    )]
    TableCountTooLarge {
        table: &'static str,
        count: u32,
        available: usize,
        min_record_size: usize,
    },
}

impl From<zip::result::ZipError> for Error {
    fn from(value: zip::result::ZipError) -> Self {
        Self::Zip(value.to_string())
    }
}
