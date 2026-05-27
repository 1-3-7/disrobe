use miette::Diagnostic;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("DR-NUITKA-0001: input does not appear to be a Nuitka-compiled binary")]
    NotNuitka,

    #[error("DR-NUITKA-0002: I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DR-NUITKA-0003: PE/ELF/Mach-O parse error: {0}")]
    ObjectParse(String),

    #[error("DR-NUITKA-0004: onefile payload magic mismatch (expected 'KA[XY]', got {0:?})")]
    BadOnefileMagic([u8; 3]),

    #[error("DR-NUITKA-0005: zstd decompression failed: {0}")]
    Zstd(String),

    #[error("DR-NUITKA-0006: onefile entry record truncated at offset {0}")]
    EntryTruncated(usize),

    #[error(
        "DR-NUITKA-0007: source-level recovery is mathematically impossible for Nuitka builds (native code; constants/symbols emitted only)"
    )]
    NoSource,

    #[error("DR-NUITKA-0008: build-info section not found in image")]
    BuildInfoMissing,

    #[error("DR-NUITKA-0009: build-info record malformed at offset {offset}: {reason}")]
    BuildInfoMalformed { offset: usize, reason: String },

    #[error("DR-NUITKA-0010: reassembly requires at least one payload entry")]
    EmptyPayload,
}
