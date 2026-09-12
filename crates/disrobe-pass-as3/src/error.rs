use miette::Diagnostic;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("DR-AS3-0001: I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DR-AS3-0002: invalid SWF signature: expected FWS/CWS/ZWS, got {0:?}")]
    BadSwfSignature([u8; 3]),

    #[error("DR-AS3-0003: truncated SWF at offset {offset} (needed {needed} bytes, had {had})")]
    SwfTruncated {
        offset: usize,
        needed: usize,
        had: usize,
    },

    #[error("DR-AS3-0004: unsupported SWF version {0} (supported 1..=40)")]
    SwfUnsupportedVersion(u8),

    #[error("DR-AS3-0005: SWF body decompression failed ({kind}): {message}")]
    SwfDecompress { kind: &'static str, message: String },

    #[error("DR-AS3-0006: malformed SWF RECT header at offset {0}")]
    BadRect(usize),

    #[error("DR-AS3-0007: malformed SWF tag at offset {offset}: {reason}")]
    BadTag { offset: usize, reason: &'static str },

    #[error(
        "DR-AS3-0010: invalid ABC magic: expected 16 0x002E, got minor {minor:#06X} major {major:#06X}"
    )]
    BadAbcMagic { minor: u16, major: u16 },

    #[error("DR-AS3-0011: truncated ABC at offset {offset} (needed {needed} bytes, had {had})")]
    AbcTruncated {
        offset: usize,
        needed: usize,
        had: usize,
    },

    #[error("DR-AS3-0012: ABC variable-length u30/u32 exceeds its width: {0:#010X}")]
    AbcU30Overflow(u32),

    #[error("DR-AS3-0013: ABC constant-pool index {idx} out of range (size {size}) in pool {pool}")]
    AbcBadPoolIndex {
        pool: &'static str,
        idx: usize,
        size: usize,
    },

    #[error("DR-AS3-0015: unknown ABC multiname kind {0:#04X} at index {1}")]
    AbcUnknownMultinameKind(u8, usize),

    #[error("DR-AS3-0016: ABC method-body code length {0} exceeds remaining buffer")]
    AbcBadCodeLen(usize),

    #[error("DR-AS3-0017: unknown ABC trait kind {0:#04X} for name index {1}")]
    AbcUnknownTraitKind(u8, u32),

    #[error(
        "DR-AS3-0018: ABC pool count {count} for {pool} exceeds remaining input ({remaining} bytes)"
    )]
    AbcPoolCountTooLarge {
        pool: &'static str,
        count: u32,
        remaining: usize,
    },

    #[error("DR-AS3-0020: heuristic recovery aborted: {0}")]
    HeuristicAbort(&'static str),
}
