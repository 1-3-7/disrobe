use miette::Diagnostic;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("DR-MARSHAL-0001: unexpected end of input at offset {offset}")]
    Eof { offset: usize },

    #[error("DR-MARSHAL-0002: unknown marshal type tag 0x{tag:02x} at offset {offset}")]
    UnknownTag { tag: u8, offset: usize },

    #[error("DR-MARSHAL-0003: invalid utf-8 in marshal string at offset {offset}: {source}")]
    InvalidUtf8 {
        offset: usize,
        #[source]
        source: core::str::Utf8Error,
    },

    #[error("DR-MARSHAL-0004: marshal ref-table index {index} out of bounds (table size {len})")]
    RefOutOfBounds { index: u32, len: usize },

    #[error(
        "DR-MARSHAL-0005: code object field count mismatch for {era:?} (expected {expected}, got {got})"
    )]
    CodeObjectShape {
        era: super::object::CodeEra,
        expected: usize,
        got: usize,
    },

    #[error("DR-MARSHAL-0006: unsupported python version {0:?}")]
    UnsupportedPyVersion(super::PyVersion),

    #[error("DR-MARSHAL-0007: pyc header too short (need {need} bytes, got {got})")]
    PycHeaderShort { need: usize, got: usize },

    #[error("DR-MARSHAL-0008: unknown pyc magic 0x{magic:08x}")]
    UnknownPycMagic { magic: u32 },

    #[error("DR-MARSHAL-0009: depth limit exceeded (limit {0})")]
    DepthLimit(usize),

    #[error("DR-MARSHAL-0010: long-int digit count {0} exceeds sanity limit")]
    LongDigitOverflow(u32),

    #[error("DR-MARSHAL-0011: tuple/list/dict length {0} exceeds sanity limit")]
    LengthOverflow(u32),

    #[error("DR-MARSHAL-0012: payload length {actual} exceeds marshal u32 size field max ({max})")]
    WriterLengthOverflow { actual: usize, max: u32 },

    #[error(
        "DR-MARSHAL-0013: malformed ascii float/complex literal {literal:?} at offset {offset}"
    )]
    InvalidAsciiFloat { literal: String, offset: usize },

    #[error(
        "DR-MARSHAL-0014: materialized object node count exceeds budget {limit} (possible back-ref clone bomb)"
    )]
    NodeBudget { limit: u64 },

    #[error(
        "DR-MARSHAL-0015: strict round-trip mismatch for {version:?} (object_matches={object_matches}, bytes_match={bytes_match}, first_diff_offset={first_diff_offset:?})"
    )]
    RoundtripMismatch {
        version: super::PyVersion,
        object_matches: bool,
        bytes_match: bool,
        first_diff_offset: Option<usize>,
    },

    #[error(
        "DR-MARSHAL-0016: code-object {field} field for {era:?} has unexpected type tag {got} (expected {expected})"
    )]
    CodeFieldType {
        era: super::object::CodeEra,
        field: &'static str,
        expected: &'static str,
        got: &'static str,
    },

    #[error(
        "DR-MARSHAL-0017: code-object {field} value {value} does not fit the 16-bit field of legacy era {era:?}"
    )]
    CodeFieldWidth {
        era: super::object::CodeEra,
        field: &'static str,
        value: i32,
    },

    #[error(
        "DR-MARSHAL-0018: materialized object byte count exceeds budget {limit} (possible back-ref clone bomb)"
    )]
    ByteBudget { limit: u64 },

    #[error("DR-MARSHAL-0019: payload length {actual} exceeds marshal u8 size field max ({max})")]
    WriterShortLengthOverflow { actual: usize, max: u8 },

    #[error(
        "DR-MARSHAL-0020: recursive marshal reference {index} at offset {reference_offset} targets unfinished object at offset {definition_offset}; cyclic object graphs are unsupported"
    )]
    RecursiveReference {
        index: u32,
        reference_offset: usize,
        definition_offset: usize,
    },
}
