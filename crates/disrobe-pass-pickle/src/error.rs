use miette::Diagnostic;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("DR-PICKLE-0001: empty input: no pickle stream")]
    Empty,

    #[error("DR-PICKLE-0002: unknown opcode {opcode:#04x} at offset {offset}")]
    UnknownOpcode { opcode: u8, offset: usize },

    #[error(
        "DR-PICKLE-0003: truncated reading {what} at offset {offset}: needed {needed} bytes, had {had}"
    )]
    Truncated {
        what: &'static str,
        offset: usize,
        needed: usize,
        had: usize,
    },

    #[error("DR-PICKLE-0004: invalid UTF-8 in {what} at offset {offset}")]
    BadUtf8 { what: &'static str, offset: usize },

    #[error("DR-PICKLE-0005: missing newline terminator for {what} at offset {offset}")]
    MissingNewline { what: &'static str, offset: usize },

    #[error("DR-PICKLE-0006: malformed {what} literal at offset {offset}: {detail}")]
    BadLiteral {
        what: &'static str,
        offset: usize,
        detail: String,
    },

    #[error("DR-PICKLE-0007: stack underflow executing {op} at offset {offset}")]
    StackUnderflow { op: &'static str, offset: usize },

    #[error("DR-PICKLE-0008: no MARK on stack for {op} at offset {offset}")]
    NoMark { op: &'static str, offset: usize },

    #[error("DR-PICKLE-0009: memo key {key} not found at offset {offset}")]
    MemoMiss { key: u64, offset: usize },

    #[error(
        "DR-PICKLE-0010: declared length {declared} for {what} overflows remaining {remaining}"
    )]
    LengthOverflow {
        what: &'static str,
        declared: u64,
        remaining: usize,
    },

    #[error("DR-PICKLE-0011: recursion depth {depth} exceeds limit {limit}")]
    RecursionLimit { depth: usize, limit: usize },

    #[error("DR-PICKLE-0012: opcode budget {limit} exceeded (possible decompression bomb)")]
    OpcodeBudget { limit: usize },

    #[error("DR-PICKLE-0013: stream ended without STOP opcode")]
    NoStop,

    #[error("DR-PICKLE-0014: STOP reached with empty stack (no result value)")]
    EmptyResult,

    #[error("DR-PICKLE-0015: container error: {0}")]
    Container(String),

    #[error("DR-PICKLE-0016: I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error(
        "DR-PICKLE-0017: materialized value node count exceeds budget {limit} (possible clone bomb)"
    )]
    NodeBudget { limit: u64 },

    #[error(
        "DR-PICKLE-0018: value nesting depth {depth} exceeds limit {limit} (possible recursion bomb)"
    )]
    ValueDepth { depth: usize, limit: usize },

    #[error("DR-PICKLE-0019: archive entry {path} declares {declared} bytes over limit {limit}")]
    ArchiveEntryTooLarge {
        path: String,
        declared: u64,
        limit: u64,
    },

    #[error("DR-PICKLE-0020: archive entry count {count} exceeds limit {limit}")]
    ArchiveEntryCount { count: usize, limit: usize },

    #[error(
        "DR-PICKLE-0021: archive payload budget exceeded after {path}: {total} over limit {limit}"
    )]
    ArchivePayloadBudget {
        path: String,
        total: usize,
        limit: usize,
    },

    #[error("DR-PICKLE-0022: invalid argument for {op} at offset {offset}: expected {expected}")]
    InvalidArgument {
        op: &'static str,
        offset: usize,
        expected: &'static str,
    },
}
