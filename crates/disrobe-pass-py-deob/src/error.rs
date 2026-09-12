use miette::Diagnostic;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("DR-PYDEOB-0001: source does not match any known obfuscation family")]
    NoFamilyMatched,

    #[error("DR-PYDEOB-0002: I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error(
        "DR-PYDEOB-0003: encoder peel depth limit ({0}) reached without converging on plaintext"
    )]
    DepthLimit(usize),

    #[error("DR-PYDEOB-0004: base64 decode failed: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("DR-PYDEOB-0005: zlib decompression failed: {0}")]
    Zlib(String),

    #[error("DR-PYDEOB-0006: lzma decompression failed: {0}")]
    Lzma(String),

    #[error("DR-PYDEOB-0007: extracted bytes literal in obfuscated wrapper not found")]
    LiteralNotFound,

    #[error("DR-PYDEOB-0008: invalid utf-8 in deobfuscated source: {0}")]
    Utf8(#[from] core::str::Utf8Error),

    #[error("DR-PYDEOB-0009: AST cleanup failed: {0}")]
    AstCleanup(String),

    #[error("DR-PYDEOB-0010: marshal decode failed: {0}")]
    Marshal(String),

    #[error("DR-PYDEOB-0011: XOR key extraction failed: {0}")]
    XorKey(String),

    #[error("DR-PYDEOB-0012: XOR layer detected but key bytes not recoverable")]
    XorKeyMissing,

    #[error(
        "DR-PYDEOB-0013: decompressed output exceeds {limit} byte ceiling (possible decompression bomb)"
    )]
    DecompressionTooLarge { limit: u64 },

    #[error("DR-PYDEOB-0014: bzip2 decompression failed: {0}")]
    Bzip2(String),

    #[error("DR-PYDEOB-0015: gzip decompression failed: {0}")]
    Gzip(String),
}
