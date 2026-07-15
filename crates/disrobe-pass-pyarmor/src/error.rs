use miette::Diagnostic;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("DR-PYARM-0001: input does not appear to be a PyArmor-protected wrapper")]
    NotPyarmor,

    #[error("DR-PYARM-0002: unknown PyArmor wrapper format: {0}")]
    UnknownWrapper(String),

    #[error("DR-PYARM-0003: payload bytes literal could not be extracted from wrapper")]
    PayloadLiteralMissing,

    #[error(
        "DR-PYARM-0004: PyArmor runtime extension not located alongside wrapper (looked at: {searched:?})"
    )]
    RuntimeNotFound { searched: Vec<String> },

    #[error("DR-PYARM-0005: PyArmor v8/v9 header truncated (need {need} bytes, got {got})")]
    HeaderTruncated { need: usize, got: usize },

    #[error("DR-PYARM-0006: PyArmor v8/v9 magic mismatch: expected ASCII PY+6digits, got {0:?}")]
    BadV8Magic([u8; 8]),

    #[error("DR-PYARM-0007: PyArmor v6/v7 magic mismatch: expected PYARMOR\\0, got {0:?}")]
    BadV6Magic([u8; 8]),

    #[error("DR-PYARM-0008: runtime DLL parse failed: {0}")]
    RuntimeParse(String),

    #[error("DR-PYARM-0009: AES key extraction failed (reason: {0})")]
    KeyExtraction(String),

    #[error("DR-PYARM-0010: AES decryption failed (likely wrong key)")]
    DecryptFailed,

    #[error("DR-PYARM-0011: marshal decode error after decrypt: {0}")]
    MarshalDecode(#[from] disrobe_py_marshal::Error),

    #[error("DR-PYARM-0012: I/O error reading input/runtime: {0}")]
    Io(#[from] std::io::Error),

    #[error(
        "DR-PYARM-0013: PyArmor v3/v4/v5 static decryption is an information-theoretic wall: AES-128-CTR code-object key is RSA-wrapped in the capsule (private RSA key never distributed)"
    )]
    LegacyNotImplemented,

    #[error(
        "DR-PYARM-0014: BCC mode payload requires native lifter (only Python half recoverable)"
    )]
    BccPartialOnly,

    #[error("DR-PYARM-0015: hex/escape decoding of wrapper bytes literal failed at position {0}")]
    HexDecode(usize),

    #[error("DR-PYARM-0016: dynamic hook required (--allow-dynamic) but disabled")]
    DynamicHookRequiresAllow,

    #[error("DR-PYARM-0017: no usable Python >= 3.9.7 found (searched: {searched:?})")]
    DynamicHookNoPython { searched: Vec<String> },

    #[error("DR-PYARM-0018: dynamic hook subprocess timed out after {secs}s")]
    DynamicHookTimedOut { secs: u64 },

    #[error("DR-PYARM-0019: dynamic hook subprocess exited (code {exit_code:?}); stderr={stderr}")]
    DynamicHookSubprocess {
        exit_code: Option<i32>,
        stderr: String,
    },

    #[error("DR-PYARM-0020: dynamic hook produced zero captures (stderr: {stderr})")]
    DynamicHookZeroCaptures { stderr: String },

    #[error("DR-PYARM-0021: dynamic hook found Python {found} but requires >= {required}")]
    DynamicHookPythonTooOld { found: String, required: String },

    #[error("DR-PYARM-0050: BCC native body present, lift requires --allow-bcc")]
    BccRequiresAllowBcc,

    #[error(
        "DR-PYARM-0052: --strict requested and pass produced only a partial/skeleton decode (reason: {0})"
    )]
    StrictPartial(String),

    #[error(
        "DR-PYARM-0053: PyArmor {version:?} legacy wrapper detected; static decryption walled (AES-128-CTR code-object key is RSA-wrapped in the capsule and absent from the distributed artifact)"
    )]
    LegacyDetectedOnly {
        version: crate::detect::PyarmorVersion,
    },

    #[error("DR-PYARM-0054: target python version {0} could not be mapped to a known .pyc magic")]
    UnknownTargetPyVersion(String),

    #[error("DR-PYARM-0055: --mode override {0} incompatible with detection {1}")]
    ModeOverrideIncompatible(String, String),

    #[error("DR-PYARM-0060: BCC lift called with empty blob")]
    BccLiftEmptyBlob,

    #[error("DR-PYARM-0061: BCC native object could not be parsed for lift: {0}")]
    BccLiftParse(String),

    #[error("DR-PYARM-0062: BCC function-to-source link found no residual module: {0}")]
    BccLinkNoResidual(String),
}
