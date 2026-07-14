use disrobe_bytes::ByteReadError;
use miette::Diagnostic;
use thiserror::Error;

use crate::model::WebviewFamily;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("DR-WEBVIEW-0001: no webview-desktop frontend detected in input")]
    NotDetected,

    #[error(
        "DR-WEBVIEW-0002: {family} frontend detected but static extraction is not yet implemented"
    )]
    FamilyNotExtractable { family: WebviewFamily },

    #[error("DR-WEBVIEW-0003: asar header malformed: {0}")]
    AsarHeader(String),

    #[error("DR-WEBVIEW-0004: asar entry `{path}` out of bounds: {detail}")]
    AsarBounds { path: String, detail: String },

    #[error("DR-WEBVIEW-0005: asar json tree parse failed: {0}")]
    Json(#[from] serde_json::Error),

    #[error("DR-WEBVIEW-0006: byte read out of bounds: {0}")]
    ByteRead(String),

    #[error("DR-WEBVIEW-0007: extraction quota exceeded on `{entry}`: {reason}")]
    Quota { entry: String, reason: String },

    #[error("DR-WEBVIEW-0008: recovered path escapes output root: {0}")]
    UnsafePath(String),

    #[error("DR-WEBVIEW-0009: nested asset depth exceeds cap {0}")]
    DepthExceeded(usize),
}

impl From<ByteReadError> for Error {
    fn from(value: ByteReadError) -> Self {
        Self::ByteRead(value.to_string())
    }
}

impl From<disrobe_binfmt::Error> for Error {
    fn from(value: disrobe_binfmt::Error) -> Self {
        match value {
            disrobe_binfmt::Error::QuotaExceeded { entry, reason } => Self::Quota { entry, reason },
            disrobe_binfmt::Error::UnsafeEntryPath(path) => Self::UnsafePath(path),
            other => Self::AsarBounds {
                path: String::new(),
                detail: other.to_string(),
            },
        }
    }
}
