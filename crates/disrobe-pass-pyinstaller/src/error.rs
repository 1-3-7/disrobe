use miette::Diagnostic;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("DR-PYINST-0001: MEI cookie magic not found in input (not a PyInstaller binary?)")]
    CookieNotFound,

    #[error("DR-PYINST-0002: cookie truncated at offset {0}")]
    CookieTruncated(usize),

    #[error("DR-PYINST-0003: I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DR-PYINST-0004: TOC walk failed at offset {0}: {1}")]
    TocWalk(usize, String),

    #[error("DR-PYINST-0005: zlib inflate failed for entry '{name}': {source}")]
    Inflate {
        name: String,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "DR-PYINST-0006: AES decryption failed (likely PyInstaller >= 6.0 without key, or wrong key)"
    )]
    DecryptFailed,

    #[error("DR-PYINST-0007: PYZ archive magic mismatch (expected b\"PYZ\\0\", got {0:?})")]
    BadPyzMagic([u8; 4]),

    #[error("DR-PYINST-0008: PYZ table-of-contents marshal decode error: {0}")]
    PyzTocDecode(#[from] disrobe_py_marshal::Error),

    #[error("DR-PYINST-0009: path traversal detected in TOC entry name '{0}'")]
    PathTraversal(String),

    #[error("DR-PYINST-0010: pyver field {0} could not be decoded to (major, minor)")]
    BadPyver(u32),
}
