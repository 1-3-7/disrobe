use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid base64: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("invalid utf-16 little-endian payload")]
    InvalidUtf16Le,

    #[error("gzip decompression failed: {0}")]
    Gzip(#[from] std::io::Error),

    #[error("invalid regex: {0}")]
    Regex(#[from] regex::Error),

    #[error("ooxml extraction failed: {0}")]
    OoxmlZip(#[from] zip::result::ZipError),

    #[error("ole compound file error: {0}")]
    OleCfb(String),

    #[error("vba pcode stream is malformed: {reason}")]
    VbaPcode { reason: String },

    #[error("unrecognised shell dialect")]
    UnknownDialect,

    #[error("input is empty")]
    EmptyInput,

    #[error("invoke-obfuscation level not recognised")]
    UnknownObfuscationLevel,
}

pub type Result<T> = std::result::Result<T, Error>;
