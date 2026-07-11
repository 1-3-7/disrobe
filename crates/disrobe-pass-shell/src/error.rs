use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
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

    #[error("{what} exceeds {max_bytes}-byte cap")]
    InputTooLarge {
        what: &'static str,
        max_bytes: usize,
    },

    #[error("unrecognised shell dialect")]
    UnknownDialect,

    #[error("input is empty")]
    EmptyInput,

    #[error("invoke-obfuscation level not recognised")]
    UnknownObfuscationLevel,
}

pub(crate) fn base64_error(input: &[u8], source: disrobe_core::codec::DecodeError) -> Error {
    let error: base64::DecodeError = match BASE64_STANDARD.decode(input) {
        Ok(_) => fallback_base64_error(input, source),
        Err(error) => error,
    };
    Error::Base64(error)
}

fn fallback_base64_error(
    input: &[u8],
    source: disrobe_core::codec::DecodeError,
) -> base64::DecodeError {
    match source {
        disrobe_core::codec::DecodeError::InvalidSymbol { symbol } => {
            let offset: usize = input
                .iter()
                .position(|byte: &u8| *byte == symbol)
                .map_or(0usize, |index: usize| index);
            base64::DecodeError::InvalidByte(offset, symbol)
        }
        disrobe_core::codec::DecodeError::BadLength { len }
        | disrobe_core::codec::DecodeError::TooLarge { len } => {
            base64::DecodeError::InvalidLength(len)
        }
        disrobe_core::codec::DecodeError::BadPadding => base64::DecodeError::InvalidPadding,
        disrobe_core::codec::DecodeError::MissingFrame
        | disrobe_core::codec::DecodeError::Overflow => {
            base64::DecodeError::InvalidLength(input.len())
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
