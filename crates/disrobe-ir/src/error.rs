use thiserror::Error;

#[derive(Debug, Error)]
pub enum EnvelopeError {
    #[error("envelope too short: expected >={expected} bytes, got {got}")]
    Truncated { expected: usize, got: usize },

    #[error("bad magic: expected {expected:?}, got {got:?}")]
    BadMagic { expected: [u8; 8], got: [u8; 8] },

    #[error("unsupported envelope version: {0}")]
    BadVersion(u16),

    #[error("unknown rung: {0}")]
    BadRung(u8),

    #[error("BLAKE3 root hash mismatch: header {header:?}, computed {computed:?}")]
    RootHashMismatch {
        header: [u8; 32],
        computed: [u8; 32],
    },

    #[error("rkyv serialize: {0}")]
    RkyvSer(String),

    #[error("rkyv access: {0}")]
    RkyvAccess(String),

    #[error("rkyv deserialize: {0}")]
    RkyvDeser(String),

    #[error("postcard codec: {0}")]
    Postcard(#[from] postcard::Error),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("payload too large for u32 length field: actual {actual}, max {max}")]
    PayloadTooLarge { actual: usize, max: u32 },

    #[error("envelope too large to decode: declared {actual} bytes, max {max}")]
    EnvelopeTooLarge { actual: usize, max: usize },
}

pub type Result<T> = std::result::Result<T, EnvelopeError>;
