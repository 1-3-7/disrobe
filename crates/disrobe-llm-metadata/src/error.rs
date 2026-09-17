use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LlmMetadataError {
    #[error("unknown LLM metadata category `{0}`")]
    UnknownCategory(String),

    #[error("`decryption_keys` requested without `--i-have-authorization`")]
    UnauthorizedDecryptionKeys,

    #[error("LLM metadata emission failed for category `{category}` in pass `{pass}`: {reason}")]
    EmissionFailed {
        pass: String,
        category: String,
        reason: String,
    },

    #[error("LLM metadata serialization failed: {0}")]
    Serialization(String),
}
