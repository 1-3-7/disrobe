use miette::Diagnostic;
use thiserror::Error;

pub(crate) type Result<T> = core::result::Result<T, RubyError>;

#[derive(Debug, Error, Diagnostic)]
pub enum RubyError {
    #[error("DR-RUBY-0001: input envelope is empty")]
    EmptyInput,

    #[error("DR-RUBY-0002: input envelope is too short ({got} bytes, need at least {need})")]
    Truncated { got: usize, need: usize },

    #[error("DR-RUBY-0003: unknown ruby flavor at input head: {hex_head}")]
    UnknownFlavor { hex_head: String },

    #[error("DR-RUBY-0010: YARV header magic mismatch (expected 'YARB', got {got:?})")]
    YarvBadMagic { got: [u8; 4] },

    #[error("DR-RUBY-0011: YARV unsupported major version {major}.{minor} (supported 2.6-3.4)")]
    YarvUnsupportedVersion { major: u32, minor: u32 },

    #[error("DR-RUBY-0012: YARV header truncated at field {field}")]
    YarvHeaderTruncated { field: &'static str },

    #[error("DR-RUBY-0013: YARV opcode 0x{op:02x} unknown for ruby {major}.{minor}")]
    YarvUnknownOpcode { op: u8, major: u32, minor: u32 },

    #[error("DR-RUBY-0020: mruby RITE magic mismatch (expected 'RITE', got {got:?})")]
    MrubyBadMagic { got: [u8; 4] },

    #[error("DR-RUBY-0021: mruby unsupported format version {version:?}")]
    MrubyUnsupportedVersion { version: [u8; 4] },

    #[error("DR-RUBY-0022: mruby section header truncated at offset {offset}")]
    MrubySectionTruncated { offset: usize },

    #[error("DR-RUBY-0023: mruby unknown section identifier {section:?}")]
    MrubyUnknownSection { section: [u8; 4] },

    #[error("DR-RUBY-0024: mruby IREP record truncated at offset {at}")]
    MrubyIrepTruncated { at: usize },

    #[error("DR-RUBY-0025: mruby IREP child nesting exceeded the safety bound")]
    MrubyIrepDepthExceeded,

    #[error("DR-RUBY-0026: mruby IREP record count exceeded the safety bound")]
    MrubyIrepTooManyRecords,

    #[error("DR-RUBY-0027: mruby opcode 0x{op:02x} unknown at iseq offset {at}")]
    MrubyUnknownOpcode { op: u8, at: usize },

    #[error("DR-RUBY-0030: MRI source is not valid UTF-8 at byte {at}")]
    MriBadUtf8 { at: usize },

    #[error("DR-RUBY-0040: JRuby .class delegation requires disrobe-pass-jvm in the pipeline")]
    JrubyDelegationRequired,

    #[error("DR-RUBY-0050: TruffleRuby AOT image header not recognised")]
    TruffleRubyUnknownImage,

    #[error("DR-RUBY-0060: ruby2exe/ocra wrapper signature not found")]
    Ruby2ExeNoSignature,

    #[error("DR-RUBY-0061: ocra opcode stream truncated at offset {at}")]
    OcraOpcodeStreamTruncated { at: usize },

    #[error("DR-RUBY-0062: ocra opcode 0x{opcode:x} unknown at offset {at}")]
    OcraUnknownOpcode { opcode: u32, at: usize },

    #[error("DR-RUBY-0063: ocra opcode count exceeded the safety bound")]
    OcraTooManyOpcodes,

    #[error("DR-RUBY-0064: ocra LZMA chunk decode failed: {0}")]
    OcraLzmaDecode(String),

    #[error("DR-RUBY-0099: serialization failure: {0}")]
    Serialize(String),
}

impl From<serde_json::Error> for RubyError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialize(value.to_string())
    }
}
