use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EvmError {
    #[error("input is empty")]
    Empty,
    #[error("bytecode is {size} bytes, above the {limit}-byte limit")]
    TooLarge { size: usize, limit: usize },
    #[error("hex text has an odd number of digits ({digits})")]
    OddHex { digits: usize },
    #[error("hex text has a non-hex character {found:?} at offset {offset}")]
    BadHex { offset: usize, found: char },
    #[error(
        "EOF container (EIP-3540 magic 0xef00, version {version}) is not decoded; only legacy bytecode is analysed"
    )]
    EofContainer { version: u8 },
    #[error(
        "no runtime image found: the code never returns a region it copied from itself with CODECOPY, so it is not solc-style creation bytecode"
    )]
    NoRuntimeImage,
    #[error("input holds {found} after the 0x prefix but no hex digits")]
    NoDigits { found: &'static str },
}
