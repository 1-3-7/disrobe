use thiserror::Error;

#[derive(Debug, Error)]
pub enum TypeRecError {
    #[error("binary parse failed: {0}")]
    Object(String),
    #[error("dwarf read failed: {0}")]
    Dwarf(String),
    #[error("no .text section in image")]
    NoText,
    #[error("function range {low:#x}..{high:#x} is outside the mapped image")]
    RangeOutsideImage { low: u64, high: u64 },
    #[error("function bytes for {0:#x} could not be located")]
    FunctionBytes(u64),
}

pub type Result<T> = core::result::Result<T, TypeRecError>;
