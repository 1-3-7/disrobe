use miette::Diagnostic;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("DR-WASMDEOB-0001: input is not a valid WebAssembly module: {0}")]
    Parse(String),

    #[error("DR-WASMDEOB-0002: I/O error: {0}")]
    Io(#[from] std::io::Error),
}
