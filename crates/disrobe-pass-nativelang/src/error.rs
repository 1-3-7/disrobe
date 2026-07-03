use miette::Diagnostic;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("DR-NATIVELANG-0001: input too small for any native container ({0} bytes)")]
    InputTooSmall(usize),

    #[error("DR-NATIVELANG-0002: input is not a recognized native container (PE/ELF/Mach-O)")]
    UnrecognizedContainer,

    #[error("DR-NATIVELANG-0003: native container parse failed: {0}")]
    ContainerParse(String),

    #[error(
        "DR-NATIVELANG-0004: no Nim/Zig/Crystal/D fingerprint matched (not a recognized native-lang binary)"
    )]
    NoLanguageFingerprint,
}
