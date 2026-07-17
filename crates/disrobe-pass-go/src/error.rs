use miette::Diagnostic;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("DR-GO-0001: input too small for any native container ({0} bytes)")]
    InputTooSmall(usize),

    #[error("DR-GO-0002: input is not a recognized native container (PE/ELF/Mach-O)")]
    UnrecognizedContainer,

    #[error("DR-GO-0003: native container parse failed: {0}")]
    ContainerParse(String),

    #[error("DR-GO-0004: gopclntab section not found")]
    PclntabMissing,

    #[error("DR-GO-0005: gopclntab magic mismatch (got {magic:#010x})")]
    PclntabMagic { magic: u32 },

    #[error(
        "DR-GO-0007: pclntab field at offset {offset:#x} read overflowed section ({len} bytes)"
    )]
    PclntabRead { offset: usize, len: usize },

    #[error("DR-GO-0008: pclntab references invalid quantum/ptrsize ({0})")]
    PclntabInvariant(&'static str),
}
