mod auditable;
mod paths;
mod releases;
mod symbols;

use miette::Diagnostic;
use object::read::{File as ObjectFile, FileKind};
use serde::Serialize;
use thiserror::Error;

use crate::image::ImageKind;

pub use auditable::{
    AUDITABLE_SECTION, AuditableEdge, AuditableEvidence, AuditableGraph, AuditablePackage,
    AuditableRefusal, AuditableSection, DependencyKind,
};
pub use paths::{CrateSource, PathStart, RecoveredCrate, RustcCommit};
pub use releases::{release_for_commit, stable_releases};
pub use symbols::{
    CrateSymbols, ManglingScheme, SymbolEvidence, SymbolInventory, symbol_path_crate,
};

#[derive(Debug, Error, Diagnostic)]
pub enum RustInventoryError {
    #[error("DR-RUSTINV-0001: input is not a PE, ELF or Mach-O image")]
    UnsupportedContainer,

    #[error(
        "DR-RUSTINV-0002: input is a universal Mach-O; extract one architecture slice and inventory that"
    )]
    UniversalMachO,

    #[error("DR-RUSTINV-0003: {container:?} image does not parse: {reason}")]
    ContainerParse {
        container: ImageKind,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Evidence {
    pub offset: u64,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct InventoryTruncation {
    pub paths: bool,
    pub crates: bool,
    pub rustc_commits: bool,
    pub symbols: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RustInventory {
    pub container: ImageKind,
    pub input_bytes: u64,
    pub rustc: Vec<RustcCommit>,
    pub crates: Vec<RecoveredCrate>,
    pub auditable: AuditableEvidence,
    pub symbols: SymbolInventory,
    pub truncated: InventoryTruncation,
}

pub fn rust_inventory(bytes: &[u8]) -> Result<RustInventory, RustInventoryError> {
    let container: ImageKind = match FileKind::parse(bytes) {
        Ok(FileKind::Pe32 | FileKind::Pe64) => ImageKind::Pe,
        Ok(FileKind::Elf32 | FileKind::Elf64) => ImageKind::Elf,
        Ok(FileKind::MachO32 | FileKind::MachO64) => ImageKind::MachO,
        Ok(FileKind::MachOFat32 | FileKind::MachOFat64) => {
            return Err(RustInventoryError::UniversalMachO);
        }
        Ok(_) | Err(_) => return Err(RustInventoryError::UnsupportedContainer),
    };
    let file: ObjectFile<'_> = ObjectFile::parse(bytes).map_err(|error: object::Error| {
        RustInventoryError::ContainerParse {
            container,
            reason: error.to_string(),
        }
    })?;
    let scan: paths::PathScan = paths::scan(bytes, &file, container);
    let auditable: AuditableEvidence = auditable::read(&file);
    let symbols: SymbolInventory = symbols::inventory(&file);
    let truncated: InventoryTruncation = InventoryTruncation {
        paths: scan.truncated_paths,
        crates: scan.truncated_crates,
        rustc_commits: scan.truncated_commits,
        symbols: symbols.truncated,
    };
    Ok(RustInventory {
        container,
        input_bytes: bytes.len() as u64,
        rustc: scan.rustc,
        crates: scan.crates,
        auditable,
        symbols,
        truncated,
    })
}
