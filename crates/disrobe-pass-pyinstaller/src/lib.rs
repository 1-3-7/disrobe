#![forbid(unsafe_code)]
#![allow(clippy::redundant_pub_crate)]
mod base_library;
#[cfg(feature = "chain")]
pub mod chain_detector;
mod cookie;
pub(crate) mod crypto;
pub(crate) mod debug;
mod deptree;
mod error;
mod extract;
mod manifest;
#[cfg(feature = "chain")]
pub mod native_surface;
mod onedir;
pub mod pass;
mod provenance_header;
mod pyc_zipper;
mod pyz;
mod toc;

pub use cookie::{Cookie, CookieVariant, find_cookie};
pub use deptree::{DependencyNode, DependencyTree, ModuleKind, build_dependency_tree};
pub use error::{Error, Result};
pub use extract::{ExtractOutput, ExtractedEntry, extract_archive, extract_from_path};
pub use manifest::{
    EntryClassification, ProtectionReport, ProtectionSignal, PyInstallerManifest, build_manifest,
};
pub use onedir::{OnedirLayout, OnedirPlan, plan_onedir};
pub use provenance_header::{
    python_extracted_header, python_unpacked_header, render_extracted_with_header,
    render_unpacked_with_header,
};
pub use pyc_zipper::{UnzippedPyc, ZipperCompression, looks_like_pyc, unzip_pyc};
pub use pyz::{PyzEntry, PyzTocKind, extract_pyz, extract_pyz_with_key};
pub use toc::{EntryType, TocEntry, walk_toc};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const MEI_MAGIC: &[u8; 8] = b"MEI\x0C\x0B\x0A\x0B\x0E";
