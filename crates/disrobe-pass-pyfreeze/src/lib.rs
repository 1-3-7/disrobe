#![forbid(unsafe_code)]

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod briefcase;
#[cfg(feature = "chain")]
pub mod chain_detector;
pub mod common;
pub mod cxfreeze;
pub mod detect;
pub mod error;
pub mod pass;
pub mod pex;
pub mod provenance_header;
pub mod py2exe;
pub mod pyoxidizer;
pub mod shiv;

pub use common::manifest::{EntryKind, EntryOrigin, EntryRecord, FreezerKind, FreezerManifest};
pub use common::quota::{ExtractionQuota, QuotaGuard, QuotaReport};
pub use detect::{Detection, detect_bytes};
pub use error::{Error, Result};
pub use pass::{PyfreezeOutput, detect, extract};
pub use provenance_header::{
    python_extracted_header, python_unpacked_header, render_extracted_with_header,
};
