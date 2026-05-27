#![forbid(unsafe_code)]

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod asar;
#[cfg(feature = "chain")]
pub mod chain_detector;
pub mod classify;
pub mod container;
pub mod containers;
pub mod error;
pub mod external_wrap;
pub mod extract;
pub mod native;
pub mod quota;

pub use classify::{
    Action, Confidence, InputClassification, Lang, NativeFormat, ObfuscatorFamily, classify_input,
};
pub use container::{ContainerKind, detect_container, detect_container_with_hint};
pub use error::{Error, Result};
pub use external_wrap::{
    ExternalTool, ProbeResult, ToolOverrides, clear_overrides, extract_via_tool,
    probe_external_tools, set_overrides, wrap_external_extract,
};
pub use extract::{
    EntryCompression, ExtractedEntry, ExtractionResult, QuotaSummary, detect_and_extract_with_hint,
    extract_to, extract_to_with_quota,
};
pub use native::{
    Arch, Endian, ExportInfo, ImportInfo, NativeFile, NativeFormat as ParsedNativeFormat,
    SectionInfo, SegmentInfo, SymbolInfo, SymbolRole, parse_native,
};
pub use quota::{ExtractionQuota, QuotaGuard, QuotaReport, sanitize_entry_path};
