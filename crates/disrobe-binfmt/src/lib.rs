#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
#![allow(clippy::redundant_pub_crate)]
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod asar;
pub mod carve;
#[cfg(feature = "chain")]
pub mod chain_detector;
pub mod classify;
pub mod container;
pub mod containers;
pub(crate) mod debug;
pub mod elf_dynamic;
pub mod error;
pub mod external_wrap;
pub mod extract;
pub mod native;
pub mod native_graph;
pub mod native_image;
mod ne;
pub mod quota;
pub use disrobe_core::structural;

pub use carve::{
    CarveConfig, CarveNode, CarveReport, CarvedChunk, ChunkClass, DEFAULT_MAX_DEPTH,
    carve_recursive, is_skip_magic, skip_magic_label,
};
pub use classify::{
    Action, Confidence, InputClassification, Lang, NativeFormat, NativeLangHint, ObfuscatorFamily,
    classify_input, native_lang_fingerprint,
};
pub use container::{ContainerKind, detect_container, detect_container_with_hint};
pub use elf_dynamic::{ElfDynamic, parse_elf_dynamic};
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
pub use native_graph::{ImportGraph, import_graph_dot};
pub use native_image::{NativeImage, NativeImageSection, parse_native_image};
pub use quota::{
    ExtractionQuota, QuotaGuard, QuotaReport, prepare_entry_dir, prepare_entry_path,
    sanitize_entry_path,
};
pub use structural::{StructuralFormat, identify_by_structure, locate_pe_header};
