#![forbid(unsafe_code)]
#![allow(clippy::redundant_pub_crate)]

mod buildinfo;
#[cfg(feature = "chain")]
pub mod chain_detector;
mod detect;
mod error;
mod extract;
mod manifest;
mod markers;
mod onefile;
mod plugin;
mod provenance_header;
mod reassembly;
mod signed;
mod symbols;
pub(crate) mod util;
mod variant;

pub use buildinfo::{BuildInfo, BuildInfoFlag, scan_build_info};
pub use detect::{
    Detection, NuitkaFlavor, NuitkaVersion, WheelMarker, detect_in_bytes, detect_in_file,
};
pub use error::{Error, Result};
pub use extract::{
    ModuleSurface, OnefileExtraction, SignedPeExtraction, StandaloneSurface, VariantExtraction,
    extract_for_classification, extract_variant,
};
pub use manifest::{NuitkaVariantManifest, build_manifest, build_manifest_from_file};
pub use markers::{CSourceMarker, DecompReadyMarkers, NuitkaEraGuess, scan_c_source_markers};
pub use onefile::{OnefileEntry, OnefilePayload, extract_onefile};
pub use plugin::{NuitkaPlugin, PluginConfidence, PluginHit, PluginScan, scan_plugins};
pub use provenance_header::{
    c_disasm_header, python_extracted_header, render_c_disasm_with_header,
};
pub use reassembly::{
    EntryRole, ReassembledTree, ReassemblyPlan, ReassemblyStats, plan_reassembly,
};
pub use signed::{
    AuthenticodeSummary, CertificateRevision, CertificateType, detect_authenticode,
    strip_authenticode,
};
pub use symbols::{ImpFunction, ModuleInit, SymbolGraph, scan_symbols};
pub use variant::{BinaryFormat, NuitkaVariant, VariantClassification, classify, classify_in_file};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
