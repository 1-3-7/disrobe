#![forbid(unsafe_code)]
#![allow(clippy::redundant_pub_crate)]

mod body;
mod buildinfo;
mod c_module;
#[cfg(feature = "chain")]
pub mod chain_detector;
mod const_manifest;
mod constants;
mod decompile;
mod demangle;
mod detect;
mod error;
mod extract;
mod manifest;
mod markers;
mod onefile;
mod onefile_locator;
mod plugin;
mod provenance_header;
mod reassembly;
mod signed;
mod surface;
mod symbols;
pub(crate) mod util;
mod variant;
mod version_db;

pub use body::{
    BinOpKind, CmpOpKind, LiftFidelity, PythonExpr, PythonStmt, extract_impl_body_text, lift_body,
};
pub use buildinfo::{BuildInfo, BuildInfoFlag, scan_build_info};
pub use c_module::{CCodeObject, CFunctionWiring, CImplBody, CModuleStructure, parse_c_module};
pub use const_manifest::{
    ConstantBlobEntry, ConstantManifest, parse_constant_manifest, parse_constant_manifest_from_file,
};
pub use constants::{
    ConstantEntry, ConstantProvenance, ConstantsPool, ConstantsTable, decode_build_constants,
    decode_const_file,
};
pub use decompile::{
    DecompSourceKind, NuitkaDecompilation, decompile_binary, decompile_build_dir,
    decompile_const_bytes,
};
pub use demangle::{DemangledFunction, NuitkaSymbolKind, demangle_function};
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
pub use onefile::{FilenameEncoding, OnefileEntry, OnefilePayload, extract_onefile};
pub use onefile_locator::{LocatedOnefile, locate_onefile_payload};
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
pub use surface::{
    SurfaceFidelity, SurfaceFunction, SurfaceModule, SurfaceParam, build_surface,
    build_surface_names_only, emit_python,
};
pub use symbols::{ImpFunction, ModuleInit, SymbolGraph, scan_symbols};
pub use variant::{BinaryFormat, NuitkaVariant, VariantClassification, classify, classify_in_file};
pub use version_db::{
    ExactNuitkaVersion, NuitkaVersionReport, VersionConfidence, detect_nuitka_version,
    parse_exact_version_from_constants_c,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
