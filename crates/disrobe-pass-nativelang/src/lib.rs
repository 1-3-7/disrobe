#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
#![deny(missing_debug_implementations)]
#![allow(clippy::redundant_pub_crate)]
pub mod bodies;
#[cfg(feature = "chain")]
pub mod chain_detector;
pub(crate) mod d_mangle;
pub(crate) mod debug;
pub mod demangle;
pub mod detect;
pub mod disasm;
pub mod dwarf;
pub mod dwarf_types;
pub mod error;
pub mod functions;
pub mod image;
pub mod nir;
pub mod pass;
pub mod recover;

use disrobe_nir::NirModule;
use serde::{Deserialize, Serialize};

pub use bodies::{
    BodyAbi, BodyRecovery, BodyRejection, BodySkip, BodyStatus, FunctionBody, RuntimeRole,
    RustBody, recover_bodies,
};
#[cfg(feature = "chain")]
pub use chain_detector::{NATIVELANG_PASS, NativeLangDetector, NativeLangPassAdapter};
pub use demangle::{DemangledSymbol, demangle_crystal, demangle_d, demangle_nim, demangle_zig};
pub use detect::{LangFingerprint, NativeLang, fingerprint};
pub use disasm::{DisasmInstruction, DisasmListing, FunctionListing, disassemble_functions};
pub use dwarf::{
    AggregateKind, DwarfAggregate, DwarfFunction, DwarfMember, DwarfReport, recover_dwarf,
};
pub use dwarf_types::{
    ReconstructedMember, ReconstructedTypeReport, SourceGrade, TypeReport, recover_types,
};
pub use error::{Error, Result};
pub use functions::{
    BoundaryConfidence, EndBasis, FunctionExtent, FunctionOrigin, FunctionRecovery, LineRange,
    RecoveredFunction, recover_functions,
};
pub use image::{CodeArch, FuncSymbol, ImageKind, NativeImage, Section};
pub use nir::lift_native_nir;
pub use pass::{NativeLangPassReport, build_report};
pub use recover::{GcMetadata, Recovery, module_histogram, recover};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[must_use]
pub const fn version() -> &'static str {
    VERSION
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NativeLangAnalysis {
    pub image_kind: ImageKind,
    pub arch: CodeArch,
    pub ptr_size: u8,
    pub fingerprint: LangFingerprint,
    pub recovery: Recovery,
    pub dwarf: DwarfReport,
    pub types: TypeReport,
    pub function_recovery: FunctionRecovery,
    pub disasm: DisasmListing,
    pub bodies: BodyRecovery,
    pub nir: NirModule,
}

pub fn analyze(bytes: &[u8]) -> Result<NativeLangAnalysis> {
    debug::dbg_section("nativelang analyze");
    debug::dbg_kv("input-bytes", || bytes.len().to_string());
    let image: NativeImage<'_> = NativeImage::parse(bytes)?;
    debug::dbg_kv("image-kind", || format!("{:?}", image.kind));
    debug::dbg_kv("arch", || format!("{:?}", image.arch));
    debug::dbg_kv("ptr-size", || image.ptr_size.to_string());
    debug::dbg_kv("entry", || format!("{:#x}", image.entry));
    debug::dbg_kv("sections", || image.sections.len().to_string());
    debug::dbg_kv("symbols", || image.symbols.len().to_string());
    debug::dbg_kv("func-symbols", || image.func_symbols.len().to_string());
    let fp: LangFingerprint = fingerprint(&image).ok_or(Error::NoLanguageFingerprint)?;
    debug::dbg_kv("fingerprint", || {
        format!("{} confidence={:.3}", fp.lang.label(), fp.confidence)
    });
    debug::dbg_kv("fingerprint-markers", || fp.markers.join(","));
    let types: TypeReport = recover_types(bytes, image.has_symbol_table());
    let recovery: Recovery = recover(&image, fp.lang, &types);
    let dwarf: DwarfReport = recover_dwarf(&image);
    debug::dbg_kv("dwarf", || {
        format!(
            "present={} version={:?} units={} functions={} aggregates={}",
            dwarf.present,
            dwarf.dwarf_version,
            dwarf.compile_units,
            dwarf.functions.len(),
            dwarf.aggregates.len()
        )
    });
    let function_recovery: FunctionRecovery = recover_functions(&image, fp.lang, &dwarf);
    let disasm: DisasmListing = disassemble_functions(&image, &function_recovery.functions);
    let bodies: BodyRecovery = recover_bodies(&image, fp.lang, &function_recovery.functions);
    debug::dbg_kv("bodies", || {
        format!(
            "arch-supported={} recovered={} elided={} rejected={} not-attempted={} \
             retained-source-bytes={}",
            bodies.arch_supported,
            bodies.recovered,
            bodies.recovered_elided,
            bodies.rejected,
            bodies.not_attempted,
            bodies.retained_source_bytes
        )
    });
    let nir: NirModule = lift_native_nir(bytes, image.arch, &function_recovery, &disasm);
    debug::dbg_kv("function-recovery", || {
        format!(
            "total={} symtab={} dwarf={} traversal={} relocatable={} unresolved={}",
            function_recovery.functions.len(),
            function_recovery.from_symbol_table,
            function_recovery.from_dwarf,
            function_recovery.from_traversal,
            function_recovery.from_relocatable,
            function_recovery.unresolved_targets.len()
        )
    });
    debug::dbg_kv("nir", || {
        format!(
            "functions={} symbols={}",
            nir.functions.len(),
            nir.symbols.len()
        )
    });
    Ok(NativeLangAnalysis {
        image_kind: image.kind,
        arch: image.arch,
        ptr_size: image.ptr_size,
        fingerprint: fp,
        recovery,
        dwarf,
        types,
        function_recovery,
        disasm,
        bodies,
        nir,
    })
}
