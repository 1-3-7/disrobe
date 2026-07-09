use disrobe_nir::NirModule;
use serde::{Deserialize, Serialize};

use crate::NativeLangAnalysis;
use crate::disasm::DisasmListing;
use crate::dwarf::DwarfAggregate;
use crate::dwarf_types::{ReconstructedTypeReport, SourceGrade};
use crate::functions::RecoveredFunction;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NativeLangPassReport {
    pub source_path: String,
    pub image_kind: String,
    pub ptr_size: u8,
    pub lang: String,
    pub confidence: f32,
    pub source_recoverable: bool,
    pub source_grade: SourceGrade,
    pub reconstructed_type_count: u32,
    pub reconstructed_named_type_count: u32,
    pub line_coverage_pct: f64,
    pub reconstructed_types: Vec<ReconstructedTypeReport>,
    pub disasm_arch_supported: bool,
    pub disassembled_function_count: u32,
    pub nir_function_count: u32,
    pub nir_symbol_count: u32,
    pub disasm: DisasmListing,
    pub nir: NirModule,
    pub demangled_count: u32,
    pub user_module_count: u32,
    pub std_symbol_count: u32,
    pub gc_kind: Option<String>,
    pub dwarf_present: bool,
    pub dwarf_function_count: u32,
    pub dwarf_aggregate_count: u32,
    pub aggregates: Vec<DwarfAggregate>,
    pub recovered_function_count: u32,
    pub functions_from_symbol_table: u32,
    pub functions_from_dwarf: u32,
    pub functions_from_traversal: u32,
    pub functions_from_relocatable: u32,
    pub unresolved_target_count: u32,
    pub functions: Vec<RecoveredFunction>,
}

#[must_use]
pub fn build_report(source_path: String, analysis: NativeLangAnalysis) -> NativeLangPassReport {
    NativeLangPassReport {
        source_path,
        image_kind: format!("{:?}", analysis.image_kind),
        ptr_size: analysis.ptr_size,
        lang: analysis.fingerprint.lang.label().to_owned(),
        confidence: analysis.fingerprint.confidence,
        source_recoverable: analysis.recovery.source_recoverable,
        source_grade: analysis.recovery.source_grade,
        reconstructed_type_count: u32::try_from(analysis.types.types.len()).unwrap_or(u32::MAX),
        reconstructed_named_type_count: analysis.types.named_type_count,
        line_coverage_pct: analysis.types.line_coverage_pct,
        disasm_arch_supported: analysis.disasm.arch_supported,
        disassembled_function_count: u32::try_from(analysis.disasm.listings.len())
            .unwrap_or(u32::MAX),
        nir_function_count: u32::try_from(analysis.nir.functions.len()).unwrap_or(u32::MAX),
        nir_symbol_count: u32::try_from(analysis.nir.symbols.len()).unwrap_or(u32::MAX),
        reconstructed_types: analysis.types.types,
        disasm: analysis.disasm,
        nir: analysis.nir,
        demangled_count: u32::try_from(analysis.recovery.demangled.len()).unwrap_or(u32::MAX),
        user_module_count: u32::try_from(analysis.recovery.user_modules.len()).unwrap_or(u32::MAX),
        std_symbol_count: u32::try_from(analysis.recovery.std_symbol_count).unwrap_or(u32::MAX),
        gc_kind: analysis.recovery.gc.gc_kind,
        dwarf_present: analysis.dwarf.present,
        dwarf_function_count: u32::try_from(analysis.dwarf.functions.len()).unwrap_or(u32::MAX),
        dwarf_aggregate_count: u32::try_from(analysis.dwarf.aggregates.len()).unwrap_or(u32::MAX),
        aggregates: analysis.dwarf.aggregates.clone(),
        recovered_function_count: u32::try_from(analysis.function_recovery.functions.len())
            .unwrap_or(u32::MAX),
        functions_from_symbol_table: u32::try_from(analysis.function_recovery.from_symbol_table)
            .unwrap_or(u32::MAX),
        functions_from_dwarf: u32::try_from(analysis.function_recovery.from_dwarf)
            .unwrap_or(u32::MAX),
        functions_from_traversal: u32::try_from(analysis.function_recovery.from_traversal)
            .unwrap_or(u32::MAX),
        functions_from_relocatable: u32::try_from(analysis.function_recovery.from_relocatable)
            .unwrap_or(u32::MAX),
        unresolved_target_count: u32::try_from(analysis.function_recovery.unresolved_targets.len())
            .unwrap_or(u32::MAX),
        functions: analysis.function_recovery.functions,
    }
}
