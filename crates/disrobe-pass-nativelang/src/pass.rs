use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};
use disrobe_ir::{Envelope, decode_raw};
use disrobe_nir::NirModule;
use serde::{Deserialize, Serialize};

use crate::disasm::DisasmListing;
use crate::dwarf::DwarfAggregate;
use crate::dwarf_types::{ReconstructedTypeReport, SourceGrade};
use crate::functions::RecoveredFunction;
use crate::{NativeLangAnalysis, analyze};

pub const PASS_INPUT_PATH_CAP: &str = "raw.nativelang";

#[derive(Debug, Default, Clone, Copy)]
pub struct NativeLangPass;

impl LegacyPass for NativeLangPass {
    const CONSUMES: &'static [Rung] = &[Rung::Raw];
    const EMITS: &'static [Rung] = &[Rung::Surface];
    const REQUIRES: &'static [fn() -> Capability] =
        &[|| Capability::requires(PASS_INPUT_PATH_CAP, 1)];
    const PRODUCES: &'static [fn() -> Capability] =
        &[|| Capability::produces("nativelang.image-analyzed", 1)];

    fn id(&self) -> PassId {
        "disrobe-pass-nativelang"
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let input: PassInput = decode_pass_input(&artifact.envelope);
        let analysis: NativeLangAnalysis = analyze(&input.bytes)
            .map_err(|e| CoreError::PassFailure(format!("DR-NATIVELANG-PASS: {e}")))?;
        let report: NativeLangPassReport = NativeLangPassReport {
            source_path: input.source_path,
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
            user_module_count: u32::try_from(analysis.recovery.user_modules.len())
                .unwrap_or(u32::MAX),
            std_symbol_count: u32::try_from(analysis.recovery.std_symbol_count).unwrap_or(u32::MAX),
            gc_kind: analysis.recovery.gc.gc_kind,
            dwarf_present: analysis.dwarf.present,
            dwarf_function_count: u32::try_from(analysis.dwarf.functions.len()).unwrap_or(u32::MAX),
            dwarf_aggregate_count: u32::try_from(analysis.dwarf.aggregates.len())
                .unwrap_or(u32::MAX),
            aggregates: analysis.dwarf.aggregates.clone(),
            recovered_function_count: u32::try_from(analysis.function_recovery.functions.len())
                .unwrap_or(u32::MAX),
            functions_from_symbol_table: u32::try_from(
                analysis.function_recovery.from_symbol_table,
            )
            .unwrap_or(u32::MAX),
            functions_from_dwarf: u32::try_from(analysis.function_recovery.from_dwarf)
                .unwrap_or(u32::MAX),
            functions_from_traversal: u32::try_from(analysis.function_recovery.from_traversal)
                .unwrap_or(u32::MAX),
            functions_from_relocatable: u32::try_from(analysis.function_recovery.from_relocatable)
                .unwrap_or(u32::MAX),
            unresolved_target_count: u32::try_from(
                analysis.function_recovery.unresolved_targets.len(),
            )
            .unwrap_or(u32::MAX),
            functions: analysis.function_recovery.functions,
        };
        let payload: Vec<u8> = serde_json::to_vec(&report)
            .map_err(|e| CoreError::PassFailure(format!("DR-NATIVELANG-PASS: serialize: {e}")))?;
        let mut next: Artifact = Artifact::new(Rung::Surface, payload, artifact.root_hash);
        for producer in <Self as LegacyPass>::PRODUCES {
            next.add_capability(producer());
        }
        Ok(next)
    }
}

#[derive(Debug, Clone)]
pub struct PassInput {
    pub source_path: String,
    pub bytes: Vec<u8>,
}

#[must_use]
pub fn decode_pass_input(envelope_bytes: &[u8]) -> PassInput {
    if let Ok(envelope) = Envelope::decode(envelope_bytes)
        && let Ok(raw) = decode_raw(&envelope.hot)
    {
        return PassInput {
            source_path: raw.source_path,
            bytes: raw.source_bytes,
        };
    }
    if let Ok(raw) = decode_raw(envelope_bytes) {
        return PassInput {
            source_path: raw.source_path,
            bytes: raw.source_bytes,
        };
    }
    PassInput {
        source_path: "<artifact>".to_owned(),
        bytes: envelope_bytes.to_vec(),
    }
}

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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use disrobe_core::PassMetadata;
    use disrobe_ir::{Envelope, RawPayload, encode_raw};

    use super::*;

    fn synth_envelope(source_path: &str, body: &[u8]) -> Vec<u8> {
        let raw: RawPayload = RawPayload {
            source_path: source_path.to_owned(),
            source_bytes: body.to_vec(),
            source_hash: [0u8; 32],
            detected_format: None,
        };
        let hot: Vec<u8> = encode_raw(&raw).expect("encode raw");
        Envelope::new(Rung::Raw, hot, vec![])
            .encode()
            .expect("encode envelope")
    }

    #[test]
    fn pass_metadata_advertises_capabilities() {
        let p: NativeLangPass = NativeLangPass;
        assert_eq!(PassMetadata::id(&p), "disrobe-pass-nativelang");
        assert_eq!(p.consumes(), &[Rung::Raw]);
        assert_eq!(p.emits(), &[Rung::Surface]);
        assert_eq!(p.required_capabilities().len(), 1);
        assert_eq!(p.produced_capabilities().len(), 1);
    }

    #[test]
    fn pass_run_rejects_unrecognized_input() {
        let bytes: Vec<u8> = synth_envelope("junk.bin", &[0u8; 128]);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let err: CoreError = NativeLangPass.run(&input).expect_err("must reject");
        assert!(format!("{err}").contains("DR-NATIVELANG-PASS"));
    }
}
