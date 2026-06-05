use serde::{Deserialize, Serialize};

use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};

use crate::aot::{AotReport, detect as detect_aot};
use crate::cil;
use crate::metadata::{MetadataRoot, RuntimeLabel, parse_metadata_root};
use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use crate::peel::{ConfuserConstantsRecovery, peel_confuserex_constants};
use crate::protectors::{DetectionReport, Protector, detect_all};
use crate::r2r::{R2rReport, detect as detect_r2r};

pub const PASS_INPUT_PE_CAP: &str = "raw.pe";

#[derive(Debug, Default, Clone, Copy)]
pub struct DotnetPass;

impl LegacyPass for DotnetPass {
    const CONSUMES: &'static [Rung] = &[Rung::Raw];
    const EMITS: &'static [Rung] = &[Rung::Disasm];
    const REQUIRES: &'static [fn() -> Capability] =
        &[|| Capability::requires(PASS_INPUT_PE_CAP, 1)];
    const PRODUCES: &'static [fn() -> Capability] = &[
        || Capability::produces("dotnet.pe.parsed", 1),
        || Capability::produces("dotnet.metadata.parsed", 1),
        || Capability::produces("disasm.cil", 1),
        || Capability::produces("dotnet.protector.detected", 1),
    ];

    fn id(&self) -> PassId {
        "disrobe-pass-dotnet"
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let summary: PassSummary = analyze(&artifact.envelope)
            .map_err(|e: crate::error::Error| CoreError::PassFailure(format!("{e}")))?;
        let payload: Vec<u8> = serde_json::to_vec(&summary).map_err(|e: serde_json::Error| {
            CoreError::PassFailure(format!("DR-DOTNET-SER: {e}"))
        })?;
        let mut next: Artifact = Artifact::new(Rung::Disasm, payload, artifact.root_hash);
        for producer in <Self as LegacyPass>::PRODUCES {
            next.add_capability(producer());
        }
        Ok(next)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassSummary {
    pub pe_bitness: String,
    pub machine: u16,
    pub clr_runtime_version: String,
    pub runtime_label: RuntimeLabel,
    pub stream_names: Vec<String>,
    pub r2r_present: bool,
    pub native_aot: bool,
    pub primary_protector: Option<Protector>,
    pub protectors_detected: Vec<Protector>,
    pub opcode_table_size: u32,
    pub opcode_spec_coverage_pct: u32,
    pub recovered_constants: Vec<String>,
}

pub fn analyze(image: &[u8]) -> crate::error::Result<PassSummary> {
    let pe: PeImage = parse(image)?;
    let clr: ClrHeader = parse_clr_header(image, &pe)?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr)?;
    let runtime: RuntimeLabel = root.runtime_label();
    let r2r: R2rReport = detect_r2r(image, &pe, &clr);
    let aot: AotReport = detect_aot(image);
    let detection: DetectionReport = detect_all(image);
    let stream_names: Vec<String> = root.streams.keys().cloned().collect();
    let mut protectors: Vec<Protector> = detection.matches.keys().copied().collect();
    protectors.sort();
    let recovered_constants: Vec<String> = peel_confuserex_constants(image)
        .ok()
        .flatten()
        .map(|r: ConfuserConstantsRecovery| {
            r.strings_recovered
                .into_iter()
                .map(|s: crate::peel::RecoveredString| s.text)
                .collect()
        })
        .unwrap_or_default();
    Ok(PassSummary {
        pe_bitness: format!("{:?}", pe.bitness),
        machine: pe.machine,
        clr_runtime_version: root.version,
        runtime_label: runtime,
        stream_names,
        r2r_present: r2r.present,
        native_aot: aot.is_native_aot,
        primary_protector: detection.primary,
        protectors_detected: protectors,
        opcode_table_size: u32::try_from(cil::total_opcode_count()).unwrap_or(u32::MAX),
        opcode_spec_coverage_pct: cil::coverage_percent(),
        recovered_constants,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use disrobe_core::PassMetadata;

    use super::*;

    #[test]
    fn dotnet_pass_metadata_advertises_capabilities() {
        let p: DotnetPass = DotnetPass;
        assert_eq!(PassMetadata::id(&p), "disrobe-pass-dotnet");
        assert_eq!(p.consumes(), &[Rung::Raw]);
        assert_eq!(p.emits(), &[Rung::Disasm]);
        assert_eq!(p.required_capabilities().len(), 1);
        assert_eq!(p.produced_capabilities().len(), 4);
    }

    #[test]
    fn dotnet_pass_run_on_garbage_returns_pass_failure() {
        let artifact: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            vec![0u8; 64],
            [Capability::produces(PASS_INPUT_PE_CAP, 1)],
            [0u8; 32],
        );
        let err: CoreError = DotnetPass.run(&artifact).expect_err("garbage should fail");
        let text: String = format!("{err}");
        assert!(text.contains("DR-DOTNET"), "got: {text}");
    }
}
