#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_INTERPRETER_BYTECODE, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use disrobe_core::provenance::Language;

use crate::pass::{PassSummary, analyze};
use crate::pe::{DataDirectory, PeImage, parse as parse_pe};

pub const PASS_ID: PassId = "dotnet.classify";

const TAG_PE_CLR: &str = "dotnet-pe-clr";

#[derive(Debug)]
pub struct DotnetDetector;

impl Detector for DotnetDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let bytes: &[u8] = ctx.bytes;
        if bytes.len() < 64 || &bytes[..2] != b"MZ" {
            return None;
        }
        let pe: PeImage = parse_pe(bytes).ok()?;
        let dir: DataDirectory = pe.clr_directory()?;
        if dir.rva == 0 || dir.size == 0 {
            return None;
        }
        Some(verdict_clr(dir))
    }
}

#[derive(Debug)]
pub struct DotnetPass;

impl Pass for DotnetPass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &DotnetDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Source {
            language: Language::CSharp,
            formatted: true,
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let pe: PeImage = parse_pe(bytes).map_err(|e: crate::error::Error| {
            CoreError::PassFailure(format!("DR-DOTNET-0902: PE parse: {e}"))
        })?;
        let clr: DataDirectory = pe.clr_directory().ok_or_else(|| {
            CoreError::PassFailure(
                "DR-DOTNET-0903: dotnet.classify: PE has no CLR data directory".to_string(),
            )
        })?;
        if clr.rva == 0 || clr.size == 0 {
            return Err(CoreError::PassFailure(
                "DR-DOTNET-0904: dotnet.classify: empty CLR data directory".to_string(),
            ));
        }
        let summary: PassSummary = analyze(bytes).map_err(|e: crate::error::Error| {
            CoreError::PassFailure(format!("DR-DOTNET-0905: dotnet analyze: {e}"))
        })?;
        let payload: Vec<u8> =
            serde_json::to_vec_pretty(&summary).map_err(|e: serde_json::Error| {
                CoreError::PassFailure(format!("DR-DOTNET-0906: serialize summary: {e}"))
            })?;
        Ok(Artifact::new(Rung::Disasm, payload, artifact.root_hash))
    }
}

pub static DOTNET_PASS: DotnetPass = DotnetPass;

fn verdict_clr(dir: DataDirectory) -> DetectVerdict {
    DetectVerdict::new(
        PASS_ID,
        TAG_PE_CLR,
        FAMILY_INTERPRETER_BYTECODE,
        0.95,
        25,
        vec!["PE+CLR-data-directory"],
        format!(
            "PE with CLR header rva={rva:#x} size={sz}",
            rva = dir.rva,
            sz = dir.size,
        ),
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use disrobe_core::Rung;

    fn ctx(bytes: &[u8]) -> DetectContext<'_> {
        DetectContext {
            bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        }
    }

    #[test]
    fn detector_id_is_stable() {
        assert_eq!(DotnetDetector.id(), PASS_ID);
    }

    #[test]
    fn detect_misses_non_pe() {
        let bytes: Vec<u8> = vec![0u8; 256];
        assert!(DotnetDetector.detect(&ctx(&bytes)).is_none());
    }

    #[test]
    fn detect_misses_pe_without_clr() {
        let mut bytes: Vec<u8> = vec![0u8; 1024];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        assert!(DotnetDetector.detect(&ctx(&bytes)).is_none());
    }

    #[test]
    fn pass_output_kind_is_csharp_source() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match DOTNET_PASS.output_kind(&a) {
            OutputKind::Source {
                language,
                formatted,
            } => {
                assert_eq!(language, Language::CSharp);
                assert!(formatted);
            }
            _ => panic!("expected Source"),
        }
    }

    #[test]
    fn pass_run_rejects_non_pe() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 16], [0u8; 32]);
        let err: CoreError = DOTNET_PASS.run(&a).expect_err("must reject");
        let msg: String = format!("{err}");
        assert!(msg.contains("DR-DOTNET-0902") || msg.contains("DR-DOTNET-0903"));
    }
}
