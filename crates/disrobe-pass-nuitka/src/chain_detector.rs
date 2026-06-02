#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_PACKER_ARCHIVE, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;

use crate::detect::{Detection, NuitkaFlavor, detect_in_bytes};
use crate::extract::{VariantExtraction, extract_variant};

pub const PASS_ID: PassId = "nuitka.extract";

const TAG_STANDALONE: &str = "nuitka-standalone";
const TAG_ONEFILE_UNCOMPRESSED: &str = "nuitka-onefile-uncompressed";
const TAG_ONEFILE_ZSTD: &str = "nuitka-onefile-zstd";
const TAG_WHEEL: &str = "nuitka-wheel";

#[derive(Debug)]
pub struct NuitkaDetector;

impl Detector for NuitkaDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let detection: Detection = detect_in_bytes(ctx.bytes).ok()?;
        Some(verdict_for(&detection))
    }
}

#[derive(Debug)]
pub struct NuitkaPass;

impl Pass for NuitkaPass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &NuitkaDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Mixed {
            children: Vec::new(),
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let extraction: VariantExtraction =
            extract_variant(bytes).map_err(|e: crate::error::Error| {
                CoreError::PassFailure(format!("DR-NUITKA-0902: nuitka extract: {e}"))
            })?;
        let body: Vec<u8> =
            serde_json::to_vec_pretty(&extraction).map_err(|e: serde_json::Error| {
                CoreError::PassFailure(format!("DR-NUITKA-0903: nuitka serialize: {e}"))
            })?;
        Ok(Artifact::new(Rung::Disasm, body, artifact.root_hash))
    }
}

pub static NUITKA_PASS: NuitkaPass = NuitkaPass;

fn verdict_for(d: &Detection) -> DetectVerdict {
    let (tag, marker, confidence): (&'static str, &'static str, f32) = match d.flavor {
        NuitkaFlavor::Standalone => (TAG_STANDALONE, "nuitka_module_loader", 0.92),
        NuitkaFlavor::OnefileUncompressed => (TAG_ONEFILE_UNCOMPRESSED, "KA-onefile", 0.95),
        NuitkaFlavor::OnefileZstd => (TAG_ONEFILE_ZSTD, "KA-onefile-zstd", 0.95),
        NuitkaFlavor::Wheel => (TAG_WHEEL, "dist-info-WHEEL", 0.88),
    };
    DetectVerdict::new(
        PASS_ID,
        tag,
        FAMILY_PACKER_ARCHIVE,
        confidence,
        20,
        vec![marker],
        format!("nuitka flavor={tag} hits={n}", n = d.hits.len()),
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
        assert_eq!(NuitkaDetector.id(), PASS_ID);
    }

    #[test]
    fn detect_standalone_signature() {
        let mut bytes: Vec<u8> = Vec::with_capacity(256);
        bytes.extend_from_slice(b"prefix\x00");
        bytes.extend_from_slice(b"nuitka_module_loader");
        bytes.extend_from_slice(b"\x00__compiled__\x00suffix");
        let v: DetectVerdict = NuitkaDetector.detect(&ctx(&bytes)).expect("must detect");
        assert!(v.format_tag.starts_with("nuitka-"));
        assert_eq!(v.specificity, 20);
    }

    #[test]
    fn detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0u8; 64];
        assert!(NuitkaDetector.detect(&ctx(&bytes)).is_none());
    }

    #[test]
    fn pass_output_kind_is_mixed() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match NUITKA_PASS.output_kind(&a) {
            OutputKind::Mixed { children } => assert!(children.is_empty()),
            _ => panic!("expected Mixed"),
        }
    }

    #[test]
    fn pass_run_rejects_non_nuitka_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 16], [0u8; 32]);
        let err: CoreError = NUITKA_PASS.run(&a).expect_err("must reject");
        assert!(format!("{err}").contains("DR-NUITKA-0902"));
    }
}
