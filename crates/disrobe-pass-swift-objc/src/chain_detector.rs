#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_NATIVE_FORMAT, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use disrobe_core::provenance::Language;

use crate::macho::{MachoKind, detect_magic};
use crate::pass::{SwiftObjcReport, analyze as analyze_swift_objc};

pub const PASS_ID: PassId = "swift-objc.classify";

const TAG_MACHO_SLICE32: &str = "macho-slice-32";
const TAG_MACHO_SLICE64: &str = "macho-slice-64";
const TAG_MACHO_FAT32: &str = "macho-fat-32";
const TAG_MACHO_FAT64: &str = "macho-fat-64";

#[derive(Debug)]
pub struct SwiftObjcDetector;

impl Detector for SwiftObjcDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let kind: MachoKind = detect_magic(ctx.bytes)?;
        Some(verdict_for(kind))
    }
}

#[derive(Debug)]
pub struct SwiftObjcPassAdapter;

impl Pass for SwiftObjcPassAdapter {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &SwiftObjcDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Source {
            language: Language::Swift,
            formatted: true,
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        if detect_magic(bytes).is_none() {
            return Err(CoreError::PassFailure(
                "DR-SWOBJ-0902: swift-objc.classify: input is not a recognized Mach-O magic"
                    .to_string(),
            ));
        }
        let report: SwiftObjcReport =
            analyze_swift_objc(bytes).map_err(|e: crate::error::Error| {
                CoreError::PassFailure(format!("DR-SWOBJ-0903: swift-objc analyze: {e}"))
            })?;
        let payload: Vec<u8> =
            serde_json::to_vec_pretty(&report).map_err(|e: serde_json::Error| {
                CoreError::PassFailure(format!("DR-SWOBJ-0904: serialize report: {e}"))
            })?;
        Ok(Artifact::new(Rung::Disasm, payload, artifact.root_hash))
    }
}

pub static SWIFT_OBJC_PASS: SwiftObjcPassAdapter = SwiftObjcPassAdapter;

fn verdict_for(kind: MachoKind) -> DetectVerdict {
    let (tag, marker, confidence): (&'static str, &'static str, f32) = match kind {
        MachoKind::Fat32 => (TAG_MACHO_FAT32, "fat-magic-32", 0.95),
        MachoKind::Fat64 => (TAG_MACHO_FAT64, "fat-magic-64", 0.95),
        MachoKind::Slice32Le | MachoKind::Slice32Be => (TAG_MACHO_SLICE32, "mh-magic-32", 0.95),
        MachoKind::Slice64Le | MachoKind::Slice64Be => (TAG_MACHO_SLICE64, "mh-magic-64", 0.95),
    };
    DetectVerdict::new(
        PASS_ID,
        tag,
        FAMILY_NATIVE_FORMAT,
        confidence,
        40,
        vec![marker],
        format!("macho kind={tag}"),
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
        assert_eq!(SwiftObjcDetector.id(), PASS_ID);
    }

    #[test]
    fn detect_macho_64_le() {
        let bytes: Vec<u8> = vec![0xCF, 0xFA, 0xED, 0xFE, 0u8, 0u8, 0u8, 0u8];
        let v: DetectVerdict = SwiftObjcDetector.detect(&ctx(&bytes)).expect("must detect");
        assert!(v.format_tag.starts_with("macho-"));
    }

    #[test]
    fn detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0u8; 8];
        assert!(SwiftObjcDetector.detect(&ctx(&bytes)).is_none());
    }

    #[test]
    fn pass_output_kind_is_swift_source() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match SWIFT_OBJC_PASS.output_kind(&a) {
            OutputKind::Source {
                language,
                formatted,
            } => {
                assert_eq!(language, Language::Swift);
                assert!(formatted);
            }
            _ => panic!("expected Source"),
        }
    }

    #[test]
    fn pass_run_rejects_synthetic_macho_without_load_commands() {
        let bytes: Vec<u8> = vec![0xCF, 0xFA, 0xED, 0xFE, 0u8, 0u8, 0u8, 0u8];
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let err: CoreError = SWIFT_OBJC_PASS
            .run(&a)
            .expect_err("synthetic mach-o has no load commands");
        let msg: String = format!("{err}");
        assert!(msg.contains("DR-SWOBJ-0903") || msg.contains("DR-SWOBJ-0904"));
    }

    #[test]
    fn pass_run_rejects_unknown_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 16], [0u8; 32]);
        let err: CoreError = SWIFT_OBJC_PASS.run(&a).expect_err("must reject");
        assert!(format!("{err}").contains("DR-SWOBJ-0902"));
    }
}
