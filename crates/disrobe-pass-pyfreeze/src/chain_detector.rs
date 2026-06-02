#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    ChildHandle, DetectContext, DetectVerdict, Detector, FAMILY_PACKER_ARCHIVE, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;

use crate::common::manifest::FreezerKind;
use crate::detect::{Detection, detect_bytes};

pub const PASS_ID: PassId = "pyfreeze.extract";

const TAG_CXFREEZE: &str = "pyfreeze-cxfreeze";
const TAG_PY2EXE: &str = "pyfreeze-py2exe";
const TAG_PYOXIDIZER: &str = "pyfreeze-pyoxidizer";
const TAG_PEX: &str = "pyfreeze-pex";
const TAG_SHIV: &str = "pyfreeze-shiv";
const TAG_BRIEFCASE: &str = "pyfreeze-briefcase";

#[derive(Debug)]
pub struct PyfreezeDetector;

impl Detector for PyfreezeDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let detection: Detection = detect_bytes(ctx.bytes, None);
        verdict_for(&detection)
    }
}

#[derive(Debug)]
pub struct PyfreezePass;

impl Pass for PyfreezePass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &PyfreezeDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Mixed {
            children: Vec::new(),
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let detection: Detection = detect_bytes(bytes, None);
        if verdict_for(&detection).is_none() {
            return Err(CoreError::PassFailure(
                "DR-PYFRZ-0902: pyfreeze.extract: input is not a recognized python freezer container"
                    .to_string(),
            ));
        }
        if matches!(detection.kind, FreezerKind::Unknown) {
            return Err(CoreError::PassFailure(
                "DR-PYFRZ-0903: pyfreeze.extract: freezer kind unknown".to_string(),
            ));
        }
        Ok(Artifact::new(
            Rung::Disasm,
            bytes.to_vec(),
            artifact.root_hash,
        ))
    }
}

pub static PYFREEZE_PASS: PyfreezePass = PyfreezePass;

#[inline]
#[must_use]
pub const fn child_handles_empty() -> Vec<ChildHandle> {
    Vec::new()
}

fn verdict_for(d: &Detection) -> Option<DetectVerdict> {
    if d.confidence < 0.5 {
        return None;
    }
    let (tag, marker): (&'static str, &'static str) = match d.kind {
        FreezerKind::CxFreeze => (TAG_CXFREEZE, "cxfreeze-layout"),
        FreezerKind::Py2exe => (TAG_PY2EXE, "PYTHONSCRIPT-resource"),
        FreezerKind::PyOxidizer => (TAG_PYOXIDIZER, "pyoxidizer-symbol"),
        FreezerKind::Pex => (TAG_PEX, "PEX-INFO-marker"),
        FreezerKind::Shiv => (TAG_SHIV, "_bootstrap-marker"),
        FreezerKind::Briefcase => (TAG_BRIEFCASE, "briefcase-layout"),
        FreezerKind::Unknown => return None,
    };
    Some(DetectVerdict::new(
        PASS_ID,
        tag,
        FAMILY_PACKER_ARCHIVE,
        d.confidence,
        22,
        vec![marker],
        format!("pyfreeze kind={tag}"),
    ))
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
        assert_eq!(PyfreezeDetector.id(), PASS_ID);
    }

    #[test]
    fn detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0u8; 32];
        assert!(PyfreezeDetector.detect(&ctx(&bytes)).is_none());
    }

    #[test]
    fn pass_output_kind_is_mixed() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match PYFREEZE_PASS.output_kind(&a) {
            OutputKind::Mixed { children } => assert!(children.is_empty()),
            _ => panic!("expected Mixed"),
        }
    }

    #[test]
    fn pass_run_rejects_random_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 16], [0u8; 32]);
        let err: CoreError = PYFREEZE_PASS.run(&a).expect_err("must reject");
        let msg: String = format!("{err}");
        assert!(msg.contains("DR-PYFRZ-0902") || msg.contains("DR-PYFRZ-0903"));
    }
}
