#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]
use std::collections::BTreeMap;

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_INTERPRETER_BYTECODE, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use disrobe_core::provenance::Language;

use crate::disasm::{Disassembly, disassemble};
use crate::polyglot::looks_like_pickle;
use crate::reconstruct::{Reconstruction, needs_memo_table, reconstruct};
use crate::vm::{PickleValue, VmTrace, execute_full};

pub const PASS_ID: PassId = "pickle.classify";

const TAG_PICKLE: &str = "python-pickle";

#[derive(Debug)]
pub struct PickleDetector;

impl Detector for PickleDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let bytes: &[u8] = ctx.bytes;
        if bytes.len() >= 2 && bytes[0] == 0x80 && bytes[1] <= crate::opcode::max_proto() {
            return Some(verdict(0.98, 35, "proto-2+ \\x80 opener"));
        }
        if looks_like_pickle(bytes) && disassemble(bytes).is_ok() {
            return Some(verdict(0.82, 25, "proto-0/1 opcode + STOP heuristic"));
        }
        None
    }
}

#[derive(Debug)]
pub struct PicklePass;

impl Pass for PicklePass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &PickleDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Source {
            language: Language::Python,
            formatted: false,
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let ctx: DetectContext<'_> = DetectContext {
            bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        if PickleDetector.detect(&ctx).is_none() {
            return Err(CoreError::PassFailure(
                "DR-PICKLE-0901: pickle.classify: input is not a recognizable pickle stream"
                    .to_string(),
            ));
        }
        let dis: Disassembly = disassemble(bytes).map_err(|e: crate::error::Error| {
            CoreError::PassFailure(format!("DR-PICKLE-0903: pickle disasm: {e}"))
        })?;
        let (trace, memo): (VmTrace, BTreeMap<u64, PickleValue>) =
            execute_full(&dis).map_err(|e: crate::error::Error| {
                CoreError::PassFailure(format!("DR-PICKLE-0904: pickle vm: {e}"))
            })?;
        let source: String = if needs_memo_table(&trace.result) {
            let recovered: Reconstruction = reconstruct(&trace.result, &memo, trace.root_memo_key);
            recovered.program
        } else {
            crate::decompile::to_python_assignment(&trace.result)
        };
        Ok(Artifact::new(
            Rung::Surface,
            source.into_bytes(),
            artifact.root_hash,
        ))
    }
}

pub static PICKLE_PASS: PicklePass = PicklePass;

fn verdict(confidence: f32, specificity: u16, marker: &'static str) -> DetectVerdict {
    DetectVerdict::new(
        PASS_ID,
        TAG_PICKLE,
        FAMILY_INTERPRETER_BYTECODE,
        confidence,
        specificity,
        vec![marker],
        "pickle classify: python-pickle".to_string(),
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

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
        assert_eq!(PickleDetector.id(), PASS_ID);
    }

    #[test]
    fn detects_proto2() {
        let v: DetectVerdict = PickleDetector.detect(&ctx(b"\x80\x02N.")).expect("pickle");
        assert_eq!(v.format_tag, TAG_PICKLE);
        assert!(v.confidence > 0.95);
    }

    #[test]
    fn rejects_random() {
        assert!(
            PickleDetector
                .detect(&ctx(&[0x01, 0x02, 0x03, 0x04]))
                .is_none()
        );
    }

    #[test]
    fn pass_emits_python_surface() {
        let art: Artifact = Artifact::new(Rung::Raw, b"\x80\x02K\x2a.".to_vec(), [0u8; 32]);
        let out: Artifact = PICKLE_PASS.run(&art).expect("run");
        assert!(String::from_utf8_lossy(&out.envelope).contains("result = 42"));
    }

    #[test]
    fn pass_emits_a_self_defined_memo_table_for_a_self_referential_list() {
        let art: Artifact = Artifact::new(Rung::Raw, b"\x80\x02]q\x00h\x00a.".to_vec(), [0u8; 32]);
        let out: Artifact = PICKLE_PASS.run(&art).expect("run");
        let source: String = String::from_utf8_lossy(&out.envelope).into_owned();
        assert!(
            source.contains("_m = {}"),
            "a memo-backed reference must never appear without the dict that defines it: {source}"
        );
        assert!(source.contains("_m[0] = []"));
        assert!(source.contains("_m[0].extend([_m[0]])"));
    }
}
