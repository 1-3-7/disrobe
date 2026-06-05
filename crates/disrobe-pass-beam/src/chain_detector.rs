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

use crate::file::RawBeam;

pub const PASS_ID: PassId = "beam.classify";

const TAG_BEAM: &str = "beam-file";
const TAG_EZ: &str = "ez-archive";
const BEAM_MAGIC_IFF: &[u8; 4] = b"FOR1";
const BEAM_MAGIC_TAG: &[u8; 4] = b"BEAM";

#[derive(Debug)]
pub struct BeamDetector;

impl Detector for BeamDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let bytes: &[u8] = ctx.bytes;
        if is_beam_file(bytes) {
            return Some(verdict(TAG_BEAM, "FOR1+BEAM iff header"));
        }
        if is_ez_archive(bytes) {
            return Some(verdict(TAG_EZ, "EZ archive (zip wrapping .beam entries)"));
        }
        None
    }
}

#[derive(Debug)]
pub struct BeamPass;

impl Pass for BeamPass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &BeamDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Source {
            language: Language::Erlang,
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
        let Some(verdict): Option<DetectVerdict> = BeamDetector.detect(&ctx) else {
            return Err(CoreError::PassFailure(
                "DR-BEAM-0901: beam.classify: input is neither a BEAM file nor an EZ archive"
                    .to_string(),
            ));
        };
        if verdict.format_tag == TAG_BEAM {
            RawBeam::parse(bytes).map_err(|e: crate::error::Error| {
                CoreError::PassFailure(format!("DR-BEAM-0903: beam parse: {e}"))
            })?;
        }
        Ok(Artifact::new(
            Rung::Disasm,
            bytes.to_vec(),
            artifact.root_hash,
        ))
    }
}

pub static BEAM_PASS: BeamPass = BeamPass;

fn is_beam_file(bytes: &[u8]) -> bool {
    bytes.len() >= 12 && &bytes[0..4] == BEAM_MAGIC_IFF && &bytes[8..12] == BEAM_MAGIC_TAG
}

fn is_ez_archive(bytes: &[u8]) -> bool {
    if !bytes.starts_with(b"PK\x03\x04") {
        return false;
    }
    bytes.windows(5).take(8192).any(|w: &[u8]| w == b".beam")
}

fn verdict(tag: &'static str, marker: &'static str) -> DetectVerdict {
    DetectVerdict::new(
        PASS_ID,
        tag,
        FAMILY_INTERPRETER_BYTECODE,
        0.97,
        30,
        vec![marker],
        format!("beam classify: {tag}"),
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
        assert_eq!(BeamDetector.id(), PASS_ID);
    }

    #[test]
    fn detects_beam_file() {
        let mut bytes: Vec<u8> = Vec::with_capacity(16);
        bytes.extend_from_slice(BEAM_MAGIC_IFF);
        bytes.extend_from_slice(&[0, 0, 0, 4]);
        bytes.extend_from_slice(BEAM_MAGIC_TAG);
        let v: DetectVerdict = BeamDetector.detect(&ctx(&bytes)).expect("beam magic");
        assert_eq!(v.format_tag, TAG_BEAM);
    }

    #[test]
    fn rejects_for1_without_beam_tag() {
        let bytes: Vec<u8> = b"FOR1\x00\x00\x00\x04AIFF".to_vec();
        assert!(BeamDetector.detect(&ctx(&bytes)).is_none());
    }

    #[test]
    fn rejects_random_bytes() {
        assert!(BeamDetector.detect(&ctx(&[0u8; 32])).is_none());
    }
}
