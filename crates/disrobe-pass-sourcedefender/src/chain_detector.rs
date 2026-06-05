#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_OBFUSCATOR_WRAPPER, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;

use crate::envelope::{DecryptedPye, PYE_BEGIN_MARKER, PYE_END_MARKER, decrypt_pye};

pub const PASS_ID: PassId = "sourcedefender.decrypt";

const FORMAT_PYE: &str = "sourcedefender-pye";
const FORMAT_PYE_INLINED: &str = "sourcedefender-pye-inlined";

#[derive(Debug)]
pub struct SourceDefenderDetector;

impl Detector for SourceDefenderDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let bytes: &[u8] = ctx.bytes;
        let has_begin: bool = window_contains(bytes, PYE_BEGIN_MARKER.as_bytes());
        let has_end: bool = window_contains(bytes, PYE_END_MARKER.as_bytes());
        if has_begin && has_end {
            return Some(verdict_full());
        }
        if has_begin {
            return Some(verdict_inlined());
        }
        None
    }
}

#[derive(Debug)]
pub struct SourceDefenderPass;

impl Pass for SourceDefenderPass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &SourceDefenderDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Bytes {
            format_tag: "msgpack-plaintext",
            family: "interpreter-bytecode",
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let decrypted: DecryptedPye = decrypt_pye(bytes, "chain.pye")
            .map_err(|e| CoreError::PassFailure(format!("DR-SD-0901: decrypt_pye: {e}")))?;
        if decrypted.plaintext_msgpack.is_empty() {
            return Err(CoreError::PassFailure(
                "DR-SD-0902: sourcedefender.decrypt: empty plaintext".to_string(),
            ));
        }
        Ok(Artifact::new(
            Rung::Raw,
            decrypted.plaintext_msgpack,
            artifact.root_hash,
        ))
    }
}

pub static SOURCEDEFENDER_PASS: SourceDefenderPass = SourceDefenderPass;

#[inline]
fn verdict_full() -> DetectVerdict {
    DetectVerdict::new(
        PASS_ID,
        FORMAT_PYE,
        FAMILY_OBFUSCATOR_WRAPPER,
        0.96,
        12,
        vec!["BEGIN-PYE-FILE", "END-PYE-FILE"],
        "sourcedefender .pye envelope (full)".to_string(),
    )
}

#[inline]
fn verdict_inlined() -> DetectVerdict {
    DetectVerdict::new(
        PASS_ID,
        FORMAT_PYE_INLINED,
        FAMILY_OBFUSCATOR_WRAPPER,
        0.78,
        14,
        vec!["BEGIN-PYE-FILE"],
        "sourcedefender inlined .pye block".to_string(),
    )
}

#[inline]
fn window_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
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
        assert_eq!(SourceDefenderDetector.id(), PASS_ID);
    }

    #[test]
    fn detect_full_envelope() {
        let text: &[u8] =
            b"--BEGIN SOURCEDEFENDER FILE---\niv-line\nciphertext\n---END SOURCEDEFENDER FILE----";
        let v: DetectVerdict = SourceDefenderDetector
            .detect(&ctx(text))
            .expect("must detect");
        assert_eq!(v.format_tag, FORMAT_PYE);
        assert!(v.confidence > 0.9);
        assert_eq!(v.specificity, 12);
    }

    #[test]
    fn detect_inlined_begin_only() {
        let text: &[u8] = b"# inlined fragment\n--BEGIN SOURCEDEFENDER FILE---\nblob";
        let v: DetectVerdict = SourceDefenderDetector
            .detect(&ctx(text))
            .expect("must detect");
        assert_eq!(v.format_tag, FORMAT_PYE_INLINED);
        assert_eq!(v.specificity, 14);
    }

    #[test]
    fn detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0u8; 32];
        assert!(SourceDefenderDetector.detect(&ctx(&bytes)).is_none());
    }

    #[test]
    fn pass_output_kind_is_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match SOURCEDEFENDER_PASS.output_kind(&a) {
            OutputKind::Bytes { format_tag, family } => {
                assert_eq!(format_tag, "msgpack-plaintext");
                assert_eq!(family, "interpreter-bytecode");
            }
            _ => panic!("expected Bytes"),
        }
    }

    #[test]
    fn pass_run_rejects_non_pye() {
        let a: Artifact = Artifact::new(Rung::Raw, b"plain text".to_vec(), [0u8; 32]);
        assert!(SOURCEDEFENDER_PASS.run(&a).is_err());
    }
}
