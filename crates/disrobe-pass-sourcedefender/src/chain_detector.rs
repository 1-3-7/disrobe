#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]
use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_OBFUSCATOR_WRAPPER, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;

use crate::envelope::{PYE_BEGIN_MARKER, PYE_END_MARKER};
use crate::layered::{LayeredRecovery, MODERN_BEGIN_MARKER, MODERN_END_MARKER, recover_layered};

pub const PASS_ID: PassId = "sourcedefender.decrypt";

const FORMAT_PYE: &str = "sourcedefender-pye";
const FORMAT_PYE_INLINED: &str = "sourcedefender-pye-inlined";
const FORMAT_PYE_MODERN: &str = "sourcedefender-pye-modern";

#[derive(Debug)]
pub struct SourceDefenderDetector;

impl Detector for SourceDefenderDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let bytes: &[u8] = ctx.bytes;
        match armor_span(bytes, PYE_BEGIN_MARKER, PYE_END_MARKER) {
            ArmorSpan::Closed => return Some(verdict_full()),
            ArmorSpan::Open => return Some(verdict_inlined()),
            ArmorSpan::Absent => {}
        }
        match armor_span(bytes, MODERN_BEGIN_MARKER, MODERN_END_MARKER) {
            ArmorSpan::Closed => Some(verdict_modern()),
            ArmorSpan::Open | ArmorSpan::Absent => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArmorSpan {
    Absent,
    Open,
    Closed,
}

fn armor_span(bytes: &[u8], begin: &str, end: &str) -> ArmorSpan {
    let mut lines = bytes.split(|b: &u8| *b == b'\n');
    if !lines
        .by_ref()
        .any(|line: &[u8]| is_armor_line(line, begin.as_bytes()))
    {
        return ArmorSpan::Absent;
    }
    let mut body_lines: usize = 0;
    for line in lines {
        if is_armor_line(line, end.as_bytes()) {
            return if body_lines == 0 {
                ArmorSpan::Absent
            } else {
                ArmorSpan::Closed
            };
        }
        if !is_armor_body_line(line) {
            return ArmorSpan::Absent;
        }
        if !line.trim_ascii().is_empty() {
            body_lines += 1;
        }
    }
    if body_lines == 0 {
        ArmorSpan::Absent
    } else {
        ArmorSpan::Open
    }
}

fn is_armor_line(line: &[u8], marker: &[u8]) -> bool {
    let line: &[u8] = line
        .strip_prefix(b"\xEF\xBB\xBF")
        .unwrap_or(line)
        .trim_ascii();
    let Some(inner): Option<&[u8]> = line
        .strip_prefix(b"-")
        .and_then(|rest: &[u8]| rest.strip_suffix(b"-"))
    else {
        return false;
    };
    let start: usize = inner.iter().take_while(|b: &&u8| **b == b'-').count();
    let stop: usize = inner.iter().rev().take_while(|b: &&u8| **b == b'-').count();
    inner
        .get(start..inner.len().saturating_sub(stop))
        .is_some_and(|core: &[u8]| core == marker)
}

fn is_armor_body_line(line: &[u8]) -> bool {
    line.trim_ascii().iter().all(|b: &u8| b.is_ascii_graphic())
}

#[derive(Debug)]
pub struct SourceDefenderPass;

impl Pass for SourceDefenderPass {
    #[inline]
    fn meta(&self) -> disrobe_core::chain::PassMeta {
        META
    }
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
        self.run_with_path(artifact, None)
    }

    fn run_with_path(&self, artifact: &Artifact, path_hint: Option<&str>) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let filename: &str = path_hint.unwrap_or("chain.pye");
        let recovery: LayeredRecovery = recover_layered(bytes, filename)
            .map_err(|e| CoreError::PassFailure(format!("DR-SD-0901: recover_layered: {e}")))?;

        if let Some(wall) = recovery.wall {
            return Err(CoreError::PassFailure(format!(
                "DR-SD-0903: sourcedefender.decrypt: {} ({})",
                wall.detail,
                wall.reason.tag()
            )));
        }

        let plaintext: Vec<u8> = recovery
            .recovered_source
            .map(String::into_bytes)
            .or(recovery.recovered_marshal)
            .filter(|p: &Vec<u8>| !p.is_empty())
            .ok_or_else(|| {
                CoreError::PassFailure(
                    "DR-SD-0902: sourcedefender.decrypt: empty plaintext".to_string(),
                )
            })?;
        Ok(Artifact::new(Rung::Raw, plaintext, artifact.root_hash))
    }
}

pub const META: disrobe_core::chain::PassMeta = disrobe_core::chain::PassMeta::new(
    PASS_ID,
    disrobe_core::chain::Ecosystem::Python,
    disrobe_core::chain::SupportQuality::Full,
    disrobe_core::chain::Determinism::Deterministic,
    disrobe_core::chain::SafetyClass::Static,
);

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
fn verdict_modern() -> DetectVerdict {
    DetectVerdict::new(
        PASS_ID,
        FORMAT_PYE_MODERN,
        FAMILY_OBFUSCATOR_WRAPPER,
        0.95,
        12,
        vec!["BEGIN-PYE-FILE", "END-PYE-FILE", "hex-body"],
        "sourcedefender modern .pye envelope (aes-gcm, runtime-license-key body)".to_string(),
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
    fn detect_ignores_text_that_only_quotes_the_armor_markers() {
        let dir: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus/python/sourcedefender");
        for name in ["PROVENANCE.txt", "build_crafted_modern.mjs"] {
            let path: std::path::PathBuf = dir.join(name);
            let bytes: Vec<u8> = std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
                panic!(
                    "required tracked fixture {} is unreadable: {e}",
                    path.display()
                )
            });
            assert!(
                SourceDefenderDetector.detect(&ctx(&bytes)).is_none(),
                "{name} mentions the armor markers inside prose or a template literal and is \
                 not a sourcedefender envelope",
            );
        }
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

    const MODERN_TRIAL: &[u8] =
        include_bytes!("../../../corpus/python/sourcedefender/known_v16_trial.pye");
    const LEGACY_HELLO: &[u8] = include_bytes!("../../../corpus/python/sourcedefender/hello.pye");

    #[test]
    fn pass_run_recovers_real_legacy_free_source() {
        let a: Artifact = Artifact::new(Rung::Raw, LEGACY_HELLO.to_vec(), [0u8; 32]);
        let out: Artifact = SOURCEDEFENDER_PASS
            .run_with_path(&a, Some("hello.pye"))
            .expect("legacy body must recover with its real basename-derived key");
        let recovered: &str = core::str::from_utf8(&out.envelope).expect("utf8 source");
        assert_eq!(recovered.trim_end(), "print(\"Hello World!\")");
    }

    #[test]
    fn pass_run_without_path_hint_falls_back_to_a_stable_default_basename() {
        let a: Artifact = Artifact::new(Rung::Raw, LEGACY_HELLO.to_vec(), [0u8; 32]);
        let err: CoreError = SOURCEDEFENDER_PASS
            .run(&a)
            .expect_err("legacy body keyed to a different basename must not falsely recover");
        let message: String = format!("{err}");
        assert!(message.contains("DR-SD-0901"), "{message}");
        assert!(message.contains("DR-SDEF-0014"), "{message}");
        assert!(message.contains("`chain.pye`"), "{message}");
    }

    #[test]
    fn detect_real_modern_pye_envelope() {
        let v: DetectVerdict = SourceDefenderDetector
            .detect(&ctx(MODERN_TRIAL))
            .expect("modern .pye must be detected");
        assert_eq!(v.format_tag, FORMAT_PYE_MODERN);
        assert!(v.confidence > 0.9);
    }

    #[test]
    fn pass_run_walls_real_modern_body_with_reason() {
        let a: Artifact = Artifact::new(Rung::Raw, MODERN_TRIAL.to_vec(), [0u8; 32]);
        let err: CoreError = SOURCEDEFENDER_PASS
            .run(&a)
            .expect_err("modern body must wall");
        let msg: String = format!("{err}");
        assert!(msg.contains("runtime-license-key"));
        assert!(msg.contains("aes-256-gcm"));
    }
}
