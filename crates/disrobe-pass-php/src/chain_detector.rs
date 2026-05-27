#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_OBFUSCATOR_WRAPPER, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use disrobe_core::provenance::Language;

use serde::Serialize;

use crate::detect::{PhpConfidence, PhpDetection, PhpKind, detect as detect_php};
use crate::peel::{PeelOptions, PeelReport, peel as peel_php};
use crate::phar::{PharArchive, parse as parse_phar};

pub const PASS_ID: PassId = "php.peel";

const TAG_PHP_SOURCE: &str = "php-source";
const TAG_PHAR_STUB: &str = "php-phar-stub";
const TAG_PHAR_ARCHIVE: &str = "php-phar-archive";
const TAG_BCG: &str = "php-bcg";

#[derive(Debug)]
pub struct PhpDetectorImpl;

impl Detector for PhpDetectorImpl {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let detection: PhpDetection = detect_php(ctx.bytes);
        verdict_for(&detection)
    }
}

#[derive(Debug)]
pub struct PhpPass;

impl Pass for PhpPass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &PhpDetectorImpl
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Source {
            language: Language::Php,
            formatted: true,
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let detection: PhpDetection = detect_php(bytes);
        let verdict: DetectVerdict = verdict_for(&detection).ok_or_else(|| {
            CoreError::PassFailure(
                "DR-PHP-0902: php.peel: input is not a recognized php source or archive"
                    .to_string(),
            )
        })?;
        let extract: PhpExtract = extract_for(verdict.format_tag, bytes, &detection);
        let payload: Vec<u8> =
            serde_json::to_vec_pretty(&extract).map_err(|e: serde_json::Error| {
                CoreError::PassFailure(format!("DR-PHP-0903: serialize php extract: {e}"))
            })?;
        let next_rung: Rung = if verdict.format_tag == TAG_PHP_SOURCE {
            Rung::Surface
        } else {
            Rung::Disasm
        };
        Ok(Artifact::new(next_rung, payload, artifact.root_hash))
    }
}

pub static PHP_PASS: PhpPass = PhpPass;

#[derive(Debug, Clone, Serialize)]
pub struct PhpExtract {
    pub kind: PhpKind,
    pub has_halt_compiler: bool,
    pub source_text: Option<String>,
    pub peel: Option<PeelReport>,
    pub phar_entry_count: Option<usize>,
}

fn extract_for(format_tag: &str, bytes: &[u8], detection: &PhpDetection) -> PhpExtract {
    let kind: PhpKind = detection.kind;
    let has_halt: bool = detection.has_halt_compiler;
    match format_tag {
        TAG_PHP_SOURCE => {
            let source_text: Option<String> = std::str::from_utf8(bytes).ok().map(str::to_owned);
            let peel: Option<PeelReport> = peel_php(bytes, PeelOptions::default()).ok();
            PhpExtract {
                kind,
                has_halt_compiler: has_halt,
                source_text,
                peel,
                phar_entry_count: None,
            }
        }
        TAG_PHAR_STUB | TAG_PHAR_ARCHIVE => {
            let phar: Option<PharArchive> = parse_phar(bytes).ok();
            let entry_count: Option<usize> = phar.as_ref().map(|p: &PharArchive| p.entries.len());
            PhpExtract {
                kind,
                has_halt_compiler: has_halt,
                source_text: None,
                peel: None,
                phar_entry_count: entry_count,
            }
        }
        _ => PhpExtract {
            kind,
            has_halt_compiler: has_halt,
            source_text: None,
            peel: None,
            phar_entry_count: None,
        },
    }
}

fn verdict_for(d: &PhpDetection) -> Option<DetectVerdict> {
    let confidence: f32 = confidence_to_float(d.confidence);
    if confidence < 0.5 {
        return None;
    }
    let (tag, marker): (&'static str, &'static str) = match d.kind {
        PhpKind::Source => (TAG_PHP_SOURCE, "<?php-tag"),
        PhpKind::PharStub => (TAG_PHAR_STUB, "__HALT_COMPILER"),
        PhpKind::PharArchive => (TAG_PHAR_ARCHIVE, "phar-GBMB"),
        PhpKind::Bcg => (TAG_BCG, "bcg-magic"),
        PhpKind::Unknown => return None,
    };
    Some(DetectVerdict::new(
        PASS_ID,
        tag,
        FAMILY_OBFUSCATOR_WRAPPER,
        confidence,
        30,
        vec![marker],
        format!("php kind={tag} halt={halt}", halt = d.has_halt_compiler),
    ))
}

#[inline]
const fn confidence_to_float(c: PhpConfidence) -> f32 {
    match c {
        PhpConfidence::Definite => 0.96,
        PhpConfidence::High => 0.86,
        PhpConfidence::Medium => 0.72,
        PhpConfidence::Low => 0.40,
    }
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
        assert_eq!(PhpDetectorImpl.id(), PASS_ID);
    }

    #[test]
    fn detect_open_tag_source() {
        let bytes: &[u8] = b"<?php echo 'hi';";
        let v: DetectVerdict = PhpDetectorImpl.detect(&ctx(bytes)).expect("must detect");
        assert_eq!(v.format_tag, TAG_PHP_SOURCE);
        assert!(v.confidence > 0.9);
    }

    #[test]
    fn detect_bcg_magic() {
        let bytes: &[u8] = b"BCG\x00rest";
        let v: DetectVerdict = PhpDetectorImpl.detect(&ctx(bytes)).expect("must detect");
        assert_eq!(v.format_tag, TAG_BCG);
    }

    #[test]
    fn detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0u8; 32];
        assert!(PhpDetectorImpl.detect(&ctx(&bytes)).is_none());
    }

    #[test]
    fn pass_output_kind_is_php_source() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match PHP_PASS.output_kind(&a) {
            OutputKind::Source {
                language,
                formatted,
            } => {
                assert_eq!(language, Language::Php);
                assert!(formatted);
            }
            _ => panic!("expected Source"),
        }
    }

    #[test]
    fn pass_run_extracts_php_source_with_serialized_text() {
        let bytes: Vec<u8> = b"<?php echo 'hi';".to_vec();
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let out: Artifact = PHP_PASS.run(&a).expect("classify must succeed");
        assert_eq!(out.rung, Rung::Surface);
        let s: &str = std::str::from_utf8(&out.envelope).expect("utf8 json");
        assert!(s.contains("\"Source\""));
        assert!(s.contains("echo"));
    }

    #[test]
    fn pass_run_classifies_bcg_as_disasm() {
        let bytes: Vec<u8> = b"BCG\x00rest".to_vec();
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let out: Artifact = PHP_PASS.run(&a).expect("classify must succeed");
        assert_eq!(out.rung, Rung::Disasm);
        let s: &str = std::str::from_utf8(&out.envelope).expect("utf8 json");
        assert!(s.contains("\"Bcg\""));
    }

    #[test]
    fn pass_run_rejects_unknown_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 32], [0u8; 32]);
        let err: CoreError = PHP_PASS.run(&a).expect_err("must reject");
        assert!(format!("{err}").contains("DR-PHP-0902"));
    }
}
