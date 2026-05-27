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

use crate::obfuscators::{
    DetectReport, Obfuscator, ObfuscatorPass, PeelOutcome, berserker::BerserkerPass,
    py_mauricelambert::PyObfuscatorMauricelambertPass,
    python_obfuscator_pypi::PythonObfuscatorPypiPass,
};

pub const PASS_ID: PassId = "py.deob";

const TAG_BERSERKER: &str = "py-berserker";
const TAG_MAURICELAMBERT: &str = "py-pyobfuscator-mauricelambert";
const TAG_PYPI: &str = "py-python-obfuscator-pypi";
const TAG_GENERIC: &str = "py-source-obfuscated";

#[derive(Debug)]
pub struct PyDeobDetector;

impl Detector for PyDeobDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let bytes: &[u8] = ctx.bytes;
        let candidates: [(&'static dyn ObfuscatorPass, &'static str); 3] = candidate_table();
        let mut best: Option<(DetectReport, &'static str)> = None;
        for (pass, tag) in candidates {
            let report: DetectReport = pass.detect(bytes);
            if !report.matched || report.confidence < 0.5 {
                continue;
            }
            best = match best {
                None => Some((report, tag)),
                Some((prev, prev_tag)) => {
                    if report.confidence > prev.confidence {
                        Some((report, tag))
                    } else {
                        Some((prev, prev_tag))
                    }
                }
            };
        }
        let (report, tag): (DetectReport, &'static str) = best?;
        Some(DetectVerdict::new(
            PASS_ID,
            tag,
            FAMILY_OBFUSCATOR_WRAPPER,
            report.confidence,
            40,
            vec!["py-source-marker"],
            format!("py-deob family={obf:?}", obf = report.obfuscator),
        ))
    }
}

#[derive(Debug)]
pub struct PyDeobPass;

impl Pass for PyDeobPass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &PyDeobDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Source {
            language: Language::Python,
            formatted: true,
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let candidates: [(&'static dyn ObfuscatorPass, &'static str); 3] = candidate_table();
        for (pass, _tag) in candidates {
            let report: DetectReport = pass.detect(bytes);
            if !report.matched || report.confidence < 0.5 {
                continue;
            }
            let outcome: PeelOutcome = pass
                .peel(bytes)
                .map_err(|e| CoreError::PassFailure(format!("DR-PYDEOB-0901: peel: {e}")))?;
            return Ok(Artifact::new(
                Rung::Surface,
                outcome.recovered_source.into_bytes(),
                artifact.root_hash,
            ));
        }
        Err(CoreError::PassFailure(
            "DR-PYDEOB-0902: py.deob: no matching obfuscator pass".to_string(),
        ))
    }
}

pub static PY_DEOB_PASS: PyDeobPass = PyDeobPass;

fn candidate_table() -> [(&'static dyn ObfuscatorPass, &'static str); 3] {
    [
        (&BerserkerPass as &'static dyn ObfuscatorPass, TAG_BERSERKER),
        (
            &PyObfuscatorMauricelambertPass as &'static dyn ObfuscatorPass,
            TAG_MAURICELAMBERT,
        ),
        (
            &PythonObfuscatorPypiPass as &'static dyn ObfuscatorPass,
            TAG_PYPI,
        ),
    ]
}

#[allow(dead_code)]
const _: &str = TAG_GENERIC;

#[allow(dead_code)]
const fn _enum_keeps_compat() -> Obfuscator {
    Obfuscator::Berserker
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detector_id_is_stable() {
        assert_eq!(PyDeobDetector.id(), PASS_ID);
    }

    #[test]
    fn pass_output_kind_is_python_source() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        let k: OutputKind = PY_DEOB_PASS.output_kind(&a);
        match k {
            OutputKind::Source {
                language,
                formatted,
            } => {
                assert_eq!(language, Language::Python);
                assert!(formatted);
            }
            _ => panic!("expected Source"),
        }
    }

    #[test]
    fn detect_clean_python_yields_none() {
        let src: &[u8] = b"def foo():\n    return 1\n";
        let ctx: DetectContext<'_> = DetectContext {
            bytes: src,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        assert!(PyDeobDetector.detect(&ctx).is_none());
    }
}
