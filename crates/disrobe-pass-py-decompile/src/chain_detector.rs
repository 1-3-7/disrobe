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

use disrobe_py_marshal::{PyVersion as MarshalVersion, pyversion_from_magic};

use crate::engine::{NativeDecompile, decompile_pyc};

pub const PASS_ID: PassId = "py.decompile";

const TAG_PYC_PREFIX: &str = "pyc";

#[derive(Debug)]
pub struct PyDecompileDetector;

impl Detector for PyDecompileDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let bytes: &[u8] = ctx.bytes;
        if bytes.len() < 4 {
            return None;
        }
        let magic: u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let version: MarshalVersion = pyversion_from_magic(magic)?;
        Some(verdict_for(version))
    }
}

#[derive(Debug)]
pub struct PyDecompilePass;

impl Pass for PyDecompilePass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &PyDecompileDetector
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
        let ctx: DetectContext<'_> = DetectContext {
            bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        if PyDecompileDetector.detect(&ctx).is_none() {
            return Err(CoreError::PassFailure(
                "DR-PYDEC-0902: py.decompile: input is not a recognized cpython pyc magic"
                    .to_string(),
            ));
        }
        let result: NativeDecompile = decompile_pyc(bytes).map_err(|e| {
            CoreError::PassFailure(format!("DR-PYDEC-0908: py.decompile engine: {e}"))
        })?;
        Ok(Artifact::new(
            Rung::Surface,
            result.source.into_bytes(),
            artifact.root_hash,
        ))
    }
}

pub static PY_DECOMPILE_PASS: PyDecompilePass = PyDecompilePass;

fn verdict_for(v: MarshalVersion) -> DetectVerdict {
    let tag: &'static str = format_tag_for(v);
    DetectVerdict::new(
        PASS_ID,
        tag,
        FAMILY_INTERPRETER_BYTECODE,
        0.94,
        50,
        vec!["pyc-magic-known"],
        format!(
            "cpython pyc {major}.{minor}",
            major = v.major,
            minor = v.minor
        ),
    )
}

const fn format_tag_for(v: MarshalVersion) -> &'static str {
    match (v.major, v.minor) {
        (2, 7) => "pyc-2.7",
        (3, 3) => "pyc-3.3",
        (3, 4) => "pyc-3.4",
        (3, 5) => "pyc-3.5",
        (3, 6) => "pyc-3.6",
        (3, 7) => "pyc-3.7",
        (3, 8) => "pyc-3.8",
        (3, 9) => "pyc-3.9",
        (3, 10) => "pyc-3.10",
        (3, 11) => "pyc-3.11",
        (3, 12) => "pyc-3.12",
        (3, 13) => "pyc-3.13",
        (3, 14) => "pyc-3.14",
        _ => TAG_PYC_PREFIX,
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

    fn pyc_for(magic: u16) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(16);
        v.extend_from_slice(&magic.to_le_bytes());
        v.extend_from_slice(&[0x0d, 0x0a, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]);
        v
    }

    #[test]
    fn detector_id_is_stable() {
        assert_eq!(PyDecompileDetector.id(), PASS_ID);
    }

    #[test]
    fn detect_311_magic() {
        let v: DetectVerdict = PyDecompileDetector
            .detect(&ctx(&pyc_for(3495)))
            .expect("must detect");
        assert_eq!(v.format_tag, "pyc-3.11");
        assert_eq!(v.specificity, 50);
    }

    #[test]
    fn detect_312_magic() {
        let v: DetectVerdict = PyDecompileDetector
            .detect(&ctx(&pyc_for(3531)))
            .expect("must detect");
        assert_eq!(v.format_tag, "pyc-3.12");
    }

    #[test]
    fn detect_misses_unknown_magic() {
        let bytes: Vec<u8> = pyc_for(9999);
        assert!(PyDecompileDetector.detect(&ctx(&bytes)).is_none());
    }

    #[test]
    fn pass_output_kind_is_python_source_formatted() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match PY_DECOMPILE_PASS.output_kind(&a) {
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
    fn pass_run_rejects_synthetic_pyc311_without_code_body() {
        let bytes: Vec<u8> = pyc_for(3495);
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let err: CoreError = PY_DECOMPILE_PASS
            .run(&a)
            .expect_err("synthetic pyc lacks marshaled code");
        let msg: String = format!("{err}");
        assert!(msg.contains("DR-PYDEC-0908") || msg.contains("DR-PYDEC-0909"));
    }

    #[test]
    fn pass_run_rejects_unknown_magic() {
        let a: Artifact = Artifact::new(Rung::Raw, pyc_for(9999), [0u8; 32]);
        let err: CoreError = PY_DECOMPILE_PASS.run(&a).expect_err("must reject");
        assert!(format!("{err}").contains("DR-PYDEC-0902"));
    }
}
