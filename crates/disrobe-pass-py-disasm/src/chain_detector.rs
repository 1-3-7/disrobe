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

use serde::Serialize;

use crate::Instruction;
use crate::alt_runtimes::{AltRuntime, detect_runtime};
use disrobe_py_marshal::{CodeObject, Object, PyVersion, PycFile, pyversion_from_magic, read_pyc};

pub const PASS_ID: PassId = "py.disasm";

const TAG_PYPY: &str = "pyc-pypy";
const TAG_MICROPYTHON: &str = "pyc-micropython";
const TAG_MICROPYTHON_NATIVE: &str = "pyc-micropython-native";
const TAG_JYTHON: &str = "pyc-jython";
const TAG_IRONPYTHON: &str = "pyc-ironpython";
const TAG_BRYTHON: &str = "pyc-brython";
const TAG_CPYTHON_PYC: &str = "pyc-cpython";

#[derive(Debug)]
pub struct PyDisasmDetector;

impl Detector for PyDisasmDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let bytes: &[u8] = ctx.bytes;
        if let Some(rt) = detect_runtime(bytes) {
            return Some(verdict_for_alt(rt));
        }
        if is_cpython_pyc(bytes) {
            return Some(verdict_cpython());
        }
        None
    }
}

#[derive(Debug)]
pub struct PyDisasmPass;

impl Pass for PyDisasmPass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &PyDisasmDetector
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
        if PyDisasmDetector.detect(&ctx).is_none() {
            return Err(CoreError::PassFailure(
                "DR-PYDIS-0902: py.disasm: input is not a recognized cpython or alt-runtime pyc"
                    .to_string(),
            ));
        }
        let extract: PyDisasmExtract = extract_for(bytes)?;
        let payload: Vec<u8> =
            serde_json::to_vec_pretty(&extract).map_err(|e: serde_json::Error| {
                CoreError::PassFailure(format!("DR-PYDIS-0905: serialize py disasm extract: {e}"))
            })?;
        Ok(Artifact::new(Rung::Disasm, payload, artifact.root_hash))
    }
}

pub static PY_DISASM_PASS: PyDisasmPass = PyDisasmPass;

#[derive(Debug, Clone, Serialize)]
pub struct PyDisasmExtract {
    pub runtime: String,
    pub py_version: Option<String>,
    pub disasm_text: String,
    pub instruction_count: usize,
}

fn extract_for(bytes: &[u8]) -> CoreResult<PyDisasmExtract> {
    if let Some(rt) = detect_runtime(bytes) {
        return Ok(PyDisasmExtract {
            runtime: alt_label(rt).to_owned(),
            py_version: None,
            disasm_text: format!(
                "; alt-runtime {} disassembly delegation pending\n",
                alt_label(rt)
            ),
            instruction_count: 0usize,
        });
    }
    if bytes.len() < 4 {
        return Err(CoreError::PassFailure(
            "DR-PYDIS-0906: py.disasm: input too short for pyc header".to_owned(),
        ));
    }
    let magic: u16 = u16::from_le_bytes([bytes[0], bytes[1]]);
    let version: PyVersion = pyversion_from_magic(magic).ok_or_else(|| {
        CoreError::PassFailure(format!(
            "DR-PYDIS-0907: py.disasm: unknown pyc magic 0x{magic:04x}"
        ))
    })?;
    let pyc: PycFile = read_pyc(bytes).map_err(|e: disrobe_py_marshal::Error| {
        CoreError::PassFailure(format!("DR-PYDIS-0908: pyc parse: {e}"))
    })?;
    let code: &CodeObject = match &pyc.code {
        Object::Code(co) => co.as_ref(),
        _ => {
            return Err(CoreError::PassFailure(
                "DR-PYDIS-0909: py.disasm: pyc top-level object is not a code object".to_owned(),
            ));
        }
    };
    let ins: Vec<Instruction> = crate::disassemble(code, version);
    let text: String = crate::render_dis(&ins);
    Ok(PyDisasmExtract {
        runtime: "cpython".to_owned(),
        py_version: Some(format!("{}.{}", version.major, version.minor)),
        instruction_count: ins.len(),
        disasm_text: text,
    })
}

const fn alt_label(rt: AltRuntime) -> &'static str {
    match rt {
        AltRuntime::PyPy => "pypy",
        AltRuntime::MicroPython => "micropython",
        AltRuntime::MicroPythonNative => "micropython-native",
        AltRuntime::Jython => "jython",
        AltRuntime::IronPython => "ironpython",
        AltRuntime::Brython => "brython",
    }
}

fn verdict_for_alt(rt: AltRuntime) -> DetectVerdict {
    let (tag, marker): (&'static str, &'static str) = match rt {
        AltRuntime::PyPy => (TAG_PYPY, "pypy-marker"),
        AltRuntime::MicroPython => (TAG_MICROPYTHON, "micropython-magic"),
        AltRuntime::MicroPythonNative => (TAG_MICROPYTHON_NATIVE, "micropython-native-magic"),
        AltRuntime::Jython => (TAG_JYTHON, "jython-marker"),
        AltRuntime::IronPython => (TAG_IRONPYTHON, "ironpython-marker"),
        AltRuntime::Brython => (TAG_BRYTHON, "brython-marker"),
    };
    DetectVerdict::new(
        PASS_ID,
        tag,
        FAMILY_INTERPRETER_BYTECODE,
        0.92,
        50,
        vec![marker],
        format!("python alt-runtime={tag}"),
    )
}

fn verdict_cpython() -> DetectVerdict {
    DetectVerdict::new(
        PASS_ID,
        TAG_CPYTHON_PYC,
        FAMILY_INTERPRETER_BYTECODE,
        0.86,
        50,
        vec!["pyc-magic-0x0a0d-suffix"],
        "cpython pyc magic suffix".to_string(),
    )
}

fn is_cpython_pyc(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    let suffix: u16 = u16::from_le_bytes([bytes[2], bytes[3]]);
    let magic: u16 = u16::from_le_bytes([bytes[0], bytes[1]]);
    suffix == 0x0A0D && disrobe_py_marshal::pyversion_from_magic(magic).is_some()
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

    fn pyc311_header() -> Vec<u8> {
        let magic: u16 = 3495;
        let mut v: Vec<u8> = Vec::with_capacity(16);
        v.extend_from_slice(&magic.to_le_bytes());
        v.extend_from_slice(&[0x0d, 0x0a, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]);
        v
    }

    #[test]
    fn detector_id_is_stable() {
        assert_eq!(PyDisasmDetector.id(), PASS_ID);
    }

    #[test]
    fn detect_cpython_pyc_311() {
        let bytes: Vec<u8> = pyc311_header();
        let v: DetectVerdict = PyDisasmDetector.detect(&ctx(&bytes)).expect("must detect");
        assert_eq!(v.format_tag, TAG_CPYTHON_PYC);
        assert_eq!(v.specificity, 50);
    }

    #[test]
    fn detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0xff; 32];
        assert!(PyDisasmDetector.detect(&ctx(&bytes)).is_none());
    }

    #[test]
    fn pass_output_kind_is_python_source() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match PY_DISASM_PASS.output_kind(&a) {
            OutputKind::Source {
                language,
                formatted,
            } => {
                assert_eq!(language, Language::Python);
                assert!(!formatted);
            }
            _ => panic!("expected Source"),
        }
    }

    #[test]
    fn pass_run_rejects_synthetic_pyc311_without_code_body() {
        let bytes: Vec<u8> = pyc311_header();
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let err: CoreError = PY_DISASM_PASS
            .run(&a)
            .expect_err("synthetic pyc lacks marshaled code");
        let msg: String = format!("{err}");
        assert!(msg.contains("DR-PYDIS-0908") || msg.contains("DR-PYDIS-0909"));
    }

    #[test]
    fn pass_run_rejects_unknown_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0xff; 32], [0u8; 32]);
        let err: CoreError = PY_DISASM_PASS.run(&a).expect_err("must reject");
        assert!(format!("{err}").contains("DR-PYDIS-0902"));
    }
}
