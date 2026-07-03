#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]
use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::detection::{ChildArtifact, ChildHandle, TERMINAL_HINT};
use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_INTERPRETER_BYTECODE, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;

use serde::{Deserialize, Serialize};

use crate::Instruction;
use crate::alt_runtimes::recover::{AltRecovery, recover};
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

    fn output_kind(&self, output: &Artifact) -> OutputKind {
        let recovered: bool = std::str::from_utf8(output.envelope.as_slice())
            .is_ok_and(|s: &str| !s.starts_with(ALT_RUNTIME_NOTE_PREFIX));
        if recovered {
            OutputKind::Mixed {
                children: Vec::new(),
            }
        } else {
            OutputKind::Bytes {
                format_tag: "py.runtime-detected",
                family: FAMILY_INTERPRETER_BYTECODE,
            }
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
        let (extract, _instructions): (PyDisasmExtract, Vec<Instruction>) = extract_for(bytes)?;
        Ok(Artifact::new(
            Rung::Disasm,
            extract.disasm_text.into_bytes(),
            artifact.root_hash,
        ))
    }

    fn extract_children(&self, input: &Artifact) -> CoreResult<Vec<ChildArtifact>> {
        let bytes: &[u8] = input.envelope.as_slice();
        let (extract, instructions): (PyDisasmExtract, Vec<Instruction>) = match extract_for(bytes)
        {
            Ok(pair) => pair,
            Err(_) => return Ok(Vec::new()),
        };
        if extract.disasm_text.starts_with(ALT_RUNTIME_NOTE_PREFIX) {
            return Ok(Vec::new());
        }
        let sidecar: PyDisasmSidecar = PyDisasmSidecar {
            runtime: extract.runtime,
            py_version: extract.py_version,
            instruction_count: extract.instruction_count,
            instructions,
        };
        let json: Vec<u8> =
            serde_json::to_vec_pretty(&sidecar).map_err(|e: serde_json::Error| {
                CoreError::PassFailure(format!("DR-PYDIS-0910: serialize disasm sidecar json: {e}"))
            })?;
        Ok(vec![dis_json_child(json)])
    }
}

fn dis_json_child(bytes: Vec<u8>) -> ChildArtifact {
    ChildArtifact {
        handle: ChildHandle {
            artifact_index: u32::MAX,
            relative_path: "disasm.dis.json".to_owned(),
            hint: Some(TERMINAL_HINT.to_owned()),
        },
        bytes,
    }
}

const ALT_RUNTIME_NOTE_PREFIX: &str = "; alt-runtime ";

pub static PY_DISASM_PASS: PyDisasmPass = PyDisasmPass;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PyDisasmExtract {
    pub runtime: String,
    pub py_version: Option<String>,
    pub disasm_text: String,
    pub instruction_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct PyDisasmSidecar {
    pub runtime: String,
    pub py_version: Option<String>,
    pub instruction_count: usize,
    pub instructions: Vec<Instruction>,
}

fn extract_for(bytes: &[u8]) -> CoreResult<(PyDisasmExtract, Vec<Instruction>)> {
    if let Some(rt) = detect_runtime(bytes) {
        let recovery: AltRecovery = recover(bytes, rt);
        let extract: PyDisasmExtract = PyDisasmExtract {
            runtime: recovery.label.to_owned(),
            py_version: None,
            disasm_text: recovery.disasm_text,
            instruction_count: recovery.instruction_count,
        };
        return Ok((extract, Vec::new()));
    }
    if bytes.len() < 4 {
        return Err(CoreError::PassFailure(
            "DR-PYDIS-0906: py.disasm: input too short for pyc header".to_owned(),
        ));
    }
    let magic: u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let version: PyVersion = pyversion_from_magic(magic).ok_or_else(|| {
        CoreError::PassFailure(format!(
            "DR-PYDIS-0907: py.disasm: unknown pyc magic 0x{magic:08x}"
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
    let text: String = crate::render_listing(&ins, code, version);
    let extract: PyDisasmExtract = PyDisasmExtract {
        runtime: "cpython".to_owned(),
        py_version: Some(format!("{}.{}", version.major, version.minor)),
        instruction_count: ins.len(),
        disasm_text: text,
    };
    Ok((extract, ins))
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
    let magic: u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    disrobe_py_marshal::pyversion_from_magic(magic).is_some()
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
    fn pass_output_kind_reflects_recovery() {
        let recovered: Vec<u8> = b"  0 RESUME 0\n  2 LOAD_CONST 0\n".to_vec();
        let a: Artifact = Artifact::new(Rung::Disasm, recovered, [0u8; 32]);
        assert!(
            PY_DISASM_PASS.output_kind(&a).is_mixed(),
            "recovered disasm must be Mixed so the runner invokes extract_children"
        );

        let parse_failed: Vec<u8> =
            b"; alt-runtime pypy detected; pypy payload decode failed: truncated\n".to_vec();
        let a: Artifact = Artifact::new(Rung::Disasm, parse_failed, [0u8; 32]);
        match PY_DISASM_PASS.output_kind(&a) {
            OutputKind::Bytes { format_tag, .. } => {
                assert_eq!(format_tag, "py.runtime-detected");
            }
            _ => panic!("expected Bytes for parse-failed result"),
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
