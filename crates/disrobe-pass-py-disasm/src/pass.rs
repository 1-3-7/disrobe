use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};
use disrobe_ir::{Envelope, decode_raw};
use disrobe_py_marshal::{CodeObject, Object, PyVersion, PycFile, pyversion_from_magic, read_pyc};
use serde::{Deserialize, Serialize};

use crate::Instruction;
use crate::alt_runtimes::{AltRuntime, detect_runtime};
use crate::{disassemble, render_dis};

pub const PASS_INPUT_PATH_CAP: &str = "raw.python";

#[derive(Debug, Default, Clone, Copy)]
pub struct PyDisasmPass;

impl LegacyPass for PyDisasmPass {
    const CONSUMES: &'static [Rung] = &[Rung::Raw];
    const EMITS: &'static [Rung] = &[Rung::Disasm];
    const REQUIRES: &'static [fn() -> Capability] =
        &[|| Capability::requires(PASS_INPUT_PATH_CAP, 1)];
    const PRODUCES: &'static [fn() -> Capability] = &[
        || Capability::produces("disasm.python", 1),
        || Capability::produces("py.runtime-detected", 1),
    ];

    fn id(&self) -> PassId {
        "disrobe-pass-py-disasm"
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let input: PassInput = decode_pass_input(&artifact.envelope);
        let recognized: bool =
            detect_runtime(&input.bytes).is_some() || is_cpython_pyc(&input.bytes);
        if !recognized {
            return Err(CoreError::PassFailure(
                "DR-PYDIS-PASS: input is not a recognized cpython or alt-runtime pyc".to_owned(),
            ));
        }
        let (runtime, py_version, disasm_text, instruction_count): (
            String,
            Option<String>,
            String,
            usize,
        ) = extract_for(&input.bytes)?;
        let report: PyDisasmPassReport = PyDisasmPassReport {
            source_path: input.source_path,
            runtime,
            py_version,
            instruction_count,
            disasm_text,
        };
        let payload: Vec<u8> = serde_json::to_vec(&report)
            .map_err(|e| CoreError::PassFailure(format!("DR-PYDIS-PASS encode: {e}")))?;
        let mut next: Artifact = Artifact::new(Rung::Disasm, payload, artifact.root_hash);
        for producer in <Self as LegacyPass>::PRODUCES {
            next.add_capability(producer());
        }
        Ok(next)
    }
}

fn is_cpython_pyc(bytes: &[u8]) -> bool {
    let Some(first4): Option<&[u8]> = bytes.get(0..4) else {
        return false;
    };
    let magic: u32 = u32::from_le_bytes([first4[0], first4[1], first4[2], first4[3]]);
    pyversion_from_magic(magic).is_some()
}

fn extract_for(bytes: &[u8]) -> CoreResult<(String, Option<String>, String, usize)> {
    if let Some(rt) = detect_runtime(bytes) {
        let label: &str = alt_label(rt);
        return Ok((
            label.to_owned(),
            None,
            format!("; alt-runtime {label} disassembly delegation pending\n"),
            0usize,
        ));
    }
    let first4: &[u8] = bytes.get(0..4).ok_or_else(|| {
        CoreError::PassFailure("DR-PYDIS-PASS: input too short for pyc header".to_owned())
    })?;
    let magic: u32 = u32::from_le_bytes([first4[0], first4[1], first4[2], first4[3]]);
    let version: PyVersion = pyversion_from_magic(magic).ok_or_else(|| {
        CoreError::PassFailure(format!("DR-PYDIS-PASS: unknown pyc magic 0x{magic:08x}"))
    })?;
    let pyc: PycFile = read_pyc(bytes)
        .map_err(|e| CoreError::PassFailure(format!("DR-PYDIS-PASS: pyc parse: {e}")))?;
    let code: &CodeObject = match &pyc.code {
        Object::Code(co) => co.as_ref(),
        _ => {
            return Err(CoreError::PassFailure(
                "DR-PYDIS-PASS: pyc top-level object is not a code object".to_owned(),
            ));
        }
    };
    let instructions: Vec<Instruction> = disassemble(code, version);
    let text: String = render_dis(&instructions);
    Ok((
        "cpython".to_owned(),
        Some(format!("{}.{}", version.major, version.minor)),
        text,
        instructions.len(),
    ))
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

#[derive(Debug, Clone)]
pub struct PassInput {
    pub source_path: String,
    pub bytes: Vec<u8>,
}

#[must_use]
pub fn decode_pass_input(envelope_bytes: &[u8]) -> PassInput {
    if let Ok(envelope) = Envelope::decode(envelope_bytes)
        && let Ok(raw) = decode_raw(&envelope.hot)
    {
        return PassInput {
            source_path: raw.source_path,
            bytes: raw.source_bytes,
        };
    }
    if let Ok(raw) = decode_raw(envelope_bytes) {
        return PassInput {
            source_path: raw.source_path,
            bytes: raw.source_bytes,
        };
    }
    PassInput {
        source_path: "<artifact>".to_owned(),
        bytes: envelope_bytes.to_vec(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PyDisasmPassReport {
    pub source_path: String,
    pub runtime: String,
    pub py_version: Option<String>,
    pub instruction_count: usize,
    pub disasm_text: String,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use disrobe_core::PassMetadata;
    use disrobe_ir::{Envelope, RawPayload, encode_raw};

    use super::*;

    fn synth_envelope(source_path: &str, body: &[u8]) -> Vec<u8> {
        let raw: RawPayload = RawPayload {
            source_path: source_path.to_owned(),
            source_bytes: body.to_vec(),
            source_hash: [0u8; 32],
            detected_format: None,
        };
        let hot: Vec<u8> = encode_raw(&raw).expect("encode raw");
        Envelope::new(Rung::Raw, hot, vec![])
            .encode()
            .expect("encode envelope")
    }

    #[test]
    fn py_disasm_pass_metadata_advertises_capabilities() {
        let p: PyDisasmPass = PyDisasmPass;
        assert_eq!(PassMetadata::id(&p), "disrobe-pass-py-disasm");
        assert_eq!(p.consumes(), &[Rung::Raw]);
        assert_eq!(p.emits(), &[Rung::Disasm]);
        assert_eq!(p.required_capabilities().len(), 1);
        assert_eq!(p.produced_capabilities().len(), 2);
    }

    #[test]
    fn pass_run_envelope_roundtrip() {
        let body: &[u8] = &[b'M', 5, 0x00, 0x00];
        let bytes: Vec<u8> = synth_envelope("frozen.mpy", body);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let out: Artifact = PyDisasmPass.run(&input).expect("run");
        assert_eq!(out.rung, Rung::Disasm);
        assert_eq!(out.root_hash, [7u8; 32]);
        let report: PyDisasmPassReport =
            serde_json::from_slice(&out.envelope).expect("decode report");
        assert_eq!(report.source_path, "frozen.mpy");
        assert_eq!(report.runtime, "micropython");
        assert_eq!(report.py_version, None);
    }

    #[test]
    fn py_disasm_pass_run_rejects_unrecognized_input() {
        let bytes: Vec<u8> = synth_envelope("notes.txt", &[0xffu8; 32]);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let err: CoreError = PyDisasmPass.run(&input).expect_err("must reject");
        assert!(format!("{err}").contains("DR-PYDIS-PASS"));
    }
}
