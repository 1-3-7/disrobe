use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};
use disrobe_ir::{Envelope, decode_raw};
use disrobe_py_marshal::{CodeObject, Object, PyVersion, PycFile, pyversion_from_magic, read_pyc};
use serde::{Deserialize, Serialize};

use crate::Instruction;
use crate::alt_runtimes::recover::{AltRecovery, alt_label, recover};
use crate::alt_runtimes::{AltRuntime, detect_runtime};
use crate::{disassemble, render_listing};

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
        crate::debug::dbg_section("py.disasm");
        let input: PassInput = decode_pass_input(&artifact.envelope);
        crate::debug::dbg_kv("source-path", || input.source_path.clone());
        crate::debug::dbg_kv("input-len", || input.bytes.len().to_string());
        crate::debug::dbg_hex("input-magic", &input.bytes, 8);
        let alt: Option<AltRuntime> = detect_runtime(&input.bytes);
        let cpython: bool = is_cpython_pyc(&input.bytes);
        crate::debug::dbg_kv("classify", || match alt {
            Some(rt) => format!("alt-runtime {}", alt_label(rt)),
            None if cpython => "cpython pyc (magic recognized)".to_owned(),
            None => "unrecognized".to_owned(),
        });
        if alt.is_none() && !cpython {
            crate::debug::dbg_line(|| "not a recognized cpython or alt-runtime pyc".to_owned());
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
        crate::debug::dbg_kv("runtime", || runtime.clone());
        crate::debug::dbg_kv("py-version", || format!("{py_version:?}"));
        crate::debug::dbg_kv("instruction-count", || instruction_count.to_string());
        let report: PyDisasmPassReport = PyDisasmPassReport {
            source_path: input.source_path,
            runtime,
            py_version,
            instruction_count,
            disasm_text,
        };
        let disassembled: bool = report.instruction_count > 0;
        let payload: Vec<u8> = serde_json::to_vec(&report)
            .map_err(|e| CoreError::PassFailure(format!("DR-PYDIS-PASS encode: {e}")))?;
        let mut next: Artifact = Artifact::new(Rung::Disasm, payload, artifact.root_hash);
        next.add_capability(Capability::produces("py.runtime-detected", 1));
        if disassembled {
            next.add_capability(Capability::produces("disasm.python", 1));
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
        let recovery: AltRecovery = recover(bytes, rt);
        crate::debug::dbg_kv("alt-recovery", || {
            format!(
                "{} instructions={} source={}",
                recovery.label,
                recovery.instruction_count,
                recovery.source.is_some()
            )
        });
        return Ok((
            recovery.label.to_owned(),
            None,
            recovery.disasm_text,
            recovery.instruction_count,
        ));
    }
    let first4: &[u8] = bytes.get(0..4).ok_or_else(|| {
        CoreError::PassFailure("DR-PYDIS-PASS: input too short for pyc header".to_owned())
    })?;
    let magic: u32 = u32::from_le_bytes([first4[0], first4[1], first4[2], first4[3]]);
    let version: PyVersion = pyversion_from_magic(magic).ok_or_else(|| {
        crate::debug::dbg_kv("pyc-magic", || format!("0x{magic:08x} unknown"));
        CoreError::PassFailure(format!("DR-PYDIS-PASS: unknown pyc magic 0x{magic:08x}"))
    })?;
    crate::debug::dbg_kv("pyc-magic", || {
        format!(
            "0x{magic:08x} -> cpython {}.{}",
            version.major, version.minor
        )
    });
    let pyc: PycFile = read_pyc(bytes).map_err(|e| {
        crate::debug::dbg_kv("marshal-parse", || format!("failed: {e}"));
        CoreError::PassFailure(format!("DR-PYDIS-PASS: pyc parse: {e}"))
    })?;
    let code: &CodeObject = match &pyc.code {
        Object::Code(co) => co.as_ref(),
        other => {
            crate::debug::dbg_kv("marshal-parse", || {
                format!("top-level object is {} not code", object_tag(other))
            });
            return Err(CoreError::PassFailure(
                "DR-PYDIS-PASS: pyc top-level object is not a code object".to_owned(),
            ));
        }
    };
    crate::debug::dbg_kv("marshal-parse", || {
        format!(
            "code object code_len={} consts={} names={}",
            code.code.len(),
            code.consts.len(),
            code.names.len()
        )
    });
    let instructions: Vec<Instruction> = disassemble(code, version);
    let text: String = render_listing(&instructions, code, version);
    Ok((
        "cpython".to_owned(),
        Some(format!("{}.{}", version.major, version.minor)),
        text,
        instructions.len(),
    ))
}

const fn object_tag(obj: &Object) -> &'static str {
    match obj {
        Object::Code(_) => "code",
        Object::None => "none",
        Object::String { .. } | Object::Unicode { .. } | Object::ShortAscii { .. } => "string",
        Object::Tuple(_) => "tuple",
        Object::Int(_) => "int",
        _ => "other",
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

    #[test]
    fn pass_disassembles_real_native_mpy_instructions() {
        let fixture: &[u8] =
            include_bytes!("../../../corpus/python/alt_runtimes/micropython/hello_native_x64.mpy");
        let bytes: Vec<u8> = synth_envelope("hello_native.mpy", fixture);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let out: Artifact = PyDisasmPass.run(&input).expect("run");
        let report: PyDisasmPassReport =
            serde_json::from_slice(&out.envelope).expect("decode report");
        assert_eq!(report.runtime, "micropython-native");
        assert!(
            report.instruction_count > 0,
            "native disassembly must recover instructions, not wall at detection"
        );
        assert!(
            report.disasm_text.contains("push"),
            "x64 native listing must contain real x86 mnemonics"
        );
        assert!(out.has_capability(&Capability::produces("disasm.python", 1)));
    }
}
