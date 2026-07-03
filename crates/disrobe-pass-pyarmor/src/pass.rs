use std::path::PathBuf;

use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};
use disrobe_ir::{Envelope, decode_raw};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::unpack::{UnpackOptions, UnpackOutput, unpack_wrapper_text_with_options};

pub const PASS_INPUT_PATH_CAP: &str = "raw.pyc";

#[derive(Debug, Default, Clone, Copy)]
pub struct PyarmorPass;

impl LegacyPass for PyarmorPass {
    const CONSUMES: &'static [Rung] = &[Rung::Raw];
    const EMITS: &'static [Rung] = &[Rung::Disasm];
    const REQUIRES: &'static [fn() -> Capability] =
        &[|| Capability::requires(PASS_INPUT_PATH_CAP, 1)];
    const PRODUCES: &'static [fn() -> Capability] = &[
        || Capability::produces("pyarmor.unwrapped", 1),
        || Capability::produces("disasm.python", 1),
    ];

    fn id(&self) -> PassId {
        "disrobe-pass-pyarmor"
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        crate::debug::dbg_section("pyarmor.unpack");
        let decoded: PassInput = decode_pass_input(&artifact.envelope);
        crate::debug::dbg_kv("wrapper_len", || decoded.wrapper_bytes.len().to_string());
        let options: UnpackOptions = UnpackOptions::default();
        let path: PathBuf = PathBuf::from(decoded.source_path.as_str());
        let wrapper_text: &str = match std::str::from_utf8(&decoded.wrapper_bytes) {
            Ok(text) => text,
            Err(err) => {
                crate::debug::dbg_line(|| format!("wrapper bytes not utf-8: {err}"));
                return Err(CoreError::PassFailure(format!(
                    "DR-PYARM-PASS: wrapper bytes not utf-8: {err}"
                )));
            }
        };
        let output: UnpackOutput = unpack_wrapper_text_with_options(wrapper_text, &path, &options)
            .map_err(|e: Error| {
                crate::debug::dbg_line(|| format!("unpack failed: {e}"));
                CoreError::PassFailure(format!("{e}"))
            })?;
        crate::debug::dbg_kv("version", || format!("{:?}", output.detection.version));
        crate::debug::dbg_kv("protection", || {
            format!("{:?}", output.detection.protection)
        });
        crate::debug::debug_log().secret("recovered_key", output.key_hex.len() / 2);
        crate::debug::dbg_kv("plaintext_len", || output.plaintext.len().to_string());
        crate::debug::dbg_kv("marshal_error", || format!("{:?}", output.marshal_error));
        let payload: Vec<u8> = encode_pass_output(&decoded.source_path, &output)
            .map_err(|e: Error| CoreError::PassFailure(format!("{e}")))?;
        let mut next: Artifact = Artifact::new(Rung::Disasm, payload, artifact.root_hash);
        for producer in <Self as LegacyPass>::PRODUCES {
            next.add_capability(producer());
        }
        Ok(next)
    }
}

#[derive(Debug, Clone)]
pub struct PassInput {
    pub source_path: String,
    pub wrapper_bytes: Vec<u8>,
}

#[must_use]
pub fn decode_pass_input(envelope_bytes: &[u8]) -> PassInput {
    if let Ok(envelope) = Envelope::decode(envelope_bytes)
        && let Ok(raw) = decode_raw(&envelope.hot)
    {
        return PassInput {
            source_path: raw.source_path,
            wrapper_bytes: raw.source_bytes,
        };
    }
    if let Ok(raw) = decode_raw(envelope_bytes) {
        return PassInput {
            source_path: raw.source_path,
            wrapper_bytes: raw.source_bytes,
        };
    }
    PassInput {
        source_path: "<artifact>".to_owned(),
        wrapper_bytes: envelope_bytes.to_vec(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnpackSummary {
    pub source_path: String,
    pub version: String,
    pub protection: String,
    pub key_hex: String,
    pub iv_hex: String,
    pub wrap_stripped: bool,
    pub pyc_present: bool,
    pub plaintext_len: u32,
    pub marshal_error: Option<String>,
    pub fallback_reason: Option<String>,
}

pub fn encode_pass_output(source_path: &str, output: &UnpackOutput) -> Result<Vec<u8>> {
    let pyc: Vec<u8> = output.pyc.clone().unwrap_or_default();
    let summary: UnpackSummary = UnpackSummary {
        source_path: source_path.to_owned(),
        version: format!("{:?}", output.detection.version),
        protection: format!("{:?}", output.detection.protection),
        key_hex: output.key_hex.clone(),
        iv_hex: output.iv_hex.clone(),
        wrap_stripped: output.wrap_stripped,
        pyc_present: output.pyc.is_some(),
        plaintext_len: u32::try_from(output.plaintext.len()).unwrap_or(u32::MAX),
        marshal_error: output.marshal_error.clone(),
        fallback_reason: output.fallback_reason.clone(),
    };
    let header: Vec<u8> = serde_json::to_vec(&summary).map_err(std::io::Error::from)?;
    let header_len: u32 = u32::try_from(header.len())
        .map_err(|_| Error::UnknownWrapper("summary too large for u32 length prefix".to_owned()))?;
    let mut out: Vec<u8> = Vec::with_capacity(4 + header.len() + pyc.len());
    out.extend_from_slice(&header_len.to_le_bytes());
    out.extend_from_slice(&header);
    out.extend_from_slice(&pyc);
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use disrobe_core::PassMetadata;
    use disrobe_ir::{Envelope, RawPayload, encode_raw};

    use super::*;

    fn synth_v8_wrapper(payload_hex: &str) -> String {
        format!(
            "from pyarmor_runtime_000000 import __pyarmor__\n__pyarmor__(__name__, __file__, b'{payload_hex}')\n"
        )
    }

    fn synth_envelope(source_path: &str, wrapper_text: &str) -> Vec<u8> {
        let raw: RawPayload = RawPayload {
            source_path: source_path.to_owned(),
            source_bytes: wrapper_text.as_bytes().to_vec(),
            source_hash: blake3::hash(wrapper_text.as_bytes()).into(),
            detected_format: Some("python-source".to_owned()),
        };
        let hot: Vec<u8> = encode_raw(&raw).expect("encode raw");
        let envelope: Envelope = Envelope::new(Rung::Raw, hot, vec![]);
        envelope.encode().expect("encode envelope")
    }

    #[test]
    fn pyarmor_pass_metadata_advertises_capabilities() {
        let p: PyarmorPass = PyarmorPass;
        assert_eq!(PassMetadata::id(&p), "disrobe-pass-pyarmor");
        assert_eq!(p.consumes(), &[Rung::Raw]);
        assert_eq!(p.emits(), &[Rung::Disasm]);
        assert_eq!(p.required_capabilities().len(), 1);
        assert_eq!(p.produced_capabilities().len(), 2);
    }

    #[test]
    fn decode_pass_input_handles_real_envelope() {
        let bytes: Vec<u8> = synth_envelope("payload.py", "import x\n");
        let decoded: PassInput = decode_pass_input(&bytes);
        assert_eq!(decoded.source_path, "payload.py");
        assert_eq!(decoded.wrapper_bytes, b"import x\n");
    }

    #[test]
    fn decode_pass_input_falls_back_to_raw_payload_only() {
        let raw: RawPayload = RawPayload {
            source_path: "naked.py".to_owned(),
            source_bytes: b"y = 1\n".to_vec(),
            source_hash: [0u8; 32],
            detected_format: None,
        };
        let bytes: Vec<u8> = encode_raw(&raw).expect("encode raw");
        let decoded: PassInput = decode_pass_input(&bytes);
        assert_eq!(decoded.source_path, "naked.py");
        assert_eq!(decoded.wrapper_bytes, b"y = 1\n");
    }

    #[test]
    fn decode_pass_input_treats_random_bytes_as_anonymous_wrapper() {
        let bytes: Vec<u8> = b"def main(): pass\n".to_vec();
        let decoded: PassInput = decode_pass_input(&bytes);
        assert_eq!(decoded.source_path, "<artifact>");
        assert_eq!(decoded.wrapper_bytes, bytes);
    }

    #[test]
    fn pyarmor_pass_run_on_non_pyarmor_input_returns_pass_failure() {
        let wrapper: &str = "print('hello world')\n";
        let bytes: Vec<u8> = synth_envelope("hello.py", wrapper);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [9u8; 32],
        );
        let err: CoreError = PyarmorPass
            .run(&input)
            .expect_err("non-pyarmor should fail");
        let text: String = format!("{err}");
        assert!(
            text.contains("DR-PYARM") || text.contains("pass returned"),
            "unexpected error: {text}"
        );
    }

    #[test]
    fn pyarmor_pass_run_round_trip_emits_disasm_artifact_with_caps_on_synthetic_wrapper() {
        let wrapper: String = synth_v8_wrapper("PY009999deadbeef");
        let bytes: Vec<u8> = synth_envelope("mock.py", &wrapper);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [9u8; 32],
        );
        let result: CoreResult<Artifact> = PyarmorPass.run(&input);
        match result {
            Ok(out) => {
                assert_eq!(out.rung, Rung::Disasm);
                assert!(out.has_capability(&Capability::produces("pyarmor.unwrapped", 1)));
                assert!(out.has_capability(&Capability::produces("disasm.python", 1)));
                let header_len: u32 =
                    u32::from_le_bytes(out.envelope[..4].try_into().expect("len prefix"));
                let header: &[u8] = &out.envelope[4..4 + header_len as usize];
                let summary: UnpackSummary =
                    serde_json::from_slice(header).expect("summary parses");
                assert_eq!(summary.source_path, "mock.py");
            }
            Err(CoreError::PassFailure(msg)) => {
                assert!(
                    msg.starts_with("DR-PYARM"),
                    "expected DR-PYARM error, got {msg}"
                );
            }
            Err(other) => panic!("unexpected non-PassFailure error: {other}"),
        }
    }
}
