use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};
use disrobe_ir::{Envelope, decode_raw};
use serde::Serialize;

use crate::analyze::{ModuleSummary, analyze_module};
use crate::detect::{WasmDetection, detect};

pub const PASS_INPUT_PATH_CAP: &str = "raw.wasm";

#[derive(Debug, Default, Clone, Copy)]
pub struct WasmDeobLegacyPass;

impl LegacyPass for WasmDeobLegacyPass {
    const CONSUMES: &'static [Rung] = &[Rung::Raw];
    const EMITS: &'static [Rung] = &[Rung::Disasm];
    const REQUIRES: &'static [fn() -> Capability] =
        &[|| Capability::requires(PASS_INPUT_PATH_CAP, 1)];
    const PRODUCES: &'static [fn() -> Capability] =
        &[|| Capability::produces("wasm.module-analyzed", 1)];

    fn id(&self) -> PassId {
        "disrobe-pass-wasm-deob"
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let input: PassInput = decode_pass_input(&artifact.envelope);
        if input.bytes.len() < 8 || &input.bytes[..4] != b"\0asm" {
            return Err(CoreError::PassFailure(
                "DR-WASM-PASS: input lacks wasm magic header".to_owned(),
            ));
        }
        let detection: WasmDetection = detect(&input.bytes)
            .map_err(|e| CoreError::PassFailure(format!("DR-WASM-PASS detect: {e}")))?;
        let summary: ModuleSummary = analyze_module(&input.bytes)
            .map_err(|e| CoreError::PassFailure(format!("DR-WASM-PASS analyze: {e}")))?;
        let report: WasmPassReport = WasmPassReport {
            source_path: input.source_path,
            detection,
            summary,
        };
        let payload: Vec<u8> = serde_json::to_vec(&report)
            .map_err(|e| CoreError::PassFailure(format!("DR-WASM-PASS encode: {e}")))?;
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

#[derive(Debug, Clone, Serialize)]
pub struct WasmPassReport {
    pub source_path: String,
    pub detection: WasmDetection,
    pub summary: ModuleSummary,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use disrobe_core::PassMetadata;
    use disrobe_ir::{Envelope, RawPayload, encode_raw};

    use super::*;

    fn minimal_wasm() -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(8);
        v.extend_from_slice(b"\0asm");
        v.extend_from_slice(&1u32.to_le_bytes());
        v
    }

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
    fn wasm_pass_metadata_advertises_capabilities() {
        let p: WasmDeobLegacyPass = WasmDeobLegacyPass;
        assert_eq!(PassMetadata::id(&p), "disrobe-pass-wasm-deob");
        assert_eq!(p.consumes(), &[Rung::Raw]);
        assert_eq!(p.emits(), &[Rung::Disasm]);
        assert_eq!(p.required_capabilities().len(), 1);
        assert_eq!(p.produced_capabilities().len(), 1);
    }

    #[test]
    fn pass_run_envelope_roundtrip() {
        let bytes: Vec<u8> = synth_envelope("module.wasm", &minimal_wasm());
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let out: Artifact = WasmDeobLegacyPass.run(&input).expect("run");
        assert_eq!(out.rung, Rung::Disasm);
        assert_eq!(out.root_hash, [7u8; 32]);
        let s: &str = std::str::from_utf8(&out.envelope).expect("utf8 json");
        assert!(s.contains("\"detection\""));
        assert!(s.contains("\"summary\""));
        assert!(s.contains("\"source_path\":\"module.wasm\""));
        assert!(s.contains("\"function_count\":0"));
    }

    #[test]
    fn wasm_pass_run_rejects_unrecognized_input() {
        let bytes: Vec<u8> = synth_envelope("junk.bin", &[0u8; 16]);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let err: CoreError = WasmDeobLegacyPass.run(&input).expect_err("must reject");
        assert!(format!("{err}").contains("DR-WASM-PASS"));
    }
}
