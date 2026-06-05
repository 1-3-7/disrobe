use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};
use disrobe_ir::{Envelope, decode_raw};
use serde::{Deserialize, Serialize};

use crate::decompile::to_python_assignment;
use crate::disasm::{Disassembly, disassemble};
use crate::polyglot::looks_like_pickle;
use crate::vm::{VmTrace, execute};

pub const PASS_INPUT_PATH_CAP: &str = "raw.pickle";

#[derive(Debug, Default, Clone, Copy)]
pub struct PickleLegacyPass;

impl LegacyPass for PickleLegacyPass {
    const CONSUMES: &'static [Rung] = &[Rung::Raw];
    const EMITS: &'static [Rung] = &[Rung::Surface];
    const REQUIRES: &'static [fn() -> Capability] =
        &[|| Capability::requires(PASS_INPUT_PATH_CAP, 1)];
    const PRODUCES: &'static [fn() -> Capability] =
        &[|| Capability::produces("pickle.stream-decompiled", 1)];

    fn id(&self) -> PassId {
        "disrobe-pass-pickle"
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let input: PassInput = decode_pass_input(&artifact.envelope);
        let is_proto2: bool = input.bytes.len() >= 2
            && input.bytes[0] == 0x80
            && input.bytes[1] <= crate::opcode::max_proto();
        if !is_proto2 && !looks_like_pickle(&input.bytes) {
            return Err(CoreError::PassFailure(
                "DR-PICKLE-PASS: input is not a recognizable pickle stream".to_owned(),
            ));
        }
        let dis: Disassembly = disassemble(&input.bytes)
            .map_err(|e| CoreError::PassFailure(format!("DR-PICKLE-PASS disasm: {e}")))?;
        let trace: VmTrace =
            execute(&dis).map_err(|e| CoreError::PassFailure(format!("DR-PICKLE-PASS vm: {e}")))?;
        let source: String = to_python_assignment(&trace.result);
        let report: PicklePassReport = PicklePassReport {
            source_path: input.source_path,
            protocol: dis.protocol,
            opcode_count: dis.instructions.len(),
            source,
        };
        let payload: Vec<u8> = serde_json::to_vec(&report)
            .map_err(|e| CoreError::PassFailure(format!("DR-PICKLE-PASS encode: {e}")))?;
        let mut next: Artifact = Artifact::new(Rung::Surface, payload, artifact.root_hash);
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PicklePassReport {
    pub source_path: String,
    pub protocol: u8,
    pub opcode_count: usize,
    pub source: String,
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
    fn pickle_pass_metadata_advertises_capabilities() {
        let p: PickleLegacyPass = PickleLegacyPass;
        assert_eq!(PassMetadata::id(&p), "disrobe-pass-pickle");
        assert_eq!(p.consumes(), &[Rung::Raw]);
        assert_eq!(p.emits(), &[Rung::Surface]);
        assert_eq!(p.required_capabilities().len(), 1);
        assert_eq!(p.produced_capabilities().len(), 1);
    }

    #[test]
    fn pass_run_envelope_roundtrip() {
        let bytes: Vec<u8> = synth_envelope("model.pkl", b"\x80\x02K\x2a.");
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let out: Artifact = PickleLegacyPass.run(&input).expect("run");
        assert_eq!(out.rung, Rung::Surface);
        assert_eq!(out.root_hash, [7u8; 32]);
        let report: PicklePassReport =
            serde_json::from_slice(&out.envelope).expect("decode report");
        assert_eq!(report.protocol, 2);
        assert_eq!(report.source_path, "model.pkl");
        assert!(report.source.contains("result = 42"));
    }

    #[test]
    fn pickle_pass_run_rejects_unrecognized_input() {
        let bytes: Vec<u8> = synth_envelope("junk.bin", &[0x01, 0x02, 0x03, 0x04]);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let err: CoreError = PickleLegacyPass.run(&input).expect_err("must reject");
        assert!(format!("{err}").contains("DR-PICKLE-PASS"));
    }
}
