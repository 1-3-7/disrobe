use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};
use disrobe_ir::{Envelope, decode_raw};
use serde::{Deserialize, Serialize};

use crate::detect::{Detection, detect};
use crate::format_wire::format_identity;

pub const PASS_INPUT_PATH_CAP: &str = "raw.shell";

#[derive(Debug, Default, Clone, Copy)]
pub struct ShellPass;

impl LegacyPass for ShellPass {
    const CONSUMES: &'static [Rung] = &[Rung::Raw];
    const EMITS: &'static [Rung] = &[Rung::Surface];
    const REQUIRES: &'static [fn() -> Capability] =
        &[|| Capability::requires(PASS_INPUT_PATH_CAP, 1)];
    const PRODUCES: &'static [fn() -> Capability] =
        &[|| Capability::produces("shell.dialect-detected", 1)];

    fn id(&self) -> PassId {
        "disrobe-pass-shell"
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let input: PassInput = decode_pass_input(&artifact.envelope);
        let detection: Detection = detect(&input.bytes);
        if detection.confidence < 0.5 {
            return Err(CoreError::PassFailure(
                "DR-SHELL-PASS: dialect below threshold".to_owned(),
            ));
        }
        let source: String = std::str::from_utf8(&input.bytes).map_or_else(
            |_| {
                format!(
                    "/* non-utf8 shell payload of {} bytes */",
                    input.bytes.len()
                )
            },
            format_identity,
        );
        let report: ShellPassReport = ShellPassReport {
            source_path: input.source_path,
            dialect: format!("{:?}", detection.dialect),
            family: format!("{:?}", detection.family),
            confidence: detection.confidence,
            source,
        };
        let payload: Vec<u8> = serde_json::to_vec(&report)
            .map_err(|e| CoreError::PassFailure(format!("DR-SHELL-PASS encode: {e}")))?;
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ShellPassReport {
    pub source_path: String,
    pub dialect: String,
    pub family: String,
    pub confidence: f32,
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
    fn shell_pass_metadata_advertises_capabilities() {
        let p: ShellPass = ShellPass;
        assert_eq!(PassMetadata::id(&p), "disrobe-pass-shell");
        assert_eq!(p.consumes(), &[Rung::Raw]);
        assert_eq!(p.emits(), &[Rung::Surface]);
        assert_eq!(p.required_capabilities().len(), 1);
        assert_eq!(p.produced_capabilities().len(), 1);
    }

    #[test]
    fn pass_run_envelope_roundtrip() {
        let body: &[u8] = b"#!/bin/bash\necho hi\n";
        let bytes: Vec<u8> = synth_envelope("script.sh", body);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let out: Artifact = ShellPass.run(&input).expect("run");
        assert_eq!(out.rung, Rung::Surface);
        assert_eq!(out.root_hash, [7u8; 32]);
        let report: ShellPassReport = serde_json::from_slice(&out.envelope).expect("decode report");
        assert_eq!(report.source_path, "script.sh");
        assert_eq!(report.dialect, "Bash");
        assert!(report.source.contains("echo hi"));
    }

    #[test]
    fn shell_pass_run_rejects_unrecognized_input() {
        let bytes: Vec<u8> = synth_envelope("junk.bin", &[0u8; 16]);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let err: CoreError = ShellPass.run(&input).expect_err("must reject");
        assert!(format!("{err}").contains("DR-SHELL-PASS"));
    }
}
