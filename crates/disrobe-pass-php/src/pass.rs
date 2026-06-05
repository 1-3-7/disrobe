use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};
use disrobe_ir::{Envelope, decode_raw};
use serde::{Deserialize, Serialize};

use crate::pipeline::{RecoveryReport, recover};
use crate::{PhpDetection, PhpKind, detect_php};

pub const PASS_INPUT_PATH_CAP: &str = "raw.php";

#[derive(Debug, Default, Clone, Copy)]
pub struct PhpPass;

impl LegacyPass for PhpPass {
    const CONSUMES: &'static [Rung] = &[Rung::Raw];
    const EMITS: &'static [Rung] = &[Rung::Surface];
    const REQUIRES: &'static [fn() -> Capability] =
        &[|| Capability::requires(PASS_INPUT_PATH_CAP, 1)];
    const PRODUCES: &'static [fn() -> Capability] =
        &[|| Capability::produces("php.kind-detected", 1)];

    fn id(&self) -> PassId {
        "disrobe-pass-php"
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let input: PassInput = decode_pass_input(&artifact.envelope);
        let detection: PhpDetection = detect_php(&input.bytes);
        if matches!(detection.kind, PhpKind::Unknown) {
            return Err(CoreError::PassFailure(
                "DR-PHP-PASS: no PHP source/phar/bcg signature".to_owned(),
            ));
        }
        let recovery: Option<RecoveryReport> = recover(&input.bytes, None).ok();
        let report: PhpPassReport = PhpPassReport {
            source_path: input.source_path,
            kind: format!("{:?}", detection.kind),
            confidence: format!("{:?}", detection.confidence),
            has_halt_compiler: detection.has_halt_compiler,
            open_tag_offset: detection.open_tag_offset,
            recovery,
        };
        let payload: Vec<u8> = serde_json::to_vec(&report).map_err(|e: serde_json::Error| {
            CoreError::PassFailure(format!("DR-PHP-PASS: serialize: {e}"))
        })?;
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
pub struct PhpPassReport {
    pub source_path: String,
    pub kind: String,
    pub confidence: String,
    pub has_halt_compiler: bool,
    pub open_tag_offset: Option<usize>,
    pub recovery: Option<RecoveryReport>,
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
    fn php_pass_metadata_advertises_capabilities() {
        let p: PhpPass = PhpPass;
        assert_eq!(PassMetadata::id(&p), "disrobe-pass-php");
        assert_eq!(p.consumes(), &[Rung::Raw]);
        assert_eq!(p.emits(), &[Rung::Surface]);
        assert_eq!(p.required_capabilities().len(), 1);
        assert_eq!(p.produced_capabilities().len(), 1);
    }

    #[test]
    fn pass_run_envelope_roundtrip() {
        let body: &[u8] = b"<?php eval(base64_decode('Zm9v')); ?>";
        let bytes: Vec<u8> = synth_envelope("raw.php", body);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let out: Artifact = PhpPass.run(&input).expect("run");
        assert_eq!(out.rung, Rung::Surface);
        assert_eq!(out.root_hash, [7u8; 32]);
        let report: PhpPassReport = serde_json::from_slice(&out.envelope).expect("decode report");
        assert_eq!(report.source_path, "raw.php");
        assert_eq!(report.kind, "Source");
        assert_eq!(report.open_tag_offset, Some(0));
    }

    #[test]
    fn php_pass_run_rejects_unrecognized_input() {
        let bytes: Vec<u8> = synth_envelope("junk.bin", &[0u8; 16]);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let err: CoreError = PhpPass.run(&input).expect_err("must reject");
        assert!(format!("{err}").contains("DR-PHP-PASS"));
    }
}
