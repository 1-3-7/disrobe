use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};
use disrobe_ir::{Envelope, decode_raw};

use crate::envelope::{DecryptedPye, decrypt_pye};

pub const PASS_INPUT_PATH_CAP: &str = "raw.python";

#[derive(Debug, Default, Clone, Copy)]
pub struct SourceDefenderPass;

impl LegacyPass for SourceDefenderPass {
    const CONSUMES: &'static [Rung] = &[Rung::Raw];
    const EMITS: &'static [Rung] = &[Rung::Raw];
    const REQUIRES: &'static [fn() -> Capability] =
        &[|| Capability::requires(PASS_INPUT_PATH_CAP, 1)];
    const PRODUCES: &'static [fn() -> Capability] = &[
        || Capability::produces("sourcedefender.decrypted", 1),
        || Capability::produces("raw.python-bytecode", 1),
    ];

    fn id(&self) -> PassId {
        "disrobe-pass-sourcedefender"
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let input: PassInput = decode_pass_input(&artifact.envelope);
        let decrypted: DecryptedPye = decrypt_pye(&input.bytes, "chain.pye")
            .map_err(|e| CoreError::PassFailure(format!("DR-SD-PASS: {e}")))?;
        if decrypted.plaintext_msgpack.is_empty() {
            return Err(CoreError::PassFailure(
                "DR-SD-PASS: empty plaintext".to_owned(),
            ));
        }
        let mut next: Artifact =
            Artifact::new(Rung::Raw, decrypted.plaintext_msgpack, artifact.root_hash);
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

    fn synthetic_pye_frame() -> Vec<u8> {
        let iv_line: &str = "00000000000000000000";
        let ciphertext_line: &str = "00000";
        format!("-----BEGIN PYE FILE-----\n{iv_line}\n{ciphertext_line}\n-----END PYE FILE-----")
            .into_bytes()
    }

    #[test]
    fn sourcedefender_pass_metadata_advertises_capabilities() {
        let p: SourceDefenderPass = SourceDefenderPass;
        assert_eq!(PassMetadata::id(&p), "disrobe-pass-sourcedefender");
        assert_eq!(p.consumes(), &[Rung::Raw]);
        assert_eq!(p.emits(), &[Rung::Raw]);
        assert_eq!(p.required_capabilities().len(), 1);
        assert_eq!(p.produced_capabilities().len(), 2);
    }

    #[test]
    fn pass_run_envelope_roundtrip() {
        let body: Vec<u8> = synthetic_pye_frame();
        let bytes: Vec<u8> = synth_envelope("module.pye", &body);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let out: Artifact = SourceDefenderPass.run(&input).expect("run");
        assert_eq!(out.rung, Rung::Raw);
        assert_eq!(out.root_hash, [7u8; 32]);
        assert_eq!(
            out.envelope.len(),
            4,
            "four base85 ciphertext bytes decrypt to four plaintext bytes"
        );
    }

    #[test]
    fn sourcedefender_pass_run_rejects_unrecognized_input() {
        let bytes: Vec<u8> = synth_envelope("notes.txt", b"plain text not a pye envelope");
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let err: CoreError = SourceDefenderPass.run(&input).expect_err("must reject");
        assert!(format!("{err}").contains("DR-SD-PASS"));
    }
}
