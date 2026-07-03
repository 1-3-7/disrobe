use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};
use disrobe_ir::{Envelope, decode_raw};

use crate::debug::{dbg_hex, dbg_kv, dbg_line, dbg_section};
use crate::layered::{ContainerVariant, LayeredRecovery, classify_container, recover_layered};

pub const PASS_INPUT_PATH_CAP: &str = "raw.python";
pub const PASS_WALL_CAP: &str = "sourcedefender.runtime-license-key-wall";

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
        dbg_section("sourcedefender analyze");
        let input: PassInput = decode_pass_input(&artifact.envelope);
        dbg_kv("input-len", || input.bytes.len().to_string());
        dbg_hex("input-head", &input.bytes, 24);
        let filename: &str = if input.source_path.is_empty() {
            "chain.pye"
        } else {
            input.source_path.as_str()
        };
        dbg_kv("filename", || filename.to_owned());
        dbg_kv("classify", || {
            classify_container(&input.bytes).map_or_else(
                || "not a .pye container".to_owned(),
                |variant: ContainerVariant| format!(".pye {} container", variant.tag()),
            )
        });
        let recovery: LayeredRecovery = recover_layered(&input.bytes, filename).map_err(|e| {
            dbg_line(|| format!("layered recovery failed: {e}"));
            CoreError::PassFailure(format!("DR-SD-PASS: {e}"))
        })?;
        dbg_kv("variant", || recovery.variant.tag().to_owned());

        if let Some(wall) = recovery.wall.as_ref() {
            dbg_kv("wall", || {
                format!(
                    "{}: {} bytes ciphertext, key absent from artifact",
                    wall.reason.tag(),
                    wall.ciphertext_len
                )
            });
            let mut next: Artifact = Artifact::new(Rung::Raw, Vec::new(), artifact.root_hash);
            next.add_capability(Capability::produces("sourcedefender.detected", 1));
            let ct_major: u32 = u32::try_from(wall.ciphertext_len).unwrap_or(u32::MAX);
            next.add_capability(Capability::produces(PASS_WALL_CAP, ct_major));
            return Ok(next);
        }

        let payload: Vec<u8> = recovery
            .recovered_source
            .map(String::into_bytes)
            .or(recovery.recovered_marshal)
            .ok_or_else(|| {
                dbg_line(|| "legacy decrypt yielded no payload".to_owned());
                CoreError::PassFailure("DR-SD-PASS: legacy decrypt yielded no payload".to_owned())
            })?;
        dbg_kv("recovered-payload-len", || payload.len().to_string());
        if payload.is_empty() {
            return Err(CoreError::PassFailure(
                "DR-SD-PASS: empty recovered payload".to_owned(),
            ));
        }
        let mut next: Artifact = Artifact::new(Rung::Raw, payload, artifact.root_hash);
        next.add_capability(Capability::produces("sourcedefender.detected", 1));
        if recovery.variant == ContainerVariant::LegacyArmored {
            for producer in <Self as LegacyPass>::PRODUCES {
                next.add_capability(producer());
            }
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

    const LEGACY_HELLO: &[u8] = include_bytes!("../../../corpus/python/sourcedefender/hello.pye");
    const MODERN_TRIAL: &[u8] =
        include_bytes!("../../../corpus/python/sourcedefender/known_v16_trial.pye");

    fn has_cap(artifact: &Artifact, name: &str) -> bool {
        artifact
            .capabilities
            .iter()
            .any(|c: &Capability| c.name == name)
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
    fn pass_run_recovers_real_legacy_free_source() {
        let bytes: Vec<u8> = synth_envelope("hello.pye", LEGACY_HELLO);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let out: Artifact = SourceDefenderPass.run(&input).expect("run");
        assert_eq!(out.rung, Rung::Raw);
        assert_eq!(out.root_hash, [7u8; 32]);
        let recovered: &str = core::str::from_utf8(&out.envelope).expect("utf8 source");
        assert_eq!(recovered.trim_end(), "print(\"Hello World!\")");
        assert!(has_cap(&out, "sourcedefender.detected"));
    }

    #[test]
    fn pass_run_honest_walls_real_modern_trial_body() {
        let bytes: Vec<u8> = synth_envelope("known.pye", MODERN_TRIAL);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let out: Artifact = SourceDefenderPass.run(&input).expect("run");
        assert!(out.envelope.is_empty(), "walled body yields no plaintext");
        assert!(has_cap(&out, "sourcedefender.detected"));
        assert!(has_cap(&out, PASS_WALL_CAP));
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
