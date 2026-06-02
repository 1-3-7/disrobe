use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};
use disrobe_ir::{Envelope, decode_raw};
use serde::{Deserialize, Serialize};

use crate::{GoAnalysis, analyze};

pub const PASS_INPUT_PATH_CAP: &str = "raw.go";

#[derive(Debug, Default, Clone, Copy)]
pub struct GoPass;

impl LegacyPass for GoPass {
    const CONSUMES: &'static [Rung] = &[Rung::Raw];
    const EMITS: &'static [Rung] = &[Rung::Surface];
    const REQUIRES: &'static [fn() -> Capability] =
        &[|| Capability::requires(PASS_INPUT_PATH_CAP, 1)];
    const PRODUCES: &'static [fn() -> Capability] =
        &[|| Capability::produces("go.image-analyzed", 1)];

    fn id(&self) -> PassId {
        "disrobe-pass-go"
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let input: PassInput = decode_pass_input(&artifact.envelope);
        let analysis: GoAnalysis = analyze(&input.bytes)
            .map_err(|e| CoreError::PassFailure(format!("DR-GO-PASS: {e}")))?;
        let report: GoPassReport = GoPassReport {
            source_path: input.source_path,
            image_kind: analysis.image_kind,
            ptr_size: analysis.ptr_size,
            pclntab_version: analysis.pclntab_version,
            buildversion: analysis.buildversion,
            func_count: u32::try_from(analysis.symbols.funcs.len()).unwrap_or(u32::MAX),
            package_count: u32::try_from(analysis.symbols.package_set.len()).unwrap_or(u32::MAX),
            garble_quality: format!("{:?}", analysis.garble.quality),
            embed_file_count: u32::try_from(analysis.embed.files.len()).unwrap_or(u32::MAX),
        };
        let payload: Vec<u8> = serde_json::to_vec(&report)
            .map_err(|e| CoreError::PassFailure(format!("DR-GO-PASS: serialize: {e}")))?;
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
pub struct GoPassReport {
    pub source_path: String,
    pub image_kind: String,
    pub ptr_size: u8,
    pub pclntab_version: String,
    pub buildversion: Option<String>,
    pub func_count: u32,
    pub package_count: u32,
    pub garble_quality: String,
    pub embed_file_count: u32,
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

    fn minimal_elf64() -> Vec<u8> {
        let mut e: Vec<u8> = vec![0u8; 64];
        e[0..4].copy_from_slice(b"\x7fELF");
        e[4] = 2;
        e[5] = 1;
        e[6] = 1;
        e[16..18].copy_from_slice(&2u16.to_le_bytes());
        e[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
        e[20..24].copy_from_slice(&1u32.to_le_bytes());
        e[52..54].copy_from_slice(&64u16.to_le_bytes());
        e[54..56].copy_from_slice(&56u16.to_le_bytes());
        e[58..60].copy_from_slice(&64u16.to_le_bytes());
        e
    }

    #[test]
    fn go_pass_metadata_advertises_capabilities() {
        let p: GoPass = GoPass;
        assert_eq!(PassMetadata::id(&p), "disrobe-pass-go");
        assert_eq!(p.consumes(), &[Rung::Raw]);
        assert_eq!(p.emits(), &[Rung::Surface]);
        assert_eq!(p.required_capabilities().len(), 1);
        assert_eq!(p.produced_capabilities().len(), 1);
    }

    #[test]
    fn pass_run_envelope_roundtrip() {
        let body: Vec<u8> = minimal_elf64();
        let bytes: Vec<u8> = synth_envelope("raw.go", &body);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let out: Artifact = GoPass.run(&input).expect("run");
        assert_eq!(out.rung, Rung::Surface);
        assert_eq!(out.root_hash, [7u8; 32]);
        let report: GoPassReport = serde_json::from_slice(&out.envelope).expect("decode report");
        assert_eq!(report.image_kind, "elf");
        assert_eq!(report.ptr_size, 8);
    }

    #[test]
    fn go_pass_run_rejects_unrecognized_input() {
        let bytes: Vec<u8> = synth_envelope("junk.bin", &[0u8; 64]);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let err: CoreError = GoPass.run(&input).expect_err("must reject");
        assert!(format!("{err}").contains("DR-GO-PASS"));
    }
}
