use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};
use disrobe_ir::{Envelope, decode_raw};
use serde::{Deserialize, Serialize};

use crate::debug::{dbg_kv, dbg_line, dbg_section};
use crate::{DoAbc, Swf, swf};

pub const PASS_INPUT_PATH_CAP: &str = "raw.swf";

#[derive(Debug, Default, Clone, Copy)]
pub struct As3Pass;

impl LegacyPass for As3Pass {
    const CONSUMES: &'static [Rung] = &[Rung::Raw];
    const EMITS: &'static [Rung] = &[Rung::Disasm];
    const REQUIRES: &'static [fn() -> Capability] =
        &[|| Capability::requires(PASS_INPUT_PATH_CAP, 1)];
    const PRODUCES: &'static [fn() -> Capability] = &[
        || Capability::produces("disasm.as3", 1),
        || Capability::produces("as3.swf-detected", 1),
    ];

    fn id(&self) -> PassId {
        "disrobe-pass-as3"
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        dbg_section("as3.pass");
        let input: PassInput = decode_pass_input(&artifact.envelope);
        dbg_kv("input_len", || input.bytes.len().to_string());
        let parsed: Swf = swf::parse(&input.bytes).map_err(|e: crate::error::Error| {
            dbg_line(|| format!("swf parse failed: {e}"));
            CoreError::PassFailure(format!("DR-AS3-PASS: {e}"))
        })?;
        dbg_kv("swf_version", || parsed.header.version.to_string());
        dbg_kv("compression", || format!("{:?}", parsed.header.compression));
        dbg_kv("tag_count", || parsed.tags.len().to_string());
        let abc_blocks: Vec<DoAbc> = parsed.collect_do_abc();
        dbg_kv("abc_block_count", || abc_blocks.len().to_string());
        let report: As3PassReport = As3PassReport {
            source_path: input.source_path,
            swf_version: parsed.header.version,
            compression: format!("{:?}", parsed.header.compression),
            file_length: parsed.header.file_length,
            frame_count: parsed.header.frame_count,
            tag_count: u32::try_from(parsed.tags.len()).unwrap_or(u32::MAX),
            abc_block_count: u32::try_from(abc_blocks.len()).unwrap_or(u32::MAX),
        };
        let payload: Vec<u8> = serde_json::to_vec(&report).map_err(|e: serde_json::Error| {
            CoreError::PassFailure(format!("DR-AS3-PASS: serialize: {e}"))
        })?;
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct As3PassReport {
    pub source_path: String,
    pub swf_version: u8,
    pub compression: String,
    pub file_length: u32,
    pub frame_count: u16,
    pub tag_count: u32,
    pub abc_block_count: u32,
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

    fn minimal_swf() -> Vec<u8> {
        let body: Vec<u8> = {
            let mut b: Vec<u8> = Vec::new();
            b.push(0x08);
            b.push(0x00);
            b.extend_from_slice(&24u16.to_le_bytes());
            b.extend_from_slice(&1u16.to_le_bytes());
            let end_header: u16 = 0;
            b.extend_from_slice(&end_header.to_le_bytes());
            b
        };
        let mut swf: Vec<u8> = Vec::new();
        swf.extend_from_slice(b"FWS");
        swf.push(10);
        let file_length: u32 = u32::try_from(8 + body.len()).unwrap();
        swf.extend_from_slice(&file_length.to_le_bytes());
        swf.extend_from_slice(&body);
        swf
    }

    #[test]
    fn as3_pass_metadata_advertises_capabilities() {
        let p: As3Pass = As3Pass;
        assert_eq!(PassMetadata::id(&p), "disrobe-pass-as3");
        assert_eq!(p.consumes(), &[Rung::Raw]);
        assert_eq!(p.emits(), &[Rung::Disasm]);
        assert_eq!(p.required_capabilities().len(), 1);
        assert_eq!(p.produced_capabilities().len(), 2);
    }

    #[test]
    fn pass_run_envelope_roundtrip() {
        let body: Vec<u8> = minimal_swf();
        let bytes: Vec<u8> = synth_envelope("raw.swf", &body);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let out: Artifact = As3Pass.run(&input).expect("run");
        assert_eq!(out.rung, Rung::Disasm);
        assert_eq!(out.root_hash, [7u8; 32]);
        let report: As3PassReport = serde_json::from_slice(&out.envelope).expect("decode report");
        assert_eq!(report.swf_version, 10);
        assert_eq!(report.frame_count, 1);
        assert_eq!(report.abc_block_count, 0);
    }

    #[test]
    fn as3_pass_run_rejects_unrecognized_input() {
        let bytes: Vec<u8> = synth_envelope("junk.bin", &[0xffu8; 16]);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let err: CoreError = As3Pass.run(&input).expect_err("must reject");
        assert!(format!("{err}").contains("DR-AS3-PASS"));
    }
}
