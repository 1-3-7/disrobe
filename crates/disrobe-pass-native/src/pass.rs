use std::collections::BTreeSet;

use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};
use disrobe_ir::{Envelope, decode_raw};
use serde::{Deserialize, Serialize};

use crate::decompile::{DecompilerBackend, Probe, probe_all};
use crate::format::{DetectedFormat, detect as detect_format};
use crate::obfuscators::{ObfuscatorHit, detect as detect_obfuscators};
use crate::packers::{Detection as PackerDetection, detect as detect_packers};

pub const PASS_INPUT_PATH_CAP: &str = "raw.native";

#[derive(Debug, Default, Clone, Copy)]
pub struct NativePass;

impl LegacyPass for NativePass {
    const CONSUMES: &'static [Rung] = &[Rung::Raw];
    const EMITS: &'static [Rung] = &[Rung::Disasm];
    const REQUIRES: &'static [fn() -> Capability] =
        &[|| Capability::requires(PASS_INPUT_PATH_CAP, 1)];
    const PRODUCES: &'static [fn() -> Capability] = &[
        || Capability::produces("native.format-detected", 1),
        || Capability::produces("native.packer-fingerprinted", 1),
        || Capability::produces("native.obfuscator-fingerprinted", 1),
        || Capability::produces("disasm.native", 1),
    ];

    fn id(&self) -> PassId {
        "disrobe-pass-native"
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let input: PassInput = decode_pass_input(&artifact.envelope);
        let format: DetectedFormat = detect_format(&input.bytes)
            .map_err(|e| CoreError::PassFailure(format!("DR-NATIVE-PASS: {e}")))?;
        let packers: Vec<PackerDetection> = detect_packers(&input.bytes);
        let obfuscators: Vec<ObfuscatorHit> = detect_obfuscators(&input.bytes);
        let backend_probe: NativePassReport = NativePassReport {
            source_path: input.source_path.clone(),
            format,
            packers,
            obfuscators,
            decompiler_probe: probe_all_serializable(),
            byte_count: input.bytes.len() as u64,
        };
        let payload: Vec<u8> = serde_json::to_vec(&backend_probe)
            .map_err(|e| CoreError::PassFailure(format!("DR-NATIVE-PASS encode: {e}")))?;
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativePassReport {
    pub source_path: String,
    pub format: DetectedFormat,
    pub packers: Vec<PackerDetection>,
    pub obfuscators: Vec<ObfuscatorHit>,
    pub decompiler_probe: Vec<DecompilerProbeSummary>,
    pub byte_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompilerProbeSummary {
    pub backend: DecompilerBackend,
    pub found: bool,
    pub note: Option<String>,
}

fn probe_all_serializable() -> Vec<DecompilerProbeSummary> {
    probe_all()
        .into_values()
        .map(|p: Probe| DecompilerProbeSummary {
            backend: p.backend,
            found: p.found,
            note: p.note,
        })
        .collect()
}

#[must_use]
pub fn distinct_packer_labels(report: &NativePassReport) -> BTreeSet<&'static str> {
    report
        .packers
        .iter()
        .map(|p: &PackerDetection| p.packer.label())
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use disrobe_core::PassMetadata;
    use disrobe_ir::{Envelope, RawPayload, encode_raw};

    use super::*;
    use crate::format::NativeFormat;

    fn synth_envelope(source_path: &str, body: &[u8]) -> Vec<u8> {
        let raw: RawPayload = RawPayload {
            source_path: source_path.to_owned(),
            source_bytes: body.to_vec(),
            source_hash: blake3::hash(body).into(),
            detected_format: Some("native".to_owned()),
        };
        let hot: Vec<u8> = encode_raw(&raw).expect("encode raw");
        let envelope: Envelope = Envelope::new(Rung::Raw, hot, vec![]);
        envelope.encode().expect("encode envelope")
    }

    #[test]
    fn native_pass_metadata_advertises_capabilities() {
        let p: NativePass = NativePass;
        assert_eq!(PassMetadata::id(&p), "disrobe-pass-native");
        assert_eq!(p.consumes(), &[Rung::Raw]);
        assert_eq!(p.emits(), &[Rung::Disasm]);
        assert_eq!(p.required_capabilities().len(), 1);
        assert_eq!(p.produced_capabilities().len(), 4);
    }

    #[test]
    fn native_pass_on_elf64_envelope_reports_format_and_emits_disasm() {
        let mut body: Vec<u8> = b"\x7FELF\x02\x01\x01\x00".to_vec();
        body.resize(0x80, 0);
        body[16] = 2;
        body[17] = 0;
        let bytes: Vec<u8> = synth_envelope("hello.elf", &body);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [0u8; 32],
        );
        let out: Artifact = NativePass.run(&input).expect("run");
        assert_eq!(out.rung, Rung::Disasm);
        let report: NativePassReport =
            serde_json::from_slice(&out.envelope).expect("decode report");
        assert_eq!(report.format.kind, NativeFormat::Elf64);
        assert_eq!(report.source_path, "hello.elf");
    }

    #[test]
    fn native_pass_on_unrecognized_input_returns_pass_failure() {
        let body: Vec<u8> = b"random non-binary text".to_vec();
        let bytes: Vec<u8> = synth_envelope("notes.txt", &body);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [0u8; 32],
        );
        let err: CoreError = NativePass.run(&input).expect_err("non-native");
        assert!(format!("{err}").contains("DR-NATIVE"));
    }

    #[test]
    fn native_pass_finds_upx_signature_in_envelope() {
        let mut body: Vec<u8> = b"\x7FELF\x02\x01\x01\x00".to_vec();
        body.resize(0x200, 0);
        body[16] = 2;
        body[17] = 0;
        body[0x100..0x104].copy_from_slice(b"UPX!");
        let bytes: Vec<u8> = synth_envelope("packed.elf", &body);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [0u8; 32],
        );
        let out: Artifact = NativePass.run(&input).expect("run");
        let report: NativePassReport = serde_json::from_slice(&out.envelope).expect("decode");
        let labels: BTreeSet<&'static str> = distinct_packer_labels(&report);
        assert!(labels.contains("upx"));
    }
}
