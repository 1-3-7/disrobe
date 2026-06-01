use std::path::{Path, PathBuf};

use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};
use disrobe_ir::{Envelope, decode_raw};
use serde::{Deserialize, Serialize};

use crate::briefcase;
use crate::common::manifest::{FreezerKind, FreezerManifest};
use crate::cxfreeze;
use crate::detect::{Detection, detect_bytes};
use crate::error::{Error, Result};
use crate::pex;
use crate::py2exe;
use crate::pyoxidizer;
use crate::shiv;

#[derive(Debug, Clone)]
pub struct PyfreezeOutput {
    pub detection: Detection,
    pub manifest: FreezerManifest,
    pub out_dir: PathBuf,
    pub extracted_count: usize,
}

pub fn extract(input: &Path, out_dir: &Path) -> Result<PyfreezeOutput> {
    let bytes: Vec<u8> = std::fs::read(input)?;
    let detection: Detection = detect_bytes(&bytes, Some(input));

    let manifest: FreezerManifest = match detection.kind {
        FreezerKind::Py2exe => {
            let res: py2exe::Py2exeExtraction = py2exe::detect_and_extract(&bytes, input, out_dir)?;
            res.manifest
        }
        FreezerKind::CxFreeze => {
            let res: cxfreeze::CxFreezeExtraction = cxfreeze::detect_and_extract(input, out_dir)?;
            res.manifest
        }
        FreezerKind::Pex => {
            let res: pex::PexExtraction = pex::detect_and_extract(&bytes, input, out_dir)?;
            res.manifest
        }
        FreezerKind::Shiv => {
            let res: shiv::ShivExtraction = shiv::detect_and_extract(&bytes, input, out_dir)?;
            res.manifest
        }
        FreezerKind::PyOxidizer => {
            let res: pyoxidizer::PyOxidizerExtraction =
                pyoxidizer::detect_and_extract(&bytes, input, out_dir)?;
            res.manifest
        }
        FreezerKind::Briefcase => {
            let res: briefcase::BriefcaseExtraction = briefcase::detect_and_extract(input)?;
            res.manifest
        }
        FreezerKind::Unknown => return Err(Error::UnknownFormat),
    };

    let extracted_count: usize = manifest.entry_count;
    Ok(PyfreezeOutput {
        detection,
        manifest,
        out_dir: out_dir.to_path_buf(),
        extracted_count,
    })
}

pub fn detect(input: &Path) -> Result<Detection> {
    let bytes: Vec<u8> = std::fs::read(input)?;
    Ok(detect_bytes(&bytes, Some(input)))
}

pub const PASS_INPUT_PATH_CAP: &str = "raw.python";

#[derive(Debug, Default, Clone, Copy)]
pub struct PyfreezePass;

impl LegacyPass for PyfreezePass {
    const CONSUMES: &'static [Rung] = &[Rung::Raw];
    const EMITS: &'static [Rung] = &[Rung::Disasm];
    const REQUIRES: &'static [fn() -> Capability] =
        &[|| Capability::requires(PASS_INPUT_PATH_CAP, 1)];
    const PRODUCES: &'static [fn() -> Capability] =
        &[|| Capability::produces("pyfreeze.format-detected", 1)];

    fn id(&self) -> PassId {
        "disrobe-pass-pyfreeze"
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let input: PassInput = decode_pass_input(&artifact.envelope);
        let detection: Detection = detect_bytes(&input.bytes, None);
        if matches!(detection.kind, FreezerKind::Unknown) {
            return Err(CoreError::PassFailure(
                "DR-PYFRZ-PASS: unknown freezer".to_owned(),
            ));
        }
        let report: PyfreezePassReport = PyfreezePassReport {
            source_path: input.source_path,
            kind: format!("{:?}", detection.kind),
            confidence: detection.confidence,
            reasons: detection.reasons,
        };
        let payload: Vec<u8> = serde_json::to_vec(&report)
            .map_err(|e| CoreError::PassFailure(format!("DR-PYFRZ-PASS encode: {e}")))?;
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PyfreezePassReport {
    pub source_path: String,
    pub kind: String,
    pub confidence: f32,
    pub reasons: Vec<String>,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod pass_tests {
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

    fn pyoxidizer_blob() -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0u8; 64];
        buf.extend_from_slice(b"pyembed");
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(b"python-stdlib");
        buf
    }

    #[test]
    fn pyfreeze_pass_metadata_advertises_capabilities() {
        let p: PyfreezePass = PyfreezePass;
        assert_eq!(PassMetadata::id(&p), "disrobe-pass-pyfreeze");
        assert_eq!(p.consumes(), &[Rung::Raw]);
        assert_eq!(p.emits(), &[Rung::Disasm]);
        assert_eq!(p.required_capabilities().len(), 1);
        assert_eq!(p.produced_capabilities().len(), 1);
    }

    #[test]
    fn pass_run_envelope_roundtrip() {
        let body: Vec<u8> = pyoxidizer_blob();
        let bytes: Vec<u8> = synth_envelope("app.exe", &body);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let out: Artifact = PyfreezePass.run(&input).expect("run");
        assert_eq!(out.rung, Rung::Disasm);
        assert_eq!(out.root_hash, [7u8; 32]);
        let report: PyfreezePassReport =
            serde_json::from_slice(&out.envelope).expect("decode report");
        assert_eq!(report.source_path, "app.exe");
        assert_eq!(report.kind, "PyOxidizer");
    }

    #[test]
    fn pyfreeze_pass_run_rejects_unrecognized_input() {
        let bytes: Vec<u8> = synth_envelope("notes.txt", b"no freezer markers present here");
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let err: CoreError = PyfreezePass.run(&input).expect_err("must reject");
        assert!(format!("{err}").contains("DR-PYFRZ-PASS"));
    }
}
