use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};
use disrobe_ir::{Envelope, decode_raw};
use serde::{Deserialize, Serialize};

use crate::debug::{dbg_kv, dbg_line, dbg_section};
use crate::error::Error;
use crate::extract::{ExtractOutput, ExtractedEntry, extract_archive};

pub const PASS_INPUT_PATH_CAP: &str = "raw.python";

#[derive(Debug, Default, Clone, Copy)]
pub struct PyInstallerPass;

impl LegacyPass for PyInstallerPass {
    const CONSUMES: &'static [Rung] = &[Rung::Raw];
    const EMITS: &'static [Rung] = &[Rung::Disasm];
    const REQUIRES: &'static [fn() -> Capability] =
        &[|| Capability::requires(PASS_INPUT_PATH_CAP, 1)];
    const PRODUCES: &'static [fn() -> Capability] = &[
        || Capability::produces("pyinstaller.extracted", 1),
        || Capability::produces("disasm.python", 1),
    ];

    fn id(&self) -> PassId {
        "disrobe-pass-pyinstaller"
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        dbg_section("pyinstaller.run");
        let input: PassInput = decode_pass_input(&artifact.envelope);
        dbg_kv("source_path", || input.source_path.clone());
        dbg_kv("input_len", || input.bytes.len().to_string());
        let extracted: ExtractOutput = extract_archive(&input.bytes).map_err(|e: Error| {
            dbg_line(|| format!("extract failed: {e}"));
            CoreError::PassFailure(format!("DR-PYINS-PASS: {e}"))
        })?;
        dbg_kv("python_version", || {
            format!(
                "{}.{}",
                extracted.cookie.python_major, extracted.cookie.python_minor
            )
        });
        dbg_kv("entry_count", || extracted.entries.len().to_string());
        dbg_kv("pyz_module_count", || {
            extracted.pyz_module_count.to_string()
        });
        dbg_kv("base_library_module_count", || {
            extracted.base_library_module_count.to_string()
        });
        dbg_kv("encryption", || {
            if extracted.encryption_key.is_some() {
                "aes-128-ctr keyed".to_owned()
            } else {
                "none".to_owned()
            }
        });
        if extracted.entries.is_empty() {
            dbg_line(|| "archive has no entries".to_owned());
            return Err(CoreError::PassFailure(
                "DR-PYINS-PASS: archive has no entries".to_owned(),
            ));
        }
        let entry_names: Vec<String> = extracted
            .entries
            .iter()
            .map(|e: &ExtractedEntry| e.toc.name.clone())
            .collect();
        let report: PyInstallerPassReport = PyInstallerPassReport {
            source_path: input.source_path,
            py_major: extracted.cookie.python_major,
            py_minor: extracted.cookie.python_minor,
            entry_count: extracted.entries.len(),
            entry_names,
        };
        let payload: Vec<u8> = serde_json::to_vec(&report)
            .map_err(|e| CoreError::PassFailure(format!("DR-PYINS-PASS encode: {e}")))?;
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
pub struct PyInstallerPassReport {
    pub source_path: String,
    pub py_major: u8,
    pub py_minor: u8,
    pub entry_count: usize,
    pub entry_names: Vec<String>,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use disrobe_core::PassMetadata;
    use disrobe_ir::{Envelope, RawPayload, encode_raw};

    use super::*;
    use crate::MEI_MAGIC;

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

    fn minimal_archive() -> Vec<u8> {
        let entry_data: &[u8] = b"ABCD";
        let name: &[u8] = b"hello";
        let entry_size: u32 = 18 + name.len() as u32;
        let mut toc: Vec<u8> = Vec::with_capacity(entry_size as usize);
        toc.extend_from_slice(&entry_size.to_be_bytes());
        toc.extend_from_slice(&0u32.to_be_bytes());
        toc.extend_from_slice(&(entry_data.len() as u32).to_be_bytes());
        toc.extend_from_slice(&(entry_data.len() as u32).to_be_bytes());
        toc.push(0u8);
        toc.push(b'x');
        toc.extend_from_slice(name);

        let toc_offset: u32 = entry_data.len() as u32;
        let toc_length: u32 = toc.len() as u32;
        let file_len: u32 = entry_data.len() as u32 + toc_length + 24;

        let mut cookie: Vec<u8> = Vec::with_capacity(24);
        cookie.extend_from_slice(MEI_MAGIC);
        cookie.extend_from_slice(&file_len.to_be_bytes());
        cookie.extend_from_slice(&toc_offset.to_be_bytes());
        cookie.extend_from_slice(&toc_length.to_be_bytes());
        cookie.extend_from_slice(&311u32.to_be_bytes());

        let mut image: Vec<u8> = Vec::with_capacity(file_len as usize);
        image.extend_from_slice(entry_data);
        image.extend_from_slice(&toc);
        image.extend_from_slice(&cookie);
        image
    }

    #[test]
    fn pyinstaller_pass_metadata_advertises_capabilities() {
        let p: PyInstallerPass = PyInstallerPass;
        assert_eq!(PassMetadata::id(&p), "disrobe-pass-pyinstaller");
        assert_eq!(p.consumes(), &[Rung::Raw]);
        assert_eq!(p.emits(), &[Rung::Disasm]);
        assert_eq!(p.required_capabilities().len(), 1);
        assert_eq!(p.produced_capabilities().len(), 2);
    }

    #[test]
    fn pass_run_envelope_roundtrip() {
        let body: Vec<u8> = minimal_archive();
        let bytes: Vec<u8> = synth_envelope("dist.exe", &body);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let out: Artifact = PyInstallerPass.run(&input).expect("run");
        assert_eq!(out.rung, Rung::Disasm);
        assert_eq!(out.root_hash, [7u8; 32]);
        let report: PyInstallerPassReport =
            serde_json::from_slice(&out.envelope).expect("decode report");
        assert_eq!(report.source_path, "dist.exe");
        assert_eq!(report.py_major, 3);
        assert_eq!(report.py_minor, 11);
        assert_eq!(report.entry_count, 1);
        assert_eq!(report.entry_names, vec!["hello".to_owned()]);
    }

    #[test]
    fn pyinstaller_pass_run_rejects_unrecognized_input() {
        let bytes: Vec<u8> = synth_envelope("notes.txt", &[0u8; 64]);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let err: CoreError = PyInstallerPass.run(&input).expect_err("must reject");
        assert!(format!("{err}").contains("DR-PYINS-PASS"));
    }
}
