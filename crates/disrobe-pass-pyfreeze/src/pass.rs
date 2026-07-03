use std::path::{Path, PathBuf};

use disrobe_core::debug::DebugLog;
use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};
use disrobe_ir::{Envelope, decode_raw};
use serde::{Deserialize, Serialize};

use crate::bbfreeze;
use crate::briefcase;
use crate::common::manifest::{EntryKind, EntryOrigin, EntryRecord, FreezerKind, FreezerManifest};
use crate::cxfreeze;
use crate::debug::{dbg_enabled, dbg_kv, dbg_line, dbg_section};
use crate::detect::{Detection, detect_bytes};
use crate::error::{Error, Result};
use crate::pex;
use crate::py2exe;
use crate::pyoxidizer;
use crate::recover::{RecoveredModule, SurfacedNative};
use crate::recover::{
    looks_like_bytecode, looks_like_native_extension, recover_bytecode_file, surface_native_file,
};
use crate::shiv;
use crate::zipapp;
use crate::{MAX_FREEZE_INPUT_BYTES, read_file_bounded};

#[derive(Debug, Clone, Default)]
pub struct PyfreezeRecovery {
    pub modules: Vec<RecoveredModule>,
    pub native: Vec<SurfacedNative>,
}

impl PyfreezeRecovery {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.modules.is_empty() && self.native.is_empty()
    }

    #[must_use]
    pub fn equivalent_module_count(&self) -> usize {
        self.modules
            .iter()
            .filter(|m: &&RecoveredModule| m.roundtrip.is_equivalent())
            .count()
    }
}

#[derive(Debug, Clone)]
pub struct PyfreezeOutput {
    pub detection: Detection,
    pub manifest: FreezerManifest,
    pub out_dir: PathBuf,
    pub extracted_count: usize,
    pub recovery: PyfreezeRecovery,
}

pub fn extract(input: &Path, out_dir: &Path) -> Result<PyfreezeOutput> {
    dbg_section("pyfreeze extract");
    let bytes: Vec<u8> = read_file_bounded(input, MAX_FREEZE_INPUT_BYTES)?;
    dbg_kv("input", || input.display().to_string());
    dbg_kv("input-len", || bytes.len().to_string());
    let detection: Detection = detect_bytes(&bytes, Some(input));
    dbg_kv("dispatch", || format!("{:?}", detection.kind));

    let mut recovery: PyfreezeRecovery = PyfreezeRecovery::default();
    let manifest: FreezerManifest = match detection.kind {
        FreezerKind::Py2exe => {
            let res: py2exe::Py2exeExtraction = py2exe::detect_and_extract(&bytes, input, out_dir)?;
            dbg_kv("py2exe-python", || {
                match (res.manifest.python_major, res.manifest.python_minor) {
                    (Some(maj), Some(min)) => format!("{maj}.{min}"),
                    _ => "unknown".to_owned(),
                }
            });
            if let (Some(major), Some(minor)) =
                (res.manifest.python_major, res.manifest.python_minor)
                && let Ok(module) = res.recover_main(major, minor)
            {
                dbg_kv("py2exe-recover-main", || {
                    format!("{} -> {}", module.name, module.roundtrip.label())
                });
                recovery.modules.push(module);
            }
            dbg_kv("py2exe-bundled-modules", || {
                res.bundled_modules.len().to_string()
            });
            recover_disk_entries(
                res.bundled_modules.iter().map(
                    |e: &crate::cxfreeze::library_zip::ExtractedEntry| {
                        (e.name.as_str(), e.disk_path.as_path())
                    },
                ),
                &mut recovery,
            );
            res.manifest
        }
        FreezerKind::Bbfreeze => {
            let res: bbfreeze::BbfreezeExtraction = bbfreeze::detect_and_extract(input, out_dir)?;
            dbg_kv("bbfreeze-entries", || res.extracted.len().to_string());
            dbg_kv("bbfreeze-python-dll", || {
                res.python_dll.as_ref().map_or_else(
                    || "<none>".to_owned(),
                    |p: &PathBuf| p.display().to_string(),
                )
            });
            recover_disk_entries(
                res.extracted
                    .iter()
                    .map(|e: &crate::cxfreeze::library_zip::ExtractedEntry| {
                        (e.name.as_str(), e.disk_path.as_path())
                    }),
                &mut recovery,
            );
            if let Some(dll) = res.python_dll.as_ref()
                && let Some(name) = dll.file_name().and_then(|n| n.to_str())
                && let Ok(surfaced) = surface_native_file(name, dll)
            {
                recovery.native.push(surfaced);
            }
            res.manifest
        }
        FreezerKind::CxFreeze => {
            let res: cxfreeze::CxFreezeExtraction = cxfreeze::detect_and_extract(input, out_dir)?;
            dbg_kv("cxfreeze-library-zip", || {
                res.library_zip_path.as_ref().map_or_else(
                    || "<none>".to_owned(),
                    |p: &PathBuf| p.display().to_string(),
                )
            });
            dbg_kv("cxfreeze-entries", || res.extracted.len().to_string());
            let recovered: cxfreeze::CxFreezeRecovery = res.recover();
            if dbg_enabled() {
                for (module, reason) in &recovered.bytecode_failures {
                    dbg_kv("cxfreeze-bytecode-failed", || format!("{module}: {reason}"));
                }
                for (module, reason) in &recovered.native_failures {
                    dbg_kv("cxfreeze-native-failed", || format!("{module}: {reason}"));
                }
            }
            recovery.modules = recovered.modules;
            recovery.native = recovered.native;
            recovery.native.extend(res.sibling_native_extensions());
            res.manifest
        }
        FreezerKind::Pex => {
            let res: pex::PexExtraction = pex::detect_and_extract(&bytes, input, out_dir)?;
            dbg_kv("pex-entries", || res.extracted.len().to_string());
            recover_disk_entries(
                res.extracted
                    .iter()
                    .map(|e: &pex::ExtractedEntry| (e.name.as_str(), e.disk_path.as_path())),
                &mut recovery,
            );
            res.manifest
        }
        FreezerKind::Shiv => {
            let res: shiv::ShivExtraction = shiv::detect_and_extract(&bytes, input, out_dir)?;
            dbg_kv("shiv-entries", || res.extracted.len().to_string());
            recover_disk_entries(
                res.extracted
                    .iter()
                    .map(|e: &shiv::ExtractedEntry| (e.name.as_str(), e.disk_path.as_path())),
                &mut recovery,
            );
            res.manifest
        }
        FreezerKind::Zipapp => {
            let res: zipapp::ZipappExtraction = zipapp::detect_and_extract(&bytes, input, out_dir)?;
            dbg_kv("zipapp-entries", || res.extracted.len().to_string());
            recover_disk_entries(
                res.extracted
                    .iter()
                    .map(|e: &zipapp::ExtractedEntry| (e.name.as_str(), e.disk_path.as_path())),
                &mut recovery,
            );
            res.manifest
        }
        FreezerKind::Pyc => {
            let manifest: FreezerManifest = extract_pyc_file(input, out_dir, &bytes)?;
            recover_disk_entries(manifest_disk_entries(&manifest), &mut recovery);
            manifest
        }
        FreezerKind::PyOxidizer => {
            let res: pyoxidizer::PyOxidizerExtraction =
                pyoxidizer::detect_and_extract(&bytes, input, out_dir)?;
            dbg_kv("pyoxidizer-modules-extracted", || {
                res.extracted_modules.to_string()
            });
            dbg_kv("pyoxidizer-fs-relative-surfaced", || {
                res.fs_relative_modules_surfaced.to_string()
            });
            if res.extracted_modules == 0 {
                dbg_line(|| {
                    "pyoxidizer: no in-memory bytecode blob; manifest is count/inventory only"
                        .to_owned()
                });
            }
            recover_disk_entries(manifest_disk_entries(&res.manifest), &mut recovery);
            res.manifest
        }
        FreezerKind::Briefcase => {
            let res: briefcase::BriefcaseExtraction = briefcase::detect_and_extract(input)?;
            dbg_kv("briefcase-indexed", || {
                res.indexed_modules.len().to_string()
            });
            dbg_line(|| {
                "briefcase: on-disk sibling tree indexed in place; no in-container blob to carve"
                    .to_owned()
            });
            recover_disk_entries(manifest_disk_entries(&res.manifest), &mut recovery);
            res.manifest
        }
        FreezerKind::Unknown => {
            dbg_line(|| "unknown freezer: not extractable".to_owned());
            return Err(Error::UnknownFormat);
        }
    };

    dbg_kv("recovered-modules", || recovery.modules.len().to_string());
    dbg_kv("equivalent-modules", || {
        recovery.equivalent_module_count().to_string()
    });
    dbg_kv("surfaced-native", || recovery.native.len().to_string());

    let extracted_count: usize = manifest.entry_count;
    Ok(PyfreezeOutput {
        detection,
        manifest,
        out_dir: out_dir.to_path_buf(),
        extracted_count,
        recovery,
    })
}

fn extract_pyc_file(input: &Path, out_dir: &Path, bytes: &[u8]) -> Result<FreezerManifest> {
    std::fs::create_dir_all(out_dir)?;
    let Some(fp): Option<crate::common::pyc::PycFingerprint> =
        crate::common::pyc::fingerprint(bytes)
    else {
        let magic: u32 = bytes
            .get(0..4)
            .and_then(|s: &[u8]| <[u8; 4]>::try_from(s).ok())
            .map_or(0, u32::from_le_bytes);
        return Err(Error::UnknownPycMagic(magic));
    };
    if bytes.len() < fp.header_len {
        return Err(Error::UnknownPycMagic(fp.magic));
    }
    let name: String = input
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n: &&str| !n.is_empty())
        .map_or_else(|| "module.pyc".to_owned(), str::to_owned);
    let disk_path: PathBuf = out_dir.join(&name);
    std::fs::write(&disk_path, bytes)?;
    let size: u64 = u64::try_from(bytes.len()).map_err(|_| Error::QuotaExceeded {
        entry: name.clone(),
        reason: "pyc size exceeds u64".to_owned(),
    })?;
    let mut manifest: FreezerManifest =
        FreezerManifest::new(FreezerKind::Pyc, input.display().to_string());
    manifest.python_major = Some(fp.python_major);
    manifest.python_minor = Some(fp.python_minor);
    manifest.primary_module = Some(name.clone());
    manifest.push(EntryRecord {
        name,
        kind: EntryKind::PythonByteCode,
        size,
        compressed_size: None,
        python_major: Some(fp.python_major),
        python_minor: Some(fp.python_minor),
        source_path: Some(disk_path.display().to_string()),
        origin: EntryOrigin::Other,
    });
    Ok(manifest)
}

fn manifest_disk_entries(manifest: &FreezerManifest) -> impl Iterator<Item = (&str, &Path)> {
    manifest.entries.iter().filter_map(|e: &EntryRecord| {
        e.source_path
            .as_deref()
            .map(|p: &str| (e.name.as_str(), Path::new(p)))
    })
}

fn recover_disk_entries<'a>(
    entries: impl Iterator<Item = (&'a str, &'a Path)>,
    recovery: &mut PyfreezeRecovery,
) {
    for (name, disk_path) in entries {
        if looks_like_bytecode(name) {
            match recover_bytecode_file(name, disk_path) {
                Ok(module) => {
                    dbg_kv("recover-bytecode", || {
                        format!("{name} -> {}", module.roundtrip.label())
                    });
                    recovery.modules.push(module);
                }
                Err(e) => dbg_kv("recover-bytecode-failed", || format!("{name}: {e}")),
            }
        } else if looks_like_native_extension(name) {
            match surface_native_file(name, disk_path) {
                Ok(surfaced) => {
                    dbg_kv("surface-native", || {
                        format!(
                            "{name}: {:?}/{:?} {} insns",
                            surfaced.format, surfaced.arch, surfaced.instruction_count
                        )
                    });
                    recovery.native.push(surfaced);
                }
                Err(e) => dbg_kv("surface-native-failed", || format!("{name}: {e}")),
            }
        }
    }
}

pub fn detect(input: &Path) -> Result<Detection> {
    let bytes: Vec<u8> = read_file_bounded(input, MAX_FREEZE_INPUT_BYTES)?;
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
        let dbg: DebugLog = DebugLog::for_scope("pyfreeze");
        dbg.section("pyfreeze.pass");
        let input: PassInput = decode_pass_input(&artifact.envelope);
        dbg.kv("input_len", || input.bytes.len().to_string());
        let detection: Detection = detect_bytes(&input.bytes, None);
        dbg.kv("freezer_kind", || format!("{:?}", detection.kind));
        dbg.kv("confidence", || detection.confidence.to_string());
        if matches!(detection.kind, FreezerKind::Unknown) {
            dbg.line(|| "unknown freezer: not recoverable".to_owned());
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
