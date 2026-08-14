use std::path::{Path, PathBuf};

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
            dbg_kv("cxfreeze-filesystem-entries", || {
                res.filesystem_entries.len().to_string()
            });
            dbg_kv("cxfreeze-filesystem-symlinks-skipped", || {
                res.filesystem_symlinks_skipped.to_string()
            });
            let recovered: cxfreeze::CxFreezeRecovery = res.recover();
            dbg_kv("cxfreeze-filesystem-bytecode", || {
                format!(
                    "{} attempted, {} past the cap",
                    recovered.filesystem_bytecode_attempted, recovered.filesystem_bytecode_capped
                )
            });
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
