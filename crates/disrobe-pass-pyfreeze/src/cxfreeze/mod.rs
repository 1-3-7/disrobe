pub mod layout;
pub mod library_zip;

use std::path::{Path, PathBuf};

use crate::common::manifest::{EntryKind, EntryOrigin, EntryRecord, FreezerKind, FreezerManifest};
use crate::error::{Error, Result};
use crate::recover::{
    RecoveredModule, SurfacedNative, looks_like_bytecode, looks_like_native_extension,
    recover_bytecode_file, surface_native_file,
};
use crate::{MAX_FREEZE_DIR_ENTRIES, MAX_LIBRARY_ZIP_BYTES, read_file_bounded};

#[derive(Debug, Clone)]
pub struct CxFreezeExtraction {
    pub manifest: FreezerManifest,
    pub library_zip_path: Option<PathBuf>,
    pub license_path: Option<PathBuf>,
    pub frozen_binary: PathBuf,
    pub extracted: Vec<library_zip::ExtractedEntry>,
}

#[derive(Debug, Clone, Default)]
pub struct CxFreezeRecovery {
    pub modules: Vec<RecoveredModule>,
    pub native: Vec<SurfacedNative>,
    pub bytecode_failures: Vec<(String, String)>,
    pub native_failures: Vec<(String, String)>,
}

impl CxFreezeExtraction {
    #[must_use]
    pub fn recover(&self) -> CxFreezeRecovery {
        let mut out: CxFreezeRecovery = CxFreezeRecovery::default();
        for entry in &self.extracted {
            if looks_like_bytecode(&entry.name) {
                match recover_bytecode_file(&entry.name, &entry.disk_path) {
                    Ok(module) => out.modules.push(module),
                    Err(e) => out
                        .bytecode_failures
                        .push((entry.name.clone(), e.to_string())),
                }
            } else if looks_like_native_extension(&entry.name) {
                match surface_native_file(&entry.name, &entry.disk_path) {
                    Ok(surfaced) => out.native.push(surfaced),
                    Err(e) => out
                        .native_failures
                        .push((entry.name.clone(), e.to_string())),
                }
            }
        }
        out
    }

    #[must_use]
    pub fn sibling_native_extensions(&self) -> Vec<SurfacedNative> {
        let Some(zip) = self.library_zip_path.as_ref() else {
            return Vec::new();
        };
        let Some(lib_dir) = zip.parent() else {
            return Vec::new();
        };
        let mut out: Vec<SurfacedNative> = Vec::new();
        let Ok(read_dir) = std::fs::read_dir(lib_dir) else {
            return out;
        };
        for entry_result in read_dir.take(MAX_FREEZE_DIR_ENTRIES) {
            let Ok(entry): std::io::Result<std::fs::DirEntry> = entry_result else {
                continue;
            };
            let path: PathBuf = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if looks_like_native_extension(name)
                && let Ok(surfaced) = surface_native_file(name, &path)
            {
                out.push(surfaced);
            }
        }
        out
    }
}

pub fn detect_and_extract(binary_path: &Path, out_dir: &Path) -> Result<CxFreezeExtraction> {
    let layout: layout::CxFreezeLayout = layout::probe(binary_path)?;
    let zip_bytes: Vec<u8> = read_file_bounded(&layout.library_zip, MAX_LIBRARY_ZIP_BYTES)?;
    let extracted: Vec<library_zip::ExtractedEntry> =
        library_zip::extract_all(&zip_bytes, out_dir)?;

    let mut manifest: FreezerManifest =
        FreezerManifest::new(FreezerKind::CxFreeze, binary_path.display().to_string());
    let mut primary: Option<String> = None;
    for ent in &extracted {
        let kind: EntryKind = classify(&ent.name);
        if primary.is_none()
            && (ent.name.ends_with("__main__.pyc") || ent.name.ends_with("__main__.py"))
        {
            primary = Some(ent.name.clone());
        }
        let (maj, min): (u8, u8) = ent.python_version.unwrap_or((0, 0));
        manifest.push(EntryRecord {
            name: ent.name.clone(),
            kind,
            size: ent.uncompressed_size,
            compressed_size: Some(ent.compressed_size),
            python_major: if maj == 0 { None } else { Some(maj) },
            python_minor: if maj == 0 { None } else { Some(min) },
            source_path: Some(ent.disk_path.display().to_string()),
            origin: EntryOrigin::LibraryZip,
        });
    }
    manifest.primary_module = primary;

    Ok(CxFreezeExtraction {
        manifest,
        library_zip_path: Some(layout.library_zip),
        license_path: layout.license_file,
        frozen_binary: binary_path.to_path_buf(),
        extracted,
    })
}

#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn classify(name: &str) -> EntryKind {
    if name.ends_with(".pyc") {
        EntryKind::PythonByteCode
    } else if name.ends_with(".py") {
        EntryKind::PythonModule
    } else if name.ends_with(".pyd") || name.ends_with(".so") || name.ends_with(".dll") {
        EntryKind::NativeExtension
    } else if name.ends_with(".dist-info/METADATA")
        || name.ends_with(".dist-info/RECORD")
        || name.ends_with(".dist-info/WHEEL")
    {
        EntryKind::Metadata
    } else {
        EntryKind::Resource
    }
}

#[allow(dead_code)]
pub(crate) fn marker_error(binary: &Path, missing: Vec<String>) -> Error {
    Error::CxFreezeMissingSibling {
        binary: binary.display().to_string(),
        missing,
    }
}
