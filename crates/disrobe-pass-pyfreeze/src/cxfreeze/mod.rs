pub mod layout;
pub mod lib_tree;
pub mod library_zip;

use std::path::{Path, PathBuf};

use crate::common::manifest::{EntryKind, EntryOrigin, EntryRecord, FreezerKind, FreezerManifest};
use crate::error::{Error, Result};
use crate::recover::{
    RecoveredModule, SurfacedNative, looks_like_bytecode, looks_like_native_extension,
    recover_bytecode_file, surface_native_file,
};
use crate::{MAX_FREEZE_DIR_ENTRIES, MAX_LIBRARY_ZIP_BYTES, read_file_bounded};

pub const MAX_FILESYSTEM_BYTECODE_ATTEMPTS: usize = 512;

#[derive(Debug, Clone)]
pub struct CxFreezeExtraction {
    pub manifest: FreezerManifest,
    pub library_zip_path: Option<PathBuf>,
    pub license_path: Option<PathBuf>,
    pub frozen_binary: PathBuf,
    pub extracted: Vec<library_zip::ExtractedEntry>,
    pub filesystem_entries: Vec<lib_tree::LibTreeEntry>,
    pub filesystem_symlinks_skipped: usize,
}

#[derive(Debug, Clone, Default)]
pub struct CxFreezeRecovery {
    pub modules: Vec<RecoveredModule>,
    pub native: Vec<SurfacedNative>,
    pub bytecode_failures: Vec<(String, String)>,
    pub native_failures: Vec<(String, String)>,
    pub filesystem_bytecode_attempted: usize,
    pub filesystem_bytecode_capped: usize,
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
        for entry in self.filesystem_bytecode() {
            if out.filesystem_bytecode_attempted >= MAX_FILESYSTEM_BYTECODE_ATTEMPTS {
                out.filesystem_bytecode_capped = out.filesystem_bytecode_capped.saturating_add(1);
                continue;
            }
            out.filesystem_bytecode_attempted = out.filesystem_bytecode_attempted.saturating_add(1);
            match recover_bytecode_file(&entry.relative_name, &entry.disk_path) {
                Ok(module) => out.modules.push(module),
                Err(e) => out
                    .bytecode_failures
                    .push((entry.relative_name.clone(), e.to_string())),
            }
        }
        out
    }

    pub fn filesystem_bytecode(&self) -> impl Iterator<Item = &lib_tree::LibTreeEntry> {
        self.filesystem_entries
            .iter()
            .filter(|entry: &&lib_tree::LibTreeEntry| looks_like_bytecode(&entry.relative_name))
    }

    #[must_use]
    pub fn sibling_native_extensions(&self) -> Vec<SurfacedNative> {
        let mut out: Vec<SurfacedNative> = Vec::new();
        for entry in &self.filesystem_entries {
            if out.len() >= MAX_FREEZE_DIR_ENTRIES {
                break;
            }
            if !looks_like_native_extension(&entry.relative_name) {
                continue;
            }
            if let Ok(surfaced) = surface_native_file(&entry.relative_name, &entry.disk_path) {
                out.push(surfaced);
            }
        }
        out
    }
}

pub fn detect_and_extract(binary_path: &Path, out_dir: &Path) -> Result<CxFreezeExtraction> {
    let layout: layout::CxFreezeLayout = layout::probe(binary_path)?;
    let lib_root: PathBuf = layout
        .library_zip
        .parent()
        .map_or_else(PathBuf::new, Path::to_path_buf);
    let tree: lib_tree::LibTreeWalk =
        lib_tree::walk(&lib_root, &[layout.library_zip.as_path(), out_dir])?;
    let zip_bytes: Vec<u8> = read_file_bounded(&layout.library_zip, MAX_LIBRARY_ZIP_BYTES)?;
    let extracted: Vec<library_zip::ExtractedEntry> =
        library_zip::extract_all(&zip_bytes, out_dir)?;

    let mut manifest: FreezerManifest =
        FreezerManifest::new(FreezerKind::CxFreeze, binary_path.display().to_string());
    let mut primary: Option<String> = None;
    for ent in &extracted {
        let kind: EntryKind = classify(&ent.name);
        if primary.is_none() && is_entry_point(&ent.name) {
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
    for ent in &tree.entries {
        let kind: EntryKind = classify(&ent.relative_name);
        if primary.is_none() && is_entry_point(&ent.relative_name) {
            primary = Some(ent.relative_name.clone());
        }
        let (major, minor): (Option<u8>, Option<u8>) = ent
            .python_version
            .map_or((None, None), |(major, minor): (u8, u8)| {
                (Some(major), Some(minor))
            });
        manifest.push(EntryRecord {
            name: ent.relative_name.clone(),
            kind,
            size: ent.size,
            compressed_size: None,
            python_major: major,
            python_minor: minor,
            source_path: Some(ent.disk_path.display().to_string()),
            origin: EntryOrigin::SiblingFile,
        });
    }
    manifest.primary_module = primary;

    Ok(CxFreezeExtraction {
        manifest,
        library_zip_path: Some(layout.library_zip),
        license_path: layout.license_file,
        frozen_binary: binary_path.to_path_buf(),
        extracted,
        filesystem_entries: tree.entries,
        filesystem_symlinks_skipped: tree.symlinks_skipped,
    })
}

fn is_entry_point(name: &str) -> bool {
    name.ends_with("__main__.pyc") || name.ends_with("__main__.py")
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
