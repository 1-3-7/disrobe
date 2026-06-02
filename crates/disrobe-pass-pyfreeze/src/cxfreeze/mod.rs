pub mod layout;
pub mod library_zip;

use std::path::{Path, PathBuf};

use crate::common::manifest::{EntryKind, EntryOrigin, EntryRecord, FreezerKind, FreezerManifest};
use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct CxFreezeExtraction {
    pub manifest: FreezerManifest,
    pub library_zip_path: Option<PathBuf>,
    pub license_path: Option<PathBuf>,
    pub frozen_binary: PathBuf,
    pub extracted: Vec<library_zip::ExtractedEntry>,
}

pub fn detect_and_extract(binary_path: &Path, out_dir: &Path) -> Result<CxFreezeExtraction> {
    let layout: layout::CxFreezeLayout = layout::probe(binary_path)?;
    let zip_bytes: Vec<u8> = std::fs::read(&layout.library_zip)?;
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
