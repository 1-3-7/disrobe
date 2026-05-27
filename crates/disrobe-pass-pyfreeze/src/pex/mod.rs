#![allow(
    clippy::case_sensitive_file_extension_comparisons,
    clippy::cast_possible_truncation
)]

pub mod deps;
pub mod pex_info;

use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use zip::ZipArchive;

use crate::common::manifest::{EntryKind, EntryOrigin, EntryRecord, FreezerKind, FreezerManifest};
use crate::common::pyc::fingerprint;
use crate::common::quota::{ExtractionQuota, QuotaGuard};
use crate::common::shebang::parse as parse_shebang;
use crate::common::zip_tail::locate;
use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct PexExtraction {
    pub manifest: FreezerManifest,
    pub pex_info: pex_info::PexInfo,
    pub wheels: Vec<deps::WheelRecord>,
    pub extracted: Vec<ExtractedEntry>,
}

#[derive(Debug, Clone)]
pub struct ExtractedEntry {
    pub name: String,
    pub disk_path: PathBuf,
}

pub fn detect_and_extract(bytes: &[u8], source: &Path, out_dir: &Path) -> Result<PexExtraction> {
    detect_and_extract_with_quota(bytes, source, out_dir, ExtractionQuota::default_safe())
}

pub fn detect_and_extract_with_quota(
    bytes: &[u8],
    source: &Path,
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<PexExtraction> {
    std::fs::create_dir_all(out_dir)?;
    let info: crate::common::zip_tail::ZipTailInfo = locate(bytes)?;
    let zip_slice: &[u8] = &bytes[info.archive_start_offset..];
    let mut archive: ZipArchive<Cursor<&[u8]>> =
        ZipArchive::new(Cursor::new(zip_slice)).map_err(|e| Error::Zip(e.to_string()))?;

    let pex_info_bytes: Vec<u8> =
        read_entry(&mut archive, "PEX-INFO")?.ok_or(Error::PexInfoMissing)?;
    let pex: pex_info::PexInfo = pex_info::parse(&pex_info_bytes)?;

    let shebang: Option<crate::common::shebang::Shebang> = parse_shebang(bytes);

    let mut manifest: FreezerManifest =
        FreezerManifest::new(FreezerKind::Pex, source.display().to_string());
    manifest.interpreter_hint = shebang.as_ref().and_then(|s| s.interpreter_hint.clone());
    manifest.primary_module.clone_from(&pex.entry_point);

    let mut extracted: Vec<ExtractedEntry> = Vec::new();
    let mut wheels: Vec<deps::WheelRecord> = Vec::new();
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    for i in 0..archive.len() {
        let mut file: zip::read::ZipFile<'_> =
            archive.by_index(i).map_err(|e| Error::Zip(e.to_string()))?;
        if file.is_dir() {
            continue;
        }
        let safe: String = sanitize(file.name())?;
        guard.admit_entry(&safe, file.size(), file.compressed_size())?;
        let mut buf: Vec<u8> = Vec::with_capacity(file.size() as usize);
        file.read_to_end(&mut buf)
            .map_err(|e| Error::ZipEntry(safe.clone(), e.to_string()))?;
        let disk_path: PathBuf = out_dir.join(&safe);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &buf)?;

        let kind: EntryKind = classify(&safe);
        if matches!(kind, EntryKind::Wheel) {
            wheels.push(deps::WheelRecord {
                name: safe.clone(),
                path: disk_path.clone(),
                size: file.size(),
            });
        }

        let fp: Option<crate::common::pyc::PycFingerprint> = if safe.ends_with(".pyc") {
            fingerprint(&buf)
        } else {
            None
        };
        manifest.push(EntryRecord {
            name: safe.clone(),
            kind,
            size: file.size(),
            compressed_size: Some(file.compressed_size()),
            python_major: fp.map(|f| f.python_major),
            python_minor: fp.map(|f| f.python_minor),
            source_path: Some(disk_path.display().to_string()),
            origin: if safe.starts_with(".deps/") {
                EntryOrigin::Deps
            } else {
                EntryOrigin::TrailingZip
            },
        });
        extracted.push(ExtractedEntry {
            name: safe,
            disk_path,
        });
    }

    Ok(PexExtraction {
        manifest,
        pex_info: pex,
        wheels,
        extracted,
    })
}

fn read_entry(archive: &mut ZipArchive<Cursor<&[u8]>>, name: &str) -> Result<Option<Vec<u8>>> {
    match archive.by_name(name) {
        Ok(mut file) => {
            let mut buf: Vec<u8> = Vec::with_capacity(file.size() as usize);
            file.read_to_end(&mut buf)
                .map_err(|e| Error::ZipEntry(name.to_owned(), e.to_string()))?;
            Ok(Some(buf))
        }
        Err(zip::result::ZipError::FileNotFound) => Ok(None),
        Err(e) => Err(Error::Zip(e.to_string())),
    }
}

fn classify(name: &str) -> EntryKind {
    if name.ends_with(".pyc") {
        EntryKind::PythonByteCode
    } else if name.ends_with(".py") {
        EntryKind::PythonModule
    } else if name.ends_with(".whl") {
        EntryKind::Wheel
    } else if name.ends_with(".pyd") || name.ends_with(".so") || name.ends_with(".dll") {
        EntryKind::NativeExtension
    } else if name == "PEX-INFO" || name.ends_with(".dist-info/METADATA") {
        EntryKind::Metadata
    } else {
        EntryKind::Resource
    }
}

fn sanitize(name: &str) -> Result<String> {
    let trimmed: String = name.replace('\\', "/");
    if trimmed.split('/').any(|c| c == "..") {
        return Err(Error::UnsafeEntryPath(name.to_owned()));
    }
    let cleaned: String = trimmed
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect::<Vec<_>>()
        .join("/");
    if cleaned.is_empty() {
        return Err(Error::UnsafeEntryPath(name.to_owned()));
    }
    Ok(cleaned)
}
