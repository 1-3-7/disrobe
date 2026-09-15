#![allow(
    clippy::case_sensitive_file_extension_comparisons,
    clippy::cast_possible_truncation
)]

pub mod deps;
pub mod pex_info;

use std::io::Cursor;
use std::path::{Path, PathBuf};

use zip::ZipArchive;

use crate::common::manifest::{EntryKind, EntryOrigin, EntryRecord, FreezerKind, FreezerManifest};
use crate::common::pyc::fingerprint;
use crate::common::quota::{
    ExtractionQuota, QuotaGuard, admit_charged_entry, default_quota, next_entry_uncompressed_limit,
    reject_declared_entry_over_cap,
};
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
    detect_and_extract_with_quota(bytes, source, out_dir, default_quota())
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
        let declared_size: u64 = file.size();
        let compressed_size: u64 = file.compressed_size();
        reject_declared_entry_over_cap(quota, &safe, declared_size)?;
        let read_limit: u64 = next_entry_uncompressed_limit(quota, &guard);
        let buf: Vec<u8> =
            crate::common::read_bounded::read_to_vec_limited(&mut file, declared_size, read_limit)
                .map_err(|e| Error::ZipEntry(safe.clone(), e.to_string()))?;
        let actual_size: u64 = u64::try_from(buf.len()).map_err(|_| Error::QuotaExceeded {
            entry: safe.clone(),
            reason: "actual uncompressed size exceeds u64".to_owned(),
        })?;
        admit_charged_entry(&mut guard, &safe, actual_size, compressed_size)?;
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

const MAX_PEX_ENTRY: u64 = 256 * 1024 * 1024;

fn read_entry(archive: &mut ZipArchive<Cursor<&[u8]>>, name: &str) -> Result<Option<Vec<u8>>> {
    match archive.by_name(name) {
        Ok(mut file) => {
            let declared_size: u64 = file.size();
            let buf: Vec<u8> = crate::common::read_bounded::read_to_vec_limited(
                &mut file,
                declared_size,
                MAX_PEX_ENTRY,
            )
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
    if trimmed.split('/').any(|c| c == ".." || c.contains(':')) {
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
