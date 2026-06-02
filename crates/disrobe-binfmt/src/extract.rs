use std::collections::BTreeMap;
use std::io::{Cursor, Read, Seek};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::asar::AsarLayout;
use crate::container::ContainerKind;
use crate::error::{Error, Result};
use crate::quota::{ExtractionQuota, QuotaGuard, QuotaReport, sanitize_entry_path};
use crate::{asar, container};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EntryCompression {
    Stored,
    Deflate,
    Deflate64,
    Bzip2,
    Lzma,
    Xz,
    Zstd,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedEntry {
    pub name: String,
    pub disk_path: Option<PathBuf>,
    pub uncompressed_size: u64,
    pub compressed_size: u64,
    pub compression: EntryCompression,
    pub is_executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionResult {
    pub kind: ContainerKind,
    pub entries: Vec<ExtractedEntry>,
    pub encoding: BTreeMap<String, EntryCompression>,
    pub integrity_violations: Vec<String>,
    pub quota: QuotaSummary,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct QuotaSummary {
    pub entries_accepted: usize,
    pub total_uncompressed_bytes: u64,
    pub total_compressed_bytes: u64,
    pub max_observed_ratio: u64,
}

impl From<&QuotaReport> for QuotaSummary {
    fn from(r: &QuotaReport) -> Self {
        Self {
            entries_accepted: r.entries_accepted,
            total_uncompressed_bytes: r.total_uncompressed_bytes,
            total_compressed_bytes: r.total_compressed_bytes,
            max_observed_ratio: r.max_observed_ratio,
        }
    }
}

pub fn extract_to(kind: ContainerKind, bytes: &[u8], out_dir: &Path) -> Result<ExtractionResult> {
    extract_to_with_quota(kind, bytes, out_dir, ExtractionQuota::default_safe())
}

pub fn extract_to_with_quota(
    kind: ContainerKind,
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    std::fs::create_dir_all(out_dir)?;
    match kind {
        ContainerKind::Zip
        | ContainerKind::Jar
        | ContainerKind::War
        | ContainerKind::Apk
        | ContainerKind::Xpi
        | ContainerKind::Whl
        | ContainerKind::Egg
        | ContainerKind::Crx
        | ContainerKind::Nupkg
        | ContainerKind::Vsix
        | ContainerKind::Pyz => extract_zip(kind, bytes, out_dir, quota),
        ContainerKind::Tar => extract_tar(kind, bytes, out_dir, quota),
        ContainerKind::TarGz => {
            extract_tar_compressed(kind, bytes, out_dir, quota, CompressionWrap::Gz)
        }
        ContainerKind::TarBz2 => {
            extract_tar_compressed(kind, bytes, out_dir, quota, CompressionWrap::Bz2)
        }
        ContainerKind::TarXz => {
            extract_tar_compressed(kind, bytes, out_dir, quota, CompressionWrap::Xz)
        }
        ContainerKind::TarZst => {
            extract_tar_compressed(kind, bytes, out_dir, quota, CompressionWrap::Zst)
        }
        ContainerKind::SevenZ => extract_sevenz(bytes, out_dir, quota),
        ContainerKind::Asar => extract_asar(bytes, out_dir, quota),
        ContainerKind::Deb => extract_deb(bytes, out_dir, quota),
        ContainerKind::Rpm => extract_rpm(bytes, out_dir, quota),
        ContainerKind::Cab => extract_cab(bytes, out_dir, quota),
        ContainerKind::Rar => {
            dispatch_external_or_fallback(kind, bytes, out_dir, Error::RarNotExtractable)
        }
        ContainerKind::Pkg => {
            dispatch_external_or_fallback(kind, bytes, out_dir, Error::PkgNoApacheDecoder)
        }
        ContainerKind::Dmg => {
            dispatch_external_or_fallback(kind, bytes, out_dir, Error::DmgNoApacheDecoder)
        }
        ContainerKind::Iso => {
            dispatch_external_or_fallback(kind, bytes, out_dir, Error::IsoNoApacheDecoder)
        }
        ContainerKind::Msix => extract_msix(bytes, out_dir, quota),
        ContainerKind::Oci | ContainerKind::DockerImage => {
            extract_oci_tarball(kind, bytes, out_dir, quota)
        }
        ContainerKind::AppImage => extract_appimage_stub(bytes, out_dir),
        ContainerKind::Snap => extract_snap_stub(bytes, out_dir),
        ContainerKind::Flatpak => Err(Error::MissingTool {
            container: "flatpak",
            tool: crate::containers::flatpak::flatpak_external_hint().tool_binary,
            hint: crate::containers::flatpak::flatpak_external_hint().install_hint,
        }),
        ContainerKind::Msi => extract_msi_metadata(bytes, out_dir),
        ContainerKind::Nsis => extract_nsis_metadata(bytes, out_dir),
        ContainerKind::InnoSetup => Err(Error::MissingTool {
            container: "innosetup",
            tool: crate::containers::innosetup::innosetup_external_hint().tool_binary,
            hint: crate::containers::innosetup::innosetup_external_hint().install_hint,
        }),
        ContainerKind::InstallShield => Err(Error::MissingTool {
            container: "installshield",
            tool: crate::containers::installshield::installshield_external_hint().tool_binary,
            hint: crate::containers::installshield::installshield_external_hint().install_hint,
        }),
        ContainerKind::Squashfs => extract_squashfs_summary(bytes, out_dir),
        ContainerKind::Cramfs => Err(Error::NoSource {
            kind: "cramfs",
            hint: "cramfs full extraction is not implemented in-tree; magic detected (use external `cramfsck` or 7z if available)",
        }),
        ContainerKind::Ext4 => Err(Error::NoSource {
            kind: "ext4",
            hint: "ext4 full extraction is not implemented in-tree; superblock parse only (use `debugfs` / mount loop on Linux for full filesystem walk)",
        }),
        ContainerKind::None => Err(Error::UnsupportedContainer(kind.label())),
    }
}

fn extract_msix(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let manifest: crate::containers::MsixManifest = crate::containers::parse_appx_manifest(bytes)
        .map_err(|e: Error| match e {
        Error::Zip(s) => Error::Msix(s),
        other => other,
    })?;
    let mut result: ExtractionResult = extract_zip(ContainerKind::Msix, bytes, out_dir, quota)?;
    let manifest_json: String = serde_json::to_string_pretty(&manifest)
        .unwrap_or_else(|_: serde_json::Error| String::new());
    if !manifest_json.is_empty() {
        let summary_path: PathBuf = out_dir.join(".disrobe-appx-manifest.json");
        std::fs::write(&summary_path, manifest_json.as_bytes())?;
        result.encoding.insert(
            ".disrobe-appx-manifest.json".to_owned(),
            EntryCompression::Stored,
        );
    }
    result.kind = ContainerKind::Msix;
    Ok(result)
}

fn extract_oci_tarball(
    kind: ContainerKind,
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let payload_kind: ContainerKind =
        container::detect_container(bytes).unwrap_or(ContainerKind::Tar);
    let mut result: ExtractionResult = match payload_kind {
        ContainerKind::TarGz => {
            extract_tar_compressed(kind, bytes, out_dir, quota, CompressionWrap::Gz)?
        }
        ContainerKind::TarBz2 => {
            extract_tar_compressed(kind, bytes, out_dir, quota, CompressionWrap::Bz2)?
        }
        ContainerKind::TarXz => {
            extract_tar_compressed(kind, bytes, out_dir, quota, CompressionWrap::Xz)?
        }
        ContainerKind::TarZst => {
            extract_tar_compressed(kind, bytes, out_dir, quota, CompressionWrap::Zst)?
        }
        _ => extract_tar(kind, bytes, out_dir, quota)?,
    };
    let manifest_path: PathBuf = out_dir.join("manifest.json");
    if manifest_path.is_file()
        && let Ok(bytes_read) = std::fs::read(&manifest_path)
        && let Ok(parsed) = crate::containers::parse_docker_manifest(&bytes_read)
    {
        let summary_json: String = serde_json::to_string_pretty(&parsed)
            .unwrap_or_else(|_: serde_json::Error| String::new());
        let summary_path: PathBuf = out_dir.join(".disrobe-docker-manifest.json");
        let _ = std::fs::write(&summary_path, summary_json.as_bytes());
        result.encoding.insert(
            ".disrobe-docker-manifest.json".to_owned(),
            EntryCompression::Stored,
        );
    }
    result.kind = kind;
    Ok(result)
}

fn extract_appimage_stub(bytes: &[u8], out_dir: &Path) -> Result<ExtractionResult> {
    let layout: crate::containers::AppImageLayout = crate::containers::parse_appimage(bytes)
        .map_err(|e: Error| match e {
            Error::Decompression(s) => Error::AppImage(s),
            other => other,
        })?;
    std::fs::create_dir_all(out_dir)?;
    let json: String =
        serde_json::to_string_pretty(&layout).unwrap_or_else(|_: serde_json::Error| String::new());
    let path: PathBuf = out_dir.join(".disrobe-appimage-layout.json");
    std::fs::write(&path, json.as_bytes())?;
    Err(Error::NoSource {
        kind: "appimage",
        hint: "appimage detected: ELF + squashfs offset parsed (see .disrobe-appimage-layout.json); full squashfs walk pending (use external 7z / unsquashfs to extract entries)",
    })
}

fn extract_snap_stub(bytes: &[u8], out_dir: &Path) -> Result<ExtractionResult> {
    let sb: crate::containers::squashfs::SquashfsSuperblock =
        crate::containers::squashfs::parse_squashfs_superblock(bytes, 0).map_err(
            |e: Error| match e {
                Error::Decompression(s) => Error::Snap(s),
                other => other,
            },
        )?;
    std::fs::create_dir_all(out_dir)?;
    let json: String =
        serde_json::to_string_pretty(&sb).unwrap_or_else(|_: serde_json::Error| String::new());
    let path: PathBuf = out_dir.join(".disrobe-snap-superblock.json");
    std::fs::write(&path, json.as_bytes())?;
    Err(Error::NoSource {
        kind: "snap",
        hint: "snap is a squashfs container: superblock parsed (see .disrobe-snap-superblock.json); full filesystem walk pending (use `unsquashfs` / 7z)",
    })
}

fn extract_msi_metadata(bytes: &[u8], out_dir: &Path) -> Result<ExtractionResult> {
    let summary: crate::containers::MsiSummary = crate::containers::parse_msi_minimal(bytes)
        .map_err(|e: Error| match e {
            Error::Decompression(s) => Error::Msi(s),
            other => other,
        })?;
    std::fs::create_dir_all(out_dir)?;
    let json: String =
        serde_json::to_string_pretty(&summary).unwrap_or_else(|_: serde_json::Error| String::new());
    let path: PathBuf = out_dir.join(".disrobe-msi-summary.json");
    std::fs::write(&path, json.as_bytes())?;
    let entries: Vec<ExtractedEntry> = vec![ExtractedEntry {
        name: ".disrobe-msi-summary.json".to_owned(),
        disk_path: Some(path),
        uncompressed_size: json.len() as u64,
        compressed_size: json.len() as u64,
        compression: EntryCompression::Stored,
        is_executable: false,
    }];
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    encoding.insert(
        ".disrobe-msi-summary.json".to_owned(),
        EntryCompression::Stored,
    );
    Ok(ExtractionResult {
        kind: ContainerKind::Msi,
        entries,
        encoding,
        integrity_violations: Vec::new(),
        quota: QuotaSummary {
            entries_accepted: 1,
            total_uncompressed_bytes: json.len() as u64,
            total_compressed_bytes: bytes.len() as u64,
            max_observed_ratio: 0,
        },
    })
}

fn extract_nsis_metadata(bytes: &[u8], out_dir: &Path) -> Result<ExtractionResult> {
    let header: crate::containers::NsisHeader = crate::containers::nsis::parse_nsis(bytes)
        .map_err(|e: Error| match e {
            Error::Decompression(s) => Error::Nsis(s),
            other => other,
        })?;
    std::fs::create_dir_all(out_dir)?;
    let json: String =
        serde_json::to_string_pretty(&header).unwrap_or_else(|_: serde_json::Error| String::new());
    let path: PathBuf = out_dir.join(".disrobe-nsis-header.json");
    std::fs::write(&path, json.as_bytes())?;
    Err(Error::NoSource {
        kind: "nsis",
        hint: "nsis first-header parsed (see .disrobe-nsis-header.json); full LZMA/bzip2/deflate payload extraction pending in-tree port of 7zip's NSIS extractor (use external 7z for now)",
    })
}

fn extract_squashfs_summary(bytes: &[u8], out_dir: &Path) -> Result<ExtractionResult> {
    let sb: crate::containers::squashfs::SquashfsSuperblock =
        crate::containers::squashfs::parse_squashfs_superblock(bytes, 0)?;
    std::fs::create_dir_all(out_dir)?;
    let json: String =
        serde_json::to_string_pretty(&sb).unwrap_or_else(|_: serde_json::Error| String::new());
    let path: PathBuf = out_dir.join(".disrobe-squashfs-superblock.json");
    std::fs::write(&path, json.as_bytes())?;
    Err(Error::NoSource {
        kind: "squashfs",
        hint: "squashfs superblock parsed (see .disrobe-squashfs-superblock.json); full filesystem walk via backhand crate pending - use `unsquashfs` / 7z for now",
    })
}

fn dispatch_external_or_fallback(
    kind: ContainerKind,
    bytes: &[u8],
    out_dir: &Path,
    fallback: Error,
) -> Result<ExtractionResult> {
    match crate::external_wrap::extract_via_tool(kind, bytes, out_dir) {
        Ok(r) => Ok(r),
        Err(Error::ExternalToolMissing { .. }) => Err(fallback),
        Err(other) => Err(other),
    }
}

fn extract_deb(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let mut archive: ar::Archive<Cursor<&[u8]>> = ar::Archive::new(cursor);
    let mut data_blob: Option<(String, Vec<u8>)> = None;
    while let Some(entry_result) = archive.next_entry() {
        let mut entry: ar::Entry<'_, Cursor<&[u8]>> =
            entry_result.map_err(|e| Error::Deb(e.to_string()))?;
        let name: String = String::from_utf8_lossy(entry.header().identifier()).into_owned();
        let trimmed: &str = name.trim_end_matches('/');
        if trimmed.starts_with("data.tar") {
            let mut buf: Vec<u8> =
                Vec::with_capacity(usize::try_from(entry.header().size()).unwrap_or(0));
            entry
                .read_to_end(&mut buf)
                .map_err(|e| Error::Deb(format!("reading {trimmed}: {e}")))?;
            data_blob = Some((trimmed.to_owned(), buf));
            break;
        }
    }
    let (name, payload): (String, Vec<u8>) = data_blob
        .ok_or_else(|| Error::Deb("data.tar.* member missing from deb ar archive".to_owned()))?;
    let wrap: CompressionWrap = match name.as_str() {
        "data.tar" => {
            let cursor: Cursor<Vec<u8>> = Cursor::new(payload);
            let mut result: ExtractionResult = walk_tar(
                ContainerKind::Deb,
                cursor,
                out_dir,
                quota,
                EntryCompression::Stored,
            )?;
            result.kind = ContainerKind::Deb;
            return Ok(result);
        }
        "data.tar.gz" => CompressionWrap::Gz,
        "data.tar.xz" => CompressionWrap::Xz,
        "data.tar.bz2" => CompressionWrap::Bz2,
        "data.tar.zst" => CompressionWrap::Zst,
        other => {
            return Err(Error::Deb(format!(
                "unsupported deb inner compression: {other}"
            )));
        }
    };
    let decoded: Vec<u8> = decompress_wrap_capped(
        &payload,
        wrap,
        quota.max_total_uncompressed,
        "<deb-data.tar>",
    )?;
    let cursor: Cursor<Vec<u8>> = Cursor::new(decoded);
    let inner_compression: EntryCompression = match wrap {
        CompressionWrap::Gz => EntryCompression::Deflate,
        CompressionWrap::Bz2 => EntryCompression::Bzip2,
        CompressionWrap::Xz => EntryCompression::Xz,
        CompressionWrap::Zst => EntryCompression::Zstd,
    };
    walk_tar(
        ContainerKind::Deb,
        cursor,
        out_dir,
        quota,
        inner_compression,
    )
}

const CPIO_NEWC_HEADER_LEN: usize = 110;
const CPIO_TRAILER_NAME: &str = "TRAILER!!!";

fn rpm_payload_wrap(compressor: rpm::CompressionType, payload: &[u8]) -> PayloadWrap {
    match compressor {
        rpm::CompressionType::None => sniff_payload_wrap(payload),
        rpm::CompressionType::Gzip => PayloadWrap::Compressed(CompressionWrap::Gz),
        rpm::CompressionType::Xz => PayloadWrap::Compressed(CompressionWrap::Xz),
        rpm::CompressionType::Zstd => PayloadWrap::Compressed(CompressionWrap::Zst),
        rpm::CompressionType::Bzip2 => PayloadWrap::Compressed(CompressionWrap::Bz2),
    }
}

fn sniff_payload_wrap(payload: &[u8]) -> PayloadWrap {
    match payload {
        [0x1f, 0x8b, ..] => PayloadWrap::Compressed(CompressionWrap::Gz),
        [0xfd, b'7', b'z', b'X', b'Z', 0x00, ..] => PayloadWrap::Compressed(CompressionWrap::Xz),
        [0x28, 0xb5, 0x2f, 0xfd, ..] => PayloadWrap::Compressed(CompressionWrap::Zst),
        [b'B', b'Z', b'h', ..] => PayloadWrap::Compressed(CompressionWrap::Bz2),
        _ => PayloadWrap::Stored,
    }
}

const fn rpm_entry_compression(wrap: PayloadWrap) -> EntryCompression {
    match wrap {
        PayloadWrap::Stored => EntryCompression::Stored,
        PayloadWrap::Compressed(CompressionWrap::Gz) => EntryCompression::Deflate,
        PayloadWrap::Compressed(CompressionWrap::Xz) => EntryCompression::Xz,
        PayloadWrap::Compressed(CompressionWrap::Zst) => EntryCompression::Zstd,
        PayloadWrap::Compressed(CompressionWrap::Bz2) => EntryCompression::Bzip2,
    }
}

fn extract_rpm(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let mut reader: Cursor<&[u8]> = Cursor::new(bytes);
    let package: rpm::Package =
        rpm::Package::parse(&mut reader).map_err(|e| Error::Rpm(e.to_string()))?;
    let compressor: rpm::CompressionType = package
        .metadata
        .get_payload_compressor()
        .map_err(|e| Error::Rpm(e.to_string()))?;
    let payload: &[u8] = package.content.as_slice();
    let compressed_size: u64 = payload.len() as u64;
    let wrap: PayloadWrap = rpm_payload_wrap(compressor, payload);
    let entry_compression: EntryCompression = rpm_entry_compression(wrap);
    let cpio: Vec<u8> = match wrap {
        PayloadWrap::Stored => payload.to_vec(),
        PayloadWrap::Compressed(inner) => decompress_wrap_capped(
            payload,
            inner,
            quota.max_total_uncompressed,
            "<rpm-payload>",
        )?,
    };
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::new();
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();
    let mut offset: usize = 0;
    while offset < cpio.len() {
        let Some(entry): Option<CpioEntry> = parse_cpio_entry(&cpio, &mut offset)? else {
            break;
        };
        if entry.name == CPIO_TRAILER_NAME {
            break;
        }
        if !is_cpio_regular_file(entry.mode) {
            continue;
        }
        let safe_name: String = match sanitize_entry_path(&entry.name) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("rpm-slip: {e}"));
                continue;
            }
        };
        let uncompressed_size: u64 = entry.data.len() as u64;
        guard.admit_entry(&safe_name, uncompressed_size, uncompressed_size)?;
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, entry.data)?;
        encoding.insert(safe_name.clone(), entry_compression);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size,
            compressed_size: uncompressed_size,
            compression: entry_compression,
            is_executable: entry.mode & 0o111 != 0,
        });
    }
    let mut summary: QuotaSummary = QuotaSummary::from(guard.report());
    summary.total_compressed_bytes = compressed_size;
    Ok(ExtractionResult {
        kind: ContainerKind::Rpm,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: summary,
    })
}

#[derive(Debug)]
struct CpioEntry {
    name: String,
    mode: u32,
    data: Vec<u8>,
}

const fn is_cpio_regular_file(mode: u32) -> bool {
    mode & 0o170_000 == 0o100_000
}

fn parse_cpio_entry(cpio: &[u8], offset: &mut usize) -> Result<Option<CpioEntry>> {
    let header_end: usize = offset.saturating_add(CPIO_NEWC_HEADER_LEN);
    let Some(header): Option<&[u8]> = cpio.get(*offset..header_end) else {
        return Ok(None);
    };
    let magic: &[u8] = &header[..6];
    if magic != b"070701" && magic != b"070702" {
        return Err(Error::Rpm(format!(
            "cpio: bad magic {:02x?} at offset {}",
            magic, *offset
        )));
    }
    let mode: u32 = cpio_hex_field(header, 14)?;
    let filesize: u32 = cpio_hex_field(header, 54)?;
    let namesize: u32 = cpio_hex_field(header, 94)?;
    let name_start: usize = header_end;
    let name_end: usize = name_start
        .checked_add(namesize as usize)
        .ok_or_else(|| Error::Rpm("cpio: namesize overflow".to_owned()))?;
    let name_bytes: &[u8] = cpio
        .get(name_start..name_end)
        .ok_or_else(|| Error::Rpm("cpio: truncated name field".to_owned()))?;
    let name: String = std::str::from_utf8(name_bytes.split_last().map_or(name_bytes, |(_, n)| n))
        .map_err(|e| Error::Rpm(format!("cpio: non-utf8 name: {e}")))?
        .to_owned();
    let data_start: usize = cpio_align4(name_end);
    let data_end: usize = data_start
        .checked_add(filesize as usize)
        .ok_or_else(|| Error::Rpm("cpio: filesize overflow".to_owned()))?;
    let data: Vec<u8> = cpio
        .get(data_start..data_end)
        .ok_or_else(|| Error::Rpm("cpio: truncated data field".to_owned()))?
        .to_vec();
    *offset = cpio_align4(data_end);
    Ok(Some(CpioEntry { name, mode, data }))
}

fn cpio_hex_field(header: &[u8], start: usize) -> Result<u32> {
    let field: &[u8] = header
        .get(start..start + 8)
        .ok_or_else(|| Error::Rpm("cpio: header field out of range".to_owned()))?;
    let text: &str = std::str::from_utf8(field)
        .map_err(|e| Error::Rpm(format!("cpio: non-ascii header field: {e}")))?;
    u32::from_str_radix(text, 16)
        .map_err(|e| Error::Rpm(format!("cpio: bad hex header field `{text}`: {e}")))
}

const fn cpio_align4(value: usize) -> usize {
    value.next_multiple_of(4)
}

fn extract_cab(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let mut cabinet: cab::Cabinet<Cursor<&[u8]>> =
        cab::Cabinet::new(cursor).map_err(|e| Error::Cab(e.to_string()))?;
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::new();
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();
    let names: Vec<String> = cabinet
        .folder_entries()
        .flat_map(|folder| {
            folder
                .file_entries()
                .map(|file| file.name().to_owned())
                .collect::<Vec<String>>()
        })
        .collect();
    for raw_name in names {
        let safe_name: String = match sanitize_entry_path(&raw_name) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("cab-slip: {e}"));
                continue;
            }
        };
        let mut reader: cab::FileReader<Cursor<&[u8]>> = cabinet
            .read_file(&raw_name)
            .map_err(|e| Error::Cab(e.to_string()))?;
        let mut buf: Vec<u8> = Vec::new();
        reader
            .read_to_end(&mut buf)
            .map_err(|e| Error::Cab(format!("reading {raw_name}: {e}")))?;
        let uncompressed_size: u64 = buf.len() as u64;
        guard.admit_entry(&safe_name, uncompressed_size, uncompressed_size)?;
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &buf)?;
        encoding.insert(safe_name.clone(), EntryCompression::Other);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size,
            compressed_size: uncompressed_size,
            compression: EntryCompression::Other,
            is_executable: false,
        });
    }
    Ok(ExtractionResult {
        kind: ContainerKind::Cab,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

pub fn detect_and_extract_with_hint(
    bytes: &[u8],
    source_hint: Option<&Path>,
    out_dir: &Path,
) -> Result<ExtractionResult> {
    let kind: ContainerKind =
        container::detect_container_with_hint(bytes, source_hint).ok_or(Error::UnknownContainer)?;
    extract_to(kind, bytes, out_dir)
}

#[derive(Debug, Clone, Copy)]
enum CompressionWrap {
    Gz,
    Bz2,
    Xz,
    Zst,
}

#[derive(Debug, Clone, Copy)]
enum PayloadWrap {
    Stored,
    Compressed(CompressionWrap),
}

fn extract_zip(
    kind: ContainerKind,
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let mut archive: zip::ZipArchive<Cursor<&[u8]>> =
        zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| Error::Zip(e.to_string()))?;
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut entries: Vec<ExtractedEntry> = Vec::with_capacity(archive.len());
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();

    for i in 0..archive.len() {
        let mut file: zip::read::ZipFile<'_> =
            archive.by_index(i).map_err(|e| Error::Zip(e.to_string()))?;
        let raw_name: String = file.name().to_owned();
        let safe_name: String = match sanitize_entry_path(&raw_name) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("zip-slip: {e}"));
                continue;
            }
        };
        if file.is_dir() {
            continue;
        }
        let compressed_size: u64 = file.compressed_size();
        let uncompressed_size: u64 = file.size();
        guard.admit_entry(&safe_name, uncompressed_size, compressed_size)?;
        let mut buf: Vec<u8> = Vec::with_capacity(usize::try_from(uncompressed_size).unwrap_or(0));
        file.read_to_end(&mut buf).map_err(|e| Error::ZipEntry {
            name: safe_name.clone(),
            reason: e.to_string(),
        })?;
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &buf)?;
        let compression: EntryCompression = encode_method(file.compression());
        encoding.insert(safe_name.clone(), compression);
        entries.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size,
            compressed_size,
            compression,
            is_executable: false,
        });
    }
    Ok(ExtractionResult {
        kind,
        entries,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn encode_method(m: zip::CompressionMethod) -> EntryCompression {
    if m == zip::CompressionMethod::Stored {
        EntryCompression::Stored
    } else if m == zip::CompressionMethod::Deflated {
        EntryCompression::Deflate
    } else if m == zip::CompressionMethod::Deflate64 {
        EntryCompression::Deflate64
    } else if m == zip::CompressionMethod::Zstd {
        EntryCompression::Zstd
    } else if m == zip::CompressionMethod::BZIP2 {
        EntryCompression::Bzip2
    } else if m == zip::CompressionMethod::LZMA {
        EntryCompression::Lzma
    } else if m == zip::CompressionMethod::XZ {
        EntryCompression::Xz
    } else {
        EntryCompression::Other
    }
}

fn extract_tar(
    kind: ContainerKind,
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let cursor: Cursor<&[u8]> = Cursor::new(bytes);
    walk_tar(kind, cursor, out_dir, quota, EntryCompression::Stored)
}

fn extract_tar_compressed(
    kind: ContainerKind,
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
    wrap: CompressionWrap,
) -> Result<ExtractionResult> {
    let decoded: Vec<u8> =
        decompress_wrap_capped(bytes, wrap, quota.max_total_uncompressed, "<tar-stream>")?;
    let cursor: Cursor<Vec<u8>> = Cursor::new(decoded);
    let inner_compression: EntryCompression = match wrap {
        CompressionWrap::Gz => EntryCompression::Deflate,
        CompressionWrap::Bz2 => EntryCompression::Bzip2,
        CompressionWrap::Xz => EntryCompression::Xz,
        CompressionWrap::Zst => EntryCompression::Zstd,
    };
    walk_tar(kind, cursor, out_dir, quota, inner_compression)
}

fn decompress_wrap_capped(
    bytes: &[u8],
    wrap: CompressionWrap,
    cap: u64,
    entry: &str,
) -> Result<Vec<u8>> {
    let limit: u64 = cap.saturating_add(1);
    let mut out: Vec<u8> = Vec::new();
    let read: u64 = match wrap {
        CompressionWrap::Gz => {
            let d: flate2::read::GzDecoder<&[u8]> = flate2::read::GzDecoder::new(bytes);
            std::io::copy(&mut d.take(limit), &mut out)
        }
        CompressionWrap::Bz2 => {
            let d: bzip2_rs::DecoderReader<&[u8]> = bzip2_rs::DecoderReader::new(bytes);
            std::io::copy(&mut d.take(limit), &mut out)
        }
        CompressionWrap::Xz => {
            let d: liblzma::read::XzDecoder<&[u8]> = liblzma::read::XzDecoder::new(bytes);
            std::io::copy(&mut d.take(limit), &mut out)
        }
        CompressionWrap::Zst => {
            let d: zstd::stream::read::Decoder<'static, std::io::BufReader<&[u8]>> =
                zstd::stream::read::Decoder::new(bytes)
                    .map_err(|e| Error::Decompression(e.to_string()))?;
            std::io::copy(&mut d.take(limit), &mut out)
        }
    }
    .map_err(|e| Error::Decompression(e.to_string()))?;
    if read > cap {
        return Err(Error::QuotaExceeded {
            entry: entry.to_owned(),
            reason: format!("decompressed stream exceeds bomb cap {cap}"),
        });
    }
    Ok(out)
}

fn walk_tar<R: Read + Seek>(
    kind: ContainerKind,
    reader: R,
    out_dir: &Path,
    quota: ExtractionQuota,
    inner_compression: EntryCompression,
) -> Result<ExtractionResult> {
    let mut archive: tar::Archive<R> = tar::Archive::new(reader);
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::new();
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();
    let raw_entries: tar::Entries<'_, R> =
        archive.entries().map_err(|e| Error::Tar(e.to_string()))?;
    for entry_result in raw_entries {
        let mut entry: tar::Entry<'_, R> = entry_result.map_err(|e| Error::Tar(e.to_string()))?;
        let entry_type: tar::EntryType = entry.header().entry_type();
        if !entry_type.is_file() {
            continue;
        }
        let mode_bits: u32 = entry.header().mode().unwrap_or(0);
        let raw_path: PathBuf = entry
            .path()
            .map_err(|e| Error::Tar(e.to_string()))?
            .into_owned();
        let raw_name: String = raw_path.to_string_lossy().into_owned();
        let safe_name: String = match sanitize_entry_path(&raw_name) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("tar-slip: {e}"));
                continue;
            }
        };
        let uncompressed_size: u64 = entry.size();
        guard.admit_entry(&safe_name, uncompressed_size, uncompressed_size)?;
        let mut buf: Vec<u8> = Vec::with_capacity(usize::try_from(uncompressed_size).unwrap_or(0));
        entry
            .read_to_end(&mut buf)
            .map_err(|e| Error::Tar(e.to_string()))?;
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &buf)?;
        let is_executable: bool = mode_bits & 0o111 != 0;
        encoding.insert(safe_name.clone(), inner_compression);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size,
            compressed_size: uncompressed_size,
            compression: inner_compression,
            is_executable,
        });
    }
    Ok(ExtractionResult {
        kind,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_sevenz(
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let reader: Cursor<&[u8]> = Cursor::new(bytes);
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::new();
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let violations: Vec<String> = Vec::new();
    let mut sz_reader: sevenz_rust2::SevenZReader<Cursor<&[u8]>> =
        sevenz_rust2::SevenZReader::new(reader, sevenz_rust2::Password::empty())
            .map_err(|e| Error::SevenZ(e.to_string()))?;
    sz_reader
        .for_each_entries(
            |entry: &sevenz_rust2::SevenZArchiveEntry, data: &mut dyn Read| {
                if entry.is_directory() {
                    return Ok(true);
                }
                let raw_name: String = entry.name().to_owned();
                let safe_name: String = match sanitize_entry_path(&raw_name) {
                    Ok(s) => s,
                    Err(_) => return Ok(true),
                };
                let uncompressed_size: u64 = entry.size();
                let compressed_size: u64 = entry.compressed_size;
                if let Err(e) = guard.admit_entry(&safe_name, uncompressed_size, compressed_size) {
                    return Err(sevenz_rust2::Error::other(e.to_string()));
                }
                let mut buf: Vec<u8> =
                    Vec::with_capacity(usize::try_from(uncompressed_size).unwrap_or(0));
                data.read_to_end(&mut buf)
                    .map_err(|e: std::io::Error| sevenz_rust2::Error::other(e.to_string()))?;
                let disk_path: PathBuf = out_dir.join(&safe_name);
                if let Some(parent) = disk_path.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e: std::io::Error| sevenz_rust2::Error::other(e.to_string()))?;
                }
                std::fs::write(&disk_path, &buf)
                    .map_err(|e: std::io::Error| sevenz_rust2::Error::other(e.to_string()))?;
                encoding.insert(safe_name.clone(), EntryCompression::Other);
                entries_out.push(ExtractedEntry {
                    name: safe_name,
                    disk_path: Some(disk_path),
                    uncompressed_size,
                    compressed_size,
                    compression: EntryCompression::Other,
                    is_executable: false,
                });
                Ok(true)
            },
        )
        .map_err(|e| Error::SevenZ(e.to_string()))?;
    Ok(ExtractionResult {
        kind: ContainerKind::SevenZ,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_asar(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let layout: AsarLayout = asar::parse(bytes)?;
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::with_capacity(layout.entries.len());
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();
    for entry in &layout.entries {
        let safe_name: String = match sanitize_entry_path(&entry.path) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("asar-slip: {e}"));
                continue;
            }
        };
        let size: u64 = entry.size;
        guard.admit_entry(&safe_name, size, size)?;
        let view: &[u8] = asar::read_entry(bytes, &layout, entry)?;
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, view)?;
        encoding.insert(safe_name.clone(), EntryCompression::Stored);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: size,
            compression: EntryCompression::Stored,
            is_executable: entry.executable,
        });
    }
    Ok(ExtractionResult {
        kind: ContainerKind::Asar,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::io::Write as _;

    use super::*;

    fn temp_dir(suffix: &str) -> PathBuf {
        let base: PathBuf = std::env::temp_dir();
        let pid: u32 = std::process::id();
        let dir: PathBuf = base.join(format!("disrobe-binfmt-{pid}-{suffix}"));
        if dir.exists() {
            let _ = std::fs::remove_dir_all(&dir);
        }
        std::fs::create_dir_all(&dir).expect("mkdir tmp");
        dir
    }

    fn synth_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        let buf: Vec<u8> = Vec::new();
        let cursor: Cursor<Vec<u8>> = Cursor::new(buf);
        let mut zw: zip::ZipWriter<Cursor<Vec<u8>>> = zip::ZipWriter::new(cursor);
        let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default();
        for (name, body) in files {
            zw.start_file(*name, opts).expect("start");
            zw.write_all(body).expect("write");
        }
        let finished: Cursor<Vec<u8>> = zw.finish().expect("finish");
        finished.into_inner()
    }

    fn synth_tar_gz(files: &[(&str, &[u8])]) -> Vec<u8> {
        let plain: Vec<u8> = synth_tar(files);
        let buf: Vec<u8> = Vec::new();
        let mut enc: flate2::write::GzEncoder<Vec<u8>> =
            flate2::write::GzEncoder::new(buf, flate2::Compression::default());
        enc.write_all(&plain).expect("gz write");
        enc.finish().expect("gz finish")
    }

    fn synth_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let buf: Vec<u8> = Vec::new();
        let mut tw: tar::Builder<Vec<u8>> = tar::Builder::new(buf);
        for (name, body) in files {
            let mut header: tar::Header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tw.append_data(&mut header, *name, *body).expect("append");
        }
        tw.into_inner().expect("inner")
    }

    fn synth_asar(files: &[(&str, &[u8])]) -> Vec<u8> {
        use std::fmt::Write as _;
        let mut header: String = String::from(r#"{"files":{"#);
        let mut offset: u64 = 0;
        for (i, (name, body)) in files.iter().enumerate() {
            if i > 0 {
                header.push(',');
            }
            let size: usize = body.len();
            let _ = write!(header, r#""{name}":{{"size":{size},"offset":"{offset}"}}"#);
            offset += body.len() as u64;
        }
        header.push_str("}}");
        let header_bytes: &[u8] = header.as_bytes();
        let header_size: u32 = u32::try_from(header_bytes.len()).expect("hdr size");
        let aligned: u32 = {
            let r: u32 = header_size % 4;
            if r == 0 {
                header_size
            } else {
                header_size + (4 - r)
            }
        };
        let pickle_size: u32 = 8 + aligned;
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]);
        out.extend_from_slice(&pickle_size.to_le_bytes());
        out.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]);
        out.extend_from_slice(&header_size.to_le_bytes());
        out.extend_from_slice(header_bytes);
        out.extend(std::iter::repeat_n(0u8, (aligned - header_size) as usize));
        for (_, body) in files {
            out.extend_from_slice(body);
        }
        out
    }

    #[test]
    fn extract_zip_writes_entries_and_records_them() {
        let out: PathBuf = temp_dir("zip-ok");
        let zip_bytes: Vec<u8> = synth_zip(&[("a.txt", b"alpha"), ("pkg/b.txt", b"bravo bravo")]);
        let result: ExtractionResult =
            extract_to(ContainerKind::Zip, &zip_bytes, &out).expect("extract");
        assert_eq!(result.entries.len(), 2);
        assert_eq!(std::fs::read(out.join("a.txt")).expect("a"), b"alpha");
        assert_eq!(
            std::fs::read(out.join("pkg/b.txt")).expect("b"),
            b"bravo bravo"
        );
        assert!(result.integrity_violations.is_empty());
    }

    #[test]
    fn extract_zip_rejects_zip_slip() {
        let out: PathBuf = temp_dir("zip-slip");
        let bytes: Vec<u8> = synth_zip(&[("../escape.txt", b"x")]);
        let r: ExtractionResult =
            extract_to(ContainerKind::Zip, &bytes, &out).expect("must extract");
        assert!(
            r.integrity_violations
                .iter()
                .any(|v| v.contains("zip-slip"))
        );
        assert!(r.entries.is_empty());
    }

    #[test]
    fn extract_zip_rejects_bomb_ratio() {
        let mut payload: Vec<u8> = Vec::with_capacity(1_000_000);
        payload.extend(std::iter::repeat_n(b'A', 1_000_000));
        let bytes: Vec<u8> = synth_zip(&[("bomb.bin", &payload)]);
        let out: PathBuf = temp_dir("zip-bomb");
        let tight: ExtractionQuota = ExtractionQuota {
            max_per_entry_ratio: 2,
            ..ExtractionQuota::default_safe()
        };
        let err: Error =
            extract_to_with_quota(ContainerKind::Zip, &bytes, &out, tight).unwrap_err();
        assert!(matches!(err, Error::QuotaExceeded { .. }));
    }

    #[test]
    fn extract_tar_writes_entries() {
        let out: PathBuf = temp_dir("tar-ok");
        let bytes: Vec<u8> = synth_tar(&[("a.txt", b"alpha"), ("b.txt", b"bravo")]);
        let result: ExtractionResult =
            extract_to(ContainerKind::Tar, &bytes, &out).expect("extract");
        assert_eq!(result.entries.len(), 2);
        assert_eq!(std::fs::read(out.join("a.txt")).expect("a"), b"alpha");
    }

    #[test]
    fn extract_tar_gz_writes_entries() {
        let out: PathBuf = temp_dir("targz-ok");
        let bytes: Vec<u8> = synth_tar_gz(&[("dir/a.txt", b"alpha"), ("dir/b.txt", b"bravo")]);
        let result: ExtractionResult =
            extract_to(ContainerKind::TarGz, &bytes, &out).expect("extract");
        assert_eq!(result.entries.len(), 2);
        assert_eq!(std::fs::read(out.join("dir/a.txt")).expect("a"), b"alpha");
    }

    #[test]
    fn extract_tar_gz_rejects_decompression_bomb_during_inflate() {
        let mut bomb_body: Vec<u8> = Vec::with_capacity(8 * 1024 * 1024);
        bomb_body.extend(std::iter::repeat_n(b'A', 8 * 1024 * 1024));
        let bytes: Vec<u8> = synth_tar_gz(&[("bomb.bin", &bomb_body)]);
        assert!(
            bytes.len() < 64 * 1024,
            "highly-compressible bomb must stay small on disk: {} bytes",
            bytes.len()
        );
        let out: PathBuf = temp_dir("targz-bomb");
        let tight: ExtractionQuota = ExtractionQuota {
            max_total_uncompressed: 1024 * 1024,
            ..ExtractionQuota::default_safe()
        };
        let err: Error =
            extract_to_with_quota(ContainerKind::TarGz, &bytes, &out, tight).unwrap_err();
        assert!(
            matches!(err, Error::QuotaExceeded { .. }),
            "expected QuotaExceeded during inflate, got {err:?}"
        );
    }

    fn synth_tar_with_raw_name(name: &[u8], body: &[u8]) -> Vec<u8> {
        let mut header: [u8; 512] = [0u8; 512];
        header[..name.len().min(100)].copy_from_slice(&name[..name.len().min(100)]);
        let mode: &[u8] = b"0000644\0";
        header[100..108].copy_from_slice(mode);
        let uid_gid: &[u8] = b"0000000\0";
        header[108..116].copy_from_slice(uid_gid);
        header[116..124].copy_from_slice(uid_gid);
        let size_oct: String = format!("{:011o}\0", body.len());
        header[124..136].copy_from_slice(size_oct.as_bytes());
        let mtime: &[u8] = b"00000000000\0";
        header[136..148].copy_from_slice(mtime);
        header[148..156].copy_from_slice(b"        ");
        header[156] = b'0';
        header[257..262].copy_from_slice(b"ustar");
        header[263..265].copy_from_slice(b"00");
        let sum: u32 = header.iter().map(|&b: &u8| u32::from(b)).sum();
        let chk: String = format!("{sum:06o}\0 ");
        header[148..156].copy_from_slice(chk.as_bytes());
        let mut out: Vec<u8> = Vec::with_capacity(1024 + body.len() + 1024);
        out.extend_from_slice(&header);
        out.extend_from_slice(body);
        let pad: usize = (512 - body.len() % 512) % 512;
        out.extend(std::iter::repeat_n(0u8, pad));
        out.extend(std::iter::repeat_n(0u8, 1024));
        out
    }

    #[test]
    fn extract_tar_rejects_zip_slip() {
        let out: PathBuf = temp_dir("tar-slip");
        let bytes: Vec<u8> = synth_tar_with_raw_name(b"../escape.txt", b"x");
        let r: ExtractionResult = extract_to(ContainerKind::Tar, &bytes, &out).expect("extract");
        assert!(
            r.integrity_violations
                .iter()
                .any(|v| v.contains("tar-slip"))
        );
        assert!(r.entries.is_empty());
    }

    #[test]
    fn extract_asar_writes_entries() {
        let out: PathBuf = temp_dir("asar-ok");
        let bytes: Vec<u8> = synth_asar(&[("a.txt", b"alpha"), ("b.txt", b"bravo")]);
        let r: ExtractionResult = extract_to(ContainerKind::Asar, &bytes, &out).expect("extract");
        assert_eq!(r.entries.len(), 2);
        assert_eq!(std::fs::read(out.join("a.txt")).expect("a"), b"alpha");
        assert_eq!(std::fs::read(out.join("b.txt")).expect("b"), b"bravo");
    }

    #[test]
    fn unsupported_container_returns_error_for_none_kind() {
        let out: PathBuf = temp_dir("unsupp");
        let err: Error = extract_to(ContainerKind::None, &[0u8; 16], &out).unwrap_err();
        assert!(matches!(err, Error::UnsupportedContainer(_)));
    }

    fn with_disabled_external<F: FnOnce()>(f: F) {
        let guard: std::sync::MutexGuard<'_, ()> = crate::external_wrap::lock_overrides();
        crate::external_wrap::set_overrides(crate::external_wrap::ToolOverrides {
            disable_all: true,
            paths: BTreeMap::new(),
        });
        f();
        crate::external_wrap::clear_overrides();
        drop(guard);
    }

    #[test]
    fn rar_extraction_falls_back_when_no_external_tool() {
        with_disabled_external(|| {
            let out: PathBuf = temp_dir("rar");
            let err: Error = extract_to(ContainerKind::Rar, &[0u8; 16], &out).unwrap_err();
            assert!(matches!(err, Error::RarNotExtractable));
        });
    }

    #[test]
    fn pkg_extraction_falls_back_when_no_external_tool() {
        with_disabled_external(|| {
            let out: PathBuf = temp_dir("pkg");
            let err: Error = extract_to(ContainerKind::Pkg, &[0u8; 16], &out).unwrap_err();
            assert!(matches!(err, Error::PkgNoApacheDecoder));
        });
    }

    #[test]
    fn dmg_extraction_falls_back_when_no_external_tool() {
        with_disabled_external(|| {
            let out: PathBuf = temp_dir("dmg");
            let err: Error = extract_to(ContainerKind::Dmg, &[0u8; 16], &out).unwrap_err();
            assert!(matches!(err, Error::DmgNoApacheDecoder));
        });
    }

    #[test]
    fn iso_extraction_falls_back_when_no_external_tool() {
        with_disabled_external(|| {
            let out: PathBuf = temp_dir("iso");
            let err: Error = extract_to(ContainerKind::Iso, &[0u8; 16], &out).unwrap_err();
            assert!(matches!(err, Error::IsoNoApacheDecoder));
        });
    }

    #[test]
    fn jar_routed_through_zip_path() {
        let out: PathBuf = temp_dir("jar-ok");
        let bytes: Vec<u8> = synth_zip(&[("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")]);
        let r: ExtractionResult = extract_to(ContainerKind::Jar, &bytes, &out).expect("extract");
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.kind, ContainerKind::Jar);
    }

    fn synth_deb(inner_tar_gz: &[u8]) -> Vec<u8> {
        let buf: Vec<u8> = Vec::new();
        let mut builder: ar::Builder<Vec<u8>> = ar::Builder::new(buf);
        let debian_binary: &[u8] = b"2.0\n";
        let mut hdr_db: ar::Header =
            ar::Header::new(b"debian-binary".to_vec(), debian_binary.len() as u64);
        hdr_db.set_mode(0o100_644);
        builder
            .append(&hdr_db, debian_binary)
            .expect("append debian-binary");
        let control_payload: Vec<u8> = synth_tar_gz(&[("control", b"Package: synth\n")]);
        let mut hdr_ctl: ar::Header =
            ar::Header::new(b"control.tar.gz".to_vec(), control_payload.len() as u64);
        hdr_ctl.set_mode(0o100_644);
        builder
            .append(&hdr_ctl, control_payload.as_slice())
            .expect("append control");
        let mut hdr_data: ar::Header =
            ar::Header::new(b"data.tar.gz".to_vec(), inner_tar_gz.len() as u64);
        hdr_data.set_mode(0o100_644);
        builder
            .append(&hdr_data, inner_tar_gz)
            .expect("append data");
        builder.into_inner().expect("into inner")
    }

    #[test]
    fn extract_deb_writes_inner_data_tar_gz_entries() {
        let out: PathBuf = temp_dir("deb-ok");
        let inner: Vec<u8> = synth_tar_gz(&[
            ("usr/bin/example", b"#!/bin/sh\necho hi\n"),
            ("etc/example/config", b"key = value\n"),
        ]);
        let bytes: Vec<u8> = synth_deb(&inner);
        let r: ExtractionResult =
            extract_to(ContainerKind::Deb, &bytes, &out).expect("deb extract");
        assert_eq!(r.kind, ContainerKind::Deb);
        assert_eq!(r.entries.len(), 2);
        assert_eq!(
            std::fs::read(out.join("usr/bin/example")).expect("usr"),
            b"#!/bin/sh\necho hi\n"
        );
    }
}
