use std::collections::BTreeMap;
use std::io::{Cursor, Read, Seek};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::asar::AsarLayout;
use crate::container::ContainerKind;
use crate::error::{Error, Result};
use crate::quota::{
    ExtractionQuota, QuotaGuard, QuotaReport, bounded_prealloc, read_entry_to_limit,
    sanitize_entry_path,
};
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
    if crate::debug::dbg_enabled() {
        crate::debug::dbg_section("binfmt extract");
        crate::debug::dbg_kv("kind", || kind.label().to_owned());
        crate::debug::dbg_kv("extraction-mode", || {
            format!("{:?}", kind.extraction_mode())
        });
        crate::debug::dbg_kv("input-len", || bytes.len().to_string());
        crate::debug::dbg_kv("quota", || {
            format!(
                "max_entries={} max_total={} max_per_entry={} per_entry_ratio={} aggregate_ratio={}",
                quota.max_entries,
                quota.max_total_uncompressed,
                quota.max_per_entry_uncompressed,
                quota.max_per_entry_ratio,
                quota.max_aggregate_ratio,
            )
        });
    }
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
        #[cfg(feature = "rpm")]
        ContainerKind::Rpm => extract_rpm(bytes, out_dir, quota),
        #[cfg(not(feature = "rpm"))]
        ContainerKind::Rpm => Err(Error::UnsupportedContainer("rpm")),
        ContainerKind::Cab => extract_cab(bytes, out_dir, quota),
        ContainerKind::Rar => extract_rar(bytes, out_dir, quota),
        ContainerKind::Pkg => extract_xar(bytes, out_dir, quota),
        ContainerKind::Dmg => extract_dmg(bytes, out_dir, quota),
        ContainerKind::Iso => extract_iso(bytes, out_dir, quota),
        ContainerKind::Msix => extract_msix(bytes, out_dir, quota),
        ContainerKind::Oci | ContainerKind::DockerImage => {
            extract_oci_tarball(kind, bytes, out_dir, quota)
        }
        ContainerKind::AppImage => extract_appimage(bytes, out_dir, quota),
        ContainerKind::Snap => extract_snap(bytes, out_dir, quota),
        ContainerKind::Flatpak => extract_flatpak(bytes, out_dir, quota),
        ContainerKind::Msi => extract_msi(bytes, out_dir, quota),
        ContainerKind::Nsis => extract_nsis_metadata(bytes, out_dir),
        ContainerKind::Squirrel => extract_squirrel(bytes, out_dir, quota),
        ContainerKind::InnoSetup => extract_innosetup(bytes, out_dir, quota),
        ContainerKind::InstallShield => extract_installshield(bytes, out_dir, quota),
        ContainerKind::Squashfs => extract_squashfs(bytes, out_dir, quota),
        ContainerKind::Cramfs => extract_cramfs(bytes, out_dir, quota),
        ContainerKind::Ext4 => extract_ext4(bytes, out_dir, quota),
        ContainerKind::Romfs => extract_romfs(bytes, out_dir, quota),
        ContainerKind::MinixFs => extract_minixfs(bytes, out_dir, quota),
        ContainerKind::AndroidSparse => extract_android_sparse(bytes, out_dir, quota),
        ContainerKind::BtrfsSend => extract_btrfs_send(bytes, out_dir, quota),
        ContainerKind::Erofs => extract_erofs(bytes, out_dir, quota),
        ContainerKind::Jffs2 => extract_jffs2(bytes, out_dir, quota),
        ContainerKind::Ntfs => extract_ntfs(bytes, out_dir, quota),
        ContainerKind::Ubifs => extract_ubifs(bytes, out_dir, quota),
        ContainerKind::Yaffs2 => extract_yaffs2(bytes, out_dir, quota),
        ContainerKind::Cpio => extract_cpio(bytes, out_dir, quota),
        ContainerKind::Arj => extract_arj(bytes, out_dir, quota),
        ContainerKind::Arc => extract_arc(bytes, out_dir, quota),
        ContainerKind::Lzh => extract_lzh(bytes, out_dir, quota),
        ContainerKind::Lzo => extract_lzop(bytes, out_dir, quota),
        ContainerKind::Uzip => extract_uzip(bytes, out_dir, quota),
        ContainerKind::Xalz => extract_xalz(bytes, out_dir, quota),
        ContainerKind::Ar => extract_ar(bytes, out_dir, quota),
        ContainerKind::Par2 => extract_par2(bytes, out_dir, quota),
        ContainerKind::Partclone => extract_partclone(bytes, out_dir, quota),
        ContainerKind::StuffIt => extract_stuffit(bytes, out_dir, quota),
        ContainerKind::Qnx => extract_qnx(bytes, out_dir, quota),
        ContainerKind::Xz => extract_bare_xz(bytes, out_dir, quota),
        ContainerKind::Gzip => extract_bare_gzip(bytes, out_dir, quota),
        ContainerKind::Bzip2 => {
            extract_bare_single_stream(ContainerKind::Bzip2, bytes, out_dir, quota)
        }
        ContainerKind::Zstd => {
            extract_bare_single_stream(ContainerKind::Zstd, bytes, out_dir, quota)
        }
        ContainerKind::Lzma => {
            extract_bare_single_stream(ContainerKind::Lzma, bytes, out_dir, quota)
        }
        ContainerKind::Lzip => {
            extract_bare_single_stream(ContainerKind::Lzip, bytes, out_dir, quota)
        }
        ContainerKind::Lz4 => extract_bare_single_stream(ContainerKind::Lz4, bytes, out_dir, quota),
        ContainerKind::Zlib => {
            extract_bare_single_stream(ContainerKind::Zlib, bytes, out_dir, quota)
        }
        ContainerKind::UnixCompress => {
            extract_bare_single_stream(ContainerKind::UnixCompress, bytes, out_dir, quota)
        }
        ContainerKind::Vhd => extract_vhd_summary(bytes, out_dir),
        ContainerKind::Vhdx => extract_vhdx_summary(bytes, out_dir),
        ContainerKind::Wim => extract_wim(bytes, out_dir),
        ContainerKind::Gpt => extract_gpt_summary(bytes, out_dir),
        ContainerKind::Mbr => extract_mbr_summary(bytes, out_dir),
        ContainerKind::Fat => extract_fat(bytes, out_dir, quota),
        ContainerKind::BunStandalone => extract_bun(bytes, out_dir, quota),
        ContainerKind::UnityFs => extract_unityfs(bytes, out_dir, quota),
        ContainerKind::FwDlinkShrs
        | ContainerKind::FwDlinkEncrptedImg
        | ContainerKind::FwDlinkAlphaV1
        | ContainerKind::FwDlinkAlphaV2
        | ContainerKind::FwDlinkDeafbead
        | ContainerKind::FwDlinkFpkg
        | ContainerKind::FwEnGenius
        | ContainerKind::FwAutelEcc
        | ContainerKind::FwQnap
        | ContainerKind::FwNetgearChk
        | ContainerKind::FwNetgearTrxV1
        | ContainerKind::FwNetgearTrxV2
        | ContainerKind::FwXiaomiHdr1
        | ContainerKind::FwXiaomiHdr2
        | ContainerKind::FwTeslaSbfh
        | ContainerKind::FwHpBdl
        | ContainerKind::FwHpIpkg
        | ContainerKind::FwMoxaFrm
        | ContainerKind::FwInstarBneg
        | ContainerKind::FwInstarHd
        | ContainerKind::FwAiroha => extract_firmware(kind, bytes, out_dir, quota),
        ContainerKind::None => Err(Error::UnsupportedContainer(kind.label())),
    }
}

fn extract_firmware(
    kind: ContainerKind,
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let fw_kind: crate::containers::FirmwareKind = kind
        .firmware_kind()
        .ok_or_else(|| Error::Firmware(format!("{} is not a firmware kind", kind.label())))?;
    let extraction: crate::containers::FirmwareExtraction =
        crate::containers::extract_firmware(fw_kind, bytes)?;
    std::fs::create_dir_all(out_dir)?;
    let mut guard: QuotaGuard = QuotaGuard::new(ExtractionQuota {
        max_aggregate_ratio: quota.max_aggregate_ratio.max(1000),
        max_per_entry_ratio: quota.max_per_entry_ratio.max(1000),
        ..quota
    });
    let mut entries: Vec<ExtractedEntry> = Vec::with_capacity(extraction.members.len());
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = extraction.notes.clone();

    for member in &extraction.members {
        let safe_name: String = match sanitize_entry_path(&member.name) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("firmware-slip: {e}"));
                continue;
            }
        };
        let size: u64 = member.data.len() as u64;
        if let Err(e) = guard.admit_entry(&safe_name, size, bytes.len() as u64) {
            violations.push(format!("firmware-quota `{safe_name}`: {e}"));
            continue;
        }
        if let (Some(expected), Some(false)) = (member.crc_expected, member.crc_ok) {
            violations.push(format!(
                "firmware-crc `{safe_name}`: stored checksum 0x{expected:08x} does not match the computed checksum 0x{:08x}",
                member.crc_actual.map_or(0, |value: u32| value)
            ));
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &member.data)?;
        encoding.insert(safe_name.clone(), EntryCompression::Other);
        entries.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: size,
            compression: EntryCompression::Other,
            is_executable: false,
        });
    }

    let summary_json: String = serde_json::to_string_pretty(&FirmwareSummary {
        kind: extraction.kind.label(),
        member_count: extraction.members.len(),
        inner_kind_hint: extraction.inner_kind_hint.as_deref(),
        notes: &extraction.notes,
    })
    .unwrap_or_else(|_: serde_json::Error| String::new());
    let summary_name: String = ".disrobe-firmware.json".to_owned();
    let summary_path: PathBuf = out_dir.join(&summary_name);
    std::fs::write(&summary_path, summary_json.as_bytes())?;
    encoding.insert(summary_name.clone(), EntryCompression::Stored);
    entries.push(ExtractedEntry {
        name: summary_name,
        disk_path: Some(summary_path),
        uncompressed_size: summary_json.len() as u64,
        compressed_size: summary_json.len() as u64,
        compression: EntryCompression::Stored,
        is_executable: false,
    });

    Ok(ExtractionResult {
        kind,
        entries,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

#[derive(Debug, Serialize)]
struct FirmwareSummary<'a> {
    kind: &'static str,
    member_count: usize,
    inner_kind_hint: Option<&'a str>,
    notes: &'a [String],
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
        container::detect_container(bytes).map_or(ContainerKind::Tar, |value: ContainerKind| value);
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
        let summary_json: String = serde_json::to_string_pretty(&parsed)?;
        let summary_path: PathBuf = out_dir.join(".disrobe-docker-manifest.json");
        std::fs::write(&summary_path, summary_json.as_bytes())?;
        result.encoding.insert(
            ".disrobe-docker-manifest.json".to_owned(),
            EntryCompression::Stored,
        );
    }
    result.kind = kind;
    Ok(result)
}

fn squashfs_walk_to_disk(
    bytes: &[u8],
    base: usize,
    kind: ContainerKind,
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let walk: crate::containers::SquashfsWalk =
        crate::containers::walk_squashfs(bytes, base, quota.max_total_uncompressed)?;
    std::fs::create_dir_all(out_dir)?;
    let installer_quota: ExtractionQuota = ExtractionQuota {
        max_aggregate_ratio: quota.max_aggregate_ratio.max(1000),
        max_per_entry_ratio: quota.max_per_entry_ratio.max(1000),
        ..quota
    };
    let mut guard: QuotaGuard = QuotaGuard::new(installer_quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::with_capacity(walk.files.len());
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();
    for file in &walk.files {
        if file.is_symlink {
            continue;
        }
        let safe_name: String = match sanitize_entry_path(&file.path) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("squashfs-slip: {e}"));
                continue;
            }
        };
        let size: u64 = file.data.len() as u64;
        if let Err(e) = guard.admit_entry(&safe_name, size, size) {
            violations.push(format!("squashfs-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &file.data)?;
        encoding.insert(safe_name.clone(), EntryCompression::Other);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: size,
            compression: EntryCompression::Other,
            is_executable: file.is_executable,
        });
    }
    if entries_out.is_empty() && !walk.files.is_empty() {
        return Err(Error::Squashfs(format!(
            "squashfs walked {} inodes but no regular file was written (compressor={:?}); lzo/lz4 squashfs need an external decoder",
            walk.files.len(),
            walk.superblock.compression
        )));
    }
    Ok(ExtractionResult {
        kind,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_squashfs(
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    squashfs_walk_to_disk(bytes, 0, ContainerKind::Squashfs, out_dir, quota)
}

fn extract_appimage(
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let layout: crate::containers::AppImageLayout = crate::containers::parse_appimage(bytes)
        .map_err(|e: Error| match e {
            Error::Decompression(s) => Error::AppImage(s),
            other => other,
        })?;
    let base: usize =
        usize::try_from(layout.squashfs_offset).map_err(|_e: std::num::TryFromIntError| {
            Error::AppImage("squashfs offset overflow".to_owned())
        })?;
    let mut result: ExtractionResult =
        squashfs_walk_to_disk(bytes, base, ContainerKind::AppImage, out_dir, quota).map_err(
            |e: Error| match e {
                Error::Squashfs(s) => Error::AppImage(format!("embedded squashfs: {s}")),
                other => other,
            },
        )?;
    let json: String =
        serde_json::to_string_pretty(&layout).unwrap_or_else(|_: serde_json::Error| String::new());
    let path: PathBuf = out_dir.join(".disrobe-appimage-layout.json");
    std::fs::write(&path, json.as_bytes())?;
    result.encoding.insert(
        ".disrobe-appimage-layout.json".to_owned(),
        EntryCompression::Stored,
    );
    Ok(result)
}

fn extract_snap(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    squashfs_walk_to_disk(bytes, 0, ContainerKind::Snap, out_dir, quota).map_err(|e: Error| match e
    {
        Error::Squashfs(s) => Error::Snap(s),
        other => other,
    })
}

fn extract_cramfs(
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let walk: crate::containers::CramfsWalk =
        crate::containers::walk_cramfs(bytes, quota.max_total_uncompressed)?;
    std::fs::create_dir_all(out_dir)?;
    let installer_quota: ExtractionQuota = ExtractionQuota {
        max_aggregate_ratio: quota.max_aggregate_ratio.max(1000),
        max_per_entry_ratio: quota.max_per_entry_ratio.max(1000),
        ..quota
    };
    let mut guard: QuotaGuard = QuotaGuard::new(installer_quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::with_capacity(walk.files.len());
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();
    for file in &walk.files {
        if file.is_symlink {
            continue;
        }
        let safe_name: String = match sanitize_entry_path(&file.path) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("cramfs-slip: {e}"));
                continue;
            }
        };
        let size: u64 = file.data.len() as u64;
        if let Err(e) = guard.admit_entry(&safe_name, size, size) {
            violations.push(format!("cramfs-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &file.data)?;
        encoding.insert(safe_name.clone(), EntryCompression::Deflate);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: size,
            compression: EntryCompression::Deflate,
            is_executable: file.is_executable,
        });
    }
    Ok(ExtractionResult {
        kind: ContainerKind::Cramfs,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_ext4(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let walk: crate::containers::Ext4Walk =
        crate::containers::walk_ext4(bytes, quota.max_total_uncompressed)?;
    std::fs::create_dir_all(out_dir)?;
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::with_capacity(walk.files.len());
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();
    for file in &walk.files {
        if file.is_symlink {
            continue;
        }
        let safe_name: String = match sanitize_entry_path(&file.path) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("ext4-slip: {e}"));
                continue;
            }
        };
        let size: u64 = file.data.len() as u64;
        if let Err(e) = guard.admit_entry(&safe_name, size, size) {
            violations.push(format!("ext4-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &file.data)?;
        encoding.insert(safe_name.clone(), EntryCompression::Stored);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: size,
            compression: EntryCompression::Stored,
            is_executable: file.is_executable,
        });
    }
    Ok(ExtractionResult {
        kind: ContainerKind::Ext4,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_romfs(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let walk: crate::containers::RomfsWalk =
        crate::containers::walk_romfs(bytes, quota.max_total_uncompressed)?;
    std::fs::create_dir_all(out_dir)?;
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::with_capacity(walk.files.len());
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();
    for file in &walk.files {
        if file.is_symlink {
            continue;
        }
        let safe_name: String = match sanitize_entry_path(&file.path) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("romfs-slip: {e}"));
                continue;
            }
        };
        let size: u64 = file.data.len() as u64;
        if let Err(e) = guard.admit_entry(&safe_name, size, size) {
            violations.push(format!("romfs-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &file.data)?;
        encoding.insert(safe_name.clone(), EntryCompression::Stored);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: size,
            compression: EntryCompression::Stored,
            is_executable: file.is_executable,
        });
    }
    Ok(ExtractionResult {
        kind: ContainerKind::Romfs,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_minixfs(
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let walk: crate::containers::MinixWalk =
        crate::containers::walk_minixfs(bytes, quota.max_total_uncompressed)?;
    std::fs::create_dir_all(out_dir)?;
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::with_capacity(walk.files.len());
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();
    for file in &walk.files {
        if file.is_symlink {
            continue;
        }
        let safe_name: String = match sanitize_entry_path(&file.path) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("minixfs-slip: {e}"));
                continue;
            }
        };
        let size: u64 = file.data.len() as u64;
        if let Err(e) = guard.admit_entry(&safe_name, size, size) {
            violations.push(format!("minixfs-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &file.data)?;
        encoding.insert(safe_name.clone(), EntryCompression::Stored);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: size,
            compression: EntryCompression::Stored,
            is_executable: file.is_executable,
        });
    }
    Ok(ExtractionResult {
        kind: ContainerKind::MinixFs,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_android_sparse(
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let raw: Vec<u8> = crate::containers::unsparse(bytes)?;
    std::fs::create_dir_all(out_dir)?;
    let mut guard: QuotaGuard = QuotaGuard::new(ExtractionQuota {
        max_aggregate_ratio: quota.max_aggregate_ratio.max(1000),
        max_per_entry_ratio: quota.max_per_entry_ratio.max(1000),
        ..quota
    });
    let mut entries_out: Vec<ExtractedEntry> = Vec::new();
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();

    let inner: Option<ContainerKind> = container::detect_container(&raw);
    let name: String = "unsparse.img".to_owned();
    let size: u64 = raw.len() as u64;
    guard.admit_entry(&name, size, bytes.len() as u64)?;
    let disk_path: PathBuf = out_dir.join(&name);
    std::fs::write(&disk_path, &raw)?;
    encoding.insert(name.clone(), EntryCompression::Other);
    entries_out.push(ExtractedEntry {
        name,
        disk_path: Some(disk_path),
        uncompressed_size: size,
        compressed_size: bytes.len() as u64,
        compression: EntryCompression::Other,
        is_executable: false,
    });
    if let Some(kind) = inner {
        violations.push(format!(
            "android-sparse: reconstructed raw image is {} - re-run extraction on unsparse.img",
            kind.label()
        ));
    }
    Ok(ExtractionResult {
        kind: ContainerKind::AndroidSparse,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_btrfs_send(
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let replay: crate::containers::BtrfsSendReplay =
        crate::containers::replay_btrfs_send(bytes, quota.max_total_uncompressed)?;
    std::fs::create_dir_all(out_dir)?;
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::with_capacity(replay.files.len());
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = replay.notes.clone();
    for file in &replay.files {
        if file.is_symlink {
            continue;
        }
        let safe_name: String = match sanitize_entry_path(&file.path) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("btrfs-send-slip: {e}"));
                continue;
            }
        };
        let size: u64 = file.data.len() as u64;
        if let Err(e) = guard.admit_entry(&safe_name, size, size) {
            violations.push(format!("btrfs-send-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &file.data)?;
        encoding.insert(safe_name.clone(), EntryCompression::Stored);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: size,
            compression: EntryCompression::Stored,
            is_executable: false,
        });
    }
    Ok(ExtractionResult {
        kind: ContainerKind::BtrfsSend,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_erofs(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let walk: crate::containers::ErofsWalk =
        crate::containers::walk_erofs(bytes, quota.max_total_uncompressed)?;
    std::fs::create_dir_all(out_dir)?;
    let mut guard: QuotaGuard = QuotaGuard::new(ExtractionQuota {
        max_aggregate_ratio: quota.max_aggregate_ratio.max(1000),
        max_per_entry_ratio: quota.max_per_entry_ratio.max(1000),
        ..quota
    });
    let mut entries_out: Vec<ExtractedEntry> = Vec::with_capacity(walk.files.len());
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = walk.notes.clone();
    for file in &walk.files {
        if file.is_symlink {
            continue;
        }
        let safe_name: String = match sanitize_entry_path(&file.path) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("erofs-slip: {e}"));
                continue;
            }
        };
        let size: u64 = file.data.len() as u64;
        if let Err(e) = guard.admit_entry(&safe_name, size, size) {
            violations.push(format!("erofs-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &file.data)?;
        encoding.insert(safe_name.clone(), EntryCompression::Stored);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: size,
            compression: EntryCompression::Stored,
            is_executable: file.is_executable,
        });
    }
    Ok(ExtractionResult {
        kind: ContainerKind::Erofs,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_jffs2(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let walk: crate::containers::Jffs2Walk =
        crate::containers::walk_jffs2(bytes, quota.max_total_uncompressed)?;
    std::fs::create_dir_all(out_dir)?;
    let mut guard: QuotaGuard = QuotaGuard::new(ExtractionQuota {
        max_aggregate_ratio: quota.max_aggregate_ratio.max(1000),
        max_per_entry_ratio: quota.max_per_entry_ratio.max(1000),
        ..quota
    });
    let mut entries_out: Vec<ExtractedEntry> = Vec::with_capacity(walk.files.len());
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = walk.notes.clone();
    for file in &walk.files {
        if file.is_symlink {
            continue;
        }
        let safe_name: String = match sanitize_entry_path(&file.path) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("jffs2-slip: {e}"));
                continue;
            }
        };
        let size: u64 = file.data.len() as u64;
        if let Err(e) = guard.admit_entry(&safe_name, size, size) {
            violations.push(format!("jffs2-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &file.data)?;
        encoding.insert(safe_name.clone(), EntryCompression::Other);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: size,
            compression: EntryCompression::Other,
            is_executable: file.is_executable,
        });
    }
    Ok(ExtractionResult {
        kind: ContainerKind::Jffs2,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_ntfs(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let walk: crate::containers::NtfsWalk =
        crate::containers::walk_ntfs(bytes, quota.max_total_uncompressed)?;
    std::fs::create_dir_all(out_dir)?;
    let mut guard: QuotaGuard = QuotaGuard::new(ExtractionQuota {
        max_aggregate_ratio: quota.max_aggregate_ratio.max(1000),
        max_per_entry_ratio: quota.max_per_entry_ratio.max(1000),
        ..quota
    });
    let mut entries_out: Vec<ExtractedEntry> = Vec::with_capacity(walk.files.len());
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = walk.notes.clone();
    for file in &walk.files {
        let safe_name: String = match sanitize_entry_path(&file.path) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("ntfs-slip: {e}"));
                continue;
            }
        };
        let size: u64 = file.data.len() as u64;
        if let Err(e) = guard.admit_entry(&safe_name, size, size) {
            violations.push(format!("ntfs-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &file.data)?;
        encoding.insert(safe_name.clone(), EntryCompression::Stored);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: size,
            compression: EntryCompression::Stored,
            is_executable: false,
        });
    }
    Ok(ExtractionResult {
        kind: ContainerKind::Ntfs,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_ubifs(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let walk: crate::containers::UbifsWalk =
        crate::containers::walk_ubifs(bytes, quota.max_total_uncompressed)?;
    std::fs::create_dir_all(out_dir)?;
    let mut guard: QuotaGuard = QuotaGuard::new(ExtractionQuota {
        max_aggregate_ratio: quota.max_aggregate_ratio.max(1000),
        max_per_entry_ratio: quota.max_per_entry_ratio.max(1000),
        ..quota
    });
    let mut entries_out: Vec<ExtractedEntry> = Vec::with_capacity(walk.files.len());
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = walk.notes.clone();
    for file in &walk.files {
        if file.is_symlink {
            continue;
        }
        let safe_name: String = match sanitize_entry_path(&file.path) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("ubifs-slip: {e}"));
                continue;
            }
        };
        let size: u64 = file.data.len() as u64;
        if let Err(e) = guard.admit_entry(&safe_name, size, size) {
            violations.push(format!("ubifs-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &file.data)?;
        encoding.insert(safe_name.clone(), EntryCompression::Other);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: size,
            compression: EntryCompression::Other,
            is_executable: file.is_executable,
        });
    }
    for (vol_id, image) in &walk.leb_images {
        let name: String = format!("vol{vol_id}.ubifs.img");
        let size: u64 = image.len() as u64;
        if let Err(e) = guard.admit_entry(&name, size, size) {
            violations.push(format!("ubifs-quota `{name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&name);
        std::fs::write(&disk_path, image)?;
        encoding.insert(name.clone(), EntryCompression::Other);
        entries_out.push(ExtractedEntry {
            name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: size,
            compression: EntryCompression::Other,
            is_executable: false,
        });
    }
    Ok(ExtractionResult {
        kind: ContainerKind::Ubifs,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_yaffs2(
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let walk: crate::containers::Yaffs2Walk =
        crate::containers::walk_yaffs2(bytes, quota.max_total_uncompressed)?;
    std::fs::create_dir_all(out_dir)?;
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::with_capacity(walk.files.len());
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = walk.notes.clone();
    for file in &walk.files {
        if file.is_symlink {
            continue;
        }
        let safe_name: String = match sanitize_entry_path(&file.path) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("yaffs2-slip: {e}"));
                continue;
            }
        };
        let size: u64 = file.data.len() as u64;
        if let Err(e) = guard.admit_entry(&safe_name, size, size) {
            violations.push(format!("yaffs2-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &file.data)?;
        encoding.insert(safe_name.clone(), EntryCompression::Stored);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: size,
            compression: EntryCompression::Stored,
            is_executable: file.is_executable,
        });
    }
    Ok(ExtractionResult {
        kind: ContainerKind::Yaffs2,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_fat(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let volume: crate::containers::FatVolume =
        crate::containers::walk_fat(bytes, quota.max_total_uncompressed)?;
    std::fs::create_dir_all(out_dir)?;
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::with_capacity(volume.files.len());
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();
    for file in &volume.files {
        let safe_name: String = match sanitize_entry_path(&file.path) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("fat-slip: {e}"));
                continue;
            }
        };
        let data: Vec<u8> = match crate::containers::fat_file_data(
            bytes,
            volume.bpb,
            file,
            quota.max_per_entry_uncompressed,
        ) {
            Ok(d) => d,
            Err(e) => {
                violations.push(format!("fat-read `{safe_name}`: {e}"));
                continue;
            }
        };
        let size: u64 = data.len() as u64;
        if let Err(e) = guard.admit_entry(&safe_name, size, size) {
            violations.push(format!("fat-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &data)?;
        encoding.insert(safe_name.clone(), EntryCompression::Stored);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: size,
            compression: EntryCompression::Stored,
            is_executable: false,
        });
    }
    let summary_json: String =
        serde_json::to_string_pretty(&volume).unwrap_or_else(|_: serde_json::Error| String::new());
    let summary_path: PathBuf = out_dir.join(".disrobe-fat-layout.json");
    std::fs::write(&summary_path, summary_json.as_bytes())?;
    encoding.insert(
        ".disrobe-fat-layout.json".to_owned(),
        EntryCompression::Stored,
    );
    Ok(ExtractionResult {
        kind: ContainerKind::Fat,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_msi(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let summary: crate::containers::MsiSummary = crate::containers::parse_msi_minimal(bytes)
        .map_err(|e: Error| match e {
            Error::Decompression(s) => Error::Msi(s),
            other => other,
        })?;
    let extractable: crate::containers::MsiExtractable =
        crate::containers::read_msi_extractable(bytes)?;
    std::fs::create_dir_all(out_dir)?;
    let summary_json: String =
        serde_json::to_string_pretty(&summary).unwrap_or_else(|_: serde_json::Error| String::new());
    let summary_path: PathBuf = out_dir.join(".disrobe-msi-summary.json");
    std::fs::write(&summary_path, summary_json.as_bytes())?;

    let mut guard: QuotaGuard = QuotaGuard::new(ExtractionQuota {
        max_aggregate_ratio: quota.max_aggregate_ratio.max(200),
        max_per_entry_ratio: quota.max_per_entry_ratio.max(1000),
        ..quota
    });
    let mut entries_out: Vec<ExtractedEntry> = Vec::new();
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();

    for ext in &extractable.external_cabinets {
        violations.push(format!(
            "msi-external-cab `{ext}`: referenced cabinet is not embedded in the package (ships alongside the .msi)"
        ));
    }

    for cab in &extractable.cabs {
        extract_msi_cab(
            cab,
            &extractable.long_names,
            out_dir,
            &mut guard,
            &mut entries_out,
            &mut encoding,
            &mut violations,
        )?;
    }

    encoding.insert(
        ".disrobe-msi-summary.json".to_owned(),
        EntryCompression::Stored,
    );
    entries_out.push(ExtractedEntry {
        name: ".disrobe-msi-summary.json".to_owned(),
        disk_path: Some(summary_path),
        uncompressed_size: summary_json.len() as u64,
        compressed_size: summary_json.len() as u64,
        compression: EntryCompression::Stored,
        is_executable: false,
    });
    Ok(ExtractionResult {
        kind: ContainerKind::Msi,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_msi_cab(
    cab: &crate::containers::MsiEmbeddedCab,
    long_names: &BTreeMap<String, String>,
    out_dir: &Path,
    guard: &mut QuotaGuard,
    entries_out: &mut Vec<ExtractedEntry>,
    encoding: &mut BTreeMap<String, EntryCompression>,
    violations: &mut Vec<String>,
) -> Result<()> {
    let cursor: Cursor<&[u8]> = Cursor::new(cab.bytes.as_slice());
    let mut cabinet: cab::Cabinet<Cursor<&[u8]>> = cab::Cabinet::new(cursor)
        .map_err(|e| Error::Msi(format!("embedded cab `{}`: {e}", cab.stream_name)))?;
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
        let mapped: &str = long_names
            .get(&raw_name)
            .map_or(raw_name.as_str(), String::as_str);
        let safe_name: String = match sanitize_entry_path(mapped) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("msi-slip: {e}"));
                continue;
            }
        };
        let mut reader: cab::FileReader<Cursor<&[u8]>> = cabinet
            .read_file(&raw_name)
            .map_err(|e| Error::Msi(format!("read cab file {raw_name}: {e}")))?;
        let buf: Vec<u8> =
            read_entry_to_limit(&mut reader, &safe_name, guard.max_per_entry_uncompressed())
                .map_err(|e: Error| match e {
                    Error::Io(e) => Error::Msi(format!("drain cab file {raw_name}: {e}")),
                    other => other,
                })?;
        let uncompressed_size: u64 = buf.len() as u64;
        if let Err(e) = guard.admit_entry(&safe_name, uncompressed_size, uncompressed_size) {
            violations.push(format!("msi-quota `{safe_name}`: {e}"));
            continue;
        }
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
    Ok(())
}

fn extract_nsis_metadata(bytes: &[u8], out_dir: &Path) -> Result<ExtractionResult> {
    extract_nsis(bytes, out_dir, ExtractionQuota::default_safe())
}

const fn xar_entry_compression(encoding: crate::containers::XarEncoding) -> EntryCompression {
    match encoding {
        crate::containers::XarEncoding::Gzip => EntryCompression::Deflate,
        crate::containers::XarEncoding::Bzip2 => EntryCompression::Bzip2,
        crate::containers::XarEncoding::Xz => EntryCompression::Xz,
        crate::containers::XarEncoding::Lzma => EntryCompression::Lzma,
        crate::containers::XarEncoding::None | crate::containers::XarEncoding::Other => {
            EntryCompression::Stored
        }
    }
}

fn extract_rar(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let archive: crate::containers::RarArchive = match crate::containers::rar::parse_rar(bytes) {
        Ok(a) => a,
        Err(_) => {
            return dispatch_external_or_fallback(
                ContainerKind::Rar,
                bytes,
                out_dir,
                Error::RarNotExtractable,
            );
        }
    };
    std::fs::create_dir_all(out_dir)?;
    let archive_quota: ExtractionQuota = ExtractionQuota {
        max_aggregate_ratio: quota.max_aggregate_ratio.max(1000),
        max_per_entry_ratio: quota.max_per_entry_ratio.max(1000),
        ..quota
    };
    let mut guard: QuotaGuard = QuotaGuard::new(archive_quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::new();
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();

    for entry in &archive.entries {
        if entry.is_dir {
            continue;
        }
        let safe_name: String = match sanitize_entry_path(&entry.name) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("rar-slip: {e}"));
                continue;
            }
        };
        let is_store: bool = entry.method == crate::containers::RarMethod::Store;
        let data: Vec<u8> = match crate::containers::rar_entry_bytes(
            bytes,
            entry,
            quota.max_per_entry_uncompressed,
        ) {
            Ok(d) => d,
            Err(e) => {
                if is_store {
                    violations.push(format!("rar-bounds `{safe_name}`: {e}"));
                } else {
                    let codec: &str = if entry.compression_version >= 50 {
                        "rar 5.0 LZ"
                    } else {
                        "rar 2.9/3.x LZ"
                    };
                    violations.push(format!(
                        "rar-compressed `{safe_name}`: {codec} decode failed: {e}"
                    ));
                }
                continue;
            }
        };
        let size: u64 = data.len() as u64;
        let packed_size: u64 = entry.packed_size;
        if let Err(e) = guard.admit_entry(&safe_name, size, packed_size) {
            violations.push(format!("rar-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &data)?;
        let compression: EntryCompression = if is_store {
            EntryCompression::Stored
        } else {
            EntryCompression::Other
        };
        encoding.insert(safe_name.clone(), compression);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: packed_size,
            compression,
            is_executable: false,
        });
    }

    Ok(ExtractionResult {
        kind: ContainerKind::Rar,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_xar(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let archive: crate::containers::XarArchive = crate::containers::xar::parse_xar(bytes)?;
    std::fs::create_dir_all(out_dir)?;
    let toc_path: PathBuf = out_dir.join(".disrobe-xar-toc.xml");
    std::fs::write(&toc_path, archive.toc_xml.as_bytes())?;

    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::with_capacity(archive.files.len());
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();

    for file in &archive.files {
        let safe_name: String = match sanitize_entry_path(&file.path) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("xar-slip: {e}"));
                continue;
            }
        };
        let data: Vec<u8> = match crate::containers::xar::file_data(bytes, &archive, file) {
            Ok(d) => d,
            Err(e) => {
                violations.push(format!("xar-decode `{safe_name}`: {e}"));
                continue;
            }
        };
        let uncompressed_size: u64 = data.len() as u64;
        let compressed_size: u64 = file.length;
        if let Err(e) = guard.admit_entry(&safe_name, uncompressed_size, compressed_size) {
            violations.push(format!("xar-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &data)?;
        let comp: EntryCompression = xar_entry_compression(file.encoding);
        encoding.insert(safe_name.clone(), comp);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size,
            compressed_size,
            compression: comp,
            is_executable: false,
        });
    }

    encoding.insert(".disrobe-xar-toc.xml".to_owned(), EntryCompression::Stored);
    Ok(ExtractionResult {
        kind: ContainerKind::Pkg,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_dmg(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let (image, summary): (Vec<u8>, crate::containers::DmgSummary) =
        crate::containers::dmg::reconstruct_image(bytes)?;
    std::fs::create_dir_all(out_dir)?;
    let summary_json: String =
        serde_json::to_string_pretty(&summary).unwrap_or_else(|_: serde_json::Error| String::new());
    let summary_path: PathBuf = out_dir.join(".disrobe-dmg-layout.json");
    std::fs::write(&summary_path, summary_json.as_bytes())?;

    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut violations: Vec<String> = Vec::new();
    for ty in &summary.unsupported_chunk_types {
        violations.push(format!(
            "dmg-chunk-unknown: unrecognised UDIF chunk type 0x{ty:08x} skipped (raw/zero/ignore/ADC/zlib/bzip2/LZFSE/LZMA are all decoded in-tree)"
        ));
    }
    let image_size: u64 = image.len() as u64;
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut entries: Vec<ExtractedEntry> = Vec::new();

    if crate::containers::apfs::detect_apfs(&image)
        && let Ok(container) = crate::containers::apfs::parse_apfs(&image)
    {
        let apfs_json: String = serde_json::to_string_pretty(&container)
            .unwrap_or_else(|_: serde_json::Error| String::new());
        let apfs_path: PathBuf = out_dir.join(".disrobe-apfs-layout.json");
        std::fs::write(&apfs_path, apfs_json.as_bytes())?;
        encoding.insert(
            ".disrobe-apfs-layout.json".to_owned(),
            EntryCompression::Stored,
        );
        let block_size: u32 = container.block_size;
        for volume in &container.volumes {
            if volume.root_tree_oid == 0 {
                continue;
            }
            let files: Vec<crate::containers::ApfsExtractedFile> =
                crate::containers::apfs::extract_apfs_files(
                    &image,
                    block_size,
                    volume.root_tree_oid,
                );
            for file in &files {
                let safe_name: String = match sanitize_entry_path(&file.name) {
                    Ok(s) => s,
                    Err(e) => {
                        violations.push(format!("dmg-apfs-slip: {e}"));
                        continue;
                    }
                };
                let data: Vec<u8> = crate::containers::apfs::apfs_file_bytes(
                    &image,
                    block_size,
                    file,
                    quota.max_per_entry_uncompressed,
                );
                let size: u64 = data.len() as u64;
                if let Err(e) = guard.admit_entry(&safe_name, size, size) {
                    violations.push(format!("dmg-apfs-quota `{safe_name}`: {e}"));
                    continue;
                }
                let disk_path: PathBuf = out_dir.join(&safe_name);
                if let Some(parent) = disk_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&disk_path, &data)?;
                encoding.insert(safe_name.clone(), EntryCompression::Stored);
                entries.push(ExtractedEntry {
                    name: safe_name,
                    disk_path: Some(disk_path),
                    uncompressed_size: size,
                    compressed_size: size,
                    compression: EntryCompression::Stored,
                    is_executable: false,
                });
            }
        }
        if entries.is_empty() {
            violations.push(format!(
                "dmg-apfs: {} APFS volume(s) parsed (see .disrobe-apfs-layout.json); fs-tree produced no directly-resolvable files (multi-node omap-indirected trees fall through to the raw image)",
                container.volumes.len()
            ));
        }
    }

    for base in crate::containers::hfsplus::locate_hfsplus_volumes(&image) {
        let Ok(volume): Result<crate::containers::HfsVolume> =
            crate::containers::hfsplus::parse_hfsplus_at(&image, base)
        else {
            continue;
        };
        for file in &volume.files {
            let full: String = volume.full_path(file);
            let safe_name: String = match sanitize_entry_path(&full) {
                Ok(s) => s,
                Err(e) => {
                    violations.push(format!("dmg-hfs-slip: {e}"));
                    continue;
                }
            };
            let data: Vec<u8> = crate::containers::hfsplus::file_data(
                &image,
                &volume,
                file,
                quota.max_per_entry_uncompressed,
            );
            let size: u64 = data.len() as u64;
            if let Err(e) = guard.admit_entry(&safe_name, size, size) {
                violations.push(format!("dmg-hfs-quota `{safe_name}`: {e}"));
                continue;
            }
            let disk_path: PathBuf = out_dir.join(&safe_name);
            if let Some(parent) = disk_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&disk_path, &data)?;
            encoding.insert(safe_name.clone(), EntryCompression::Stored);
            entries.push(ExtractedEntry {
                name: safe_name,
                disk_path: Some(disk_path),
                uncompressed_size: size,
                compressed_size: size,
                compression: EntryCompression::Stored,
                is_executable: false,
            });
        }
    }

    let safe_name: String = "disk-image.img".to_owned();
    guard.admit_entry(&safe_name, image_size, bytes.len() as u64)?;
    let disk_path: PathBuf = out_dir.join(&safe_name);
    std::fs::write(&disk_path, &image)?;
    encoding.insert(safe_name.clone(), EntryCompression::Other);
    encoding.insert(
        ".disrobe-dmg-layout.json".to_owned(),
        EntryCompression::Stored,
    );
    entries.push(ExtractedEntry {
        name: safe_name,
        disk_path: Some(disk_path),
        uncompressed_size: image_size,
        compressed_size: bytes.len() as u64,
        compression: EntryCompression::Other,
        is_executable: false,
    });
    Ok(ExtractionResult {
        kind: ContainerKind::Dmg,
        entries,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_iso(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let image: crate::containers::IsoImage = crate::containers::iso::parse_iso(bytes)?;
    std::fs::create_dir_all(out_dir)?;
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::new();
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();

    for entry in &image.files {
        if entry.is_dir {
            continue;
        }
        let safe_name: String = match sanitize_entry_path(&entry.path) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("iso-slip: {e}"));
                continue;
            }
        };
        let Some(data) = crate::containers::iso::file_data(bytes, entry) else {
            violations.push(format!("iso-bounds `{safe_name}`: extent out of range"));
            continue;
        };
        let size: u64 = data.len() as u64;
        if let Err(e) = guard.admit_entry(&safe_name, size, size) {
            violations.push(format!("iso-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, data)?;
        encoding.insert(safe_name.clone(), EntryCompression::Stored);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: size,
            compression: EntryCompression::Stored,
            is_executable: false,
        });
    }

    Ok(ExtractionResult {
        kind: ContainerKind::Iso,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_bun(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let archive: crate::containers::BunStandalone = crate::containers::bun::parse_bun(bytes)?;
    std::fs::create_dir_all(out_dir)?;
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::with_capacity(archive.modules.len());
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();

    for module in &archive.modules {
        let cleaned: String = crate::containers::bun::sanitize_bun_name(&module.name);
        let safe_name: String = match sanitize_entry_path(&cleaned) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("bun-slip: {e}"));
                continue;
            }
        };
        let Some(contents) = crate::containers::bun::module_contents(bytes, &archive, module)
        else {
            violations.push(format!(
                "bun-bounds `{safe_name}`: module contents out of range"
            ));
            continue;
        };
        let size: u64 = contents.len() as u64;
        if let Err(e) = guard.admit_entry(&safe_name, size, size) {
            violations.push(format!("bun-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, contents)?;
        encoding.insert(safe_name.clone(), EntryCompression::Stored);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: size,
            compression: EntryCompression::Stored,
            is_executable: false,
        });
        if module.sourcemap_length > 0
            && let Some(map) = bytes.get(
                archive.data_start as usize + module.sourcemap_offset as usize
                    ..archive.data_start as usize
                        + module.sourcemap_offset as usize
                        + module.sourcemap_length as usize,
            )
        {
            let map_name: String = format!("{cleaned}.map");
            if let Ok(map_safe) = sanitize_entry_path(&map_name) {
                let map_path: PathBuf = out_dir.join(&map_safe);
                if let Some(parent) = map_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&map_path, map)?;
                encoding.insert(map_safe, EntryCompression::Stored);
            }
        }
    }

    Ok(ExtractionResult {
        kind: ContainerKind::BunStandalone,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_squirrel(
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let layout: crate::containers::SquirrelLayout = crate::containers::detect_squirrel(bytes)
        .ok_or_else(|| {
            Error::Squirrel(
                "input is not a recognizable Squirrel installer (no marker, no embedded nupkg)"
                    .to_owned(),
            )
        })?;
    std::fs::create_dir_all(out_dir)?;
    let json: String =
        serde_json::to_string_pretty(&layout).unwrap_or_else(|_: serde_json::Error| String::new());
    let layout_path: PathBuf = out_dir.join(".disrobe-squirrel-layout.json");
    std::fs::write(&layout_path, json.as_bytes())?;

    let Some(offset): Option<u64> = layout.nupkg_offset else {
        return Err(Error::Squirrel(format!(
            "squirrel marker present (marker={}) but no embedded nupkg zip is appended to this PE; the application payload ships as a sibling `packages/*.nupkg` (a standard zip) - extract that directly",
            layout.squirrel_marker_present
        )));
    };
    let start: usize = usize::try_from(offset).map_err(|_e: std::num::TryFromIntError| {
        Error::Squirrel("nupkg offset overflow".to_owned())
    })?;
    let nupkg: &[u8] = bytes
        .get(start..)
        .ok_or_else(|| Error::Squirrel("nupkg offset past end of input".to_owned()))?;
    let installer_quota: ExtractionQuota = ExtractionQuota {
        max_aggregate_ratio: quota.max_aggregate_ratio.max(200),
        max_per_entry_ratio: quota.max_per_entry_ratio.max(1000),
        ..quota
    };
    let mut result: ExtractionResult =
        extract_zip(ContainerKind::Squirrel, nupkg, out_dir, installer_quota).map_err(
            |e: Error| match e {
                Error::Zip(s) => Error::Squirrel(format!("embedded nupkg unzip: {s}")),
                other => other,
            },
        )?;
    result.encoding.insert(
        ".disrobe-squirrel-layout.json".to_owned(),
        EntryCompression::Stored,
    );
    result.kind = ContainerKind::Squirrel;
    Ok(result)
}

fn extract_flatpak(
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let extraction: crate::containers::FlatpakExtraction =
        crate::containers::extract_flatpak_bundle(bytes)?;
    std::fs::create_dir_all(out_dir)?;
    let installer_quota: ExtractionQuota = ExtractionQuota {
        max_aggregate_ratio: quota.max_aggregate_ratio.max(1000),
        max_per_entry_ratio: quota.max_per_entry_ratio.max(1000),
        ..quota
    };
    let mut guard: QuotaGuard = QuotaGuard::new(installer_quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::with_capacity(extraction.files.len());
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = extraction.notes.clone();

    for file in &extraction.files {
        if file.symlink_target.is_some() {
            continue;
        }
        let safe_name: String = match sanitize_entry_path(&file.path) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("flatpak-slip: {e}"));
                continue;
            }
        };
        let size: u64 = file.content.len() as u64;
        if let Err(e) = guard.admit_entry(&safe_name, size, size) {
            violations.push(format!("flatpak-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &file.content)?;
        encoding.insert(safe_name.clone(), EntryCompression::Deflate);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: size,
            compression: EntryCompression::Deflate,
            is_executable: file.mode & 0o111 != 0,
        });
    }

    let summary_json: String = serde_json::to_string_pretty(&extraction.source)
        .unwrap_or_else(|_: serde_json::Error| String::new());
    let summary_path: PathBuf = out_dir.join(".disrobe-flatpak.json");
    std::fs::write(&summary_path, summary_json.as_bytes())?;
    encoding.insert(".disrobe-flatpak.json".to_owned(), EntryCompression::Stored);
    entries_out.push(ExtractedEntry {
        name: ".disrobe-flatpak.json".to_owned(),
        disk_path: Some(summary_path),
        uncompressed_size: summary_json.len() as u64,
        compressed_size: summary_json.len() as u64,
        compression: EntryCompression::Stored,
        is_executable: false,
    });

    Ok(ExtractionResult {
        kind: ContainerKind::Flatpak,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_innosetup(
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let info: crate::containers::InnoSetupInfo = crate::containers::detect_innosetup(bytes)
        .ok_or_else(|| {
            Error::InnoSetup(
                "no `Inno Setup Setup Data (X.Y.Z)` id string found in input".to_owned(),
            )
        })?;
    std::fs::create_dir_all(out_dir)?;
    let installer_quota: ExtractionQuota = ExtractionQuota {
        max_aggregate_ratio: quota.max_aggregate_ratio.max(1000),
        max_per_entry_ratio: quota.max_per_entry_ratio.max(1000),
        ..quota
    };
    let mut guard: QuotaGuard = QuotaGuard::new(installer_quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::new();
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();

    let info_json: String =
        serde_json::to_string_pretty(&info).unwrap_or_else(|_: serde_json::Error| String::new());
    let info_path: PathBuf = out_dir.join(".disrobe-innosetup-info.json");
    std::fs::write(&info_path, info_json.as_bytes())?;
    encoding.insert(
        ".disrobe-innosetup-info.json".to_owned(),
        EntryCompression::Stored,
    );
    entries_out.push(ExtractedEntry {
        name: ".disrobe-innosetup-info.json".to_owned(),
        disk_path: Some(info_path),
        uncompressed_size: info_json.len() as u64,
        compressed_size: info_json.len() as u64,
        compression: EntryCompression::Stored,
        is_executable: false,
    });

    if let Ok(decoded) = crate::containers::extract_inno_block_stream(bytes, &info) {
        let blob_name: String = "setup-headers.bin".to_owned();
        let blob_path: PathBuf = out_dir.join(&blob_name);
        std::fs::write(&blob_path, &decoded)?;
        encoding.insert(blob_name.clone(), EntryCompression::Deflate);
        entries_out.push(ExtractedEntry {
            name: blob_name,
            disk_path: Some(blob_path),
            uncompressed_size: decoded.len() as u64,
            compressed_size: info.stored_size.into(),
            compression: EntryCompression::Deflate,
            is_executable: false,
        });
    } else {
        violations.push(
            "inno setup-data header stream uses lzma1 props (not decoded in-tree); per-file content is still recovered from the data area".to_owned(),
        );
    }

    let chunks: Vec<crate::containers::InnoFileChunk> =
        crate::containers::extract_inno_file_chunks(bytes, &info, quota.max_total_uncompressed);
    for (index, chunk) in chunks.iter().enumerate() {
        let name: String = format!("file-{index}.bin");
        let size: u64 = chunk.data.len() as u64;
        if let Err(e) = guard.admit_entry(&name, size, size) {
            violations.push(format!("inno-quota `{name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&name);
        std::fs::write(&disk_path, &chunk.data)?;
        let entry_compression: EntryCompression = match chunk.compression {
            crate::containers::InnoCompression::Stored => EntryCompression::Stored,
            _ => EntryCompression::Deflate,
        };
        encoding.insert(name.clone(), entry_compression);
        entries_out.push(ExtractedEntry {
            name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: size,
            compression: entry_compression,
            is_executable: false,
        });
    }
    if let Some(loader) = info.loader
        && loader.exe_offset > 0
        && loader.exe_compressed_size > 0
    {
        let start: usize = loader.exe_offset as usize;
        let end: usize = start.saturating_add(loader.exe_compressed_size as usize);
        if let Some(engine) = bytes.get(start..end.min(bytes.len())) {
            let name: String = "setup-engine.lzma".to_owned();
            let disk_path: PathBuf = out_dir.join(&name);
            std::fs::write(&disk_path, engine)?;
            encoding.insert(name.clone(), EntryCompression::Stored);
            entries_out.push(ExtractedEntry {
                name,
                disk_path: Some(disk_path),
                uncompressed_size: loader.exe_uncompressed_size,
                compressed_size: engine.len() as u64,
                compression: EntryCompression::Stored,
                is_executable: true,
            });
        }
    }
    if chunks.is_empty() {
        violations.push(
            "inno data area held no decodable file chunks (a password-encrypted installer gates file content behind a runtime password: only salt and verifier are present in the artifact)".to_owned(),
        );
    } else {
        violations.push(
            "inno per-file destination names and solid-chunk file boundaries require the version-gated TSetupFile/data_entry walk; members are emitted by data-area chunk order (solid chunks are emitted as one concatenated member)".to_owned(),
        );
    }

    Ok(ExtractionResult {
        kind: ContainerKind::InnoSetup,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_installshield(
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let files: Vec<crate::containers::InstallShieldFile> =
        crate::containers::walk_installshield(bytes, quota.max_total_uncompressed)?;
    std::fs::create_dir_all(out_dir)?;
    let installer_quota: ExtractionQuota = ExtractionQuota {
        max_aggregate_ratio: quota.max_aggregate_ratio.max(1000),
        max_per_entry_ratio: quota.max_per_entry_ratio.max(1000),
        ..quota
    };
    let mut guard: QuotaGuard = QuotaGuard::new(installer_quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::with_capacity(files.len());
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();
    for file in &files {
        let safe_name: String = match sanitize_entry_path(&file.name) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("installshield-slip: {e}"));
                continue;
            }
        };
        let size: u64 = file.data.len() as u64;
        if let Err(e) = guard.admit_entry(&safe_name, size, size) {
            violations.push(format!("installshield-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &file.data)?;
        let compression: EntryCompression = if file.compressed {
            EntryCompression::Deflate
        } else {
            EntryCompression::Stored
        };
        encoding.insert(safe_name.clone(), compression);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: size,
            compression,
            is_executable: false,
        });
    }
    Ok(ExtractionResult {
        kind: ContainerKind::InstallShield,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

const fn nsis_entry_compression(method: crate::containers::NsisCompression) -> EntryCompression {
    match method {
        crate::containers::NsisCompression::Stored => EntryCompression::Stored,
        crate::containers::NsisCompression::Deflate => EntryCompression::Deflate,
        crate::containers::NsisCompression::Lzma => EntryCompression::Lzma,
        crate::containers::NsisCompression::Bzip2 => EntryCompression::Bzip2,
    }
}

fn nsis_relative_path(name: &str) -> String {
    let normalized: String = name.replace('\\', "/");
    let segments: Vec<&str> = normalized
        .split('/')
        .filter(|s: &&str| !s.is_empty())
        .collect();
    let mut kept: Vec<&str> = Vec::with_capacity(segments.len());
    let mut leading: bool = true;
    for seg in segments {
        if leading && is_nsis_var_segment(seg) {
            continue;
        }
        leading = false;
        kept.push(seg);
    }
    if kept.is_empty() {
        return normalized.trim_matches('/').to_owned();
    }
    kept.join("/")
}

fn is_nsis_var_segment(seg: &str) -> bool {
    seg.starts_with('$')
        || seg.chars().all(|c: char| c.is_ascii_digit())
        || seg.eq_ignore_ascii_case("temp")
        || seg.eq_ignore_ascii_case("plugins")
}

fn extract_nsis(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let archive: crate::containers::NsisArchive =
        crate::containers::nsis::parse_nsis_archive(bytes).map_err(|e: Error| match e {
            Error::Decompression(s) => Error::Nsis(s),
            other => other,
        })?;
    std::fs::create_dir_all(out_dir)?;
    let json: String = serde_json::to_string_pretty(&archive).map_err(|e: serde_json::Error| {
        Error::Decompression(format!("nsis: serialize header failed: {e}"))
    })?;
    let header_json_path: PathBuf = out_dir.join(".disrobe-nsis-header.json");
    std::fs::write(&header_json_path, json.as_bytes())?;

    let entry_compression: EntryCompression = nsis_entry_compression(archive.compression);
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::with_capacity(archive.files.len());
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();
    let cap: u64 = quota.max_per_entry_uncompressed;
    let solid_stream: Option<Vec<u8>> = if archive.solid {
        crate::containers::nsis::decode_solid_region(bytes, &archive, quota.max_total_uncompressed)
            .ok()
    } else {
        None
    };

    let decode = |file: &crate::containers::NsisFileEntry| -> Result<Vec<u8>> {
        solid_stream.as_deref().map_or_else(
            || crate::containers::nsis::decompress_file(bytes, &archive, file, cap),
            |stream: &[u8]| crate::containers::nsis::slice_solid_file(stream, file, cap),
        )
    };

    let mut recovered: usize = 0;
    for file in &archive.files {
        let rel: String = nsis_relative_path(&file.name);
        let safe_name: String = match sanitize_entry_path(&rel) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("nsis-slip: {e}"));
                continue;
            }
        };
        let data: Vec<u8> = match decode(file) {
            Ok(d) => d,
            Err(e) => {
                violations.push(format!("nsis-decode `{safe_name}`: {e}"));
                continue;
            }
        };
        let uncompressed_size: u64 = data.len() as u64;
        if let Err(e) = guard.admit_entry(&safe_name, uncompressed_size, uncompressed_size) {
            violations.push(format!("nsis-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &data)?;
        encoding.insert(safe_name.clone(), entry_compression);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size,
            compressed_size: uncompressed_size,
            compression: entry_compression,
            is_executable: false,
        });
        recovered += 1;
    }

    if recovered == 0 && !archive.files.is_empty() {
        return Err(Error::Nsis(format!(
            "nsis archive parsed ({} extract-file instructions) but every member failed to decode; compression={:?} solid={}",
            archive.files.len(),
            archive.compression,
            archive.solid
        )));
    }

    encoding.insert(
        ".disrobe-nsis-header.json".to_owned(),
        EntryCompression::Stored,
    );
    Ok(ExtractionResult {
        kind: ContainerKind::Nsis,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
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
            let entry_size: u64 = entry.header().size();
            let buf: Vec<u8> = read_entry_to_limit(&mut entry, trimmed, entry_size).map_err(
                |e: Error| match e {
                    Error::Io(e) => Error::Deb(format!("reading {trimmed}: {e}")),
                    other => other,
                },
            )?;
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
        "data.tar.lzma" => CompressionWrap::Lzma,
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
        CompressionWrap::Lzma => EntryCompression::Lzma,
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

#[cfg(feature = "rpm")]
fn rpm_payload_wrap(compressor: rpm::CompressionType, payload: &[u8]) -> PayloadWrap {
    match compressor {
        rpm::CompressionType::None => sniff_payload_wrap(payload),
        rpm::CompressionType::Gzip => PayloadWrap::Compressed(CompressionWrap::Gz),
        rpm::CompressionType::Xz => PayloadWrap::Compressed(CompressionWrap::Xz),
        rpm::CompressionType::Zstd => PayloadWrap::Compressed(CompressionWrap::Zst),
        rpm::CompressionType::Bzip2 => PayloadWrap::Compressed(CompressionWrap::Bz2),
    }
}

#[cfg(feature = "rpm")]
fn sniff_payload_wrap(payload: &[u8]) -> PayloadWrap {
    match payload {
        [0x1f, 0x8b, ..] => PayloadWrap::Compressed(CompressionWrap::Gz),
        [0xfd, b'7', b'z', b'X', b'Z', 0x00, ..] => PayloadWrap::Compressed(CompressionWrap::Xz),
        [0x28, 0xb5, 0x2f, 0xfd, ..] => PayloadWrap::Compressed(CompressionWrap::Zst),
        [b'B', b'Z', b'h', ..] => PayloadWrap::Compressed(CompressionWrap::Bz2),
        _ => PayloadWrap::Stored,
    }
}

#[cfg(feature = "rpm")]
const fn rpm_entry_compression(wrap: PayloadWrap) -> EntryCompression {
    match wrap {
        PayloadWrap::Stored => EntryCompression::Stored,
        PayloadWrap::Compressed(CompressionWrap::Gz) => EntryCompression::Deflate,
        PayloadWrap::Compressed(CompressionWrap::Xz) => EntryCompression::Xz,
        PayloadWrap::Compressed(CompressionWrap::Zst) => EntryCompression::Zstd,
        PayloadWrap::Compressed(CompressionWrap::Bz2) => EntryCompression::Bzip2,
        PayloadWrap::Compressed(CompressionWrap::Lzma) => EntryCompression::Lzma,
    }
}

#[cfg(feature = "rpm")]
fn extract_rpm(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let mut reader: Cursor<&[u8]> = Cursor::new(bytes);
    let package: rpm::Package =
        rpm::Package::parse(&mut reader).map_err(|e| Error::Rpm(e.to_string()))?;
    let compressor: rpm::CompressionType = package
        .metadata
        .get_payload_compressor()
        .map_err(|e| Error::Rpm(e.to_string()))?;
    let payload: &[u8] = package.payload.as_slice();
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

#[cfg(feature = "rpm")]
#[derive(Debug)]
struct CpioEntry {
    name: String,
    mode: u32,
    data: Vec<u8>,
}

#[cfg(feature = "rpm")]
const fn is_cpio_regular_file(mode: u32) -> bool {
    mode & 0o170_000 == 0o100_000
}

#[cfg(feature = "rpm")]
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
    let name: String =
        String::from_utf8_lossy(name_bytes.split_last().map_or(name_bytes, |(_, n)| n))
            .into_owned();
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

#[cfg(feature = "rpm")]
fn cpio_hex_field(header: &[u8], start: usize) -> Result<u32> {
    let field: &[u8] = header
        .get(start..start + 8)
        .ok_or_else(|| Error::Rpm("cpio: header field out of range".to_owned()))?;
    let text: &str = std::str::from_utf8(field)
        .map_err(|e| Error::Rpm(format!("cpio: non-ascii header field: {e}")))?;
    u32::from_str_radix(text, 16)
        .map_err(|e| Error::Rpm(format!("cpio: bad hex header field `{text}`: {e}")))
}

#[cfg(feature = "rpm")]
const fn cpio_align4(value: usize) -> usize {
    value.next_multiple_of(4)
}

fn extract_cab(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    if crate::containers::cab_uses_lzms(bytes) {
        return extract_cab_lzms_folders(bytes, out_dir, quota);
    }
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
        let buf: Vec<u8> =
            read_entry_to_limit(&mut reader, &safe_name, quota.max_per_entry_uncompressed)
                .map_err(|e: Error| match e {
                    Error::Io(e) => Error::Cab(format!("reading {raw_name}: {e}")),
                    other => other,
                })?;
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

fn extract_cab_lzms_folders(
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::new();
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();
    let files: Vec<crate::containers::CabLzmsFile> =
        crate::containers::extract_cab_lzms(bytes, quota.max_per_entry_uncompressed)?;
    for file in files {
        let safe_name: String = match sanitize_entry_path(&file.name) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("cab-slip: {e}"));
                continue;
            }
        };
        let uncompressed_size: u64 = file.data.len() as u64;
        guard.admit_entry(&safe_name, uncompressed_size, uncompressed_size)?;
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &file.data)?;
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
    Lzma,
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
    let count: usize = archive.len();
    let max_entries: usize = quota.max_entries.min(crate::quota::ABSOLUTE_MAX_ENTRIES);
    if count > max_entries {
        return Err(Error::QuotaExceeded {
            entry: "<zip>".to_owned(),
            reason: format!("zip entry count {count} exceeds max_entries={max_entries}"),
        });
    }
    let mut entries: Vec<ExtractedEntry> =
        Vec::with_capacity(count.min(crate::quota::DEFAULT_MAX_ENTRIES));
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();

    for i in 0..count {
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
        let entry_compression: EntryCompression = encode_method(file.compression());
        crate::debug::dbg_kv(&format!("entry {safe_name}"), || {
            let ratio: u64 = uncompressed_size / compressed_size.max(1);
            format!(
                "{entry_compression:?} compressed={compressed_size} uncompressed={uncompressed_size} ratio={ratio} prealloc={}",
                bounded_prealloc(uncompressed_size)
            )
        });
        if let Err(e) = guard.admit_entry(&safe_name, uncompressed_size, compressed_size) {
            crate::debug::dbg_line(|| format!("zip-quota reject `{safe_name}`: {e}"));
            return Err(e);
        }
        let buf: Vec<u8> =
            read_entry_to_limit(&mut file, &safe_name, uncompressed_size).map_err(|e: Error| {
                match e {
                    Error::Io(e) => Error::ZipEntry {
                        name: safe_name.clone(),
                        reason: e.to_string(),
                    },
                    other => other,
                }
            })?;
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &buf)?;
        encoding.insert(safe_name.clone(), entry_compression);
        entries.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size,
            compressed_size,
            compression: entry_compression,
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
        CompressionWrap::Lzma => EntryCompression::Lzma,
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
        CompressionWrap::Lzma => {
            return decompress_lzma_alone_capped(bytes, cap, entry);
        }
    }
    .map_err(|e| Error::Decompression(e.to_string()))?;
    crate::debug::dbg_kv(&format!("decompress {entry}"), || {
        format!(
            "wrap={wrap:?} cap={cap} decompressed={read} compressed-in={}",
            bytes.len()
        )
    });
    if read > cap {
        crate::debug::dbg_line(|| {
            format!("decompression-bomb reject `{entry}`: {read} bytes exceeds cap {cap}")
        });
        return Err(Error::QuotaExceeded {
            entry: entry.to_owned(),
            reason: format!("decompressed stream exceeds bomb cap {cap}"),
        });
    }
    Ok(out)
}

fn decompress_lzma_alone_capped(bytes: &[u8], cap: u64, entry: &str) -> Result<Vec<u8>> {
    crate::containers::bare_stream::decompress_lzma_alone(bytes, cap).map_err(|e: Error| match e {
        Error::QuotaExceeded { reason, .. } => Error::QuotaExceeded {
            entry: entry.to_owned(),
            reason,
        },
        Error::Decompression(msg) => Error::Decompression(format!("{entry}: {msg}")),
        other => other,
    })
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
        let mode_bits: u32 = entry.header().mode().map_or(0, |value: u32| value);
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
        let buf: Vec<u8> = read_entry_to_limit(&mut entry, &safe_name, uncompressed_size).map_err(
            |e: Error| match e {
                Error::Io(e) => Error::Tar(e.to_string()),
                other => other,
            },
        )?;
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
                let buf: Vec<u8> = read_entry_to_limit(data, &safe_name, uncompressed_size)
                    .map_err(|e: Error| sevenz_rust2::Error::other(e.to_string()))?;
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

fn extract_cpio(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let archive: crate::containers::CpioArchive = crate::containers::parse_cpio(bytes)?;
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::with_capacity(archive.entries.len());
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();
    for entry in &archive.entries {
        let is_dir: bool = entry.mode & 0o170_000 == 0o040_000;
        let is_regular: bool = entry.mode & 0o170_000 == 0o100_000;
        let safe_name: String = match sanitize_entry_path(&entry.name) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("cpio-slip: {e}"));
                continue;
            }
        };
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if is_dir {
            std::fs::create_dir_all(&disk_path)?;
            continue;
        }
        if !is_regular {
            continue;
        }
        let size: u64 = entry.file_size;
        guard.admit_entry(&safe_name, size, size)?;
        let data_end: usize = entry
            .data_offset
            .checked_add(size as usize)
            .ok_or_else(|| Error::Tar("cpio entry data overflow".to_owned()))?;
        let view: &[u8] = bytes
            .get(entry.data_offset..data_end)
            .ok_or_else(|| Error::Tar(format!("cpio entry `{}` out of bounds", entry.name)))?;
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
            is_executable: entry.mode & 0o111 != 0,
        });
    }
    Ok(ExtractionResult {
        kind: ContainerKind::Cpio,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_ar(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let archive: crate::containers::ArArchive = crate::containers::parse_ar(bytes)?;
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::new();
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();
    for member in &archive.members {
        if member.is_special {
            continue;
        }
        let safe_name: String = match sanitize_entry_path(&member.name) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("ar-slip: {e}"));
                continue;
            }
        };
        let Some(data): Option<&[u8]> = crate::containers::ar_member_bytes(bytes, member) else {
            violations.push(format!("ar-bounds `{safe_name}`: member data out of range"));
            continue;
        };
        let size: u64 = data.len() as u64;
        if let Err(e) = guard.admit_entry(&safe_name, size, size) {
            violations.push(format!("ar-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, data)?;
        encoding.insert(safe_name.clone(), EntryCompression::Stored);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: size,
            compression: EntryCompression::Stored,
            is_executable: false,
        });
    }
    Ok(ExtractionResult {
        kind: ContainerKind::Ar,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_arj(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let archive: crate::containers::ArjArchive = crate::containers::parse_arj(bytes)?;
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::new();
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();
    for entry in &archive.entries {
        if entry.is_directory {
            continue;
        }
        let safe_name: String = match sanitize_entry_path(&entry.name) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("arj-slip: {e}"));
                continue;
            }
        };
        let data: Vec<u8> = match crate::containers::arj_entry_bytes(
            bytes,
            entry,
            quota.max_per_entry_uncompressed,
        ) {
            Ok(d) => d,
            Err(e) => {
                violations.push(format!("arj `{safe_name}`: {e}"));
                continue;
            }
        };
        let size: u64 = data.len() as u64;
        if let Err(e) = guard.admit_entry(&safe_name, size, entry.compressed_size.into()) {
            violations.push(format!("arj-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &data)?;
        let compression: EntryCompression = if crate::containers::arj_entry_is_stored(entry) {
            EntryCompression::Stored
        } else {
            EntryCompression::Other
        };
        encoding.insert(safe_name.clone(), compression);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: u64::from(entry.compressed_size),
            compression,
            is_executable: false,
        });
    }
    Ok(ExtractionResult {
        kind: ContainerKind::Arj,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_arc(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let archive: crate::containers::ArcArchive = crate::containers::parse_arc(bytes)?;
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::new();
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();
    for entry in &archive.entries {
        let safe_name: String = match sanitize_entry_path(&entry.name) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("arc-slip: {e}"));
                continue;
            }
        };
        let data: Vec<u8> = match crate::containers::arc_entry_bytes(
            bytes,
            entry,
            quota.max_per_entry_uncompressed,
        ) {
            Ok(d) => d,
            Err(e) => {
                violations.push(format!("arc `{safe_name}`: {e}"));
                continue;
            }
        };
        let size: u64 = data.len() as u64;
        if let Err(e) = guard.admit_entry(&safe_name, size, u64::from(entry.compressed_size)) {
            violations.push(format!("arc-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &data)?;
        let compression: EntryCompression = if crate::containers::arc_entry_is_stored(entry) {
            EntryCompression::Stored
        } else {
            EntryCompression::Other
        };
        encoding.insert(safe_name.clone(), compression);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: u64::from(entry.compressed_size),
            compression,
            is_executable: false,
        });
    }
    Ok(ExtractionResult {
        kind: ContainerKind::Arc,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_lzh(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let archive: crate::containers::LzhArchive =
        crate::containers::parse_lzh(bytes, quota.max_total_uncompressed)?;
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::new();
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = archive.notes.clone();
    for file in &archive.files {
        if file.is_directory || !file.decoder_supported {
            continue;
        }
        let safe_name: String = match sanitize_entry_path(&file.path) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("lzh-slip: {e}"));
                continue;
            }
        };
        let size: u64 = file.data.len() as u64;
        if let Err(e) = guard.admit_entry(&safe_name, size, size) {
            violations.push(format!("lzh-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &file.data)?;
        encoding.insert(safe_name.clone(), EntryCompression::Other);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: size,
            compression: EntryCompression::Other,
            is_executable: false,
        });
    }
    Ok(ExtractionResult {
        kind: ContainerKind::Lzh,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_lzop(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let file: crate::containers::LzopFile =
        crate::containers::parse_lzop(bytes, quota.max_total_uncompressed)?;
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let raw_name: String = if file.name.is_empty() {
        "stream.bin".to_owned()
    } else {
        file.name.clone()
    };
    let safe_name: String = sanitize_entry_path(&raw_name)?;
    let size: u64 = file.data.len() as u64;
    guard.admit_entry(&safe_name, size, bytes.len() as u64)?;
    let disk_path: PathBuf = out_dir.join(&safe_name);
    if let Some(parent) = disk_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&disk_path, &file.data)?;
    encoding.insert(safe_name.clone(), EntryCompression::Other);
    let entries_out: Vec<ExtractedEntry> = vec![ExtractedEntry {
        name: safe_name,
        disk_path: Some(disk_path),
        uncompressed_size: size,
        compressed_size: bytes.len() as u64,
        compression: EntryCompression::Other,
        is_executable: false,
    }];
    Ok(ExtractionResult {
        kind: ContainerKind::Lzo,
        entries: entries_out,
        encoding,
        integrity_violations: Vec::new(),
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_uzip(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let image: crate::containers::UzipImage =
        crate::containers::parse_uzip(bytes, quota.max_total_uncompressed)?;
    let mut guard: QuotaGuard = QuotaGuard::new(ExtractionQuota {
        max_aggregate_ratio: quota.max_aggregate_ratio.max(1000),
        max_per_entry_ratio: quota.max_per_entry_ratio.max(1000),
        ..quota
    });
    let mut entries_out: Vec<ExtractedEntry> = Vec::new();
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();
    let name: String = "uzip.img".to_owned();
    let size: u64 = image.image.len() as u64;
    let compression: EntryCompression = match image.compressor {
        crate::containers::UzipCompressor::Zlib => EntryCompression::Deflate,
        crate::containers::UzipCompressor::Lzma => EntryCompression::Lzma,
        crate::containers::UzipCompressor::Zstd => EntryCompression::Zstd,
    };
    guard.admit_entry(&name, size, bytes.len() as u64)?;
    let disk_path: PathBuf = out_dir.join(&name);
    std::fs::write(&disk_path, &image.image)?;
    encoding.insert(name.clone(), compression);
    entries_out.push(ExtractedEntry {
        name,
        disk_path: Some(disk_path),
        uncompressed_size: size,
        compressed_size: bytes.len() as u64,
        compression,
        is_executable: false,
    });
    if let Some(inner) = container::detect_container(&image.image) {
        violations.push(format!(
            "uzip: reconstructed disk image is {} - re-run extraction on uzip.img",
            inner.label()
        ));
    }
    Ok(ExtractionResult {
        kind: ContainerKind::Uzip,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_xalz(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let asm: crate::containers::XalzAssembly =
        crate::containers::parse_xalz(bytes, quota.max_total_uncompressed)?;
    let mut guard: QuotaGuard = QuotaGuard::new(ExtractionQuota {
        max_aggregate_ratio: quota.max_aggregate_ratio.max(1000),
        max_per_entry_ratio: quota.max_per_entry_ratio.max(1000),
        ..quota
    });
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let name: String = "assembly.dll".to_owned();
    let size: u64 = asm.data.len() as u64;
    guard.admit_entry(&name, size, bytes.len() as u64)?;
    let disk_path: PathBuf = out_dir.join(&name);
    std::fs::write(&disk_path, &asm.data)?;
    encoding.insert(name.clone(), EntryCompression::Other);
    let entries_out: Vec<ExtractedEntry> = vec![ExtractedEntry {
        name,
        disk_path: Some(disk_path),
        uncompressed_size: size,
        compressed_size: bytes.len() as u64,
        compression: EntryCompression::Other,
        is_executable: false,
    }];
    Ok(ExtractionResult {
        kind: ContainerKind::Xalz,
        entries: entries_out,
        encoding,
        integrity_violations: Vec::new(),
        quota: QuotaSummary::from(guard.report()),
    })
}

#[derive(Debug, Serialize)]
struct Par2Summary<'a> {
    packet_count: usize,
    recovery_slice_count: usize,
    creator: Option<&'a str>,
    protected_files: Vec<Par2SummaryFile<'a>>,
}

#[derive(Debug, Serialize)]
struct Par2SummaryFile<'a> {
    name: &'a str,
    length: u64,
}

fn extract_par2(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let set: crate::containers::Par2RecoverySet = crate::containers::parse_par2(bytes)?;
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::new();
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let summary: Par2Summary<'_> = Par2Summary {
        packet_count: set.packets.len(),
        recovery_slice_count: set.recovery_slice_count,
        creator: set.creator.as_deref(),
        protected_files: set
            .protected_files
            .iter()
            .map(|f: &crate::containers::Par2ProtectedFile| Par2SummaryFile {
                name: &f.name,
                length: f.length,
            })
            .collect(),
    };
    let summary_json: String =
        serde_json::to_string_pretty(&summary).unwrap_or_else(|_: serde_json::Error| String::new());
    let summary_name: String = ".disrobe-par2.json".to_owned();
    let summary_path: PathBuf = out_dir.join(&summary_name);
    std::fs::write(&summary_path, summary_json.as_bytes())?;
    encoding.insert(summary_name.clone(), EntryCompression::Stored);
    entries_out.push(ExtractedEntry {
        name: summary_name,
        disk_path: Some(summary_path),
        uncompressed_size: summary_json.len() as u64,
        compressed_size: summary_json.len() as u64,
        compression: EntryCompression::Stored,
        is_executable: false,
    });
    let recovery_name: String = "recovery-set.par2".to_owned();
    let size: u64 = bytes.len() as u64;
    guard.admit_entry(&recovery_name, size, size)?;
    let recovery_path: PathBuf = out_dir.join(&recovery_name);
    std::fs::write(&recovery_path, bytes)?;
    encoding.insert(recovery_name.clone(), EntryCompression::Stored);
    entries_out.push(ExtractedEntry {
        name: recovery_name,
        disk_path: Some(recovery_path),
        uncompressed_size: size,
        compressed_size: size,
        compression: EntryCompression::Stored,
        is_executable: false,
    });
    Ok(ExtractionResult {
        kind: ContainerKind::Par2,
        entries: entries_out,
        encoding,
        integrity_violations: Vec::new(),
        quota: QuotaSummary::from(guard.report()),
    })
}

fn carve_only_payload(
    kind: ContainerKind,
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
    member_name: &str,
    note: String,
) -> Result<ExtractionResult> {
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let safe_name: String = sanitize_entry_path(member_name)?;
    let size: u64 = bytes.len() as u64;
    guard.admit_entry(&safe_name, size, size)?;
    let disk_path: PathBuf = out_dir.join(&safe_name);
    std::fs::write(&disk_path, bytes)?;
    encoding.insert(safe_name.clone(), EntryCompression::Other);
    let entries_out: Vec<ExtractedEntry> = vec![ExtractedEntry {
        name: safe_name,
        disk_path: Some(disk_path),
        uncompressed_size: size,
        compressed_size: size,
        compression: EntryCompression::Other,
        is_executable: false,
    }];
    Ok(ExtractionResult {
        kind,
        entries: entries_out,
        encoding,
        integrity_violations: vec![note],
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_partclone(
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let image: crate::containers::PartcloneImage = crate::containers::detect_partclone(bytes)
        .ok_or_else(|| Error::Partclone("partclone: signature not recognized".to_owned()))?;
    if image.version != *b"0002" {
        let version: String = String::from_utf8_lossy(&image.version).into_owned();
        return carve_only_payload(
            ContainerKind::Partclone,
            bytes,
            out_dir,
            quota,
            "partclone.img",
            format!(
                "partclone v{version} carved verbatim: only the v0002 on-disk header is reconstructed in tree"
            ),
        );
    }
    let raw: Vec<u8> =
        crate::containers::reconstruct_partclone(bytes, quota.max_total_uncompressed)?;
    std::fs::create_dir_all(out_dir)?;
    let mut guard: QuotaGuard = QuotaGuard::new(ExtractionQuota {
        max_aggregate_ratio: quota.max_aggregate_ratio.max(1000),
        max_per_entry_ratio: quota.max_per_entry_ratio.max(1000),
        ..quota
    });
    let mut entries_out: Vec<ExtractedEntry> = Vec::new();
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();

    let name: String = "partclone.img".to_owned();
    let size: u64 = raw.len() as u64;
    guard.admit_entry(&name, size, bytes.len() as u64)?;
    let disk_path: PathBuf = out_dir.join(&name);
    std::fs::write(&disk_path, &raw)?;
    encoding.insert(name.clone(), EntryCompression::Other);
    entries_out.push(ExtractedEntry {
        name,
        disk_path: Some(disk_path),
        uncompressed_size: size,
        compressed_size: bytes.len() as u64,
        compression: EntryCompression::Other,
        is_executable: false,
    });
    if let Some(inner) = container::detect_container(&raw) {
        violations.push(format!(
            "partclone: reconstructed filesystem image is {} - re-run extraction on partclone.img",
            inner.label()
        ));
    }
    Ok(ExtractionResult {
        kind: ContainerKind::Partclone,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_stuffit(
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let kind: crate::containers::StuffItKind = crate::containers::detect_stuffit(bytes)
        .ok_or_else(|| Error::StuffIt("stuffit: signature not recognized".to_owned()))?;
    if kind != crate::containers::StuffItKind::Classic {
        return carve_only_payload(
            ContainerKind::StuffIt,
            bytes,
            out_dir,
            quota,
            "archive.sit",
            format!(
                "stuffit {kind:?} archive carved verbatim: only the classic SIT! container directory is parsed in tree"
            ),
        );
    }
    let archive: crate::containers::SitArchive = crate::containers::parse_sit_classic(bytes)?;
    std::fs::create_dir_all(out_dir)?;
    let mut guard: QuotaGuard = QuotaGuard::new(ExtractionQuota {
        max_aggregate_ratio: quota.max_aggregate_ratio.max(1000),
        max_per_entry_ratio: quota.max_per_entry_ratio.max(1000),
        ..quota
    });
    let mut entries_out: Vec<ExtractedEntry> = Vec::new();
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();

    for entry in &archive.entries {
        if entry.is_folder {
            continue;
        }
        for (suffix, fork) in [("", &entry.data), (".rsrc", &entry.resource)] {
            if fork.compressed_len == 0 {
                continue;
            }
            let raw_name: String = format!("{}{suffix}", entry.name);
            let safe_name: String = match sanitize_entry_path(&raw_name) {
                Ok(s) => s,
                Err(e) => {
                    violations.push(format!("stuffit-slip: {e}"));
                    continue;
                }
            };
            let data: Vec<u8> = match crate::containers::sit_fork_bytes(bytes, fork) {
                Ok(d) => d,
                Err(e) => {
                    violations.push(format!("stuffit `{safe_name}`: {e}"));
                    continue;
                }
            };
            let size: u64 = data.len() as u64;
            if let Err(e) = guard.admit_entry(&safe_name, size, u64::from(fork.compressed_len)) {
                violations.push(format!("stuffit-quota `{safe_name}`: {e}"));
                continue;
            }
            let disk_path: PathBuf = out_dir.join(&safe_name);
            if let Some(parent) = disk_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&disk_path, &data)?;
            let compression: EntryCompression = if crate::containers::sit_fork_is_stored(fork) {
                EntryCompression::Stored
            } else {
                EntryCompression::Other
            };
            encoding.insert(safe_name.clone(), compression);
            entries_out.push(ExtractedEntry {
                name: safe_name,
                disk_path: Some(disk_path),
                uncompressed_size: size,
                compressed_size: u64::from(fork.compressed_len),
                compression,
                is_executable: false,
            });
        }
    }
    Ok(ExtractionResult {
        kind: ContainerKind::StuffIt,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_qnx(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let kind: crate::containers::QnxKind = crate::containers::detect_qnx(bytes)
        .ok_or_else(|| Error::Qnx("qnx: signature not recognized".to_owned()))?;
    if kind == crate::containers::QnxKind::IfsStartup
        && let Some(header) = crate::containers::qnx_parse_startup(bytes)
        && header.compress == crate::containers::QnxCompress::Zlib
    {
        let cap: usize =
            usize::try_from(quota.max_total_uncompressed).map_or(usize::MAX, |value: usize| value);
        let image: Vec<u8> = crate::containers::qnx_inflate_startup_zlib(bytes, &header, cap)?;
        std::fs::create_dir_all(out_dir)?;
        let mut guard: QuotaGuard = QuotaGuard::new(ExtractionQuota {
            max_aggregate_ratio: quota.max_aggregate_ratio.max(1000),
            max_per_entry_ratio: quota.max_per_entry_ratio.max(1000),
            ..quota
        });
        let mut entries_out: Vec<ExtractedEntry> = Vec::new();
        let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
        let name: String = "qnx-ifs.img".to_owned();
        let size: u64 = image.len() as u64;
        guard.admit_entry(&name, size, bytes.len() as u64)?;
        let disk_path: PathBuf = out_dir.join(&name);
        std::fs::write(&disk_path, &image)?;
        encoding.insert(name.clone(), EntryCompression::Deflate);
        entries_out.push(ExtractedEntry {
            name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: bytes.len() as u64,
            compression: EntryCompression::Deflate,
            is_executable: false,
        });
        return Ok(ExtractionResult {
            kind: ContainerKind::Qnx,
            entries: entries_out,
            encoding,
            integrity_violations: vec![
                "qnx ifs startup decompressed via zlib gzip stream".to_owned(),
            ],
            quota: QuotaSummary::from(guard.report()),
        });
    }
    if kind == crate::containers::QnxKind::IfsStartup
        && let Some((offset, variant, image)) = qnx_try_ucl(bytes, quota.max_total_uncompressed)
    {
        std::fs::create_dir_all(out_dir)?;
        let mut guard: QuotaGuard = QuotaGuard::new(ExtractionQuota {
            max_aggregate_ratio: quota.max_aggregate_ratio.max(1000),
            max_per_entry_ratio: quota.max_per_entry_ratio.max(1000),
            ..quota
        });
        let mut entries_out: Vec<ExtractedEntry> = Vec::new();
        let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
        let name: String = "qnx-ifs.img".to_owned();
        let size: u64 = image.len() as u64;
        guard.admit_entry(&name, size, bytes.len() as u64)?;
        let disk_path: PathBuf = out_dir.join(&name);
        std::fs::write(&disk_path, &image)?;
        encoding.insert(name.clone(), EntryCompression::Other);
        entries_out.push(ExtractedEntry {
            name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: bytes.len() as u64,
            compression: EntryCompression::Other,
            is_executable: false,
        });
        let note: String = format!(
            "qnx ifs startup decompressed via {variant:?} (compressed segment stream at offset {offset})"
        );
        return Ok(ExtractionResult {
            kind: ContainerKind::Qnx,
            entries: entries_out,
            encoding,
            integrity_violations: vec![note],
            quota: QuotaSummary::from(guard.report()),
        });
    }
    carve_only_payload(
        ContainerKind::Qnx,
        bytes,
        out_dir,
        quota,
        "qnx-image.bin",
        format!(
            "qnx {kind:?} image carved verbatim: no nrv2b/nrv2d/nrv2e compressed-segment stream was located after the startup header (an uncompressed or qnx6-fs image needs no decompression)"
        ),
    )
}

fn qnx_try_ucl(
    bytes: &[u8],
    max_total: u64,
) -> Option<(usize, crate::containers::ucl::NrvVariant, Vec<u8>)> {
    use crate::containers::ucl::NrvVariant;
    let cap: usize = usize::try_from(max_total).map_or(usize::MAX, |value: usize| value);
    let scan_end: usize = bytes.len().min(8192);
    for offset in (4..scan_end).step_by(2) {
        for variant in [NrvVariant::Nrv2b, NrvVariant::Nrv2d, NrvVariant::Nrv2e] {
            if let Ok(image) =
                crate::containers::qnx_decompress_ucl_segments(variant, &bytes[offset..], cap)
                && image.len() >= 512
            {
                return Some((offset, variant, image));
            }
        }
    }
    None
}

fn extract_bare_xz(
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let cap: u64 = quota.max_total_uncompressed;
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let payload: Vec<u8> = decompress_wrap_capped(bytes, CompressionWrap::Xz, cap, "stream.xz")?;
    let uncompressed_size: u64 = payload.len() as u64;
    let safe_name: String = sanitize_entry_path("stream.bin")?;
    guard.admit_entry(&safe_name, uncompressed_size, bytes.len() as u64)?;
    let disk_path: PathBuf = out_dir.join(&safe_name);
    std::fs::write(&disk_path, &payload)?;
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    encoding.insert(safe_name.clone(), EntryCompression::Xz);
    let entries: Vec<ExtractedEntry> = vec![ExtractedEntry {
        name: safe_name,
        disk_path: Some(disk_path),
        uncompressed_size,
        compressed_size: bytes.len() as u64,
        compression: EntryCompression::Xz,
        is_executable: false,
    }];
    Ok(ExtractionResult {
        kind: ContainerKind::Xz,
        entries,
        encoding,
        integrity_violations: Vec::new(),
        quota: QuotaSummary::from(guard.report()),
    })
}

const fn bare_stream_output_name(kind: ContainerKind) -> &'static str {
    match kind {
        ContainerKind::Bzip2 => "stream.bz2.out",
        ContainerKind::Zstd => "stream.zst.out",
        ContainerKind::Lzma => "stream.lzma.out",
        ContainerKind::Lzip => "stream.lz.out",
        ContainerKind::Lz4 => "stream.lz4.out",
        ContainerKind::Zlib => "stream.zlib.out",
        ContainerKind::UnixCompress => "stream.Z.out",
        _ => "stream.bin",
    }
}

const fn bare_stream_compression(kind: ContainerKind) -> EntryCompression {
    match kind {
        ContainerKind::Bzip2 => EntryCompression::Bzip2,
        ContainerKind::Zstd => EntryCompression::Zstd,
        ContainerKind::Lzma | ContainerKind::Lzip => EntryCompression::Lzma,
        ContainerKind::Zlib => EntryCompression::Deflate,
        _ => EntryCompression::Other,
    }
}

fn decode_bare_stream(kind: ContainerKind, bytes: &[u8], cap: u64) -> Result<Vec<u8>> {
    match kind {
        ContainerKind::Bzip2 => crate::containers::bare_stream::decompress_bzip2(bytes, cap),
        ContainerKind::Zstd => crate::containers::bare_stream::decompress_zstd(bytes, cap),
        ContainerKind::Lzma => decompress_lzma_alone_capped(bytes, cap, "stream.lzma"),
        ContainerKind::Lzip => crate::containers::bare_stream::decompress_lzip(bytes, cap),
        ContainerKind::Lz4 => crate::containers::bare_stream::decompress_lz4(bytes, cap),
        ContainerKind::Zlib => crate::containers::bare_stream::inflate_zlib_verified(bytes, cap),
        ContainerKind::UnixCompress => {
            crate::containers::bare_stream::decompress_compress(bytes, cap)
        }
        _ => Err(Error::UnsupportedContainer(kind.label())),
    }
}

fn extract_bare_single_stream(
    kind: ContainerKind,
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let cap: u64 = quota.max_total_uncompressed;
    let stream_quota: ExtractionQuota = ExtractionQuota {
        max_aggregate_ratio: quota.max_aggregate_ratio.max(1000),
        max_per_entry_ratio: quota.max_per_entry_ratio.max(1000),
        ..quota
    };
    let mut guard: QuotaGuard = QuotaGuard::new(stream_quota);
    let payload: Vec<u8> = decode_bare_stream(kind, bytes, cap)?;
    let uncompressed_size: u64 = payload.len() as u64;
    let compression: EntryCompression = bare_stream_compression(kind);
    let safe_name: String = sanitize_entry_path(bare_stream_output_name(kind))?;
    guard.admit_entry(&safe_name, uncompressed_size, bytes.len() as u64)?;
    let disk_path: PathBuf = out_dir.join(&safe_name);
    std::fs::write(&disk_path, &payload)?;
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    encoding.insert(safe_name.clone(), compression);
    let entries: Vec<ExtractedEntry> = vec![ExtractedEntry {
        name: safe_name,
        disk_path: Some(disk_path),
        uncompressed_size,
        compressed_size: bytes.len() as u64,
        compression,
        is_executable: false,
    }];
    Ok(ExtractionResult {
        kind,
        entries,
        encoding,
        integrity_violations: Vec::new(),
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_bare_gzip(
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let cap: u64 = quota.max_total_uncompressed;
    let stream_quota: ExtractionQuota = ExtractionQuota {
        max_aggregate_ratio: quota.max_aggregate_ratio.max(1000),
        max_per_entry_ratio: quota.max_per_entry_ratio.max(1000),
        ..quota
    };
    let members: Vec<crate::containers::GzipMember> =
        crate::containers::bare_stream::decompress_gzip_members(bytes, cap)?;
    let mut guard: QuotaGuard = QuotaGuard::new(stream_quota);
    let mut entries: Vec<ExtractedEntry> = Vec::with_capacity(members.len());
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();
    let multi_member: bool = members.len() > 1;
    for (index, member) in members.iter().enumerate() {
        let raw_name: String = member.original_name.clone().unwrap_or_else(|| {
            if multi_member {
                format!("stream.gz.{index}.out")
            } else {
                "stream.gz.out".to_owned()
            }
        });
        let safe_name: String = match sanitize_entry_path(&raw_name) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("gzip-slip: {e}"));
                continue;
            }
        };
        let uncompressed_size: u64 = member.data.len() as u64;
        if let Err(e) =
            guard.admit_entry(&safe_name, uncompressed_size, member.compressed_len as u64)
        {
            violations.push(format!("gzip-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &member.data)?;
        encoding.insert(safe_name.clone(), EntryCompression::Deflate);
        entries.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size,
            compressed_size: member.compressed_len as u64,
            compression: EntryCompression::Deflate,
            is_executable: false,
        });
    }
    Ok(ExtractionResult {
        kind: ContainerKind::Gzip,
        entries,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

const MAX_DISK_NESTING_DEPTH: u32 = 4;

const fn gpt_type_label(type_guid: &[u8; 16]) -> &'static str {
    const ESP: [u8; 16] = [
        0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9,
        0x3b,
    ];
    const LINUX_FS: [u8; 16] = [
        0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d,
        0xe4,
    ];
    const MS_BASIC_DATA: [u8; 16] = [
        0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44, 0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99,
        0xc7,
    ];
    match *type_guid {
        ESP => "esp",
        LINUX_FS => "linux",
        MS_BASIC_DATA => "msdata",
        _ => "part",
    }
}

struct CarveSink<'a> {
    guard: &'a mut QuotaGuard,
    entries: &'a mut Vec<ExtractedEntry>,
    encoding: &'a mut BTreeMap<String, EntryCompression>,
    violations: &'a mut Vec<String>,
}

impl std::fmt::Debug for CarveSink<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CarveSink")
            .field("entries", &self.entries.len())
            .field("violations", &self.violations.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
struct DiskCarveCtx<'a> {
    disk: &'a [u8],
    out_dir: &'a Path,
    depth: u32,
    quota: ExtractionQuota,
}

fn carve_partition_to_disk(
    label: &str,
    region: Option<(usize, usize)>,
    ctx: DiskCarveCtx<'_>,
    sink: &mut CarveSink<'_>,
) -> Result<()> {
    let disk: &[u8] = ctx.disk;
    let Some((start, end)): Option<(usize, usize)> = region else {
        sink.violations.push(format!(
            "partition-bounds `{label}`: LBA range overflows usize"
        ));
        return Ok(());
    };
    let clamped_end: usize = end.min(disk.len());
    if start >= disk.len() || clamped_end <= start {
        sink.violations.push(format!(
            "partition-bounds `{label}`: range {start}..{end} lies outside the {}-byte disk view",
            disk.len()
        ));
        return Ok(());
    }
    let slice: &[u8] = &disk[start..clamped_end];
    let safe_name: String = match sanitize_entry_path(label) {
        Ok(s) => s,
        Err(e) => {
            sink.violations.push(format!("partition-slip: {e}"));
            return Ok(());
        }
    };
    let size: u64 = slice.len() as u64;
    if let Err(e) = sink.guard.admit_entry(&safe_name, size, size) {
        sink.violations
            .push(format!("partition-quota `{safe_name}`: {e}"));
        return Ok(());
    }
    let disk_path: PathBuf = ctx.out_dir.join(&safe_name);
    if let Some(parent) = disk_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&disk_path, slice)?;
    sink.encoding
        .insert(safe_name.clone(), EntryCompression::Stored);
    sink.entries.push(ExtractedEntry {
        name: safe_name.clone(),
        disk_path: Some(disk_path),
        uncompressed_size: size,
        compressed_size: size,
        compression: EntryCompression::Stored,
        is_executable: false,
    });
    recurse_into_filesystem(&safe_name, slice, ctx, sink);
    Ok(())
}

fn recurse_into_filesystem(
    partition_name: &str,
    slice: &[u8],
    ctx: DiskCarveCtx<'_>,
    sink: &mut CarveSink<'_>,
) {
    if ctx.depth >= MAX_DISK_NESTING_DEPTH {
        return;
    }
    if crate::containers::fat::detect_fat(slice) {
        let sub_dir: PathBuf = ctx.out_dir.join(format!("{partition_name}.d"));
        if let Err(e) = extract_fat_into(slice, &sub_dir, partition_name, ctx.quota, sink) {
            sink.violations
                .push(format!("partition-fs `{partition_name}` (fat): {e}"));
        }
        return;
    }
    let Some(kind): Option<ContainerKind> = inner_filesystem_kind(slice) else {
        return;
    };
    let sub_dir: PathBuf = ctx.out_dir.join(format!("{partition_name}.d"));
    if let Err(e) = extract_disk_member(kind, slice, &sub_dir, ctx.depth + 1, ctx.quota) {
        sink.violations.push(format!(
            "partition-fs `{partition_name}` ({}): {e}",
            kind.label()
        ));
    }
}

fn extract_fat_into(
    image: &[u8],
    out_dir: &Path,
    partition_name: &str,
    quota: ExtractionQuota,
    sink: &mut CarveSink<'_>,
) -> Result<()> {
    let volume: crate::containers::FatVolume =
        crate::containers::walk_fat(image, quota.max_total_uncompressed)?;
    std::fs::create_dir_all(out_dir)?;
    for file in &volume.files {
        let safe_name: String = match sanitize_entry_path(&file.path) {
            Ok(s) => s,
            Err(e) => {
                sink.violations.push(format!("fat-slip: {e}"));
                continue;
            }
        };
        let data: Vec<u8> = match crate::containers::fat_file_data(
            image,
            volume.bpb,
            file,
            quota.max_per_entry_uncompressed,
        ) {
            Ok(d) => d,
            Err(e) => {
                sink.violations.push(format!("fat-read `{safe_name}`: {e}"));
                continue;
            }
        };
        let size: u64 = data.len() as u64;
        if let Err(e) = sink.guard.admit_entry(&safe_name, size, size) {
            sink.violations
                .push(format!("fat-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &data)?;
        let entry_name: String = format!("{partition_name}.d/{safe_name}");
        sink.encoding
            .insert(entry_name.clone(), EntryCompression::Stored);
        sink.entries.push(ExtractedEntry {
            name: entry_name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: size,
            compression: EntryCompression::Stored,
            is_executable: false,
        });
    }
    Ok(())
}

fn inner_filesystem_kind(slice: &[u8]) -> Option<ContainerKind> {
    if crate::containers::ext4::detect_ext4(slice).is_some() {
        return Some(ContainerKind::Ext4);
    }
    if crate::containers::squashfs::parse_squashfs_superblock(slice, 0).is_ok() {
        return Some(ContainerKind::Squashfs);
    }
    if crate::containers::cramfs::detect_cramfs(slice).is_some() {
        return Some(ContainerKind::Cramfs);
    }
    if crate::containers::iso::detect_iso(slice) {
        return Some(ContainerKind::Iso);
    }
    match container::detect_container(slice) {
        Some(ContainerKind::Gpt) => Some(ContainerKind::Gpt),
        Some(ContainerKind::Mbr) => Some(ContainerKind::Mbr),
        _ => None,
    }
}

fn extract_disk_member(
    kind: ContainerKind,
    bytes: &[u8],
    out_dir: &Path,
    depth: u32,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    match kind {
        ContainerKind::Gpt => carve_gpt(bytes, bytes, out_dir, depth, quota),
        ContainerKind::Mbr => carve_mbr(bytes, bytes, out_dir, depth, quota),
        other => extract_to_with_quota(other, bytes, out_dir, quota),
    }
}

fn carve_mbr(
    table_source: &[u8],
    disk: &[u8],
    out_dir: &Path,
    depth: u32,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let table: crate::containers::MbrTable = crate::containers::parse_mbr(table_source)?;
    std::fs::create_dir_all(out_dir)?;
    let json: String =
        serde_json::to_string_pretty(&table).unwrap_or_else(|_: serde_json::Error| String::new());
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut entries: Vec<ExtractedEntry> = Vec::new();
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();
    write_summary_entry(
        out_dir,
        ".disrobe-mbr-partitions.json",
        &json,
        &mut entries,
        &mut encoding,
    )?;
    if table.is_protective && crate::containers::parse_gpt(disk).is_ok() {
        violations.push(
            "mbr-protective: GPT protective MBR; the real partition map is the GPT header at LBA1 (extract the disk as gpt)".to_owned(),
        );
    }
    let ctx: DiskCarveCtx<'_> = DiskCarveCtx {
        disk,
        out_dir,
        depth,
        quota,
    };
    let mut sink: CarveSink<'_> = CarveSink {
        guard: &mut guard,
        entries: &mut entries,
        encoding: &mut encoding,
        violations: &mut violations,
    };
    for (index, part) in table.partitions.iter().enumerate() {
        if part.partition_type == crate::containers::partition::MBR_TYPE_GPT_PROTECTIVE {
            continue;
        }
        let label: String = format!("partition{index:02}.{:02x}.img", part.partition_type);
        carve_partition_to_disk(&label, part.byte_range(), ctx, &mut sink)?;
    }
    Ok(ExtractionResult {
        kind: ContainerKind::Mbr,
        entries,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn carve_gpt(
    table_source: &[u8],
    disk: &[u8],
    out_dir: &Path,
    depth: u32,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let table: crate::containers::GptTable = crate::containers::parse_gpt(table_source)?;
    std::fs::create_dir_all(out_dir)?;
    let json: String =
        serde_json::to_string_pretty(&table).unwrap_or_else(|_: serde_json::Error| String::new());
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut entries: Vec<ExtractedEntry> = Vec::new();
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();
    write_summary_entry(
        out_dir,
        ".disrobe-gpt-partitions.json",
        &json,
        &mut entries,
        &mut encoding,
    )?;
    if !table.header.header_crc32_valid {
        violations.push(format!(
            "gpt-crc-header: stored header CRC32 0x{:08x} does not match the computed CRC over the {}-byte header (image may be corrupt or truncated)",
            table.header.header_crc32, table.header.header_size
        ));
    }
    if !table.entries_crc32_valid {
        violations.push(format!(
            "gpt-crc-entries: stored partition-array CRC32 0x{:08x} does not match the computed CRC over the entry array",
            table.header.partition_entry_array_crc32
        ));
    }
    let ctx: DiskCarveCtx<'_> = DiskCarveCtx {
        disk,
        out_dir,
        depth,
        quota,
    };
    let mut sink: CarveSink<'_> = CarveSink {
        guard: &mut guard,
        entries: &mut entries,
        encoding: &mut encoding,
        violations: &mut violations,
    };
    for (index, part) in table.partitions.iter().enumerate() {
        let label: String = format!(
            "partition{index:02}.{}.img",
            gpt_type_label(&part.type_guid)
        );
        carve_partition_to_disk(&label, part.byte_range(), ctx, &mut sink)?;
    }
    Ok(ExtractionResult {
        kind: ContainerKind::Gpt,
        entries,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn extract_unityfs(
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let archive: crate::containers::UnityFsArchive = crate::containers::parse_unityfs(bytes)?;
    std::fs::create_dir_all(out_dir)?;
    let mut entries: Vec<ExtractedEntry> = Vec::new();
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();

    let json: String =
        serde_json::to_string_pretty(&archive).unwrap_or_else(|_: serde_json::Error| String::new());
    write_summary_entry(
        out_dir,
        ".disrobe-unityfs-layout.json",
        &json,
        &mut entries,
        &mut encoding,
    )?;

    let bundle_quota: ExtractionQuota = ExtractionQuota {
        max_aggregate_ratio: quota.max_aggregate_ratio.max(1000),
        max_per_entry_ratio: quota.max_per_entry_ratio.max(1000),
        ..quota
    };
    let mut guard: QuotaGuard = QuotaGuard::new(bundle_quota);

    let nodes: Vec<crate::containers::UnityExtractedNode> =
        match crate::containers::unityfs_extract_nodes(
            bytes,
            &archive,
            quota.max_total_uncompressed,
        ) {
            Ok(n) => n,
            Err(e) => {
                violations.push(format!("unityfs-blocks: {e}"));
                Vec::new()
            }
        };

    for node in &nodes {
        let safe_name: String = match sanitize_entry_path(&node.path) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("unityfs-slip: {e}"));
                continue;
            }
        };
        let size: u64 = node.data.len() as u64;
        if let Err(e) = guard.admit_entry(&safe_name, size, size) {
            violations.push(format!("unityfs-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&disk_path, &node.data)?;
        encoding.insert(safe_name.clone(), EntryCompression::Other);
        entries.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: size,
            compression: EntryCompression::Other,
            is_executable: false,
        });
    }

    if !nodes.is_empty() {
        let text_assets: Vec<crate::containers::UnityTextAsset> =
            match crate::containers::unityfs_extract_text_assets(
                bytes,
                &archive,
                quota.max_total_uncompressed,
            ) {
                Ok(assets) => assets,
                Err(e) => {
                    violations.push(format!("unityfs-textasset: {e}"));
                    Vec::new()
                }
            };
        for asset in &text_assets {
            let raw_name: String = if asset.name.is_empty() {
                "TextAsset.bytes".to_owned()
            } else {
                format!("TextAsset/{}.bytes", asset.name)
            };
            let safe_name: String = match sanitize_entry_path(&raw_name) {
                Ok(s) => s,
                Err(e) => {
                    violations.push(format!("unityfs-textasset-slip: {e}"));
                    continue;
                }
            };
            let size: u64 = asset.script.len() as u64;
            if let Err(e) = guard.admit_entry(&safe_name, size, size) {
                violations.push(format!("unityfs-textasset-quota `{safe_name}`: {e}"));
                continue;
            }
            let disk_path: PathBuf = out_dir.join(&safe_name);
            if let Some(parent) = disk_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&disk_path, &asset.script)?;
            encoding.insert(safe_name.clone(), EntryCompression::Stored);
            entries.push(ExtractedEntry {
                name: safe_name,
                disk_path: Some(disk_path),
                uncompressed_size: size,
                compressed_size: size,
                compression: EntryCompression::Stored,
                is_executable: false,
            });
        }
    }

    let codec: &str = archive.header.blocks_info_compression.label();
    if archive.blocks.is_empty() {
        violations.push(format!(
            "unityfs-payload: bundle header parsed (blocks-info {codec}) but the block table is empty; nothing to assemble"
        ));
    }

    Ok(ExtractionResult {
        kind: ContainerKind::UnityFs,
        entries,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn write_summary_entry(
    out_dir: &Path,
    filename: &str,
    json: &str,
    entries: &mut Vec<ExtractedEntry>,
    encoding: &mut BTreeMap<String, EntryCompression>,
) -> Result<()> {
    let path: PathBuf = out_dir.join(filename);
    std::fs::write(&path, json.as_bytes())?;
    encoding.insert(filename.to_owned(), EntryCompression::Stored);
    entries.push(ExtractedEntry {
        name: filename.to_owned(),
        disk_path: Some(path),
        uncompressed_size: json.len() as u64,
        compressed_size: json.len() as u64,
        compression: EntryCompression::Stored,
        is_executable: false,
    });
    Ok(())
}

fn write_disk_layout_json<T: Serialize>(
    out_dir: &Path,
    filename: &str,
    value: &T,
    entries: &mut Vec<ExtractedEntry>,
    encoding: &mut BTreeMap<String, EntryCompression>,
) -> Result<()> {
    let json: String =
        serde_json::to_string_pretty(value).unwrap_or_else(|_: serde_json::Error| String::new());
    write_summary_entry(out_dir, filename, &json, entries, encoding)
}

fn carve_partitions_over_view(
    kind: ContainerKind,
    disk: &[u8],
    out_dir: &Path,
    depth: u32,
    quota: ExtractionQuota,
    mut seed: impl FnMut(
        &Path,
        &mut Vec<ExtractedEntry>,
        &mut BTreeMap<String, EntryCompression>,
    ) -> Result<()>,
) -> Result<ExtractionResult> {
    std::fs::create_dir_all(out_dir)?;
    let mut entries: Vec<ExtractedEntry> = Vec::new();
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();
    seed(out_dir, &mut entries, &mut encoding)?;

    let inner: Option<ExtractionResult> = if crate::containers::parse_gpt(disk).is_ok() {
        Some(carve_gpt(disk, disk, out_dir, depth, quota)?)
    } else if crate::containers::parse_mbr(disk).is_ok() {
        Some(carve_mbr(disk, disk, out_dir, depth, quota)?)
    } else if let Some(fs_kind) = inner_filesystem_kind(disk) {
        let sub_dir: PathBuf = out_dir.join("disk.d");
        Some(extract_disk_member(
            fs_kind,
            disk,
            &sub_dir,
            depth + 1,
            quota,
        )?)
    } else {
        violations.push(format!(
            "{}-disk: logical disk materialized ({} bytes) but holds no in-tree-recognized partition table or filesystem (NTFS/FAT/exFAT/APFS-on-raw need their own fs pass)",
            kind.label(),
            disk.len()
        ));
        None
    };

    if let Some(result) = inner {
        for entry in result.entries {
            encoding.insert(entry.name.clone(), entry.compression);
            entries.push(entry);
        }
        violations.extend(result.integrity_violations);
    }

    Ok(ExtractionResult {
        kind,
        entries,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary {
            entries_accepted: 0,
            total_uncompressed_bytes: disk.len() as u64,
            total_compressed_bytes: 0,
            max_observed_ratio: 0,
        },
    })
}

fn extract_vhd_summary(bytes: &[u8], out_dir: &Path) -> Result<ExtractionResult> {
    extract_vhd_disk(bytes, out_dir, 0, ExtractionQuota::default_safe())
}

#[must_use]
const fn logical_disk_materialization_cap(quota: ExtractionQuota) -> u64 {
    if quota.max_total_uncompressed < quota.max_per_entry_uncompressed {
        quota.max_total_uncompressed
    } else {
        quota.max_per_entry_uncompressed
    }
}

fn extract_vhd_disk(
    bytes: &[u8],
    out_dir: &Path,
    depth: u32,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let image: crate::containers::vhd::VhdImage = crate::containers::vhd::parse_vhd(bytes)?;
    let disk: Vec<u8> = crate::containers::vhd_materialize_logical_disk(
        bytes,
        &image,
        logical_disk_materialization_cap(quota),
    )?;
    carve_partitions_over_view(
        ContainerKind::Vhd,
        &disk,
        out_dir,
        depth,
        quota,
        |dir: &Path,
         entries: &mut Vec<ExtractedEntry>,
         encoding: &mut BTreeMap<String, EntryCompression>| {
            write_disk_layout_json(dir, ".disrobe-vhd-layout.json", &image, entries, encoding)
        },
    )
}

fn extract_vhdx_summary(bytes: &[u8], out_dir: &Path) -> Result<ExtractionResult> {
    extract_vhdx_disk(bytes, out_dir, 0, ExtractionQuota::default_safe())
}

fn extract_vhdx_disk(
    bytes: &[u8],
    out_dir: &Path,
    depth: u32,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let image: crate::containers::vhdx::VhdxImage = crate::containers::vhdx::parse_vhdx(bytes)?;
    let disk: Vec<u8> = crate::containers::vhdx_materialize_logical_disk(
        bytes,
        &image,
        logical_disk_materialization_cap(quota),
    )?;
    carve_partitions_over_view(
        ContainerKind::Vhdx,
        &disk,
        out_dir,
        depth,
        quota,
        |dir: &Path,
         entries: &mut Vec<ExtractedEntry>,
         encoding: &mut BTreeMap<String, EntryCompression>| {
            write_disk_layout_json(dir, ".disrobe-vhdx-layout.json", &image, entries, encoding)
        },
    )
}

fn extract_wim(bytes: &[u8], out_dir: &Path) -> Result<ExtractionResult> {
    let archive: crate::containers::WimArchive = crate::containers::parse_wim(bytes)?;
    std::fs::create_dir_all(out_dir)?;
    let json: String =
        serde_json::to_string_pretty(&archive).unwrap_or_else(|_: serde_json::Error| String::new());
    let mut entries: Vec<ExtractedEntry> = Vec::new();
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();
    write_summary_entry(
        out_dir,
        ".disrobe-wim-images.json",
        &json,
        &mut entries,
        &mut encoding,
    )?;

    let base_quota: ExtractionQuota = ExtractionQuota::default_safe();
    let quota: ExtractionQuota = ExtractionQuota {
        max_per_entry_ratio: base_quota.max_per_entry_ratio.max(1000),
        max_aggregate_ratio: base_quota.max_aggregate_ratio.max(1000),
        ..base_quota
    };
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let carved: Vec<crate::containers::WimCarvedResource> = crate::containers::carve_wim_resources(
        bytes,
        &archive.header,
        quota.max_per_entry_uncompressed,
    );
    for resource in carved {
        let size: u64 = resource.data.len() as u64;
        let safe_name: String = match sanitize_entry_path(&resource.name) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("wim-slip: {e}"));
                continue;
            }
        };
        if let Err(e) = guard.admit_entry(&safe_name, size, size) {
            violations.push(format!("wim-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        std::fs::write(&disk_path, &resource.data)?;
        encoding.insert(safe_name.clone(), EntryCompression::Stored);
        entries.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: size,
            compression: EntryCompression::Stored,
            is_executable: false,
        });
    }

    decompress_wim_header_resources(
        bytes,
        &archive.header,
        out_dir,
        quota,
        &mut entries,
        &mut encoding,
        &mut violations,
    );

    extract_wim_image_files(
        bytes,
        &archive.header,
        out_dir,
        quota,
        &mut guard,
        &mut entries,
        &mut encoding,
        &mut violations,
    );

    Ok(ExtractionResult {
        kind: ContainerKind::Wim,
        entries,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
}

fn decompress_wim_header_resources(
    bytes: &[u8],
    header: &crate::containers::WimHeader,
    out_dir: &Path,
    quota: ExtractionQuota,
    entries: &mut Vec<ExtractedEntry>,
    encoding: &mut BTreeMap<String, EntryCompression>,
    violations: &mut Vec<String>,
) {
    let candidates: [(&str, crate::containers::WimResource); 2] = [
        (".disrobe-wim-offset-table.dec.bin", header.offset_table),
        (".disrobe-wim-boot-metadata.dec.bin", header.boot_metadata),
    ];
    for (name, resource) in candidates {
        if !resource.is_compressed() || resource.size == 0 || resource.original_size == 0 {
            continue;
        }
        if resource.original_size > quota.max_per_entry_uncompressed {
            violations.push(format!(
                "wim-resource `{name}`: original size {} exceeds per-entry cap",
                resource.original_size
            ));
            continue;
        }
        let decoded: Vec<u8> =
            match crate::containers::decompress_named_resource(bytes, header, &resource, &quota) {
                Ok(data) => data,
                Err(e) => {
                    violations.push(format!("wim-decompress `{name}`: {e}"));
                    continue;
                }
            };
        let safe_name: String = match sanitize_entry_path(name) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("wim-slip: {e}"));
                continue;
            }
        };
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Err(e) = std::fs::write(&disk_path, &decoded) {
            violations.push(format!("wim-write `{safe_name}`: {e}"));
            continue;
        }
        encoding.insert(safe_name.clone(), EntryCompression::Other);
        entries.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: decoded.len() as u64,
            compressed_size: resource.size,
            compression: EntryCompression::Other,
            is_executable: false,
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn extract_wim_image_files(
    bytes: &[u8],
    header: &crate::containers::WimHeader,
    out_dir: &Path,
    quota: ExtractionQuota,
    guard: &mut QuotaGuard,
    entries: &mut Vec<ExtractedEntry>,
    encoding: &mut BTreeMap<String, EntryCompression>,
    violations: &mut Vec<String>,
) {
    let resource_quota: ExtractionQuota = ExtractionQuota {
        max_per_entry_ratio: quota.max_per_entry_ratio.max(1000),
        max_aggregate_ratio: quota.max_aggregate_ratio.max(1000),
        ..quota
    };
    let extraction: crate::containers::WimImageExtraction =
        match crate::containers::extract_wim_files(bytes, header, &resource_quota) {
            Ok(e) => e,
            Err(e) => {
                violations.push(format!("wim-image: {e}"));
                return;
            }
        };
    for note in extraction.notes {
        violations.push(note);
    }
    let compression: EntryCompression = match header.compression {
        crate::containers::WimCompression::None => EntryCompression::Stored,
        _ => EntryCompression::Other,
    };
    for file in extraction.files {
        let safe_name: String = match sanitize_entry_path(&file.path) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("wim-slip: {e}"));
                continue;
            }
        };
        let size: u64 = file.data.len() as u64;
        let packed: u64 = if file.compressed_size == 0 {
            size
        } else {
            file.compressed_size
        };
        if let Err(e) = guard.admit_entry(&safe_name, size, packed) {
            violations.push(format!("wim-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&safe_name);
        if let Some(parent) = disk_path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            violations.push(format!("wim-mkdir `{safe_name}`: {e}"));
            continue;
        }
        if let Err(e) = std::fs::write(&disk_path, &file.data) {
            violations.push(format!("wim-write `{safe_name}`: {e}"));
            continue;
        }
        let entry_compression: EntryCompression = if file.compressed {
            compression
        } else {
            EntryCompression::Stored
        };
        encoding.insert(safe_name.clone(), entry_compression);
        entries.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: size,
            compressed_size: packed,
            compression: entry_compression,
            is_executable: false,
        });
    }
}

fn extract_gpt_summary(bytes: &[u8], out_dir: &Path) -> Result<ExtractionResult> {
    carve_gpt(bytes, bytes, out_dir, 0, ExtractionQuota::default_safe())
}

fn extract_mbr_summary(bytes: &[u8], out_dir: &Path) -> Result<ExtractionResult> {
    carve_mbr(bytes, bytes, out_dir, 0, ExtractionQuota::default_safe())
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
        let mut header: String = String::from(r#"{"files":{"#);
        let mut offset: u64 = 0;
        for (i, (name, body)) in files.iter().enumerate() {
            if i > 0 {
                header.push(',');
            }
            let size: usize = body.len();
            push_asar_entry(&mut header, name, size, offset);
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

    fn push_asar_entry(header: &mut String, name: &str, size: usize, offset: u64) {
        header.push('"');
        header.push_str(name);
        header.push_str(r#"":{"size":"#);
        header.push_str(&size.to_string());
        header.push_str(r#","offset":""#);
        header.push_str(&offset.to_string());
        header.push_str(r#""}"#);
    }

    #[test]
    fn unityfs_textasset_errors_are_reported_as_violations() {
        let out: PathBuf = temp_dir("unityfs-textasset-violation");
        let script: Vec<u8> = b"\x1bLua\x53 fake bytecode body".to_vec();
        let mut serialized: Vec<u8> =
            crate::containers::unityfs_build_serialized_textasset("payload", &script);
        serialized.truncate(serialized.len() - 1);
        let bundle: Vec<u8> =
            crate::containers::unityfs_build_bundle_uncompressed("CAB-truncated", &serialized);
        let result: ExtractionResult =
            extract_to(ContainerKind::UnityFs, &bundle, &out).expect("extract unityfs");
        assert!(
            result
                .integrity_violations
                .iter()
                .any(|violation: &String| violation.contains("unityfs-textasset"))
        );
    }

    #[test]
    fn logical_disk_materialization_uses_per_entry_cap() {
        let quota: ExtractionQuota = ExtractionQuota::default_safe();
        assert_eq!(
            logical_disk_materialization_cap(quota),
            quota.max_per_entry_uncompressed
        );
        let smaller_total: ExtractionQuota = ExtractionQuota {
            max_total_uncompressed: 1024,
            ..quota
        };
        assert_eq!(logical_disk_materialization_cap(smaller_total), 1024);
        assert_eq!(
            logical_disk_materialization_cap(ExtractionQuota::unrestricted()),
            u64::MAX
        );
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
    fn extract_zip_rejects_raw_entry_count_over_quota() {
        let bytes: Vec<u8> = synth_zip(&[("../a.txt", b"a"), ("../b.txt", b"b")]);
        let out: PathBuf = temp_dir("zip-count");
        let tight: ExtractionQuota = ExtractionQuota {
            max_entries: 1,
            ..ExtractionQuota::default_safe()
        };
        let err: Error =
            extract_to_with_quota(ContainerKind::Zip, &bytes, &out, tight).unwrap_err();
        assert!(
            matches!(err, Error::QuotaExceeded { reason, .. } if reason.contains("entry count"))
        );
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
    fn rar_extracts_stored_entries_in_tree() {
        let out: PathBuf = temp_dir("rar-store");
        let body: &[u8] = b"stored rar5 payload recovered in-tree";
        let bytes: Vec<u8> = crate::containers::rar::build_test_rar5_store("dir/payload.bin", body);
        let r: ExtractionResult =
            extract_to(ContainerKind::Rar, &bytes, &out).expect("rar extract");
        assert_eq!(r.kind, ContainerKind::Rar);
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].name, "dir/payload.bin");
        assert_eq!(
            std::fs::read(out.join("dir/payload.bin")).expect("file"),
            body
        );
    }

    #[test]
    fn pkg_extraction_errors_on_invalid_xar() {
        let out: PathBuf = temp_dir("pkg-bad");
        let err: Error = extract_to(ContainerKind::Pkg, &[0u8; 16], &out).unwrap_err();
        assert!(matches!(err, Error::Decompression(_)));
    }

    #[test]
    fn dmg_extraction_errors_on_invalid_image() {
        let out: PathBuf = temp_dir("dmg-bad");
        let err: Error = extract_to(ContainerKind::Dmg, &[0u8; 16], &out).unwrap_err();
        assert!(matches!(err, Error::Decompression(_)));
    }

    #[test]
    fn iso_extraction_errors_on_invalid_image() {
        let out: PathBuf = temp_dir("iso-bad");
        let err: Error = extract_to(ContainerKind::Iso, &[0u8; 16], &out).unwrap_err();
        assert!(matches!(err, Error::Decompression(_)));
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

    fn synth_cab(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder: cab::CabinetBuilder = cab::CabinetBuilder::new();
        {
            let folder: &mut cab::FolderBuilder = builder.add_folder(cab::CompressionType::None);
            for (name, _) in files {
                folder.add_file(*name);
            }
        }
        let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let mut writer: cab::CabinetWriter<Cursor<Vec<u8>>> =
            builder.build(cursor).expect("cab build");
        let mut idx: usize = 0;
        while let Some(mut fw) = writer.next_file().expect("next file") {
            fw.write_all(files[idx].1).expect("cab write");
            idx += 1;
        }
        writer.finish().expect("cab finish").into_inner()
    }

    fn synth_msi_with_embedded_cab(cab_bytes: &[u8], file_key: &str, long_name: &str) -> Vec<u8> {
        use msi::{Column, Insert, Value};
        let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let mut package: msi::Package<Cursor<Vec<u8>>> =
            msi::Package::create(msi::PackageType::Installer, cursor).expect("create msi");
        package
            .create_table(
                "Media",
                vec![
                    Column::build("DiskId").primary_key().int16(),
                    Column::build("LastSequence").int16(),
                    Column::build("Cabinet").nullable().string(255),
                ],
            )
            .expect("media table");
        package
            .insert_rows(Insert::into("Media").row(vec![
                Value::Int(1),
                Value::Int(1),
                Value::Str("#cab1".to_owned()),
            ]))
            .expect("media row");
        package
            .create_table(
                "File",
                vec![
                    Column::build("File").primary_key().id_string(72),
                    Column::build("FileName").string(255),
                ],
            )
            .expect("file table");
        package
            .insert_rows(Insert::into("File").row(vec![
                Value::Str(file_key.to_owned()),
                Value::Str(long_name.to_owned()),
            ]))
            .expect("file row");
        {
            let mut sw: msi::StreamWriter<Cursor<Vec<u8>>> =
                package.write_stream("cab1").expect("stream writer");
            sw.write_all(cab_bytes).expect("write cab stream");
        }
        package.flush().expect("flush");
        package.into_inner().expect("inner").into_inner()
    }

    #[test]
    fn extract_msi_unpacks_embedded_cab_with_long_names() {
        let out: PathBuf = temp_dir("msi-ok");
        let cab_bytes: Vec<u8> =
            synth_cab(&[("app.exe", b"MZ\x90\x00 msi-packed application binary")]);
        let msi_bytes: Vec<u8> =
            synth_msi_with_embedded_cab(&cab_bytes, "app.exe", "appname|TheApplication.exe");
        let r: ExtractionResult =
            extract_to(ContainerKind::Msi, &msi_bytes, &out).expect("msi extract");
        assert_eq!(r.kind, ContainerKind::Msi);
        assert_eq!(
            std::fs::read(out.join("TheApplication.exe")).expect("long-named file"),
            b"MZ\x90\x00 msi-packed application binary"
        );
        assert!(out.join(".disrobe-msi-summary.json").is_file());
    }

    #[test]
    fn extract_squirrel_unpacks_embedded_nupkg() {
        let out: PathBuf = temp_dir("squirrel-ok");
        let nupkg: Vec<u8> = synth_zip(&[
            ("Discord.nuspec", b"<package><metadata/></package>"),
            ("[Content_Types].xml", b"<Types/>"),
            ("lib/net45/Discord.exe", b"MZ\x90\x00 the real app binary"),
        ]);
        let stub: Vec<u8> = crate::containers::squirrel::build_test_squirrel_setup(&nupkg);
        let r: ExtractionResult =
            extract_to(ContainerKind::Squirrel, &stub, &out).expect("squirrel extract");
        assert_eq!(r.kind, ContainerKind::Squirrel);
        assert_eq!(
            std::fs::read(out.join("lib/net45/Discord.exe")).expect("app binary"),
            b"MZ\x90\x00 the real app binary"
        );
        assert_eq!(
            std::fs::read(out.join("Discord.nuspec")).expect("nuspec"),
            b"<package><metadata/></package>"
        );
        assert!(out.join(".disrobe-squirrel-layout.json").is_file());
    }

    #[test]
    fn extract_squirrel_without_embedded_nupkg_reports_sibling_packages() {
        let out: PathBuf = temp_dir("squirrel-updater");
        let mut stub: Vec<u8> = b"MZ".to_vec();
        stub.extend_from_slice(b" SquirrelAwareVersion NuGet ");
        stub.extend(std::iter::repeat_n(0u8, 4096));
        let err: Error = extract_to(ContainerKind::Squirrel, &stub, &out).unwrap_err();
        assert!(matches!(err, Error::Squirrel(_)));
        assert!(out.join(".disrobe-squirrel-layout.json").is_file());
    }

    #[test]
    fn extract_nsis_writes_real_file_and_strips_var_prefix() {
        let out: PathBuf = temp_dir("nsis-ok");
        let body: &[u8] = b"MZ\x90\x00 fake-but-distinctive nsis payload bytes payload payload";
        let bytes: Vec<u8> =
            crate::containers::nsis::build_test_nsis("$VAR4\\app\\hello.dll", body);
        let r: ExtractionResult =
            extract_to(ContainerKind::Nsis, &bytes, &out).expect("nsis extract");
        assert_eq!(r.kind, ContainerKind::Nsis);
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].name, "app/hello.dll");
        assert_eq!(
            std::fs::read(out.join("app/hello.dll")).expect("written file"),
            body
        );
        assert!(r.integrity_violations.is_empty());
    }

    #[cfg(feature = "rpm")]
    fn newc_entry(name_bytes: &[u8], mode: u32, data: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(b"070701");
        let namesize: usize = name_bytes.len() + 1;
        let fields: [u32; 13] = [
            0,
            mode,
            0,
            0,
            0,
            0,
            data.len() as u32,
            0,
            0,
            0,
            0,
            namesize as u32,
            0,
        ];
        for f in fields {
            out.extend_from_slice(format!("{f:08X}").as_bytes());
        }
        out.extend_from_slice(name_bytes);
        out.push(0);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out.extend_from_slice(data);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out
    }

    #[cfg(feature = "rpm")]
    #[test]
    fn non_utf8_cpio_name_does_not_drop_the_whole_payload() {
        let mut cpio: Vec<u8> = Vec::new();
        cpio.extend_from_slice(&newc_entry(&[b'a', 0xff, b'b'], 0o100_644, b"first"));
        cpio.extend_from_slice(&newc_entry(b"clean.txt", 0o100_644, b"second"));

        let mut offset: usize = 0;
        let first: CpioEntry = parse_cpio_entry(&cpio, &mut offset)
            .expect("a bad name byte must not abort the walk")
            .expect("first entry present");
        assert!(first.name.contains('\u{fffd}'));
        assert_eq!(first.data, b"first");

        let second: CpioEntry = parse_cpio_entry(&cpio, &mut offset)
            .expect("second entry parses")
            .expect("second entry present");
        assert_eq!(second.name, "clean.txt");
        assert_eq!(second.data, b"second");
    }
}
