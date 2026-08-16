use std::collections::BTreeMap;
use std::io::{Cursor, Read, Seek};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::asar::AsarLayout;
use crate::container::ContainerKind;
use crate::error::{Error, Result};
use crate::quota::{
    ExtractionQuota, QuotaGuard, QuotaReport, bounded_prealloc, prepare_entry_dir,
    prepare_entry_path, read_entry_to_limit, sanitize_entry_path,
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
        ContainerKind::Rpm => extract_rpm(bytes, out_dir, quota),
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
        ContainerKind::UefiFv => extract_uefi_firmware_volume(bytes, out_dir, quota),
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
        ContainerKind::Vhd => extract_vhd_disk(bytes, out_dir, 0, quota),
        ContainerKind::Vhdx => extract_vhdx_disk(bytes, out_dir, 0, quota),
        ContainerKind::Wim => extract_wim(bytes, out_dir, quota),
        ContainerKind::Gpt => carve_gpt(bytes, bytes, out_dir, 0, quota),
        ContainerKind::Mbr => carve_mbr(bytes, bytes, out_dir, 0, quota),
        ContainerKind::Fat => extract_fat(bytes, out_dir, quota),
        ContainerKind::BunStandalone => extract_bun(bytes, out_dir, quota),
        ContainerKind::DotnetSingleFile => extract_dotnet_single_file(bytes, out_dir, quota),
        ContainerKind::UnityFs => extract_unityfs(bytes, out_dir, quota),
        ContainerKind::Minidump => extract_minidump(bytes, out_dir, quota),
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
    let tool_summary_name: String = ".disrobe-firmware.json".to_owned();
    let summary_path: PathBuf = out_dir.join(&tool_summary_name);
    std::fs::write(&summary_path, summary_json.as_bytes())?;
    encoding.insert(tool_summary_name.clone(), EntryCompression::Stored);
    entries.push(ExtractedEntry {
        name: tool_summary_name,
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
    if entries_out.is_empty() && !walk.files.is_empty() && violations.is_empty() {
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
    let raw: Vec<u8> = crate::containers::unsparse(bytes, quota.max_total_uncompressed)?;
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
    let tool_name: String = "unsparse.img".to_owned();
    let size: u64 = raw.len() as u64;
    guard.admit_entry(&tool_name, size, bytes.len() as u64)?;
    let disk_path: PathBuf = out_dir.join(&tool_name);
    std::fs::write(&disk_path, &raw)?;
    encoding.insert(tool_name.clone(), EntryCompression::Other);
    entries_out.push(ExtractedEntry {
        name: tool_name,
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
        let tool_name: String = format!("vol{vol_id}.ubifs.img");
        let size: u64 = image.len() as u64;
        if let Err(e) = guard.admit_entry(&tool_name, size, size) {
            violations.push(format!("ubifs-quota `{tool_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&tool_name);
        std::fs::write(&disk_path, image)?;
        encoding.insert(tool_name.clone(), EntryCompression::Other);
        entries_out.push(ExtractedEntry {
            name: tool_name,
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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

#[derive(Debug, Serialize)]
struct MinidumpSummary<'a> {
    version: u32,
    architecture: &'static str,
    pointer_width: u8,
    module_count: usize,
    memory_region_count: usize,
    modules: &'a [MinidumpModuleSummary],
    notes: &'a [String],
}

#[derive(Debug, Serialize)]
struct MinidumpModuleSummary {
    name: String,
    base_of_image: u64,
    size_of_image: u64,
    status: &'static str,
    coverage_ratio: f64,
    complete: bool,
    headers_present: bool,
    covered_bytes: u64,
    truncated_bytes: u64,
    absent_bytes: u64,
    absent_range_count: usize,
    overlap_detected: bool,
    structurally_valid_pe: bool,
    import_dll_count: Option<usize>,
    pdb_guid: Option<String>,
    pdb_age: Option<u32>,
    pdb_path: Option<String>,
    written_file: Option<String>,
}

const fn minidump_module_status(carved: &crate::containers::CarvedModule) -> &'static str {
    if !carved.coverage.headers_present {
        "headers-absent"
    } else if carved.coverage.complete {
        "complete"
    } else {
        "partial"
    }
}

fn extract_minidump(
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let dump: crate::containers::MinidumpFile = crate::containers::parse_minidump(bytes)?;
    std::fs::create_dir_all(out_dir)?;
    let mut guard: QuotaGuard = QuotaGuard::new(ExtractionQuota {
        max_aggregate_ratio: quota.max_aggregate_ratio.max(1000),
        max_per_entry_ratio: quota.max_per_entry_ratio.max(1000),
        ..quota
    });
    let mut entries_out: Vec<ExtractedEntry> = Vec::new();
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = dump.notes.clone();
    let mut module_summaries: Vec<MinidumpModuleSummary> = Vec::with_capacity(dump.modules.len());
    let mut used_names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for module in &dump.modules {
        let carved: crate::containers::CarvedModule = match crate::containers::carve_module(
            &dump,
            bytes,
            module,
            quota.max_per_entry_uncompressed,
        ) {
            Ok(carved) => carved,
            Err(e) => {
                violations.push(format!("minidump-module `{}`: {e}", module.file_name()));
                continue;
            }
        };
        for note in &carved.notes {
            violations.push(format!("minidump `{}`: {note}", carved.module_name));
        }
        let (structurally_valid, import_dll_count): (bool, Option<usize>) = carved
            .pe_emit
            .as_ref()
            .map_or((false, None), |report: &crate::containers::PeEmitReport| {
                (report.structurally_valid, report.import_dll_count)
            });

        let mut written_file: Option<String> = None;
        if carved.coverage.headers_present {
            let base_name: String = match sanitize_entry_path(&carved.module_name) {
                Ok(name) => name,
                Err(_) => format!("module_{:016x}.bin", carved.base_of_image),
            };
            let label: String = if used_names.contains(&base_name) {
                format!("{base_name}.{:016x}", carved.base_of_image)
            } else {
                base_name
            };
            let size: u64 = carved.image.len() as u64;
            if let Err(e) = guard.admit_entry(&label, size, size) {
                violations.push(format!("minidump-quota `{label}`: {e}"));
            } else {
                used_names.insert(label.clone());
                let disk_path: PathBuf = prepare_entry_path(out_dir, &label)?;
                std::fs::write(&disk_path, &carved.image)?;
                encoding.insert(label.clone(), EntryCompression::Stored);
                entries_out.push(ExtractedEntry {
                    name: label.clone(),
                    disk_path: Some(disk_path),
                    uncompressed_size: size,
                    compressed_size: size,
                    compression: EntryCompression::Stored,
                    is_executable: true,
                });
                written_file = Some(label);
            }
        }

        module_summaries.push(MinidumpModuleSummary {
            name: carved.module_name.clone(),
            base_of_image: carved.base_of_image,
            size_of_image: carved.size_of_image,
            status: minidump_module_status(&carved),
            coverage_ratio: carved.coverage.coverage_ratio,
            complete: carved.coverage.complete,
            headers_present: carved.coverage.headers_present,
            covered_bytes: carved.coverage.covered_bytes,
            truncated_bytes: carved.coverage.truncated_bytes,
            absent_bytes: carved.coverage.absent_bytes,
            absent_range_count: carved.absent_ranges.len(),
            overlap_detected: carved.coverage.overlap_detected,
            structurally_valid_pe: structurally_valid,
            import_dll_count,
            pdb_guid: module
                .cv_record
                .as_ref()
                .map(crate::containers::CvRecord::guid_string),
            pdb_age: module
                .cv_record
                .as_ref()
                .map(|cv: &crate::containers::CvRecord| cv.age),
            pdb_path: module
                .cv_record
                .as_ref()
                .map(|cv: &crate::containers::CvRecord| cv.pdb_path.clone()),
            written_file,
        });
    }

    let summary: MinidumpSummary = MinidumpSummary {
        version: dump.version,
        architecture: dump.arch.label(),
        pointer_width: dump.pointer_width,
        module_count: dump.modules.len(),
        memory_region_count: dump.memory_regions.len(),
        modules: &module_summaries,
        notes: &dump.notes,
    };
    let summary_json: String =
        serde_json::to_string_pretty(&summary).unwrap_or_else(|_: serde_json::Error| String::new());
    let tool_summary_name: String = ".disrobe-minidump.json".to_owned();
    let summary_path: PathBuf = out_dir.join(&tool_summary_name);
    std::fs::write(&summary_path, summary_json.as_bytes())?;
    encoding.insert(tool_summary_name.clone(), EntryCompression::Stored);
    entries_out.push(ExtractedEntry {
        name: tool_summary_name,
        disk_path: Some(summary_path),
        uncompressed_size: summary_json.len() as u64,
        compressed_size: summary_json.len() as u64,
        compression: EntryCompression::Stored,
        is_executable: false,
    });

    Ok(ExtractionResult {
        kind: ContainerKind::Minidump,
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
    let names: Vec<String> = cab_backed_file_names(&cabinet, violations);
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
            "dmg-chunk-unknown: unrecognized UDIF chunk type 0x{ty:08x} skipped (raw/zero/ignore/ADC/zlib/bzip2/LZFSE/LZMA are all decoded in-tree)"
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
                let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
            let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
    let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
                let map_path: PathBuf = prepare_entry_path(out_dir, &map_safe)?;
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

fn extract_dotnet_single_file(
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    use crate::containers::dotnet_bundle::{DotnetBundle, write_bundle_file};

    let bundle: DotnetBundle = crate::containers::parse_dotnet_bundle(bytes)?;
    std::fs::create_dir_all(out_dir)?;
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let cap: u64 = guard.max_per_entry_uncompressed();
    let mut entries_out: Vec<ExtractedEntry> = Vec::with_capacity(bundle.files.len());
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();

    for file in &bundle.files {
        let safe_name: String = match sanitize_entry_path(&file.relative_path) {
            Ok(s) => s,
            Err(e) => {
                violations.push(format!("dotnet-bundle-slip: {e}"));
                continue;
            }
        };
        if let Err(e) = guard.admit_entry(&safe_name, file.size, file.stored_len()) {
            violations.push(format!("dotnet-bundle-quota `{safe_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
        let mut sink: std::io::BufWriter<std::fs::File> =
            std::io::BufWriter::new(std::fs::File::create(&disk_path)?);
        if let Err(e) = write_bundle_file(bytes, file, cap, &mut sink) {
            violations.push(format!("dotnet-bundle-decode `{safe_name}`: {e}"));
            drop(sink);
            let _ = std::fs::remove_file(&disk_path);
            continue;
        }
        std::io::Write::flush(&mut sink)?;
        let compression: EntryCompression = if file.is_compressed() {
            EntryCompression::Deflate
        } else {
            EntryCompression::Stored
        };
        encoding.insert(safe_name.clone(), compression);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: file.size,
            compressed_size: file.stored_len(),
            compression,
            is_executable: matches!(
                file.file_type,
                crate::containers::BundleFileType::NativeBinary
            ),
        });
    }

    Ok(ExtractionResult {
        kind: ContainerKind::DotnetSingleFile,
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
        let tool_blob_name: String = "setup-headers.bin".to_owned();
        let blob_path: PathBuf = out_dir.join(&tool_blob_name);
        std::fs::write(&blob_path, &decoded)?;
        encoding.insert(tool_blob_name.clone(), EntryCompression::Deflate);
        entries_out.push(ExtractedEntry {
            name: tool_blob_name,
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
        let tool_name: String = format!("file-{index}.bin");
        let size: u64 = chunk.data.len() as u64;
        if let Err(e) = guard.admit_entry(&tool_name, size, size) {
            violations.push(format!("inno-quota `{tool_name}`: {e}"));
            continue;
        }
        let disk_path: PathBuf = out_dir.join(&tool_name);
        std::fs::write(&disk_path, &chunk.data)?;
        let entry_compression: EntryCompression = match chunk.compression {
            crate::containers::InnoCompression::Stored => EntryCompression::Stored,
            _ => EntryCompression::Deflate,
        };
        encoding.insert(tool_name.clone(), entry_compression);
        entries_out.push(ExtractedEntry {
            name: tool_name,
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
            let tool_name: String = "setup-engine.lzma".to_owned();
            let disk_path: PathBuf = out_dir.join(&tool_name);
            std::fs::write(&disk_path, engine)?;
            encoding.insert(tool_name.clone(), EntryCompression::Stored);
            entries_out.push(ExtractedEntry {
                name: tool_name,
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
    let mut rest: &str = normalized.as_str();
    let mut stripped_a_variable_segment: bool = false;
    loop {
        let candidate: &str = rest.trim_start_matches('/');
        let head: &str = candidate.split('/').next().unwrap_or_default();
        if head.is_empty() || !is_nsis_var_segment(head) {
            break;
        }
        stripped_a_variable_segment = true;
        rest = &candidate[head.len()..];
    }
    if !stripped_a_variable_segment {
        return normalized;
    }
    let tail: &str = rest.trim_start_matches('/');
    if tail.is_empty() {
        return normalized.trim_matches('/').to_owned();
    }
    tail.to_owned()
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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

    if recovered == 0 && !archive.files.is_empty() && violations.is_empty() {
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

const fn rpm_entry_compression(compression: crate::containers::RpmCompression) -> EntryCompression {
    match compression {
        crate::containers::RpmCompression::Stored => EntryCompression::Stored,
        crate::containers::RpmCompression::Gzip => EntryCompression::Deflate,
        crate::containers::RpmCompression::Xz => EntryCompression::Xz,
        crate::containers::RpmCompression::Zstd => EntryCompression::Zstd,
        crate::containers::RpmCompression::Bzip2 => EntryCompression::Bzip2,
        crate::containers::RpmCompression::Lzma => EntryCompression::Lzma,
    }
}

const fn cpio_entry_kind(mode: u32) -> u32 {
    mode & 0o170_000
}

#[cfg(not(windows))]
const fn rpm_host_path_is_representable(_name: &str) -> bool {
    true
}

#[cfg(windows)]
fn rpm_host_path_is_representable(name: &str) -> bool {
    name.split('/').all(|component: &str| {
        let invalid_byte: bool = component.bytes().any(|byte: u8| {
            byte <= 31 || matches!(byte, b'<' | b'>' | b':' | b'"' | b'|' | b'?' | b'*')
        });
        let invalid_ending: bool = matches!(component.as_bytes().last(), Some(b' ' | b'.'));
        let stem: &str = component
            .split_once('.')
            .map_or(component, |(stem, _suffix): (&str, &str)| stem);
        let uppercase: String = stem.to_ascii_uppercase();
        let reserved: bool = matches!(
            uppercase.as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        );
        !component.is_empty() && !invalid_byte && !invalid_ending && !reserved
    })
}

fn extract_rpm(bytes: &[u8], out_dir: &Path, quota: ExtractionQuota) -> Result<ExtractionResult> {
    let recovered: crate::containers::RecoveredRpm =
        crate::containers::recover_rpm(bytes, quota.max_total_uncompressed)?;
    let entry_compression: EntryCompression = rpm_entry_compression(recovered.compression);
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut entries_out: Vec<ExtractedEntry> = Vec::new();
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();
    let mut accepted: Vec<(usize, String)> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (index, entry) in recovered.entries.iter().enumerate() {
        let safe_name: String = sanitize_entry_path(&entry.name)?;
        if !seen.insert(safe_name.clone()) {
            return Err(Error::Rpm(format!(
                "duplicate normalized payload path `{safe_name}`"
            )));
        }
        if cpio_entry_kind(entry.mode) == 0o100_000 && !entry.ghost {
            guard.admit_entry(&safe_name, entry.file_size, entry.file_size)?;
        }
        accepted.push((index, safe_name));
    }
    for (index, safe_name) in accepted {
        let entry: &crate::containers::RpmEntry = recovered
            .entries
            .get(index)
            .ok_or_else(|| Error::Rpm("validated RPM entry disappeared".to_owned()))?;
        let entry_kind: u32 = cpio_entry_kind(entry.mode);
        let materializes: bool =
            entry_kind == 0o040_000 || (entry_kind == 0o100_000 && !entry.ghost);
        if materializes && !rpm_host_path_is_representable(&safe_name) {
            violations.push(format!(
                "rpm-host-path `{safe_name}` cannot be represented by the output filesystem"
            ));
            entries_out.push(ExtractedEntry {
                name: safe_name,
                disk_path: None,
                uncompressed_size: entry.file_size,
                compressed_size: entry.file_size,
                compression: entry_compression,
                is_executable: entry.mode & 0o111 != 0,
            });
            continue;
        }
        if entry_kind == 0o040_000 {
            let _: PathBuf = prepare_entry_dir(out_dir, &safe_name)?;
            entries_out.push(ExtractedEntry {
                name: safe_name,
                disk_path: None,
                uncompressed_size: 0,
                compressed_size: 0,
                compression: entry_compression,
                is_executable: entry.mode & 0o111 != 0,
            });
            continue;
        }
        if entry_kind != 0o100_000 || entry.ghost {
            entries_out.push(ExtractedEntry {
                name: safe_name,
                disk_path: None,
                uncompressed_size: entry.file_size,
                compressed_size: entry.file_size,
                compression: entry_compression,
                is_executable: entry.mode & 0o111 != 0,
            });
            continue;
        }
        let data: &[u8] = recovered.member_bytes(entry)?;
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
        std::fs::write(&disk_path, data)?;
        encoding.insert(safe_name.clone(), entry_compression);
        entries_out.push(ExtractedEntry {
            name: safe_name,
            disk_path: Some(disk_path),
            uncompressed_size: entry.file_size,
            compressed_size: entry.file_size,
            compression: entry_compression,
            is_executable: entry.mode & 0o111 != 0,
        });
    }
    let mut summary: QuotaSummary = QuotaSummary::from(guard.report());
    summary.total_compressed_bytes = recovered.compressed_size;
    Ok(ExtractionResult {
        kind: ContainerKind::Rpm,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: summary,
    })
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
    let names: Vec<String> = cab_backed_file_names(&cabinet, &mut violations);
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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

const EOCD_SIGNATURE: [u8; 4] = [b'P', b'K', 0x05, 0x06];
const CENTRAL_DIRECTORY_SIGNATURE: [u8; 4] = [b'P', b'K', 0x01, 0x02];
const LOCAL_FILE_SIGNATURE: [u8; 4] = [b'P', b'K', 0x03, 0x04];
const EOCD_MIN_LEN: usize = 22;
const EOCD_MAX_COMMENT: usize = 0xFFFF;
const CENTRAL_DIRECTORY_FIXED_LEN: usize = 46;
const ZIP64_U16_SENTINEL: u16 = 0xFFFF;
const ZIP64_U32_SENTINEL: u32 = 0xFFFF_FFFF;
const ZIP64_LOCATOR_SIGNATURE: [u8; 4] = [b'P', b'K', 0x06, 0x07];
const ZIP64_EOCD_SIGNATURE: [u8; 4] = [b'P', b'K', 0x06, 0x06];
const ZIP64_LOCATOR_LEN: usize = 20;
const ZIP64_EOCD_FIXED_LEN: usize = 56;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ZipDirectoryMetadata {
    name: &'static str,
    entries: u64,
    size: u64,
    offset: u64,
    archive_prefix: usize,
    directory_limit: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ClassicEocd {
    disk_number: u16,
    directory_disk: u16,
    disk_entries: u16,
    entries: u16,
    directory_size: u32,
    directory_offset: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EocdLocation {
    Complete(usize),
    Truncated(usize),
    Absent,
}

enum Zip64CandidateFailure {
    NotFound,
    Invalid(String),
}

fn find_eocd(bytes: &[u8]) -> EocdLocation {
    let window: usize = EOCD_MIN_LEN
        .saturating_add(EOCD_MAX_COMMENT)
        .min(bytes.len());
    let start: usize = bytes.len().saturating_sub(window);
    let Some(search): Option<&[u8]> = bytes.get(start..) else {
        return EocdLocation::Absent;
    };
    let mut truncated: Option<usize> = None;
    for relative in 0..search.len().saturating_sub(EOCD_SIGNATURE.len() - 1) {
        let Some(absolute): Option<usize> = start.checked_add(relative) else {
            continue;
        };
        let Some(signature_end): Option<usize> = absolute.checked_add(EOCD_SIGNATURE.len()) else {
            continue;
        };
        if bytes.get(absolute..signature_end) != Some(&EOCD_SIGNATURE) {
            continue;
        }
        let Some(record_end): Option<usize> = absolute.checked_add(EOCD_MIN_LEN) else {
            truncated.get_or_insert(absolute);
            continue;
        };
        let Some(record): Option<&[u8]> = bytes.get(absolute..record_end) else {
            truncated.get_or_insert(absolute);
            continue;
        };
        let comment_len: usize = usize::from(u16::from_le_bytes([record[20], record[21]]));
        let Some(end): Option<usize> = absolute
            .checked_add(EOCD_MIN_LEN)
            .and_then(|value: usize| value.checked_add(comment_len))
        else {
            truncated.get_or_insert(absolute);
            continue;
        };
        if end == bytes.len() {
            return EocdLocation::Complete(absolute);
        }
        if end > bytes.len() {
            truncated.get_or_insert(absolute);
        }
    }
    truncated.map_or(EocdLocation::Absent, EocdLocation::Truncated)
}

fn zip_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let raw: &[u8] = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([raw[0], raw[1]]))
}

fn zip_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw: &[u8] = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn zip_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let raw: &[u8] = bytes.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

fn parse_classic_eocd(record: &[u8]) -> Option<ClassicEocd> {
    Some(ClassicEocd {
        disk_number: zip_u16(record, 4)?,
        directory_disk: zip_u16(record, 6)?,
        disk_entries: zip_u16(record, 8)?,
        entries: zip_u16(record, 10)?,
        directory_size: zip_u32(record, 12)?,
        directory_offset: zip_u32(record, 16)?,
    })
}

fn validate_zip64_extensible_sector(sector: &[u8]) -> core::result::Result<(), String> {
    let mut cursor: usize = 0;
    while cursor < sector.len() {
        let header_end: usize = cursor
            .checked_add(6)
            .ok_or_else(|| "the ZIP64 extensible-sector header offset overflows".to_owned())?;
        let header: &[u8] = sector.get(cursor..header_end).ok_or_else(|| {
            "the ZIP64 extensible sector ends with a truncated block header".to_owned()
        })?;
        let payload_len: usize = usize::try_from(u32::from_le_bytes([
            header[2], header[3], header[4], header[5],
        ]))
        .map_err(|_| "a ZIP64 extensible-sector block exceeds the host address space".to_owned())?;
        let payload_end: usize = header_end
            .checked_add(payload_len)
            .ok_or_else(|| "a ZIP64 extensible-sector block extent overflows".to_owned())?;
        sector.get(header_end..payload_end).ok_or_else(|| {
            "a ZIP64 extensible-sector block extends past the ZIP64 end record".to_owned()
        })?;
        cursor = payload_end;
    }
    Ok(())
}

fn parse_zip64_candidate(
    bytes: &[u8],
    physical_eocd: usize,
    record_size: u64,
    logical_eocd: usize,
    locator_disk: u32,
    classic: ClassicEocd,
) -> core::result::Result<ZipDirectoryMetadata, String> {
    if record_size < 44 {
        return Err(format!(
            "the ZIP64 end record declares {record_size} byte(s) after its size field, below the 44-byte fixed minimum"
        ));
    }
    let archive_prefix: usize = physical_eocd.checked_sub(logical_eocd).ok_or_else(|| {
        "the ZIP64 locator end-record offset is past the physical ZIP64 record".to_owned()
    })?;
    let fixed_end: usize = physical_eocd
        .checked_add(ZIP64_EOCD_FIXED_LEN)
        .ok_or_else(|| "the ZIP64 end-record fixed extent overflows".to_owned())?;
    let fixed: &[u8] = bytes
        .get(physical_eocd..fixed_end)
        .ok_or_else(|| "the ZIP64 end record is truncated".to_owned())?;
    let total_size: usize = usize::try_from(
        record_size
            .checked_add(12)
            .ok_or_else(|| "the ZIP64 end-record extent overflows".to_owned())?,
    )
    .map_err(|_| "the ZIP64 end-record extent exceeds the host address space".to_owned())?;
    let record_end: usize = physical_eocd
        .checked_add(total_size)
        .ok_or_else(|| "the ZIP64 end-record physical extent overflows".to_owned())?;
    let record: &[u8] = bytes
        .get(physical_eocd..record_end)
        .ok_or_else(|| "the ZIP64 end record is truncated".to_owned())?;
    validate_zip64_extensible_sector(&record[ZIP64_EOCD_FIXED_LEN..])?;
    let disk_number: u32 = zip_u32(fixed, 16)
        .ok_or_else(|| "the ZIP64 end record is truncated before its disk number".to_owned())?;
    let directory_disk: u32 = zip_u32(fixed, 20).ok_or_else(|| {
        "the ZIP64 end record is truncated before its central-directory disk".to_owned()
    })?;
    let disk_entries: u64 = zip_u64(fixed, 24).ok_or_else(|| {
        "the ZIP64 end record is truncated before its per-disk entry count".to_owned()
    })?;
    let entries: u64 = zip_u64(fixed, 32)
        .ok_or_else(|| "the ZIP64 end record is truncated before its entry count".to_owned())?;
    let size: u64 = zip_u64(fixed, 40).ok_or_else(|| {
        "the ZIP64 end record is truncated before its central-directory size".to_owned()
    })?;
    let offset: u64 = zip_u64(fixed, 48).ok_or_else(|| {
        "the ZIP64 end record is truncated before its central-directory offset".to_owned()
    })?;
    if disk_number != 0
        || directory_disk != 0
        || directory_disk != locator_disk
        || disk_entries != entries
    {
        return Err(format!(
            "the ZIP64 end record describes inconsistent multi-disk metadata: disk={disk_number}, directory_disk={directory_disk}, disk_entries={disk_entries}, total_entries={entries}"
        ));
    }
    let fields_agree: bool = (classic.disk_number == ZIP64_U16_SENTINEL
        || u32::from(classic.disk_number) == disk_number)
        && (classic.directory_disk == ZIP64_U16_SENTINEL
            || u32::from(classic.directory_disk) == directory_disk)
        && (classic.disk_entries == ZIP64_U16_SENTINEL
            || u64::from(classic.disk_entries) == disk_entries)
        && (classic.entries == ZIP64_U16_SENTINEL || u64::from(classic.entries) == entries)
        && (classic.directory_size == ZIP64_U32_SENTINEL
            || u64::from(classic.directory_size) == size)
        && (classic.directory_offset == ZIP64_U32_SENTINEL
            || u64::from(classic.directory_offset) == offset);
    if !fields_agree {
        return Err("the classic and ZIP64 end-of-central-directory records disagree".to_owned());
    }
    let physical_directory: usize = archive_prefix
        .checked_add(usize::try_from(offset).map_err(|_| {
            "the ZIP64 central-directory offset exceeds the host address space".to_owned()
        })?)
        .ok_or_else(|| "the ZIP64 central-directory physical offset overflows".to_owned())?;
    let physical_directory_end: usize = physical_directory
        .checked_add(usize::try_from(size).map_err(|_| {
            "the ZIP64 central-directory size exceeds the host address space".to_owned()
        })?)
        .ok_or_else(|| "the ZIP64 central-directory physical extent overflows".to_owned())?;
    if physical_directory_end > physical_eocd {
        return Err(format!(
            "the ZIP64 central directory ends at physical offset {physical_directory_end}, past its end record at {physical_eocd}"
        ));
    }
    Ok(ZipDirectoryMetadata {
        name: "ZIP64 end-of-central-directory record",
        entries,
        size,
        offset,
        archive_prefix,
        directory_limit: physical_eocd,
    })
}

fn parse_zip64_metadata(
    bytes: &[u8],
    eocd: usize,
    classic: ClassicEocd,
) -> core::result::Result<ZipDirectoryMetadata, String> {
    let Some(locator): Option<usize> = eocd.checked_sub(ZIP64_LOCATOR_LEN) else {
        return Err("the end-of-central-directory record uses a reserved ZIP64 sentinel, but the 20-byte ZIP64 locator immediately before it is absent".to_owned());
    };
    let locator_end: usize = locator
        .checked_add(ZIP64_LOCATOR_LEN)
        .ok_or_else(|| "the ZIP64 locator extent overflows the host address space".to_owned())?;
    let locator_record: &[u8] = bytes.get(locator..locator_end).ok_or_else(|| {
        "the end-of-central-directory record uses a reserved ZIP64 sentinel, but the 20-byte ZIP64 locator immediately before it is absent".to_owned()
    })?;
    if locator_record.get(..ZIP64_LOCATOR_SIGNATURE.len()) != Some(&ZIP64_LOCATOR_SIGNATURE) {
        return Err("the end-of-central-directory record uses a reserved ZIP64 sentinel, but the 20-byte ZIP64 locator immediately before it is absent".to_owned());
    }
    let locator_disk: u32 = zip_u32(locator_record, 4)
        .ok_or_else(|| "the ZIP64 locator is truncated before its disk number".to_owned())?;
    let logical_eocd: u64 = zip_u64(locator_record, 8)
        .ok_or_else(|| "the ZIP64 locator is truncated before its record offset".to_owned())?;
    let disk_count: u32 = zip_u32(locator_record, 16)
        .ok_or_else(|| "the ZIP64 locator is truncated before its disk count".to_owned())?;
    if locator_disk != 0 || disk_count != 1 {
        return Err(format!(
            "the ZIP64 multi-disk layout is unsupported for one input file: end_record_disk={locator_disk}, total_disks={disk_count}"
        ));
    }
    let logical_eocd: usize = usize::try_from(logical_eocd)
        .map_err(|_| "the ZIP64 end-record offset exceeds the host address space".to_owned())?;
    if logical_eocd >= locator {
        return Err(format!(
            "the ZIP64 locator points to end record offset {logical_eocd}, which is not before the locator at {locator}"
        ));
    }
    let search: &[u8] = bytes
        .get(logical_eocd..locator)
        .ok_or_else(|| "the ZIP64 end-record search range is outside the input".to_owned())?;
    let mut candidate_failure: Zip64CandidateFailure = Zip64CandidateFailure::NotFound;
    for relative in 0..search.len().saturating_sub(ZIP64_EOCD_SIGNATURE.len() - 1) {
        let Some(physical_eocd): Option<usize> = logical_eocd.checked_add(relative) else {
            continue;
        };
        let Some(signature_end): Option<usize> =
            physical_eocd.checked_add(ZIP64_EOCD_SIGNATURE.len())
        else {
            continue;
        };
        if bytes.get(physical_eocd..signature_end) != Some(&ZIP64_EOCD_SIGNATURE) {
            continue;
        }
        let Some(size_offset): Option<usize> = physical_eocd.checked_add(4) else {
            continue;
        };
        let Some(record_size): Option<u64> = zip_u64(bytes, size_offset) else {
            continue;
        };
        let Some(total_size): Option<usize> = record_size
            .checked_add(12)
            .and_then(|value: u64| usize::try_from(value).ok())
        else {
            continue;
        };
        if physical_eocd.checked_add(total_size) != Some(locator) {
            continue;
        }
        match parse_zip64_candidate(
            bytes,
            physical_eocd,
            record_size,
            logical_eocd,
            locator_disk,
            classic,
        ) {
            Ok(metadata) => return Ok(metadata),
            Err(reason) => {
                if matches!(candidate_failure, Zip64CandidateFailure::NotFound) {
                    candidate_failure = Zip64CandidateFailure::Invalid(reason);
                }
            }
        }
    }
    match candidate_failure {
        Zip64CandidateFailure::NotFound => Err(format!(
            "the ZIP64 locator points to end record offset {logical_eocd}, but no bounded ZIP64 end record terminates at the locator"
        )),
        Zip64CandidateFailure::Invalid(reason) => Err(reason),
    }
}

fn zip64_local_offset(
    entry: &[u8],
    name_len: usize,
    extra_len: usize,
    entry_index: usize,
    local_offset: u32,
    disk_start: u16,
) -> core::result::Result<u64, String> {
    let Some(extra_start): Option<usize> = CENTRAL_DIRECTORY_FIXED_LEN.checked_add(name_len) else {
        return Err(format!(
            "central-directory entry {entry_index} name length overflows"
        ));
    };
    let Some(extra_end): Option<usize> = extra_start.checked_add(extra_len) else {
        return Err(format!(
            "central-directory entry {entry_index} extra-field length overflows"
        ));
    };
    let extra: &[u8] = entry.get(extra_start..extra_end).ok_or_else(|| {
        format!("central-directory entry {entry_index} has a truncated extra-field area")
    })?;
    let mut cursor: usize = 0;
    while cursor < extra.len() {
        let header_end: usize = cursor.checked_add(4).ok_or_else(|| {
            format!("central-directory entry {entry_index} extra-field offset overflows")
        })?;
        let header: &[u8] = extra.get(cursor..header_end).ok_or_else(|| {
            format!("central-directory entry {entry_index} has a truncated extra-field header")
        })?;
        let tag: u16 = u16::from_le_bytes([header[0], header[1]]);
        let field_len: usize = usize::from(u16::from_le_bytes([header[2], header[3]]));
        let data_start: usize = header_end;
        let data_end: usize = data_start.checked_add(field_len).ok_or_else(|| {
            format!("central-directory entry {entry_index} extra-field length overflows")
        })?;
        let data: &[u8] = extra.get(data_start..data_end).ok_or_else(|| {
            format!("central-directory entry {entry_index} has a truncated extra field")
        })?;
        if tag == 0x0001 {
            let mut value_offset: usize = 0;
            if zip_u32(entry, 24) == Some(ZIP64_U32_SENTINEL) {
                value_offset = value_offset.checked_add(8).ok_or_else(|| {
                    format!("central-directory entry {entry_index} ZIP64 field offset overflows")
                })?;
            }
            if zip_u32(entry, 20) == Some(ZIP64_U32_SENTINEL) {
                value_offset = value_offset.checked_add(8).ok_or_else(|| {
                    format!("central-directory entry {entry_index} ZIP64 field offset overflows")
                })?;
            }
            let resolved_offset: u64 = if local_offset == ZIP64_U32_SENTINEL {
                let value: u64 = zip_u64(data, value_offset).ok_or_else(|| {
                    format!(
                        "central-directory entry {entry_index} omits its ZIP64 local-header offset"
                    )
                })?;
                value_offset = value_offset.checked_add(8).ok_or_else(|| {
                    format!("central-directory entry {entry_index} ZIP64 field offset overflows")
                })?;
                value
            } else {
                u64::from(local_offset)
            };
            if disk_start == ZIP64_U16_SENTINEL {
                let resolved_disk: u32 = zip_u32(data, value_offset).ok_or_else(|| {
                    format!("central-directory entry {entry_index} omits its ZIP64 starting disk")
                })?;
                if resolved_disk != 0 {
                    return Err(format!(
                        "central-directory entry {entry_index} starts on ZIP64 disk {resolved_disk}, but only one input file was provided"
                    ));
                }
            }
            return Ok(resolved_offset);
        }
        cursor = data_end;
    }
    Err(format!(
        "central-directory entry {entry_index} omits the ZIP64 extra field for its selected fields"
    ))
}

fn count_central_directory_entries(
    bytes: &[u8],
    directory: &[u8],
    archive_prefix: usize,
) -> core::result::Result<usize, String> {
    let mut cursor: usize = 0;
    let mut entries: usize = 0;
    while cursor < directory.len() {
        let remaining: usize = directory.len() - cursor;
        let Some(signature_end): Option<usize> = cursor.checked_add(4) else {
            return Err(format!(
                "central-directory entry {entries} signature extent overflows"
            ));
        };
        let Some(signature): Option<&[u8]> = directory.get(cursor..signature_end) else {
            return Err(format!(
                "central-directory entry {entries} is truncated before its signature; {remaining} byte(s) remain"
            ));
        };
        if signature != CENTRAL_DIRECTORY_SIGNATURE {
            return Err(format!(
                "central-directory entry {entries} at relative offset {cursor} does not begin with the central-directory signature"
            ));
        }
        let Some(fixed_end): Option<usize> = cursor.checked_add(CENTRAL_DIRECTORY_FIXED_LEN) else {
            return Err(format!(
                "central-directory entry {entries} fixed-header extent overflows"
            ));
        };
        let Some(record): Option<&[u8]> = directory.get(cursor..fixed_end) else {
            return Err(format!(
                "central-directory entry {entries} is truncated; {remaining} byte(s) remain of the {CENTRAL_DIRECTORY_FIXED_LEN} byte fixed header"
            ));
        };
        let name_len: usize = usize::from(u16::from_le_bytes([record[28], record[29]]));
        let extra_len: usize = usize::from(u16::from_le_bytes([record[30], record[31]]));
        let comment_len: usize = usize::from(u16::from_le_bytes([record[32], record[33]]));
        let Some(entry_len): Option<usize> = CENTRAL_DIRECTORY_FIXED_LEN
            .checked_add(name_len)
            .and_then(|value: usize| value.checked_add(extra_len))
            .and_then(|value: usize| value.checked_add(comment_len))
        else {
            return Err(format!(
                "central-directory entry {entries} has lengths that overflow the host address space"
            ));
        };
        if entry_len > remaining {
            return Err(format!(
                "central-directory entry {entries} declares {entry_len} byte(s), but only {remaining} remain"
            ));
        }
        let local_offset: u32 =
            u32::from_le_bytes([record[42], record[43], record[44], record[45]]);
        let disk_start: u16 = u16::from_le_bytes([record[34], record[35]]);
        if disk_start != 0 && disk_start != ZIP64_U16_SENTINEL {
            return Err(format!(
                "central-directory entry {entries} starts on disk {disk_start}, but only one input file was provided"
            ));
        }
        let entry_end: usize = cursor
            .checked_add(entry_len)
            .ok_or_else(|| format!("central-directory entry {entries} extent overflows"))?;
        let entry: &[u8] = directory
            .get(cursor..entry_end)
            .ok_or_else(|| format!("central-directory entry {entries} extent is invalid"))?;
        let local_offset: u64 =
            if local_offset == ZIP64_U32_SENTINEL || disk_start == ZIP64_U16_SENTINEL {
                zip64_local_offset(
                    entry,
                    name_len,
                    extra_len,
                    entries,
                    local_offset,
                    disk_start,
                )?
            } else {
                u64::from(local_offset)
            };
        let local_offset: usize = usize::try_from(local_offset).map_err(|_| {
            format!("central-directory entry {entries} has an unrepresentable local-header offset")
        })?;
        let physical_local: usize = archive_prefix.checked_add(local_offset).ok_or_else(|| {
            format!("central-directory entry {entries} local-header offset overflows")
        })?;
        let physical_end: usize = physical_local
            .checked_add(LOCAL_FILE_SIGNATURE.len())
            .ok_or_else(|| {
                format!("central-directory entry {entries} local-header extent overflows")
            })?;
        if bytes.get(physical_local..physical_end) != Some(&LOCAL_FILE_SIGNATURE) {
            return Err(format!(
                "central-directory entry {entries} points to local-header offset {local_offset}, which does not identify a local file record"
            ));
        }
        cursor = entry_end;
        entries = entries.checked_add(1).ok_or_else(|| {
            "the central-directory entry count exceeds the host address space".to_owned()
        })?;
    }
    Ok(entries)
}

fn diagnose_zip_failure(bytes: &[u8], upstream: &str) -> String {
    if bytes.is_empty() {
        return "the input is empty, so it holds no archive".to_owned();
    }
    let eocd: usize = match find_eocd(bytes) {
        EocdLocation::Complete(offset) => offset,
        EocdLocation::Truncated(offset) => {
            return format!(
                "the end-of-central-directory record at offset {offset} is truncated; {} byte(s) remain of the {EOCD_MIN_LEN} byte fixed record",
                bytes.len().saturating_sub(offset)
            );
        }
        EocdLocation::Absent => {
            return format!(
                "no end-of-central-directory record in the last {} byte(s), so this is not a zip archive whatever its leading bytes say",
                EOCD_MIN_LEN
                    .saturating_add(EOCD_MAX_COMMENT)
                    .min(bytes.len())
            );
        }
    };
    let Some(record_end): Option<usize> = eocd.checked_add(EOCD_MIN_LEN) else {
        return format!("zip parser rejected a malformed archive ({upstream})");
    };
    let Some(record): Option<&[u8]> = bytes.get(eocd..record_end) else {
        return format!("zip parser rejected a malformed archive ({upstream})");
    };
    let Some(classic): Option<ClassicEocd> = parse_classic_eocd(record) else {
        return format!("zip parser rejected a malformed archive ({upstream})");
    };
    let ClassicEocd {
        disk_number,
        directory_disk,
        disk_entries: disk_declared,
        entries: declared,
        directory_size,
        directory_offset,
    }: ClassicEocd = classic;
    let uses_zip64: bool = disk_number == ZIP64_U16_SENTINEL
        || directory_disk == ZIP64_U16_SENTINEL
        || disk_declared == ZIP64_U16_SENTINEL
        || declared == ZIP64_U16_SENTINEL
        || directory_size == ZIP64_U32_SENTINEL
        || directory_offset == ZIP64_U32_SENTINEL;
    let locator_present: bool = eocd
        .checked_sub(ZIP64_LOCATOR_LEN)
        .and_then(|offset: usize| {
            let end: usize = offset.checked_add(ZIP64_LOCATOR_SIGNATURE.len())?;
            bytes.get(offset..end)
        })
        == Some(&ZIP64_LOCATOR_SIGNATURE);
    let metadata: ZipDirectoryMetadata = if uses_zip64 || locator_present {
        match parse_zip64_metadata(bytes, eocd, classic) {
            Ok(metadata) => metadata,
            Err(reason) => return reason,
        }
    } else {
        if disk_number != 0 || directory_disk != 0 || disk_declared != declared {
            return format!(
                "the end-of-central-directory record describes inconsistent multi-disk metadata: disk={disk_number}, directory_disk={directory_disk}, disk_entries={disk_declared}, total_entries={declared}"
            );
        }
        let declared_end: u64 = u64::from(directory_offset) + u64::from(directory_size);
        if declared_end > eocd as u64 {
            return format!(
                "the central directory is declared at offset {directory_offset} for {directory_size} byte(s), which ends past the end-of-central-directory record at offset {eocd}"
            );
        }
        let declared_end: usize = match usize::try_from(declared_end) {
            Ok(value) => value,
            Err(_) => {
                return "the central-directory extent exceeds the host address space".to_owned();
            }
        };
        ZipDirectoryMetadata {
            name: "end-of-central-directory record",
            entries: u64::from(declared),
            size: u64::from(directory_size),
            offset: u64::from(directory_offset),
            archive_prefix: eocd - declared_end,
            directory_limit: eocd,
        }
    };
    let directory_offset: usize = match usize::try_from(metadata.offset) {
        Ok(value) => value,
        Err(_) => return "the central-directory offset exceeds the host address space".to_owned(),
    };
    let directory_size: usize = match usize::try_from(metadata.size) {
        Ok(value) => value,
        Err(_) => return "the central-directory size exceeds the host address space".to_owned(),
    };
    let physical_offset: usize = match metadata.archive_prefix.checked_add(directory_offset) {
        Some(offset) => offset,
        None => {
            return "the central-directory offset overflows the host address space".to_owned();
        }
    };
    let Some(physical_end): Option<usize> = physical_offset.checked_add(directory_size) else {
        return "the central-directory extent overflows the host address space".to_owned();
    };
    if physical_end > metadata.directory_limit {
        return format!(
            "the central directory ends at physical offset {physical_end}, past its metadata record at {}",
            metadata.directory_limit
        );
    }
    let Some(directory): Option<&[u8]> = bytes.get(physical_offset..physical_end) else {
        return format!(
            "the central-directory offset {directory_offset} does not map inside the archive"
        );
    };
    let actual: usize =
        match count_central_directory_entries(bytes, directory, metadata.archive_prefix) {
            Ok(count) => count,
            Err(reason) => return reason,
        };
    let actual: u64 = match u64::try_from(actual) {
        Ok(value) => value,
        Err(_) => return "the central-directory entry count exceeds u64".to_owned(),
    };
    if actual != metadata.entries {
        let noun: &str = if metadata.entries == 1 {
            "entry"
        } else {
            "entries"
        };
        return format!(
            "the {} declares {} {noun}, but the central directory contains {actual}",
            metadata.name, metadata.entries
        );
    }
    format!("zip parser rejected structurally consistent directory metadata ({upstream})")
}

fn extract_zip(
    kind: ContainerKind,
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let mut archive: zip::ZipArchive<Cursor<&[u8]>> = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| Error::Zip(diagnose_zip_failure(bytes, &e.to_string())))?;
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
    let mut violations: Vec<String> = Vec::new();
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
                    Err(e) => {
                        violations.push(format!("sevenz-slip: {e}"));
                        return Ok(true);
                    }
                };
                let uncompressed_size: u64 = entry.size();
                let compressed_size: u64 = entry.compressed_size;
                if let Err(e) = guard.admit_entry(&safe_name, uncompressed_size, compressed_size) {
                    return Err(sevenz_rust2::Error::other(e.to_string()));
                }
                let buf: Vec<u8> = read_entry_to_limit(data, &safe_name, uncompressed_size)
                    .map_err(|e: Error| sevenz_rust2::Error::other(e.to_string()))?;
                let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)
                    .map_err(|e: Error| sevenz_rust2::Error::other(e.to_string()))?;
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
    let safe_name: String = match sanitize_entry_path(&raw_name) {
        Ok(s) => s,
        Err(e) => {
            return Ok(ExtractionResult {
                kind: ContainerKind::Lzo,
                entries: Vec::new(),
                encoding,
                integrity_violations: vec![format!("lzop-slip: {e}")],
                quota: QuotaSummary::from(guard.report()),
            });
        }
    };
    let size: u64 = file.data.len() as u64;
    guard.admit_entry(&safe_name, size, bytes.len() as u64)?;
    let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
    let tool_name: String = "uzip.img".to_owned();
    let size: u64 = image.image.len() as u64;
    let compression: EntryCompression = match image.compressor {
        crate::containers::UzipCompressor::Zlib => EntryCompression::Deflate,
        crate::containers::UzipCompressor::Lzma => EntryCompression::Lzma,
        crate::containers::UzipCompressor::Zstd => EntryCompression::Zstd,
    };
    guard.admit_entry(&tool_name, size, bytes.len() as u64)?;
    let disk_path: PathBuf = out_dir.join(&tool_name);
    std::fs::write(&disk_path, &image.image)?;
    encoding.insert(tool_name.clone(), compression);
    entries_out.push(ExtractedEntry {
        name: tool_name,
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
    let tool_name: String = "assembly.dll".to_owned();
    let size: u64 = asm.data.len() as u64;
    guard.admit_entry(&tool_name, size, bytes.len() as u64)?;
    let disk_path: PathBuf = out_dir.join(&tool_name);
    std::fs::write(&disk_path, &asm.data)?;
    encoding.insert(tool_name.clone(), EntryCompression::Other);
    let entries_out: Vec<ExtractedEntry> = vec![ExtractedEntry {
        name: tool_name,
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
    let tool_summary_name: String = ".disrobe-par2.json".to_owned();
    let summary_path: PathBuf = out_dir.join(&tool_summary_name);
    std::fs::write(&summary_path, summary_json.as_bytes())?;
    encoding.insert(tool_summary_name.clone(), EntryCompression::Stored);
    entries_out.push(ExtractedEntry {
        name: tool_summary_name,
        disk_path: Some(summary_path),
        uncompressed_size: summary_json.len() as u64,
        compressed_size: summary_json.len() as u64,
        compression: EntryCompression::Stored,
        is_executable: false,
    });
    let tool_recovery_name: String = "recovery-set.par2".to_owned();
    let size: u64 = bytes.len() as u64;
    guard.admit_entry(&tool_recovery_name, size, size)?;
    let recovery_path: PathBuf = out_dir.join(&tool_recovery_name);
    std::fs::write(&recovery_path, bytes)?;
    encoding.insert(tool_recovery_name.clone(), EntryCompression::Stored);
    entries_out.push(ExtractedEntry {
        name: tool_recovery_name,
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
    let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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

    let tool_name: String = "partclone.img".to_owned();
    let size: u64 = raw.len() as u64;
    guard.admit_entry(&tool_name, size, bytes.len() as u64)?;
    let disk_path: PathBuf = out_dir.join(&tool_name);
    std::fs::write(&disk_path, &raw)?;
    encoding.insert(tool_name.clone(), EntryCompression::Other);
    entries_out.push(ExtractedEntry {
        name: tool_name,
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
            let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
        let tool_name: String = "qnx-ifs.img".to_owned();
        let size: u64 = image.len() as u64;
        guard.admit_entry(&tool_name, size, bytes.len() as u64)?;
        let disk_path: PathBuf = out_dir.join(&tool_name);
        std::fs::write(&disk_path, &image)?;
        encoding.insert(tool_name.clone(), EntryCompression::Deflate);
        entries_out.push(ExtractedEntry {
            name: tool_name,
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
        let tool_name: String = "qnx-ifs.img".to_owned();
        let size: u64 = image.len() as u64;
        guard.admit_entry(&tool_name, size, bytes.len() as u64)?;
        let disk_path: PathBuf = out_dir.join(&tool_name);
        std::fs::write(&disk_path, &image)?;
        encoding.insert(tool_name.clone(), EntryCompression::Other);
        entries_out.push(ExtractedEntry {
            name: tool_name,
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

#[derive(Debug, Serialize)]
struct UefiFvSummary<'a> {
    volumes_walked: usize,
    file_count: usize,
    files: &'a [UefiFvFileSummary],
    notes: &'a [String],
    truncated: bool,
}

#[derive(Debug, Serialize)]
struct UefiFvFileSummary {
    guid: String,
    file_type: String,
    depth: usize,
    name: Option<String>,
    size: u64,
    section_count: usize,
    written_file: Option<String>,
}

fn extract_uefi_firmware_volume(
    bytes: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Result<ExtractionResult> {
    let extraction: crate::containers::FvExtraction =
        crate::containers::extract_uefi_fv(bytes, quota)?;
    std::fs::create_dir_all(out_dir)?;
    let mut guard: QuotaGuard = QuotaGuard::new(ExtractionQuota {
        max_aggregate_ratio: quota.max_aggregate_ratio.max(1000),
        max_per_entry_ratio: quota.max_per_entry_ratio.max(1000),
        ..quota
    });
    let mut entries_out: Vec<ExtractedEntry> = Vec::new();
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let mut violations: Vec<String> = extraction.notes.clone();
    let mut file_summaries: Vec<UefiFvFileSummary> = Vec::with_capacity(extraction.files.len());
    let mut used_names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for file in &extraction.files {
        let guid_string: String = crate::containers::guid_to_string(&file.guid);
        let pe_image: Option<&crate::containers::FvPeImage> = extraction
            .pe_images
            .iter()
            .find(|p: &&crate::containers::FvPeImage| p.file_guid == file.guid);
        let mut written_file: Option<String> = None;
        if let Some(pe) = pe_image {
            let base_name: String = pe
                .name
                .clone()
                .and_then(|n: String| sanitize_entry_path(&n).ok())
                .unwrap_or_else(|| format!("{guid_string}.efi"));
            let label: String = if used_names.contains(&base_name) {
                format!("{guid_string}.{base_name}")
            } else {
                base_name
            };
            let size: u64 = pe.data.len() as u64;
            if let Err(e) = guard.admit_entry(&label, size, size) {
                violations.push(format!("uefi-fv-quota `{label}`: {e}"));
            } else {
                used_names.insert(label.clone());
                let disk_path: PathBuf = prepare_entry_path(out_dir, &label)?;
                std::fs::write(&disk_path, &pe.data)?;
                encoding.insert(label.clone(), EntryCompression::Stored);
                entries_out.push(ExtractedEntry {
                    name: label.clone(),
                    disk_path: Some(disk_path),
                    uncompressed_size: size,
                    compressed_size: size,
                    compression: EntryCompression::Stored,
                    is_executable: true,
                });
                written_file = Some(label);
            }
        }
        file_summaries.push(UefiFvFileSummary {
            guid: guid_string,
            file_type: format!("{:?}", file.file_type),
            depth: file.depth,
            name: file.name.clone(),
            size: file.size,
            section_count: file.sections.len(),
            written_file,
        });
    }

    let summary: UefiFvSummary = UefiFvSummary {
        volumes_walked: extraction.volumes_walked,
        file_count: extraction.files.len(),
        files: &file_summaries,
        notes: &extraction.notes,
        truncated: extraction.truncated,
    };
    let summary_json: String =
        serde_json::to_string_pretty(&summary).unwrap_or_else(|_: serde_json::Error| String::new());
    let tool_summary_name: String = ".disrobe-uefi-fv.json".to_owned();
    let summary_path: PathBuf = out_dir.join(&tool_summary_name);
    std::fs::write(&summary_path, summary_json.as_bytes())?;
    encoding.insert(tool_summary_name.clone(), EntryCompression::Stored);
    entries_out.push(ExtractedEntry {
        name: tool_summary_name,
        disk_path: Some(summary_path),
        uncompressed_size: summary_json.len() as u64,
        compressed_size: summary_json.len() as u64,
        compression: EntryCompression::Stored,
        is_executable: false,
    });

    Ok(ExtractionResult {
        kind: ContainerKind::UefiFv,
        entries: entries_out,
        encoding,
        integrity_violations: violations,
        quota: QuotaSummary::from(guard.report()),
    })
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
    let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
    let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
    let disk_path: PathBuf = prepare_entry_path(ctx.out_dir, &safe_name)?;
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
    if start == 0 {
        sink.violations.push(format!(
            "partition-overlap `{safe_name}`: range {start}..{end} starts at the partition table itself, so it is not descended into"
        ));
        return Ok(());
    }
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
    let nested_name: String = format!("{partition_name}.d");
    if crate::containers::fat::detect_fat(slice) {
        let sub_dir: PathBuf = match prepare_entry_dir(ctx.out_dir, &nested_name) {
            Ok(dir) => dir,
            Err(e) => {
                sink.violations
                    .push(format!("partition-slip `{partition_name}`: {e}"));
                return;
            }
        };
        if let Err(e) = extract_fat_into(slice, &sub_dir, partition_name, ctx.quota, sink) {
            sink.violations
                .push(format!("partition-fs `{partition_name}` (fat): {e}"));
        }
        return;
    }
    let Some(kind): Option<ContainerKind> = inner_filesystem_kind(slice) else {
        return;
    };
    let sub_dir: PathBuf = match prepare_entry_dir(ctx.out_dir, &nested_name) {
        Ok(dir) => dir,
        Err(e) => {
            sink.violations
                .push(format!("partition-slip `{partition_name}`: {e}"));
            return;
        }
    };
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
        carve_partition_to_disk(
            &label,
            part.byte_range(table.logical_sector_size),
            ctx,
            &mut sink,
        )?;
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
            let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
    tool_filename: &str,
    json: &str,
    entries: &mut Vec<ExtractedEntry>,
    encoding: &mut BTreeMap<String, EntryCompression>,
) -> Result<()> {
    let path: PathBuf = out_dir.join(tool_filename);
    std::fs::write(&path, json.as_bytes())?;
    encoding.insert(tool_filename.to_owned(), EntryCompression::Stored);
    entries.push(ExtractedEntry {
        name: tool_filename.to_owned(),
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
    tool_filename: &str,
    value: &T,
    entries: &mut Vec<ExtractedEntry>,
    encoding: &mut BTreeMap<String, EntryCompression>,
) -> Result<()> {
    let json: String =
        serde_json::to_string_pretty(value).unwrap_or_else(|_: serde_json::Error| String::new());
    write_summary_entry(out_dir, tool_filename, &json, entries, encoding)
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

fn cab_backed_file_names<R: std::io::Read + std::io::Seek>(
    cabinet: &cab::Cabinet<R>,
    violations: &mut Vec<String>,
) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for folder in cabinet.folder_entries() {
        let blocks: u16 = folder.num_data_blocks();
        for file in folder.file_entries() {
            if blocks == 0 {
                violations.push(format!(
                    "cab-folder `{}`: the folder declares no data blocks, so the file has no backing data",
                    file.name()
                ));
                continue;
            }
            names.push(file.name().to_owned());
        }
    }
    names
}

fn extract_wim(
    bytes: &[u8],
    out_dir: &Path,
    requested_quota: ExtractionQuota,
) -> Result<ExtractionResult> {
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

    let base_quota: ExtractionQuota = requested_quota;
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
        let disk_path: PathBuf = prepare_entry_path(out_dir, &safe_name)?;
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
        let disk_path: PathBuf = match prepare_entry_path(out_dir, &safe_name) {
            Ok(path) => path,
            Err(e) => {
                violations.push(format!("wim-mkdir `{safe_name}`: {e}"));
                continue;
            }
        };
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
        let disk_path: PathBuf = match prepare_entry_path(out_dir, &safe_name) {
            Ok(path) => path,
            Err(e) => {
                violations.push(format!("wim-mkdir `{safe_name}`: {e}"));
                continue;
            }
        };
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::io::Write as _;

    use super::*;

    fn temp_dir(suffix: &str) -> disrobe_core::scratch::ScratchDir {
        let purpose: String = format!("binfmt-extract-{suffix}");
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir")
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
        let string_pickle_size: u32 = aligned + 4;
        let header_pickle_size: u32 = string_pickle_size + 4;
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]);
        out.extend_from_slice(&header_pickle_size.to_le_bytes());
        out.extend_from_slice(&string_pickle_size.to_le_bytes());
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
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("unityfs-textasset-violation");
        let out: PathBuf = scratch.path().to_path_buf();
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
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("zip-ok");
        let out: PathBuf = scratch.path().to_path_buf();
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
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("zip-slip");
        let out: PathBuf = scratch.path().to_path_buf();
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
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("zip-bomb");
        let out: PathBuf = scratch.path().to_path_buf();
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
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("zip-count");
        let out: PathBuf = scratch.path().to_path_buf();
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
    fn extract_zip_recovers_reference_utf8_names_byte_identically() {
        let bytes: &[u8] = include_bytes!("../tests/fixtures/containers/utf8_names_zip.bin");
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("zip-utf8-names");
        let out: PathBuf = scratch.path().to_path_buf();
        let result: ExtractionResult =
            extract_to(ContainerKind::Zip, bytes, &out).expect("extract reference zip");
        let cafe: &ExtractedEntry = result
            .entries
            .iter()
            .find(|e: &&ExtractedEntry| e.name == "café.txt")
            .expect("café.txt entry present");
        assert_eq!(
            cafe.name.as_bytes(),
            &[0x63, 0x61, 0x66, 0xC3, 0xA9, 0x2E, 0x74, 0x78, 0x74],
            "café must stay UTF-8, not Latin-1-split or double-encoded"
        );
        let cjk: &ExtractedEntry = result
            .entries
            .iter()
            .find(|e: &&ExtractedEntry| e.name == "日本語.bin")
            .expect("日本語.bin entry present");
        assert_eq!(cjk.name.as_bytes(), "日本語.bin".as_bytes());
        assert!(
            result
                .entries
                .iter()
                .any(|e: &ExtractedEntry| e.name == "nested/deep/path.txt")
        );
        assert!(
            !result
                .entries
                .iter()
                .any(|e: &ExtractedEntry| e.name.contains("evil"))
        );
        assert_eq!(
            std::fs::read(out.join("café.txt")).expect("café file written"),
            b"PAYLOAD-DATA-1234"
        );
        assert_eq!(
            std::fs::read(out.join("nested/deep/path.txt")).expect("nested file written"),
            b"PAYLOAD-DATA-1234"
        );
        assert!(
            result
                .integrity_violations
                .iter()
                .any(|v: &String| v.contains("zip-slip"))
        );
        let escaped: PathBuf = out.parent().expect("parent dir").join("evil.txt");
        assert!(
            !escaped.exists(),
            "traversal entry must not escape the root"
        );
        for entry in &result.entries {
            if let Some(disk) = &entry.disk_path {
                assert!(
                    disk.starts_with(&out),
                    "recovered path escaped root: {disk:?}"
                );
            }
        }
    }

    fn synth_sevenz(files: &[(&str, &[u8])]) -> Vec<u8> {
        let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let mut writer: sevenz_rust2::SevenZWriter<Cursor<Vec<u8>>> =
            sevenz_rust2::SevenZWriter::new(cursor).expect("7z writer");
        for (name, body) in files {
            let entry: sevenz_rust2::SevenZArchiveEntry =
                sevenz_rust2::SevenZArchiveEntry::new_file(name);
            writer
                .push_archive_entry::<&[u8]>(entry, Some(*body))
                .expect("push 7z entry");
        }
        writer.finish().expect("finish 7z").into_inner()
    }

    #[test]
    fn extract_sevenz_records_slip_violation_for_unsafe_entry() {
        let bytes: Vec<u8> = synth_sevenz(&[("ok/data.bin", b"good"), ("../evil.txt", b"bad")]);
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("7z-slip");
        let out: PathBuf = scratch.path().to_path_buf();
        let result: ExtractionResult =
            extract_to(ContainerKind::SevenZ, &bytes, &out).expect("extract 7z");
        assert!(
            result
                .entries
                .iter()
                .any(|e: &ExtractedEntry| e.name == "ok/data.bin")
        );
        assert!(
            !result
                .entries
                .iter()
                .any(|e: &ExtractedEntry| e.name.contains("evil"))
        );
        assert!(
            result
                .integrity_violations
                .iter()
                .any(|v: &String| v.contains("sevenz-slip")),
            "unsafe 7z entry must be surfaced, not silently dropped: {:?}",
            result.integrity_violations
        );
        let escaped: PathBuf = out.parent().expect("parent dir").join("evil.txt");
        assert!(
            !escaped.exists(),
            "traversal entry must not escape the root"
        );
    }

    #[test]
    fn extract_tar_writes_entries() {
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("tar-ok");
        let out: PathBuf = scratch.path().to_path_buf();
        let bytes: Vec<u8> = synth_tar(&[("a.txt", b"alpha"), ("b.txt", b"bravo")]);
        let result: ExtractionResult =
            extract_to(ContainerKind::Tar, &bytes, &out).expect("extract");
        assert_eq!(result.entries.len(), 2);
        assert_eq!(std::fs::read(out.join("a.txt")).expect("a"), b"alpha");
    }

    #[test]
    fn extract_tar_gz_writes_entries() {
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("targz-ok");
        let out: PathBuf = scratch.path().to_path_buf();
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
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("targz-bomb");
        let out: PathBuf = scratch.path().to_path_buf();
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
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("tar-slip");
        let out: PathBuf = scratch.path().to_path_buf();
        let bytes: Vec<u8> = synth_tar_with_raw_name(b"../escape.txt", b"x");
        let r: ExtractionResult = extract_to(ContainerKind::Tar, &bytes, &out).expect("extract");
        assert!(
            r.integrity_violations
                .iter()
                .any(|v| v.contains("tar-slip"))
        );
        assert!(r.entries.is_empty());
    }

    fn assert_no_escape_around(root: &Path) {
        let parent: &Path = root.parent().expect("scratch parent");
        for leaked in ["escape.txt", "evil.txt", "passwd", "win.ini"] {
            assert!(
                !parent.join(leaked).exists(),
                "`{leaked}` landed beside the output root"
            );
        }
    }

    fn assert_result_stays_inside(result: &ExtractionResult, root: &Path) {
        let root_real: PathBuf = std::fs::canonicalize(root).expect("canonical root");
        for entry in &result.entries {
            let Some(disk) = &entry.disk_path else {
                continue;
            };
            let real: PathBuf = std::fs::canonicalize(disk).expect("canonical entry path");
            assert!(
                real.starts_with(&root_real),
                "`{}` resolved to {real:?} outside {root_real:?}",
                entry.name
            );
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum NameOrigin {
        ArchiveSupplied,
        ToolGenerated,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum HostileCoverage {
        DrivenEndToEnd,
        GuardOnly(&'static str),
    }

    #[derive(Debug, Clone, Copy)]
    struct WritePathRow {
        function: &'static str,
        origin: NameOrigin,
        coverage: HostileCoverage,
    }

    const WRITE_PATH_ROSTER: &[WritePathRow] = &[
        row("extract_ar", NameOrigin::ArchiveSupplied, DRIVEN),
        row("extract_arc", NameOrigin::ArchiveSupplied, DRIVEN),
        row("extract_arj", NameOrigin::ArchiveSupplied, DRIVEN),
        row("extract_asar", NameOrigin::ArchiveSupplied, DRIVEN),
        row("extract_bare_gzip", NameOrigin::ArchiveSupplied, DRIVEN),
        row(
            "extract_bare_single_stream",
            NameOrigin::ToolGenerated,
            HostileCoverage::GuardOnly(
                "writes bare_stream_output_name(kind), a constant per container kind",
            ),
        ),
        row(
            "extract_bare_xz",
            NameOrigin::ToolGenerated,
            HostileCoverage::GuardOnly("writes the constant name stream.bin"),
        ),
        row("extract_btrfs_send", NameOrigin::ArchiveSupplied, DRIVEN),
        row("extract_bun", NameOrigin::ArchiveSupplied, DRIVEN),
        row("extract_cab", NameOrigin::ArchiveSupplied, DRIVEN),
        row(
            "extract_dotnet_single_file",
            NameOrigin::ArchiveSupplied,
            DRIVEN,
        ),
        row(
            "extract_cab_lzms_folders",
            NameOrigin::ArchiveSupplied,
            DRIVEN,
        ),
        row(
            "carve_only_payload",
            NameOrigin::ToolGenerated,
            HostileCoverage::GuardOnly(
                "all three callers pass a literal: partclone.img, archive.sit, qnx-image.bin",
            ),
        ),
        row(
            "carve_partition_to_disk",
            NameOrigin::ToolGenerated,
            HostileCoverage::GuardOnly(
                "writes partitionNN.TT.img built from the partition index and type byte",
            ),
        ),
        row("extract_cpio", NameOrigin::ArchiveSupplied, DRIVEN),
        row("extract_cramfs", NameOrigin::ArchiveSupplied, DRIVEN),
        row(
            "decompress_wim_header_resources",
            NameOrigin::ToolGenerated,
            HostileCoverage::GuardOnly(
                "writes one of two fixed names, .disrobe-wim-offset-table.dec.bin or \
                 .disrobe-wim-boot-metadata.dec.bin, picked by which header resource is \
                 compressed; it decompresses header bytes and never reads an \
                 archive-supplied name",
            ),
        ),
        row("extract_dmg", NameOrigin::ArchiveSupplied, DRIVEN),
        row("extract_erofs", NameOrigin::ArchiveSupplied, DRIVEN),
        row("extract_ext4", NameOrigin::ArchiveSupplied, DRIVEN),
        row("extract_fat", NameOrigin::ArchiveSupplied, DRIVEN),
        row("extract_fat_into", NameOrigin::ArchiveSupplied, DRIVEN),
        row("extract_firmware", NameOrigin::ArchiveSupplied, DRIVEN),
        row(
            "extract_flatpak",
            NameOrigin::ArchiveSupplied,
            HostileCoverage::GuardOnly(
                "the wired ContainerKind::Flatpak arm calls only extract_flatpak_bundle, \
                 which returns files: Vec::new() by design (BUG-072); its sibling \
                 extract_flatpak_repo does recover real file content but has no caller \
                 anywhere in the tree, so no in-crate builder can currently place a \
                 hostile name into recovered file content until BUG-072 wires a real \
                 consumer",
            ),
        ),
        row("extract_installshield", NameOrigin::ArchiveSupplied, DRIVEN),
        row("extract_iso", NameOrigin::ArchiveSupplied, DRIVEN),
        row("extract_jffs2", NameOrigin::ArchiveSupplied, DRIVEN),
        row("extract_lzh", NameOrigin::ArchiveSupplied, DRIVEN),
        row("extract_lzop", NameOrigin::ArchiveSupplied, DRIVEN),
        row(
            "extract_minidump",
            NameOrigin::ArchiveSupplied,
            HostileCoverage::GuardOnly(
                "a real hostile-named module is driven through every HOSTILE_ENTRY_NAMES case in \
                 every_hostile_module_name_stays_contained_by_the_minidump_write_path, but the \
                 write path always succeeds through a synthesised module_N.bin fallback name \
                 rather than a binary refuse/contain verdict, so it does not fit the generic \
                 drive_write_path driver",
            ),
        ),
        row("extract_minixfs", NameOrigin::ArchiveSupplied, DRIVEN),
        row("extract_msi_cab", NameOrigin::ArchiveSupplied, DRIVEN),
        row("extract_nsis", NameOrigin::ArchiveSupplied, DRIVEN),
        row("extract_ntfs", NameOrigin::ArchiveSupplied, DRIVEN),
        row("extract_rar", NameOrigin::ArchiveSupplied, DRIVEN),
        row(
            "recurse_into_filesystem",
            NameOrigin::ToolGenerated,
            HostileCoverage::GuardOnly(
                "appends .d to the tool-generated partition name from carve_partition_to_disk",
            ),
        ),
        row("extract_romfs", NameOrigin::ArchiveSupplied, DRIVEN),
        row("extract_rpm", NameOrigin::ArchiveSupplied, DRIVEN),
        row("extract_sevenz", NameOrigin::ArchiveSupplied, DRIVEN),
        row("squashfs_walk_to_disk", NameOrigin::ArchiveSupplied, DRIVEN),
        row("extract_stuffit", NameOrigin::ArchiveSupplied, DRIVEN),
        row("extract_ubifs", NameOrigin::ArchiveSupplied, DRIVEN),
        row(
            "extract_uefi_firmware_volume",
            NameOrigin::ArchiveSupplied,
            DRIVEN,
        ),
        row("extract_unityfs", NameOrigin::ArchiveSupplied, DRIVEN),
        row("walk_tar", NameOrigin::ArchiveSupplied, DRIVEN),
        row(
            "extract_wim",
            NameOrigin::ToolGenerated,
            HostileCoverage::GuardOnly(
                "the wim dispatcher's own write site places one of four fixed names from \
                 carve_wim_resources (containers/wim.rs): .disrobe-wim-offset-table.bin, \
                 .disrobe-wim-xml.bin, .disrobe-wim-boot-metadata.bin, \
                 .disrobe-wim-integrity.bin; the archive-supplied image file names flow \
                 through the delegated extract_wim_image_files, which already carries its \
                 own driven row",
            ),
        ),
        row(
            "extract_wim_image_files",
            NameOrigin::ArchiveSupplied,
            DRIVEN,
        ),
        row("extract_xar", NameOrigin::ArchiveSupplied, DRIVEN),
        row("extract_yaffs2", NameOrigin::ArchiveSupplied, DRIVEN),
        row("extract_zip", NameOrigin::ArchiveSupplied, DRIVEN),
    ];

    const DRIVEN: HostileCoverage = HostileCoverage::DrivenEndToEnd;

    const fn row(
        function: &'static str,
        origin: NameOrigin,
        coverage: HostileCoverage,
    ) -> WritePathRow {
        WritePathRow {
            function,
            origin,
            coverage,
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct DrivenWritePath {
        function: &'static str,
        kind: ContainerKind,
        slip_tag: &'static str,
        minimum_exercised: usize,
        minimum_refused_as_a_slip: usize,
        build: fn(&str, &[u8]) -> Option<Vec<u8>>,
    }

    const HOSTILE_NAMES_MINUS_EMPTY: usize = crate::quota::HOSTILE_ENTRY_NAMES.len() - 1;

    const DRIVEN_WRITE_PATHS: &[DrivenWritePath] = &[
        DrivenWritePath {
            function: "extract_zip",
            kind: ContainerKind::Zip,
            slip_tag: "zip-slip",
            minimum_exercised: HOSTILE_NAMES_MINUS_EMPTY,
            minimum_refused_as_a_slip: 35,
            build: build_hostile_zip,
        },
        DrivenWritePath {
            function: "walk_tar",
            kind: ContainerKind::Tar,
            slip_tag: "tar-slip",
            minimum_exercised: HOSTILE_NAMES_MINUS_EMPTY,
            minimum_refused_as_a_slip: 34,
            build: build_hostile_tar,
        },
        DrivenWritePath {
            function: "extract_cpio",
            kind: ContainerKind::Cpio,
            slip_tag: "cpio-slip",
            minimum_exercised: HOSTILE_NAMES_MINUS_EMPTY,
            minimum_refused_as_a_slip: 34,
            build: build_hostile_cpio,
        },
        DrivenWritePath {
            function: "extract_asar",
            kind: ContainerKind::Asar,
            slip_tag: "asar-slip",
            minimum_exercised: HOSTILE_NAMES_MINUS_EMPTY,
            minimum_refused_as_a_slip: 35,
            build: build_hostile_asar,
        },
        DrivenWritePath {
            function: "extract_sevenz",
            kind: ContainerKind::SevenZ,
            slip_tag: "sevenz-slip",
            minimum_exercised: HOSTILE_NAMES_MINUS_EMPTY - 1,
            minimum_refused_as_a_slip: 34,
            build: build_hostile_sevenz,
        },
        DrivenWritePath {
            function: "extract_ar",
            kind: ContainerKind::Ar,
            slip_tag: "ar-slip",
            minimum_exercised: 20,
            minimum_refused_as_a_slip: 22,
            build: build_hostile_ar,
        },
        DrivenWritePath {
            function: "extract_arj",
            kind: ContainerKind::Arj,
            slip_tag: "arj-slip",
            minimum_exercised: 40,
            minimum_refused_as_a_slip: 34,
            build: build_hostile_arj,
        },
        DrivenWritePath {
            function: "extract_arc",
            kind: ContainerKind::Arc,
            slip_tag: "arc-slip",
            minimum_exercised: 29,
            minimum_refused_as_a_slip: 21,
            build: build_hostile_arc,
        },
        DrivenWritePath {
            function: "extract_lzop",
            kind: ContainerKind::Lzo,
            slip_tag: "lzop-slip",
            minimum_exercised: 40,
            minimum_refused_as_a_slip: 34,
            build: build_hostile_lzop,
        },
        DrivenWritePath {
            function: "extract_xar",
            kind: ContainerKind::Pkg,
            slip_tag: "xar-slip",
            minimum_exercised: 40,
            minimum_refused_as_a_slip: 32,
            build: build_hostile_xar,
        },
        DrivenWritePath {
            function: "extract_iso",
            kind: ContainerKind::Iso,
            slip_tag: "iso-slip",
            minimum_exercised: 40,
            minimum_refused_as_a_slip: 34,
            build: build_hostile_iso,
        },
        DrivenWritePath {
            function: "extract_cramfs",
            kind: ContainerKind::Cramfs,
            slip_tag: "cramfs-slip",
            minimum_exercised: 40,
            minimum_refused_as_a_slip: 33,
            build: build_hostile_cramfs,
        },
        DrivenWritePath {
            function: "extract_ext4",
            kind: ContainerKind::Ext4,
            slip_tag: "ext4-slip",
            minimum_exercised: 40,
            minimum_refused_as_a_slip: 33,
            build: build_hostile_ext4,
        },
        DrivenWritePath {
            function: "squashfs_walk_to_disk",
            kind: ContainerKind::Squashfs,
            slip_tag: "squashfs-slip",
            minimum_exercised: 40,
            minimum_refused_as_a_slip: 34,
            build: build_hostile_squashfs,
        },
        DrivenWritePath {
            function: "extract_stuffit",
            kind: ContainerKind::StuffIt,
            slip_tag: "stuffit-slip",
            minimum_exercised: 40,
            minimum_refused_as_a_slip: 34,
            build: build_hostile_stuffit,
        },
        DrivenWritePath {
            function: "extract_rar",
            kind: ContainerKind::Rar,
            slip_tag: "rar-slip",
            minimum_exercised: 40,
            minimum_refused_as_a_slip: 34,
            build: build_hostile_rar,
        },
        DrivenWritePath {
            function: "extract_nsis",
            kind: ContainerKind::Nsis,
            slip_tag: "nsis-slip",
            minimum_exercised: 40,
            minimum_refused_as_a_slip: 34,
            build: build_hostile_nsis,
        },
        DrivenWritePath {
            function: "extract_installshield",
            kind: ContainerKind::InstallShield,
            slip_tag: "installshield-slip",
            minimum_exercised: 40,
            minimum_refused_as_a_slip: 34,
            build: build_hostile_installshield,
        },
        DrivenWritePath {
            function: "extract_cab",
            kind: ContainerKind::Cab,
            slip_tag: "cab-slip",
            minimum_exercised: 40,
            minimum_refused_as_a_slip: 33,
            build: build_hostile_cab,
        },
        DrivenWritePath {
            function: "extract_cab_lzms_folders",
            kind: ContainerKind::Cab,
            slip_tag: "cab-slip",
            minimum_exercised: 40,
            minimum_refused_as_a_slip: 33,
            build: build_hostile_lzms_cab,
        },
        DrivenWritePath {
            function: "extract_msi_cab",
            kind: ContainerKind::Msi,
            slip_tag: "msi-slip",
            minimum_exercised: 30,
            minimum_refused_as_a_slip: 33,
            build: build_hostile_msi,
        },
        DrivenWritePath {
            function: "extract_unityfs",
            kind: ContainerKind::UnityFs,
            slip_tag: "unityfs-slip",
            minimum_exercised: 40,
            minimum_refused_as_a_slip: 34,
            build: build_hostile_unityfs,
        },
        DrivenWritePath {
            function: "extract_bun",
            kind: ContainerKind::BunStandalone,
            slip_tag: "bun-slip",
            minimum_exercised: 40,
            minimum_refused_as_a_slip: 34,
            build: build_hostile_bun,
        },
        DrivenWritePath {
            function: "extract_dotnet_single_file",
            kind: ContainerKind::DotnetSingleFile,
            slip_tag: "dotnet-bundle-slip",
            minimum_exercised: 40,
            minimum_refused_as_a_slip: 34,
            build: build_hostile_dotnet_single_file,
        },
        DrivenWritePath {
            function: "extract_bare_gzip",
            kind: ContainerKind::Gzip,
            slip_tag: "gzip-slip",
            minimum_exercised: 40,
            minimum_refused_as_a_slip: 34,
            build: build_hostile_gzip,
        },
        DrivenWritePath {
            function: "extract_lzh",
            kind: ContainerKind::Lzh,
            slip_tag: "lzh-slip",
            minimum_exercised: 40,
            minimum_refused_as_a_slip: 35,
            build: build_hostile_lzh,
        },
        DrivenWritePath {
            function: "extract_btrfs_send",
            kind: ContainerKind::BtrfsSend,
            slip_tag: "btrfs-send-slip",
            minimum_exercised: 49,
            minimum_refused_as_a_slip: 35,
            build: crate::containers::btrfs_send::hostile_named_image,
        },
        DrivenWritePath {
            function: "extract_erofs",
            kind: ContainerKind::Erofs,
            slip_tag: "erofs-slip",
            minimum_exercised: 48,
            minimum_refused_as_a_slip: 34,
            build: crate::containers::erofs::hostile_named_image,
        },
        DrivenWritePath {
            function: "extract_jffs2",
            kind: ContainerKind::Jffs2,
            slip_tag: "jffs2-slip",
            minimum_exercised: 49,
            minimum_refused_as_a_slip: 35,
            build: crate::containers::jffs2::hostile_named_image,
        },
        DrivenWritePath {
            function: "extract_minixfs",
            kind: ContainerKind::MinixFs,
            slip_tag: "minixfs-slip",
            minimum_exercised: 47,
            minimum_refused_as_a_slip: 33,
            build: crate::containers::minixfs::hostile_named_image,
        },
        DrivenWritePath {
            function: "extract_romfs",
            kind: ContainerKind::Romfs,
            slip_tag: "romfs-slip",
            minimum_exercised: 47,
            minimum_refused_as_a_slip: 33,
            build: crate::containers::romfs::hostile_named_image,
        },
        DrivenWritePath {
            function: "extract_ubifs",
            kind: ContainerKind::Ubifs,
            slip_tag: "ubifs-slip",
            minimum_exercised: 49,
            minimum_refused_as_a_slip: 35,
            build: crate::containers::ubifs::hostile_named_image,
        },
        DrivenWritePath {
            function: "extract_yaffs2",
            kind: ContainerKind::Yaffs2,
            slip_tag: "yaffs2-slip",
            minimum_exercised: 48,
            minimum_refused_as_a_slip: 34,
            build: crate::containers::yaffs::hostile_named_image,
        },
        DrivenWritePath {
            function: "extract_rpm",
            kind: ContainerKind::Rpm,
            slip_tag: "rpm-slip",
            minimum_exercised: 49,
            minimum_refused_as_a_slip: 35,
            build: hostile_named_rpm,
        },
        DrivenWritePath {
            function: "extract_wim_image_files",
            kind: ContainerKind::Wim,
            slip_tag: "wim-slip",
            minimum_exercised: 49,
            minimum_refused_as_a_slip: 35,
            build: crate::containers::wim_image::hostile_named_image,
        },
        DrivenWritePath {
            function: "extract_fat",
            kind: ContainerKind::Fat,
            slip_tag: "fat-slip",
            minimum_exercised: 47,
            minimum_refused_as_a_slip: 33,
            build: crate::containers::fat::hostile_named_image,
        },
        DrivenWritePath {
            function: "extract_fat_into",
            kind: ContainerKind::Mbr,
            slip_tag: "fat-slip",
            minimum_exercised: 47,
            minimum_refused_as_a_slip: 33,
            build: hostile_named_mbr_fat_partition,
        },
        DrivenWritePath {
            function: "extract_dmg",
            kind: ContainerKind::Dmg,
            slip_tag: "dmg-hfs-slip",
            minimum_exercised: 48,
            minimum_refused_as_a_slip: 34,
            build: crate::containers::dmg::hostile_named_image,
        },
        DrivenWritePath {
            function: "extract_uefi_firmware_volume",
            kind: ContainerKind::UefiFv,
            slip_tag: "uefi-fv-slip",
            minimum_exercised: 48,
            minimum_refused_as_a_slip: 0,
            build: crate::containers::uefi_fv::hostile_named_image,
        },
        DrivenWritePath {
            function: "extract_ntfs",
            kind: ContainerKind::Ntfs,
            slip_tag: "ntfs-slip",
            minimum_exercised: 49,
            minimum_refused_as_a_slip: 35,
            build: crate::containers::ntfs::hostile_named_image,
        },
        DrivenWritePath {
            function: "extract_firmware",
            kind: ContainerKind::FwHpIpkg,
            slip_tag: "firmware-slip",
            minimum_exercised: 13,
            minimum_refused_as_a_slip: 11,
            build: crate::containers::firmware::hostile_named_image,
        },
    ];

    fn representable_without_control_bytes(name: &str) -> bool {
        !name.chars().any(char::is_control)
    }

    #[expect(clippy::unnecessary_wraps)]
    fn build_hostile_zip(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        Some(synth_zip_raw_name(name, body))
    }

    #[expect(clippy::unnecessary_wraps)]
    fn build_hostile_tar(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        Some(synth_tar_with_raw_name(name.as_bytes(), body))
    }

    #[expect(clippy::unnecessary_wraps)]
    fn build_hostile_cpio(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        let mut bytes: Vec<u8> = newc_entry(name.as_bytes(), 0o100_644, body);
        bytes.extend_from_slice(&newc_entry(
            crate::containers::cpio::TRAILER_NAME.as_bytes(),
            0,
            &[],
        ));
        Some(bytes)
    }

    #[expect(clippy::unnecessary_wraps)]
    fn build_hostile_asar(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        Some(synth_asar_raw_name(name, body))
    }

    fn build_hostile_sevenz(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        let name_terminates_early_inside_the_sevenz_reader: bool = name.contains('\u{0}');
        if name_terminates_early_inside_the_sevenz_reader {
            return None;
        }
        Some(synth_sevenz(&[(name, body)]))
    }

    fn build_hostile_ar(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        synth_ar_raw_name(name, body)
    }

    fn build_hostile_arj(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        if name.contains('\u{0}') {
            return None;
        }
        Some(crate::containers::arj::synth_stored_arj(name, body))
    }

    fn build_hostile_arc(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        if name.contains('\u{0}') {
            return None;
        }
        crate::containers::arc::synth_stored_arc(name, body)
    }

    fn build_hostile_lzop(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        if name.contains('\u{0}') {
            return None;
        }
        crate::containers::lzop::build_stored_lzop(name, body)
    }

    fn build_hostile_xar(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        if !representable_without_control_bytes(name) || name.contains(['<', '>', '&']) {
            return None;
        }
        Some(crate::containers::xar::build_xar(&[(name, body)]))
    }

    fn build_hostile_iso(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        if name.len() > 200 || name.contains('\u{0}') {
            return None;
        }
        Some(crate::containers::iso::build_iso(name.as_bytes(), body))
    }

    fn build_hostile_cramfs(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        if name.contains('\u{0}') {
            return None;
        }
        let mut padded: String = name.to_owned();
        while !padded.len().is_multiple_of(4) {
            padded.push('\u{0}');
        }
        if padded.len() > 252 {
            return None;
        }
        Some(crate::containers::cramfs::build_real_cramfs(&padded, body))
    }

    fn build_hostile_ext4(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        if name.len() > 200 || name.contains('\u{0}') {
            return None;
        }
        Some(crate::containers::ext4::build_real_ext4(name, body))
    }

    fn build_hostile_squashfs(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        if name.len() > 200 || name.contains('\u{0}') {
            return None;
        }
        Some(crate::containers::squashfs::build_real_squashfs(name, body))
    }

    fn build_hostile_stuffit(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        if name.len() > 63 || name.contains('\u{0}') {
            return None;
        }
        Some(crate::containers::stuffit::build_archive(&[(name, body)]))
    }

    fn build_hostile_rar(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        if name.contains('\u{0}') {
            return None;
        }
        Some(crate::containers::rar::build_test_rar5_store(name, body))
    }

    fn build_hostile_nsis(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        if name.contains('\u{0}') {
            return None;
        }
        Some(crate::containers::nsis::build_test_nsis(name, body))
    }

    fn build_hostile_installshield(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        if name.len() > 200 || name.contains('\u{0}') {
            return None;
        }
        Some(crate::containers::installshield::build_test_installshield(
            name, body,
        ))
    }

    fn build_hostile_cab(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        if !representable_without_control_bytes(name) || name.len() > 200 {
            return None;
        }
        Some(synth_cab(&[(name, body)]))
    }

    fn build_hostile_lzms_cab(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        if !representable_without_control_bytes(name) || name.len() > 200 {
            return None;
        }
        Some(crate::containers::cab_lzms::build_lzms_cab(&[(name, body)]))
    }

    fn build_hostile_msi(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        if !representable_without_control_bytes(name) || name.len() > 200 || name.contains('|') {
            return None;
        }
        let cab_bytes: Vec<u8> = synth_cab(&[("payload.bin", body)]);
        Some(synth_msi_with_embedded_cab(&cab_bytes, "payload.bin", name))
    }

    fn build_hostile_unityfs(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        if name.contains('\u{0}') {
            return None;
        }
        Some(crate::containers::unityfs_build_bundle_uncompressed(
            name, body,
        ))
    }

    fn build_hostile_bun(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        if name.contains('\u{0}') {
            return None;
        }
        Some(crate::containers::bun::build_bun(&[(name, body)]))
    }

    fn build_hostile_dotnet_single_file(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        if name.is_empty() || name.len() > 64 * 1024 {
            return None;
        }
        Some(crate::containers::dotnet_bundle::build_dotnet_bundle(
            6,
            &[(
                name,
                crate::containers::BundleFileType::Assembly,
                body,
                false,
            )],
        ))
    }

    fn build_hostile_gzip(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        if name.contains('\u{0}') {
            return None;
        }
        let mut encoder: flate2::write::DeflateEncoder<Vec<u8>> =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(body).expect("deflate write");
        let compressed: Vec<u8> = encoder.finish().expect("deflate finish");
        let mut out: Vec<u8> = vec![0x1f, 0x8b, 0x08, 0x08, 0, 0, 0, 0, 0x00, 0xff];
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        out.extend_from_slice(&compressed);
        out.extend_from_slice(&crc32fast::hash(body).to_le_bytes());
        out.extend_from_slice(&u32::try_from(body.len()).ok()?.to_le_bytes());
        Some(out)
    }

    fn build_hostile_lzh(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        crate::containers::lzh::build_stored_lzh(name, body)
    }

    fn driven_write_path(function: &str) -> &'static DrivenWritePath {
        DRIVEN_WRITE_PATHS
            .iter()
            .find(|row: &&DrivenWritePath| row.function == function)
            .unwrap_or_else(|| panic!("{function} is not listed in DRIVEN_WRITE_PATHS"))
    }

    fn drive_write_path(function: &str) {
        let path: &DrivenWritePath = driven_write_path(function);
        let mut exercised: usize = 0;
        let mut refused_through_the_tag: usize = 0;
        let mut rpm_refused_before_write: usize = 0;
        let mut contained_writes: usize = 0;
        for (name, verdict) in crate::quota::HOSTILE_ENTRY_NAMES {
            if name.is_empty() {
                continue;
            }
            let Some(bytes): Option<Vec<u8>> = (path.build)(name, b"payload") else {
                continue;
            };
            let scratch: disrobe_core::scratch::ScratchDir = temp_dir(function);
            let out: PathBuf = scratch.path().to_path_buf();
            std::fs::create_dir_all(&out).expect("out dir");
            exercised += 1;
            let result: ExtractionResult = match extract_to(path.kind, &bytes, &out) {
                Ok(result) => result,
                Err(e) => {
                    assert_eq!(
                        *verdict,
                        crate::quota::HostileNameVerdict::Refused,
                        "{name:?} must stay extractable by {function}: {e}"
                    );
                    assert_no_escape_around(&out);
                    if function == "extract_rpm" {
                        match &e {
                            Error::UnsafeEntryPath(rejected_name) => {
                                assert_eq!(rejected_name, name, "RPM rejected the wrong path");
                            }
                            other => panic!(
                                "{name:?} reached an unrelated RPM refusal before writing: {other:?}"
                            ),
                        }
                        let mut output_entries: std::fs::ReadDir =
                            std::fs::read_dir(&out).expect("read RPM output directory");
                        assert!(
                            output_entries.next().is_none(),
                            "{name:?} wrote inside the RPM output directory before refusal"
                        );
                        rpm_refused_before_write += 1;
                    }
                    continue;
                }
            };
            assert_result_stays_inside(&result, &out);
            assert_no_escape_around(&out);
            let tagged: bool = result
                .integrity_violations
                .iter()
                .any(|v: &String| v.contains(path.slip_tag));
            match verdict {
                crate::quota::HostileNameVerdict::Refused => {
                    assert!(
                        result
                            .entries
                            .iter()
                            .all(|e: &ExtractedEntry| e.name != *name),
                        "{name:?} must never be written verbatim by {function}: {:?}",
                        result.entries
                    );
                    refused_through_the_tag += usize::from(tagged);
                    if function == "extract_rpm" {
                        rpm_refused_before_write += usize::from(tagged);
                    }
                }
                crate::quota::HostileNameVerdict::ContainedWrite => {
                    assert!(
                        !tagged,
                        "{name:?} must not be refused by {function}: {:?}",
                        result.integrity_violations
                    );
                    contained_writes += 1;
                }
            }
        }
        assert!(
            exercised >= path.minimum_exercised,
            "{function} exercised only {exercised} hostile names, expected at least {}",
            path.minimum_exercised
        );
        if function == "extract_rpm" {
            assert!(
                rpm_refused_before_write >= path.minimum_refused_as_a_slip,
                "{function} refused only {rpm_refused_before_write} hostile names before writing, expected at least {}",
                path.minimum_refused_as_a_slip
            );
        } else {
            assert!(
                refused_through_the_tag >= path.minimum_refused_as_a_slip,
                "{function} refused only {refused_through_the_tag} hostile names as {}, expected at least {}",
                path.slip_tag,
                path.minimum_refused_as_a_slip
            );
        }
        assert!(
            contained_writes > 0,
            "{function} wrote nothing at all, so the container builder never produced a real archive"
        );
    }

    #[test]
    fn hostile_names_reach_the_zip_write_path_guard() {
        drive_write_path("extract_zip");
    }

    #[test]
    fn hostile_names_reach_the_tar_write_path_guard() {
        drive_write_path("walk_tar");
    }

    #[test]
    fn hostile_names_reach_the_cpio_write_path_guard() {
        drive_write_path("extract_cpio");
    }

    #[test]
    fn hostile_names_reach_the_asar_write_path_guard() {
        drive_write_path("extract_asar");
    }

    #[test]
    fn hostile_names_reach_the_sevenz_write_path_guard() {
        drive_write_path("extract_sevenz");
    }

    #[test]
    fn hostile_names_reach_the_ar_write_path_guard() {
        drive_write_path("extract_ar");
    }

    #[test]
    fn hostile_names_reach_the_arj_write_path_guard() {
        drive_write_path("extract_arj");
    }

    #[test]
    fn hostile_names_reach_the_arc_write_path_guard() {
        drive_write_path("extract_arc");
    }

    #[test]
    fn hostile_names_reach_the_lzop_write_path_guard() {
        drive_write_path("extract_lzop");
    }

    #[test]
    fn hostile_names_reach_the_xar_write_path_guard() {
        drive_write_path("extract_xar");
    }

    #[test]
    fn hostile_names_reach_the_iso_write_path_guard() {
        drive_write_path("extract_iso");
    }

    #[test]
    fn hostile_names_reach_the_cramfs_write_path_guard() {
        drive_write_path("extract_cramfs");
    }

    #[test]
    fn hostile_names_reach_the_ext4_write_path_guard() {
        drive_write_path("extract_ext4");
    }

    #[test]
    fn hostile_names_reach_the_squashfs_write_path_guard() {
        drive_write_path("squashfs_walk_to_disk");
    }

    #[test]
    fn hostile_names_reach_the_stuffit_write_path_guard() {
        drive_write_path("extract_stuffit");
    }

    #[test]
    fn hostile_names_reach_the_rar_write_path_guard() {
        drive_write_path("extract_rar");
    }

    #[test]
    fn hostile_names_reach_the_nsis_write_path_guard() {
        drive_write_path("extract_nsis");
    }

    #[test]
    fn hostile_names_reach_the_installshield_write_path_guard() {
        drive_write_path("extract_installshield");
    }

    #[test]
    fn hostile_names_reach_the_cab_write_path_guard() {
        drive_write_path("extract_cab");
    }

    #[test]
    fn hostile_names_reach_the_lzms_cab_write_path_guard() {
        drive_write_path("extract_cab_lzms_folders");
    }

    #[test]
    fn hostile_names_reach_the_msi_write_path_guard() {
        drive_write_path("extract_msi_cab");
    }

    #[test]
    fn hostile_names_reach_the_unityfs_write_path_guard() {
        drive_write_path("extract_unityfs");
    }

    #[test]
    fn hostile_names_reach_the_bun_write_path_guard() {
        drive_write_path("extract_bun");
    }

    #[test]
    fn hostile_names_reach_the_dotnet_single_file_write_path_guard() {
        drive_write_path("extract_dotnet_single_file");
    }

    #[test]
    fn hostile_names_reach_the_gzip_write_path_guard() {
        drive_write_path("extract_bare_gzip");
    }

    #[test]
    fn hostile_names_reach_the_lzh_write_path_guard() {
        drive_write_path("extract_lzh");
    }

    #[test]
    fn hostile_names_reach_the_btrfs_send_write_path_guard() {
        drive_write_path("extract_btrfs_send");
    }

    #[test]
    fn hostile_names_reach_the_erofs_write_path_guard() {
        drive_write_path("extract_erofs");
    }

    #[test]
    fn hostile_names_reach_the_jffs2_write_path_guard() {
        drive_write_path("extract_jffs2");
    }

    #[test]
    fn hostile_names_reach_the_minixfs_write_path_guard() {
        drive_write_path("extract_minixfs");
    }

    #[test]
    fn hostile_names_reach_the_romfs_write_path_guard() {
        drive_write_path("extract_romfs");
    }

    #[test]
    fn hostile_names_reach_the_ubifs_write_path_guard() {
        drive_write_path("extract_ubifs");
    }

    #[test]
    fn hostile_names_reach_the_yaffs2_write_path_guard() {
        drive_write_path("extract_yaffs2");
    }

    #[test]
    fn hostile_names_reach_the_ntfs_write_path_guard() {
        drive_write_path("extract_ntfs");
    }

    #[test]
    fn hostile_names_reach_the_firmware_write_path_guard() {
        drive_write_path("extract_firmware");
    }

    fn guarded_write_path_functions(source: &str) -> Vec<String> {
        let mut enclosing: String = String::new();
        let mut found: Vec<String> = Vec::new();
        for line in source.lines() {
            if line.starts_with("#[cfg(test)]") {
                break;
            }
            if let Some(rest) = line
                .strip_prefix("fn ")
                .or_else(|| line.strip_prefix("pub fn "))
                .or_else(|| line.strip_prefix("pub(crate) fn "))
            {
                enclosing = rest
                    .split(['(', '<'])
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_owned();
            }
            if (line.contains("prepare_entry_path(") || line.contains("prepare_entry_dir("))
                && !found.contains(&enclosing)
            {
                found.push(enclosing.clone());
            }
        }
        found.sort_unstable();
        found
    }

    #[test]
    fn the_write_path_roster_names_every_guarded_site_in_the_source() {
        let source: &str = include_str!("extract.rs");
        let found: Vec<String> = guarded_write_path_functions(source);
        let mut rostered: Vec<String> = WRITE_PATH_ROSTER
            .iter()
            .map(|r: &WritePathRow| r.function.to_owned())
            .collect();
        rostered.sort_unstable();
        assert_eq!(
            found, rostered,
            "the write-path roster drifted from the guarded sites in extract.rs"
        );
        assert!(
            found.len() >= 45,
            "only {} guarded write paths were found, the scan is not seeing the source",
            found.len()
        );
    }

    #[test]
    fn every_driven_roster_row_owns_a_driver_and_a_test() {
        let source: &str = include_str!("extract.rs");
        let mut driven: Vec<&str> = WRITE_PATH_ROSTER
            .iter()
            .filter(|r: &&WritePathRow| r.coverage == HostileCoverage::DrivenEndToEnd)
            .map(|r: &WritePathRow| r.function)
            .collect();
        driven.sort_unstable();
        let mut tabled: Vec<&str> = DRIVEN_WRITE_PATHS
            .iter()
            .map(|r: &DrivenWritePath| r.function)
            .collect();
        tabled.sort_unstable();
        assert_eq!(
            driven, tabled,
            "every roster row marked driven must appear in DRIVEN_WRITE_PATHS and no other"
        );
        for function in &driven {
            let call: String = format!("drive_write_path(\"{function}\")");
            assert!(
                source.contains(&call),
                "{function} is marked driven but no test calls {call}"
            );
        }
        assert!(
            driven.len() >= 25,
            "end-to-end coverage dropped to {} write paths",
            driven.len()
        );
    }

    #[test]
    fn no_write_path_ever_materialises_a_link_entry() {
        let source: &str = include_str!("extract.rs");
        let lines: Vec<&str> = source.lines().collect();
        let mut guards: usize = 0;
        for (index, line) in lines.iter().enumerate() {
            if line.starts_with("#[cfg(test)]") {
                break;
            }
            let trimmed: &str = line.trim();
            if trimmed != "if file.is_symlink {" && trimmed != "if file.symlink_target.is_some() {"
            {
                continue;
            }
            guards += 1;
            let body: &str = lines.get(index + 1).map_or("", |l: &&str| l.trim());
            assert_eq!(
                body,
                "continue;",
                "the link branch at line {} writes instead of skipping",
                index + 1
            );
        }
        assert!(
            guards >= 11,
            "only {guards} link guards were found, the scan is not seeing the source"
        );
    }

    #[test]
    fn every_tool_generated_write_path_records_why_it_is_not_a_slip_path() {
        for entry in WRITE_PATH_ROSTER {
            if entry.origin == NameOrigin::ToolGenerated {
                let HostileCoverage::GuardOnly(reason) = entry.coverage else {
                    panic!(
                        "{} writes a tool-generated name, so it cannot be driven with archive-supplied names",
                        entry.function
                    );
                };
                assert!(
                    reason.len() > 20,
                    "{} needs a real reason, not `{reason}`",
                    entry.function
                );
            }
        }
    }

    fn synth_ar_raw_name(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        if name.len() > 16 || name.contains(' ') || name.ends_with('/') {
            return None;
        }
        let mut out: Vec<u8> = Vec::with_capacity(8 + 60 + body.len() + 1);
        out.extend_from_slice(b"!<arch>\n");
        let mut header: [u8; 60] = [b' '; 60];
        header[..name.len()].copy_from_slice(name.as_bytes());
        let size_text: String = body.len().to_string();
        header[48..48 + size_text.len()].copy_from_slice(size_text.as_bytes());
        header[58] = 0x60;
        header[59] = b'\n';
        out.extend_from_slice(&header);
        out.extend_from_slice(body);
        if !body.len().is_multiple_of(2) {
            out.push(b'\n');
        }
        Some(out)
    }

    fn synth_asar_raw_name(name: &str, body: &[u8]) -> Vec<u8> {
        let mut file: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        file.insert("size".to_owned(), serde_json::json!(body.len()));
        file.insert("offset".to_owned(), serde_json::json!("0"));
        let mut files: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        files.insert(name.to_owned(), serde_json::Value::Object(file));
        let mut root: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        root.insert("files".to_owned(), serde_json::Value::Object(files));
        let header: String =
            serde_json::to_string(&serde_json::Value::Object(root)).expect("asar header json");
        asar_container(&header, body)
    }

    fn asar_container(header: &str, body: &[u8]) -> Vec<u8> {
        let header_bytes: &[u8] = header.as_bytes();
        let header_size: u32 = u32::try_from(header_bytes.len()).expect("hdr size");
        let aligned: u32 = header_size.next_multiple_of(4);
        let string_pickle_size: u32 = aligned + 4;
        let header_pickle_size: u32 = string_pickle_size + 4;
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]);
        out.extend_from_slice(&header_pickle_size.to_le_bytes());
        out.extend_from_slice(&string_pickle_size.to_le_bytes());
        out.extend_from_slice(&header_size.to_le_bytes());
        out.extend_from_slice(header_bytes);
        out.extend(std::iter::repeat_n(0u8, (aligned - header_size) as usize));
        out.extend_from_slice(body);
        out
    }

    fn synth_zip_raw_name(name: &str, body: &[u8]) -> Vec<u8> {
        let name_bytes: &[u8] = name.as_bytes();
        let mut local: Vec<u8> = Vec::new();
        local.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        local.extend_from_slice(&20u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&0u32.to_le_bytes());
        let crc: u32 = crc32fast::hash(body);
        local.extend_from_slice(&crc.to_le_bytes());
        local.extend_from_slice(&(body.len() as u32).to_le_bytes());
        local.extend_from_slice(&(body.len() as u32).to_le_bytes());
        local.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(name_bytes);
        local.extend_from_slice(body);

        let mut central: Vec<u8> = Vec::new();
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(body.len() as u32).to_le_bytes());
        central.extend_from_slice(&(body.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(name_bytes);

        let mut out: Vec<u8> = Vec::with_capacity(local.len() + central.len() + 22);
        out.extend_from_slice(&local);
        let central_offset: u32 = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&central_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn tar_overlong_utf8_traversal_stays_inside_the_root() {
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("tar-overlong-utf8");
        let out: PathBuf = scratch.path().to_path_buf();
        let raw_name: [u8; 15] = [
            0xC0, 0xAE, 0xC0, 0xAE, 0x2F, b'e', b's', b'c', b'a', b'p', b'e', b'.', b't', b'x',
            b't',
        ];
        let bytes: Vec<u8> = synth_tar_with_raw_name(&raw_name, b"payload");
        match extract_to(ContainerKind::Tar, &bytes, &out) {
            Ok(result) => {
                assert!(
                    result
                        .entries
                        .iter()
                        .all(|e: &ExtractedEntry| !e.name.contains("escape")),
                    "an overlong-UTF-8 traversal must not be decoded back into one: {:?}",
                    result.entries
                );
                assert_result_stays_inside(&result, &out);
            }
            Err(e) => assert!(
                matches!(e, Error::Tar(_) | Error::UnsafeEntryPath(_)),
                "unexpected failure on a non-Unicode entry name: {e:?}"
            ),
        }
        assert_no_escape_around(&out);
    }

    #[test]
    fn tar_symlink_entry_is_skipped_and_a_later_write_through_it_stays_inside() {
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("tar-symlink-escape");
        let out: PathBuf = scratch.path().to_path_buf();
        let mut bytes: Vec<u8> = synth_tar_link_entry(b"link", b"../..", b'2');
        bytes.truncate(512);
        bytes.extend_from_slice(&synth_tar_link_entry(b"hard", b"../../hardlink", b'1')[..512]);
        bytes.extend_from_slice(&synth_tar_with_raw_name(b"link/escape.txt", b"payload"));
        let result: ExtractionResult =
            extract_to(ContainerKind::Tar, &bytes, &out).expect("extract tar");
        assert!(
            result
                .entries
                .iter()
                .all(|e: &ExtractedEntry| e.name != "link" && e.name != "hard"),
            "link entries must never be materialised: {:?}",
            result.entries
        );
        assert_result_stays_inside(&result, &out);
        assert_no_escape_around(&out);
        assert_eq!(
            std::fs::read(out.join("link").join("escape.txt")).expect("contained write"),
            b"payload"
        );
    }

    fn synth_tar_link_entry(name: &[u8], target: &[u8], type_flag: u8) -> Vec<u8> {
        let mut header: [u8; 512] = [0u8; 512];
        header[..name.len().min(100)].copy_from_slice(&name[..name.len().min(100)]);
        header[100..108].copy_from_slice(b"0000777\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        header[124..136].copy_from_slice(b"00000000000\0");
        header[136..148].copy_from_slice(b"00000000000\0");
        header[148..156].copy_from_slice(b"        ");
        header[156] = type_flag;
        header[157..157 + target.len().min(100)].copy_from_slice(&target[..target.len().min(100)]);
        header[257..262].copy_from_slice(b"ustar");
        header[263..265].copy_from_slice(b"00");
        let sum: u32 = header.iter().map(|&b: &u8| u32::from(b)).sum();
        let chk: String = format!("{sum:06o}\0 ");
        header[148..156].copy_from_slice(chk.as_bytes());
        let mut out: Vec<u8> = Vec::with_capacity(512 + 1024);
        out.extend_from_slice(&header);
        out.extend(std::iter::repeat_n(0u8, 1024));
        out
    }

    #[test]
    fn cpio_link_entries_are_never_materialised_and_a_write_through_one_stays_inside() {
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("cpio-symlink-escape");
        let out: PathBuf = scratch.path().to_path_buf();
        let mut bytes: Vec<u8> = newc_entry(b"link", 0o120_777, b"../..");
        bytes.extend_from_slice(&newc_entry(b"link/escape.txt", 0o100_644, b"payload"));
        bytes.extend_from_slice(&newc_entry(
            crate::containers::cpio::TRAILER_NAME.as_bytes(),
            0,
            &[],
        ));
        let result: ExtractionResult =
            extract_to(ContainerKind::Cpio, &bytes, &out).expect("extract cpio");
        assert!(
            result
                .entries
                .iter()
                .all(|e: &ExtractedEntry| e.name != "link"),
            "a cpio symlink entry must never be materialised: {:?}",
            result.entries
        );
        assert_result_stays_inside(&result, &out);
        assert_no_escape_around(&out);
        assert_eq!(
            std::fs::read(out.join("link").join("escape.txt")).expect("contained write"),
            b"payload"
        );
    }

    #[test]
    fn zip_names_colliding_only_by_case_stay_under_the_root() {
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("zip-case-collision");
        let out: PathBuf = scratch.path().to_path_buf();
        let bytes: Vec<u8> = synth_zip(&[("Data.TXT", b"upper"), ("data.txt", b"lower")]);
        let result: ExtractionResult =
            extract_to(ContainerKind::Zip, &bytes, &out).expect("extract zip");
        assert_eq!(result.entries.len(), 2);
        assert_result_stays_inside(&result, &out);
        assert_no_escape_around(&out);
        let bodies: Vec<Vec<u8>> = result
            .entries
            .iter()
            .filter_map(|e: &ExtractedEntry| e.disk_path.as_ref())
            .map(|p: &PathBuf| std::fs::read(p).expect("written body"))
            .collect();
        assert!(
            bodies
                .iter()
                .all(|b: &Vec<u8>| b == b"upper" || b == b"lower"),
            "a case collision must resolve to one of the two written bodies"
        );
    }

    #[test]
    fn a_zip_entry_colliding_with_an_earlier_directory_never_escapes_the_root() {
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("zip-dir-collision");
        let out: PathBuf = scratch.path().to_path_buf();
        let bytes: Vec<u8> = synth_zip(&[("dir/inner.txt", b"inner"), ("dir", b"clobber")]);
        match extract_to(ContainerKind::Zip, &bytes, &out) {
            Ok(result) => assert_result_stays_inside(&result, &out),
            Err(e) => assert!(
                matches!(e, Error::Io(_)),
                "a name colliding with a directory must fail as io, got {e:?}"
            ),
        }
        assert_no_escape_around(&out);
        assert_eq!(
            std::fs::read(out.join("dir").join("inner.txt")).expect("first write survives"),
            b"inner"
        );
    }

    #[test]
    fn every_archive_named_write_routes_through_the_entry_path_guard() {
        let source: &str = include_str!("extract.rs");
        let mut unguarded: Vec<(usize, String)> = Vec::new();
        let mut in_tests: bool = false;
        for (index, line) in source.lines().enumerate() {
            if line.starts_with("mod tests {") || line.starts_with("#[cfg(test)]") {
                in_tests = true;
            }
            if in_tests {
                continue;
            }
            let Some(rest) = line.split_once("out_dir.join(") else {
                continue;
            };
            let argument: &str = rest.1.split(')').next().unwrap_or(rest.1);
            let tool_named: bool = argument.starts_with('"')
                || argument.starts_with("&tool_")
                || argument == "tool_filename";
            if !tool_named {
                unguarded.push((index + 1, line.trim().to_owned()));
            }
        }
        assert!(
            unguarded.is_empty(),
            "every archive-supplied name must go through prepare_entry_path, found {unguarded:?}"
        );
        assert!(
            source.matches("prepare_entry_path(").count() >= 45,
            "the guarded write sites disappeared"
        );
        let hand_rolled_parent: String = ["std::fs::create_dir_all(", "parent)"].concat();
        assert!(
            !source.contains(&hand_rolled_parent),
            "a write path still builds its own parent directory outside the guard"
        );
    }

    #[test]
    fn extract_asar_writes_entries() {
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("asar-ok");
        let out: PathBuf = scratch.path().to_path_buf();
        let bytes: Vec<u8> = synth_asar(&[("a.txt", b"alpha"), ("b.txt", b"bravo")]);
        let r: ExtractionResult = extract_to(ContainerKind::Asar, &bytes, &out).expect("extract");
        assert_eq!(r.entries.len(), 2);
        assert_eq!(std::fs::read(out.join("a.txt")).expect("a"), b"alpha");
        assert_eq!(std::fs::read(out.join("b.txt")).expect("b"), b"bravo");
    }

    #[test]
    fn unsupported_container_returns_error_for_none_kind() {
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("unsupp");
        let out: PathBuf = scratch.path().to_path_buf();
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
            let scratch: disrobe_core::scratch::ScratchDir = temp_dir("rar");
            let out: PathBuf = scratch.path().to_path_buf();
            let err: Error = extract_to(ContainerKind::Rar, &[0u8; 16], &out).unwrap_err();
            assert!(matches!(err, Error::RarNotExtractable));
        });
    }

    #[test]
    fn rar_extracts_stored_entries_in_tree() {
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("rar-store");
        let out: PathBuf = scratch.path().to_path_buf();
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
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("pkg-bad");
        let out: PathBuf = scratch.path().to_path_buf();
        let err: Error = extract_to(ContainerKind::Pkg, &[0u8; 16], &out).unwrap_err();
        assert!(matches!(err, Error::Decompression(_)));
    }

    #[test]
    fn dmg_extraction_errors_on_invalid_image() {
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("dmg-bad");
        let out: PathBuf = scratch.path().to_path_buf();
        let err: Error = extract_to(ContainerKind::Dmg, &[0u8; 16], &out).unwrap_err();
        assert!(matches!(err, Error::Decompression(_)));
    }

    #[test]
    fn iso_extraction_errors_on_invalid_image() {
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("iso-bad");
        let out: PathBuf = scratch.path().to_path_buf();
        let err: Error = extract_to(ContainerKind::Iso, &[0u8; 16], &out).unwrap_err();
        assert!(matches!(err, Error::Decompression(_)));
    }

    #[test]
    fn jar_routed_through_zip_path() {
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("jar-ok");
        let out: PathBuf = scratch.path().to_path_buf();
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
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("deb-ok");
        let out: PathBuf = scratch.path().to_path_buf();
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
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("msi-ok");
        let out: PathBuf = scratch.path().to_path_buf();
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
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("squirrel-ok");
        let out: PathBuf = scratch.path().to_path_buf();
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
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("squirrel-updater");
        let out: PathBuf = scratch.path().to_path_buf();
        let mut stub: Vec<u8> = b"MZ".to_vec();
        stub.extend_from_slice(b" SquirrelAwareVersion NuGet ");
        stub.extend(std::iter::repeat_n(0u8, 4096));
        let err: Error = extract_to(ContainerKind::Squirrel, &stub, &out).unwrap_err();
        assert!(matches!(err, Error::Squirrel(_)));
        assert!(out.join(".disrobe-squirrel-layout.json").is_file());
    }

    #[test]
    fn extract_nsis_writes_real_file_and_strips_var_prefix() {
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("nsis-ok");
        let out: PathBuf = scratch.path().to_path_buf();
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

    fn append_rpm_header(
        output: &mut Vec<u8>,
        entries: &[(u32, u32, i32, u32)],
        store: &[u8],
    ) -> Option<()> {
        output.extend_from_slice(&[0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0]);
        output.extend_from_slice(&u32::try_from(entries.len()).ok()?.to_be_bytes());
        output.extend_from_slice(&u32::try_from(store.len()).ok()?.to_be_bytes());
        for (tag, kind, offset, count) in entries {
            output.extend_from_slice(&tag.to_be_bytes());
            output.extend_from_slice(&kind.to_be_bytes());
            output.extend_from_slice(&offset.to_be_bytes());
            output.extend_from_slice(&count.to_be_bytes());
        }
        output.extend_from_slice(store);
        Some(())
    }

    fn hostile_named_rpm(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        use sha2::Digest as _;

        let mut cpio: Vec<u8> = newc_entry(name.as_bytes(), 0o100_644, body);
        cpio.extend_from_slice(&newc_entry(
            crate::containers::cpio::TRAILER_NAME.as_bytes(),
            0,
            &[],
        ));
        let digest: String = format!("{:x}", sha2::Sha256::digest(&cpio));
        let mut signature_store: Vec<u8> = Vec::new();
        signature_store.extend_from_slice(&62u32.to_be_bytes());
        signature_store.extend_from_slice(&7u32.to_be_bytes());
        signature_store.extend_from_slice(&(-16i32).to_be_bytes());
        signature_store.extend_from_slice(&16u32.to_be_bytes());
        let signature_entries: [(u32, u32, i32, u32); 1] = [(62, 7, 0, 16)];

        let mut main_store: Vec<u8> = Vec::new();
        main_store.extend_from_slice(&63u32.to_be_bytes());
        main_store.extend_from_slice(&7u32.to_be_bytes());
        main_store.extend_from_slice(&(-80i32).to_be_bytes());
        main_store.extend_from_slice(&16u32.to_be_bytes());
        main_store.extend_from_slice(b"cpio\0none\0");
        main_store.extend_from_slice(digest.as_bytes());
        main_store.push(0);
        main_store.extend_from_slice(digest.as_bytes());
        main_store.push(0);
        let main_entries: [(u32, u32, i32, u32); 5] = [
            (63, 7, 0, 16),
            (1124, 6, 16, 1),
            (1125, 6, 21, 1),
            (5092, 6, 26, 1),
            (5097, 6, 91, 1),
        ];

        let mut output: Vec<u8> = vec![0u8; 96];
        output[..4].copy_from_slice(&[0xed, 0xab, 0xee, 0xdb]);
        output[4] = 4;
        output[78..80].copy_from_slice(&5u16.to_be_bytes());
        append_rpm_header(&mut output, &signature_entries, &signature_store)?;
        append_rpm_header(&mut output, &main_entries, &main_store)?;
        output.extend_from_slice(&cpio);
        Some(output)
    }

    #[test]
    fn hostile_names_reach_the_rpm_write_path_guard() {
        drive_write_path("extract_rpm");
    }

    #[test]
    fn hostile_names_reach_the_wim_image_files_write_path_guard() {
        drive_write_path("extract_wim_image_files");
    }

    #[test]
    fn hostile_names_reach_the_fat_write_path_guard() {
        drive_write_path("extract_fat");
    }

    fn hostile_named_mbr_fat_partition(name: &str, body: &[u8]) -> Option<Vec<u8>> {
        let fat_image: Vec<u8> = crate::containers::fat::hostile_named_image(name, body)?;
        let mut disk: Vec<u8> =
            vec![0u8; crate::containers::partition::SECTOR_SIZE + fat_image.len()];
        disk[crate::containers::partition::MBR_SIGNATURE_OFFSET
            ..crate::containers::partition::MBR_SIGNATURE_OFFSET + 2]
            .copy_from_slice(crate::containers::partition::MBR_SIGNATURE);
        let entry_off: usize = crate::containers::partition::MBR_PARTITION_TABLE_OFFSET;
        disk[entry_off] = 0x00;
        disk[entry_off + 4] = 0x83;
        disk[entry_off + 8..entry_off + 12].copy_from_slice(&1u32.to_le_bytes());
        let sector_count: u32 =
            (fat_image.len() / crate::containers::partition::SECTOR_SIZE) as u32;
        disk[entry_off + 12..entry_off + 16].copy_from_slice(&sector_count.to_le_bytes());
        disk[crate::containers::partition::SECTOR_SIZE..].copy_from_slice(&fat_image);
        Some(disk)
    }

    #[test]
    fn hostile_names_reach_the_fat_into_write_path_guard() {
        drive_write_path("extract_fat_into");
    }

    #[test]
    fn hostile_names_reach_the_dmg_write_path_guard() {
        drive_write_path("extract_dmg");
    }

    const MINIDUMP_FALLBACK_NAMES: [&str; 15] = [
        "..",
        "evil\u{0}.txt",
        "evil\u{1b}.txt",
        "...",
        "evil.",
        "CON",
        "con",
        "con.txt",
        "PRN.log",
        "AUX",
        "NUL.dat",
        "COM1",
        "com9.txt",
        "LPT1",
        "lpt9.dat",
    ];

    #[test]
    fn every_hostile_module_name_stays_contained_by_the_minidump_write_path() {
        for (name, verdict) in crate::quota::HOSTILE_ENTRY_NAMES {
            if name.is_empty() {
                continue;
            }
            let scratch: disrobe_core::scratch::ScratchDir = temp_dir("minidump-hostile");
            let out: PathBuf = scratch.path().to_path_buf();
            std::fs::create_dir_all(&out).expect("out dir");
            let bytes: Vec<u8> = crate::containers::minidump::hostile_named_dump(name);
            let result: ExtractionResult = extract_to(ContainerKind::Minidump, &bytes, &out)
                .unwrap_or_else(|e: Error| {
                    panic!("{name:?} must always extract through the fallback name: {e}")
                });
            assert_result_stays_inside(&result, &out);
            assert_no_escape_around(&out);
            if *verdict == crate::quota::HostileNameVerdict::Refused {
                assert!(
                    result
                        .entries
                        .iter()
                        .all(|e: &ExtractedEntry| e.name != *name),
                    "{name:?} must never be written verbatim by the minidump write path: {:?}",
                    result.entries
                );
            }
            if MINIDUMP_FALLBACK_NAMES.contains(name) {
                let module_entry: &ExtractedEntry = result
                    .entries
                    .iter()
                    .find(|e: &&ExtractedEntry| e.name != ".disrobe-minidump.json")
                    .unwrap_or_else(|| {
                        panic!(
                            "{name:?} must still carve the one module: {:?}",
                            result.entries
                        )
                    });
                assert!(
                    module_entry.name.starts_with("module_")
                        && Path::new(&module_entry.name)
                            .extension()
                            .is_some_and(|ext: &std::ffi::OsStr| ext.eq_ignore_ascii_case("bin")),
                    "{name:?} must fall back to the synthesised module name, got {}",
                    module_entry.name
                );
            }
        }
    }

    #[test]
    fn hostile_names_reach_the_uefi_fv_write_path_guard() {
        drive_write_path("extract_uefi_firmware_volume");
    }

    #[test]
    fn non_utf8_cpio_name_does_not_drop_the_whole_payload() {
        let mut cpio: Vec<u8> = Vec::new();
        cpio.extend_from_slice(&newc_entry(&[b'a', 0xff, b'b'], 0o100_644, b"first"));
        cpio.extend_from_slice(&newc_entry(b"clean.txt", 0o100_644, b"second"));
        cpio.extend_from_slice(&newc_entry(
            crate::containers::cpio::TRAILER_NAME.as_bytes(),
            0,
            &[],
        ));

        let archive: crate::containers::CpioArchive =
            crate::containers::parse_cpio(&cpio).expect("parse CPIO");
        let first: &crate::containers::CpioEntry = &archive.entries[0];
        assert!(first.name.contains('\u{fffd}'));
        let first_end: usize = first.data_offset + first.file_size as usize;
        assert_eq!(&cpio[first.data_offset..first_end], b"first");

        let second: &crate::containers::CpioEntry = &archive.entries[1];
        assert_eq!(second.name, "clean.txt");
        let second_end: usize = second.data_offset + second.file_size as usize;
        assert_eq!(&cpio[second.data_offset..second_end], b"second");
    }
}
