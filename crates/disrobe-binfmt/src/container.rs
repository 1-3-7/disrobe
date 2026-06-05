use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContainerKind {
    Zip,
    Tar,
    TarGz,
    TarBz2,
    TarXz,
    TarZst,
    SevenZ,
    Rar,
    Cab,
    Iso,
    Asar,
    Pkg,
    Dmg,
    Deb,
    Rpm,
    Jar,
    War,
    Apk,
    Xpi,
    Whl,
    Egg,
    Crx,
    Nupkg,
    Vsix,
    Pyz,
    AppImage,
    Snap,
    Flatpak,
    Msix,
    Msi,
    Nsis,
    InnoSetup,
    InstallShield,
    Oci,
    DockerImage,
    Squashfs,
    Cramfs,
    Ext4,
    Cpio,
    Vhd,
    Vhdx,
    Wim,
    Gpt,
    Mbr,
    Xz,
    None,
}

impl ContainerKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::Tar => "tar",
            Self::TarGz => "tar.gz",
            Self::TarBz2 => "tar.bz2",
            Self::TarXz => "tar.xz",
            Self::TarZst => "tar.zst",
            Self::SevenZ => "7z",
            Self::Rar => "rar",
            Self::Cab => "cab",
            Self::Iso => "iso",
            Self::Asar => "asar",
            Self::Pkg => "pkg",
            Self::Dmg => "dmg",
            Self::Deb => "deb",
            Self::Rpm => "rpm",
            Self::Jar => "jar",
            Self::War => "war",
            Self::Apk => "apk",
            Self::Xpi => "xpi",
            Self::Whl => "whl",
            Self::Egg => "egg",
            Self::Crx => "crx",
            Self::Nupkg => "nupkg",
            Self::Vsix => "vsix",
            Self::Pyz => "pyz",
            Self::AppImage => "appimage",
            Self::Snap => "snap",
            Self::Flatpak => "flatpak",
            Self::Msix => "msix",
            Self::Msi => "msi",
            Self::Nsis => "nsis",
            Self::InnoSetup => "innosetup",
            Self::InstallShield => "installshield",
            Self::Oci => "oci",
            Self::DockerImage => "docker-image",
            Self::Squashfs => "squashfs",
            Self::Cramfs => "cramfs",
            Self::Ext4 => "ext4",
            Self::Cpio => "cpio",
            Self::Vhd => "vhd",
            Self::Vhdx => "vhdx",
            Self::Wim => "wim",
            Self::Gpt => "gpt",
            Self::Mbr => "mbr",
            Self::Xz => "xz",
            Self::None => "none",
        }
    }

    #[must_use]
    pub const fn is_zip_family(self) -> bool {
        matches!(
            self,
            Self::Zip
                | Self::Jar
                | Self::War
                | Self::Apk
                | Self::Xpi
                | Self::Whl
                | Self::Egg
                | Self::Crx
                | Self::Nupkg
                | Self::Vsix
                | Self::Pyz
        )
    }
}

const ZIP_LOCAL_HEADER: &[u8; 4] = b"PK\x03\x04";
const ZIP_EMPTY_EOCD: &[u8; 4] = b"PK\x05\x06";
const ZIP_SPANNED: &[u8; 4] = b"PK\x07\x08";
const SEVENZ_MAGIC: &[u8; 6] = &[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];
const RAR4_MAGIC: &[u8; 7] = &[0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00];
const RAR5_MAGIC: &[u8; 8] = &[0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00];
const CAB_MAGIC: &[u8; 4] = b"MSCF";
const RPM_MAGIC: &[u8; 4] = &[0xed, 0xab, 0xee, 0xdb];
const DEB_MAGIC: &[u8; 8] = b"!<arch>\n";
const DEB_MEMBER: &[u8; 14] = b"debian-binary ";
const GZIP_MAGIC: &[u8; 2] = &[0x1f, 0x8b];
const BZIP2_MAGIC: &[u8; 3] = b"BZh";
const XZ_MAGIC: &[u8; 6] = &[0xfd, b'7', b'z', b'X', b'Z', 0x00];
const ZSTD_MAGIC: &[u8; 4] = &[0x28, 0xb5, 0x2f, 0xfd];
const DMG_TRAILER_MAGIC: &[u8; 4] = b"koly";
const ASAR_HEADER_PREFIX: &[u8; 4] = &[0x04, 0x00, 0x00, 0x00];
const PKG_XAR_MAGIC: &[u8; 4] = b"xar!";
const TAR_USTAR_OFFSET: usize = 257;
const TAR_USTAR: &[u8; 5] = b"ustar";
const ISO_PRIMARY_OFFSET: usize = 32_768 + 1;
const ISO_PRIMARY_TAG: &[u8; 5] = b"CD001";
const CPIO_NEWC_MAGIC: &[u8; 6] = b"070701";
const CPIO_CRC_MAGIC: &[u8; 6] = b"070702";
const CPIO_ODC_MAGIC: &[u8; 6] = b"070707";
const CPIO_BIN_MAGIC_LE: &[u8; 2] = &[0xc7, 0x71];
const CPIO_BIN_MAGIC_BE: &[u8; 2] = &[0x71, 0xc7];
const WIM_MAGIC: &[u8; 8] = b"MSWIM\x00\x00\x00";
const VHDX_MAGIC: &[u8; 8] = b"vhdxfile";
const VHD_COOKIE: &[u8; 8] = b"conectix";
const VHD_FOOTER_LEN: usize = 512;
const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
const GPT_HEADER_OFFSET: usize = 512;
const MBR_SIGNATURE_OFFSET: usize = 510;
const MBR_PARTITION_TABLE_OFFSET: usize = 446;
const MBR_SIGNATURE: &[u8; 2] = &[0x55, 0xaa];

#[must_use]
pub fn detect_container(bytes: &[u8]) -> Option<ContainerKind> {
    detect_container_with_hint(bytes, None)
}

#[must_use]
pub fn detect_container_with_hint(bytes: &[u8], path: Option<&Path>) -> Option<ContainerKind> {
    if let Some(kind) = detect_by_magic(bytes) {
        if let Some(extension_hint) = path.and_then(extension_subkind)
            && let Some(refined) = refine_with_extension(kind, extension_hint)
        {
            return Some(refined);
        }
        return Some(kind);
    }
    if let Some(kind) = detect_by_tail(bytes) {
        if let Some(extension_hint) = path.and_then(extension_subkind)
            && let Some(refined) = refine_with_extension(kind, extension_hint)
        {
            return Some(refined);
        }
        return Some(kind);
    }
    path.and_then(extension_subkind).map(subkind_default_kind)
}

const fn subkind_default_kind(s: ExtensionSubkind) -> ContainerKind {
    match s {
        ExtensionSubkind::Jar => ContainerKind::Jar,
        ExtensionSubkind::War => ContainerKind::War,
        ExtensionSubkind::Apk => ContainerKind::Apk,
        ExtensionSubkind::Xpi => ContainerKind::Xpi,
        ExtensionSubkind::Whl => ContainerKind::Whl,
        ExtensionSubkind::Egg => ContainerKind::Egg,
        ExtensionSubkind::Crx => ContainerKind::Crx,
        ExtensionSubkind::Nupkg => ContainerKind::Nupkg,
        ExtensionSubkind::Vsix => ContainerKind::Vsix,
        ExtensionSubkind::Pyz => ContainerKind::Pyz,
        ExtensionSubkind::Asar => ContainerKind::Asar,
    }
}

fn detect_by_magic(bytes: &[u8]) -> Option<ContainerKind> {
    if bytes.len() < 4 {
        return None;
    }
    if bytes.starts_with(ZIP_LOCAL_HEADER)
        || bytes.starts_with(ZIP_EMPTY_EOCD)
        || bytes.starts_with(ZIP_SPANNED)
    {
        return Some(ContainerKind::Zip);
    }
    if bytes.len() >= 8 && bytes.starts_with(DEB_MAGIC) {
        let after_header: &[u8] = &bytes[8..];
        if after_header.len() >= DEB_MEMBER.len() && after_header.starts_with(DEB_MEMBER) {
            return Some(ContainerKind::Deb);
        }
    }
    if bytes.starts_with(SEVENZ_MAGIC) {
        return Some(ContainerKind::SevenZ);
    }
    if bytes.starts_with(RAR5_MAGIC) || bytes.starts_with(RAR4_MAGIC) {
        return Some(ContainerKind::Rar);
    }
    if bytes.starts_with(CAB_MAGIC) {
        return Some(ContainerKind::Cab);
    }
    if bytes.starts_with(RPM_MAGIC) {
        return Some(ContainerKind::Rpm);
    }
    if bytes.starts_with(XZ_MAGIC) {
        return Some(if smells_like_tar_decompressed(bytes) {
            ContainerKind::TarXz
        } else {
            ContainerKind::Xz
        });
    }
    if bytes.starts_with(ZSTD_MAGIC) {
        return Some(ContainerKind::TarZst);
    }
    if bytes.starts_with(GZIP_MAGIC) {
        return Some(ContainerKind::TarGz);
    }
    if bytes.starts_with(BZIP2_MAGIC) {
        return Some(ContainerKind::TarBz2);
    }
    if bytes.starts_with(PKG_XAR_MAGIC) {
        return Some(ContainerKind::Pkg);
    }
    if bytes.starts_with(WIM_MAGIC) {
        return Some(ContainerKind::Wim);
    }
    if bytes.starts_with(VHDX_MAGIC) {
        return Some(ContainerKind::Vhdx);
    }
    if smells_like_cpio(bytes) {
        return Some(ContainerKind::Cpio);
    }
    if smells_like_asar(bytes) {
        return Some(ContainerKind::Asar);
    }
    if smells_like_tar(bytes) {
        return Some(ContainerKind::Tar);
    }
    if smells_like_iso(bytes) {
        return Some(ContainerKind::Iso);
    }
    if smells_like_dmg(bytes) {
        return Some(ContainerKind::Dmg);
    }
    if smells_like_gpt(bytes) {
        return Some(ContainerKind::Gpt);
    }
    if smells_like_mbr(bytes) {
        return Some(ContainerKind::Mbr);
    }
    None
}

fn detect_by_tail(bytes: &[u8]) -> Option<ContainerKind> {
    if find_eocd(bytes).is_some() {
        return Some(ContainerKind::Zip);
    }
    if smells_like_vhd(bytes) {
        return Some(ContainerKind::Vhd);
    }
    None
}

const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const EOCD_FIXED_LEN: usize = 22;
const MAX_COMMENT: usize = 0xFFFF;
const SEARCH_BUDGET: usize = MAX_COMMENT + EOCD_FIXED_LEN + 4;

fn find_eocd(bytes: &[u8]) -> Option<usize> {
    let len: usize = bytes.len();
    if len < EOCD_FIXED_LEN {
        return None;
    }
    let start: usize = len.saturating_sub(SEARCH_BUDGET);
    for off in (start..=len - EOCD_FIXED_LEN).rev() {
        let sig: u32 =
            u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
        if sig == EOCD_SIGNATURE {
            return Some(off);
        }
    }
    None
}

fn smells_like_tar(bytes: &[u8]) -> bool {
    let need: usize = TAR_USTAR_OFFSET + TAR_USTAR.len();
    if bytes.len() < need {
        return false;
    }
    &bytes[TAR_USTAR_OFFSET..TAR_USTAR_OFFSET + TAR_USTAR.len()] == TAR_USTAR
}

const XZ_TAR_PEEK_BYTES: usize = TAR_USTAR_OFFSET + TAR_USTAR.len();

fn smells_like_tar_decompressed(bytes: &[u8]) -> bool {
    use std::io::Read as _;

    let limit: u64 = XZ_TAR_PEEK_BYTES as u64;
    let mut head: Vec<u8> = Vec::with_capacity(XZ_TAR_PEEK_BYTES);
    let decoder: liblzma::read::XzDecoder<&[u8]> = liblzma::read::XzDecoder::new(bytes);
    if std::io::copy(&mut decoder.take(limit), &mut head).is_err() {
        return false;
    }
    head.len() >= XZ_TAR_PEEK_BYTES
        && &head[TAR_USTAR_OFFSET..TAR_USTAR_OFFSET + TAR_USTAR.len()] == TAR_USTAR
}

fn smells_like_iso(bytes: &[u8]) -> bool {
    let need: usize = ISO_PRIMARY_OFFSET + ISO_PRIMARY_TAG.len();
    if bytes.len() < need {
        return false;
    }
    &bytes[ISO_PRIMARY_OFFSET..ISO_PRIMARY_OFFSET + ISO_PRIMARY_TAG.len()] == ISO_PRIMARY_TAG
}

fn smells_like_dmg(bytes: &[u8]) -> bool {
    if bytes.len() < 512 {
        return false;
    }
    let tail_start: usize = bytes.len() - 512;
    bytes[tail_start..]
        .windows(4)
        .any(|w| w == DMG_TRAILER_MAGIC)
}

fn smells_like_asar(bytes: &[u8]) -> bool {
    if bytes.len() < 16 {
        return false;
    }
    if &bytes[0..4] != ASAR_HEADER_PREFIX {
        return false;
    }
    let pickle_size: u32 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if !(8..=64 * 1024 * 1024).contains(&pickle_size) {
        return false;
    }
    if &bytes[8..12] != ASAR_HEADER_PREFIX {
        return false;
    }
    let header_size: u32 = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    if !(1..=64 * 1024 * 1024).contains(&header_size) {
        return false;
    }
    let header_off: usize = 16;
    let header_end: usize = header_off.saturating_add(header_size as usize);
    if header_end > bytes.len() {
        return false;
    }
    bytes[header_off..header_end.min(header_off + 16)].contains(&b'{')
}

fn smells_like_cpio(bytes: &[u8]) -> bool {
    if bytes.len() >= 6
        && (bytes[..6] == *CPIO_NEWC_MAGIC
            || bytes[..6] == *CPIO_CRC_MAGIC
            || bytes[..6] == *CPIO_ODC_MAGIC)
    {
        return true;
    }
    bytes.len() >= 2 && (bytes[..2] == *CPIO_BIN_MAGIC_LE || bytes[..2] == *CPIO_BIN_MAGIC_BE)
}

fn smells_like_vhd(bytes: &[u8]) -> bool {
    if bytes.len() >= 8 && &bytes[..8] == VHD_COOKIE {
        return true;
    }
    if bytes.len() < VHD_FOOTER_LEN {
        return false;
    }
    let footer_start: usize = bytes.len() - VHD_FOOTER_LEN;
    &bytes[footer_start..footer_start + 8] == VHD_COOKIE
}

fn smells_like_gpt(bytes: &[u8]) -> bool {
    let need: usize = GPT_HEADER_OFFSET + GPT_SIGNATURE.len();
    if bytes.len() < need {
        return false;
    }
    &bytes[GPT_HEADER_OFFSET..GPT_HEADER_OFFSET + GPT_SIGNATURE.len()] == GPT_SIGNATURE
}

fn smells_like_mbr(bytes: &[u8]) -> bool {
    if bytes.len() < MBR_SIGNATURE_OFFSET + 2 {
        return false;
    }
    if &bytes[MBR_SIGNATURE_OFFSET..MBR_SIGNATURE_OFFSET + 2] != MBR_SIGNATURE {
        return false;
    }
    (0..4).any(|i: usize| {
        let entry: usize = MBR_PARTITION_TABLE_OFFSET + i * 16;
        let boot_flag: u8 = bytes[entry];
        let part_type: u8 = bytes[entry + 4];
        (boot_flag == 0x00 || boot_flag == 0x80) && part_type != 0x00
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExtensionSubkind {
    Jar,
    War,
    Apk,
    Xpi,
    Whl,
    Egg,
    Crx,
    Nupkg,
    Vsix,
    Pyz,
    Asar,
}

fn extension_subkind(path: &Path) -> Option<ExtensionSubkind> {
    let extension: &str = path
        .extension()
        .and_then(|s: &std::ffi::OsStr| s.to_str())?;
    let lowered: String = extension.to_ascii_lowercase();
    match lowered.as_str() {
        "jar" => Some(ExtensionSubkind::Jar),
        "war" => Some(ExtensionSubkind::War),
        "apk" => Some(ExtensionSubkind::Apk),
        "xpi" => Some(ExtensionSubkind::Xpi),
        "whl" => Some(ExtensionSubkind::Whl),
        "egg" => Some(ExtensionSubkind::Egg),
        "crx" => Some(ExtensionSubkind::Crx),
        "nupkg" => Some(ExtensionSubkind::Nupkg),
        "vsix" => Some(ExtensionSubkind::Vsix),
        "pyz" => Some(ExtensionSubkind::Pyz),
        "asar" => Some(ExtensionSubkind::Asar),
        _ => None,
    }
}

const fn refine_with_extension(
    detected: ContainerKind,
    hint: ExtensionSubkind,
) -> Option<ContainerKind> {
    match (detected, hint) {
        (ContainerKind::Zip, ExtensionSubkind::Jar) => Some(ContainerKind::Jar),
        (ContainerKind::Zip, ExtensionSubkind::War) => Some(ContainerKind::War),
        (ContainerKind::Zip, ExtensionSubkind::Apk) => Some(ContainerKind::Apk),
        (ContainerKind::Zip, ExtensionSubkind::Xpi) => Some(ContainerKind::Xpi),
        (ContainerKind::Zip, ExtensionSubkind::Whl) => Some(ContainerKind::Whl),
        (ContainerKind::Zip, ExtensionSubkind::Egg) => Some(ContainerKind::Egg),
        (ContainerKind::Zip, ExtensionSubkind::Crx) => Some(ContainerKind::Crx),
        (ContainerKind::Zip, ExtensionSubkind::Nupkg) => Some(ContainerKind::Nupkg),
        (ContainerKind::Zip, ExtensionSubkind::Vsix) => Some(ContainerKind::Vsix),
        (ContainerKind::Zip, ExtensionSubkind::Pyz) => Some(ContainerKind::Pyz),
        (_, _) => None,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn empty_bytes_yields_none() {
        assert_eq!(detect_container(&[]), None);
    }

    #[test]
    fn random_bytes_yield_none() {
        let bytes: Vec<u8> = (0u8..200).collect();
        assert!(detect_container(&bytes).is_none());
    }

    #[test]
    fn detects_zip_local_header() {
        let mut bytes: Vec<u8> = Vec::with_capacity(256);
        bytes.extend_from_slice(ZIP_LOCAL_HEADER);
        bytes.extend(std::iter::repeat_n(0u8, 252));
        assert_eq!(detect_container(&bytes), Some(ContainerKind::Zip));
    }

    #[test]
    fn detects_empty_zip_eocd_at_start() {
        let mut bytes: Vec<u8> = Vec::with_capacity(64);
        bytes.extend_from_slice(ZIP_EMPTY_EOCD);
        bytes.extend(std::iter::repeat_n(0u8, 60));
        assert_eq!(detect_container(&bytes), Some(ContainerKind::Zip));
    }

    #[test]
    fn detects_zip_via_tail_eocd_only() {
        let mut bytes: Vec<u8> = vec![0u8; 1024];
        let off: usize = bytes.len() - EOCD_FIXED_LEN;
        bytes[off..off + 4].copy_from_slice(&EOCD_SIGNATURE.to_le_bytes());
        assert_eq!(detect_container(&bytes), Some(ContainerKind::Zip));
    }

    #[test]
    fn detects_sevenz_magic() {
        let mut bytes: Vec<u8> = SEVENZ_MAGIC.to_vec();
        bytes.extend([0u8; 32]);
        assert_eq!(detect_container(&bytes), Some(ContainerKind::SevenZ));
    }

    #[test]
    fn detects_rar5_magic() {
        let mut bytes: Vec<u8> = RAR5_MAGIC.to_vec();
        bytes.extend([0u8; 32]);
        assert_eq!(detect_container(&bytes), Some(ContainerKind::Rar));
    }

    #[test]
    fn detects_rar4_magic() {
        let mut bytes: Vec<u8> = RAR4_MAGIC.to_vec();
        bytes.extend([0u8; 32]);
        assert_eq!(detect_container(&bytes), Some(ContainerKind::Rar));
    }

    #[test]
    fn detects_cab_magic() {
        let mut bytes: Vec<u8> = CAB_MAGIC.to_vec();
        bytes.extend([0u8; 36]);
        assert_eq!(detect_container(&bytes), Some(ContainerKind::Cab));
    }

    #[test]
    fn detects_rpm_magic() {
        let mut bytes: Vec<u8> = RPM_MAGIC.to_vec();
        bytes.extend([0u8; 32]);
        assert_eq!(detect_container(&bytes), Some(ContainerKind::Rpm));
    }

    #[test]
    fn detects_deb_archive() {
        let mut bytes: Vec<u8> = DEB_MAGIC.to_vec();
        bytes.extend_from_slice(DEB_MEMBER);
        bytes.extend([0u8; 64]);
        assert_eq!(detect_container(&bytes), Some(ContainerKind::Deb));
    }

    #[test]
    fn detects_gzip_as_tar_gz() {
        let bytes: Vec<u8> = vec![0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0];
        assert_eq!(detect_container(&bytes), Some(ContainerKind::TarGz));
    }

    #[test]
    fn undecompressable_xz_stub_is_bare_xz() {
        let mut bytes: Vec<u8> = XZ_MAGIC.to_vec();
        bytes.extend([0u8; 32]);
        assert_eq!(detect_container(&bytes), Some(ContainerKind::Xz));
    }

    fn xz_compress(payload: &[u8]) -> Vec<u8> {
        use std::io::Read as _;
        let mut out: Vec<u8> = Vec::new();
        let mut encoder: liblzma::read::XzEncoder<&[u8]> =
            liblzma::read::XzEncoder::new(payload, 1);
        encoder.read_to_end(&mut out).expect("xz compress");
        out
    }

    #[test]
    fn xz_wrapping_tar_detects_tar_xz() {
        let mut tar: Vec<u8> = vec![0u8; 1024];
        tar[TAR_USTAR_OFFSET..TAR_USTAR_OFFSET + TAR_USTAR.len()].copy_from_slice(TAR_USTAR);
        let compressed: Vec<u8> = xz_compress(&tar);
        assert!(compressed.starts_with(XZ_MAGIC));
        assert_eq!(detect_container(&compressed), Some(ContainerKind::TarXz));
    }

    #[test]
    fn xz_wrapping_plain_payload_detects_bare_xz() {
        let payload: Vec<u8> =
            b"this is just a plain text file, not a tar archive at all".repeat(8);
        let compressed: Vec<u8> = xz_compress(&payload);
        assert!(compressed.starts_with(XZ_MAGIC));
        assert_eq!(detect_container(&compressed), Some(ContainerKind::Xz));
    }

    #[test]
    fn detects_zstd_as_tar_zst() {
        let mut bytes: Vec<u8> = ZSTD_MAGIC.to_vec();
        bytes.extend([0u8; 32]);
        assert_eq!(detect_container(&bytes), Some(ContainerKind::TarZst));
    }

    #[test]
    fn detects_bzip2_as_tar_bz2() {
        let mut bytes: Vec<u8> = BZIP2_MAGIC.to_vec();
        bytes.extend([0u8; 32]);
        assert_eq!(detect_container(&bytes), Some(ContainerKind::TarBz2));
    }

    #[test]
    fn detects_ustar_offset() {
        let mut bytes: Vec<u8> = vec![0u8; 1024];
        bytes[TAR_USTAR_OFFSET..TAR_USTAR_OFFSET + TAR_USTAR.len()].copy_from_slice(TAR_USTAR);
        assert_eq!(detect_container(&bytes), Some(ContainerKind::Tar));
    }

    #[test]
    fn detects_iso_at_offset_32769() {
        let mut bytes: Vec<u8> = vec![0u8; ISO_PRIMARY_OFFSET + 16];
        bytes[ISO_PRIMARY_OFFSET..ISO_PRIMARY_OFFSET + ISO_PRIMARY_TAG.len()]
            .copy_from_slice(ISO_PRIMARY_TAG);
        assert_eq!(detect_container(&bytes), Some(ContainerKind::Iso));
    }

    #[test]
    fn detects_pkg_xar() {
        let mut bytes: Vec<u8> = PKG_XAR_MAGIC.to_vec();
        bytes.extend([0u8; 32]);
        assert_eq!(detect_container(&bytes), Some(ContainerKind::Pkg));
    }

    #[test]
    fn extension_refines_zip_to_jar() {
        let mut bytes: Vec<u8> = ZIP_LOCAL_HEADER.to_vec();
        bytes.extend([0u8; 256]);
        let path: &Path = Path::new("app.jar");
        assert_eq!(
            detect_container_with_hint(&bytes, Some(path)),
            Some(ContainerKind::Jar)
        );
    }

    #[test]
    fn extension_refines_zip_to_whl() {
        let mut bytes: Vec<u8> = ZIP_LOCAL_HEADER.to_vec();
        bytes.extend([0u8; 256]);
        let path: &Path = Path::new("package-1.0-py3-none-any.whl");
        assert_eq!(
            detect_container_with_hint(&bytes, Some(path)),
            Some(ContainerKind::Whl)
        );
    }

    #[test]
    fn extension_refines_zip_to_apk() {
        let mut bytes: Vec<u8> = ZIP_LOCAL_HEADER.to_vec();
        bytes.extend([0u8; 256]);
        let path: &Path = Path::new("App.apk");
        assert_eq!(
            detect_container_with_hint(&bytes, Some(path)),
            Some(ContainerKind::Apk)
        );
    }

    #[test]
    fn detects_asar_header_shape() {
        let mut bytes: Vec<u8> = ASAR_HEADER_PREFIX.to_vec();
        let pickle_size: u32 = 100;
        bytes.extend_from_slice(&pickle_size.to_le_bytes());
        bytes.extend_from_slice(ASAR_HEADER_PREFIX);
        let header_size: u32 = 32;
        bytes.extend_from_slice(&header_size.to_le_bytes());
        let header_json: &[u8] = br#"{"files":{}}"#;
        bytes.extend_from_slice(header_json);
        bytes.extend(std::iter::repeat_n(b' ', 32 - header_json.len()));
        assert_eq!(detect_container(&bytes), Some(ContainerKind::Asar));
    }

    #[test]
    fn container_label_round_trips() {
        assert_eq!(ContainerKind::Zip.label(), "zip");
        assert_eq!(ContainerKind::TarZst.label(), "tar.zst");
        assert_eq!(ContainerKind::Whl.label(), "whl");
    }

    #[test]
    fn is_zip_family_correct() {
        assert!(ContainerKind::Whl.is_zip_family());
        assert!(ContainerKind::Apk.is_zip_family());
        assert!(!ContainerKind::Tar.is_zip_family());
        assert!(!ContainerKind::SevenZ.is_zip_family());
    }
}
