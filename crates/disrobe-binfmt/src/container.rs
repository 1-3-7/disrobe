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
    Squirrel,
    InnoSetup,
    InstallShield,
    Oci,
    DockerImage,
    Squashfs,
    Cramfs,
    Ext4,
    Romfs,
    MinixFs,
    AndroidSparse,
    BtrfsSend,
    Erofs,
    Jffs2,
    Ntfs,
    Ubifs,
    Yaffs2,
    Cpio,
    Arj,
    Arc,
    Lzh,
    Lzo,
    Uzip,
    Xalz,
    Ar,
    Par2,
    Partclone,
    StuffIt,
    Qnx,
    Vhd,
    Vhdx,
    Wim,
    Gpt,
    Mbr,
    Fat,
    Xz,
    Gzip,
    Bzip2,
    Zstd,
    Lzma,
    Lzip,
    Lz4,
    Zlib,
    UnixCompress,
    BunStandalone,
    UnityFs,
    FwDlinkShrs,
    FwDlinkEncrptedImg,
    FwDlinkAlphaV1,
    FwDlinkAlphaV2,
    FwDlinkDeafbead,
    FwDlinkFpkg,
    FwEnGenius,
    FwAutelEcc,
    FwQnap,
    FwNetgearChk,
    FwNetgearTrxV1,
    FwNetgearTrxV2,
    FwXiaomiHdr1,
    FwXiaomiHdr2,
    FwTeslaSbfh,
    FwHpBdl,
    FwHpIpkg,
    FwMoxaFrm,
    FwInstarBneg,
    FwInstarHd,
    FwAiroha,
    Minidump,
    None,
}

impl ContainerKind {
    #[must_use]
    pub const fn firmware_kind(self) -> Option<crate::containers::FirmwareKind> {
        use crate::containers::FirmwareKind as F;
        Some(match self {
            Self::FwDlinkShrs => F::DlinkShrs,
            Self::FwDlinkEncrptedImg => F::DlinkEncrptedImg,
            Self::FwDlinkAlphaV1 => F::DlinkAlphaV1,
            Self::FwDlinkAlphaV2 => F::DlinkAlphaV2,
            Self::FwDlinkDeafbead => F::DlinkDeafbead,
            Self::FwDlinkFpkg => F::DlinkFpkg,
            Self::FwEnGenius => F::EnGenius,
            Self::FwAutelEcc => F::AutelEcc,
            Self::FwQnap => F::Qnap,
            Self::FwNetgearChk => F::NetgearChk,
            Self::FwNetgearTrxV1 => F::NetgearTrxV1,
            Self::FwNetgearTrxV2 => F::NetgearTrxV2,
            Self::FwXiaomiHdr1 => F::XiaomiHdr1,
            Self::FwXiaomiHdr2 => F::XiaomiHdr2,
            Self::FwTeslaSbfh => F::TeslaSbfh,
            Self::FwHpBdl => F::HpBdl,
            Self::FwHpIpkg => F::HpIpkg,
            Self::FwMoxaFrm => F::MoxaFrm,
            Self::FwInstarBneg => F::InstarBneg,
            Self::FwInstarHd => F::InstarHd,
            Self::FwAiroha => F::Airoha,
            _ => return None,
        })
    }

    #[must_use]
    pub const fn from_firmware_kind(kind: crate::containers::FirmwareKind) -> Self {
        use crate::containers::FirmwareKind as F;
        match kind {
            F::DlinkShrs => Self::FwDlinkShrs,
            F::DlinkEncrptedImg => Self::FwDlinkEncrptedImg,
            F::DlinkAlphaV1 => Self::FwDlinkAlphaV1,
            F::DlinkAlphaV2 => Self::FwDlinkAlphaV2,
            F::DlinkDeafbead => Self::FwDlinkDeafbead,
            F::DlinkFpkg => Self::FwDlinkFpkg,
            F::EnGenius => Self::FwEnGenius,
            F::AutelEcc => Self::FwAutelEcc,
            F::Qnap => Self::FwQnap,
            F::NetgearChk => Self::FwNetgearChk,
            F::NetgearTrxV1 => Self::FwNetgearTrxV1,
            F::NetgearTrxV2 => Self::FwNetgearTrxV2,
            F::XiaomiHdr1 => Self::FwXiaomiHdr1,
            F::XiaomiHdr2 => Self::FwXiaomiHdr2,
            F::TeslaSbfh => Self::FwTeslaSbfh,
            F::HpBdl => Self::FwHpBdl,
            F::HpIpkg => Self::FwHpIpkg,
            F::MoxaFrm => Self::FwMoxaFrm,
            F::InstarBneg => Self::FwInstarBneg,
            F::InstarHd => Self::FwInstarHd,
            F::Airoha => Self::FwAiroha,
        }
    }
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
            Self::Squirrel => "squirrel",
            Self::InnoSetup => "innosetup",
            Self::InstallShield => "installshield",
            Self::Oci => "oci",
            Self::DockerImage => "docker-image",
            Self::Squashfs => "squashfs",
            Self::Cramfs => "cramfs",
            Self::Ext4 => "ext4",
            Self::Romfs => "romfs",
            Self::MinixFs => "minixfs",
            Self::AndroidSparse => "android-sparse",
            Self::BtrfsSend => "btrfs-send",
            Self::Erofs => "erofs",
            Self::Jffs2 => "jffs2",
            Self::Ntfs => "ntfs",
            Self::Ubifs => "ubifs",
            Self::Yaffs2 => "yaffs2",
            Self::Cpio => "cpio",
            Self::Arj => "arj",
            Self::Arc => "arc",
            Self::Lzh => "lzh",
            Self::Lzo => "lzo",
            Self::Uzip => "uzip",
            Self::Xalz => "xalz",
            Self::Ar => "ar",
            Self::Par2 => "par2",
            Self::Partclone => "partclone",
            Self::StuffIt => "stuffit",
            Self::Qnx => "qnx",
            Self::Vhd => "vhd",
            Self::Vhdx => "vhdx",
            Self::Wim => "wim",
            Self::Gpt => "gpt",
            Self::Mbr => "mbr",
            Self::Fat => "fat",
            Self::Xz => "xz",
            Self::Gzip => "gz",
            Self::Bzip2 => "bz2",
            Self::Zstd => "zst",
            Self::Lzma => "lzma",
            Self::Lzip => "lz",
            Self::Lz4 => "lz4",
            Self::Zlib => "zlib",
            Self::UnixCompress => "Z",
            Self::BunStandalone => "bun-standalone",
            Self::UnityFs => "unityfs",
            Self::FwDlinkShrs => "dlink-shrs",
            Self::FwDlinkEncrptedImg => "dlink-encrpted-img",
            Self::FwDlinkAlphaV1 => "dlink-alpha-v1",
            Self::FwDlinkAlphaV2 => "dlink-alpha-v2",
            Self::FwDlinkDeafbead => "dlink-deafbead",
            Self::FwDlinkFpkg => "dlink-fpkg",
            Self::FwEnGenius => "engenius",
            Self::FwAutelEcc => "autel-ecc",
            Self::FwQnap => "qnap",
            Self::FwNetgearChk => "netgear-chk",
            Self::FwNetgearTrxV1 => "netgear-trx-v1",
            Self::FwNetgearTrxV2 => "netgear-trx-v2",
            Self::FwXiaomiHdr1 => "xiaomi-hdr1",
            Self::FwXiaomiHdr2 => "xiaomi-hdr2",
            Self::FwTeslaSbfh => "tesla-sbfh",
            Self::FwHpBdl => "hp-bdl",
            Self::FwHpIpkg => "hp-ipkg",
            Self::FwMoxaFrm => "moxa-frm",
            Self::FwInstarBneg => "instar-bneg",
            Self::FwInstarHd => "instar-hd",
            Self::FwAiroha => "airoha",
            Self::Minidump => "minidump",
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

    pub const ALL: [Self; 99] = [
        Self::Zip,
        Self::Tar,
        Self::TarGz,
        Self::TarBz2,
        Self::TarXz,
        Self::TarZst,
        Self::SevenZ,
        Self::Rar,
        Self::Cab,
        Self::Iso,
        Self::Asar,
        Self::Pkg,
        Self::Dmg,
        Self::Deb,
        Self::Rpm,
        Self::Jar,
        Self::War,
        Self::Apk,
        Self::Xpi,
        Self::Whl,
        Self::Egg,
        Self::Crx,
        Self::Nupkg,
        Self::Vsix,
        Self::Pyz,
        Self::AppImage,
        Self::Snap,
        Self::Flatpak,
        Self::Msix,
        Self::Msi,
        Self::Nsis,
        Self::Squirrel,
        Self::InnoSetup,
        Self::InstallShield,
        Self::Oci,
        Self::DockerImage,
        Self::Squashfs,
        Self::Cramfs,
        Self::Ext4,
        Self::Romfs,
        Self::MinixFs,
        Self::AndroidSparse,
        Self::BtrfsSend,
        Self::Erofs,
        Self::Jffs2,
        Self::Ntfs,
        Self::Ubifs,
        Self::Yaffs2,
        Self::Cpio,
        Self::Arj,
        Self::Arc,
        Self::Lzh,
        Self::Lzo,
        Self::Uzip,
        Self::Xalz,
        Self::Ar,
        Self::Par2,
        Self::Partclone,
        Self::StuffIt,
        Self::Qnx,
        Self::Vhd,
        Self::Vhdx,
        Self::Wim,
        Self::Gpt,
        Self::Mbr,
        Self::Fat,
        Self::Xz,
        Self::Gzip,
        Self::Bzip2,
        Self::Zstd,
        Self::Lzma,
        Self::Lzip,
        Self::Lz4,
        Self::Zlib,
        Self::UnixCompress,
        Self::BunStandalone,
        Self::UnityFs,
        Self::FwDlinkShrs,
        Self::FwDlinkEncrptedImg,
        Self::FwDlinkAlphaV1,
        Self::FwDlinkAlphaV2,
        Self::FwDlinkDeafbead,
        Self::FwDlinkFpkg,
        Self::FwEnGenius,
        Self::FwAutelEcc,
        Self::FwQnap,
        Self::FwNetgearChk,
        Self::FwNetgearTrxV1,
        Self::FwNetgearTrxV2,
        Self::FwXiaomiHdr1,
        Self::FwXiaomiHdr2,
        Self::FwTeslaSbfh,
        Self::FwHpBdl,
        Self::FwHpIpkg,
        Self::FwMoxaFrm,
        Self::FwInstarBneg,
        Self::FwInstarHd,
        Self::FwAiroha,
        Self::Minidump,
    ];

    #[must_use]
    pub const fn extraction_mode(self) -> ExtractionMode {
        match self {
            Self::Zip
            | Self::Tar
            | Self::TarGz
            | Self::TarBz2
            | Self::TarXz
            | Self::TarZst
            | Self::SevenZ
            | Self::Rar
            | Self::Cab
            | Self::Iso
            | Self::Asar
            | Self::Pkg
            | Self::Dmg
            | Self::Deb
            | Self::Rpm
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
            | Self::AppImage
            | Self::Snap
            | Self::Msix
            | Self::Msi
            | Self::Nsis
            | Self::Squirrel
            | Self::Oci
            | Self::DockerImage
            | Self::Squashfs
            | Self::Cramfs
            | Self::Ext4
            | Self::Romfs
            | Self::MinixFs
            | Self::AndroidSparse
            | Self::BtrfsSend
            | Self::Erofs
            | Self::Jffs2
            | Self::Ntfs
            | Self::Ubifs
            | Self::Yaffs2
            | Self::Cpio
            | Self::Arj
            | Self::Arc
            | Self::Lzh
            | Self::Lzo
            | Self::Uzip
            | Self::Xalz
            | Self::Ar
            | Self::Par2
            | Self::Partclone
            | Self::StuffIt
            | Self::Qnx
            | Self::Xz
            | Self::Gzip
            | Self::Bzip2
            | Self::Zstd
            | Self::Lzma
            | Self::Lzip
            | Self::Lz4
            | Self::Zlib
            | Self::UnixCompress
            | Self::Vhd
            | Self::Vhdx
            | Self::Wim
            | Self::Gpt
            | Self::Mbr
            | Self::Fat
            | Self::BunStandalone
            | Self::UnityFs
            | Self::Flatpak
            | Self::InnoSetup
            | Self::FwDlinkShrs
            | Self::FwDlinkEncrptedImg
            | Self::FwDlinkAlphaV1
            | Self::FwDlinkAlphaV2
            | Self::FwDlinkDeafbead
            | Self::FwDlinkFpkg
            | Self::FwEnGenius
            | Self::FwAutelEcc
            | Self::FwQnap
            | Self::FwNetgearChk
            | Self::FwNetgearTrxV1
            | Self::FwNetgearTrxV2
            | Self::FwXiaomiHdr1
            | Self::FwXiaomiHdr2
            | Self::FwTeslaSbfh
            | Self::FwHpBdl
            | Self::FwHpIpkg
            | Self::FwMoxaFrm
            | Self::FwInstarBneg
            | Self::FwInstarHd
            | Self::FwAiroha
            | Self::Minidump
            | Self::InstallShield => ExtractionMode::Payload,
            Self::None => ExtractionMode::Unsupported,
        }
    }

    #[must_use]
    pub const fn detected_format_count() -> usize {
        Self::ALL.len()
    }

    #[must_use]
    pub fn extracted_in_tree_count() -> usize {
        Self::ALL
            .iter()
            .filter(|kind: &&Self| matches!(kind.extraction_mode(), ExtractionMode::Payload))
            .count()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractionMode {
    Payload,
    MetadataOnly,
    ExternalTool,
    Unsupported,
}

const ZIP_LOCAL_HEADER: &[u8; 4] = b"PK\x03\x04";
const ZIP_EMPTY_EOCD: &[u8; 4] = b"PK\x05\x06";
const ZIP_SPANNED: &[u8; 4] = b"PK\x07\x08";
const SEVENZ_MAGIC: &[u8; 6] = &[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];
const RAR4_MAGIC: &[u8; 7] = &[0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00];
const RAR5_MAGIC: &[u8; 8] = &[0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00];
const CAB_MAGIC: &[u8; 4] = b"MSCF";
const ISC_MAGIC: &[u8; 4] = b"ISc(";
const RPM_MAGIC: &[u8; 4] = &[0xed, 0xab, 0xee, 0xdb];
const DEB_MAGIC: &[u8; 8] = b"!<arch>\n";
const DEB_MEMBER: &[u8; 14] = b"debian-binary ";
const XZ_MAGIC: &[u8; 6] = &[0xfd, b'7', b'z', b'X', b'Z', 0x00];
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
const UNITYFS_MAGIC: &[u8; 8] = b"UnityFS\x00";
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
    if crate::debug::dbg_enabled() {
        crate::debug::dbg_section("binfmt detect-container");
        crate::debug::dbg_kv("input-len", || bytes.len().to_string());
        crate::debug::dbg_kv("path-hint", || {
            path.map_or_else(|| "<none>".to_owned(), |p: &Path| p.display().to_string())
        });
        crate::debug::dbg_hex("magic", bytes, 16);
    }
    if let Some(kind) = detect_by_magic(bytes) {
        if let Some(extension_hint) = path.and_then(extension_subkind)
            && let Some(refined) = refine_with_extension(kind, extension_hint)
        {
            crate::debug::dbg_kv("classify", || {
                format!(
                    "{} (magic, extension-refined to {})",
                    kind.label(),
                    refined.label()
                )
            });
            return Some(refined);
        }
        crate::debug::dbg_kv("classify", || format!("{} (magic)", kind.label()));
        return Some(kind);
    }
    if let Some(kind) = detect_by_tail(bytes) {
        if let Some(extension_hint) = path.and_then(extension_subkind)
            && let Some(refined) = refine_with_extension(kind, extension_hint)
        {
            crate::debug::dbg_kv("classify", || {
                format!(
                    "{} (tail, extension-refined to {})",
                    kind.label(),
                    refined.label()
                )
            });
            return Some(refined);
        }
        crate::debug::dbg_kv("classify", || format!("{} (tail)", kind.label()));
        return Some(kind);
    }
    if let Some(kind) = path.and_then(bare_stream_extension_kind) {
        crate::debug::dbg_kv("classify", || {
            format!("{} (bare-stream extension)", kind.label())
        });
        return Some(kind);
    }
    let by_extension: Option<ContainerKind> =
        path.and_then(extension_subkind).map(subkind_default_kind);
    crate::debug::dbg_kv("classify", || {
        by_extension.map_or_else(
            || "none (no magic, tail, or extension match)".to_owned(),
            |k: ContainerKind| format!("{} (extension default)", k.label()),
        )
    });
    by_extension
}

fn bare_stream_extension_kind(path: &Path) -> Option<ContainerKind> {
    let extension: &str = path
        .extension()
        .and_then(|s: &std::ffi::OsStr| s.to_str())?;
    if extension.eq_ignore_ascii_case("z") {
        return Some(ContainerKind::UnixCompress);
    }
    match extension.to_ascii_lowercase().as_str() {
        "lzma" => Some(ContainerKind::Lzma),
        "lz" => Some(ContainerKind::Lzip),
        "lz4" => Some(ContainerKind::Lz4),
        "zst" | "zstd" => Some(ContainerKind::Zstd),
        "zlib" => Some(ContainerKind::Zlib),
        _ => None,
    }
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
    if let Some(fw) = crate::containers::detect_firmware(bytes) {
        return Some(ContainerKind::from_firmware_kind(fw));
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
        return Some(ContainerKind::Ar);
    }
    if crate::containers::detect_par2(bytes) {
        return Some(ContainerKind::Par2);
    }
    if crate::containers::detect_xalz(bytes) {
        return Some(ContainerKind::Xalz);
    }
    if crate::containers::detect_lzop(bytes) {
        return Some(ContainerKind::Lzo);
    }
    if crate::containers::detect_arj(bytes) {
        return Some(ContainerKind::Arj);
    }
    if crate::containers::detect_lzh(bytes) {
        return Some(ContainerKind::Lzh);
    }
    if crate::containers::detect_partclone(bytes).is_some() {
        return Some(ContainerKind::Partclone);
    }
    if crate::containers::detect_stuffit(bytes).is_some() {
        return Some(ContainerKind::StuffIt);
    }
    if crate::containers::detect_qnx(bytes).is_some() {
        return Some(ContainerKind::Qnx);
    }
    if crate::containers::detect_uzip(bytes) {
        return Some(ContainerKind::Uzip);
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
    if bytes.starts_with(ISC_MAGIC) {
        return Some(ContainerKind::InstallShield);
    }
    if bytes.starts_with(RPM_MAGIC) {
        return Some(ContainerKind::Rpm);
    }
    if smells_like_dmg(bytes) {
        return Some(ContainerKind::Dmg);
    }
    if crate::containers::bare_stream::detect_lzip(bytes) {
        return Some(ContainerKind::Lzip);
    }
    if crate::containers::bare_stream::detect_lz4(bytes).is_some() {
        return Some(ContainerKind::Lz4);
    }
    if crate::containers::bare_stream::detect_compress(bytes) {
        return Some(ContainerKind::UnixCompress);
    }
    if bytes.starts_with(XZ_MAGIC) {
        return Some(if smells_like_tar_decompressed(bytes, DecompressWrap::Xz) {
            ContainerKind::TarXz
        } else {
            ContainerKind::Xz
        });
    }
    if crate::containers::bare_stream::detect_zstd(bytes) {
        return Some(
            if smells_like_tar_decompressed(bytes, DecompressWrap::Zstd) {
                ContainerKind::TarZst
            } else {
                ContainerKind::Zstd
            },
        );
    }
    if crate::containers::bare_stream::detect_gzip(bytes) {
        return Some(
            if smells_like_tar_decompressed(bytes, DecompressWrap::Gzip) {
                ContainerKind::TarGz
            } else {
                ContainerKind::Gzip
            },
        );
    }
    if crate::containers::bare_stream::detect_bzip2(bytes) {
        return Some(
            if smells_like_tar_decompressed(bytes, DecompressWrap::Bzip2) {
                ContainerKind::TarBz2
            } else {
                ContainerKind::Bzip2
            },
        );
    }
    if bytes.starts_with(PKG_XAR_MAGIC) {
        return Some(ContainerKind::Pkg);
    }
    if bytes.starts_with(WIM_MAGIC) {
        return Some(ContainerKind::Wim);
    }
    if bytes.starts_with(UNITYFS_MAGIC) {
        return Some(ContainerKind::UnityFs);
    }
    if bytes.starts_with(VHDX_MAGIC) {
        return Some(ContainerKind::Vhdx);
    }
    if crate::containers::minidump::detect_minidump(bytes) {
        return Some(ContainerKind::Minidump);
    }
    if crate::containers::bare_stream::detect_zlib(bytes) {
        return Some(ContainerKind::Zlib);
    }
    if smells_like_squashfs(bytes) {
        return Some(ContainerKind::Squashfs);
    }
    if crate::containers::detect_romfs(bytes).is_some() {
        return Some(ContainerKind::Romfs);
    }
    if crate::containers::detect_sparse(bytes).is_some() {
        return Some(ContainerKind::AndroidSparse);
    }
    if crate::containers::detect_btrfs_send(bytes).is_some() {
        return Some(ContainerKind::BtrfsSend);
    }
    if crate::containers::detect_erofs(bytes).is_some() {
        return Some(ContainerKind::Erofs);
    }
    if crate::containers::detect_jffs2(bytes).is_some() {
        return Some(ContainerKind::Jffs2);
    }
    if crate::containers::detect_ubi(bytes) || crate::containers::detect_ubifs(bytes).is_some() {
        return Some(ContainerKind::Ubifs);
    }
    if crate::containers::detect_yaffs2(bytes).is_some() {
        return Some(ContainerKind::Yaffs2);
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
    if smells_like_vhd(bytes) {
        return Some(ContainerKind::Vhd);
    }
    if smells_like_gpt(bytes) {
        return Some(ContainerKind::Gpt);
    }
    if crate::containers::detect_ntfs(bytes).is_some() {
        return Some(ContainerKind::Ntfs);
    }
    if crate::containers::detect_minixfs(bytes).is_some() {
        return Some(ContainerKind::MinixFs);
    }
    if smells_like_fat(bytes) {
        return Some(ContainerKind::Fat);
    }
    if smells_like_mbr(bytes) {
        return Some(ContainerKind::Mbr);
    }
    if crate::containers::detect_arc(bytes) {
        return Some(ContainerKind::Arc);
    }
    if crate::containers::bare_stream::detect_lzma_alone(bytes) {
        return Some(ContainerKind::Lzma);
    }
    None
}

fn detect_by_tail(bytes: &[u8]) -> Option<ContainerKind> {
    if crate::containers::bun::detect_bun(bytes).is_some() {
        return Some(ContainerKind::BunStandalone);
    }
    if smells_like_nsis(bytes) {
        return Some(ContainerKind::Nsis);
    }
    if crate::containers::detect_innosetup(bytes).is_some() {
        return Some(ContainerKind::InnoSetup);
    }
    if bytes.starts_with(b"MZ")
        && crate::containers::squirrel::locate_embedded_nupkg(bytes).is_some()
    {
        return Some(ContainerKind::Squirrel);
    }
    if crate::containers::detect_flatpak_bundle(bytes) {
        return Some(ContainerKind::Flatpak);
    }
    if crate::structural::validate_zip(bytes) {
        return Some(ContainerKind::Zip);
    }
    if smells_like_vhd(bytes) {
        return Some(ContainerKind::Vhd);
    }
    None
}

const NSIS_FIRSTHEADER_MAGIC: [u8; 16] = [
    0xEF, 0xBE, 0xAD, 0xDE, b'N', b'u', b'l', b'l', b's', b'o', b'f', b't', b'I', b'n', b's', b't',
];

fn smells_like_nsis(bytes: &[u8]) -> bool {
    if !bytes.starts_with(b"MZ") {
        return false;
    }
    memchr_find(bytes, &NSIS_FIRSTHEADER_MAGIC, 0).is_some()
}

pub(crate) fn memchr_find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= haystack.len() || haystack.len() - from < needle.len() {
        return None;
    }
    let first: u8 = needle[0];
    let mut cursor: usize = from;
    while let Some(rel) = haystack[cursor..].iter().position(|&b: &u8| b == first) {
        let at: usize = cursor + rel;
        if haystack[at..].starts_with(needle) {
            return Some(at);
        }
        cursor = at + 1;
        if cursor >= haystack.len() {
            break;
        }
    }
    None
}

#[cfg(test)]
const EOCD_SIGNATURE: u32 = 0x0605_4b50;
#[cfg(test)]
const EOCD_FIXED_LEN: usize = 22;

fn smells_like_tar(bytes: &[u8]) -> bool {
    let need: usize = TAR_USTAR_OFFSET + TAR_USTAR.len();
    if bytes.len() < need {
        return false;
    }
    &bytes[TAR_USTAR_OFFSET..TAR_USTAR_OFFSET + TAR_USTAR.len()] == TAR_USTAR
}

const XZ_TAR_PEEK_BYTES: usize = TAR_USTAR_OFFSET + TAR_USTAR.len();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecompressWrap {
    Xz,
    Zstd,
    Gzip,
    Bzip2,
}

fn smells_like_tar_decompressed(bytes: &[u8], wrap: DecompressWrap) -> bool {
    use std::io::Read as _;

    let limit: u64 = XZ_TAR_PEEK_BYTES as u64;
    let mut head: Vec<u8> = Vec::with_capacity(XZ_TAR_PEEK_BYTES);
    let copied: std::io::Result<u64> = match wrap {
        DecompressWrap::Xz => {
            let decoder: liblzma::read::XzDecoder<&[u8]> = liblzma::read::XzDecoder::new(bytes);
            std::io::copy(&mut decoder.take(limit), &mut head)
        }
        DecompressWrap::Zstd => match zstd::stream::read::Decoder::new(bytes) {
            Ok(decoder) => std::io::copy(&mut decoder.take(limit), &mut head),
            Err(_) => return false,
        },
        DecompressWrap::Gzip => {
            let decoder: flate2::read::GzDecoder<&[u8]> = flate2::read::GzDecoder::new(bytes);
            std::io::copy(&mut decoder.take(limit), &mut head)
        }
        DecompressWrap::Bzip2 => {
            let decoder: bzip2_rs::DecoderReader<&[u8]> = bzip2_rs::DecoderReader::new(bytes);
            std::io::copy(&mut decoder.take(limit), &mut head)
        }
    };
    if copied.is_err() {
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

fn smells_like_squashfs(bytes: &[u8]) -> bool {
    crate::containers::squashfs::parse_squashfs_superblock(bytes, 0)
        .is_ok_and(|sb: crate::containers::squashfs::SquashfsSuperblock| sb.version_major == 4)
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

fn fat_boot_jump(bytes: &[u8]) -> bool {
    match bytes.first().copied() {
        Some(0xEB) => bytes.len() >= 3 && (bytes[2] == 0x90 || bytes[2] == 0x0E),
        Some(0xE9) => bytes.len() >= 3,
        _ => false,
    }
}

fn smells_like_fat(bytes: &[u8]) -> bool {
    fat_boot_jump(bytes) && crate::containers::fat::detect_fat(bytes)
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

    fn gzip_compress(payload: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut encoder: flate2::write::GzEncoder<Vec<u8>> =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(payload).expect("gzip write");
        encoder.finish().expect("gzip finish")
    }

    #[test]
    fn gzip_wrapping_tar_detects_tar_gz() {
        let mut tar: Vec<u8> = vec![0u8; 1024];
        tar[TAR_USTAR_OFFSET..TAR_USTAR_OFFSET + TAR_USTAR.len()].copy_from_slice(TAR_USTAR);
        let compressed: Vec<u8> = gzip_compress(&tar);
        assert_eq!(detect_container(&compressed), Some(ContainerKind::TarGz));
    }

    #[test]
    fn gzip_wrapping_plain_payload_detects_bare_gzip() {
        let payload: Vec<u8> = b"plain gzip text, not a tar at all".repeat(8);
        let compressed: Vec<u8> = gzip_compress(&payload);
        assert_eq!(detect_container(&compressed), Some(ContainerKind::Gzip));
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

    fn ustar_tar_blob() -> Vec<u8> {
        let mut tar: Vec<u8> = vec![0u8; 1024];
        tar[TAR_USTAR_OFFSET..TAR_USTAR_OFFSET + TAR_USTAR.len()].copy_from_slice(TAR_USTAR);
        tar
    }

    fn zstd_compress(payload: &[u8]) -> Vec<u8> {
        zstd::stream::encode_all(payload, 1).expect("zstd encode")
    }

    #[test]
    fn zstd_wrapping_tar_detects_tar_zst() {
        let compressed: Vec<u8> = zstd_compress(&ustar_tar_blob());
        assert_eq!(detect_container(&compressed), Some(ContainerKind::TarZst));
    }

    #[test]
    fn zstd_wrapping_plain_payload_detects_bare_zstd() {
        let payload: Vec<u8> = b"plain zstd payload, definitely not a tar archive".repeat(8);
        let compressed: Vec<u8> = zstd_compress(&payload);
        assert_eq!(detect_container(&compressed), Some(ContainerKind::Zstd));
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
    fn detects_unityfs_magic() {
        let mut bytes: Vec<u8> = UNITYFS_MAGIC.to_vec();
        bytes.extend([0u8; 32]);
        assert_eq!(detect_container(&bytes), Some(ContainerKind::UnityFs));
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

    #[test]
    fn all_excludes_none_and_has_no_duplicates() {
        assert!(!ContainerKind::ALL.contains(&ContainerKind::None));
        for (i, a) in ContainerKind::ALL.iter().enumerate() {
            for b in &ContainerKind::ALL[i + 1..] {
                assert_ne!(a, b, "duplicate variant in ContainerKind::ALL: {a:?}");
            }
        }
    }

    fn minimal_fat16_boot_sector() -> Vec<u8> {
        let mut boot: Vec<u8> = vec![0u8; 512];
        boot[0] = 0xEB;
        boot[1] = 0x3C;
        boot[2] = 0x90;
        boot[11..13].copy_from_slice(&512u16.to_le_bytes());
        boot[13] = 1;
        boot[14..16].copy_from_slice(&1u16.to_le_bytes());
        boot[16] = 1;
        boot[17..19].copy_from_slice(&16u16.to_le_bytes());
        boot[19..21].copy_from_slice(&4096u16.to_le_bytes());
        boot[22..24].copy_from_slice(&8u16.to_le_bytes());
        boot[510] = 0x55;
        boot[511] = 0xaa;
        boot
    }

    #[test]
    fn detects_fat_boot_sector() {
        let boot: Vec<u8> = minimal_fat16_boot_sector();
        assert_eq!(detect_container(&boot), Some(ContainerKind::Fat));
    }

    #[test]
    fn mbr_partition_table_is_not_mistaken_for_fat() {
        let mut disk: Vec<u8> = vec![0u8; 512];
        disk[0] = 0x33;
        disk[1] = 0xc0;
        disk[MBR_PARTITION_TABLE_OFFSET] = 0x80;
        disk[MBR_PARTITION_TABLE_OFFSET + 4] = 0x0c;
        disk[MBR_SIGNATURE_OFFSET] = 0x55;
        disk[MBR_SIGNATURE_OFFSET + 1] = 0xaa;
        assert_eq!(detect_container(&disk), Some(ContainerKind::Mbr));
    }

    #[test]
    fn fat_label_round_trips() {
        assert_eq!(ContainerKind::Fat.label(), "fat");
        assert_eq!(
            ContainerKind::Fat.extraction_mode(),
            ExtractionMode::Payload
        );
    }

    #[test]
    fn detected_count_is_ninety_nine() {
        assert_eq!(ContainerKind::detected_format_count(), 99);
        assert_eq!(ContainerKind::ALL.len(), 99);
    }

    #[test]
    fn every_real_format_extracts_in_tree() {
        assert_eq!(ContainerKind::extracted_in_tree_count(), 99);
        let metadata_only: usize = ContainerKind::ALL
            .iter()
            .filter(|k: &&ContainerKind| {
                matches!(k.extraction_mode(), ExtractionMode::MetadataOnly)
            })
            .count();
        let external: usize = ContainerKind::ALL
            .iter()
            .filter(|k: &&ContainerKind| {
                matches!(k.extraction_mode(), ExtractionMode::ExternalTool)
            })
            .count();
        assert_eq!(metadata_only, 0);
        assert_eq!(external, 0);
        assert_eq!(
            ContainerKind::extracted_in_tree_count() + metadata_only + external,
            99
        );
    }

    #[test]
    fn disk_image_formats_now_extract_in_tree() {
        for kind in [
            ContainerKind::Vhd,
            ContainerKind::Vhdx,
            ContainerKind::Wim,
            ContainerKind::Gpt,
            ContainerKind::Mbr,
            ContainerKind::Fat,
        ] {
            assert_eq!(
                kind.extraction_mode(),
                ExtractionMode::Payload,
                "{kind:?} should carve real member bytes in-tree"
            );
        }
    }

    #[test]
    fn formerly_external_tool_formats_now_extract_in_tree() {
        for kind in [
            ContainerKind::Flatpak,
            ContainerKind::InnoSetup,
            ContainerKind::InstallShield,
        ] {
            assert_eq!(
                kind.extraction_mode(),
                ExtractionMode::Payload,
                "{kind:?} should extract member bytes in-tree"
            );
        }
    }

    #[test]
    fn only_none_is_unsupported() {
        assert_eq!(
            ContainerKind::None.extraction_mode(),
            ExtractionMode::Unsupported
        );
        for kind in ContainerKind::ALL {
            assert_ne!(
                kind.extraction_mode(),
                ExtractionMode::Unsupported,
                "{kind:?} is a real format but classified Unsupported"
            );
        }
    }
}
