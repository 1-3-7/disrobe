use miette::Diagnostic;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("DR-BINFMT-0001: I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DR-BINFMT-0002: container not recognized")]
    UnknownContainer,

    #[error("DR-BINFMT-0003: zip parse failed: {0}")]
    Zip(String),

    #[error("DR-BINFMT-0004: zip entry `{name}` failed: {reason}")]
    ZipEntry { name: String, reason: String },

    #[error("DR-BINFMT-0005: tar parse failed: {0}")]
    Tar(String),

    #[error("DR-BINFMT-0006: 7z parse failed: {0}")]
    SevenZ(String),

    #[error("DR-BINFMT-0007: payload decompression failed: {0}")]
    Decompression(String),

    #[error("DR-BINFMT-0008: archive entry path escapes container root: {0}")]
    UnsafeEntryPath(String),

    #[error("DR-BINFMT-0009: extraction quota exceeded on entry `{entry}`: {reason}")]
    QuotaExceeded { entry: String, reason: String },

    #[error("DR-BINFMT-0010: asar header malformed: {0}")]
    AsarHeader(String),

    #[error("DR-BINFMT-0011: asar entry `{name}` out of bounds")]
    AsarOutOfBounds { name: String },

    #[error("DR-BINFMT-0012: unsupported container kind for extraction: {0:?}")]
    UnsupportedContainer(&'static str),

    #[error("DR-BINFMT-0013: json manifest parse failed: {0}")]
    Json(#[from] serde_json::Error),

    #[error(
        "DR-BINFMT-0015: rar header did not parse; the in-tree decoder handles stored entries and the rar5 LZ codec, and no external unrar/7-Zip was available to attempt the remaining variants"
    )]
    RarNotExtractable,

    #[error("DR-BINFMT-0016: deb archive parse failed: {0}")]
    Deb(String),

    #[error("DR-BINFMT-0017: rpm archive parse failed: {0}")]
    Rpm(String),

    #[error("DR-BINFMT-0018: cab archive parse failed: {0}")]
    Cab(String),

    #[error("DR-BINFMT-0022: native binary parse failed: {0}")]
    NativeParse(String),

    #[error("DR-BINFMT-0023: external tool `{tool}` is not installed or not on PATH")]
    ExternalToolMissing { tool: &'static str },

    #[error("DR-BINFMT-0024: external tool `{tool}` failed (exit={exit}): {stderr}")]
    ExternalToolFailed {
        tool: &'static str,
        exit: i32,
        stderr: String,
    },

    #[error("DR-BINFMT-0025: external tool `{tool}` timed out after {seconds}s")]
    ExternalToolTimeout { tool: &'static str, seconds: u64 },

    #[error("DR-BINFMT-0026: external tool `{tool}` not supported on host platform `{platform}`")]
    ExternalToolUnsupported {
        tool: &'static str,
        platform: &'static str,
    },

    #[error("DR-BINFMT-0029: appimage parse failed: {0}")]
    AppImage(String),

    #[error("DR-BINFMT-0030: snap (squashfs) parse failed: {0}")]
    Snap(String),

    #[error("DR-BINFMT-0031: msi parse failed: {0}")]
    Msi(String),

    #[error("DR-BINFMT-0032: msix/appx parse failed: {0}")]
    Msix(String),

    #[error("DR-BINFMT-0033: nsis parse failed: {0}")]
    Nsis(String),

    #[error("DR-BINFMT-0034: oci/docker manifest parse failed: {0}")]
    OciManifest(String),

    #[error("DR-BINFMT-0035: squirrel installer parse failed: {0}")]
    Squirrel(String),

    #[error("DR-BINFMT-0036: innosetup parse failed: {0}")]
    InnoSetup(String),

    #[error("DR-BINFMT-0037: installshield parse failed: {0}")]
    InstallShield(String),

    #[error("DR-BINFMT-0038: squashfs parse failed: {0}")]
    Squashfs(String),

    #[error("DR-BINFMT-0039: cramfs parse failed: {0}")]
    Cramfs(String),

    #[error("DR-BINFMT-0040: ext4 parse failed: {0}")]
    Ext4(String),

    #[error("DR-BINFMT-0042: flatpak/ostree parse failed: {0}")]
    Flatpak(String),

    #[error("DR-BINFMT-0043: vendor firmware parse/decrypt failed: {0}")]
    Firmware(String),

    #[error("DR-BINFMT-0044: romfs parse failed: {0}")]
    Romfs(String),

    #[error("DR-BINFMT-0045: minix filesystem parse failed: {0}")]
    Minixfs(String),

    #[error("DR-BINFMT-0046: android sparse image parse failed: {0}")]
    Sparse(String),

    #[error("DR-BINFMT-0047: btrfs send stream replay failed: {0}")]
    BtrfsSend(String),

    #[error("DR-BINFMT-0048: erofs parse failed: {0}")]
    Erofs(String),

    #[error("DR-BINFMT-0049: jffs2 parse failed: {0}")]
    Jffs2(String),

    #[error("DR-BINFMT-0050: ntfs parse failed: {0}")]
    Ntfs(String),

    #[error("DR-BINFMT-0051: yaffs parse failed: {0}")]
    Yaffs(String),

    #[error("DR-BINFMT-0052: ubi/ubifs parse failed: {0}")]
    Ubifs(String),

    #[error("DR-BINFMT-0053: ar archive parse failed: {0}")]
    Ar(String),

    #[error("DR-BINFMT-0054: arj archive parse failed: {0}")]
    Arj(String),

    #[error("DR-BINFMT-0055: arc archive parse failed: {0}")]
    Arc(String),

    #[error("DR-BINFMT-0056: lzh/lha archive parse failed: {0}")]
    Lzh(String),

    #[error("DR-BINFMT-0057: lzop file parse failed: {0}")]
    Lzop(String),

    #[error("DR-BINFMT-0058: uzip disk image parse failed: {0}")]
    Uzip(String),

    #[error("DR-BINFMT-0059: xalz (xamarin) assembly parse failed: {0}")]
    Xalz(String),

    #[error("DR-BINFMT-0060: par2 recovery set parse failed: {0}")]
    Par2(String),

    #[error("DR-BINFMT-0061: elf overlay carve failed: {0}")]
    ElfOverlay(String),

    #[error("DR-BINFMT-0062: partclone image parse failed: {0}")]
    Partclone(String),

    #[error("DR-BINFMT-0063: stuffit archive parse failed: {0}")]
    StuffIt(String),

    #[error("DR-BINFMT-0064: qnx image parse failed: {0}")]
    Qnx(String),
}
