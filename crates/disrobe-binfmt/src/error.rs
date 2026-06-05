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

    #[error("DR-BINFMT-0014: classification failed: {0}")]
    Classify(String),

    #[error(
        "DR-BINFMT-0015: rar archives are detected but not extracted (no Apache-2.0-compatible decoder in tree)"
    )]
    RarNotExtractable,

    #[error("DR-BINFMT-0016: deb archive parse failed: {0}")]
    Deb(String),

    #[error("DR-BINFMT-0017: rpm archive parse failed: {0}")]
    Rpm(String),

    #[error("DR-BINFMT-0018: cab archive parse failed: {0}")]
    Cab(String),

    #[error(
        "DR-BINFMT-0019: pkg archives (macOS installer xar/cpio) are detected but not extracted; use Apple's `pkgutil --expand` or `xar -xf` as an external tool"
    )]
    PkgNoApacheDecoder,

    #[error(
        "DR-BINFMT-0020: dmg archives (Apple Disk Image) are detected but not extracted; use Apple's `hdiutil attach` or `7z` as an external tool"
    )]
    DmgNoApacheDecoder,

    #[error(
        "DR-BINFMT-0021: iso archives (ISO 9660 / Joliet / UDF) are detected but not extracted in this build; mount via the OS or use `7z` as an external tool"
    )]
    IsoNoApacheDecoder,

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

    #[error(
        "DR-BINFMT-0027: missing external tool `{tool}` required for {container}; hint: {hint}"
    )]
    MissingTool {
        container: &'static str,
        tool: &'static str,
        hint: &'static str,
    },

    #[error(
        "DR-BINFMT-0028: container `{kind}` is detected but no Apache-2.0-compatible in-tree decoder ships; hint: {hint}"
    )]
    NoSource {
        kind: &'static str,
        hint: &'static str,
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
}
