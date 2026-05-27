use miette::Diagnostic;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("DR-MOB-0001: I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DR-MOB-0002: zip read error: {0}")]
    Zip(String),

    #[error("DR-MOB-0003: APK/IPA does not contain expected entry: {0}")]
    EntryMissing(String),

    #[error("DR-MOB-0004: Hermes header truncated (need {need} bytes, got {got})")]
    HermesTruncated { need: usize, got: usize },

    #[error("DR-MOB-0005: Hermes magic mismatch: expected c61fbc03c103191f, got {0:#018x}")]
    HermesBadMagic(u64),

    #[error("DR-MOB-0006: Hermes version {0} not in supported range 60..=96")]
    HermesUnsupportedVersion(u32),

    #[error("DR-MOB-0007: Hermes function table OOB at index {index} of {count}")]
    HermesFunctionOob { index: usize, count: usize },

    #[error("DR-MOB-0008: Hermes string-kind table truncated")]
    HermesStringKindTruncated,

    #[error(
        "DR-MOB-0009: Hermes string-storage OOB: offset {offset}, length {length}, storage size {storage}"
    )]
    HermesStringOob {
        offset: usize,
        length: usize,
        storage: usize,
    },

    #[error("DR-MOB-0010: ELF parse failed: {0}")]
    ElfParse(String),

    #[error(
        "DR-MOB-0011: Dart AOT snapshot magic mismatch (expected dartvm.* / kSnapshotMagic 0xf6f6dcdc)"
    )]
    DartBadMagic,

    #[error("DR-MOB-0012: Dart AOT snapshot version {0:?} unknown (recognised: 2.10..3.5)")]
    DartUnknownVersion(String),

    #[error("DR-MOB-0013: Dart AOT snapshot section {0} missing")]
    DartSectionMissing(&'static str),

    #[error("DR-MOB-0014: Flutter obfuscation map malformed: {0}")]
    FlutterMapMalformed(String),

    #[error("DR-MOB-0015: webview bundle missing required asset {0}")]
    WebviewAssetMissing(&'static str),

    #[error("DR-MOB-0016: NativeScript bundle missing app/bundle.js or app/runtime.js")]
    NativeScriptBundleMissing,

    #[error("DR-MOB-0017: Xamarin assembly store header truncated")]
    XamarinHeaderTruncated,

    #[error("DR-MOB-0018: Mach-O fat magic mismatch (expected 0xcafebabe / 0xcafebabf)")]
    MachOFatBadMagic,

    #[error("DR-MOB-0019: Mach-O fat header truncated (need {need}, got {got})")]
    MachOFatTruncated { need: usize, got: usize },

    #[error("DR-MOB-0020: envelope decode failed: {0}")]
    EnvelopeDecode(String),

    #[error("DR-MOB-0021: input does not match any recognised mobile bundle format")]
    Unrecognised,
}

impl From<zip::result::ZipError> for Error {
    fn from(value: zip::result::ZipError) -> Self {
        Self::Zip(value.to_string())
    }
}
