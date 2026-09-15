use miette::Diagnostic;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("DR-IOS-0001: I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DR-IOS-0002: IPA zip-read error: {0}")]
    Ipa(String),

    #[error("DR-IOS-0003: input is not an IPA (Payload/<app>.app/<bin> layout not found)")]
    NotAnIpa,

    #[error("DR-IOS-0004: input is not a Mach-O image (no recognized magic at offset 0)")]
    NotMachO,

    #[error("DR-IOS-0005: Mach-O image truncated at offset {0}")]
    Truncated(usize),

    #[error("DR-IOS-0006: Mach-O fat header malformed: {0}")]
    BadFatHeader(String),

    #[error("DR-IOS-0007: Mach-O load-command walk failed at index {0}: {1}")]
    LoadCommand(usize, String),

    #[error("DR-IOS-0008: section '{seg},{sect}' missing or empty")]
    MissingSection { seg: String, sect: String },

    #[error("DR-IOS-0009: plist parse error: {0}")]
    Plist(String),

    #[error("DR-IOS-0010: entitlements blob (CMS/Magic 0xFADE7171) not found in code-signature")]
    NoEntitlementsBlob,

    #[error("DR-IOS-0011: Swift demangle failed on symbol '{0}'")]
    Demangle(String),

    #[error("DR-IOS-0012: utf-8 decode error in section data at offset {0}")]
    Utf8(usize),

    #[error(
        "DR-IOS-0013: input is not a Swift serialized module (signature 0xE2 0x9C 0xA8 0x0E absent)"
    )]
    NotSwiftModule,

    #[error("DR-IOS-0014: Swift module bitstream malformed: {0}")]
    BadBitstream(String),

    #[error("DR-IOS-0015: input is not a dyld shared cache (magic 'dyld_v1' prefix absent)")]
    NotDyldCache,

    #[error("DR-IOS-0016: dyld shared cache malformed: {0}")]
    BadDyldCache(String),

    #[error(
        "DR-IOS-0017: Swift demangle of '{symbol}' read {consumed} of {total} bytes and left the \
         rest unread, so the recovered text is not a complete reading of the symbol"
    )]
    DemangleResidue {
        symbol: String,
        consumed: usize,
        total: usize,
    },

    #[error("DR-IOS-0018: dyld shared cache header layout '{layout}' is not supported: {reason}")]
    UnsupportedDyldLayout { layout: String, reason: String },

    #[error(
        "DR-IOS-0019: dyld shared cache slide-info version {0} is not supported; supported \
         versions are 1, 2, 3, 4 and 5"
    )]
    UnsupportedDyldSlideInfo(u32),

    #[error(
        "DR-IOS-0020: dyld sub-cache file suffix '{suffix}' is refused because {reason}; sibling \
         files are located by computed name relative to the primary cache and never by a path \
         taken from cache content"
    )]
    DyldSubCachePathRejected { suffix: String, reason: String },

    #[error("DR-IOS-0021: dyld shared cache image '{image}' cannot be reconstructed: {reason}")]
    DyldImageUnsupported { image: String, reason: String },
}
