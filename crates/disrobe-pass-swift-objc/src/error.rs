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
}
