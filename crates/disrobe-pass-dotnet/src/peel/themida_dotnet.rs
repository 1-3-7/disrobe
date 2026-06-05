//! Themida (.NET wrapper) peel.

#![allow(clippy::doc_markdown)]

use crate::error::Result;
use crate::peel::{PeelReport, detect_only_native};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &[".vmp0", ".themida", "WinLicense", "Themida"];

pub fn peel_themida_dotnet(bytes: &[u8]) -> Result<PeelReport> {
    detect_only_native(
        Protector::ThemidaDotnet,
        bytes,
        WATERMARKS,
        "Themida-.NET embeds the managed assembly inside the Oreans VM-protected native loader. \
         The CIL is decrypted only at runtime into RWX memory. Static peeling is structurally \
         impossible. PROTECTOR-UNOBTAINABLE.",
    )
}
