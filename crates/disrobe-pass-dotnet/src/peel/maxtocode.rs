//! MaxToCode peel.

#![allow(clippy::doc_markdown)]

use crate::error::Result;
use crate::peel::{PeelReport, detect_only_native};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &["MaxtoCode", "NetSafe"];

pub fn peel_maxtocode(bytes: &[u8]) -> Result<PeelReport> {
    detect_only_native(
        Protector::MaxToCode,
        bytes,
        WATERMARKS,
        "MaxToCode wraps the managed PE with a per-method native decryption stub. Static peel \
         requires loader-emulation. PROTECTOR-UNOBTAINABLE for static round-trip.",
    )
}
