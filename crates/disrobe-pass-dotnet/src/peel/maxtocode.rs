//! MaxToCode peel.
//!
//! Algorithm summary (clean-room from de4dot/de4dot.code/deobfuscators/MaxtoCode/):
//! * Watermark - `MaxtoCode` / `NetSafe`.
//! * Native loader wraps the managed PE with a per-method native decryption stub.
//! * String encryption - per-string XOR with a constant integer.
//! * Resource encryption - Rijndael with a key derived from the loader DLL.
//!
//! Real-fixture availability - paid, mostly seen on Chinese-language scene archives. Native
//! loader extraction needed before static peel is possible.

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
