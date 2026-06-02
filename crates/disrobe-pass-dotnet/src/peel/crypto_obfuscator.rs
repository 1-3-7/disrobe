//! CryptoObfuscator (LogicNP) peel.
//!
//! Algorithm summary (clean-room from de4dot/de4dot.code/deobfuscators/CryptoObfuscator/):
//! * Watermark - `CryptoObfuscator` / `LogicNP` types.
//! * String decrypter - single static method takes `(string, int)` and decrypts via Triple-DES
//!   keyed by a per-assembly seed embedded as a static-field initialiser.
//! * Resource resolver - embedded assemblies stored as DES-encrypted resources; key derived
//!   from assembly version + culture.
//! * Renamer - uses Cyrillic + Arabic homoglyphs and very long random-style ASCII names.
//! * Anti-debug - `Debugger.IsAttached` removal pass.
//!
//! Real-fixture availability - paid; public benign samples occasionally on GitHub.

#![allow(clippy::doc_markdown)]

use crate::error::Result;
use crate::peel::{PeelReport, report_only_encrypted_resource};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &["CryptoObfuscator", "LogicNP"];

pub fn peel_crypto_obfuscator(bytes: &[u8]) -> Result<PeelReport> {
    report_only_encrypted_resource(
        Protector::CryptoObfuscator,
        bytes,
        WATERMARKS,
        "CryptoObfuscator strings: 3DES keyed by per-assembly seed. Resources: DES keyed by \
         assembly version+culture. Homoglyph + long-ASCII renamer.",
    )
}
