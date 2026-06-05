//! CryptoObfuscator (LogicNP) peel.

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
