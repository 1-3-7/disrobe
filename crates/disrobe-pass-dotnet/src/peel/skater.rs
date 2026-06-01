//! Skater.NET (RustemSoft) peel.
//!
//! Algorithm summary (clean-room from de4dot/de4dot.code/deobfuscators/Skater_NET/):
//! * Watermark - `RustemSoft.Skater` / `SkaterObfuscator` strings.
//! * String decrypter - base64 then per-char XOR with a single-byte key kept in a static field.
//! * Renamer - sequential `a`/`b`/`c` short-identifier substitution.
//! * No CFF, no resource encryption.
//!
//! Real-fixture availability - Skater is a low-tier paid protector; public demo binaries are
//! available from rustemsoft.com but require manual download (no scriptable mirror).

#![allow(clippy::doc_markdown)]

use crate::error::Result;
use crate::peel::{PeelReport, report_only_peel};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &["RustemSoft.Skater", "SkaterObfuscator"];

pub fn peel_skater(bytes: &[u8]) -> Result<PeelReport> {
    report_only_peel(
        Protector::Skater,
        bytes,
        WATERMARKS,
        vec![
            "Skater.NET strings: base64 + per-char XOR with a single byte key. Sequential a/b/c \
             renames. No CFF / no resource encryption."
                .to_string(),
        ],
    )
}
