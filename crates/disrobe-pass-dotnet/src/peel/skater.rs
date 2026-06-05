//! Skater.NET (RustemSoft) peel.

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
