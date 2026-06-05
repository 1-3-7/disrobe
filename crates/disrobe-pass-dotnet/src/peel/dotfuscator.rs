//! Dotfuscator (PreEmptive) peel.

#![allow(clippy::doc_markdown)]

use crate::error::Result;
use crate::peel::{PeelReport, report_only_peel};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &[
    "DotfuscatorAttribute",
    "DotfuscatorEnhanced",
    "DotfuscatorCE",
];

pub fn peel_dotfuscator(bytes: &[u8]) -> Result<PeelReport> {
    report_only_peel(
        Protector::Dotfuscator,
        bytes,
        WATERMARKS,
        vec![
            "Dotfuscator strings: XOR with 4-byte ldc.i4 key (Pro) or plaintext (CE). Marquee \
             feature is overload-induction renaming. CE bundled with Visual Studio."
                .to_string(),
        ],
    )
}
