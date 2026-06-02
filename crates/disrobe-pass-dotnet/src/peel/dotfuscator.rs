//! Dotfuscator (PreEmptive) peel.
//!
//! Algorithm summary (clean-room from de4dot/de4dot.code/deobfuscators/Dotfuscator/):
//! * Watermark - `DotfuscatorAttribute` / `DotfuscatorEnhanced` / `DotfuscatorCE`.
//! * String decrypter - XOR-based with key derived from a 4-byte constant embedded in the
//!   `decrypt` method. Older Community-Edition emits plaintext strings - only renames.
//! * Renamer - overload-induction (multiple distinct methods all renamed to `a`/`b` differing
//!   only in signature), the marquee Dotfuscator feature.
//! * No CFF in CE; Pro tier ships full control-flow flattening.
//!
//! Real-fixture availability - Dotfuscator Community Edition ships with Visual Studio (free).
//! CE samples are easy to obtain; Pro is paid.

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
