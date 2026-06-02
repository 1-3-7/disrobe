//! DeepSea peel.
//!
//! Algorithm summary (clean-room from de4dot/de4dot.code/deobfuscators/DeepSea/):
//! * Watermark - `DeepSeaObfuscator` attribute / version-blob in the manifest module.
//! * String decrypter - multiple versions; v1.x uses XOR with a 32-bit key embedded in the
//!   decrypter method's prologue, v3+ uses Rijndael-CBC keyed by a method-specific GUID.
//! * Resource resolver - `Lzma`-compressed assemblies stored as embedded resources.
//! * Anti-debug - `Environment.GetEnvironmentVariable("COR_PROFILER")` check + window-class
//!   scan.
//!
//! Real-fixture availability - DeepSea was discontinued; binaries circulate on niche scene
//! boards but no longer on the official site.

#![allow(clippy::doc_markdown)]

use crate::error::Result;
use crate::peel::{PeelReport, report_only_peel};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &["DeepSea", "DeepSeaObfuscator"];

pub fn peel_deepsea(bytes: &[u8]) -> Result<PeelReport> {
    report_only_peel(
        Protector::DeepSea,
        bytes,
        WATERMARKS,
        vec![
            "DeepSea strings: XOR-32bit-key (v1.x) or Rijndael-CBC (v3+). Resources: LZMA. \
             Discontinued protector, fixtures sourced from scene archives only."
                .to_string(),
        ],
    )
}
