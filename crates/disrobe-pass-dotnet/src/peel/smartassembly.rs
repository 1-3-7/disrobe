//! SmartAssembly (Red Gate) peel.

#![allow(clippy::doc_markdown)]

use crate::error::Result;
use crate::peel::{PeelReport, report_only_encrypted_resource};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &[
    "SmartAssembly.Attributes",
    "PoweredByAttribute",
    "{smartassembly}",
    "#=q",
    "#=z",
];

pub fn peel_smartassembly(bytes: &[u8]) -> Result<PeelReport> {
    report_only_encrypted_resource(
        Protector::SmartAssembly,
        bytes,
        WATERMARKS,
        "SmartAssembly decrypts strings via per-string XOR against a 32-bit magic key split into \
         4 lanes; embedded assemblies are zlib-Inflate'd from `_<random>` resources. A full peel \
         requires resolving the static-cctor key constant via partial CIL evaluation.",
    )
}
