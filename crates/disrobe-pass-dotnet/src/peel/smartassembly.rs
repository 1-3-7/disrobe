//! SmartAssembly (Red Gate) peel.
//!
//! Algorithm summary (clean-room from de4dot/de4dot.code/deobfuscators/SmartAssembly/):
//! * Watermark - `{smartassembly}` namespace + `PoweredByAttribute` carrying version string.
//! * String decrypter - single static method whose body XORs each character against a constant
//!   key plus the string-index hash (see `StringDecrypter.cs`). Key bytes derived from a magic
//!   integer split into 4 byte-lanes.
//! * Resource resolver - `AssemblyResolver.cs` Inflate-decompresses embedded assemblies stored as
//!   `_<random>` resources. The dictionary mapping resource-name to assembly-display-name is
//!   recoverable from a static initializer.
//! * Identifier renaming - `#=q...` / `#=z...` namespace prefix marks the de-renamed slots in
//!   newer SmartAssembly builds; older builds use Asian Unicode glyphs.
//! * Anti-tampering - `TamperProtectionRemover.cs` reverses MD5-of-PE checks inserted into
//!   `<Module>..cctor`.
//!
//! Real-fixture availability - SmartAssembly's "Community Edition" is gated behind Red Gate
//! licensing. Public benign samples occasionally appear on github (search
//! `is:public extension:dll "PoweredByAttribute"`).

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
