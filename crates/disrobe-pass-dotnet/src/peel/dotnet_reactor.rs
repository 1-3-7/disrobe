//! .NET Reactor (Eziriz) peel.

#![allow(clippy::doc_markdown)]

use crate::error::Result;
use crate::peel::{PeelReport, report_only_encrypted_resource};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &[
    "Eziriz",
    ".NET Reactor",
    "protect_resource",
    "Reactor.Compiler",
];

pub fn peel_dotnet_reactor(bytes: &[u8]) -> Result<PeelReport> {
    report_only_encrypted_resource(
        Protector::DotnetReactor,
        bytes,
        WATERMARKS,
        "Reactor encrypts both string and method bodies into AES/Rijndael resources; the runtime \
         decrypter key+IV are embedded in the decrypter method as ldc.i4 constants. A full peel \
         requires CIL execution emulation or a paid sample for fixture-driven testing.",
    )
}
