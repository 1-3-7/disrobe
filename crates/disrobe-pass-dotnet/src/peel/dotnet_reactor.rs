//! .NET Reactor (Eziriz) peel.
//!
//! Algorithm summary (clean-room from de4dot/de4dot.code/deobfuscators/dotNET_Reactor/v4/):
//! * String decrypter — `EncryptedResource` resource named with random GUID-like token;
//!   key + IV embedded in the decrypter method's CIL prologue as `ldc.i4` constants. Decrypts
//!   with Rijndael CBC (PKCS#7), each string indexed by `int32` argument into a length-prefixed
//!   stream.
//! * Methods decrypter — chunks of encrypted CIL stored as a separate `EncryptedResource`;
//!   decrypter runtime hooks `mscorlib!Module.ResolveMethod`.
//! * Native-image unpacker — Reactor 4.8+ wraps the entire managed PE inside a Win32 native loader
//!   that mmaps + Rijndael-decrypts the inner assembly at runtime.
//! * Anti-strong-name + metadata-token obfuscator — shuffles the metadata token table to break
//!   reflection-based introspection.
//!
//! Real-fixture availability — Reactor is a paid product (no free trial DLL output without a
//! licensed binary). We ship report-only peeling against the watermark; full byte rewrite is
//! PR-WELCOME pending a paid sample.

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
