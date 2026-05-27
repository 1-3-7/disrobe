//! Babel.NET peel.
//!
//! Algorithm summary (clean-room from de4dot/de4dot.code/deobfuscators/Babel_NET/):
//! * Watermark — `BabelAttribute` / `BabelObfuscatorAttribute` decorator at assembly level.
//! * String decrypter — `StringDecrypter.cs` finds a static method `string M(int, int)` whose
//!   body unpacks per-string blobs from an `EmbeddedResource`. The resource is RC4-keyed by the
//!   first 8 bytes of its own SHA-1.
//! * Method bodies — `MethodsDecrypter.cs` rewrites encrypted CIL chunks stored as
//!   `Babel.Module` resource entries; encryption is BlowFish in CFB mode, key derived from the
//!   `ImageReader.cs` PE-header constants.
//! * Constants decrypter — `ConstantsDecrypter.cs` inlines obfuscated `ldc.i4 + xor + add`
//!   chains keyed by a static field initialiser.
//! * Inflater — `BabelInflater.cs` uses a customised zlib variant whose Huffman table is shuffled
//!   at compile time and recovered via `InflaterCreator.cs` pattern scan.
//!
//! Real-fixture availability — Babel is paid. Public samples exist sporadically in malware
//! corpora; full peel requires porting BabelInflater + RC4 + Blowfish-CFB.

#![allow(clippy::doc_markdown)]

use crate::error::Result;
use crate::peel::{PeelReport, report_only_encrypted_resource};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &["BabelAttribute", "BabelObfuscatorAttribute", "Babel.Module"];

pub fn peel_babel_net(bytes: &[u8]) -> Result<PeelReport> {
    report_only_encrypted_resource(
        Protector::BabelDotnet,
        bytes,
        WATERMARKS,
        "Babel encrypts strings via RC4(SHA1(resource)[..8]); method bodies via Blowfish-CFB \
         keyed off PE-header constants; constants via static-field-keyed XOR chains. Inflater \
         tables are shuffled per build and recovered by signature scan.",
    )
}
