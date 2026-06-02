//! Eazfuscator.NET (Gapotchenko) peel.
//!
//! Algorithm summary (clean-room from de4dot/de4dot.code/deobfuscators/Eazfuscator_NET/):
//! * String decrypter - single static method `string Decrypt(int)` whose body locates an embedded
//!   resource and applies the version-specific cipher (`StringDecrypter.cs` + `DecrypterType.cs`).
//!   Pre-VM versions used XOR + ROL with key derived from the resource bytes; VM-tier versions
//!   (Eaz 5.0+) emit homomorphic bytecode interpreted by an embedded VM - `DynocodeService.cs`.
//! * Resource resolver - `EmbeddedResource` matching `<Module>{<guid>}` pattern is reflection-
//!   loaded and Inflate'd, then decoded as a per-assembly map.
//! * Anti-tamper - `EfConstantsReader.cs` recognizes the `Mod3` constant-decoder pattern,
//!   reversing constant inlining from the obfuscated CIL.
//!
//! Real-fixture availability - Eazfuscator is a paid product; the homomorphic-VM tier ("eaz5.x+
//! virtualization") is intentionally beyond static deobfuscation. Pre-VM-tier samples sometimes
//! appear on GitHub in malware corpora; treat as red-zone.

#![allow(clippy::doc_markdown)]

use crate::error::Result;
use crate::peel::{PeelReport, report_only_encrypted_resource};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &["Eazfuscator.NET", "EazNet", "<Module>{"];

pub fn peel_eazfuscator(bytes: &[u8]) -> Result<PeelReport> {
    report_only_encrypted_resource(
        Protector::EazfuscatorNet,
        bytes,
        WATERMARKS,
        "Eazfuscator uses a per-assembly EmbeddedResource holding key material; pre-VM strings \
         decrypt via XOR+ROL keyed by the resource bytes. VM-tier (Eaz 5+) is homomorphic \
         bytecode and is documented as PROTECTOR-UNOBTAINABLE for static peeling.",
    )
}
