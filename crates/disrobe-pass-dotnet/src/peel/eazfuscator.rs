//! Eazfuscator.NET (Gapotchenko) peel.

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
