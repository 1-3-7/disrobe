//! ILProtector (SoftLuxor) peel.

#![allow(clippy::doc_markdown)]

use crate::error::Result;
use crate::peel::{PeelReport, detect_only_native};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &["Protect32.dll", "Protect64.dll", "ILProtector"];

pub fn peel_ilprotector(bytes: &[u8]) -> Result<PeelReport> {
    detect_only_native(
        Protector::Ilprotector,
        bytes,
        WATERMARKS,
        "ILProtector replaces every method body with `call _<random>` stubs that hand decryption \
         off to a native Protect32/64.dll. The real CIL never lives in the managed PE; static \
         peeling requires native-DLL emulation. PROTECTOR-UNOBTAINABLE for static round-trip.",
    )
}
