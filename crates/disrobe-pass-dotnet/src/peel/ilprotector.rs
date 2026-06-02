//! ILProtector (SoftLuxor) peel.
//!
//! Algorithm summary (clean-room from de4dot/de4dot.code/deobfuscators/ILProtector/):
//! * Watermark - `_<random>` namespace + native helper DLL named `Protect[32|64].dll`.
//! * Methods - original CIL is replaced by stub `call _<random>` that delegates to the native
//!   DLL which decrypts and returns the real CIL into a runtime-emitted DynamicMethod.
//! * No string encryption beyond the method-body wrapping (strings ride inside the protected
//!   bodies).
//!
//! Real-fixture availability - ILProtector is paid; the native Protect32/Protect64 DLL is
//! required at runtime, making out-of-process emulation the only static-peel route.

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
