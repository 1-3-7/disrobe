//! Agile.NET (CliSecure) peel.
//!
//! Algorithm summary (clean-room from de4dot/de4dot.code/deobfuscators/Agile_NET/):
//! * Watermark — `AgileDotNet` / `CliSecure` namespace.
//! * Methods decrypter — encrypted CIL chunks held in a separate native PE section; decrypted
//!   by a CLR-loader-hook native DLL embedded in resources.
//! * String decrypter — per-string Rijndael keyed by the static-cctor magic int.
//! * Has a tier 2 "Agile.NET MX" mode that virtualises methods into a homomorphic VM.
//!
//! Real-fixture availability — paid; native-PE-section encryption requires loader-emulation to
//! extract the inner CIL blobs.

#![allow(clippy::doc_markdown)]

use crate::error::Result;
use crate::peel::{PeelReport, report_only_encrypted_resource};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &["AgileDotNet", "CliSecure"];

pub fn peel_agile_net(bytes: &[u8]) -> Result<PeelReport> {
    report_only_encrypted_resource(
        Protector::AgileNet,
        bytes,
        WATERMARKS,
        "Agile.NET encrypts CIL into a native PE section and uses a CLR-loader-hook DLL to \
         re-inject decrypted bodies at runtime. Strings decrypt via per-string Rijndael keyed \
         by a static-cctor magic int. MX-tier is full VM-virtualisation.",
    )
}
