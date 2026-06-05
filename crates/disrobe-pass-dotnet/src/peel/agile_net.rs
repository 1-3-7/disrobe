//! Agile.NET (CliSecure) peel.

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
