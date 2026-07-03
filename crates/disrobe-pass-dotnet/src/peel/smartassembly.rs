#![allow(clippy::doc_markdown)]
use crate::error::Result;
use crate::peel::smartassembly_strings::{SmartAssemblyStrings, recover_smartassembly_strings};
use crate::peel::string_emu::RecoveredString;
use crate::peel::{PeelReport, PeelStrategy, report_only_encrypted_resource};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &[
    "SmartAssembly.Attributes",
    "PoweredByAttribute",
    "{smartassembly}",
    "#=q",
    "#=z",
];

pub fn peel_smartassembly(bytes: &[u8]) -> Result<PeelReport> {
    let mut report: PeelReport = report_only_encrypted_resource(
        Protector::SmartAssembly,
        bytes,
        WATERMARKS,
        "SmartAssembly decrypts strings via per-string XOR against a 32-bit magic key split into \
         4 lanes; embedded assemblies are zlib-Inflate'd from `_<random>` resources. The key is a \
         static-cctor ldc.i4 constant recovered by partial CIL evaluation.",
    )?;
    let recovery: SmartAssemblyStrings =
        recover_smartassembly_strings(bytes).unwrap_or_else(|_| SmartAssemblyStrings::empty());
    if let Some(key) = recovery.key {
        report.strategy = PeelStrategy::EncryptedResourceExtracted;
        report.recovered_strings = recovery
            .recovered
            .iter()
            .map(
                |r: &crate::peel::smartassembly_strings::RecoveredString| RecoveredString {
                    method_token: 0,
                    method_name: ".cctor".to_string(),
                    text: r.text.clone(),
                },
            )
            .collect();
        report.notes.push(format!(
            "SmartAssembly static-key string recovery: cctor XOR key=0x{key:08x} recovered {} \
             literal(s) from the #US heap",
            recovery.recovered.len(),
        ));
    }
    Ok(report)
}
