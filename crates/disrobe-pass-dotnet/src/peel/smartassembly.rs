#![allow(clippy::doc_markdown)]
use crate::error::Result;
use crate::peel::smartassembly_resources::{
    SmartAssemblyResourceOutcome, recover_smartassembly_resources,
};
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
         4 lanes; mode-1 embedded assemblies use a {z} header with chunked raw DEFLATE. The key is \
         a static-cctor ldc.i4 constant recovered by partial CIL evaluation.",
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
    let outcomes: Vec<SmartAssemblyResourceOutcome> = recover_smartassembly_resources(bytes);
    let mut recovered_count: u32 = 0;
    for outcome in outcomes {
        match outcome {
            SmartAssemblyResourceOutcome::Recovered(resource) => {
                recovered_count = recovered_count.saturating_add(1);
                report.recovered_resources.push(resource);
            }
            SmartAssemblyResourceOutcome::Unknown {
                resource_name,
                mode,
            } => report.notes.push(format!(
                "SmartAssembly resource Unknown: {resource_name:?} uses mode 0x{mode:02X}; static resource-compression recovery handles mode 0x01 only"
            )),
            SmartAssemblyResourceOutcome::Rejected {
                resource_name,
                reason,
            } => report.notes.push(format!(
                "SmartAssembly resource rejected: {resource_name:?}: {reason}"
            )),
        }
    }
    if recovered_count != 0 {
        report.strategy = PeelStrategy::EncryptedResourceExtracted;
        report.notes.push(format!(
            "SmartAssembly static resource recovery: restored {recovered_count} managed assembly resource(s) from the chunked raw-DEFLATE container"
        ));
    }
    Ok(report)
}
