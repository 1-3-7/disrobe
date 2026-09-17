#![allow(clippy::doc_markdown)]
use crate::error::Result;
use crate::peel::protector_resources::{ResourceStringRecovery, recover_crypto_obfuscator_strings};
use crate::peel::{
    PeelReport, PeelStrategy, report_only_encrypted_resource, try_managed_string_decryptor,
};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &["CryptoObfuscator", "LogicNP"];

pub fn peel_crypto_obfuscator(bytes: &[u8]) -> Result<PeelReport> {
    let mut report: PeelReport = report_only_encrypted_resource(
        Protector::CryptoObfuscator,
        bytes,
        WATERMARKS,
        "CryptoObfuscator stores its strings in an embedded resource encrypted with DES-CBC; the \
         IV and key are written inline at the head of the resource and the records are \
         varint-length-prefixed UTF-16. The static IV+key are read straight from the resource and \
         fed to the DES engine below.",
    )?;
    try_managed_string_decryptor(&mut report, bytes, "CryptoObfuscator");
    apply_resource_strings(&mut report, recover_crypto_obfuscator_strings(bytes));
    Ok(report)
}

pub(crate) fn apply_resource_strings(
    report: &mut PeelReport,
    recovery: Option<ResourceStringRecovery>,
) {
    let Some(recovery): Option<ResourceStringRecovery> = recovery else {
        return;
    };
    if !recovery.strings.is_empty() {
        let token: u32 = 0;
        for text in &recovery.strings {
            report
                .recovered_strings
                .push(crate::peel::string_emu::RecoveredString {
                    method_token: token,
                    method_name: recovery.resource_name.clone(),
                    text: text.clone(),
                });
        }
        report.strategy = PeelStrategy::EncryptedResourceExtracted;
        report.notes.push(format!(
            "resource string recovery: decrypted {} literal(s) from resource {:?} ({}; {} bytes)",
            recovery.strings.len(),
            recovery.resource_name,
            recovery.scheme,
            recovery.resource_size,
        ));
    }
    if let Some(wall) = recovery.dynamic_wall {
        report.notes.push(format!(
            "resource string recovery walled for resource {:?}: {wall}",
            recovery.resource_name,
        ));
    }
}
