#![allow(clippy::doc_markdown)]
use crate::error::Result;
use crate::peel::skater_strings::{SkaterStrings, recover_skater_strings};
use crate::peel::string_emu::RecoveredString;
use crate::peel::{PeelReport, PeelStrategy, report_only_peel};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &["RustemSoft.Skater", "SkaterObfuscator"];

pub fn peel_skater(bytes: &[u8]) -> Result<PeelReport> {
    let mut report: PeelReport = report_only_peel(
        Protector::Skater,
        bytes,
        WATERMARKS,
        vec![
            "Skater.NET strings: base64 + per-char XOR with a single byte key recovered from the \
             static ldc.i4 constant. Sequential a/b/c renames. No CFF / no resource encryption."
                .to_string(),
        ],
    )?;
    let recovery: SkaterStrings =
        recover_skater_strings(bytes).unwrap_or_else(|_| SkaterStrings::empty());
    if let Some(key) = recovery.key {
        report.strategy = PeelStrategy::EncryptedResourceExtracted;
        report.recovered_strings = recovery
            .recovered
            .iter()
            .map(
                |r: &crate::peel::skater_strings::RecoveredString| RecoveredString {
                    method_token: 0,
                    method_name: "Skater.Decode".to_string(),
                    text: r.text.clone(),
                },
            )
            .collect();
        report.notes.push(format!(
            "Skater.NET static-key string recovery: base64 + single-byte XOR key=0x{key:02x} \
             recovered {} literal(s)",
            recovery.recovered.len(),
        ));
    }
    Ok(report)
}
