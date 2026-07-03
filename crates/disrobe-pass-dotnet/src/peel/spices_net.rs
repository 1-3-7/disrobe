#![allow(clippy::doc_markdown)]
use crate::error::Result;
use crate::peel::spices_strings::{SpicesRecovery, recover_spices};
use crate::peel::string_emu::RecoveredString;
use crate::peel::{PeelReport, PeelStrategy, report_only_peel};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &["9rays.Net", "Spices.Net"];

pub fn peel_spices_net(bytes: &[u8]) -> Result<PeelReport> {
    let mut report: PeelReport = report_only_peel(
        Protector::SpicesNet,
        bytes,
        WATERMARKS,
        vec![
            "Spices.Net uses Cyrillic-homoglyph renames + per-method ROT-N string scrambles; \
             code-flow is goto-shuffling only (no opaque predicates). The homoglyph table unmaps \
             identifiers and the ROT-N shift recovers the literals."
                .to_string(),
        ],
    )?;
    let recovery: SpicesRecovery =
        recover_spices(bytes).unwrap_or_else(|_| SpicesRecovery::empty());
    if recovery.rot_shift.is_some() || !recovery.homoglyph_unmapped.is_empty() {
        if recovery.rot_shift.is_some() {
            report.strategy = PeelStrategy::EncryptedResourceExtracted;
        }
        report.recovered_strings = recovery
            .recovered_strings
            .iter()
            .map(
                |r: &crate::peel::spices_strings::RecoveredString| RecoveredString {
                    method_token: 0,
                    method_name: "Spices.RotN".to_string(),
                    text: r.text.clone(),
                },
            )
            .collect();
        report.notes.push(format!(
            "Spices.Net recovery: rot_shift={:?} strings_recovered={} homoglyph_names_unmapped={}",
            recovery.rot_shift,
            recovery.recovered_strings.len(),
            recovery.homoglyph_unmapped.len(),
        ));
    }
    Ok(report)
}
