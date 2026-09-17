#![allow(clippy::doc_markdown)]
use crate::debug::dbg_kv;
use crate::error::Result;
use crate::peel::string_emu::{RecoveredString, recover_emulated_strings};
use crate::peel::{
    HeapsView, PeelReport, PeelStrategy, apply_eazvm_tier, read_heaps,
    report_only_encrypted_resource,
};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &["Eazfuscator.NET", "EazNet", "<Module>{"];

const RESOURCE_NOTE: &str = "Eazfuscator uses a per-assembly EmbeddedResource holding key material; pre-VM strings \
     decrypt via a static char[]/byte[] transform method. The VM-tier replaces method bodies with \
     stubs that dispatch a position-keyed encrypted virtual-instruction stream through a per-build \
     randomized opcode table.";

pub fn peel_eazfuscator(bytes: &[u8]) -> Result<PeelReport> {
    let mut report: PeelReport = report_only_encrypted_resource(
        Protector::EazfuscatorNet,
        bytes,
        WATERMARKS,
        RESOURCE_NOTE,
    )?;
    let heaps: HeapsView = read_heaps(bytes)?;
    let recovered: Vec<RecoveredString> = recover_emulated_strings(bytes, &heaps.us_strings);
    dbg_kv("eazfuscator-strings", || {
        format!(
            "us_literals={} emulated_decryptor_recovered={}",
            heaps.us_strings.len(),
            recovered.len()
        )
    });
    if recovered.is_empty() {
        report.notes.push(
            "Eazfuscator static string-emulation: no emulatable char[]/byte[] decryptor method \
             found over the #US literals (assembly is VM-tier or strings are runtime-keyed)"
                .to_string(),
        );
    } else {
        report.strategy = PeelStrategy::EncryptedResourceExtracted;
        report.notes.push(format!(
            "Eazfuscator static string-emulation: recovered {} string literal(s) by locating the \
             in-assembly decryptor method and emulating its CIL over the encrypted #US table",
            recovered.len(),
        ));
        report.recovered_strings = recovered;
    }

    apply_eazvm_tier(bytes, &mut report, "Eazfuscator");

    Ok(report)
}
