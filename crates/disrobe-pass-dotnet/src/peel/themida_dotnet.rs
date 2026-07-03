#![allow(clippy::doc_markdown)]
use crate::debug::dbg_kv;
use crate::error::Result;
use crate::pe::{PeImage, parse};
use crate::peel::native_surface::surface_native_stub;
use crate::peel::{PeelReport, detect_only_native};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &[".vmp0", ".themida", "WinLicense", "Themida"];

const NATIVE_VM_SECTIONS: &[&str] = &[".vmp0", ".vmp1", ".themida", ".winlice", ".boot"];

const BASE_RATIONALE: &str = "Themida-.NET wraps the managed assembly inside the Oreans native VM. Protected method bodies \
     are translated into native VM bytecode and decrypted into RWX memory only at runtime. This is \
     genuine native virtualization; per project policy disrobe does not ship a native-VM \
     devirtualizer (VMP/Themida class). The native-VM-protected methods are walled, not fabricated.";

pub fn peel_themida_dotnet(bytes: &[u8]) -> Result<PeelReport> {
    let mut report: PeelReport =
        detect_only_native(Protector::ThemidaDotnet, bytes, WATERMARKS, BASE_RATIONALE)?;
    report.notes.push(format_static_envelope_note(bytes));
    if let Some(surface) = surface_native_stub(bytes, NATIVE_VM_SECTIONS) {
        report.notes.push(format!(
            "Themida-.NET native surfacing: disassembled the {} native VM section at \
             rva=0x{:x} (file_off=0x{:x}, {} bytes) over a {}-byte window, {} instruction(s) \
             decoded (clean={}). The Oreans VM body is surfaced as native machine code, not \
             devirtualized.",
            surface.section_name,
            surface.section_rva,
            surface.section_file_offset,
            surface.section_size,
            surface.disasm_window_bytes,
            surface.instructions_decoded,
            surface.decode_clean,
        ));
        report.native_surface = Some(surface);
    }
    Ok(report)
}

fn format_static_envelope_note(bytes: &[u8]) -> String {
    let Ok(pe): Result<PeImage> = parse(bytes) else {
        return "Themida-.NET: PE envelope unparsable; native-VM wall stands".to_string();
    };
    let vm_sections: Vec<&str> = pe
        .sections
        .iter()
        .filter_map(|s: &crate::pe::SectionHeader| {
            let name: &str = s.name.trim_end_matches('\0');
            NATIVE_VM_SECTIONS
                .iter()
                .find(|candidate: &&&str| name == **candidate)
                .map(|_| name)
        })
        .collect();
    let total_sections: usize = pe.sections.len();
    dbg_kv("themida-dotnet-wall", || {
        format!(
            "pe_sections={total_sections} native_vm_sections={vm_sections:?} wall=native-vm-virtualization (vmp/themida-class, not devirtualized)"
        )
    });
    format!(
        "Themida-.NET static envelope: parsed {total_sections} PE sections, native-VM sections \
         present={vm_sections:?}. Managed metadata/imports that remain unvirtualized are decoded by \
         the standard CIL path; methods lifted into the native VM are walled (no static \
         devirtualization performed)."
    )
}
