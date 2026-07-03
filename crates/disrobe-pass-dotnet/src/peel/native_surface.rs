#![allow(clippy::doc_markdown)]
use disrobe_pass_native::{Arch, DisasmInsn, disassemble};
use serde::{Deserialize, Serialize};

use crate::pe::{ClrHeader, PeBitness, PeImage, SectionHeader, parse, parse_clr_header};

const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

const MAX_DISASM_BYTES: usize = 4096;
const MAX_SURFACED_INSNS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeStubSurface {
    pub section_name: String,
    pub section_rva: u32,
    pub section_file_offset: u32,
    pub section_size: u32,
    pub arch: NativeArch,
    pub disasm_window_bytes: u32,
    pub instructions_decoded: u32,
    pub decode_clean: bool,
    pub disasm: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeArch {
    X86,
    X86_64,
}

impl NativeArch {
    const fn to_native(self) -> Arch {
        match self {
            Self::X86 => Arch::X86,
            Self::X86_64 => Arch::X86_64,
        }
    }
}

#[must_use]
pub fn surface_native_stub(image: &[u8], section_name_hints: &[&str]) -> Option<NativeStubSurface> {
    let pe: PeImage = parse(image).ok()?;
    let arch: NativeArch = match pe.bitness {
        PeBitness::Pe32 => NativeArch::X86,
        PeBitness::Pe32Plus => NativeArch::X86_64,
    };
    let clr: Option<ClrHeader> = parse_clr_header(image, &pe).ok();
    let managed_metadata_rva: u32 = clr.map_or(0, |c: ClrHeader| c.metadata.rva);

    let target: &SectionHeader =
        select_native_section(&pe, section_name_hints, managed_metadata_rva)?;
    let file_offset: usize = pe.rva_to_offset(target.virtual_address)?;
    let avail: usize = target.raw_size as usize;
    let window: usize = avail.min(MAX_DISASM_BYTES);
    let end: usize = file_offset.checked_add(window)?.min(image.len());
    if end <= file_offset {
        return None;
    }
    let code: &[u8] = &image[file_offset..end];
    let base: u64 = pe
        .image_base
        .wrapping_add(u64::from(target.virtual_address));
    let insns: Vec<DisasmInsn> = disassemble(arch.to_native(), base, code).ok()?;
    let decoded_bytes: usize = insns.iter().map(|i: &DisasmInsn| i.bytes.len()).sum();
    let decode_clean: bool = decoded_bytes == code.len() && !insns.is_empty();

    let disasm: Vec<String> = insns
        .iter()
        .take(MAX_SURFACED_INSNS)
        .map(format_insn)
        .collect();

    Some(NativeStubSurface {
        section_name: target.name.trim_end_matches('\0').to_string(),
        section_rva: target.virtual_address,
        section_file_offset: u32::try_from(file_offset).unwrap_or(u32::MAX),
        section_size: target.virtual_size.max(target.raw_size),
        arch,
        disasm_window_bytes: u32::try_from(window).unwrap_or(u32::MAX),
        instructions_decoded: u32::try_from(insns.len()).unwrap_or(u32::MAX),
        decode_clean,
        disasm,
    })
}

fn select_native_section<'a>(
    pe: &'a PeImage,
    hints: &[&str],
    managed_metadata_rva: u32,
) -> Option<&'a SectionHeader> {
    let named: Option<&SectionHeader> = pe.sections.iter().find(|s: &&SectionHeader| {
        let name: &str = s.name.trim_end_matches('\0');
        hints.contains(&name) && s.raw_size > 0
    });
    if named.is_some() {
        return named;
    }
    pe.sections.iter().find(|s: &&SectionHeader| {
        let is_code: bool = s.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) != 0;
        let holds_metadata: bool = managed_metadata_rva != 0
            && managed_metadata_rva >= s.virtual_address
            && managed_metadata_rva
                < s.virtual_address
                    .saturating_add(s.virtual_size.max(s.raw_size));
        is_code && !holds_metadata && s.raw_size > 0
    })
}

fn format_insn(insn: &DisasmInsn) -> String {
    use std::fmt::Write as _;
    let mut hex: String = String::with_capacity(insn.bytes.len() * 2);
    for b in &insn.bytes {
        let _ = write!(hex, "{b:02x}");
    }
    if insn.operands.is_empty() {
        format!("0x{:08x}: {hex:<16} {}", insn.address, insn.mnemonic)
    } else {
        format!(
            "0x{:08x}: {hex:<16} {} {}",
            insn.address, insn.mnemonic, insn.operands
        )
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn native_arch_maps_to_native_crate_arch() {
        assert_eq!(NativeArch::X86.to_native(), Arch::X86);
        assert_eq!(NativeArch::X86_64.to_native(), Arch::X86_64);
    }

    #[test]
    fn format_insn_renders_address_hex_and_text() {
        let insn: DisasmInsn = DisasmInsn {
            address: 0x0040_1000,
            bytes: vec![0x55],
            mnemonic: "push".to_string(),
            operands: "rbp".to_string(),
        };
        let line: String = format_insn(&insn);
        assert!(line.contains("0x00401000"));
        assert!(line.contains("55"));
        assert!(line.contains("push rbp"));
    }
}
