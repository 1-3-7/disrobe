use disrobe_pass_native::{Arch, DisasmInsn, disassemble};
use serde::{Deserialize, Serialize};

use crate::debug;
use crate::functions::RecoveredFunction;
use crate::image::{CodeArch, NativeImage, Section};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisasmInstruction {
    pub address: u64,
    pub bytes: String,
    pub mnemonic: String,
    pub operands: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionListing {
    pub native_name: String,
    pub recovered_name: String,
    pub start: u64,
    pub end: u64,
    pub byte_len: u64,
    pub instructions: Vec<DisasmInstruction>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisasmListing {
    pub arch_supported: bool,
    pub listings: Vec<FunctionListing>,
}

impl DisasmListing {
    #[must_use]
    pub const fn unsupported() -> Self {
        Self {
            arch_supported: false,
            listings: Vec::new(),
        }
    }
}

const MAX_LISTED_FUNCTIONS: usize = 4096;
const MAX_FUNCTION_BYTES: u64 = 256 * 1024;
const MAX_INSTRUCTIONS_PER_FUNCTION: usize = 8192;

#[must_use]
pub fn disassemble_functions(
    image: &NativeImage<'_>,
    functions: &[RecoveredFunction],
) -> DisasmListing {
    debug::dbg_section("disasm");
    let Some(arch): Option<Arch> = map_arch(image.arch) else {
        debug::dbg_line(|| {
            format!(
                "disasm wall: arch {:?} has no in-house decoder; carve+disasm skipped",
                image.arch
            )
        });
        return DisasmListing::unsupported();
    };
    let mut sorted_starts: Vec<u64> = functions
        .iter()
        .filter(|f: &&RecoveredFunction| f.address_assigned)
        .map(|f: &RecoveredFunction| f.start)
        .collect();
    sorted_starts.sort_unstable();
    sorted_starts.dedup();

    let mut listings: Vec<FunctionListing> = Vec::new();
    for func in functions {
        if listings.len() >= MAX_LISTED_FUNCTIONS {
            break;
        }
        if !func.address_assigned {
            continue;
        }
        let Some(end): Option<u64> = end_boundary(image, func, &sorted_starts) else {
            continue;
        };
        let Some(code): Option<&[u8]> = carve(image, func.start, end) else {
            continue;
        };
        let byte_len: u64 = code.len() as u64;
        let Ok(decoded): Result<Vec<DisasmInsn>, _> = disassemble(arch, func.start, code) else {
            continue;
        };
        let truncated: bool = decoded.len() > MAX_INSTRUCTIONS_PER_FUNCTION;
        let instructions: Vec<DisasmInstruction> = decoded
            .into_iter()
            .take(MAX_INSTRUCTIONS_PER_FUNCTION)
            .map(render_insn)
            .collect();
        if instructions.is_empty() {
            continue;
        }
        listings.push(FunctionListing {
            native_name: func.demangled.as_ref().map_or_else(
                || func.name.clone(),
                |_| func.signature.clone().unwrap_or_else(|| func.name.clone()),
            ),
            recovered_name: func.name.clone(),
            start: func.start,
            end,
            byte_len,
            instructions,
            truncated,
        });
    }
    debug::dbg_kv("disasm-listings", || listings.len().to_string());
    DisasmListing {
        arch_supported: true,
        listings,
    }
}

fn end_boundary(
    image: &NativeImage<'_>,
    func: &RecoveredFunction,
    sorted_starts: &[u64],
) -> Option<u64> {
    if let Some(end) = func.end.filter(|e: &u64| *e > func.start) {
        return Some(end);
    }
    let next_start: Option<u64> = sorted_starts
        .iter()
        .copied()
        .find(|s: &u64| *s > func.start);
    let section_end: Option<u64> = image
        .sections
        .iter()
        .find(|s: &&Section<'_>| {
            let sec_end: u64 = s.address.saturating_add(s.data.len() as u64);
            !s.data.is_empty() && func.start >= s.address && func.start < sec_end
        })
        .map(|s: &Section<'_>| s.address.saturating_add(s.data.len() as u64));
    let inferred: u64 = match (next_start, section_end) {
        (Some(n), Some(s)) => n.min(s),
        (Some(n), None) => n,
        (None, Some(s)) => s,
        (None, None) => return None,
    };
    if inferred <= func.start {
        return None;
    }
    Some(inferred.min(func.start.saturating_add(MAX_FUNCTION_BYTES)))
}

const fn map_arch(arch: CodeArch) -> Option<Arch> {
    match arch {
        CodeArch::X86 => Some(Arch::X86),
        CodeArch::X86_64 => Some(Arch::X86_64),
        CodeArch::Aarch64 => Some(Arch::Aarch64),
        CodeArch::Other => None,
    }
}

fn carve<'a>(image: &NativeImage<'a>, start: u64, end: u64) -> Option<&'a [u8]> {
    let len: u64 = end.checked_sub(start)?;
    if len == 0 || len > MAX_FUNCTION_BYTES {
        return None;
    }
    let section: &Section<'a> = image.sections.iter().find(|s: &&Section<'a>| {
        let sec_end: u64 = s.address.saturating_add(s.data.len() as u64);
        !s.data.is_empty() && start >= s.address && end <= sec_end
    })?;
    let rel: usize = usize::try_from(start - section.address).ok()?;
    let span: usize = usize::try_from(len).ok()?;
    section.data.get(rel..rel.checked_add(span)?)
}

fn render_insn(insn: DisasmInsn) -> DisasmInstruction {
    DisasmInstruction {
        address: insn.address,
        bytes: hex_bytes(&insn.bytes),
        mnemonic: insn.mnemonic,
        operands: insn.operands,
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out: String = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(nibble(b >> 4));
        out.push(nibble(b & 0x0f));
    }
    out
}

const fn nibble(v: u8) -> char {
    match v {
        0..=9 => (b'0' + v) as char,
        _ => (b'a' + (v - 10)) as char,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::functions::FunctionOrigin;
    use crate::image::{ImageKind, NativeImage, Section};
    use object::SectionKind;

    fn image_with_text(arch: CodeArch, addr: u64, data: &'static [u8]) -> NativeImage<'static> {
        NativeImage {
            kind: ImageKind::Elf,
            relocatable: false,
            arch,
            ptr_size: 8,
            entry: addr,
            raw: &[],
            sections: vec![Section {
                name: ".text".to_owned(),
                address: addr,
                kind: SectionKind::Text,
                data,
            }],
            symbols: Vec::new(),
            func_symbols: Vec::new(),
        }
    }

    fn func(name: &str, start: u64, end: u64) -> RecoveredFunction {
        RecoveredFunction {
            name: name.to_owned(),
            demangled: None,
            signature: None,
            start,
            end: Some(end),
            source_lines: None,
            params: Vec::new(),
            origin: FunctionOrigin::SymbolTable,
            address_assigned: true,
        }
    }

    #[test]
    fn carves_and_disassembles_x86_64_function() {
        let code: &'static [u8] = &[0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3];
        let image: NativeImage<'static> = image_with_text(CodeArch::X86_64, 0x1000, code);
        let listing: DisasmListing =
            disassemble_functions(&image, &[func("greet", 0x1000, 0x1006)]);
        assert!(listing.arch_supported);
        assert_eq!(listing.listings.len(), 1);
        let f: &FunctionListing = &listing.listings[0];
        assert_eq!(f.recovered_name, "greet");
        assert_eq!(f.start, 0x1000);
        assert_eq!(f.byte_len, 6);
        assert!(
            f.instructions
                .iter()
                .any(|i: &DisasmInstruction| i.mnemonic == "push"),
            "prologue push must decode, got {:?}",
            f.instructions
        );
        assert!(
            f.instructions
                .iter()
                .any(|i: &DisasmInstruction| i.mnemonic == "ret"),
            "epilogue ret must decode",
        );
        assert_eq!(f.instructions[0].bytes, "55");
    }

    #[test]
    fn unsupported_arch_yields_no_listings() {
        let image: NativeImage<'static> = image_with_text(CodeArch::Other, 0x1000, &[0x00]);
        let listing: DisasmListing = disassemble_functions(&image, &[func("x", 0x1000, 0x1001)]);
        assert!(!listing.arch_supported);
        assert!(listing.listings.is_empty());
    }

    #[test]
    fn out_of_range_function_is_skipped() {
        let code: &'static [u8] = &[0xc3];
        let image: NativeImage<'static> = image_with_text(CodeArch::X86_64, 0x1000, code);
        let listing: DisasmListing =
            disassemble_functions(&image, &[func("ghost", 0x9000, 0x9010)]);
        assert!(listing.arch_supported);
        assert!(listing.listings.is_empty());
    }

    #[test]
    fn function_without_assigned_address_is_skipped() {
        let code: &'static [u8] = &[0xc3];
        let image: NativeImage<'static> = image_with_text(CodeArch::X86_64, 0x1000, code);
        let mut f: RecoveredFunction = func("reloc", 0x1000, 0x1001);
        f.address_assigned = false;
        let listing: DisasmListing = disassemble_functions(&image, &[f]);
        assert!(listing.listings.is_empty());
    }
}
