#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]
mod common;

use std::collections::BTreeSet;

use disrobe_nir::{NirFunction, NirInstr, NirOp, SourceLang};
use disrobe_pass_nativelang::{NativeLangAnalysis, SourceGrade, analyze};

fn debug_str_set(bytes: &[u8]) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    if bytes.len() < 0x40 || &bytes[..4] != b"\x7fELF" {
        return out;
    }
    let rd64 = |off: usize| -> u64 { u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap()) };
    let rd16 = |off: usize| -> u16 { u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap()) };
    let rd32 = |off: usize| -> u32 { u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) };
    let e_shoff: usize = rd64(0x28) as usize;
    let e_shentsize: usize = rd16(0x3a) as usize;
    let e_shnum: usize = rd16(0x3c) as usize;
    let e_shstrndx: usize = rd16(0x3e) as usize;
    let sec_off = |i: usize| -> usize { rd64(e_shoff + i * e_shentsize + 0x18) as usize };
    let sec_size = |i: usize| -> usize { rd64(e_shoff + i * e_shentsize + 0x20) as usize };
    let sec_name = |i: usize| -> u32 { rd32(e_shoff + i * e_shentsize) };
    let shstr_off: usize = sec_off(e_shstrndx);
    let cstr = |off: usize| -> String {
        let end: usize = bytes[off..]
            .iter()
            .position(|b: &u8| *b == 0)
            .map_or(bytes.len(), |p: usize| off + p);
        String::from_utf8_lossy(&bytes[off..end]).into_owned()
    };
    for i in 0..e_shnum {
        if cstr(shstr_off + sec_name(i) as usize) != ".debug_str" {
            continue;
        }
        let start: usize = sec_off(i);
        let end: usize = (start + sec_size(i)).min(bytes.len());
        for token in bytes[start..end].split(|b: &u8| *b == 0) {
            if let Ok(s) = std::str::from_utf8(token)
                && !s.is_empty()
            {
                out.insert(s.to_owned());
            }
        }
    }
    out
}

#[test]
fn zig_reconstructed_type_names_are_grounded_in_own_debug_str() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::ZIG_ELF) else {
        panic!("missing committed fixture corpus/native/zig/hello.zig.elf");
    };
    let analysis: NativeLangAnalysis = analyze(&bytes).expect("analyze zig");
    let truth: BTreeSet<String> = debug_str_set(&bytes);
    assert!(
        !truth.is_empty(),
        "the zig binary's own .debug_str must carry type-name strings (the oracle)",
    );
    assert!(
        !analysis.types.types.is_empty(),
        "type reconstruction must be non-empty on a real DWARF binary",
    );

    let grounded: usize = analysis
        .types
        .types
        .iter()
        .filter(|t| {
            let bare: &str = t
                .name
                .trim_start_matches("struct ")
                .trim_start_matches("enum ")
                .trim_start_matches("union ");
            truth.iter().any(|s: &String| s == bare || s.contains(bare))
        })
        .count();
    let ratio: f64 = grounded as f64 / analysis.types.types.len() as f64;
    println!(
        "zig: {}/{} reconstructed type names trace back to the binary's own .debug_str ({:.1}%)",
        grounded,
        analysis.types.types.len(),
        ratio * 100.0,
    );
    assert!(
        ratio >= 0.5,
        "a majority of reconstructed type names must trace back to the binary's own .debug_str \
         (non-circular: strings come from the binary, not a re-emit), got {:.1}%",
        ratio * 100.0,
    );
}

#[test]
fn debug_fixtures_disassemble_named_functions_with_demangled_bodies() {
    for rel in [common::ZIG_ELF, common::NIM_ELF] {
        let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(rel) else {
            panic!("missing committed fixture {rel}");
        };
        let analysis: NativeLangAnalysis = analyze(&bytes).expect("analyze");
        assert!(
            analysis.disasm.arch_supported,
            "{rel}: x86-64 in-house decoder must be available",
        );
        let named: usize = analysis
            .disasm
            .listings
            .iter()
            .filter(|f| !f.recovered_name.starts_with("sub_"))
            .count();
        assert!(
            named > 0,
            "{rel}: at least some carved bodies must map a demangled name -> disassembly, got {} listings",
            analysis.disasm.listings.len(),
        );
        let total_insns: usize = analysis
            .disasm
            .listings
            .iter()
            .map(|f| f.instructions.len())
            .sum();
        println!(
            "{rel}: {} function bodies disassembled ({} named), {} total instructions",
            analysis.disasm.listings.len(),
            named,
            total_insns,
        );
    }
}

const ELF_HEADER_LEN: u64 = 64;
const SHDR_LEN: u64 = 64;
const TEXT_VADDR: u64 = 0x40_1000;

fn build_stripped_zig_elf() -> Vec<u8> {
    let text: [u8; 12] = [
        0x55, 0x48, 0x89, 0xe5, 0xe8, 0x02, 0x00, 0x00, 0x00, 0x5d, 0xc3, 0xc3,
    ];
    let rodata: &[u8] = b"compiler_rt\0panicUnwrap\0panicOutOfBounds\0__zig_probe_stack\0";
    let shstrtab: &[u8] = b"\0.text\0.rodata\0.shstrtab\0";
    let name_text: u32 = 1;
    let name_rodata: u32 = 7;
    let name_shstrtab: u32 = 15;

    let text_off: u64 = ELF_HEADER_LEN;
    let rodata_off: u64 = text_off + text.len() as u64;
    let shstrtab_off: u64 = rodata_off + rodata.len() as u64;
    let shoff: u64 = shstrtab_off + shstrtab.len() as u64;

    let mut buf: Vec<u8> = vec![0u8; ELF_HEADER_LEN as usize];
    buf[0..4].copy_from_slice(b"\x7FELF");
    buf[4] = 2;
    buf[5] = 1;
    buf[6] = 1;
    buf[16..18].copy_from_slice(&2u16.to_le_bytes());
    buf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
    buf[20..24].copy_from_slice(&1u32.to_le_bytes());
    buf[24..32].copy_from_slice(&TEXT_VADDR.to_le_bytes());
    buf[32..40].copy_from_slice(&0u64.to_le_bytes());
    buf[40..48].copy_from_slice(&shoff.to_le_bytes());
    buf[48..52].copy_from_slice(&0u32.to_le_bytes());
    buf[52..54].copy_from_slice(&(ELF_HEADER_LEN as u16).to_le_bytes());
    buf[54..56].copy_from_slice(&0u16.to_le_bytes());
    buf[56..58].copy_from_slice(&0u16.to_le_bytes());
    buf[58..60].copy_from_slice(&(SHDR_LEN as u16).to_le_bytes());
    buf[60..62].copy_from_slice(&4u16.to_le_bytes());
    buf[62..64].copy_from_slice(&3u16.to_le_bytes());

    buf.extend_from_slice(&text);
    buf.extend_from_slice(rodata);
    buf.extend_from_slice(shstrtab);
    assert_eq!(buf.len(), shoff as usize);

    let mut push_shdr = |name: u32, sh_type: u32, flags: u64, addr: u64, offset: u64, size: u64| {
        buf.extend_from_slice(&name.to_le_bytes());
        buf.extend_from_slice(&sh_type.to_le_bytes());
        buf.extend_from_slice(&flags.to_le_bytes());
        buf.extend_from_slice(&addr.to_le_bytes());
        buf.extend_from_slice(&offset.to_le_bytes());
        buf.extend_from_slice(&size.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&1u64.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
    };
    push_shdr(0, 0, 0, 0, 0, 0);
    push_shdr(name_text, 1, 0x6, TEXT_VADDR, text_off, text.len() as u64);
    push_shdr(name_rodata, 1, 0x2, 0, rodata_off, rodata.len() as u64);
    push_shdr(name_shstrtab, 3, 0, 0, shstrtab_off, shstrtab.len() as u64);
    buf
}

#[test]
fn stripped_binary_degrades_honestly_carve_disasm_no_fabrication() {
    let bytes: Vec<u8> = build_stripped_zig_elf();
    assert!(
        !debug_str(&bytes),
        "the synthetic fixture must carry no DWARF"
    );
    let analysis: NativeLangAnalysis = analyze(&bytes).expect("analyze stripped zig");

    assert!(
        !analysis.recovery.source_recoverable,
        "a stripped binary with no DWARF must not claim source recoverable",
    );
    assert_eq!(
        analysis.recovery.source_grade,
        SourceGrade::None,
        "no symbols and no DWARF must grade None, never a fabricated higher grade",
    );
    assert!(
        !analysis.types.present && analysis.types.types.is_empty(),
        "no type DIEs may be fabricated when .debug_info is absent",
    );
    assert!(
        analysis
            .function_recovery
            .functions
            .iter()
            .all(|f| f.name.starts_with("sub_")),
        "stripped functions must surface as honest sub_<addr> names, got {:?}",
        analysis
            .function_recovery
            .functions
            .iter()
            .map(|f| &f.name)
            .collect::<Vec<_>>(),
    );
    assert!(
        analysis.disasm.arch_supported,
        "x86-64 carve+disasm must still run on the stripped image",
    );
    assert!(
        !analysis.disasm.listings.is_empty(),
        "carve+disasm must recover at least one body via recursive-traversal boundaries",
    );
    assert_eq!(
        analysis.nir.lang,
        SourceLang::NativeX86,
        "stripped x86-64 function bodies must lift into native NIR",
    );
    assert_eq!(
        analysis.nir.functions.len(),
        analysis.disasm.listings.len(),
        "each carved function body must be surfaced as a NIR function",
    );
    assert!(
        analysis
            .nir
            .functions
            .iter()
            .all(|function: &NirFunction| function.name.starts_with("sub_")
                && !function.instructions.is_empty()),
        "stripped NIR functions must remain address-derived and instruction-backed",
    );
    assert!(
        analysis
            .nir
            .functions
            .iter()
            .flat_map(|function: &NirFunction| function.instructions.iter())
            .any(|instruction: &NirInstr| matches!(instruction.op, NirOp::Return)),
        "native NIR must retain decoded return instructions from the carved body",
    );
    let decoded: bool = analysis
        .disasm
        .listings
        .iter()
        .flat_map(|f| f.instructions.iter())
        .any(|i| i.mnemonic == "push" || i.mnemonic == "ret");
    assert!(
        decoded,
        "carved stripped bodies must decode to real x86-64 instructions",
    );
    println!(
        "stripped: grade={:?} recoverable={} types={} sub_funcs={} disasm_funcs={}",
        analysis.recovery.source_grade,
        analysis.recovery.source_recoverable,
        analysis.types.types.len(),
        analysis.function_recovery.from_traversal,
        analysis.disasm.listings.len(),
    );
}

fn debug_str(bytes: &[u8]) -> bool {
    bytes
        .windows(b".debug_info".len())
        .any(|w: &[u8]| w == b".debug_info")
}
