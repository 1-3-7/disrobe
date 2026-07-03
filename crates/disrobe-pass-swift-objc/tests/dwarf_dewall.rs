#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use disrobe_nir::{NirFunction, NirInstr, NirOp, SourceLang};
use disrobe_pass_swift_objc::macho::{self, MachoKind, ParsedSlice};
use disrobe_pass_swift_objc::{
    FunctionBody, NativeBodyReport, SourceGrade, function_symbols, recover_native_bodies,
};

fn corpus_root() -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &Path = manifest_dir
        .ancestors()
        .nth(2)
        .expect("workspace root above crate");
    workspace_root.join("corpus")
}

fn load(rel: &[&str]) -> Option<Vec<u8>> {
    let mut p: PathBuf = corpus_root();
    for part in rel {
        p.push(part);
    }
    fs::read(&p).ok()
}

fn thin_slice(bytes: &[u8]) -> (Vec<u8>, ParsedSlice) {
    match macho::detect_magic(bytes).expect("mach-o magic") {
        MachoKind::Fat32 | MachoKind::Fat64 => {
            let entries: Vec<macho::FatArchEntry> = macho::walk_fat(bytes).expect("walk fat");
            let entry: &macho::FatArchEntry = entries.first().expect("a slice");
            let inner: &[u8] = macho::slice_bytes(bytes, entry).expect("slice bytes");
            (
                inner.to_vec(),
                macho::parse_slice(inner).expect("parse slice"),
            )
        }
        _ => (
            bytes.to_vec(),
            macho::parse_slice(bytes).expect("parse thin"),
        ),
    }
}

#[test]
fn stripped_swift_macho_degrades_honestly_with_carve_and_disasm() {
    let Some(bytes): Option<Vec<u8>> = load(&["mobile", "macho-mac", "SwiftHello.original"]) else {
        eprintln!("FIXTURE PENDING: corpus/mobile/macho-mac/SwiftHello.original missing");
        return;
    };
    let (slice, parsed): (Vec<u8>, ParsedSlice) = thin_slice(&bytes);
    assert!(
        !slice.windows(7).any(|w: &[u8]| w == b"__DWARF"),
        "this fixture is the release/stripped path: it must carry no __DWARF segment",
    );
    let report: NativeBodyReport = recover_native_bodies(&slice, &parsed);

    assert!(
        !report.dwarf_present,
        "no __DWARF means no type reconstruction",
    );
    assert!(
        !report.source_recoverable,
        "a stripped Swift Mach-O must not claim source recoverable",
    );
    assert!(
        matches!(report.grade, SourceGrade::SymbolsOnly | SourceGrade::None),
        "stripped Mach-O grades SymbolsOnly (has symtab) or None, got {:?}",
        report.grade,
    );
    assert!(
        report.reconstructed_types.is_empty(),
        "no type DIEs may be fabricated when __DWARF is absent",
    );
    assert!(
        report.disasm_arch_supported,
        "arm64/x86-64 in-house decoder must drive carve+disasm on the stripped image",
    );
    assert!(
        !report.functions.is_empty(),
        "each symbol-table function's machine code must be carved and disassembled",
    );
    assert!(
        matches!(
            report.nir.lang,
            SourceLang::NativeArm | SourceLang::NativeX86
        ),
        "supported Swift/ObjC native code must lift into native NIR, got {:?}",
        report.nir.lang,
    );
    assert_eq!(
        report.nir.functions.len(),
        report.functions.len(),
        "each carved function body must be surfaced as a NIR function",
    );
    assert!(
        report
            .nir
            .functions
            .iter()
            .all(|function: &NirFunction| !function.name.is_empty()
                && !function.instructions.is_empty()),
        "NIR functions must keep recovered names and decoded instructions",
    );
    let total_insns: usize = report.functions.iter().map(|f| f.instructions.len()).sum();
    assert!(
        total_insns > 0,
        "carved bodies must decode to real instructions, not empty listings",
    );
    let has_real_insn: bool = report
        .functions
        .iter()
        .flat_map(|f: &FunctionBody| f.instructions.iter())
        .any(|i| !i.mnemonic.is_empty() && i.mnemonic != "(bad)");
    assert!(has_real_insn, "carved bodies must hold real instructions");
    assert!(
        report.functions.iter().all(|f| f.source_lines.is_empty()),
        "no DWARF means no fabricated source lines",
    );
    assert!(
        report
            .nir
            .functions
            .iter()
            .flat_map(|function: &NirFunction| function.instructions.iter())
            .any(|instruction: &NirInstr| matches!(instruction.op, NirOp::Return)),
        "native NIR must retain decoded return instructions",
    );
    println!(
        "stripped swift: grade={:?} cpu={} symbols={} functions={} insns={}",
        report.grade,
        parsed.header.cpu.label(),
        function_symbols(&slice, &parsed).len(),
        report.functions.len(),
        total_insns,
    );
}

fn debug_str_tokens(elf: &[u8]) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    let rd64 = |o: usize| -> u64 { u64::from_le_bytes(elf[o..o + 8].try_into().unwrap()) };
    let rd32 = |o: usize| -> u32 { u32::from_le_bytes(elf[o..o + 4].try_into().unwrap()) };
    let rd16 = |o: usize| -> u16 { u16::from_le_bytes(elf[o..o + 2].try_into().unwrap()) };
    let e_shoff: usize = rd64(0x28) as usize;
    let e_shentsize: usize = rd16(0x3a) as usize;
    let e_shnum: usize = rd16(0x3c) as usize;
    let e_shstrndx: usize = rd16(0x3e) as usize;
    let sec_name = |i: usize| -> u32 { rd32(e_shoff + i * e_shentsize) };
    let sec_off = |i: usize| -> usize { rd64(e_shoff + i * e_shentsize + 0x18) as usize };
    let sec_size = |i: usize| -> usize { rd64(e_shoff + i * e_shentsize + 0x20) as usize };
    let shstr_off: usize = sec_off(e_shstrndx);
    let cstr = |o: usize| -> String {
        let end: usize = elf[o..]
            .iter()
            .position(|b| *b == 0)
            .map_or(elf.len(), |p| o + p);
        String::from_utf8_lossy(&elf[o..end]).into_owned()
    };
    for i in 0..e_shnum {
        if cstr(shstr_off + sec_name(i) as usize) != ".debug_str" {
            continue;
        }
        let start: usize = sec_off(i);
        let end: usize = (start + sec_size(i)).min(elf.len());
        for tok in elf[start..end].split(|b| *b == 0) {
            if let Ok(s) = std::str::from_utf8(tok)
                && !s.is_empty()
            {
                out.insert(s.to_owned());
            }
        }
    }
    out
}

fn elf_section_addr_size(elf: &[u8], want: &str) -> Option<(u64, u64)> {
    let rd64 = |o: usize| -> u64 { u64::from_le_bytes(elf[o..o + 8].try_into().unwrap()) };
    let rd32 = |o: usize| -> u32 { u32::from_le_bytes(elf[o..o + 4].try_into().unwrap()) };
    let rd16 = |o: usize| -> u16 { u16::from_le_bytes(elf[o..o + 2].try_into().unwrap()) };
    let e_shoff: usize = rd64(0x28) as usize;
    let e_shentsize: usize = rd16(0x3a) as usize;
    let e_shnum: usize = rd16(0x3c) as usize;
    let e_shstrndx: usize = rd16(0x3e) as usize;
    let sec_name = |i: usize| -> u32 { rd32(e_shoff + i * e_shentsize) };
    let sec_addr = |i: usize| -> u64 { rd64(e_shoff + i * e_shentsize + 0x10) };
    let sec_off = |i: usize| -> usize { rd64(e_shoff + i * e_shentsize + 0x18) as usize };
    let sec_size = |i: usize| -> u64 { rd64(e_shoff + i * e_shentsize + 0x20) };
    let shstr_off: usize = sec_off(e_shstrndx);
    let cstr = |o: usize| -> String {
        let end: usize = elf[o..]
            .iter()
            .position(|b| *b == 0)
            .map_or(elf.len(), |p| o + p);
        String::from_utf8_lossy(&elf[o..end]).into_owned()
    };
    for i in 0..e_shnum {
        if cstr(shstr_off + sec_name(i) as usize) == want {
            return Some((sec_addr(i), sec_size(i)));
        }
    }
    None
}

fn elf_debug_section<'a>(elf: &'a [u8], want: &str) -> Option<&'a [u8]> {
    let rd64 = |o: usize| -> u64 { u64::from_le_bytes(elf[o..o + 8].try_into().unwrap()) };
    let rd32 = |o: usize| -> u32 { u32::from_le_bytes(elf[o..o + 4].try_into().unwrap()) };
    let rd16 = |o: usize| -> u16 { u16::from_le_bytes(elf[o..o + 2].try_into().unwrap()) };
    let e_shoff: usize = rd64(0x28) as usize;
    let e_shentsize: usize = rd16(0x3a) as usize;
    let e_shnum: usize = rd16(0x3c) as usize;
    let e_shstrndx: usize = rd16(0x3e) as usize;
    let sec_name = |i: usize| -> u32 { rd32(e_shoff + i * e_shentsize) };
    let sec_off = |i: usize| -> usize { rd64(e_shoff + i * e_shentsize + 0x18) as usize };
    let sec_size = |i: usize| -> usize { rd64(e_shoff + i * e_shentsize + 0x20) as usize };
    let shstr_off: usize = sec_off(e_shstrndx);
    let cstr = |o: usize| -> String {
        let end: usize = elf[o..]
            .iter()
            .position(|b| *b == 0)
            .map_or(elf.len(), |p| o + p);
        String::from_utf8_lossy(&elf[o..end]).into_owned()
    };
    for i in 0..e_shnum {
        if cstr(shstr_off + sec_name(i) as usize) == want {
            let start: usize = sec_off(i);
            let end: usize = start + sec_size(i);
            return elf.get(start..end);
        }
    }
    None
}

const MH_MAGIC_64: u32 = 0xFEED_FACF;
const CPU_X86_64: u32 = 0x0100_0007;
const CPU_SUB_X86_64: u32 = 3;
const MH_EXECUTE: u32 = 2;
const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x2;
const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;
const N_SECT: u8 = 0x0e;

fn segname(name: &str) -> [u8; 16] {
    let mut b: [u8; 16] = [0u8; 16];
    let bytes: &[u8] = name.as_bytes();
    b[..bytes.len()].copy_from_slice(bytes);
    b
}

#[allow(clippy::too_many_lines)]
fn build_macho_with_dwarf(elf: &[u8]) -> Vec<u8> {
    let (text_vaddr, text_vmsize): (u64, u64) =
        elf_section_addr_size(elf, ".text").expect("zig ELF carries a .text section");
    let text_code: [u8; 6] = [0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3];
    let debug_specs: [(&str, &str); 4] = [
        ("__debug_info", ".debug_info"),
        ("__debug_abbrev", ".debug_abbrev"),
        ("__debug_str", ".debug_str"),
        ("__debug_line", ".debug_line"),
    ];
    let debug_data: Vec<(&str, Vec<u8>)> = debug_specs
        .iter()
        .map(|(macho_name, elf_name)| {
            (
                *macho_name,
                elf_debug_section(elf, elf_name)
                    .unwrap_or_else(|| panic!("zig ELF missing {elf_name}"))
                    .to_vec(),
            )
        })
        .collect();

    let n_text_sects: u32 = 1;
    let n_dwarf_sects: u32 = debug_data.len() as u32;
    let text_segcmd_size: u32 = 72 + 80 * n_text_sects;
    let dwarf_segcmd_size: u32 = 72 + 80 * n_dwarf_sects;
    let symtab_cmd_size: u32 = 24;
    let sizeofcmds: u32 = text_segcmd_size + dwarf_segcmd_size + symtab_cmd_size;
    let header_size: u32 = 32;

    let mut file_cursor: u32 = header_size + sizeofcmds;
    let text_off: u32 = file_cursor;
    file_cursor += text_code.len() as u32;
    let mut dwarf_offs: Vec<(u32, usize)> = Vec::new();
    for (_, data) in &debug_data {
        dwarf_offs.push((file_cursor, data.len()));
        file_cursor += data.len() as u32;
    }
    let sym_off: u32 = file_cursor;
    let n_syms: u32 = 1;
    file_cursor += n_syms * 16;
    let str_off: u32 = file_cursor;
    let strtab: Vec<u8> = b"\0_greet\0".to_vec();
    let str_size: u32 = strtab.len() as u32;

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
    out.extend_from_slice(&CPU_X86_64.to_le_bytes());
    out.extend_from_slice(&CPU_SUB_X86_64.to_le_bytes());
    out.extend_from_slice(&MH_EXECUTE.to_le_bytes());
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&sizeofcmds.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());

    out.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
    out.extend_from_slice(&text_segcmd_size.to_le_bytes());
    out.extend_from_slice(&segname("__TEXT"));
    out.extend_from_slice(&text_vaddr.to_le_bytes());
    out.extend_from_slice(&text_vmsize.to_le_bytes());
    out.extend_from_slice(&u64::from(text_off).to_le_bytes());
    out.extend_from_slice(&u64::from(text_code.len() as u32).to_le_bytes());
    out.extend_from_slice(&7u32.to_le_bytes());
    out.extend_from_slice(&5u32.to_le_bytes());
    out.extend_from_slice(&n_text_sects.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&segname("__text"));
    out.extend_from_slice(&segname("__TEXT"));
    out.extend_from_slice(&text_vaddr.to_le_bytes());
    out.extend_from_slice(&text_vmsize.to_le_bytes());
    out.extend_from_slice(&text_off.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());

    out.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
    out.extend_from_slice(&dwarf_segcmd_size.to_le_bytes());
    out.extend_from_slice(&segname("__DWARF"));
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&u64::from(dwarf_offs[0].0).to_le_bytes());
    let dwarf_filesize: u64 = debug_data.iter().map(|(_, d)| d.len() as u64).sum();
    out.extend_from_slice(&dwarf_filesize.to_le_bytes());
    out.extend_from_slice(&7u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&n_dwarf_sects.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    for ((macho_name, _), (off, size)) in debug_data.iter().zip(dwarf_offs.iter()) {
        out.extend_from_slice(&segname(macho_name));
        out.extend_from_slice(&segname("__DWARF"));
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&(*size as u64).to_le_bytes());
        out.extend_from_slice(&off.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
    }

    out.extend_from_slice(&LC_SYMTAB.to_le_bytes());
    out.extend_from_slice(&symtab_cmd_size.to_le_bytes());
    out.extend_from_slice(&sym_off.to_le_bytes());
    out.extend_from_slice(&n_syms.to_le_bytes());
    out.extend_from_slice(&str_off.to_le_bytes());
    out.extend_from_slice(&str_size.to_le_bytes());

    assert_eq!(out.len() as u32, header_size + sizeofcmds);
    out.extend_from_slice(&text_code);
    for (_, data) in &debug_data {
        out.extend_from_slice(data);
    }
    out.extend_from_slice(&1u32.to_le_bytes());
    out.push(N_SECT);
    out.push(1);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&text_vaddr.to_le_bytes());
    out.extend_from_slice(&strtab);
    out
}

#[test]
fn dwarf_bearing_swift_macho_recovers_types_lines_and_disasm() {
    let Some(elf): Option<Vec<u8>> = load(&["native", "zig", "hello.zig.elf"]) else {
        eprintln!("FIXTURE PENDING: corpus/native/zig/hello.zig.elf missing");
        return;
    };
    let truth: BTreeSet<String> = debug_str_tokens(&elf);
    assert!(
        !truth.is_empty(),
        "the carved zig DWARF must carry .debug_str type strings (the oracle)",
    );

    let macho: Vec<u8> = build_macho_with_dwarf(&elf);
    assert!(
        macho::detect_magic(&macho).is_some(),
        "the constructed fixture must be a valid Mach-O",
    );
    assert!(
        macho.windows(7).any(|w: &[u8]| w == b"__DWARF"),
        "the constructed Mach-O must carry a __DWARF segment",
    );
    let parsed: ParsedSlice = macho::parse_slice(&macho).expect("parse constructed mach-o");

    let report: NativeBodyReport = recover_native_bodies(&macho, &parsed);
    assert!(
        report.dwarf_present,
        "real compiler DWARF wrapped in a __DWARF segment must route through reconstruction",
    );
    assert_eq!(
        report.grade,
        SourceGrade::TypesAndLines,
        "with reconstructable types + a pc->line map the grade is TypesAndLines (the original Swift \
         surface syntax stays an honest wall)",
    );
    assert!(
        report.source_recoverable,
        "TypesAndLines grades recoverable"
    );
    assert_eq!(
        report.nir.lang,
        SourceLang::NativeX86,
        "constructed x86-64 Mach-O bodies must lift into native-x86 NIR",
    );
    assert_eq!(
        report.nir.functions.len(),
        report.functions.len(),
        "NIR must cover every carved function body from the Mach-O symtab",
    );
    assert!(
        report
            .nir
            .functions
            .iter()
            .any(|function: &NirFunction| function.name == "_greet"
                && !function.instructions.is_empty()),
        "the symtab-backed _greet body must reach NIR with decoded instructions",
    );
    assert!(
        report.named_type_count > 0 && !report.reconstructed_types.is_empty(),
        "type DIEs must be reconstructed from the Mach-O __DWARF, got {} named",
        report.named_type_count,
    );

    let grounded: usize = report
        .reconstructed_types
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
    let ratio: f64 = grounded as f64 / report.reconstructed_types.len() as f64;
    assert!(
        ratio >= 0.5,
        "a majority of reconstructed type names must trace back to the carved .debug_str \
         (non-circular: strings come from the real compiler DWARF, not a re-emit), got {:.1}%",
        ratio * 100.0,
    );
    println!(
        "macho __DWARF: grade={:?} types={} ({}/{} grounded {:.1}%) line_cov={:.1}% functions={}",
        report.grade,
        report.named_type_count,
        grounded,
        report.reconstructed_types.len(),
        ratio * 100.0,
        report.line_coverage_pct,
        report.functions.len(),
    );
}
