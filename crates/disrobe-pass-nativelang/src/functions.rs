use std::collections::BTreeMap;

use disrobe_pass_native::{
    Bitness, DesyncReport, UnresolvedKind, UnresolvedTarget, resolve_desync,
};
use serde::{Deserialize, Serialize};

use crate::debug;
use crate::demangle::{DemangledSymbol, demangle_crystal, demangle_d, demangle_nim, demangle_zig};
use crate::detect::NativeLang;
use crate::dwarf::{DwarfFunction, DwarfReport};
use crate::image::{CodeArch, NativeImage};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FunctionOrigin {
    SymbolTable,
    Dwarf,
    RecursiveTraversal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineRange {
    pub file: Option<String>,
    pub lo: u64,
    pub hi: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredFunction {
    pub name: String,
    pub demangled: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
    pub start: u64,
    pub end: Option<u64>,
    pub source_lines: Option<LineRange>,
    pub params: Vec<String>,
    pub origin: FunctionOrigin,
    #[serde(default)]
    pub address_assigned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionRecovery {
    pub functions: Vec<RecoveredFunction>,
    pub from_symbol_table: usize,
    pub from_dwarf: usize,
    pub from_traversal: usize,
    pub from_relocatable: usize,
    pub unresolved_targets: Vec<UnresolvedTarget>,
    pub traversal_attempted: bool,
    pub traversal_arch_supported: bool,
}

const MAX_TRAVERSAL_TEXT: usize = 16 * 1024 * 1024;
const MAX_RECOVERED_FUNCTIONS: usize = 1 << 18;

#[must_use]
pub fn recover_functions(
    image: &NativeImage<'_>,
    lang: NativeLang,
    dwarf: &DwarfReport,
) -> FunctionRecovery {
    debug::dbg_section("recover-functions");
    debug::dbg_kv("func-symbols-in", || image.func_symbols.len().to_string());
    let mut by_start: BTreeMap<u64, RecoveredFunction> = BTreeMap::new();
    let mut relocatable: Vec<RecoveredFunction> = Vec::new();
    let mut relocatable_symbol_indices: BTreeMap<String, Vec<usize>> = BTreeMap::new();

    let mut from_symbol_table: usize = 0;
    for sym in &image.func_symbols {
        if by_start.len().saturating_add(relocatable.len()) >= MAX_RECOVERED_FUNCTIONS {
            break;
        }
        let end: u64 = sym.address.saturating_add(sym.size);
        let demangled: Option<DemangledSymbol> = demangle_for(lang, &sym.name);
        let entry: RecoveredFunction = RecoveredFunction {
            name: demangled
                .as_ref()
                .map_or_else(|| sym.name.clone(), DemangledSymbol::qualified_name),
            demangled: demangled.as_ref().map(DemangledSymbol::qualified_name),
            signature: demangled
                .as_ref()
                .map(|d: &DemangledSymbol| d.demangled.clone()),
            start: sym.address,
            end: Some(end),
            source_lines: None,
            params: demangled
                .map(|d: DemangledSymbol| d.params)
                .unwrap_or_default(),
            origin: FunctionOrigin::SymbolTable,
            address_assigned: !sym.relocatable,
        };
        if sym.relocatable {
            let index: usize = relocatable.len();
            relocatable.push(entry);
            relocatable_symbol_indices
                .entry(sym.name.clone())
                .or_default()
                .push(index);
            from_symbol_table += 1;
        } else if by_start.insert(sym.address, entry).is_none() {
            from_symbol_table += 1;
        }
    }
    debug::dbg_kv("from-symbol-table", || from_symbol_table.to_string());

    let mut from_dwarf: usize = 0;
    let relocatable_object: bool = image.relocatable;
    for func in &dwarf.functions {
        let Some(low_pc): Option<u64> = func.low_pc else {
            continue;
        };
        let symbol_name: &str = func.linkage_name.as_deref().unwrap_or(&func.name);
        if let Some(indices) = relocatable_symbol_indices.get(symbol_name) {
            for index in indices {
                if let Some(existing) = relocatable.get_mut(*index) {
                    enrich_from_dwarf(existing, func);
                }
            }
            continue;
        }
        if let Some(existing) = by_start.get_mut(&low_pc) {
            enrich_from_dwarf(existing, func);
        } else if relocatable_object {
            if by_start.len().saturating_add(relocatable.len()) >= MAX_RECOVERED_FUNCTIONS {
                break;
            }
            let demangled: Option<DemangledSymbol> = demangle_for(lang, symbol_name);
            let entry: RecoveredFunction = dwarf_function(func, low_pc, demangled, false);
            relocatable.push(entry);
            from_dwarf += 1;
        } else {
            if by_start.len() >= MAX_RECOVERED_FUNCTIONS {
                break;
            }
            let demangled: Option<DemangledSymbol> = demangle_for(lang, symbol_name);
            by_start.insert(low_pc, dwarf_function(func, low_pc, demangled, true));
            from_dwarf += 1;
        }
    }

    debug::dbg_kv("from-dwarf", || from_dwarf.to_string());
    let from_relocatable: usize = relocatable.len();
    debug::dbg_kv("from-relocatable", || from_relocatable.to_string());

    let arch_supported: bool = matches!(image.arch, CodeArch::X86 | CodeArch::X86_64);
    let stripped: bool = image.func_symbols.is_empty() && dwarf.functions.is_empty();
    let mut from_traversal: usize = 0;
    let mut unresolved_targets: Vec<UnresolvedTarget> = Vec::new();
    let mut traversal_attempted: bool = false;

    if stripped && !arch_supported {
        debug::dbg_line(|| {
            format!(
                "traversal wall: image is stripped but arch {:?} is not x86/x86-64, no recursive descent",
                image.arch
            )
        });
    }

    if stripped
        && arch_supported
        && let Some(report) = run_traversal(image)
    {
        traversal_attempted = true;
        if let Some(text) = image.text_section() {
            debug::dbg_hex("traversal-text-head", text.data, 32);
        }
        let entries: Vec<u64> = traversal_entry_points(&report, image.entry);
        debug::dbg_kv("traversal-entries", || entries.len().to_string());
        for start in entries {
            if by_start.len() >= MAX_RECOVERED_FUNCTIONS {
                break;
            }
            if by_start.contains_key(&start) {
                continue;
            }
            by_start.insert(
                start,
                RecoveredFunction {
                    name: format!("sub_{start:x}"),
                    demangled: None,
                    signature: None,
                    start,
                    end: None,
                    source_lines: None,
                    params: Vec::new(),
                    origin: FunctionOrigin::RecursiveTraversal,
                    address_assigned: true,
                },
            );
            from_traversal += 1;
        }
        unresolved_targets = report.unresolved;
        unresolved_targets.retain(|t: &UnresolvedTarget| {
            matches!(
                t.kind,
                UnresolvedKind::IndirectCall | UnresolvedKind::IndirectBranch
            )
        });
    }

    debug::dbg_kv("from-traversal", || from_traversal.to_string());
    debug::dbg_kv("unresolved-indirect", || {
        unresolved_targets.len().to_string()
    });

    let mut functions: Vec<RecoveredFunction> = by_start.into_values().collect();
    functions.extend(relocatable);
    debug::dbg_kv("functions-total", || functions.len().to_string());

    FunctionRecovery {
        functions,
        from_symbol_table,
        from_dwarf,
        from_traversal,
        from_relocatable,
        unresolved_targets,
        traversal_attempted,
        traversal_arch_supported: arch_supported,
    }
}

fn demangle_for(lang: NativeLang, name: &str) -> Option<DemangledSymbol> {
    match lang {
        NativeLang::Nim => demangle_nim(name),
        NativeLang::Zig => demangle_zig(name),
        NativeLang::Crystal => demangle_crystal(name),
        NativeLang::D => demangle_d(name),
    }
}

fn dwarf_function(
    func: &DwarfFunction,
    low_pc: u64,
    demangled: Option<DemangledSymbol>,
    address_assigned: bool,
) -> RecoveredFunction {
    let mut out: RecoveredFunction = RecoveredFunction {
        name: demangled
            .as_ref()
            .map_or_else(|| func.name.clone(), DemangledSymbol::qualified_name),
        demangled: demangled.as_ref().map(DemangledSymbol::qualified_name),
        signature: demangled
            .as_ref()
            .map(|d: &DemangledSymbol| d.demangled.clone()),
        start: low_pc,
        end: func.high_pc,
        source_lines: None,
        params: if func.params.is_empty() {
            demangled
                .map(|d: DemangledSymbol| d.params)
                .unwrap_or_default()
        } else {
            func.params.clone()
        },
        origin: FunctionOrigin::Dwarf,
        address_assigned,
    };
    apply_lines(&mut out, func);
    out
}

fn enrich_from_dwarf(existing: &mut RecoveredFunction, func: &DwarfFunction) {
    if existing.end.is_none() {
        existing.end = func.high_pc;
    }
    if existing.params.is_empty() && !func.params.is_empty() {
        existing.params.clone_from(&func.params);
    }
    apply_lines(existing, func);
}

fn apply_lines(target: &mut RecoveredFunction, func: &DwarfFunction) {
    let lo: Option<u64> = func.line_lo.or(func.decl_line);
    let hi: Option<u64> = func.line_hi.or(func.decl_line);
    if let (Some(lo), Some(hi)) = (lo, hi) {
        target.source_lines = Some(LineRange {
            file: func.decl_file.clone(),
            lo,
            hi: hi.max(lo),
        });
    }
}

fn run_traversal(image: &NativeImage<'_>) -> Option<DesyncReport> {
    let text = image.text_section()?;
    if text.data.is_empty() || text.data.len() > MAX_TRAVERSAL_TEXT {
        return None;
    }
    let bitness: Bitness = match image.ptr_size {
        8 => Bitness::Bits64,
        _ => Bitness::Bits32,
    };
    let base: u64 = text.address;
    let end_addr: u64 = base.saturating_add(text.data.len() as u64);
    let mut entries: Vec<u64> = Vec::new();
    if image.entry >= base && image.entry < end_addr {
        entries.push(image.entry);
    }
    if entries.is_empty() {
        entries.push(base);
    }
    resolve_desync(bitness, base, text.data, &entries).ok()
}

fn traversal_entry_points(report: &DesyncReport, image_entry: u64) -> Vec<u64> {
    let mut entries: Vec<u64> = Vec::new();
    if image_entry != 0 {
        entries.push(image_entry);
    }
    for insn in &report.recovered {
        if insn.mnemonic == "call"
            && let Some(target) = direct_call_target(&insn.operands)
        {
            entries.push(target);
        }
    }
    entries.sort_unstable();
    entries.dedup();
    entries
}

fn direct_call_target(operands: &str) -> Option<u64> {
    let token: &str = operands.split(',').next()?.trim();
    let hex: &str = token
        .strip_prefix("0x")
        .or_else(|| token.strip_suffix('h'))?;
    let cleaned: &str = hex.strip_prefix("0x").unwrap_or(hex);
    u64::from_str_radix(cleaned, 16).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::dwarf::DwarfReport;
    use crate::image::{FuncSymbol, ImageKind, NativeImage, Section};
    use object::SectionKind;

    fn blank_image(arch: CodeArch) -> NativeImage<'static> {
        NativeImage {
            kind: ImageKind::Elf,
            relocatable: false,
            arch,
            ptr_size: 8,
            entry: 0,
            raw: &[],
            sections: Vec::new(),
            symbols: Vec::new(),
            func_symbols: Vec::new(),
        }
    }

    #[test]
    fn symbol_table_yields_boundaries_and_demangles() {
        let mut image: NativeImage<'static> = blank_image(CodeArch::X86_64);
        image.func_symbols = vec![FuncSymbol {
            name: "_ZN5hello3fibE3int".to_owned(),
            address: 0x1000,
            size: 0x40,
            relocatable: false,
        }];
        let rec: FunctionRecovery =
            recover_functions(&image, NativeLang::Nim, &DwarfReport::absent());
        assert_eq!(rec.from_symbol_table, 1);
        assert_eq!(rec.functions.len(), 1);
        let f: &RecoveredFunction = &rec.functions[0];
        assert_eq!(f.start, 0x1000);
        assert_eq!(f.end, Some(0x1040));
        assert_eq!(f.demangled.as_deref(), Some("hello.fib"));
        assert_eq!(f.params, vec!["int".to_owned()]);
        assert_eq!(f.origin, FunctionOrigin::SymbolTable);
    }

    #[test]
    fn dwarf_enriches_matching_symbol_with_lines() {
        let mut image: NativeImage<'static> = blank_image(CodeArch::X86_64);
        image.func_symbols = vec![FuncSymbol {
            name: "hello.fib".to_owned(),
            address: 0x2000,
            size: 0x30,
            relocatable: false,
        }];
        let dwarf: DwarfReport = DwarfReport {
            present: true,
            compressed: false,
            dwarf_version: Some(4),
            compile_units: 1,
            functions: vec![DwarfFunction {
                name: "fib".to_owned(),
                linkage_name: None,
                low_pc: Some(0x2000),
                high_pc: Some(0x2030),
                decl_file: Some("hello.zig".to_owned()),
                decl_line: Some(3),
                line_lo: Some(3),
                line_hi: Some(5),
                params: vec!["n".to_owned()],
            }],
            aggregates: Vec::new(),
        };
        let rec: FunctionRecovery = recover_functions(&image, NativeLang::Zig, &dwarf);
        assert_eq!(rec.from_symbol_table, 1);
        assert_eq!(
            rec.from_dwarf, 0,
            "dwarf should enrich, not add a duplicate"
        );
        assert_eq!(rec.functions.len(), 1);
        let f: &RecoveredFunction = &rec.functions[0];
        assert_eq!(f.params, vec!["n".to_owned()]);
        let lines: &LineRange = f.source_lines.as_ref().expect("line range");
        assert_eq!(lines.lo, 3);
        assert_eq!(lines.hi, 5);
        assert_eq!(lines.file.as_deref(), Some("hello.zig"));
    }

    #[test]
    fn dwarf_only_function_is_surfaced() {
        let image: NativeImage<'static> = blank_image(CodeArch::X86_64);
        let dwarf: DwarfReport = DwarfReport {
            present: true,
            compressed: false,
            dwarf_version: Some(4),
            compile_units: 1,
            functions: vec![DwarfFunction {
                name: "greet".to_owned(),
                linkage_name: None,
                low_pc: Some(0x3000),
                high_pc: Some(0x3050),
                decl_file: None,
                decl_line: Some(7),
                line_lo: None,
                line_hi: None,
                params: Vec::new(),
            }],
            aggregates: Vec::new(),
        };
        let rec: FunctionRecovery = recover_functions(&image, NativeLang::Zig, &dwarf);
        assert_eq!(rec.from_dwarf, 1);
        assert_eq!(rec.functions[0].start, 0x3000);
        assert_eq!(rec.functions[0].end, Some(0x3050));
    }

    #[test]
    fn relocatable_dwarf_offset_remains_unassigned_without_symbols() {
        let mut image: NativeImage<'static> = blank_image(CodeArch::X86_64);
        image.relocatable = true;
        let dwarf: DwarfReport = DwarfReport {
            present: true,
            compressed: false,
            dwarf_version: Some(4),
            compile_units: 1,
            functions: vec![DwarfFunction {
                name: "helper".to_owned(),
                linkage_name: Some("module.helper".to_owned()),
                low_pc: Some(0x40),
                high_pc: Some(0x60),
                decl_file: None,
                decl_line: None,
                line_lo: None,
                line_hi: None,
                params: Vec::new(),
            }],
            aggregates: Vec::new(),
        };
        let rec: FunctionRecovery = recover_functions(&image, NativeLang::Zig, &dwarf);
        assert_eq!(rec.from_dwarf, 1);
        assert_eq!(rec.from_relocatable, 1);
        assert_eq!(rec.functions.len(), 1);
        assert_eq!(rec.functions[0].start, 0x40);
        assert_eq!(rec.functions[0].end, Some(0x60));
        assert!(!rec.functions[0].address_assigned);
    }

    #[test]
    fn relocatable_duplicate_names_preserve_every_entry() {
        let mut image: NativeImage<'static> = blank_image(CodeArch::X86_64);
        image.relocatable = true;
        image.func_symbols = vec![
            FuncSymbol {
                name: "module.present".to_owned(),
                address: 0,
                size: 0x10,
                relocatable: true,
            },
            FuncSymbol {
                name: "module.present".to_owned(),
                address: 0x20,
                size: 0x10,
                relocatable: true,
            },
        ];
        let dwarf: DwarfReport = DwarfReport {
            present: true,
            compressed: false,
            dwarf_version: Some(4),
            compile_units: 1,
            functions: vec![
                DwarfFunction {
                    name: "missing".to_owned(),
                    linkage_name: Some("module.missing".to_owned()),
                    low_pc: Some(0x40),
                    high_pc: Some(0x50),
                    decl_file: None,
                    decl_line: None,
                    line_lo: None,
                    line_hi: None,
                    params: Vec::new(),
                },
                DwarfFunction {
                    name: "missing".to_owned(),
                    linkage_name: Some("module.missing".to_owned()),
                    low_pc: Some(0x80),
                    high_pc: Some(0x90),
                    decl_file: None,
                    decl_line: None,
                    line_lo: None,
                    line_hi: None,
                    params: Vec::new(),
                },
            ],
            aggregates: Vec::new(),
        };
        let rec: FunctionRecovery = recover_functions(&image, NativeLang::Zig, &dwarf);
        assert_eq!(rec.from_symbol_table, 2);
        assert_eq!(rec.from_dwarf, 2);
        assert_eq!(rec.from_relocatable, 4);
        assert_eq!(rec.functions.len(), 4);
        assert_eq!(
            rec.functions
                .iter()
                .map(|function: &RecoveredFunction| function.start)
                .collect::<Vec<u64>>(),
            [0, 0x20, 0x40, 0x80]
        );
        assert!(
            rec.functions
                .iter()
                .all(|function: &RecoveredFunction| !function.address_assigned)
        );
    }

    #[test]
    fn stripped_non_x86_does_not_fake_traversal() {
        let image: NativeImage<'static> = blank_image(CodeArch::Aarch64);
        let rec: FunctionRecovery =
            recover_functions(&image, NativeLang::Nim, &DwarfReport::absent());
        assert!(!rec.traversal_arch_supported);
        assert!(!rec.traversal_attempted);
        assert_eq!(rec.from_traversal, 0);
        assert!(rec.functions.is_empty());
    }

    #[test]
    fn stripped_x86_recovers_call_targets_via_traversal() {
        let mut image: NativeImage<'static> = blank_image(CodeArch::X86_64);
        let code: &'static [u8] = &[0xE8, 0x03, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0xCC, 0x90, 0xC3];
        image.entry = 0x1000;
        image.sections = vec![Section {
            name: ".text".to_owned(),
            address: 0x1000,
            kind: SectionKind::Text,
            data: code,
        }];
        let rec: FunctionRecovery =
            recover_functions(&image, NativeLang::Nim, &DwarfReport::absent());
        assert!(rec.traversal_attempted);
        assert!(rec.from_traversal >= 1);
        let starts: Vec<u64> = rec
            .functions
            .iter()
            .map(|f: &RecoveredFunction| f.start)
            .collect();
        assert!(starts.contains(&0x1000), "entry not recovered: {starts:?}");
        assert!(
            starts.contains(&0x1008),
            "call target 0x1008 not surfaced: {starts:?}"
        );
        assert!(
            rec.functions
                .iter()
                .all(|f: &RecoveredFunction| f.origin == FunctionOrigin::RecursiveTraversal)
        );
    }

    #[test]
    fn direct_call_target_parses_hex_forms() {
        assert_eq!(direct_call_target("0x1008"), Some(0x1008));
        assert_eq!(direct_call_target("1008h"), Some(0x1008));
        assert_eq!(direct_call_target("rax"), None);
    }
}
