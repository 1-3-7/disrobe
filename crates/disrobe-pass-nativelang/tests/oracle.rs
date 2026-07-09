#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use disrobe_nir::{NirFunction, SourceLang};
use disrobe_pass_nativelang::{
    AggregateKind, DemangledSymbol, DwarfAggregate, DwarfMember, FunctionOrigin, NativeLang,
    NativeLangAnalysis, RecoveredFunction, SourceGrade, analyze, demangle_crystal,
};

fn elf_symtab_names(bytes: &[u8]) -> BTreeSet<String> {
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
    let sec = |i: usize| -> (u32, u32, usize, usize, usize, usize) {
        let base: usize = e_shoff + i * e_shentsize;
        (
            rd32(base),
            rd32(base + 4),
            rd64(base + 0x18) as usize,
            rd64(base + 0x20) as usize,
            rd32(base + 0x28) as usize,
            rd64(base + 0x38) as usize,
        )
    };
    let shstr_off: usize = sec(e_shstrndx).2;
    let cstr = |off: usize| -> String {
        let end: usize = bytes[off..]
            .iter()
            .position(|b: &u8| *b == 0)
            .map_or(bytes.len(), |p: usize| off + p);
        String::from_utf8_lossy(&bytes[off..end]).into_owned()
    };
    for i in 0..e_shnum {
        let (name_off, typ, off, size, link, entsize): (u32, u32, usize, usize, usize, usize) =
            sec(i);
        let sname: String = cstr(shstr_off + name_off as usize);
        if sname == ".symtab" && typ == 2 && entsize > 0 {
            let strtab_off: usize = sec(link).2;
            let n: usize = size / entsize;
            for s in 0..n {
                let st: usize = off + s * entsize;
                let nameoff: u32 = rd32(st);
                if nameoff == 0 {
                    continue;
                }
                let nm: String = cstr(strtab_off + nameoff as usize);
                if !nm.is_empty() {
                    out.insert(nm);
                }
            }
        }
    }
    out
}

fn elf_func_symbols(bytes: &[u8]) -> BTreeMap<String, (u64, u64)> {
    let mut out: BTreeMap<String, (u64, u64)> = BTreeMap::new();
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
    let sec = |i: usize| -> (u32, u32, usize, usize, usize, usize) {
        let base: usize = e_shoff + i * e_shentsize;
        (
            rd32(base),
            rd32(base + 4),
            rd64(base + 0x18) as usize,
            rd64(base + 0x20) as usize,
            rd32(base + 0x28) as usize,
            rd64(base + 0x38) as usize,
        )
    };
    let shstr_off: usize = sec(e_shstrndx).2;
    let cstr = |off: usize| -> String {
        let end: usize = bytes[off..]
            .iter()
            .position(|b: &u8| *b == 0)
            .map_or(bytes.len(), |p: usize| off + p);
        String::from_utf8_lossy(&bytes[off..end]).into_owned()
    };
    for i in 0..e_shnum {
        let (name_off, typ, off, size, link, entsize): (u32, u32, usize, usize, usize, usize) =
            sec(i);
        let sname: String = cstr(shstr_off + name_off as usize);
        if sname == ".symtab" && typ == 2 && entsize > 0 {
            let strtab_off: usize = sec(link).2;
            let n: usize = size / entsize;
            for s in 0..n {
                let st: usize = off + s * entsize;
                let nameoff: u32 = rd32(st);
                let info: u8 = bytes[st + 4];
                let st_value: u64 = rd64(st + 8);
                let st_size: u64 = rd64(st + 16);
                if nameoff == 0 || info & 0xf != 2 || st_value == 0 || st_size == 0 {
                    continue;
                }
                let nm: String = cstr(strtab_off + nameoff as usize);
                if !nm.is_empty() {
                    out.insert(nm, (st_value, st_size));
                }
            }
        }
    }
    out
}

fn elf_func_symbol_sizes(bytes: &[u8]) -> BTreeMap<String, u64> {
    let mut out: BTreeMap<String, u64> = BTreeMap::new();
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
    let sec = |i: usize| -> (u32, u32, usize, usize, usize, usize) {
        let base: usize = e_shoff + i * e_shentsize;
        (
            rd32(base),
            rd32(base + 4),
            rd64(base + 0x18) as usize,
            rd64(base + 0x20) as usize,
            rd32(base + 0x28) as usize,
            rd64(base + 0x38) as usize,
        )
    };
    let shstr_off: usize = sec(e_shstrndx).2;
    let cstr = |off: usize| -> String {
        let end: usize = bytes[off..]
            .iter()
            .position(|b: &u8| *b == 0)
            .map_or(bytes.len(), |p: usize| off + p);
        String::from_utf8_lossy(&bytes[off..end]).into_owned()
    };
    for i in 0..e_shnum {
        let (name_off, typ, off, size, link, entsize): (u32, u32, usize, usize, usize, usize) =
            sec(i);
        let sname: String = cstr(shstr_off + name_off as usize);
        if sname == ".symtab" && typ == 2 && entsize > 0 {
            let strtab_off: usize = sec(link).2;
            let n: usize = size / entsize;
            for s in 0..n {
                let st: usize = off + s * entsize;
                let nameoff: u32 = rd32(st);
                let info: u8 = bytes[st + 4];
                let st_size: u64 = rd64(st + 16);
                if nameoff == 0 || info & 0xf != 2 || st_size == 0 {
                    continue;
                }
                let nm: String = cstr(strtab_off + nameoff as usize);
                if !nm.is_empty() {
                    out.insert(nm, st_size);
                }
            }
        }
    }
    out
}

fn elf_has_section(bytes: &[u8], want: &str) -> bool {
    if bytes.len() < 0x40 || &bytes[..4] != b"\x7fELF" {
        return false;
    }
    let rd64 = |off: usize| -> u64 { u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap()) };
    let rd16 = |off: usize| -> u16 { u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap()) };
    let rd32 = |off: usize| -> u32 { u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) };
    let e_shoff: usize = rd64(0x28) as usize;
    let e_shentsize: usize = rd16(0x3a) as usize;
    let e_shnum: usize = rd16(0x3c) as usize;
    let e_shstrndx: usize = rd16(0x3e) as usize;
    let name_off_of = |i: usize| -> u32 { rd32(e_shoff + i * e_shentsize) };
    let shstr_off: usize = rd64(e_shoff + e_shstrndx * e_shentsize + 0x18) as usize;
    let cstr = |off: usize| -> String {
        let end: usize = bytes[off..]
            .iter()
            .position(|b: &u8| *b == 0)
            .map_or(bytes.len(), |p: usize| off + p);
        String::from_utf8_lossy(&bytes[off..end]).into_owned()
    };
    (0..e_shnum).any(|i: usize| cstr(shstr_off + name_off_of(i) as usize) == want)
}

fn elf_debug_str_set(bytes: &[u8]) -> BTreeSet<String> {
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
    let shstr_off: usize = rd64(e_shoff + e_shstrndx * e_shentsize + 0x18) as usize;
    let cstr = |off: usize| -> String {
        let end: usize = bytes[off..]
            .iter()
            .position(|b: &u8| *b == 0)
            .map_or(bytes.len(), |p: usize| off + p);
        String::from_utf8_lossy(&bytes[off..end]).into_owned()
    };
    for i in 0..e_shnum {
        let base: usize = e_shoff + i * e_shentsize;
        if cstr(shstr_off + rd32(base) as usize) != ".debug_str" {
            continue;
        }
        let off: usize = rd64(base + 0x18) as usize;
        let size: usize = rd64(base + 0x20) as usize;
        if off + size > bytes.len() {
            return out;
        }
        for chunk in bytes[off..off + size].split(|b: &u8| *b == 0) {
            if !chunk.is_empty() {
                out.insert(String::from_utf8_lossy(chunk).into_owned());
            }
        }
    }
    out
}

fn raw_printable_runs(bytes: &[u8], min_len: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut run: Vec<u8> = Vec::new();
    for &b in bytes {
        if (0x20..0x7f).contains(&b) {
            run.push(b);
        } else {
            if run.len() >= min_len {
                out.push(String::from_utf8_lossy(&run).into_owned());
            }
            run.clear();
        }
    }
    if run.len() >= min_len {
        out.push(String::from_utf8_lossy(&run).into_owned());
    }
    out
}

fn crystal_class_anchor_types(bytes: &[u8]) -> BTreeSet<String> {
    raw_printable_runs(bytes, 5)
        .iter()
        .filter_map(|s: &String| s.strip_suffix(".class"))
        .filter(|name: &&str| {
            !name.is_empty()
                && name
                    .chars()
                    .next()
                    .is_some_and(|c: char| c.is_ascii_uppercase())
                && name
                    .chars()
                    .all(|c: char| c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '(' | ')'))
        })
        .map(str::to_owned)
        .collect()
}

#[test]
fn zig_detects_and_demangles_matching_independent_symtab() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::ZIG_ELF) else {
        panic!(
            "missing committed fixture corpus/native/zig/hello.zig.elf (a tracked corpus file - see corpus/native/MANIFEST or regen.ps1)"
        );
    };
    let analysis: NativeLangAnalysis = analyze(&bytes).expect("analyze zig elf");
    assert_eq!(
        analysis.fingerprint.lang,
        NativeLang::Zig,
        "lang must be zig"
    );
    assert_eq!(
        analysis.recovery.source_grade,
        SourceGrade::TypesAndLines,
        "the zig fixture is debug-built: DWARF types + pc->source line map are recoverable, so the \
         grade is TypesAndLines (the original .zig surface syntax stays an honest wall - we recover \
         types/lines/disassembly, not source text)",
    );
    assert!(
        analysis.recovery.source_recoverable,
        "TypesAndLines grade means source_recoverable is the graded truth, not a hardcoded false",
    );
    assert!(
        analysis.types.named_type_count > 0 && analysis.types.line_coverage_pct >= 80.0,
        "grade must be backed by real reconstructed types and >=80% .text line coverage, got \
         types={} cov={:.1}%",
        analysis.types.named_type_count,
        analysis.types.line_coverage_pct,
    );

    let independent: BTreeSet<String> = elf_symtab_names(&bytes);
    assert!(
        independent.contains("hello.fib"),
        "independent oracle missing hello.fib"
    );

    let demangled: BTreeSet<String> = analysis
        .recovery
        .demangled
        .iter()
        .map(|d: &DemangledSymbol| d.demangled.clone())
        .collect();
    assert!(
        demangled.contains("hello.fib"),
        "pass did not recover hello.fib; got {demangled:?}"
    );
    assert!(
        demangled.contains("hello.main"),
        "pass did not recover hello.main"
    );
    let greet_recovered: bool = analysis
        .recovery
        .demangled
        .iter()
        .any(|d: &DemangledSymbol| d.module.as_deref() == Some("hello") && d.name == "greet");
    assert!(
        greet_recovered,
        "pass did not recover demangled hello.greet (anon stripped)"
    );

    let std_recovered: bool = analysis
        .recovery
        .demangled
        .iter()
        .any(|d: &DemangledSymbol| {
            d.module.as_deref() == Some("posix") || d.module.as_deref() == Some("start")
        });
    assert!(
        std_recovered,
        "pass did not recover zig std (posix/start) symbols"
    );
    assert!(
        analysis.recovery.std_symbol_count > 10,
        "too few std symbols"
    );
}

#[test]
fn nim_detects_and_demangles_itanium_matching_known_source() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::NIM_ELF) else {
        panic!(
            "missing committed fixture corpus/native/nim/hello.nim.elf (a tracked corpus file - see corpus/native/MANIFEST or regen.ps1)"
        );
    };
    let analysis: NativeLangAnalysis = analyze(&bytes).expect("analyze nim elf");
    assert_eq!(
        analysis.fingerprint.lang,
        NativeLang::Nim,
        "lang must be nim"
    );
    assert_eq!(
        analysis.recovery.source_grade,
        SourceGrade::TypesAndLines,
        "the nim fixture is debug-built: DWARF types + line map are recoverable (TypesAndLines); \
         the original .nim surface syntax remains an honest wall",
    );
    assert!(
        analysis.recovery.source_recoverable,
        "nim debug binary grades source_recoverable=true off real DWARF, not a hardcoded false",
    );

    let independent: BTreeSet<String> = elf_symtab_names(&bytes);
    assert!(
        independent.contains("_ZN5hello5greetE6string"),
        "independent oracle missing mangled greet"
    );
    assert!(
        independent.iter().any(|s: &String| s == "NimMain"),
        "independent oracle missing NimMain runtime"
    );

    let greet: bool = analysis
        .recovery
        .demangled
        .iter()
        .any(|d: &DemangledSymbol| {
            d.module.as_deref() == Some("hello") && d.name == "greet" && d.params == ["string"]
        });
    assert!(greet, "pass did not demangle hello.greet(string)");
    let fib: bool = analysis
        .recovery
        .demangled
        .iter()
        .any(|d: &DemangledSymbol| {
            d.module.as_deref() == Some("hello") && d.name == "fib" && d.params == ["int"]
        });
    assert!(fib, "pass did not demangle hello.fib(int)");

    assert!(
        analysis
            .recovery
            .gc
            .runtime_symbols
            .iter()
            .any(|s: &String| s == "NimMain"),
        "missing NimMain in runtime metadata"
    );
    assert!(
        analysis
            .recovery
            .user_modules
            .iter()
            .any(|m: &String| m == "hello"),
        "user module 'hello' not recovered"
    );
}

#[test]
fn nim_operators_and_generics_demangle_to_source_forms() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::NIM_ELF) else {
        panic!(
            "missing committed fixture corpus/native/nim/hello.nim.elf (a tracked corpus file - see corpus/native/MANIFEST or regen.ps1)"
        );
    };
    let independent: BTreeSet<String> = elf_symtab_names(&bytes);
    for raw in [
        "_ZN6system13minuspercent_E3int3int",
        "_ZN7dollars7dollar_E3int",
        "_ZN6stdlib10eqdestroy_E3varIN10exceptions11IndexDefectEE",
    ] {
        assert!(
            independent.contains(raw),
            "independent symtab oracle missing real mangled symbol {raw}"
        );
    }

    let analysis: NativeLangAnalysis = analyze(&bytes).expect("analyze nim elf");
    let by_name = |demangled: &str| -> bool {
        analysis
            .recovery
            .demangled
            .iter()
            .any(|d: &DemangledSymbol| d.demangled == demangled)
    };

    assert!(
        by_name("system.-%(int, int)"),
        "nim arithmetic operator -% not decoded from minuspercent_"
    );
    assert!(
        by_name("dollars.$(int)"),
        "nim stringify operator $ not decoded from dollar_"
    );
    assert!(
        by_name("stdlib.=destroy(var[exceptions.IndexDefect])"),
        "nim =destroy lifecycle hook + generic param not recovered; \
         got {:?}",
        analysis
            .recovery
            .demangled
            .iter()
            .filter(|d: &&DemangledSymbol| d.name.contains("destroy"))
            .map(|d: &DemangledSymbol| d.demangled.as_str())
            .collect::<Vec<&str>>()
    );

    let leaked_raw_operator: bool =
        analysis
            .recovery
            .demangled
            .iter()
            .any(|d: &DemangledSymbol| {
                d.name.ends_with('_')
                    && (d.name.contains("percent")
                        || d.name.contains("dollar")
                        || d.name.starts_with("eq"))
            });
    assert!(
        !leaked_raw_operator,
        "an operator symbol was left as a raw word transliteration"
    );
}

#[test]
fn zig_compiler_reflection_thunks_excluded_from_user_modules() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::ZIG_ELF) else {
        panic!(
            "missing committed fixture corpus/native/zig/hello.zig.elf (a tracked corpus file - see corpus/native/MANIFEST or regen.ps1)"
        );
    };
    let independent: BTreeSet<String> = elf_symtab_names(&bytes);
    assert!(
        independent
            .iter()
            .any(|s: &String| s.starts_with("__zig_is_named_enum_value_")),
        "independent oracle: real zig binary must carry __zig_ reflection thunks"
    );

    let analysis: NativeLangAnalysis = analyze(&bytes).expect("analyze zig elf");
    assert!(
        analysis
            .recovery
            .user_modules
            .iter()
            .all(|m: &String| !m.starts_with("__zig_") && !m.contains("@typeInfo")),
        "compiler reflection thunks leaked into user_modules: {:?}",
        analysis.recovery.user_modules
    );
    assert!(
        analysis
            .recovery
            .user_modules
            .iter()
            .any(|m: &String| m == "hello"),
        "real user module 'hello' must still be recovered after the filter"
    );
}

fn crystal_source_path() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push("native");
    p.push("crystal");
    p.push("hello.cr");
    p
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceTruth {
    classes: BTreeSet<String>,
    methods: BTreeSet<String>,
}

fn parse_crystal_source(src: &str) -> SourceTruth {
    let mut classes: BTreeSet<String> = BTreeSet::new();
    let mut methods: BTreeSet<String> = BTreeSet::new();
    let ident = |s: &str| -> String {
        s.chars()
            .take_while(|c: &char| c.is_ascii_alphanumeric() || *c == '_')
            .collect::<String>()
    };
    for line in src.lines() {
        let trimmed: &str = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("class ") {
            let name: String = ident(rest.trim_start());
            if !name.is_empty() {
                classes.insert(name);
            }
        } else if let Some(rest) = trimmed.strip_prefix("def ") {
            let name: String = ident(rest.trim_start());
            if !name.is_empty() {
                methods.insert(name);
            }
        }
    }
    SourceTruth { classes, methods }
}

fn crystal_spec_mangled_symbols(truth: &SourceTruth) -> Vec<String> {
    let mut syms: Vec<String> = Vec::new();
    for class in &truth.classes {
        syms.push(format!("{class}.class"));
        for method in &truth.methods {
            syms.push(format!("{class}#{method}"));
        }
    }
    syms.push("Crystal::EventLoop::IOCP".to_owned());
    syms.push("Crystal::System::Thread".to_owned());
    syms.push("Crystal::Hasher".to_owned());
    syms.push("Fiber::StackPool".to_owned());
    syms
}

#[test]
fn crystal_demangler_reverses_spec_constructed_mangling() {
    let src: String = std::fs::read_to_string(crystal_source_path()).expect("read hello.cr source");
    let truth: SourceTruth = parse_crystal_source(&src);
    assert!(
        truth.classes.contains("Greeter"),
        "source oracle must contain class Greeter; got {:?}",
        truth.classes
    );
    for expected in ["greet", "fib", "initialize"] {
        assert!(
            truth.methods.contains(expected),
            "source oracle missing def {expected}; got {:?}",
            truth.methods
        );
    }

    let symbols: Vec<String> = crystal_spec_mangled_symbols(&truth);
    let demangled: Vec<DemangledSymbol> = symbols
        .iter()
        .filter_map(|s: &String| demangle_crystal(s))
        .collect();

    let recovered_class: bool = demangled
        .iter()
        .any(|d: &DemangledSymbol| d.name == "Greeter" || d.demangled == "Greeter");
    assert!(
        recovered_class,
        "demangler did not recover class Greeter from {symbols:?}"
    );

    for method in &truth.methods {
        let recovered: bool = demangled
            .iter()
            .any(|d: &DemangledSymbol| d.module.as_deref() == Some("Greeter") && &d.name == method);
        assert!(
            recovered,
            "demangler did not recover Greeter#{method}; got {demangled:?}"
        );
    }

    let runtime: bool = demangled.iter().any(|d: &DemangledSymbol| {
        d.module
            .as_deref()
            .is_some_and(|m: &str| m.starts_with("Crystal"))
    });
    assert!(
        runtime,
        "demangler did not recover any Crystal:: runtime namespace type"
    );

    let iocp: bool = demangled.iter().any(|d: &DemangledSymbol| {
        d.module.as_deref() == Some("Crystal::EventLoop") && d.name == "IOCP"
    });
    assert!(iocp, "demangler did not recover Crystal::EventLoop::IOCP");
}

#[test]
fn crystal_detect_and_demangle_on_real_binary() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::CRYSTAL_PE) else {
        panic!(
            "missing committed fixture corpus/native/crystal/hello.cr.exe (a tracked corpus file - see corpus/native/MANIFEST or regen.ps1)"
        );
    };
    assert_eq!(&bytes[..2], b"MZ", "crystal fixture must be a real PE");

    let analysis: NativeLangAnalysis = analyze(&bytes).expect("analyze crystal pe");
    assert_eq!(
        analysis.fingerprint.lang,
        NativeLang::Crystal,
        "real crystal PE must fingerprint as crystal; got {:?}",
        analysis.fingerprint.lang
    );
    assert!(
        analysis
            .fingerprint
            .markers
            .iter()
            .any(|m: &String| m == "Crystal::EventLoop"),
        "crystal PE must carry the Crystal::EventLoop runtime marker; got {:?}",
        analysis.fingerprint.markers
    );
    assert_eq!(analysis.recovery.gc.gc_kind.as_deref(), Some("boehm"));

    let source: String =
        std::fs::read_to_string(crystal_source_path()).expect("read hello.cr source");
    let truth: SourceTruth = parse_crystal_source(&source);
    assert!(truth.classes.contains("Greeter"));

    let recovered_user: BTreeSet<String> = analysis
        .recovery
        .demangled
        .iter()
        .map(|d: &DemangledSymbol| d.demangled.clone())
        .collect();
    for class in &truth.classes {
        assert!(
            recovered_user.contains(class),
            "user class {class} from source not recovered from the real binary"
        );
    }

    let anchor_types: BTreeSet<String> = crystal_class_anchor_types(&bytes);
    assert!(
        anchor_types.contains("Greeter"),
        "independent .class oracle must see Greeter; it saw {} types",
        anchor_types.len()
    );
    assert!(
        anchor_types.len() > 100,
        "independent .class oracle expected a rich crystal type table, got {}",
        anchor_types.len()
    );
    let recovered_from_anchors: usize = anchor_types
        .iter()
        .filter(|t: &&String| recovered_user.contains(*t))
        .count();
    let coverage: f64 = recovered_from_anchors as f64 / anchor_types.len() as f64;
    assert!(
        coverage >= 0.90,
        "recovery must cover >=90% of the binary's own .class type anchors; covered \
         {recovered_from_anchors}/{} ({coverage:.3})",
        anchor_types.len()
    );

    let runtime_namespaced: bool = analysis
        .recovery
        .demangled
        .iter()
        .any(|d: &DemangledSymbol| {
            d.module
                .as_deref()
                .is_some_and(|m: &str| m.starts_with("Crystal::EventLoop"))
                || d.demangled == "Crystal::EventLoop::IOCP"
        });
    assert!(
        runtime_namespaced,
        "real crystal binary must surface the Crystal::EventLoop::IOCP runtime namespace"
    );

    assert!(
        analysis
            .recovery
            .std_modules
            .iter()
            .any(|m: &String| m == "Crystal"),
        "Crystal runtime must be classified as a std module"
    );
    assert!(
        analysis
            .recovery
            .user_modules
            .iter()
            .any(|m: &String| m == "Greeter"),
        "Greeter must be classified as a user module, not std"
    );
}

fn d_source_path() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push("native");
    p.push("d");
    p.push("hello.d");
    p
}

fn parse_d_source(src: &str) -> SourceTruth {
    let mut classes: BTreeSet<String> = BTreeSet::new();
    let mut methods: BTreeSet<String> = BTreeSet::new();
    let ident = |s: &str| -> String {
        s.chars()
            .take_while(|c: &char| c.is_ascii_alphanumeric() || *c == '_')
            .collect::<String>()
    };
    let mut in_class: bool = false;
    let mut depth: i32 = 0;
    for line in src.lines() {
        let trimmed: &str = line.trim_start();
        let mut opened_class: bool = false;
        if let Some(rest) = trimmed.strip_prefix("class ") {
            let name: String = ident(rest.trim_start());
            if !name.is_empty() {
                classes.insert(name);
                in_class = true;
                depth = 0;
                opened_class = true;
            }
        }
        if in_class && !opened_class {
            for kw in ["string ", "long ", "void ", "int "] {
                if let Some(rest) = trimmed.strip_prefix(kw) {
                    let after: &str = rest.trim_start();
                    let name: String = ident(after);
                    if !name.is_empty() && after.contains('(') {
                        methods.insert(name);
                    }
                }
            }
        }
        if in_class {
            depth += i32::try_from(line.matches('{').count()).unwrap_or(0);
            depth -= i32::try_from(line.matches('}').count()).unwrap_or(0);
            if depth <= 0 && !opened_class {
                in_class = false;
            }
        }
    }
    SourceTruth { classes, methods }
}

#[test]
fn d_object_detects_and_demangles_matching_known_source() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::D_OBJ_ELF) else {
        panic!(
            "missing committed fixture corpus/native/d/hello.d.o.elf (a tracked corpus file - see corpus/native/MANIFEST or regen.ps1)"
        );
    };
    let src: String = std::fs::read_to_string(d_source_path()).expect("read hello.d source");
    let truth: SourceTruth = parse_d_source(&src);
    assert!(
        truth.classes.contains("Greeter"),
        "source oracle must contain class Greeter; got {:?}",
        truth.classes
    );
    assert!(
        truth.methods.contains("greet") && truth.methods.contains("fib"),
        "source oracle missing greet/fib; got {:?}",
        truth.methods
    );

    let analysis: NativeLangAnalysis = analyze(&bytes).expect("analyze d object");
    assert_eq!(analysis.fingerprint.lang, NativeLang::D, "lang must be d");
    assert_eq!(
        analysis.recovery.source_grade,
        SourceGrade::SymbolsOnly,
        "the d fixture is a relocatable .o: type DIEs are reconstructable but .text has no assigned \
         address so there is no usable pc->line coverage; the grade is SymbolsOnly and \
         source_recoverable stays false honestly (not a hardcoded wall, a measured one)",
    );
    assert!(
        !analysis.recovery.source_recoverable,
        "relocatable d object grades source_recoverable=false (no line coverage)",
    );
    assert!(
        analysis.types.named_type_count > 0,
        "d DWARF still yields reconstructed type DIEs even when line coverage is absent, got {}",
        analysis.types.named_type_count,
    );
    assert!(
        analysis.recovery.has_symbol_table,
        "real d object must carry a symbol table"
    );

    let independent: BTreeSet<String> = elf_symtab_names(&bytes);
    assert!(
        independent
            .iter()
            .any(|s: &String| s == "_D5hello7Greeter3fibMFlZl"),
        "independent symtab oracle missing the real mangled fib symbol"
    );

    let demangled: BTreeSet<String> = analysis
        .recovery
        .demangled
        .iter()
        .map(|d: &DemangledSymbol| d.demangled.clone())
        .collect();
    for method in &truth.methods {
        let recovered: bool = analysis
            .recovery
            .demangled
            .iter()
            .any(|d: &DemangledSymbol| {
                d.module.as_deref() == Some("hello.Greeter") && &d.name == method
            });
        assert!(
            recovered,
            "pass did not demangle hello.Greeter.{method} from real d symtab; got {demangled:?}"
        );
    }
    assert!(
        demangled.contains("D main"),
        "pass did not recover the D entrypoint _Dmain"
    );
    assert!(
        analysis
            .recovery
            .user_modules
            .iter()
            .any(|m: &String| m == "hello"),
        "user module 'hello' not recovered from real d binary"
    );
    assert!(
        analysis.recovery.std_symbol_count > 10,
        "too few d std (core/std/object) symbols recovered: {}",
        analysis.recovery.std_symbol_count
    );
    assert_eq!(
        analysis.recovery.gc.gc_kind.as_deref(),
        Some("druntime-conservative")
    );
}

#[test]
fn d_object_recovers_per_section_relocatable_functions() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::D_OBJ_ELF) else {
        panic!(
            "missing committed fixture corpus/native/d/hello.d.o.elf (a tracked corpus file - see corpus/native/MANIFEST or regen.ps1)"
        );
    };
    let sized: BTreeMap<String, u64> = elf_func_symbol_sizes(&bytes);
    let comdat_funcs: usize = sized.len();
    assert!(
        comdat_funcs > 50,
        "independent oracle: real d object must carry many sized STT_FUNC symbols, \
         got {comdat_funcs}"
    );

    let analysis: NativeLangAnalysis = analyze(&bytes).expect("analyze d object");
    let recovered_reloc: usize = analysis
        .function_recovery
        .functions
        .iter()
        .filter(|f: &&RecoveredFunction| !f.address_assigned)
        .count();
    assert_eq!(
        analysis.function_recovery.from_relocatable, recovered_reloc,
        "from_relocatable count must match flagged functions"
    );
    assert!(
        recovered_reloc >= comdat_funcs,
        "relocatable recovery ({recovered_reloc}) must cover every sized symtab function ({comdat_funcs})"
    );

    for (name, mangled, signature) in [
        (
            "hello.Greeter.fib",
            "_D5hello7Greeter3fibMFlZl",
            "long hello.Greeter.fib(long)",
        ),
        (
            "hello.Greeter.greet",
            "_D5hello7Greeter5greetMFZAya",
            "immutable(char)[] hello.Greeter.greet()",
        ),
        (
            "hello.Greeter.__ctor",
            "_D5hello7Greeter6__ctorMFAyaZCQBcQz",
            "hello.Greeter hello.Greeter.__ctor(immutable(char)[])",
        ),
    ] {
        let f: &RecoveredFunction = analysis
            .function_recovery
            .functions
            .iter()
            .find(|f: &&RecoveredFunction| f.demangled.as_deref() == Some(name))
            .unwrap_or_else(|| panic!("relocatable function {name} not recovered"));
        assert!(
            !f.address_assigned,
            "{name} is in an unlinked object; it must NOT claim an assigned address"
        );
        assert_eq!(
            f.signature.as_deref(),
            Some(signature),
            "{name} must surface its full ldc2-equivalent type signature"
        );
        let size: u64 = *sized
            .get(mangled)
            .unwrap_or_else(|| panic!("oracle missing mangled symbol {mangled}"));
        assert_eq!(
            f.end,
            Some(size),
            "{name} recovered size must equal the real symtab st_size"
        );
    }
}

#[test]
fn d_object_dwarf_present_with_subprograms() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::D_OBJ_ELF) else {
        panic!(
            "missing committed fixture corpus/native/d/hello.d.o.elf (a tracked corpus file - see corpus/native/MANIFEST or regen.ps1)"
        );
    };
    assert!(
        elf_has_section(&bytes, ".debug_info"),
        "real d object must carry .debug_info"
    );
    let analysis: NativeLangAnalysis = analyze(&bytes).expect("analyze d object");
    assert!(
        analysis.dwarf.present,
        "dwarf must be recovered from d object"
    );
    assert!(
        analysis.dwarf.functions.len() > 10,
        "expected many dwarf subprograms in d object, got {}",
        analysis.dwarf.functions.len()
    );
}

fn find_aggregate<'a>(aggs: &'a [DwarfAggregate], name: &str) -> Option<&'a DwarfAggregate> {
    aggs.iter().find(|a: &&DwarfAggregate| a.name == name)
}

#[test]
fn d_object_recovers_class_type_with_field_and_base_from_dwarf() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::D_OBJ_ELF) else {
        panic!(
            "missing committed fixture corpus/native/d/hello.d.o.elf (a tracked corpus file - see corpus/native/MANIFEST or regen.ps1)"
        );
    };
    let src: String = std::fs::read_to_string(d_source_path()).expect("read hello.d source");
    let truth: SourceTruth = parse_d_source(&src);
    assert!(
        truth.classes.contains("Greeter"),
        "source oracle must contain class Greeter"
    );

    let independent: BTreeSet<String> = elf_debug_str_set(&bytes);
    assert!(
        independent.contains("Greeter") && independent.contains("name"),
        "independent .debug_str oracle must carry the Greeter type and its name field"
    );

    let analysis: NativeLangAnalysis = analyze(&bytes).expect("analyze d object");
    let greeter: &DwarfAggregate = find_aggregate(&analysis.dwarf.aggregates, "Greeter")
        .expect("Greeter aggregate must be recovered from dwarf");
    assert_eq!(greeter.byte_size, Some(32), "Greeter instance size");
    assert!(
        greeter.bases.iter().any(|b: &String| b == "Object"),
        "Greeter must inherit from Object; got {:?}",
        greeter.bases
    );
    let name_field: &DwarfMember = greeter
        .members
        .iter()
        .find(|m: &&DwarfMember| m.name == "name")
        .expect("Greeter.name field must be recovered");
    assert_eq!(
        name_field.type_name.as_deref(),
        Some("string"),
        "Greeter.name must recover its source type `string`, proving relocations were applied"
    );
    assert_eq!(
        name_field.byte_offset,
        Some(16),
        "Greeter.name sits past the vtable+monitor object header"
    );

    let throwable: &DwarfAggregate = find_aggregate(&analysis.dwarf.aggregates, "Throwable")
        .expect("Throwable type recovered from druntime dwarf");
    assert!(
        throwable
            .members
            .iter()
            .any(|m: &DwarfMember| { m.name == "msg" && m.type_name.as_deref() == Some("string") }),
        "Throwable.msg:string must be recovered, not the producer string"
    );
    for field in ["infoDeallocator", "nextInChain", "_refcount"] {
        assert!(
            throwable
                .members
                .iter()
                .any(|member: &DwarfMember| member.name == field),
            "Throwable member {field} after nested TraceInfo must be recovered; got {:?}",
            throwable
                .members
                .iter()
                .map(|member: &DwarfMember| member.name.as_str())
                .collect::<Vec<&str>>()
        );
    }

    let blkattr: &DwarfAggregate =
        find_aggregate(&analysis.dwarf.aggregates, "BlkAttr").expect("BlkAttr enum recovered");
    assert_eq!(blkattr.kind, AggregateKind::Enum, "BlkAttr is an enum");
    for variant in ["NONE", "FINALIZE", "NO_SCAN", "APPENDABLE"] {
        assert!(
            blkattr.enumerators.iter().any(|e: &String| e == variant),
            "BlkAttr enum missing variant {variant}; got {:?}",
            blkattr.enumerators
        );
    }

    for agg in &analysis.dwarf.aggregates {
        assert!(
            !agg.name.starts_with("LDC "),
            "no aggregate name may resolve to the producer string (unapplied relocation): {}",
            agg.name
        );
        for m in &agg.members {
            assert!(
                m.type_name
                    .as_deref()
                    .is_none_or(|t: &str| !t.contains("LDC ")),
                "member {} of {} resolved to the producer string",
                m.name,
                agg.name
            );
        }
    }
}

#[test]
fn nim_recovers_record_types_with_named_fields_from_dwarf() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::NIM_ELF) else {
        panic!(
            "missing committed fixture corpus/native/nim/hello.nim.elf (a tracked corpus file - see corpus/native/MANIFEST or regen.ps1)"
        );
    };
    let independent: BTreeSet<String> = elf_debug_str_set(&bytes);
    for want in ["NimStringV2", "RootObj", "Exception"] {
        assert!(
            independent.contains(want),
            "independent .debug_str oracle must carry nim type {want}"
        );
    }

    let analysis: NativeLangAnalysis = analyze(&bytes).expect("analyze nim elf");
    assert!(
        analysis.dwarf.aggregates.len() > 10,
        "expected the nim runtime type table, got {}",
        analysis.dwarf.aggregates.len()
    );

    let nimstr: &DwarfAggregate =
        find_aggregate(&analysis.dwarf.aggregates, "NimStringV2").expect("NimStringV2 recovered");
    assert!(
        nimstr.members.iter().any(|m: &DwarfMember| m.name == "len"),
        "NimStringV2 must expose its len field"
    );
    assert!(
        nimstr.members.iter().any(|m: &DwarfMember| m.name == "p"),
        "NimStringV2 must expose its payload pointer field"
    );

    let exc: &DwarfAggregate =
        find_aggregate(&analysis.dwarf.aggregates, "Exception").expect("Exception recovered");
    assert!(
        exc.members
            .iter()
            .any(|m: &DwarfMember| m.name == "message"),
        "nim Exception must expose its message field; got {:?}",
        exc.members
            .iter()
            .map(|m: &DwarfMember| &m.name)
            .collect::<Vec<_>>()
    );
}

#[test]
fn zig_recovers_enum_variants_matching_independent_debug_str() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::ZIG_ELF) else {
        panic!(
            "missing committed fixture corpus/native/zig/hello.zig.elf (a tracked corpus file - see corpus/native/MANIFEST or regen.ps1)"
        );
    };
    let independent: BTreeSet<String> = elf_debug_str_set(&bytes);
    assert!(
        independent.contains("SemanticVersion"),
        "independent oracle must carry std SemanticVersion type"
    );

    let analysis: NativeLangAnalysis = analyze(&bytes).expect("analyze zig elf");
    let arch: &DwarfAggregate = find_aggregate(&analysis.dwarf.aggregates, "Target.Cpu.Arch")
        .expect("zig Target.Cpu.Arch enum recovered");
    assert_eq!(arch.kind, AggregateKind::Enum);
    for variant in ["x86_64", "aarch64", "wasm32", "riscv64"] {
        assert!(
            arch.enumerators.iter().any(|e: &String| e == variant),
            "Target.Cpu.Arch missing variant {variant}"
        );
    }

    let semver: &DwarfAggregate = find_aggregate(&analysis.dwarf.aggregates, "SemanticVersion")
        .expect("SemanticVersion struct recovered");
    for field in ["major", "minor", "patch"] {
        assert!(
            semver.members.iter().any(|m: &DwarfMember| m.name == field),
            "SemanticVersion missing field {field}"
        );
    }
}

#[test]
fn d_linked_pe_detected_on_stripped_real_binary() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::D_PE) else {
        panic!(
            "missing committed fixture corpus/native/d/hello.d.exe (a tracked corpus file - see corpus/native/MANIFEST or regen.ps1)"
        );
    };
    let analysis: NativeLangAnalysis = analyze(&bytes).expect("analyze d pe");
    assert_eq!(
        analysis.fingerprint.lang,
        NativeLang::D,
        "linked stripped d PE must still fingerprint as d"
    );
    assert!(
        analysis
            .fingerprint
            .markers
            .iter()
            .any(|m: &String| m == "rt.dmain2"),
        "d PE must carry the rt.dmain2 druntime marker; got {:?}",
        analysis.fingerprint.markers
    );
    assert_eq!(
        analysis.recovery.gc.gc_kind.as_deref(),
        Some("druntime-conservative")
    );
}

fn d_mangled_segments(body: &str) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut rest: &str = body;
    while let Some(non_digit) = rest.find(|c: char| !c.is_ascii_digit()) {
        if non_digit == 0 {
            break;
        }
        let Ok(len): Result<usize, _> = rest[..non_digit].parse::<usize>() else {
            break;
        };
        let end: usize = non_digit + len;
        if end > rest.len() || !rest.is_char_boundary(end) {
            break;
        }
        parts.push(rest[non_digit..end].to_owned());
        rest = &rest[end..];
    }
    parts
}

fn d_classinfo_names_from_symtab(bytes: &[u8]) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for sym in elf_symtab_names(bytes) {
        let Some(body): Option<&str> = sym.strip_prefix("_D") else {
            continue;
        };
        if !sym.ends_with("7__ClassZ") {
            continue;
        }
        let parts: Vec<String> = d_mangled_segments(body);
        if parts.last().map(String::as_str) != Some("__Class") || parts.len() < 2 {
            continue;
        }
        let qualified: String = parts[..parts.len() - 1].join(".");
        if qualified.contains('.') {
            out.insert(qualified);
        }
    }
    out
}

fn d_rtti_name_shape(name: &str) -> bool {
    const BUILTIN: &[&str] = &[
        "real",
        "float",
        "double",
        "int",
        "uint",
        "long",
        "ulong",
        "byte",
        "ubyte",
        "short",
        "ushort",
        "char",
        "wchar",
        "dchar",
        "bool",
        "void",
        "string",
        "wstring",
        "dstring",
        "size_t",
        "ptrdiff_t",
    ];
    const EXT: &[&str] = &["d", "di", "dll", "so", "exe", "pdb", "obj", "lib"];
    let is_lower = |seg: &str| -> bool {
        seg.bytes()
            .next()
            .is_some_and(|b: u8| b.is_ascii_lowercase() || b == b'_')
            && seg
                .bytes()
                .all(|b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    };
    let is_type = |seg: &str| -> bool {
        seg.bytes()
            .next()
            .is_some_and(|b: u8| b.is_ascii_uppercase())
            && seg
                .bytes()
                .all(|b: u8| b.is_ascii_alphanumeric() || b == b'_')
    };
    let segments: Vec<&str> = name.split('.').collect();
    if !(2..=8).contains(&segments.len()) || name.len() > 200 {
        return false;
    }
    let root: &str = segments[0];
    if root.len() < 2
        || root.bytes().any(|b: u8| b.is_ascii_digit())
        || !is_lower(root)
        || BUILTIN.contains(&root)
    {
        return false;
    }
    let leaf: &str = segments[segments.len() - 1];
    if EXT.contains(&leaf) {
        return false;
    }
    if segments[1..segments.len() - 1]
        .iter()
        .any(|seg: &&str| seg.len() < 2 || !is_lower(seg))
    {
        return false;
    }
    is_type(leaf) || (leaf.len() >= 2 && is_lower(leaf))
}

fn d_rtti_anchor_pool(bytes: &[u8]) -> BTreeSet<String> {
    const D_PACKAGE_ROOTS: [&str; 7] = ["core", "std", "object", "rt", "gc", "etc", "ldc"];
    let mut out: BTreeSet<String> = BTreeSet::new();
    for chunk in bytes.split(|b: &u8| *b == 0) {
        if chunk.len() < 4 || !chunk.iter().all(|b: &u8| (0x20..0x7f).contains(b)) {
            continue;
        }
        let Ok(text): Result<&str, _> = std::str::from_utf8(chunk) else {
            continue;
        };
        let is_package_rooted: bool = text
            .split_once('.')
            .is_some_and(|(root, _): (&str, &str)| D_PACKAGE_ROOTS.contains(&root));
        if is_package_rooted && d_rtti_name_shape(text) {
            out.insert(text.to_owned());
        }
    }
    out
}

#[test]
fn d_linked_pe_recovers_rtti_dotted_names_matching_symtab_and_pool() {
    let Some(pe): Option<Vec<u8>> = common::fixture_or_skip(common::D_PE) else {
        panic!(
            "missing committed fixture corpus/native/d/hello.d.exe (a tracked corpus file - see corpus/native/MANIFEST or regen.ps1)"
        );
    };
    let Some(obj): Option<Vec<u8>> = common::fixture_or_skip(common::D_OBJ_ELF) else {
        panic!(
            "missing committed fixture corpus/native/d/hello.d.o.elf (a tracked corpus file - see corpus/native/MANIFEST or regen.ps1)"
        );
    };
    assert_eq!(&pe[..2], b"MZ", "d fixture must be a real linked PE");

    let analysis: NativeLangAnalysis = analyze(&pe).expect("analyze d pe");
    assert_eq!(
        analysis.fingerprint.lang,
        NativeLang::D,
        "linked stripped d PE must fingerprint as d"
    );
    assert!(
        !analysis.recovery.has_symbol_table,
        "the linked d PE is stripped: it carries no COFF symbol table, so recovery runs the \
         RTTI-name fallback, not the symtab path"
    );

    let recovered: BTreeSet<String> = analysis
        .recovery
        .demangled
        .iter()
        .map(|d: &DemangledSymbol| d.demangled.clone())
        .collect();

    let ground_truth: BTreeSet<String> = d_classinfo_names_from_symtab(&obj);
    assert!(
        ground_truth.contains("hello.Greeter"),
        "the unstripped .o symtab is the ground truth; its _D..7__ClassZ symbols must include the \
         user class hello.Greeter, got {ground_truth:?}"
    );
    assert!(
        ground_truth.len() >= 3,
        "the .o symtab must attest several dotted ClassInfo names, got {ground_truth:?}"
    );
    let symtab_hits: usize = ground_truth
        .iter()
        .filter(|name: &&String| recovered.contains(*name))
        .count();
    let symtab_coverage: f64 = symtab_hits as f64 / ground_truth.len() as f64;
    assert!(
        symtab_coverage >= 0.9,
        "recovery must cover >=90% of the ClassInfo names attested by the real .o symbol table; \
         covered {symtab_hits}/{} ({symtab_coverage:.3}); recovered set omitted names {:?}",
        ground_truth.len(),
        ground_truth
            .iter()
            .filter(|n: &&String| !recovered.contains(*n))
            .collect::<Vec<&String>>()
    );
    assert!(
        recovered.contains("hello.Greeter"),
        "the whole point: the user class hello.Greeter must be recovered from the stripped PE \
         (before the RTTI miner this was zero)"
    );

    let anchors: BTreeSet<String> = d_rtti_anchor_pool(&pe);
    assert!(
        anchors.len() > 100,
        "independent druntime anchor pool (NUL-delimited C-strings rooted at real druntime \
         packages) must be rich, got {}",
        anchors.len()
    );
    let anchor_hits: usize = anchors
        .iter()
        .filter(|name: &&String| recovered.contains(*name))
        .count();
    let anchor_coverage: f64 = anchor_hits as f64 / anchors.len() as f64;
    assert!(
        anchor_coverage >= 0.9,
        "recovery must cover >=90% of the binary's own druntime RTTI anchor pool; covered \
         {anchor_hits}/{} ({anchor_coverage:.3})",
        anchors.len()
    );

    assert!(
        analysis
            .recovery
            .user_modules
            .iter()
            .any(|m: &String| m == "hello"),
        "hello must be recovered as a user module from the RTTI pool"
    );
    assert!(
        analysis
            .recovery
            .user_modules
            .iter()
            .all(|m: &String| m == "hello"),
        "soundness: the only user module is hello; druntime/runtime/junk names must not inflate \
         user recovery, got {:?}",
        analysis.recovery.user_modules
    );
    assert!(
        analysis.recovery.std_symbol_count > 100,
        "the druntime/phobos RTTI names must be recovered and honestly classified as std, got {}",
        analysis.recovery.std_symbol_count
    );
    assert!(
        analysis
            .recovery
            .std_modules
            .iter()
            .any(|m: &String| m == "core")
            && analysis
                .recovery
                .std_modules
                .iter()
                .any(|m: &String| m == "std"),
        "core and std druntime roots must be recovered as std modules, got {:?}",
        analysis.recovery.std_modules
    );
}

#[test]
fn clean_control_binary_yields_no_d_fingerprint() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::D_CLEAN_CONTROL) else {
        panic!(
            "missing committed fixture corpus/native/d/clean_control.exe (a tracked corpus file - see corpus/native/MANIFEST or regen.ps1)"
        );
    };
    if let Ok(analysis) = analyze(&bytes) {
        assert_ne!(
            analysis.fingerprint.lang,
            NativeLang::D,
            "a plain C binary must never fingerprint as D"
        );
    }
}

#[test]
fn cross_language_fingerprints_do_not_collide() {
    let langs: [(&str, NativeLang); 4] = [
        (common::ZIG_ELF, NativeLang::Zig),
        (common::NIM_ELF, NativeLang::Nim),
        (common::CRYSTAL_PE, NativeLang::Crystal),
        (common::D_PE, NativeLang::D),
    ];
    for (rel, expected) in langs {
        let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(rel) else {
            panic!("missing committed fixture {rel} (a tracked corpus file)");
        };
        let analysis: NativeLangAnalysis = analyze(&bytes).expect("analyze");
        assert_eq!(
            analysis.fingerprint.lang, expected,
            "fingerprint collision for {rel}"
        );
    }
}

fn recovered_by_start(analysis: &NativeLangAnalysis, start: u64) -> Option<&RecoveredFunction> {
    analysis
        .function_recovery
        .functions
        .iter()
        .find(|f: &&RecoveredFunction| f.start == start)
}

#[test]
fn nim_function_boundaries_match_independent_symtab() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::NIM_ELF) else {
        panic!(
            "missing committed fixture corpus/native/nim/hello.nim.elf (a tracked corpus file - see corpus/native/MANIFEST or regen.ps1)"
        );
    };
    let analysis: NativeLangAnalysis = analyze(&bytes).expect("analyze nim elf");

    let truth: BTreeMap<String, (u64, u64)> = elf_func_symbols(&bytes);
    let (fib_addr, fib_size): (u64, u64) = *truth
        .get("_ZN5hello3fibE3int")
        .expect("oracle missing fib symbol");
    let (greet_addr, greet_size): (u64, u64) = *truth
        .get("_ZN5hello5greetE6string")
        .expect("oracle missing greet symbol");

    let fib: &RecoveredFunction =
        recovered_by_start(&analysis, fib_addr).expect("fib not recovered at oracle address");
    assert_eq!(
        fib.end,
        Some(fib_addr + fib_size),
        "fib boundary disagrees with independent symtab [start,start+size)"
    );
    assert_eq!(fib.demangled.as_deref(), Some("hello.fib"));
    assert_eq!(fib.params, vec!["int".to_owned()]);

    let greet: &RecoveredFunction =
        recovered_by_start(&analysis, greet_addr).expect("greet not recovered at oracle address");
    assert_eq!(greet.end, Some(greet_addr + greet_size));
    assert_eq!(greet.demangled.as_deref(), Some("hello.greet"));
    assert_eq!(greet.params, vec!["string".to_owned()]);

    let common_boundaries: usize = analysis
        .function_recovery
        .functions
        .iter()
        .filter(|f: &&RecoveredFunction| {
            truth
                .values()
                .any(|(a, s): &(u64, u64)| *a == f.start && Some(*a + *s) == f.end)
        })
        .count();
    assert!(
        common_boundaries >= truth.len(),
        "recovered boundaries ({common_boundaries}) must cover every independent symtab function ({})",
        truth.len()
    );
}

#[test]
fn nim_dwarf_present_and_low_pc_matches_independent_symtab() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::NIM_ELF) else {
        panic!(
            "missing committed fixture corpus/native/nim/hello.nim.elf (a tracked corpus file - see corpus/native/MANIFEST or regen.ps1)"
        );
    };
    assert!(
        elf_has_section(&bytes, ".debug_info"),
        "independent oracle: nim binary must carry .debug_info"
    );
    assert!(elf_has_section(&bytes, ".debug_line"));

    let analysis: NativeLangAnalysis = analyze(&bytes).expect("analyze nim elf");
    assert!(analysis.dwarf.present, "dwarf must be recovered");
    assert_eq!(analysis.dwarf.dwarf_version, Some(4));
    assert!(
        analysis.dwarf.functions.len() > 50,
        "expected many dwarf subprograms, got {}",
        analysis.dwarf.functions.len()
    );

    let truth: BTreeMap<String, (u64, u64)> = elf_func_symbols(&bytes);
    let (fib_addr, _): (u64, u64) = *truth.get("_ZN5hello3fibE3int").unwrap();

    let dwarf_fib: &_ = analysis
        .dwarf
        .functions
        .iter()
        .find(|d| d.name == "_ZN5hello3fibE3int")
        .expect("dwarf missing fib subprogram");
    assert_eq!(
        dwarf_fib.low_pc,
        Some(fib_addr),
        "dwarf low_pc (.debug_info) must equal symtab address (.symtab); two independent oracles"
    );
    assert_eq!(dwarf_fib.decl_file.as_deref(), Some("hello.nim"));
    assert_eq!(
        dwarf_fib.decl_line,
        Some(1),
        "fib declared on line 1 of hello.nim"
    );
    assert_eq!(dwarf_fib.params, vec!["n_p0".to_owned()]);

    let fib: &RecoveredFunction = recovered_by_start(&analysis, fib_addr).unwrap();
    let lines = fib.source_lines.as_ref().expect("fib must have line range");
    assert_eq!(lines.file.as_deref(), Some("hello.nim"));
    assert_eq!(lines.lo, 1, "fib source line range starts at decl line 1");
}

#[test]
fn zig_function_boundaries_and_dwarf_lines_match_source() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::ZIG_ELF) else {
        panic!(
            "missing committed fixture corpus/native/zig/hello.zig.elf (a tracked corpus file - see corpus/native/MANIFEST or regen.ps1)"
        );
    };
    assert!(elf_has_section(&bytes, ".debug_info"));
    let analysis: NativeLangAnalysis = analyze(&bytes).expect("analyze zig elf");
    assert!(analysis.dwarf.present);

    let truth: BTreeMap<String, (u64, u64)> = elf_func_symbols(&bytes);
    let (fib_addr, fib_size): (u64, u64) =
        *truth.get("hello.fib").expect("oracle missing hello.fib");

    let fib: &RecoveredFunction =
        recovered_by_start(&analysis, fib_addr).expect("fib not recovered");
    assert_eq!(
        fib.end,
        Some(fib_addr + fib_size),
        "zig fib boundary must equal independent symtab span"
    );

    let lines = fib.source_lines.as_ref().expect("fib line range");
    assert_eq!(lines.file.as_deref(), Some("hello.zig"));
    assert_eq!(lines.lo, 3, "fn fib begins at line 3 of hello.zig");
    assert!(lines.hi >= 5, "fib body spans through at least line 5");
    assert_eq!(fib.params, vec!["n".to_owned()]);
}

#[test]
fn debug_binaries_recover_types_lines_and_disassembly_but_not_source_text() {
    for rel in [common::NIM_ELF, common::ZIG_ELF] {
        let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(rel) else {
            panic!("missing committed fixture {rel} (a tracked corpus file)");
        };
        let analysis: NativeLangAnalysis = analyze(&bytes).expect("analyze");
        assert_eq!(
            analysis.recovery.source_grade,
            SourceGrade::TypesAndLines,
            "{rel}: debug-built binary carries DWARF; types + line map are recoverable",
        );
        assert!(
            analysis.types.named_type_count > 0,
            "{rel}: real type DIEs must be reconstructed from the binary's own .debug_info",
        );
        assert!(
            analysis.types.line_coverage_pct >= 80.0,
            "{rel}: .text line coverage must clear 80%, got {:.1}%",
            analysis.types.line_coverage_pct,
        );
        assert!(
            analysis.disasm.arch_supported && !analysis.disasm.listings.is_empty(),
            "{rel}: each function's machine-code range must be carved and disassembled, got {} listings",
            analysis.disasm.listings.len(),
        );
        assert_eq!(
            analysis.nir.lang,
            SourceLang::NativeX86,
            "{rel}: native x86-64 disassembly must lift into NIR"
        );
        assert_eq!(
            analysis.nir.functions.len(),
            analysis.disasm.listings.len(),
            "{rel}: NIR must cover the same carved function bodies as disassembly"
        );
        assert!(
            analysis
                .nir
                .functions
                .iter()
                .any(|function: &NirFunction| !function.name.starts_with("sub_")
                    && !function.instructions.is_empty()),
            "{rel}: named recovered functions must reach NIR with decoded instructions",
        );
        let any_real_insn: bool = analysis
            .disasm
            .listings
            .iter()
            .flat_map(|f| f.instructions.iter())
            .any(|i| !i.mnemonic.is_empty() && i.mnemonic != "(bad)");
        assert!(
            any_real_insn,
            "{rel}: carved bodies must decode to real instructions, not garbage",
        );
        assert!(
            analysis.function_recovery.from_symbol_table > 0,
            "{rel}: symbol-table boundaries must be recovered"
        );
        assert_eq!(
            analysis.function_recovery.from_traversal, 0,
            "{rel}: symtab is present so recursive traversal must not run"
        );
    }
}

#[test]
fn stripped_binary_surfaces_entry_points_honestly() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::ZIG_ELF) else {
        panic!(
            "missing committed fixture corpus/native/zig/hello.zig.elf (a tracked corpus file - see corpus/native/MANIFEST or regen.ps1)"
        );
    };
    let stripped: Vec<u8> = strip_elf_symtab(&bytes);
    assert!(
        elf_func_symbols(&stripped).is_empty(),
        "symtab strip failed; oracle still sees function symbols"
    );

    let analysis: NativeLangAnalysis = analyze(&stripped).expect("analyze stripped zig");
    assert_eq!(
        analysis.fingerprint.lang,
        NativeLang::Zig,
        "stripped binary still fingerprints as zig"
    );
    assert!(
        analysis.function_recovery.traversal_attempted,
        "recursive traversal must run on a stripped binary"
    );
    assert!(
        analysis.function_recovery.from_traversal > 0,
        "traversal must surface entry points on a stripped x86 binary"
    );
    assert!(
        analysis
            .function_recovery
            .functions
            .iter()
            .all(|f: &RecoveredFunction| f.origin == FunctionOrigin::RecursiveTraversal),
        "stripped recovery must be traversal-only (no fake symtab names)"
    );
    assert!(
        analysis
            .function_recovery
            .functions
            .iter()
            .all(|f: &RecoveredFunction| f.demangled.is_none() && f.name.starts_with("sub_")),
        "stripped functions must be address-derived, never fabricated names"
    );
    assert!(
        analysis
            .nir
            .functions
            .iter()
            .all(|function: &NirFunction| function.name.starts_with("sub_")
                && !function.instructions.is_empty()),
        "stripped NIR functions must use the same address-derived names and real decoded instructions",
    );
}

fn strip_elf_symtab(bytes: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = bytes.to_vec();
    if out.len() < 0x40 || &out[..4] != b"\x7fELF" {
        return out;
    }
    let rd64 =
        |b: &[u8], off: usize| -> u64 { u64::from_le_bytes(b[off..off + 8].try_into().unwrap()) };
    let rd32 =
        |b: &[u8], off: usize| -> u32 { u32::from_le_bytes(b[off..off + 4].try_into().unwrap()) };
    let rd16 =
        |b: &[u8], off: usize| -> u16 { u16::from_le_bytes(b[off..off + 2].try_into().unwrap()) };
    let e_shoff: usize = rd64(&out, 0x28) as usize;
    let e_shentsize: usize = rd16(&out, 0x3a) as usize;
    let e_shnum: usize = rd16(&out, 0x3c) as usize;
    let e_shstrndx: usize = rd16(&out, 0x3e) as usize;
    let shstr_off: usize = rd64(&out, e_shoff + e_shstrndx * e_shentsize + 0x18) as usize;
    let cstr = |b: &[u8], off: usize| -> String {
        let end: usize = b[off..]
            .iter()
            .position(|x: &u8| *x == 0)
            .map_or(b.len(), |p: usize| off + p);
        String::from_utf8_lossy(&b[off..end]).into_owned()
    };
    for i in 0..e_shnum {
        let base: usize = e_shoff + i * e_shentsize;
        let name_off: u32 = rd32(&out, base);
        let sname: String = cstr(&out, shstr_off + name_off as usize);
        if sname == ".symtab" || sname.starts_with(".debug_") || sname.starts_with(".zdebug_") {
            out[base + 4..base + 8].copy_from_slice(&8u32.to_le_bytes());
        }
    }
    out
}
