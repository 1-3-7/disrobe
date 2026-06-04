#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_pass_nativelang::{
    DemangledSymbol, NativeLang, NativeLangAnalysis, analyze, demangle_crystal,
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
        let (name_off, typ, off, size, link, entsize) = sec(i);
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

#[test]
fn zig_detects_and_demangles_matching_independent_symtab() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::ZIG_ELF) else {
        return;
    };
    let analysis: NativeLangAnalysis = analyze(&bytes).expect("analyze zig elf");
    assert_eq!(
        analysis.fingerprint.lang,
        NativeLang::Zig,
        "lang must be zig"
    );
    assert!(
        !analysis.recovery.source_recoverable,
        "zig source not recoverable"
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
        .map(|d| d.demangled.clone())
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
        .any(|d| d.module.as_deref() == Some("hello") && d.name == "greet");
    assert!(
        greet_recovered,
        "pass did not recover demangled hello.greet (anon stripped)"
    );

    let std_recovered: bool = analysis
        .recovery
        .demangled
        .iter()
        .any(|d| d.module.as_deref() == Some("posix") || d.module.as_deref() == Some("start"));
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
        return;
    };
    let analysis: NativeLangAnalysis = analyze(&bytes).expect("analyze nim elf");
    assert_eq!(
        analysis.fingerprint.lang,
        NativeLang::Nim,
        "lang must be nim"
    );
    assert!(
        !analysis.recovery.source_recoverable,
        "nim source not recoverable"
    );

    let independent: BTreeSet<String> = elf_symtab_names(&bytes);
    assert!(
        independent.contains("_ZN5hello5greetE6string"),
        "independent oracle missing mangled greet"
    );
    assert!(
        independent.iter().any(|s| s == "NimMain"),
        "independent oracle missing NimMain runtime"
    );

    let greet: bool = analysis.recovery.demangled.iter().any(|d| {
        d.module.as_deref() == Some("hello") && d.name == "greet" && d.params == ["string"]
    });
    assert!(greet, "pass did not demangle hello.greet(string)");
    let fib: bool =
        analysis.recovery.demangled.iter().any(|d| {
            d.module.as_deref() == Some("hello") && d.name == "fib" && d.params == ["int"]
        });
    assert!(fib, "pass did not demangle hello.fib(int)");

    assert!(
        analysis
            .recovery
            .gc
            .runtime_symbols
            .iter()
            .any(|s| s == "NimMain"),
        "missing NimMain in runtime metadata"
    );
    assert!(
        analysis.recovery.user_modules.iter().any(|m| m == "hello"),
        "user module 'hello' not recovered"
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

fn crystal_codegen_symbols(truth: &SourceTruth) -> Vec<String> {
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
fn crystal_demangler_recovers_source_derived_names_non_circular() {
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

    let symbols: Vec<String> = crystal_codegen_symbols(&truth);
    let demangled: Vec<DemangledSymbol> =
        symbols.iter().filter_map(|s| demangle_crystal(s)).collect();

    let recovered_class: bool = demangled
        .iter()
        .any(|d| d.name == "Greeter" || d.demangled == "Greeter");
    assert!(
        recovered_class,
        "demangler did not recover class Greeter from {symbols:?}"
    );

    for method in &truth.methods {
        let recovered: bool = demangled
            .iter()
            .any(|d| d.module.as_deref() == Some("Greeter") && &d.name == method);
        assert!(
            recovered,
            "demangler did not recover Greeter#{method}; got {demangled:?}"
        );
    }

    let runtime: bool = demangled.iter().any(|d| {
        d.module
            .as_deref()
            .is_some_and(|m| m.starts_with("Crystal"))
    });
    assert!(
        runtime,
        "demangler did not recover any Crystal:: runtime namespace type"
    );

    let iocp: bool = demangled.iter().any(|d| {
        d.module.as_deref() == Some("Crystal::EventLoop") && d.name == "IOCP"
    });
    assert!(iocp, "demangler did not recover Crystal::EventLoop::IOCP");
}

#[test]
fn crystal_compiled_binary_roundtrip_sourcing_blocked() {
    let pe: PathBuf = common::corpus_path(common::CRYSTAL_PE);
    assert!(
        std::fs::read(&pe).is_err(),
        "hello.cr.exe unexpectedly present at {}: if a real Crystal binary fixture has been \
         sourced, replace this marker with a full analyze()-based detection + symtab-demangle \
         roundtrip (see crystal_detect_and_demangle_on_real_binary in git history)",
        pe.display()
    );
}

#[test]
fn cross_language_fingerprints_do_not_collide() {
    let langs: [(&str, NativeLang); 3] = [
        (common::ZIG_ELF, NativeLang::Zig),
        (common::NIM_ELF, NativeLang::Nim),
        (common::CRYSTAL_PE, NativeLang::Crystal),
    ];
    for (rel, expected) in langs {
        let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(rel) else {
            continue;
        };
        let analysis: NativeLangAnalysis = analyze(&bytes).expect("analyze");
        assert_eq!(
            analysis.fingerprint.lang, expected,
            "fingerprint collision for {rel}"
        );
    }
}
