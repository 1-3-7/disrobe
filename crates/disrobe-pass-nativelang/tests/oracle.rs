#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;

use disrobe_pass_nativelang::{NativeLang, NativeLangAnalysis, analyze};

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

#[test]
fn crystal_detects_and_recovers_type_table_matching_known_source() {
    let Some(bytes): Option<Vec<u8>> = common::fixture_or_skip(common::CRYSTAL_PE) else {
        return;
    };
    let analysis: NativeLangAnalysis = analyze(&bytes).expect("analyze crystal pe");
    assert_eq!(
        analysis.fingerprint.lang,
        NativeLang::Crystal,
        "lang must be crystal"
    );
    assert!(
        !analysis.recovery.source_recoverable,
        "crystal source not recoverable"
    );

    let user_type: bool = analysis
        .recovery
        .demangled
        .iter()
        .any(|d| d.demangled == "Greeter" || d.name == "Greeter");
    assert!(
        user_type,
        "pass did not recover user class Greeter from type table"
    );

    let crystal_runtime: bool = analysis.recovery.demangled.iter().any(|d| {
        d.module
            .as_deref()
            .is_some_and(|m| m.starts_with("Crystal"))
    });
    assert!(
        crystal_runtime,
        "pass did not recover Crystal:: runtime types"
    );

    assert!(
        analysis
            .recovery
            .gc
            .runtime_symbols
            .iter()
            .any(|s| s == "GC_init")
            || analysis
                .recovery
                .gc
                .runtime_symbols
                .iter()
                .any(|s| s == "__crystal_raise"),
        "missing crystal GC/runtime metadata"
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
