use std::collections::BTreeMap;
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::demangle::{DemangledSymbol, demangle_crystal, demangle_nim, demangle_zig};
use crate::detect::NativeLang;
use crate::image::NativeImage;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcMetadata {
    pub gc_kind: Option<String>,
    pub runtime_symbols: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recovery {
    pub lang: NativeLang,
    pub has_symbol_table: bool,
    pub source_recoverable: bool,
    pub demangled: Vec<DemangledSymbol>,
    pub user_modules: Vec<String>,
    pub std_modules: Vec<String>,
    pub std_symbol_count: usize,
    pub user_symbol_count: usize,
    pub gc: GcMetadata,
    pub strings_sampled: usize,
}

const NIM_STD_PREFIXES: &[&str] = &[
    "system",
    "std",
    "io",
    "os",
    "strutils",
    "sequtils",
    "math",
    "times",
    "tables",
    "sets",
    "hashes",
    "json",
    "parseutils",
    "unicode",
    "algorithm",
    "options",
    "streams",
    "memfiles",
    "dollars",
    "formatfloat",
    "assertions",
    "iterators",
    "widestrs",
];
const NIM_RUNTIME_SYMS: &[&[u8]] = &[
    b"NimMain",
    b"NimMainInner",
    b"NimMainModule",
    b"PreMain",
    b"PreMainInner",
    b"nimGCvisit",
    b"nimRegisterGlobalMarker",
    b"nimFrame",
];

const ZIG_STD_PREFIXES: &[&str] = &[
    "std",
    "start",
    "posix",
    "os",
    "mem",
    "fmt",
    "io",
    "fs",
    "math",
    "heap",
    "debug",
    "builtin",
    "compiler_rt",
    "Thread",
    "process",
    "Allocator",
    "hash",
    "fmt",
];
const ZIG_RUNTIME_SYMS: &[&[u8]] = &[
    b"__zig_probe_stack",
    b"start.posixCallMainAndExit",
    b"start.callMain",
    b"panicOutOfBounds",
];

const CRYSTAL_STD_PREFIXES: &[&str] = &[
    "Crystal",
    "Fiber",
    "Channel",
    "GC",
    "IO",
    "String",
    "Array",
    "Hash",
    "Slice",
    "Pointer",
    "Exception",
    "Int",
    "UInt",
    "Float",
    "Tuple",
    "Range",
    "Enumerable",
    "Iterator",
    "Atomic",
    "Thread",
    "Time",
    "Math",
    "Process",
    "Path",
    "LibC",
];
const CRYSTAL_RUNTIME_SYMS: &[&[u8]] = &[
    b"__crystal_main",
    b"__crystal_raise",
    b"__crystal_once",
    b"GC_init",
    b"Fiber::StackPool",
    b"Crystal::Scheduler",
];

#[must_use]
pub fn recover(image: &NativeImage<'_>, lang: NativeLang) -> Recovery {
    match lang {
        NativeLang::Nim => recover_nim(image),
        NativeLang::Zig => recover_zig(image),
        NativeLang::Crystal => recover_crystal(image),
    }
}

fn recover_nim(image: &NativeImage<'_>) -> Recovery {
    let mut demangled: Vec<DemangledSymbol> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for sym in &image.symbols {
        if let Some(d) = demangle_nim(sym)
            && seen.insert(d.demangled.clone())
        {
            demangled.push(d);
        }
    }
    finish(
        image,
        NativeLang::Nim,
        demangled,
        NIM_STD_PREFIXES,
        NIM_RUNTIME_SYMS,
        Some("boehm-or-orc"),
    )
}

fn recover_zig(image: &NativeImage<'_>) -> Recovery {
    let mut demangled: Vec<DemangledSymbol> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for sym in &image.symbols {
        if let Some(d) = demangle_zig(sym)
            && seen.insert(d.demangled.clone())
        {
            demangled.push(d);
        }
    }
    finish(
        image,
        NativeLang::Zig,
        demangled,
        ZIG_STD_PREFIXES,
        ZIG_RUNTIME_SYMS,
        Some("none-manual"),
    )
}

fn recover_crystal(image: &NativeImage<'_>) -> Recovery {
    let mut demangled: Vec<DemangledSymbol> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let from_symtab: bool = image.has_symbol_table();
    if from_symtab {
        for sym in &image.symbols {
            if let Some(d) = demangle_crystal(sym)
                && seen.insert(d.demangled.clone())
            {
                demangled.push(d);
            }
        }
    }
    if demangled.is_empty() {
        let strings: Vec<String> = image.ascii_strings(3);
        let confirmed_types: BTreeSet<String> = strings
            .iter()
            .filter_map(|s: &String| s.strip_suffix(".class"))
            .map(str::to_owned)
            .collect();
        for s in &strings {
            if let Some(d) = demangle_crystal(s)
                && (looks_like_crystal_type(&d.demangled) || confirmed_types.contains(&d.demangled))
                && seen.insert(d.demangled.clone())
            {
                demangled.push(d);
            }
        }
    }
    finish(
        image,
        NativeLang::Crystal,
        demangled,
        CRYSTAL_STD_PREFIXES,
        CRYSTAL_RUNTIME_SYMS,
        Some("boehm"),
    )
}

fn finish(
    image: &NativeImage<'_>,
    lang: NativeLang,
    demangled: Vec<DemangledSymbol>,
    std_prefixes: &[&str],
    runtime_syms: &[&[u8]],
    gc_kind: Option<&str>,
) -> Recovery {
    let mut user_modules: BTreeSet<String> = BTreeSet::new();
    let mut std_modules: BTreeSet<String> = BTreeSet::new();
    let mut std_count: usize = 0;
    let mut user_count: usize = 0;
    for d in &demangled {
        let top: &str = top_namespace(d);
        if is_std(top, std_prefixes) {
            std_modules.insert(top.to_owned());
            std_count += 1;
        } else {
            user_modules.insert(top.to_owned());
            user_count += 1;
        }
    }
    let runtime_symbols: Vec<String> = runtime_syms
        .iter()
        .filter(|m: &&&[u8]| image.raw_contains(m))
        .map(|m: &&[u8]| String::from_utf8_lossy(m).into_owned())
        .collect();
    Recovery {
        lang,
        has_symbol_table: image.has_symbol_table(),
        source_recoverable: false,
        demangled,
        user_modules: user_modules.into_iter().collect(),
        std_modules: std_modules.into_iter().collect(),
        std_symbol_count: std_count,
        user_symbol_count: user_count,
        gc: GcMetadata {
            gc_kind: gc_kind.map(str::to_owned),
            runtime_symbols,
        },
        strings_sampled: image.ascii_strings(3).len(),
    }
}

fn top_namespace(d: &DemangledSymbol) -> &str {
    if let Some(module) = &d.module {
        let head: &str = module
            .split("::")
            .next()
            .unwrap_or(module)
            .split('.')
            .next()
            .unwrap_or(module);
        if !head.is_empty() {
            return head;
        }
    }
    &d.name
}

fn is_std(top: &str, std_prefixes: &[&str]) -> bool {
    std_prefixes
        .iter()
        .any(|p: &&str| top == *p || top.starts_with(p))
}

fn looks_like_crystal_type(name: &str) -> bool {
    name.contains("::") || name.contains('#') || CRYSTAL_STD_PREFIXES.contains(&name)
}

#[must_use]
pub fn module_histogram(rec: &Recovery) -> BTreeMap<String, usize> {
    let mut out: BTreeMap<String, usize> = BTreeMap::new();
    for d in &rec.demangled {
        let top: &str = top_namespace(d);
        *out.entry(top.to_owned()).or_insert(0) += 1;
    }
    out
}
