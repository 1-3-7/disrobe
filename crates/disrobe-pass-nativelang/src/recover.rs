use std::collections::BTreeMap;
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::debug;
use crate::demangle::{DemangledSymbol, demangle_crystal, demangle_d, demangle_nim, demangle_zig};
use crate::detect::NativeLang;
use crate::dwarf_types::{SourceGrade, TypeReport};
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
    pub source_grade: SourceGrade,
    pub demangled: Vec<DemangledSymbol>,
    pub user_modules: Vec<String>,
    pub std_modules: Vec<String>,
    pub std_symbol_count: usize,
    pub user_symbol_count: usize,
    pub gc: GcMetadata,
    pub strings_sampled: usize,
    pub strings_truncated: bool,
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

const NIM_ARC_API_MARKERS: &[&str] = &["nimNewObj", "nimRawDispose", "nimDestroyAndDispose"];
const NIM_ORC_CYCLE_MARKERS: &[&str] = &[
    "collectCyclesBacon",
    "rememberCycle",
    "nimMarkCyclic",
    "nimIncRefCyclic",
    "nimTraceRef",
    "GC_runOrc",
];
const NIM_BOEHM_MARKERS: &[&str] = &["boehmgc", "GC_malloc", "GC_init"];
const NIM_TRACING_UNREF_MARKERS: &[&str] = &["nimGCunref"];
const NIM_REFC_CYCLE_MARKERS: &[&str] = &["collectCycles"];
const NIM_RC_ALLOC_MARKERS: &[&str] = &["newObjRC1"];
const NIM_MARK_SWEEP_MARKERS: &[&str] = &["markGlobals", "markStackAndRegisters"];
const NIM_STACK_SCAN_MARKERS: &[&str] = &["nimGC_setStackBottom", "nimGCvisit"];

fn nim_marker_present(image: &NativeImage<'_>, token: &str) -> bool {
    image.symbols.iter().any(|s: &String| s.contains(token)) || image.raw_contains(token.as_bytes())
}

fn nim_collect_markers(
    image: &NativeImage<'_>,
    tokens: &[&str],
    evidence: &mut Vec<String>,
) -> bool {
    let mut any: bool = false;
    for token in tokens {
        if nim_marker_present(image, token) {
            any = true;
            let owned: String = (*token).to_owned();
            if !evidence.contains(&owned) {
                evidence.push(owned);
            }
        }
    }
    any
}

fn classify_nim_gc(image: &NativeImage<'_>) -> (&'static str, Vec<String>) {
    let mut evidence: Vec<String> = Vec::new();
    if nim_collect_markers(image, NIM_BOEHM_MARKERS, &mut evidence) {
        return ("boehm", evidence);
    }
    if nim_collect_markers(image, NIM_ARC_API_MARKERS, &mut evidence) {
        if nim_collect_markers(image, NIM_ORC_CYCLE_MARKERS, &mut evidence) {
            return ("orc", evidence);
        }
        return ("arc", evidence);
    }
    let tracing_unref: bool = nim_collect_markers(image, NIM_TRACING_UNREF_MARKERS, &mut evidence);
    let cycle_collector: bool = nim_collect_markers(image, NIM_REFC_CYCLE_MARKERS, &mut evidence);
    let refcount_alloc: bool = nim_collect_markers(image, NIM_RC_ALLOC_MARKERS, &mut evidence);
    let mark_and_sweep: bool = nim_collect_markers(image, NIM_MARK_SWEEP_MARKERS, &mut evidence);
    let stack_scan: bool = nim_collect_markers(image, NIM_STACK_SCAN_MARKERS, &mut evidence);
    if cycle_collector {
        return ("refc", evidence);
    }
    if refcount_alloc {
        return ("go", evidence);
    }
    if tracing_unref || mark_and_sweep || stack_scan {
        return ("markAndSweep", evidence);
    }
    ("none", evidence)
}

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

const D_STD_PREFIXES: &[&str] = &[
    "core",
    "std",
    "object",
    "rt",
    "gc",
    "etc",
    "ldc",
    "TypeInfo",
    "ModuleInfo",
];

const D_BUILTIN_ROOTS: &[&str] = &[
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
    "cent",
    "ucent",
    "ireal",
    "ifloat",
    "idouble",
    "creal",
    "cfloat",
    "cdouble",
    "string",
    "wstring",
    "dstring",
    "size_t",
    "ptrdiff_t",
];
const D_NAME_EXTENSIONS: &[&str] = &[
    "d", "di", "dll", "so", "exe", "pdb", "obj", "lib", "a", "o", "c", "h", "cpp",
];
const MAX_D_RTTI_SEGMENTS: usize = 8;
const MAX_D_RTTI_LEN: usize = 200;
const D_RUNTIME_SYMS: &[&[u8]] = &[
    b"_Dmain",
    b"_d_run_main",
    b"_d_throw_exception",
    b"_d_assert",
    b"rt.dmain2",
    b"rt.lifetime",
    b"core.runtime",
    b"TypeInfo_Class",
];

#[must_use]
pub fn recover(image: &NativeImage<'_>, lang: NativeLang, types: &TypeReport) -> Recovery {
    debug::dbg_section("recover");
    debug::dbg_kv("recover-lang", || lang.label().to_owned());
    match lang {
        NativeLang::Nim => recover_nim(image, types),
        NativeLang::Zig => recover_zig(image, types),
        NativeLang::Crystal => recover_crystal(image, types),
        NativeLang::D => recover_d_lang(image, types),
    }
}

fn recover_nim(image: &NativeImage<'_>, types: &TypeReport) -> Recovery {
    let mut demangled: Vec<DemangledSymbol> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for sym in &image.symbols {
        if let Some(d) = demangle_nim(sym)
            && seen.insert(d.demangled.clone())
        {
            demangled.push(d);
        }
    }
    debug::dbg_kv("nim-demangled", || demangled.len().to_string());
    let (gc_kind, gc_evidence): (&'static str, Vec<String>) = classify_nim_gc(image);
    debug::dbg_kv("nim-gc", || {
        format!("{gc_kind} via [{}]", gc_evidence.join(","))
    });
    finish(
        image,
        NativeLang::Nim,
        demangled,
        NIM_STD_PREFIXES,
        NIM_RUNTIME_SYMS,
        Some(gc_kind),
        &gc_evidence,
        None,
        types,
    )
}

fn recover_zig(image: &NativeImage<'_>, types: &TypeReport) -> Recovery {
    let mut demangled: Vec<DemangledSymbol> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut reflection_thunks_filtered: usize = 0;
    for sym in &image.symbols {
        if sym.starts_with("__zig_") {
            reflection_thunks_filtered += 1;
        }
        if let Some(d) = demangle_zig(sym)
            && seen.insert(d.demangled.clone())
        {
            demangled.push(d);
        }
    }
    debug::dbg_kv("zig-demangled", || demangled.len().to_string());
    debug::dbg_kv("zig-reflection-thunks-filtered", || {
        reflection_thunks_filtered.to_string()
    });
    finish(
        image,
        NativeLang::Zig,
        demangled,
        ZIG_STD_PREFIXES,
        ZIG_RUNTIME_SYMS,
        Some("none-manual"),
        &[],
        None,
        types,
    )
}

fn recover_crystal(image: &NativeImage<'_>, types: &TypeReport) -> Recovery {
    let mut demangled: Vec<DemangledSymbol> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let from_symtab: bool = image.has_symbol_table();
    debug::dbg_kv("crystal-has-symbol-table", || from_symtab.to_string());
    if from_symtab {
        for sym in &image.symbols {
            if let Some(d) = demangle_crystal(sym)
                && seen.insert(d.demangled.clone())
            {
                demangled.push(d);
            }
        }
        debug::dbg_kv("crystal-from-symtab", || demangled.len().to_string());
    } else {
        debug::dbg_line(|| {
            "crystal wall: no symbol table, type names survive only as string-pool literals"
                .to_owned()
        });
    }
    let mut scanned_count: Option<(usize, bool)> = None;
    if demangled.is_empty() {
        debug::dbg_line(|| {
            "crystal fallback: scanning ascii string pool for type/method literals".to_owned()
        });
        let (strings, strings_truncated): (Vec<String>, bool) = image.ascii_strings_capped(3);
        scanned_count = Some((strings.len(), strings_truncated));
        debug::dbg_kv("crystal-strings-scanned", || strings.len().to_string());
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
        debug::dbg_kv("crystal-from-strings", || demangled.len().to_string());
    }
    finish(
        image,
        NativeLang::Crystal,
        demangled,
        CRYSTAL_STD_PREFIXES,
        CRYSTAL_RUNTIME_SYMS,
        Some("boehm"),
        &[],
        scanned_count,
        types,
    )
}

fn recover_d_lang(image: &NativeImage<'_>, types: &TypeReport) -> Recovery {
    let mut demangled: Vec<DemangledSymbol> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for sym in &image.symbols {
        if let Some(d) = demangle_d(sym)
            && seen.insert(d.demangled.clone())
        {
            demangled.push(d);
        }
    }
    debug::dbg_kv("d-from-symtab", || demangled.len().to_string());
    let mut scanned_count: Option<(usize, bool)> = None;
    if demangled.is_empty() {
        debug::dbg_line(|| {
            "d wall: symbol table absent or stripped (typical PE), scanning _D-prefixed string tokens".to_owned()
        });
        let (strings, strings_truncated): (Vec<String>, bool) = image.ascii_strings_capped(4);
        scanned_count = Some((strings.len(), strings_truncated));
        debug::dbg_kv("d-strings-scanned", || strings.len().to_string());
        for s in &strings {
            for token in s.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
                if token.starts_with("_D")
                    && let Some(d) = demangle_d(token)
                    && seen.insert(d.demangled.clone())
                {
                    demangled.push(d);
                }
            }
        }
        debug::dbg_kv("d-from-strings", || demangled.len().to_string());
        if demangled.is_empty() {
            debug::dbg_line(|| {
                "d rtti fallback: linked stripped image retains no _D mangling; mining druntime ClassInfo/ModuleInfo dotted-name pool".to_owned()
            });
            for s in &strings {
                for token in s.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
                {
                    if let Some(sym) = mine_d_rtti_name(token)
                        && seen.insert(sym.demangled.clone())
                    {
                        demangled.push(sym);
                    }
                }
            }
            debug::dbg_kv("d-from-rtti-pool", || demangled.len().to_string());
        }
    }
    finish(
        image,
        NativeLang::D,
        demangled,
        D_STD_PREFIXES,
        D_RUNTIME_SYMS,
        Some("druntime-conservative"),
        &[],
        scanned_count,
        types,
    )
}

#[allow(clippy::too_many_arguments)]
fn finish(
    image: &NativeImage<'_>,
    lang: NativeLang,
    demangled: Vec<DemangledSymbol>,
    std_prefixes: &[&str],
    runtime_syms: &[&[u8]],
    gc_kind: Option<&str>,
    gc_evidence: &[String],
    precomputed_scan: Option<(usize, bool)>,
    types: &TypeReport,
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
    let mut runtime_symbols: Vec<String> = runtime_syms
        .iter()
        .filter(|m: &&&[u8]| image.raw_contains(m))
        .map(|m: &&[u8]| String::from_utf8_lossy(m).into_owned())
        .collect();
    for symbol in gc_evidence {
        if !runtime_symbols.contains(symbol) {
            runtime_symbols.push(symbol.clone());
        }
    }
    let (strings_sampled, strings_truncated): (usize, bool) = precomputed_scan.unwrap_or_else(|| {
        let (strings, truncated): (Vec<String>, bool) = image.ascii_strings_capped(3);
        (strings.len(), truncated)
    });
    debug::dbg_kv("modules", || {
        format!(
            "user={} std={} std-syms={std_count} user-syms={user_count}",
            user_modules.len(),
            std_modules.len()
        )
    });
    debug::dbg_kv("gc-kind", || {
        gc_kind.map_or_else(|| "unknown".to_owned(), str::to_owned)
    });
    debug::dbg_kv("runtime-symbols", || runtime_symbols.len().to_string());
    debug::dbg_kv("strings-sampled", || strings_sampled.to_string());
    debug::dbg_kv("strings-truncated", || strings_truncated.to_string());
    let source_grade: SourceGrade = types.grade;
    let source_recoverable: bool = source_grade.recoverable();
    debug::dbg_kv("source-grade", || {
        format!(
            "{} recoverable={} types={} line-coverage={:.1}%",
            source_grade.label(),
            source_recoverable,
            types.named_type_count,
            types.line_coverage_pct
        )
    });
    debug::dbg_line(|| {
        match source_grade {
        SourceGrade::TypesAndLines => {
            "source partial: DWARF carries reconstructable types and a pc->source line map; high-level surface syntax (nim/zig/crystal/d) is not re-emitted".to_owned()
        }
        SourceGrade::SymbolsOnly => {
            "source wall: object code carries symbols/structure but no usable DWARF types+lines".to_owned()
        }
        SourceGrade::None => {
            "source wall: stripped object code carries no symbols and no DWARF; recovering only carved+disassembled bodies".to_owned()
        }
    }
    });
    Recovery {
        lang,
        has_symbol_table: image.has_symbol_table(),
        source_recoverable,
        source_grade,
        demangled,
        user_modules: user_modules.into_iter().collect(),
        std_modules: std_modules.into_iter().collect(),
        std_symbol_count: std_count,
        user_symbol_count: user_count,
        gc: GcMetadata {
            gc_kind: gc_kind.map(str::to_owned),
            runtime_symbols,
        },
        strings_sampled,
        strings_truncated,
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

fn is_d_module_segment(seg: &str) -> bool {
    let mut chars: std::str::Chars<'_> = seg.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c == '_')
        && seg
            .bytes()
            .all(|b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn is_d_type_segment(seg: &str) -> bool {
    let mut chars: std::str::Chars<'_> = seg.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_uppercase())
        && seg
            .bytes()
            .all(|b: u8| b.is_ascii_alphanumeric() || b == b'_')
}

fn accept_d_rtti_name(token: &str) -> bool {
    if token.is_empty() || token.len() > MAX_D_RTTI_LEN {
        return false;
    }
    let segments: Vec<&str> = token.split('.').collect();
    if segments.len() < 2 || segments.len() > MAX_D_RTTI_SEGMENTS {
        return false;
    }
    let root: &str = segments[0];
    if root.len() < 2
        || root.bytes().any(|b: u8| b.is_ascii_digit())
        || !is_d_module_segment(root)
        || D_BUILTIN_ROOTS.contains(&root)
    {
        return false;
    }
    let leaf: &str = segments[segments.len() - 1];
    if D_NAME_EXTENSIONS.contains(&leaf) {
        return false;
    }
    for seg in &segments[1..segments.len() - 1] {
        if seg.len() < 2 || !is_d_module_segment(seg) {
            return false;
        }
    }
    is_d_type_segment(leaf) || (leaf.len() >= 2 && is_d_module_segment(leaf))
}

fn mine_d_rtti_name(token: &str) -> Option<DemangledSymbol> {
    if !token.contains('.') || !accept_d_rtti_name(token) {
        return None;
    }
    let (module, name): (Option<String>, String) = match token.rsplit_once('.') {
        Some((head, leaf)) if !head.is_empty() && !leaf.is_empty() => {
            (Some(head.to_owned()), leaf.to_owned())
        }
        _ => return None,
    };
    Some(DemangledSymbol {
        mangled: token.to_owned(),
        demangled: token.to_owned(),
        module,
        name,
        params: Vec::new(),
        instantiation: None,
    })
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
