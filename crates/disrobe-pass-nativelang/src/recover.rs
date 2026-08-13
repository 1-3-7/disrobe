use std::collections::BTreeMap;
use std::collections::BTreeSet;

use disrobe_bytes::ByteReader;
use object::SectionKind;
use serde::{Deserialize, Serialize};

use crate::debug;
use crate::demangle::{DemangledSymbol, demangle_crystal, demangle_d, demangle_nim, demangle_zig};
use crate::detect::NativeLang;
use crate::dwarf_types::{SourceGrade, TypeReport};
use crate::image::{ImageKind, NativeImage, Section};

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
const MAX_D_RTTI_SEGMENTS: usize = 64;
const MAX_D_RTTI_NAME_LEN: usize = 64 * 1024;
const MAX_D_RTTI_SLICE_LEN: usize = 64 * 1024 * 1024;
const MAX_D_RTTI_VECTOR_LEN: usize = 1 << 20;
const MAX_D_RTTI_SCAN_BYTES: usize = 64 * 1024 * 1024;
const MAX_D_RTTI_CANDIDATES: usize = 1 << 20;
const MAX_D_RTTI_SECTIONS: usize = 96;
const MAX_D_RTTI_SYMBOLS: usize = 16 * 1024;
const MAX_D_RTTI_NAME_BYTES: usize = 16 * 1024 * 1024;
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
    let mut scanned_count: Option<(usize, bool)> = Some((0, false));
    if demangled.is_empty() {
        if image.kind == ImageKind::Pe {
            debug::dbg_line(|| {
                "d rtti fallback: mining structurally corroborated druntime ClassInfo records"
                    .to_owned()
            });
            let scan: DClassInfoScan = mine_d_class_info(image);
            scanned_count = Some((scan.names_sampled, scan.truncated));
            for symbol in scan.symbols {
                if seen.insert(symbol.demangled.clone()) {
                    demangled.push(symbol);
                }
            }
            debug::dbg_kv("d-from-classinfo", || demangled.len().to_string());
        } else {
            debug::dbg_line(|| {
                "d fallback: scanning a bounded string window for complete mangled names".to_owned()
            });
            let (strings, strings_truncated): (Vec<String>, bool) = image.ascii_strings_capped(4);
            scanned_count = Some((strings.len(), strings_truncated));
            for string in strings {
                for token in string.split(|character: char| {
                    !(character.is_ascii_alphanumeric() || character == '_')
                }) {
                    let symbol: Option<DemangledSymbol> = demangle_d(token);
                    if token.starts_with("_D")
                        && let Some(symbol) = symbol
                        && seen.insert(symbol.demangled.clone())
                    {
                        demangled.push(symbol);
                    }
                }
            }
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
    let (strings_sampled, strings_truncated): (usize, bool) =
        precomputed_scan.unwrap_or_else(|| {
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
    matches!(chars.next(), Some(c) if c.is_alphabetic() || c == '_')
        && chars.all(|c: char| c.is_alphanumeric() || c == '_')
}

fn is_d_type_segment(seg: &str) -> bool {
    let base: &str = seg
        .split_once('!')
        .map_or(seg, |(head, _): (&str, &str)| head);
    let mut chars: std::str::Chars<'_> = base.chars();
    matches!(chars.next(), Some(c) if c.is_uppercase() || c == '_')
        && chars.all(|c: char| c.is_alphanumeric() || c == '_')
        && balanced_d_template_suffix(seg.strip_prefix(base).unwrap_or(""))
}

fn balanced_d_template_suffix(suffix: &str) -> bool {
    if suffix.is_empty() {
        return true;
    }
    let Some(body): Option<&str> = suffix.strip_prefix("!(") else {
        return false;
    };
    let mut depth: usize = 1;
    let mut characters: std::iter::Peekable<std::str::Chars<'_>> = body.chars().peekable();
    loop {
        let next_character: Option<char> = characters.next();
        let Some(character): Option<char> = next_character else {
            break;
        };
        match character {
            '(' => depth = depth.saturating_add(1),
            ')' => {
                let Some(next): Option<usize> = depth.checked_sub(1) else {
                    return false;
                };
                depth = next;
                if depth == 0 && characters.peek().is_some() {
                    return false;
                }
            }
            c if c.is_alphanumeric()
                || matches!(c, '_' | '.' | ',' | ' ' | '*' | '[' | ']' | ':' | '-' | '!') => {}
            _ => return false,
        }
    }
    depth == 0
}

fn d_qualified_segments(token: &str) -> Option<Vec<&str>> {
    const MAX_NESTING: usize = 128;
    let mut segments: Vec<&str> = Vec::new();
    let mut start: usize = 0;
    let mut depth: usize = 0;
    for (index, character) in token.char_indices() {
        match character {
            '(' | '[' => {
                depth = depth.checked_add(1)?;
                if depth > MAX_NESTING {
                    return None;
                }
            }
            ')' | ']' => depth = depth.checked_sub(1)?,
            '.' if depth == 0 => {
                segments.push(token.get(start..index)?);
                start = index.checked_add(character.len_utf8())?;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return None;
    }
    segments.push(token.get(start..)?);
    Some(segments)
}

fn accept_d_rtti_name(token: &str) -> bool {
    if token.is_empty() || token.len() > MAX_D_RTTI_NAME_LEN {
        return false;
    }
    let Some(segments): Option<Vec<&str>> = d_qualified_segments(token) else {
        return false;
    };
    if segments.len() < 2 || segments.len() > MAX_D_RTTI_SEGMENTS {
        return false;
    }
    let root: &str = segments[0];
    if root.len() < 2 || !is_d_module_segment(root) || D_BUILTIN_ROOTS.contains(&root) {
        return false;
    }
    let leaf: &str = segments[segments.len() - 1];
    if D_NAME_EXTENSIONS.contains(&leaf) {
        return false;
    }
    for segment in &segments[1..segments.len() - 1] {
        if segment.len() < 2 || !is_d_module_segment(segment) {
            return false;
        }
    }
    is_d_type_segment(leaf) || (leaf.len() >= 2 && is_d_module_segment(leaf))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DClassInfoEvidence<'a> {
    name: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DClassInfoScan {
    symbols: Vec<DemangledSymbol>,
    names_sampled: usize,
    truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DClassInfoLimits {
    sections: usize,
    symbols: usize,
    name_bytes: usize,
}

const D_CLASS_INFO_LIMITS: DClassInfoLimits = DClassInfoLimits {
    sections: MAX_D_RTTI_SECTIONS,
    symbols: MAX_D_RTTI_SYMBOLS,
    name_bytes: MAX_D_RTTI_NAME_BYTES,
};

fn read_d_word(reader: &mut ByteReader<'_>, pointer_size: u8) -> Option<u64> {
    match pointer_size {
        4 => reader.read_u32_le().ok().map(u64::from),
        8 => reader.read_u64_le().ok(),
        _ => None,
    }
}

fn mapped_d_slice<'a>(
    image: &NativeImage<'a>,
    address: u64,
    length: u64,
    maximum: usize,
) -> Option<&'a [u8]> {
    let length_usize: usize = usize::try_from(length).ok()?;
    if length_usize == 0 || length_usize > maximum {
        return None;
    }
    for section in &image.sections {
        let Some(relative_u64): Option<u64> = address.checked_sub(section.address) else {
            continue;
        };
        let Ok(relative): Result<usize, _> = usize::try_from(relative_u64) else {
            continue;
        };
        let Some(end): Option<usize> = relative.checked_add(length_usize) else {
            continue;
        };
        let bytes: Option<&[u8]> = section.data.get(relative..end);
        if let Some(bytes) = bytes {
            return Some(bytes);
        }
    }
    None
}

fn mapped_d_pointer(image: &NativeImage<'_>, address: u64) -> bool {
    mapped_d_slice(image, address, 1, 1).is_some()
}

fn is_d_rtti_section(section: &Section<'_>) -> bool {
    matches!(
        section.kind,
        SectionKind::Data | SectionKind::ReadOnlyData | SectionKind::ReadOnlyString
    ) || matches!(section.name.as_str(), ".data" | ".rdata")
}

fn d_class_info_at<'a>(
    image: &NativeImage<'a>,
    section: &Section<'a>,
    offset: usize,
) -> Option<DClassInfoEvidence<'a>> {
    let candidate: &[u8] = section.data.get(offset..)?;
    let mut reader: ByteReader<'_> = ByteReader::new(candidate);
    let object_vtable: u64 = read_d_word(&mut reader, image.ptr_size)?;
    let _monitor: u64 = read_d_word(&mut reader, image.ptr_size)?;
    let initializer_length: u64 = read_d_word(&mut reader, image.ptr_size)?;
    let initializer_pointer: u64 = read_d_word(&mut reader, image.ptr_size)?;
    let name_length: u64 = read_d_word(&mut reader, image.ptr_size)?;
    let name_pointer: u64 = read_d_word(&mut reader, image.ptr_size)?;
    let vtable_length: u64 = read_d_word(&mut reader, image.ptr_size)?;
    let vtable_pointer: u64 = read_d_word(&mut reader, image.ptr_size)?;

    if !mapped_d_pointer(image, object_vtable) {
        return None;
    }
    mapped_d_slice(
        image,
        initializer_pointer,
        initializer_length,
        MAX_D_RTTI_SLICE_LEN,
    )?;
    let name_bytes: &[u8] = mapped_d_slice(image, name_pointer, name_length, MAX_D_RTTI_NAME_LEN)?;
    let offset_u64: u64 = u64::try_from(offset).ok()?;
    let candidate_address: u64 = section.address.checked_add(offset_u64)?;
    let vtable_bytes: u64 = vtable_length.checked_mul(u64::from(image.ptr_size))?;
    if vtable_length == 0 || vtable_length > MAX_D_RTTI_VECTOR_LEN as u64 {
        return None;
    }
    let vtable: &[u8] = mapped_d_slice(image, vtable_pointer, vtable_bytes, MAX_D_RTTI_SLICE_LEN)?;
    let mut vtable_reader: ByteReader<'_> = ByteReader::new(vtable);
    if read_d_word(&mut vtable_reader, image.ptr_size) != Some(candidate_address) {
        return None;
    }
    let name: &str = std::str::from_utf8(name_bytes).ok()?;
    if !name.contains('.') || !accept_d_rtti_name(name) {
        return None;
    }
    Some(DClassInfoEvidence { name })
}

fn mine_d_class_info(image: &NativeImage<'_>) -> DClassInfoScan {
    mine_d_class_info_with_limits(image, D_CLASS_INFO_LIMITS)
}

fn mine_d_class_info_with_limits(
    image: &NativeImage<'_>,
    limits: DClassInfoLimits,
) -> DClassInfoScan {
    let pointer_size: usize = usize::from(image.ptr_size);
    let sections_truncated: bool = image.sections.len() > limits.sections;
    if !matches!(pointer_size, 4 | 8) || sections_truncated {
        return DClassInfoScan {
            symbols: Vec::new(),
            names_sampled: 0,
            truncated: sections_truncated,
        };
    }
    let minimum_size: usize = pointer_size.saturating_mul(8);
    let mut symbols: Vec<DemangledSymbol> = Vec::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut accepted_name_bytes: usize = 0;
    let mut names_sampled: usize = 0;
    let mut scanned_bytes: usize = 0;
    let mut candidates: usize = 0;
    let mut truncated: bool = false;
    'sections: for section in image
        .sections
        .iter()
        .filter(|section: &&Section<'_>| is_d_rtti_section(section) && !section.data.is_empty())
    {
        let remaining: usize = MAX_D_RTTI_SCAN_BYTES.saturating_sub(scanned_bytes);
        if remaining == 0 || candidates >= MAX_D_RTTI_CANDIDATES {
            truncated = true;
            break;
        }
        let scan_length: usize = section.data.len().min(remaining);
        if scan_length < section.data.len() {
            truncated = true;
        }
        let Some(last_offset): Option<usize> = scan_length.checked_sub(minimum_size) else {
            scanned_bytes = scanned_bytes.saturating_add(scan_length);
            continue;
        };
        for offset in (0..=last_offset).step_by(pointer_size) {
            if candidates >= MAX_D_RTTI_CANDIDATES {
                truncated = true;
                break;
            }
            candidates = candidates.saturating_add(1);
            let evidence: Option<DClassInfoEvidence<'_>> = d_class_info_at(image, section, offset);
            if let Some(evidence) = evidence {
                names_sampled = names_sampled.saturating_add(1);
                if seen.contains(evidence.name) {
                    continue;
                }
                let Some(next_name_bytes): Option<usize> =
                    accepted_name_bytes.checked_add(evidence.name.len())
                else {
                    truncated = true;
                    break 'sections;
                };
                if symbols.len() >= limits.symbols || next_name_bytes > limits.name_bytes {
                    truncated = true;
                    break 'sections;
                }
                accepted_name_bytes = next_name_bytes;
                seen.insert(evidence.name);
                let Some(symbol): Option<DemangledSymbol> = mine_d_rtti_name(evidence.name) else {
                    continue;
                };
                symbols.push(symbol);
            }
        }
        scanned_bytes = scanned_bytes.saturating_add(scan_length);
    }
    symbols.sort_by(|left: &DemangledSymbol, right: &DemangledSymbol| {
        left.demangled.cmp(&right.demangled)
    });
    DClassInfoScan {
        symbols,
        names_sampled,
        truncated,
    }
}

fn mine_d_rtti_name(token: &str) -> Option<DemangledSymbol> {
    if !token.contains('.') || !accept_d_rtti_name(token) {
        return None;
    }
    let segments: Vec<&str> = d_qualified_segments(token)?;
    let leaf: &str = segments.last()?;
    let module_length: usize = token.len().checked_sub(leaf.len())?.checked_sub(1)?;
    let module_name: &str = token.get(..module_length)?;
    let module: Option<String> = Some(module_name.to_owned());
    let name: String = leaf.to_owned();
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn write_word(bytes: &mut [u8], offset: usize, value: u64, pointer_size: u8) {
        let encoded: [u8; 8] = value.to_le_bytes();
        let width: usize = usize::from(pointer_size);
        bytes[offset..offset + width].copy_from_slice(&encoded[..width]);
    }

    fn class_info_section(pointer_size: u8, name: &str, declared_name_length: u64) -> Vec<u8> {
        let width: usize = usize::from(pointer_size);
        let address: u64 = 0x1000;
        let object_vtable_offset: u64 = 0x100;
        let initializer_offset: u64 = 0x120;
        let class_vtable_offset: u64 = 0x140;
        let name_offset: usize = 0x180;
        let mut bytes: Vec<u8> = vec![0u8; name_offset + name.len() + 1];
        write_word(&mut bytes, 0, address + object_vtable_offset, pointer_size);
        write_word(&mut bytes, width * 2, 16, pointer_size);
        write_word(
            &mut bytes,
            width * 3,
            address + initializer_offset,
            pointer_size,
        );
        write_word(&mut bytes, width * 4, declared_name_length, pointer_size);
        write_word(
            &mut bytes,
            width * 5,
            address + name_offset as u64,
            pointer_size,
        );
        write_word(&mut bytes, width * 6, 2, pointer_size);
        write_word(
            &mut bytes,
            width * 7,
            address + class_vtable_offset,
            pointer_size,
        );
        write_word(
            &mut bytes,
            usize::try_from(class_vtable_offset).expect("test offset fits usize"),
            address,
            pointer_size,
        );
        bytes[name_offset..name_offset + name.len()].copy_from_slice(name.as_bytes());
        bytes
    }

    fn overlapping_class_info_section(pointer_size: u8, name_count: usize) -> Vec<u8> {
        let width: usize = usize::from(pointer_size);
        let record_size: usize = width * 8;
        let records_size: usize = record_size * name_count;
        let vtables_size: usize = width * name_count;
        let name_offset: usize = records_size + vtables_size;
        let name_length: usize = 3 + name_count;
        let address: u64 = 0x1000;
        let name_address: u64 =
            address + u64::try_from(name_offset).expect("test name offset fits in an address");
        let mut bytes: Vec<u8> = vec![0u8; name_offset + name_length];
        bytes[name_offset..name_offset + 3].copy_from_slice(b"aa.");
        bytes[name_offset + 3..].fill(b'A');
        for index in 0..name_count {
            let record_offset: usize = record_size * index;
            let vtable_offset: usize = records_size + width * index;
            let candidate_address: u64 = address
                + u64::try_from(record_offset).expect("test record offset fits in an address");
            let vtable_address: u64 = address
                + u64::try_from(vtable_offset).expect("test vtable offset fits in an address");
            write_word(&mut bytes, record_offset, vtable_address, pointer_size);
            write_word(&mut bytes, record_offset + width * 2, 1, pointer_size);
            write_word(
                &mut bytes,
                record_offset + width * 3,
                name_address,
                pointer_size,
            );
            write_word(
                &mut bytes,
                record_offset + width * 4,
                u64::try_from(4 + index).expect("test name length fits in u64"),
                pointer_size,
            );
            write_word(
                &mut bytes,
                record_offset + width * 5,
                name_address,
                pointer_size,
            );
            write_word(&mut bytes, record_offset + width * 6, 1, pointer_size);
            write_word(
                &mut bytes,
                record_offset + width * 7,
                vtable_address,
                pointer_size,
            );
            write_word(&mut bytes, vtable_offset, candidate_address, pointer_size);
        }
        bytes
    }

    fn scan_class_info(bytes: &[u8], pointer_size: u8) -> DClassInfoScan {
        scan_class_info_with_section_count(bytes, pointer_size, 1)
    }

    fn scan_class_info_with_section_count(
        bytes: &[u8],
        pointer_size: u8,
        section_count: usize,
    ) -> DClassInfoScan {
        let image: NativeImage<'_> = class_info_image(bytes, pointer_size, section_count);
        mine_d_class_info(&image)
    }

    fn scan_class_info_with_limits(
        bytes: &[u8],
        pointer_size: u8,
        limits: DClassInfoLimits,
    ) -> DClassInfoScan {
        let image: NativeImage<'_> = class_info_image(bytes, pointer_size, 1);
        mine_d_class_info_with_limits(&image, limits)
    }

    fn class_info_image(bytes: &[u8], pointer_size: u8, section_count: usize) -> NativeImage<'_> {
        assert!(section_count > 0);
        let mut sections: Vec<Section<'_>> = vec![Section {
            name: ".rdata".to_owned(),
            address: 0x1000,
            kind: SectionKind::ReadOnlyData,
            data: bytes,
        }];
        for index in 1..section_count {
            sections.push(Section {
                name: format!(".x{index:05}"),
                address: 0x1000 + (index as u64 * 0x1000),
                kind: SectionKind::Text,
                data: &[],
            });
        }
        NativeImage {
            kind: ImageKind::Pe,
            relocatable: false,
            arch: if pointer_size == 8 {
                crate::image::CodeArch::X86_64
            } else {
                crate::image::CodeArch::X86
            },
            ptr_size: pointer_size,
            entry: 0,
            raw: bytes,
            sections,
            symbols: Vec::new(),
            func_symbols: Vec::new(),
        }
    }

    #[test]
    fn class_info_recovers_utf8_template_name_for_pe32_and_pe32_plus() {
        let name: &str = "módulo.Contêiner!(std.type.Tuple!(int, string))";
        for pointer_size in [4u8, 8u8] {
            let bytes: Vec<u8> = class_info_section(pointer_size, name, name.len() as u64);
            let scan: DClassInfoScan = scan_class_info(&bytes, pointer_size);
            assert_eq!(scan.names_sampled, 1);
            assert_eq!(scan.symbols.len(), 1);
            assert_eq!(scan.symbols[0].demangled, name);
        }
    }

    #[test]
    fn class_info_refuses_enormous_declared_name_length() {
        for pointer_size in [4u8, 8u8] {
            let maximum: u64 = if pointer_size == 4 {
                u64::from(u32::MAX)
            } else {
                u64::MAX
            };
            let bytes: Vec<u8> = class_info_section(pointer_size, "decoy.NotAType", maximum);
            let scan: DClassInfoScan = scan_class_info(&bytes, pointer_size);
            assert!(scan.symbols.is_empty());
            assert_eq!(scan.names_sampled, 0);
        }
    }

    #[test]
    fn class_info_requires_vtable_back_reference() {
        for pointer_size in [4u8, 8u8] {
            let mut bytes: Vec<u8> = class_info_section(pointer_size, "decoy.NotAType", 14);
            write_word(&mut bytes, 0x140, 0x1180, pointer_size);
            let scan: DClassInfoScan = scan_class_info(&bytes, pointer_size);
            assert!(scan.symbols.is_empty());
        }
    }

    #[test]
    fn class_info_accepts_the_windows_pe_section_ceiling() {
        let bytes: Vec<u8> = class_info_section(8, "module.ExactBoundary", 20);
        let scan: DClassInfoScan = scan_class_info_with_section_count(&bytes, 8, 96);
        assert_eq!(scan.symbols.len(), 1);
        assert_eq!(scan.symbols[0].demangled, "module.ExactBoundary");
        assert!(!scan.truncated);
    }

    #[test]
    fn class_info_refuses_more_than_the_windows_pe_section_ceiling() {
        let bytes: Vec<u8> = class_info_section(8, "module.OverBoundary", 19);
        let scan: DClassInfoScan = scan_class_info_with_section_count(&bytes, 8, 97);
        assert!(scan.symbols.is_empty());
        assert!(scan.truncated);
    }

    #[test]
    fn class_info_accepts_the_exact_symbol_and_name_byte_boundaries() {
        let bytes: Vec<u8> = overlapping_class_info_section(8, 2);
        let scan: DClassInfoScan = scan_class_info_with_limits(
            &bytes,
            8,
            DClassInfoLimits {
                sections: 96,
                symbols: 2,
                name_bytes: 9,
            },
        );
        assert_eq!(
            scan.symbols
                .iter()
                .map(|symbol: &DemangledSymbol| symbol.demangled.as_str())
                .collect::<Vec<&str>>(),
            ["aa.A", "aa.AA"]
        );
        assert!(!scan.truncated);
    }

    #[test]
    fn class_info_stops_at_the_unique_symbol_ceiling() {
        let bytes: Vec<u8> = overlapping_class_info_section(8, 3);
        let scan: DClassInfoScan = scan_class_info_with_limits(
            &bytes,
            8,
            DClassInfoLimits {
                sections: 96,
                symbols: 2,
                name_bytes: usize::MAX,
            },
        );
        assert_eq!(scan.symbols.len(), 2);
        assert!(scan.truncated);
    }

    #[test]
    fn class_info_stops_at_the_cumulative_unique_name_byte_ceiling() {
        let bytes: Vec<u8> = overlapping_class_info_section(8, 3);
        let scan: DClassInfoScan = scan_class_info_with_limits(
            &bytes,
            8,
            DClassInfoLimits {
                sections: 96,
                symbols: usize::MAX,
                name_bytes: 9,
            },
        );
        assert_eq!(
            scan.symbols
                .iter()
                .map(|symbol: &DemangledSymbol| symbol.demangled.as_str())
                .collect::<Vec<&str>>(),
            ["aa.A", "aa.AA"]
        );
        assert!(scan.truncated);
    }
}
