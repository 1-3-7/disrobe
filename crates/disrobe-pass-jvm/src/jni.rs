use std::collections::BTreeMap;

use object::Object as _;
use object::ObjectSection as _;
use object::ObjectSymbol as _;
use object::read::File as ObjFile;
use object::{Architecture, Endianness, RelocationTarget, SectionKind, SymbolKind};
use serde::{Deserialize, Serialize};

use crate::classfile::ClassFile;
use crate::dalvik_strdec::NativeIntKey;
use crate::descriptor::{JavaType, parse_method};
use crate::dex::{DexFile, NativeMethod, extract_native_methods, jni_symbols};

const MAX_NATIVE_KEY_LIBS: usize = 128;
const MAX_NATIVE_KEY_LIB_BYTES: usize = 64 * 1024 * 1024;
const MAX_NATIVE_INT_KEYS: usize = 4096;
const MAX_STUB_BYTES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeLibrary {
    pub path: String,
    pub abi: Option<String>,
    pub format: String,
    pub arch: String,
    pub jni_exports: Vec<String>,
    pub register_natives_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedNative {
    pub class: String,
    pub method: String,
    pub descriptor: String,
    pub jni_short_symbol: String,
    pub resolved_in: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredNative {
    pub library: String,
    pub name: String,
    pub signature: String,
    pub fn_addr: u64,
    pub fn_symbol: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JniSurfaceReport {
    pub native_method_count: usize,
    pub native_methods: Vec<ResolvedNative>,
    pub libraries: Vec<NativeLibrary>,
    pub resolved_statically: usize,
    pub dynamic_only: usize,
    pub registered_natives: Vec<RegisteredNative>,
    pub code_scan_complete: bool,
    pub decode_error_count: usize,
}

fn abi_from_path(path: &str) -> Option<String> {
    let mut parts = path.split('/');
    while let Some(p) = parts.next() {
        if p == "lib" {
            return parts.next().map(str::to_owned);
        }
    }
    None
}

fn parse_library(path: &str, bytes: &[u8]) -> Option<NativeLibrary> {
    let parsed: disrobe_binfmt::NativeFile = disrobe_binfmt::parse_native(bytes).ok()?;
    let mut jni_exports: Vec<String> = parsed
        .exports
        .iter()
        .map(|e: &disrobe_binfmt::ExportInfo| e.name.as_str())
        .chain(
            parsed
                .symbols
                .iter()
                .filter(|s: &&disrobe_binfmt::SymbolInfo| {
                    matches!(s.kind, disrobe_binfmt::SymbolRole::Text)
                })
                .map(|s: &disrobe_binfmt::SymbolInfo| s.name.as_str()),
        )
        .filter(|name: &&str| name.starts_with("Java_"))
        .map(str::to_owned)
        .collect();
    jni_exports.sort();
    jni_exports.dedup();
    let register_natives_present: bool = parsed
        .symbols
        .iter()
        .any(|s: &disrobe_binfmt::SymbolInfo| s.name == "JNI_OnLoad")
        || parsed
            .imports
            .iter()
            .any(|i: &disrobe_binfmt::ImportInfo| i.name == "RegisterNatives");
    Some(NativeLibrary {
        path: path.to_owned(),
        abi: abi_from_path(path),
        format: parsed.format.label().to_owned(),
        arch: parsed.arch.label().to_owned(),
        jni_exports,
        register_natives_present,
    })
}

#[must_use]
pub fn analyze(
    dexes: &[(&str, &DexFile, &[u8])],
    native_libs: &[(&str, &[u8])],
) -> JniSurfaceReport {
    let mut native_methods: Vec<NativeMethod> = Vec::new();
    let mut code_scan_complete: bool = true;
    let mut decode_error_count: usize = 0;
    for (_name, dex, bytes) in dexes {
        match extract_native_methods(dex, bytes) {
            Ok(methods) => native_methods.extend(methods),
            Err(error) => {
                crate::debug::dbg_kv("jni-native-method-scan-reject", || error.to_string());
                code_scan_complete = false;
                decode_error_count += 1;
            }
        }
    }

    let mut libraries: Vec<NativeLibrary> = Vec::new();
    let mut registered_natives: Vec<RegisteredNative> = Vec::new();
    for (path, bytes) in native_libs {
        if let Some(lib) = parse_library(path, bytes) {
            libraries.push(lib);
        }
        registered_natives.extend(recover_register_natives(path, bytes));
    }
    libraries.sort_by(|a: &NativeLibrary, b: &NativeLibrary| a.path.cmp(&b.path));
    registered_natives.sort_by(|a: &RegisteredNative, b: &RegisteredNative| {
        (a.library.as_str(), a.fn_addr, a.name.as_str()).cmp(&(
            b.library.as_str(),
            b.fn_addr,
            b.name.as_str(),
        ))
    });

    let mut symbol_to_lib: BTreeMap<&str, &str> = BTreeMap::new();
    for lib in &libraries {
        for sym in &lib.jni_exports {
            symbol_to_lib
                .entry(sym.as_str())
                .or_insert(lib.path.as_str());
        }
    }

    let mut resolved_statically: usize = 0;
    let mut resolved: Vec<ResolvedNative> = Vec::with_capacity(native_methods.len());
    for nm in &native_methods {
        let resolved_in: Option<String> = symbol_to_lib
            .get(nm.jni_short_symbol.as_str())
            .or_else(|| symbol_to_lib.get(nm.jni_long_symbol.as_str()))
            .map(|s: &&str| (*s).to_owned());
        if resolved_in.is_some() {
            resolved_statically += 1;
        }
        resolved.push(ResolvedNative {
            class: nm.class.clone(),
            method: nm.method.clone(),
            descriptor: nm.descriptor.clone(),
            jni_short_symbol: nm.jni_short_symbol.clone(),
            resolved_in,
        });
    }

    let dynamic_only: usize = native_methods.len().saturating_sub(resolved_statically);
    JniSurfaceReport {
        native_method_count: native_methods.len(),
        native_methods: resolved,
        libraries,
        resolved_statically,
        dynamic_only,
        registered_natives,
        code_scan_complete,
        decode_error_count,
    }
}

const MAX_JNI_STRING_LEN: usize = 512;
const MAX_ARRAY_DIMS: usize = 255;

#[derive(Debug, Clone)]
struct ResolvedPtr {
    target: u64,
    symbol: Option<String>,
}

#[derive(Debug, Clone)]
struct SectionSpan<'a> {
    address: u64,
    data: &'a [u8],
    executable: bool,
}

#[must_use]
pub fn recover_register_natives(library: &str, bytes: &[u8]) -> Vec<RegisteredNative> {
    let Ok(file): Result<ObjFile<'_, &[u8]>, _> = ObjFile::parse(bytes) else {
        return Vec::new();
    };
    let ptr_size: usize = if file.is_64() { 8 } else { 4 };
    let stride: u64 = (ptr_size as u64).saturating_mul(3);
    let spans: Vec<SectionSpan<'_>> = collect_sections(&file);
    let pointers: BTreeMap<u64, ResolvedPtr> = collect_pointer_targets(&file, ptr_size, &spans);
    if pointers.is_empty() {
        return Vec::new();
    }
    let functions: BTreeMap<u64, String> = function_symbols_by_address(&file);
    let ptr: u64 = ptr_size as u64;
    let mut out: Vec<RegisteredNative> = Vec::new();
    for &base in pointers.keys() {
        if decode_entry(library, base, ptr, &pointers, &functions, &spans).is_none() {
            continue;
        }
        let preceded: bool = base
            .checked_sub(stride)
            .and_then(|prev: u64| decode_entry(library, prev, ptr, &pointers, &functions, &spans))
            .is_some();
        if preceded {
            continue;
        }
        let mut cursor: u64 = base;
        while let Some(decoded) = decode_entry(library, cursor, ptr, &pointers, &functions, &spans)
        {
            out.push(decoded);
            let Some(next): Option<u64> = cursor.checked_add(stride) else {
                break;
            };
            cursor = next;
        }
    }
    out
}

fn decode_entry(
    library: &str,
    base: u64,
    ptr: u64,
    pointers: &BTreeMap<u64, ResolvedPtr>,
    functions: &BTreeMap<u64, String>,
    spans: &[SectionSpan<'_>],
) -> Option<RegisteredNative> {
    let name_ptr: &ResolvedPtr = pointers.get(&base)?;
    let sig_ptr: &ResolvedPtr = pointers.get(&base.checked_add(ptr)?)?;
    let fn_ptr: &ResolvedPtr = pointers.get(&base.checked_add(ptr.checked_mul(2)?)?)?;
    let name: &str = read_c_string(spans, name_ptr.target)?;
    if !is_jni_method_name(name) {
        return None;
    }
    let signature: &str = read_c_string(spans, sig_ptr.target)?;
    if !is_jni_signature(signature) {
        return None;
    }
    if !is_code_target(spans, functions, fn_ptr.target) {
        return None;
    }
    let fn_symbol: Option<String> = fn_ptr
        .symbol
        .clone()
        .or_else(|| functions.get(&fn_ptr.target).cloned());
    Some(RegisteredNative {
        library: library.to_owned(),
        name: name.to_owned(),
        signature: signature.to_owned(),
        fn_addr: fn_ptr.target,
        fn_symbol,
    })
}

fn collect_sections<'a>(file: &ObjFile<'a, &'a [u8]>) -> Vec<SectionSpan<'a>> {
    let mut spans: Vec<SectionSpan<'a>> = Vec::new();
    for section in file.sections() {
        let address: u64 = section.address();
        if address == 0 {
            continue;
        }
        let Ok(data): Result<&'a [u8], _> = section.data() else {
            continue;
        };
        if data.is_empty() {
            continue;
        }
        spans.push(SectionSpan {
            address,
            data,
            executable: matches!(section.kind(), SectionKind::Text),
        });
    }
    spans
}

fn collect_pointer_targets<'a>(
    file: &ObjFile<'a, &'a [u8]>,
    ptr_size: usize,
    spans: &[SectionSpan<'_>],
) -> BTreeMap<u64, ResolvedPtr> {
    let mut out: BTreeMap<u64, ResolvedPtr> = BTreeMap::new();
    let Some(dynamic_relocations): Option<_> = file.dynamic_relocations() else {
        return out;
    };
    let dynamic_symbols: Option<_> = file.dynamic_symbol_table();
    for (offset, reloc) in dynamic_relocations {
        let base_addend: i64 = if reloc.has_implicit_addend() {
            read_pointer(spans, offset, ptr_size)
                .map_or_else(|| reloc.addend(), |value: u64| value as i64)
        } else {
            reloc.addend()
        };
        let resolved: Option<ResolvedPtr> = match reloc.target() {
            RelocationTarget::Absolute => Some(ResolvedPtr {
                target: mask_pointer(base_addend as u64, ptr_size),
                symbol: None,
            }),
            RelocationTarget::Symbol(index) => {
                resolve_symbol_target(dynamic_symbols.as_ref(), index, base_addend, ptr_size)
            }
            _ => None,
        };
        if let Some(pointer) = resolved {
            out.entry(offset).or_insert(pointer);
        }
    }
    out
}

fn resolve_symbol_target<'a, T>(
    table: Option<&T>,
    index: object::SymbolIndex,
    base_addend: i64,
    ptr_size: usize,
) -> Option<ResolvedPtr>
where
    T: object::read::ObjectSymbolTable<'a>,
{
    let symbol: T::Symbol = table?.symbol_by_index(index).ok()?;
    let name: Option<String> = symbol
        .name()
        .ok()
        .filter(|value: &&str| !value.is_empty())
        .map(str::to_owned);
    Some(ResolvedPtr {
        target: mask_pointer(symbol.address().wrapping_add(base_addend as u64), ptr_size),
        symbol: name,
    })
}

fn function_symbols_by_address<'a>(file: &ObjFile<'a, &'a [u8]>) -> BTreeMap<u64, String> {
    let mut out: BTreeMap<u64, String> = BTreeMap::new();
    for symbol in file.dynamic_symbols().chain(file.symbols()) {
        if symbol.kind() != SymbolKind::Text {
            continue;
        }
        let Ok(name): Result<&str, _> = symbol.name() else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        out.entry(symbol.address())
            .or_insert_with(|| name.to_owned());
    }
    out
}

fn read_pointer(spans: &[SectionSpan<'_>], address: u64, ptr_size: usize) -> Option<u64> {
    for span in spans {
        let end: u64 = span.address.checked_add(span.data.len() as u64)?;
        if address >= span.address && address < end {
            let offset: usize = usize::try_from(address - span.address).ok()?;
            let slice: &[u8] = span.data.get(offset..offset.checked_add(ptr_size)?)?;
            let mut value: u64 = 0;
            for (index, byte) in slice.iter().enumerate() {
                value |= u64::from(*byte) << (index * 8);
            }
            return Some(value);
        }
    }
    None
}

fn read_c_string<'a>(spans: &[SectionSpan<'a>], address: u64) -> Option<&'a str> {
    for span in spans {
        let end: u64 = span.address.checked_add(span.data.len() as u64)?;
        if address >= span.address && address < end {
            let offset: usize = usize::try_from(address - span.address).ok()?;
            let rest: &'a [u8] = span.data.get(offset..)?;
            let stop: usize = rest.iter().position(|byte: &u8| *byte == 0)?;
            if stop == 0 || stop > MAX_JNI_STRING_LEN {
                return None;
            }
            return core::str::from_utf8(&rest[..stop]).ok();
        }
    }
    None
}

fn is_code_target(
    spans: &[SectionSpan<'_>],
    functions: &BTreeMap<u64, String>,
    address: u64,
) -> bool {
    if functions.contains_key(&address) {
        return true;
    }
    spans.iter().any(|span: &SectionSpan<'_>| {
        span.executable
            && address >= span.address
            && address < span.address.saturating_add(span.data.len() as u64)
    })
}

const fn mask_pointer(value: u64, ptr_size: usize) -> u64 {
    if ptr_size >= 8 {
        value
    } else {
        value & 0xFFFF_FFFF
    }
}

fn is_jni_method_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_JNI_STRING_LEN {
        return false;
    }
    let mut chars = name.chars();
    let Some(first): Option<char> = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_' || first == '$') {
        return false;
    }
    chars.all(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

fn is_jni_signature(signature: &str) -> bool {
    let bytes: &[u8] = signature.as_bytes();
    if bytes.first() != Some(&b'(') {
        return false;
    }
    let mut index: usize = 1;
    while bytes.get(index).is_some_and(|byte: &u8| *byte != b')') {
        let Some(next): Option<usize> = consume_field_type(bytes, index) else {
            return false;
        };
        index = next;
    }
    if bytes.get(index) != Some(&b')') {
        return false;
    }
    index += 1;
    if bytes.get(index) == Some(&b'V') {
        return index + 1 == bytes.len();
    }
    consume_field_type(bytes, index).is_some_and(|end: usize| end == bytes.len())
}

fn consume_field_type(bytes: &[u8], mut index: usize) -> Option<usize> {
    let mut dims: usize = 0;
    while bytes.get(index) == Some(&b'[') {
        dims += 1;
        if dims > MAX_ARRAY_DIMS {
            return None;
        }
        index += 1;
    }
    match bytes.get(index)? {
        b'Z' | b'B' | b'C' | b'S' | b'I' | b'J' | b'F' | b'D' => Some(index + 1),
        b'L' => {
            index += 1;
            while let Some(byte) = bytes.get(index) {
                match byte {
                    b';' => return Some(index + 1),
                    b'(' | b')' | b'[' => return None,
                    _ => index += 1,
                }
            }
            None
        }
        _ => None,
    }
}

pub fn extract_static_int_keys(
    dex: &DexFile,
    dex_bytes: &[u8],
    native_libs: &[(&str, &[u8])],
) -> crate::error::Result<Vec<NativeIntKey>> {
    let native_methods: Vec<NativeMethod> = extract_native_methods(dex, dex_bytes)?;
    if native_methods.is_empty() || native_libs.is_empty() {
        return Ok(Vec::new());
    }
    let mut short_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for method in &native_methods {
        *short_counts
            .entry(method.jni_short_symbol.as_str())
            .or_insert(0) += 1;
    }
    let mut exports: BTreeMap<String, (String, i64)> = BTreeMap::new();
    for (path, bytes) in native_libs.iter().take(MAX_NATIVE_KEY_LIBS) {
        if bytes.len() > MAX_NATIVE_KEY_LIB_BYTES {
            continue;
        }
        for (symbol, value) in constant_int_exports(bytes) {
            exports
                .entry(symbol)
                .or_insert_with(|| ((*path).to_owned(), value));
        }
    }
    if exports.is_empty() {
        return Ok(Vec::new());
    }
    let mut keys: Vec<NativeIntKey> = Vec::new();
    for method in &native_methods {
        if method.descriptor.ends_with(")I") || method.descriptor.ends_with(")J") {
            let long: Option<&(String, i64)> = exports.get(&method.jni_long_symbol);
            let short: Option<&(String, i64)> = short_counts
                .get(method.jni_short_symbol.as_str())
                .copied()
                .filter(|count: &usize| *count == 1)
                .and_then(|_| exports.get(&method.jni_short_symbol));
            let Some((source_library, value)): Option<&(String, i64)> = long.or(short) else {
                continue;
            };
            let symbol: String = if long.is_some() {
                method.jni_long_symbol.clone()
            } else {
                method.jni_short_symbol.clone()
            };
            keys.push(NativeIntKey {
                class: method.class.clone(),
                method: method.method.clone(),
                descriptor: method.descriptor.clone(),
                value: *value,
                source_library: source_library.clone(),
                symbol,
            });
            if keys.len() >= MAX_NATIVE_INT_KEYS {
                break;
            }
        }
    }
    Ok(keys)
}

fn constant_int_exports(bytes: &[u8]) -> Vec<(String, i64)> {
    let Ok(file): Result<ObjFile<'_, &[u8]>, _> = ObjFile::parse(bytes) else {
        return Vec::new();
    };
    let endian: Endianness = file.endianness();
    let arch: Architecture = file.architecture();
    let mut out: BTreeMap<String, i64> = BTreeMap::new();
    if let Ok(exports) = file.exports() {
        for export in exports {
            let name: String = String::from_utf8_lossy(export.name()).into_owned();
            if let Some(value) = constant_export_value(&file, arch, endian, &name, export.address())
            {
                out.entry(name).or_insert(value);
            }
        }
    }
    for symbol in file.symbols() {
        if symbol.kind() != SymbolKind::Text {
            continue;
        }
        let Ok(name): Result<&str, _> = symbol.name() else {
            continue;
        };
        if let Some(value) = constant_export_value(&file, arch, endian, name, symbol.address()) {
            out.entry(name.to_owned()).or_insert(value);
        }
    }
    out.into_iter().collect()
}

fn constant_export_value<'a>(
    file: &ObjFile<'a, &'a [u8]>,
    arch: Architecture,
    endian: Endianness,
    name: &str,
    address: u64,
) -> Option<i64> {
    if !name.starts_with("Java_") {
        return None;
    }
    let stub: &[u8] = bytes_at_address(file, address, MAX_STUB_BYTES)?;
    decode_constant_return(arch, endian, stub)
}

fn bytes_at_address<'a>(
    file: &ObjFile<'a, &'a [u8]>,
    address: u64,
    max_len: usize,
) -> Option<&'a [u8]> {
    for section in file.sections() {
        let start: u64 = section.address();
        let end: u64 = start.checked_add(section.size())?;
        if address >= start && address < end {
            let offset: usize = usize::try_from(address - start).ok()?;
            let data: &'a [u8] = section.data().ok()?;
            let stop: usize = offset.saturating_add(max_len).min(data.len());
            return data.get(offset..stop);
        }
    }
    None
}

fn decode_constant_return(arch: Architecture, endian: Endianness, stub: &[u8]) -> Option<i64> {
    match arch {
        Architecture::Aarch64 | Architecture::Aarch64_Ilp32 => {
            decode_aarch64_constant_return(endian, stub)
        }
        Architecture::X86_64 | Architecture::X86_64_X32 => decode_x86_64_constant_return(stub),
        _ => None,
    }
}

fn decode_aarch64_constant_return(endian: Endianness, stub: &[u8]) -> Option<i64> {
    let insn: [u8; 4] = stub.get(0..4)?.try_into().ok()?;
    let ret: [u8; 4] = stub.get(4..8)?.try_into().ok()?;
    let word: u32 = match endian {
        Endianness::Little => u32::from_le_bytes(insn),
        Endianness::Big => u32::from_be_bytes(insn),
    };
    let ret_word: u32 = match endian {
        Endianness::Little => u32::from_le_bytes(ret),
        Endianness::Big => u32::from_be_bytes(ret),
    };
    if ret_word != 0xD65F03C0 {
        return None;
    }
    if word & 0xFFE0001F == 0x52800000 || word & 0xFFE0001F == 0xD2800000 {
        return Some(i64::from((word >> 5) & 0xFFFF));
    }
    None
}

fn decode_x86_64_constant_return(stub: &[u8]) -> Option<i64> {
    if stub.get(0..3) == Some(&[0x31, 0xC0, 0xC3]) {
        return Some(0);
    }
    if stub.first().copied() == Some(0xB8) && stub.get(5).copied() == Some(0xC3) {
        let raw: [u8; 4] = stub.get(1..5)?.try_into().ok()?;
        return Some(i64::from(i32::from_le_bytes(raw)));
    }
    if stub.get(0..3) == Some(&[0x48, 0xC7, 0xC0]) && stub.get(7).copied() == Some(0xC3) {
        let raw: [u8; 4] = stub.get(3..7)?.try_into().ok()?;
        return Some(i64::from(i32::from_le_bytes(raw)));
    }
    None
}

const CLASS_ACC_STATIC: u16 = 0x0008;
const CLASS_ACC_NATIVE: u16 = 0x0100;

const KNOWN_THROWABLES: &[&str] = &[
    "java/lang/Throwable",
    "java/lang/Exception",
    "java/lang/RuntimeException",
    "java/lang/Error",
    "java/lang/ArithmeticException",
    "java/lang/ArrayIndexOutOfBoundsException",
    "java/lang/ArrayStoreException",
    "java/lang/ClassCastException",
    "java/lang/ClassNotFoundException",
    "java/lang/CloneNotSupportedException",
    "java/lang/IllegalAccessException",
    "java/lang/IllegalArgumentException",
    "java/lang/IllegalMonitorStateException",
    "java/lang/IllegalStateException",
    "java/lang/IllegalThreadStateException",
    "java/lang/IndexOutOfBoundsException",
    "java/lang/InstantiationException",
    "java/lang/InterruptedException",
    "java/lang/NegativeArraySizeException",
    "java/lang/NoSuchFieldException",
    "java/lang/NoSuchMethodException",
    "java/lang/NullPointerException",
    "java/lang/NumberFormatException",
    "java/lang/ReflectiveOperationException",
    "java/lang/SecurityException",
    "java/lang/StringIndexOutOfBoundsException",
    "java/lang/UnsupportedOperationException",
    "java/lang/AssertionError",
    "java/lang/LinkageError",
    "java/lang/VirtualMachineError",
    "java/lang/StackOverflowError",
    "java/lang/OutOfMemoryError",
    "java/lang/NoClassDefFoundError",
    "java/lang/ExceptionInInitializerError",
    "java/io/IOException",
    "java/io/FileNotFoundException",
    "java/io/UncheckedIOException",
    "java/io/UnsupportedEncodingException",
    "java/util/ConcurrentModificationException",
    "java/util/NoSuchElementException",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JniPrototype {
    pub class: String,
    pub method: String,
    pub descriptor: String,
    pub symbol: String,
    pub is_static: bool,
    pub return_type: String,
    pub param_types: Vec<String>,
    pub declaration: String,
}

#[must_use]
pub fn native_methods_from_class(class: &ClassFile) -> Vec<NativeMethod> {
    let Ok(class_name): crate::error::Result<&str> = class.this_class_name() else {
        return Vec::new();
    };
    let mut out: Vec<NativeMethod> = Vec::new();
    for method in &class.methods {
        if method.access_flags & CLASS_ACC_NATIVE == 0 {
            continue;
        }
        let Ok(name): crate::error::Result<&str> = class.utf8_at(method.name_index) else {
            continue;
        };
        let Ok(descriptor): crate::error::Result<&str> = class.utf8_at(method.descriptor_index)
        else {
            continue;
        };
        let (short, long): (String, String) =
            jni_symbols(class_name, name, argument_descriptor(descriptor));
        out.push(NativeMethod {
            class: class_name.to_owned(),
            method: name.to_owned(),
            descriptor: descriptor.to_owned(),
            jni_short_symbol: short,
            jni_long_symbol: long,
            is_static: method.access_flags & CLASS_ACC_STATIC != 0,
        });
    }
    out
}

#[must_use]
pub fn emit_prototypes(methods: &[NativeMethod]) -> Vec<JniPrototype> {
    let mut name_counts: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for method in methods {
        *name_counts
            .entry((method.class.as_str(), method.method.as_str()))
            .or_insert(0) += 1;
    }
    let mut out: Vec<JniPrototype> = Vec::with_capacity(methods.len());
    for method in methods {
        let Some(parsed): Option<crate::descriptor::MethodDescriptor> =
            parse_method(&method.descriptor)
        else {
            continue;
        };
        let overloaded: bool = name_counts
            .get(&(method.class.as_str(), method.method.as_str()))
            .copied()
            .unwrap_or(0)
            > 1;
        let symbol: String = if overloaded {
            method.jni_long_symbol.clone()
        } else {
            method.jni_short_symbol.clone()
        };
        let return_type: String = jni_return_type(&parsed.returns);
        let param_types: Vec<String> = parsed.params.iter().map(jni_value_type).collect();
        let receiver: &str = if method.is_static {
            "jclass"
        } else {
            "jobject"
        };
        let mut signature: Vec<String> = Vec::with_capacity(param_types.len() + 2);
        signature.push("JNIEnv *".to_owned());
        signature.push(receiver.to_owned());
        signature.extend(param_types.iter().cloned());
        let declaration: String = format!(
            "JNIEXPORT {return_type} JNICALL {symbol}({});",
            signature.join(", ")
        );
        out.push(JniPrototype {
            class: method.class.clone(),
            method: method.method.clone(),
            descriptor: method.descriptor.clone(),
            symbol,
            is_static: method.is_static,
            return_type,
            param_types,
            declaration,
        });
    }
    out
}

fn argument_descriptor(descriptor: &str) -> &str {
    descriptor
        .strip_prefix('(')
        .and_then(|rest: &str| rest.split_once(')'))
        .map_or("", |(args, _): (&str, &str)| args)
}

fn jni_return_type(ty: &JavaType) -> String {
    match ty {
        JavaType::Void => "void".to_owned(),
        other => jni_value_type(other),
    }
}

fn jni_value_type(ty: &JavaType) -> String {
    match ty {
        JavaType::Boolean => "jboolean".to_owned(),
        JavaType::Byte => "jbyte".to_owned(),
        JavaType::Char => "jchar".to_owned(),
        JavaType::Short => "jshort".to_owned(),
        JavaType::Int => "jint".to_owned(),
        JavaType::Long => "jlong".to_owned(),
        JavaType::Float => "jfloat".to_owned(),
        JavaType::Double => "jdouble".to_owned(),
        JavaType::Void => "void".to_owned(),
        JavaType::Object(internal) => jni_reference_type(internal).to_owned(),
        JavaType::Array(inner) => jni_array_type(inner).to_owned(),
    }
}

fn jni_reference_type(internal: &str) -> &'static str {
    let name: &str = internal
        .strip_prefix('L')
        .and_then(|s: &str| s.strip_suffix(';'))
        .unwrap_or(internal);
    match name {
        "java/lang/String" => "jstring",
        "java/lang/Class" => "jclass",
        n if KNOWN_THROWABLES.contains(&n) => "jthrowable",
        _ => "jobject",
    }
}

const fn jni_array_type(inner: &JavaType) -> &'static str {
    match inner {
        JavaType::Boolean => "jbooleanArray",
        JavaType::Byte => "jbyteArray",
        JavaType::Char => "jcharArray",
        JavaType::Short => "jshortArray",
        JavaType::Int => "jintArray",
        JavaType::Long => "jlongArray",
        JavaType::Float => "jfloatArray",
        JavaType::Double => "jdoubleArray",
        JavaType::Object(_) | JavaType::Array(_) | JavaType::Void => "jobjectArray",
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn native(class: &str, method: &str, descriptor: &str, is_static: bool) -> NativeMethod {
        let (short, long): (String, String) =
            jni_symbols(class, method, argument_descriptor(descriptor));
        NativeMethod {
            class: class.to_owned(),
            method: method.to_owned(),
            descriptor: descriptor.to_owned(),
            jni_short_symbol: short,
            jni_long_symbol: long,
            is_static,
        }
    }

    #[test]
    fn abi_extracted_from_lib_path() {
        assert_eq!(
            abi_from_path("lib/arm64-v8a/libnative.so").as_deref(),
            Some("arm64-v8a")
        );
        assert_eq!(abi_from_path("classes.dex"), None);
    }

    #[test]
    fn mangling_covers_every_escape_class() {
        assert_eq!(
            jni_symbols("com/foo/Bar", "run", "").0,
            "Java_com_foo_Bar_run"
        );
        assert_eq!(
            jni_symbols("a", "with_underscore", "").0,
            "Java_a_with_1underscore"
        );
        assert_eq!(
            jni_symbols("a", "with$dollar", "").0,
            "Java_a_with_00024dollar"
        );
        assert_eq!(
            jni_symbols("a", "f", "Ljava/lang/String;").1,
            "Java_a_f__Ljava_lang_String_2"
        );
        assert_eq!(jni_symbols("a", "f", "[I").1, "Java_a_f___3I");
        assert_eq!(
            jni_symbols("a", "value\u{03c0}", "").0,
            "Java_a_value_003c0"
        );
    }

    #[test]
    fn primitive_reference_and_array_types_map_to_jni() {
        let methods: Vec<NativeMethod> = vec![
            native("Foo", "z", "()Z", false),
            native("Foo", "arr", "([I)[Ljava/lang/String;", true),
            native(
                "Foo",
                "refs",
                "(Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;Ljava/lang/Throwable;)V",
                false,
            ),
        ];
        let protos: Vec<JniPrototype> = emit_prototypes(&methods);
        let by_method = |m: &str| -> &JniPrototype {
            protos
                .iter()
                .find(|p: &&JniPrototype| p.method == m)
                .unwrap()
        };
        assert_eq!(
            by_method("z").declaration,
            "JNIEXPORT jboolean JNICALL Java_Foo_z(JNIEnv *, jobject);"
        );
        assert_eq!(
            by_method("arr").declaration,
            "JNIEXPORT jobjectArray JNICALL Java_Foo_arr(JNIEnv *, jclass, jintArray);"
        );
        assert_eq!(
            by_method("refs").declaration,
            "JNIEXPORT void JNICALL Java_Foo_refs(JNIEnv *, jobject, jstring, jclass, jobject, jthrowable);"
        );
    }

    #[test]
    fn overloaded_natives_switch_to_the_long_symbol() {
        let methods: Vec<NativeMethod> = vec![
            native("Foo", "over", "(I)I", false),
            native("Foo", "over", "(Ljava/lang/String;)I", false),
            native("Bar", "solo", "(I)I", false),
        ];
        let protos: Vec<JniPrototype> = emit_prototypes(&methods);
        assert_eq!(
            protos
                .iter()
                .find(|p: &&JniPrototype| p.descriptor == "(I)I")
                .unwrap()
                .symbol,
            "Java_Foo_over__I"
        );
        assert_eq!(
            protos
                .iter()
                .find(|p: &&JniPrototype| p.descriptor == "(Ljava/lang/String;)I")
                .unwrap()
                .symbol,
            "Java_Foo_over__Ljava_lang_String_2"
        );
        assert_eq!(
            protos
                .iter()
                .find(|p: &&JniPrototype| p.class == "Bar")
                .unwrap()
                .symbol,
            "Java_Bar_solo"
        );
    }
}
