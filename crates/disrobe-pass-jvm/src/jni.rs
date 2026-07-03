use std::collections::BTreeMap;

use object::Object as _;
use object::ObjectSection as _;
use object::ObjectSymbol as _;
use object::read::File as ObjFile;
use object::{Architecture, Endianness, SymbolKind};
use serde::{Deserialize, Serialize};

use crate::dalvik_strdec::NativeIntKey;
use crate::dex::{DexFile, NativeMethod, extract_native_methods};

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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JniSurfaceReport {
    pub native_method_count: usize,
    pub native_methods: Vec<ResolvedNative>,
    pub libraries: Vec<NativeLibrary>,
    pub resolved_statically: usize,
    pub dynamic_only: usize,
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
    for (_name, dex, bytes) in dexes {
        native_methods.extend(extract_native_methods(dex, bytes));
    }

    let mut libraries: Vec<NativeLibrary> = Vec::new();
    for (path, bytes) in native_libs {
        if let Some(lib) = parse_library(path, bytes) {
            libraries.push(lib);
        }
    }
    libraries.sort_by(|a: &NativeLibrary, b: &NativeLibrary| a.path.cmp(&b.path));

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
    }
}

#[must_use]
pub fn extract_static_int_keys(
    dex: &DexFile,
    dex_bytes: &[u8],
    native_libs: &[(&str, &[u8])],
) -> Vec<NativeIntKey> {
    let native_methods: Vec<NativeMethod> = extract_native_methods(dex, dex_bytes);
    if native_methods.is_empty() || native_libs.is_empty() {
        return Vec::new();
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
        return Vec::new();
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
    keys
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_extracted_from_lib_path() {
        assert_eq!(
            abi_from_path("lib/arm64-v8a/libnative.so").as_deref(),
            Some("arm64-v8a")
        );
        assert_eq!(abi_from_path("classes.dex"), None);
    }
}
