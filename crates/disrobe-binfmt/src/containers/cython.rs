use std::collections::BTreeMap;

use object::read::{Object, ObjectSection, ObjectSymbol, ObjectSymbolTable};
use object::{File as ObjFile, RelocationTarget, SectionKind};
use serde::{Deserialize, Serialize};

use crate::container::memchr_find;
use crate::error::{Error, Result};

const INIT_PREFIX: &[u8] = b"PyInit_";
const INIT_PREFIX_U: &[u8] = b"PyInitU_";
const MDEF_PREFIX: &str = "__pyx_mdef_";
const METHODS_SYMBOL: &str = "__pyx_methods";
const METHODS_PREFIX: &str = "__pyx_methods_";
const TYPE_PREFIX: &str = "__pyx_type_";
const IS_MAIN_PREFIX: &str = "__pyx_module_is_main_";
const FILETABLE_SYMBOL: &str = "__pyx_f";

const MARKER_PYX: &[u8] = b"__pyx_";
const MARKER_PYX_UPPER: &[u8] = b"__Pyx_";
const MARKER_REDUCE: &[u8] = b"__reduce_cython__";

const MAX_TABLE_ENTRIES: usize = 8192;
const MAX_STRUCTURAL_RECORDS: usize = 65536;
const MAX_STRUCTURAL_SCAN_ATTEMPTS: usize = 2_000_000;
const MAX_NAME_LEN: usize = 256;
const MAX_DOC_LEN: usize = 16384;
const MAX_SOURCE_FILES: usize = 512;
const MAX_FILETABLE_ENTRIES: usize = 4096;
const MAX_MODULE_NAME_LEN: usize = 512;

const METH_VARARGS: u32 = 0x0001;
const METH_NOARGS: u32 = 0x0004;
const METH_O: u32 = 0x0008;
const METH_FASTCALL: u32 = 0x0080;
const METH_FLAG_MASK: u32 = 0x03FF;
const METH_CALLCONV_MASK: u32 = METH_VARARGS | METH_NOARGS | METH_O | METH_FASTCALL;

const SOURCE_SUFFIXES: [&str; 5] = [".pyx", ".pxd", ".pxi", ".py", "<stringsource>"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecoverySource {
    Symbol,
    Structural,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CythonIdentity {
    pub module_name: String,
    pub init_symbol: String,
    pub pyx_symbols_present: bool,
    pub marker_strings_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CythonFunction {
    pub name: String,
    pub qualname: Option<String>,
    pub signature: Option<String>,
    pub doc: Option<String>,
    pub flags: u32,
    pub impl_symbol: Option<String>,
    pub recovered_via: RecoverySource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CythonClass {
    pub name: String,
    pub doc: Option<String>,
    pub methods: Vec<String>,
    pub type_symbol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CythonModule {
    pub module_name: String,
    pub init_symbol: String,
    pub pyx_symbols_present: bool,
    pub marker_strings_present: bool,
    pub functions: Vec<CythonFunction>,
    pub classes: Vec<CythonClass>,
    pub source_files: Vec<String>,
    pub has_debug_line: bool,
    pub has_debug_info: bool,
}

struct LoadedSection<'d> {
    address: u64,
    data: &'d [u8],
    executable: bool,
    readable: bool,
}

struct AddressSpace<'d> {
    sections: Vec<LoadedSection<'d>>,
    pointer_width: usize,
    little_endian: bool,
    reloc_targets: BTreeMap<u64, u64>,
}

impl<'d> AddressSpace<'d> {
    const fn record_size(&self) -> usize {
        self.pointer_width * 4
    }

    fn slice_at(&self, va: u64) -> Option<&'d [u8]> {
        for sec in &self.sections {
            if !sec.readable || sec.data.is_empty() {
                continue;
            }
            let end: u64 = sec.address.checked_add(sec.data.len() as u64)?;
            if va >= sec.address && va < end {
                let offset: usize = usize::try_from(va - sec.address).ok()?;
                return sec.data.get(offset..);
            }
        }
        None
    }

    fn is_executable(&self, va: u64) -> bool {
        self.sections.iter().any(|sec: &LoadedSection<'d>| {
            sec.executable
                && !sec.data.is_empty()
                && va >= sec.address
                && sec
                    .address
                    .checked_add(sec.data.len() as u64)
                    .is_some_and(|end: u64| va < end)
        })
    }

    fn read_pointer(&self, va: u64) -> Option<u64> {
        let slice: &[u8] = self.slice_at(va)?;
        let raw: u64 = if self.pointer_width == 8 {
            let bytes: [u8; 8] = slice.get(..8)?.try_into().ok()?;
            if self.little_endian {
                u64::from_le_bytes(bytes)
            } else {
                u64::from_be_bytes(bytes)
            }
        } else {
            let bytes: [u8; 4] = slice.get(..4)?.try_into().ok()?;
            let narrow: u32 = if self.little_endian {
                u32::from_le_bytes(bytes)
            } else {
                u32::from_be_bytes(bytes)
            };
            u64::from(narrow)
        };
        if raw != 0 {
            return Some(raw);
        }
        self.reloc_targets.get(&va).copied()
    }

    fn read_u32(&self, va: u64) -> Option<u32> {
        let slice: &[u8] = self.slice_at(va)?;
        let bytes: [u8; 4] = slice.get(..4)?.try_into().ok()?;
        Some(if self.little_endian {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        })
    }

    fn read_c_string(&self, va: u64, max_len: usize) -> Option<String> {
        let slice: &[u8] = self.slice_at(va)?;
        let bound: usize = slice.len().min(max_len);
        let window: &[u8] = slice.get(..bound)?;
        let end: usize = window.iter().position(|&b: &u8| b == 0)?;
        std::str::from_utf8(&window[..end]).ok().map(str::to_owned)
    }

    fn scan_for_marker(&self, needle: &[u8]) -> bool {
        self.sections.iter().any(|sec: &LoadedSection<'d>| {
            sec.readable && memchr_find(sec.data, needle, 0).is_some()
        })
    }
}

struct MethodDef {
    func: CythonFunction,
    meth_va: u64,
}

#[must_use]
pub fn detect_cython(bytes: &[u8]) -> Option<CythonIdentity> {
    let file: ObjFile<'_> = ObjFile::parse(bytes).ok()?;
    let space: AddressSpace<'_> = build_address_space(&file);
    let (module_name, init_symbol): (String, String) = locate_module_init(&file)?;
    let pyx_symbols_present: bool = has_pyx_symbols(&file);
    let marker_strings_present: bool = has_cython_markers(&space);
    if !pyx_symbols_present && !marker_strings_present {
        return None;
    }
    Some(CythonIdentity {
        module_name,
        init_symbol,
        pyx_symbols_present,
        marker_strings_present,
    })
}

pub fn recover_cython(bytes: &[u8]) -> Result<CythonModule> {
    let file: ObjFile<'_> =
        ObjFile::parse(bytes).map_err(|e: object::Error| Error::Cython(e.to_string()))?;
    let space: AddressSpace<'_> = build_address_space(&file);
    let (module_name, init_symbol): (String, String) = locate_module_init(&file)
        .ok_or_else(|| Error::Cython("no PyInit_* entry point found".to_owned()))?;

    let pyx_symbols_present: bool = has_pyx_symbols(&file);
    let marker_strings_present: bool = has_cython_markers(&space);
    if !pyx_symbols_present && !marker_strings_present {
        return Err(Error::Cython(
            "PyInit entry present but no cython runtime fingerprint".to_owned(),
        ));
    }

    let mut merged: BTreeMap<(String, u64), CythonFunction> = BTreeMap::new();
    let mut classes: BTreeMap<String, CythonClass> = BTreeMap::new();

    recover_from_symbols(&file, &space, &mut merged, &mut classes);
    recover_structural(&space, &mut merged);
    enrich_class_docs(&space, &mut classes);

    let mut functions: Vec<CythonFunction> = merged.into_values().collect();
    functions.sort_by(|a: &CythonFunction, b: &CythonFunction| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.qualname.cmp(&b.qualname))
    });

    let mut class_list: Vec<CythonClass> = classes.into_values().collect();
    class_list.sort_by(|a: &CythonClass, b: &CythonClass| a.name.cmp(&b.name));

    let source_files: Vec<String> = recover_source_files(&file, &space);
    let has_debug_line: bool = has_section_named(&file, ".debug_line");
    let has_debug_info: bool = has_section_named(&file, ".debug_info");

    Ok(CythonModule {
        module_name,
        init_symbol,
        pyx_symbols_present,
        marker_strings_present,
        functions,
        classes: class_list,
        source_files,
        has_debug_line,
        has_debug_info,
    })
}

fn has_pyx_symbols(file: &ObjFile<'_>) -> bool {
    file.symbols().any(|sym| {
        sym.name()
            .is_ok_and(|n: &str| n.starts_with("__pyx_") || n.starts_with("__Pyx_"))
    })
}

fn has_cython_markers(space: &AddressSpace<'_>) -> bool {
    space.scan_for_marker(MARKER_PYX)
        || space.scan_for_marker(MARKER_PYX_UPPER)
        || space.scan_for_marker(MARKER_REDUCE)
}

fn build_address_space<'d>(file: &ObjFile<'d>) -> AddressSpace<'d> {
    let pointer_width: usize = if file.is_64() { 8 } else { 4 };
    let little_endian: bool = file.is_little_endian();
    let mut sections: Vec<LoadedSection<'d>> = Vec::new();
    let mut reloc_targets: BTreeMap<u64, u64> = BTreeMap::new();

    for section in file.sections() {
        let Ok(data): std::result::Result<&[u8], object::Error> = section.data() else {
            continue;
        };
        let kind: SectionKind = section.kind();
        let executable: bool = matches!(kind, SectionKind::Text);
        let readable: bool = matches!(
            kind,
            SectionKind::Text
                | SectionKind::Data
                | SectionKind::ReadOnlyData
                | SectionKind::ReadOnlyString
                | SectionKind::ReadOnlyDataWithRel
                | SectionKind::UninitializedData
        );
        let base: u64 = section.address();
        sections.push(LoadedSection {
            address: base,
            data,
            executable,
            readable,
        });

        for (offset, reloc) in section.relocations() {
            let Some(site): Option<u64> = base.checked_add(offset) else {
                continue;
            };
            let target: Option<u64> = match reloc.target() {
                RelocationTarget::Absolute => u64::try_from(reloc.addend()).ok(),
                RelocationTarget::Symbol(index) => file
                    .symbol_by_index(index)
                    .ok()
                    .map(|sym| sym.address().wrapping_add(reloc.addend() as u64)),
                _ => None,
            };
            insert_reloc_target(&mut reloc_targets, site, target);
        }
    }

    if let Some(dynamic) = file.dynamic_relocations() {
        let dynamic_symbols: Option<_> = file.dynamic_symbol_table();
        for (site, reloc) in dynamic {
            let target: Option<u64> = match reloc.target() {
                RelocationTarget::Absolute => u64::try_from(reloc.addend()).ok(),
                RelocationTarget::Symbol(index) => dynamic_symbols
                    .as_ref()
                    .and_then(|table| table.symbol_by_index(index).ok())
                    .map(|sym| sym.address().wrapping_add(reloc.addend() as u64)),
                _ => None,
            };
            insert_reloc_target(&mut reloc_targets, site, target);
        }
    }

    AddressSpace {
        sections,
        pointer_width,
        little_endian,
        reloc_targets,
    }
}

fn insert_reloc_target(targets: &mut BTreeMap<u64, u64>, site: u64, value: Option<u64>) {
    if let Some(resolved) = value.filter(|v: &u64| *v != 0) {
        targets.entry(site).or_insert(resolved);
    }
}

fn locate_module_init(file: &ObjFile<'_>) -> Option<(String, String)> {
    if let Ok(exports) = file.exports() {
        for export in exports {
            if let Some(name) = module_name_from_init(export.name()) {
                return Some((name, String::from_utf8_lossy(export.name()).into_owned()));
            }
        }
    }
    for sym in file.symbols() {
        let Ok(name): std::result::Result<&str, object::Error> = sym.name() else {
            continue;
        };
        if let Some(module) = module_name_from_init(name.as_bytes()) {
            return Some((module, name.to_owned()));
        }
        if let Some(module) = name.strip_prefix(IS_MAIN_PREFIX)
            && !module.is_empty()
            && module.len() <= MAX_MODULE_NAME_LEN
        {
            return Some((module.to_owned(), name.to_owned()));
        }
    }
    None
}

fn module_name_from_init(symbol: &[u8]) -> Option<String> {
    let tail: &[u8] = symbol
        .strip_prefix(INIT_PREFIX)
        .or_else(|| symbol.strip_prefix(INIT_PREFIX_U))?;
    if tail.is_empty() || tail.len() > MAX_MODULE_NAME_LEN {
        return None;
    }
    if !tail
        .iter()
        .all(|&b: &u8| b.is_ascii_alphanumeric() || b == b'_')
    {
        return None;
    }
    Some(String::from_utf8_lossy(tail).into_owned())
}

fn recover_from_symbols(
    file: &ObjFile<'_>,
    space: &AddressSpace<'_>,
    functions: &mut BTreeMap<(String, u64), CythonFunction>,
    classes: &mut BTreeMap<String, CythonClass>,
) {
    for sym in file.symbols() {
        let Ok(name): std::result::Result<&str, object::Error> = sym.name() else {
            continue;
        };
        let address: u64 = sym.address();
        if name.starts_with(MDEF_PREFIX) {
            if let Some(record) = read_method_def(space, address, RecoverySource::Symbol) {
                register_function(file, record, functions);
            }
        } else if name == METHODS_SYMBOL || name.starts_with(METHODS_PREFIX) {
            let class_name: Option<String> = name
                .strip_prefix(METHODS_PREFIX)
                .and_then(demangle_qualified_name);
            let mut method_names: Vec<String> = Vec::new();
            for record in walk_method_table(space, address, RecoverySource::Symbol) {
                method_names.push(record.func.name.clone());
                register_function(file, record, functions);
            }
            if let Some(cls) = class_name
                && !method_names.is_empty()
            {
                add_class_methods(classes, cls, method_names);
            }
        } else if let Some(rest) = name.strip_prefix(TYPE_PREFIX) {
            if rest.ends_with("_spec") || rest.ends_with("_slots") {
                continue;
            }
            if let Some(cls) = demangle_qualified_name(rest) {
                let entry: &mut CythonClass = class_entry(classes, cls);
                if entry.type_symbol.is_none() {
                    entry.type_symbol = Some(name.to_owned());
                }
            }
        }
    }
}

fn class_entry(classes: &mut BTreeMap<String, CythonClass>, name: String) -> &mut CythonClass {
    classes.entry(name.clone()).or_insert_with(|| CythonClass {
        name,
        doc: None,
        methods: Vec::new(),
        type_symbol: None,
    })
}

fn add_class_methods(
    classes: &mut BTreeMap<String, CythonClass>,
    class_name: String,
    method_names: Vec<String>,
) {
    let entry: &mut CythonClass = class_entry(classes, class_name);
    for method in method_names {
        if !entry.methods.contains(&method) {
            entry.methods.push(method);
        }
    }
}

fn register_function(
    file: &ObjFile<'_>,
    mut record: MethodDef,
    functions: &mut BTreeMap<(String, u64), CythonFunction>,
) {
    if record.func.impl_symbol.is_none() {
        record.func.impl_symbol = symbol_name_at(file, record.meth_va);
    }
    functions
        .entry((record.func.name.clone(), record.meth_va))
        .or_insert(record.func);
}

fn recover_structural(
    space: &AddressSpace<'_>,
    functions: &mut BTreeMap<(String, u64), CythonFunction>,
) {
    let record_size: usize = space.record_size();
    let mut emitted: usize = 0;
    let mut attempts: usize = 0;
    for sec_index in 0..space.sections.len() {
        let (base, len, readable, executable): (u64, usize, bool, bool) = {
            let sec: &LoadedSection<'_> = &space.sections[sec_index];
            (sec.address, sec.data.len(), sec.readable, sec.executable)
        };
        if !readable || executable || len < record_size {
            continue;
        }
        let mut offset: usize = 0;
        while offset + record_size <= len {
            if attempts >= MAX_STRUCTURAL_SCAN_ATTEMPTS {
                return;
            }
            attempts += 1;
            let va: u64 = base.wrapping_add(offset as u64);
            if let Some(record) = read_method_def(space, va, RecoverySource::Structural) {
                functions
                    .entry((record.func.name.clone(), record.meth_va))
                    .or_insert(record.func);
                emitted += 1;
                if emitted >= MAX_STRUCTURAL_RECORDS {
                    return;
                }
            }
            offset += space.pointer_width;
        }
    }
}

fn walk_method_table(
    space: &AddressSpace<'_>,
    table_va: u64,
    source: RecoverySource,
) -> Vec<MethodDef> {
    let record_size: u64 = space.record_size() as u64;
    let mut out: Vec<MethodDef> = Vec::new();
    let mut index: u64 = 0;
    while (index as usize) < MAX_TABLE_ENTRIES {
        let Some(entry_va): Option<u64> = index
            .checked_mul(record_size)
            .and_then(|delta: u64| table_va.checked_add(delta))
        else {
            break;
        };
        match read_method_def(space, entry_va, source) {
            Some(record) => out.push(record),
            None => break,
        }
        index += 1;
    }
    out
}

fn read_method_def(
    space: &AddressSpace<'_>,
    entry_va: u64,
    source: RecoverySource,
) -> Option<MethodDef> {
    let ptr: u64 = space.pointer_width as u64;
    let name_va: u64 = space.read_pointer(entry_va)?;
    let meth_va: u64 = space.read_pointer(entry_va.checked_add(ptr)?)?;
    let flags_va: u64 = entry_va.checked_add(ptr.checked_mul(2)?)?;
    let flags: u32 = space.read_u32(flags_va)?;
    if space.pointer_width == 8 {
        let pad: u32 = space.read_u32(flags_va.checked_add(4)?)?;
        if pad != 0 {
            return None;
        }
    }
    let doc_va: u64 = space.read_pointer(entry_va.checked_add(ptr.checked_mul(3)?)?)?;

    if !valid_flags(flags) || !space.is_executable(meth_va) {
        return None;
    }
    let name: String = space.read_c_string(name_va, MAX_NAME_LEN)?;
    if !is_valid_identifier(&name) {
        return None;
    }
    let doc: Option<String> = if doc_va == 0 {
        None
    } else {
        space
            .read_c_string(doc_va, MAX_DOC_LEN)
            .filter(|text: &String| !text.is_empty())
    };
    let (signature, qualname): (Option<String>, Option<String>) = extract_signature(doc.as_deref());

    Some(MethodDef {
        func: CythonFunction {
            name,
            qualname,
            signature,
            doc,
            flags,
            impl_symbol: None,
            recovered_via: source,
        },
        meth_va,
    })
}

const fn valid_flags(flags: u32) -> bool {
    flags != 0 && (flags & !METH_FLAG_MASK) == 0 && (flags & METH_CALLCONV_MASK) != 0
}

fn is_valid_identifier(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return false;
    }
    let Some(first): Option<char> = name.chars().next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    name.chars()
        .all(|c: char| c.is_ascii_alphanumeric() || c == '_')
}

fn extract_signature(doc: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(text): Option<&str> = doc else {
        return (None, None);
    };
    let first_line: &str = text.lines().next().unwrap_or("").trim();
    let Some(open_idx): Option<usize> = first_line.find('(') else {
        return (None, None);
    };
    if !first_line.contains(')') {
        return (None, None);
    }
    let head: &str = first_line[..open_idx].trim();
    if head.is_empty()
        || !head
            .chars()
            .all(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    {
        return (None, None);
    }
    let qualname: Option<String> = head.contains('.').then(|| head.to_owned());
    (Some(first_line.to_owned()), qualname)
}

fn demangle_qualified_name(mangled: &str) -> Option<String> {
    let bytes: &[u8] = mangled.as_bytes();
    let digits_end: usize = bytes
        .iter()
        .take_while(|b: &&u8| b.is_ascii_digit())
        .count();
    if digits_end == 0 {
        return mangled.rsplit('_').next().map(str::to_owned);
    }
    let module_len: usize = mangled.get(..digits_end)?.parse::<usize>().ok()?;
    let after_len: &str = mangled.get(digits_end..)?;
    let boundary: usize = module_len.checked_add(1)?;
    let rest: &str = after_len.get(boundary..)?;
    let clean: &str = rest.split(['[', '.', ' ']).next().unwrap_or(rest);
    if clean.is_empty() {
        None
    } else {
        Some(clean.to_owned())
    }
}

fn symbol_name_at(file: &ObjFile<'_>, address: u64) -> Option<String> {
    let mut fallback: Option<String> = None;
    for sym in file.symbols() {
        if sym.address() != address {
            continue;
        }
        let Ok(name): std::result::Result<&str, object::Error> = sym.name() else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        if name.starts_with("__pyx_pw_") || name.starts_with("__pyx_pf_") {
            return Some(name.to_owned());
        }
        if fallback.is_none() {
            fallback = Some(name.to_owned());
        }
    }
    fallback
}

fn enrich_class_docs(space: &AddressSpace<'_>, classes: &mut BTreeMap<String, CythonClass>) {
    for class in classes.values_mut() {
        if class.doc.is_some() {
            continue;
        }
        let needle: String = format!("{}(", class.name);
        class.doc = find_doc_starting_with(space, needle.as_bytes());
    }
}

fn find_doc_starting_with(space: &AddressSpace<'_>, prefix: &[u8]) -> Option<String> {
    for sec in &space.sections {
        if !sec.readable {
            continue;
        }
        let mut from: usize = 0;
        while let Some(start) = memchr_find(sec.data, prefix, from) {
            let at_string_start: bool = start == 0 || sec.data.get(start - 1) == Some(&0);
            if at_string_start {
                let tail: &[u8] = &sec.data[start..];
                if let Some(end) = tail.iter().take(MAX_DOC_LEN).position(|&b: &u8| b == 0)
                    && end > 0
                    && let Ok(text) = std::str::from_utf8(&tail[..end])
                {
                    return Some(text.to_owned());
                }
            }
            from = start + 1;
        }
    }
    None
}

fn recover_source_files(file: &ObjFile<'_>, space: &AddressSpace<'_>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();

    if let Some(table_va) = filetable_address(file) {
        let ptr: u64 = space.pointer_width as u64;
        for index in 0..MAX_FILETABLE_ENTRIES as u64 {
            let Some(slot_va): Option<u64> = index
                .checked_mul(ptr)
                .and_then(|delta: u64| table_va.checked_add(delta))
            else {
                break;
            };
            let Some(str_va): Option<u64> = space.read_pointer(slot_va) else {
                break;
            };
            if str_va == 0 {
                break;
            }
            match space.read_c_string(str_va, MAX_NAME_LEN) {
                Some(name) => push_unique(&mut out, name),
                None => break,
            }
        }
    }

    if out.is_empty() {
        scan_source_strings(space, &mut out);
    }
    out
}

fn push_unique(out: &mut Vec<String>, value: String) {
    if !value.is_empty() && !out.contains(&value) && out.len() < MAX_SOURCE_FILES {
        out.push(value);
    }
}

fn scan_source_strings(space: &AddressSpace<'_>, out: &mut Vec<String>) {
    for sec in &space.sections {
        if !sec.readable {
            continue;
        }
        let mut start: usize = 0;
        for (idx, &byte) in sec.data.iter().enumerate() {
            if byte != 0 {
                continue;
            }
            if idx > start
                && let Ok(text) = std::str::from_utf8(&sec.data[start..idx])
            {
                let trimmed: &str = text.trim();
                if trimmed.len() <= MAX_NAME_LEN
                    && SOURCE_SUFFIXES
                        .iter()
                        .any(|suf: &&str| trimmed.ends_with(suf))
                    && is_plausible_source_name(trimmed)
                {
                    push_unique(out, trimmed.to_owned());
                }
            }
            start = idx + 1;
        }
    }
}

fn is_plausible_source_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name.chars().all(|c: char| {
            c.is_ascii_alphanumeric()
                || matches!(c, '.' | '_' | '-' | '/' | '\\' | '<' | '>' | ':' | ' ')
        })
}

fn filetable_address(file: &ObjFile<'_>) -> Option<u64> {
    file.symbols()
        .find(|sym| sym.name().is_ok_and(|n: &str| n == FILETABLE_SYMBOL))
        .map(|sym| sym.address())
}

fn has_section_named(file: &ObjFile<'_>, name: &str) -> bool {
    file.sections()
        .any(|sec| sec.name().is_ok_and(|n: &str| n == name))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn signature_extraction_reads_first_line() {
        let (sig, qual): (Option<String>, Option<String>) =
            extract_signature(Some("greet(name, count=1) -> str\n\nBody."));
        assert_eq!(sig.as_deref(), Some("greet(name, count=1) -> str"));
        assert_eq!(qual, None);
        let (sig2, qual2): (Option<String>, Option<String>) = extract_signature(Some(
            "Accumulator.accumulate(self, amount) -> long\n\nBody.",
        ));
        assert_eq!(qual2.as_deref(), Some("Accumulator.accumulate"));
        assert!(sig2.is_some());
        assert_eq!(extract_signature(Some("just prose, no call")), (None, None));
        assert_eq!(extract_signature(None), (None, None));
    }

    #[test]
    fn demangle_length_prefixed_names() {
        assert_eq!(
            demangle_qualified_name("3mod_Accumulator").as_deref(),
            Some("Accumulator")
        );
        assert_eq!(
            demangle_qualified_name("6elfmod_Foo").as_deref(),
            Some("Foo")
        );
        assert_eq!(
            demangle_qualified_name("plainname").as_deref(),
            Some("plainname")
        );
    }

    #[test]
    fn flag_and_identifier_validation() {
        assert!(valid_flags(0x82));
        assert!(valid_flags(METH_VARARGS));
        assert!(!valid_flags(0));
        assert!(!valid_flags(0x1000));
        assert!(!valid_flags(METH_FLAG_MASK & !METH_CALLCONV_MASK));
        assert!(is_valid_identifier("greet"));
        assert!(is_valid_identifier("__reduce_cython__"));
        assert!(!is_valid_identifier("1bad"));
        assert!(!is_valid_identifier("has space"));
        assert!(!is_valid_identifier(""));
    }

    #[test]
    fn module_name_from_init_rejects_junk() {
        assert_eq!(module_name_from_init(b"PyInit_mod").as_deref(), Some("mod"));
        assert_eq!(
            module_name_from_init(b"PyInitU_pkg_sub").as_deref(),
            Some("pkg_sub")
        );
        assert_eq!(module_name_from_init(b"malloc"), None);
        assert_eq!(module_name_from_init(b"PyInit_"), None);
        assert_eq!(module_name_from_init(b"PyInit_bad.name"), None);
    }

    struct ElfImage {
        rodata: Vec<u8>,
        rodata_base: u64,
    }

    impl ElfImage {
        fn new() -> Self {
            Self {
                rodata: Vec::new(),
                rodata_base: 0x2000,
            }
        }

        fn intern(&mut self, text: &[u8]) -> u64 {
            let va: u64 = self.rodata_base + self.rodata.len() as u64;
            self.rodata.extend_from_slice(text);
            self.rodata.push(0);
            va
        }
    }

    fn push_u16(buf: &mut Vec<u8>, v: u16) {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    fn push_u32(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    fn push_u64(buf: &mut Vec<u8>, v: u64) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    fn method_def_bytes(name_va: u64, meth_va: u64, flags: u32, doc_va: u64) -> Vec<u8> {
        let mut rec: Vec<u8> = Vec::with_capacity(32);
        push_u64(&mut rec, name_va);
        push_u64(&mut rec, meth_va);
        push_u32(&mut rec, flags);
        push_u32(&mut rec, 0);
        push_u64(&mut rec, doc_va);
        rec
    }

    fn build_min_elf(bad_meth_pointer: bool) -> Vec<u8> {
        let mut img: ElfImage = ElfImage::new();
        let text_base: u64 = 0x1000;
        let data_base: u64 = 0x3000;
        let meth_va: u64 = if bad_meth_pointer {
            0xdead_0000
        } else {
            text_base
        };

        let foo_name: u64 = img.intern(b"foo");
        let foo_doc: u64 = img.intern(b"foo(x, y) -> int\n\nCompute foo.");
        let bar_name: u64 = img.intern(b"bar");
        let bar_doc: u64 = img.intern(b"bar(a) -> int\n\nCompute bar.");
        let src_name: u64 = img.intern(b"elfmod.pyx");
        let _marker: u64 = img.intern(b"__pyx_marker");

        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&method_def_bytes(foo_name, meth_va, 0x82, foo_doc));
        data.extend_from_slice(&[0u8; 32]);
        data.extend_from_slice(&method_def_bytes(bar_name, meth_va, 0x82, bar_doc));
        let filetable_va: u64 = data_base + data.len() as u64;
        push_u64(&mut data, src_name);
        push_u64(&mut data, 0);

        let methods_va: u64 = data_base;
        let mdef_va: u64 = data_base + 64;

        let text: Vec<u8> = vec![0x90u8; 16];

        let mut strtab: Vec<u8> = vec![0u8];
        let mut sym_names: Vec<(String, u64, u16)> = Vec::new();
        let data_shndx: u16 = 3;
        let text_shndx: u16 = 1;
        sym_names.push(("PyInit_elfmod".to_owned(), text_base, text_shndx));
        sym_names.push((
            "__pyx_methods_6elfmod_Foo".to_owned(),
            methods_va,
            data_shndx,
        ));
        sym_names.push(("__pyx_mdef_6elfmod_3bar".to_owned(), mdef_va, data_shndx));
        sym_names.push(("__pyx_f".to_owned(), filetable_va, data_shndx));

        let mut symtab: Vec<u8> = vec![0u8; 24];
        for (name, value, shndx) in &sym_names {
            let name_off: u32 = strtab.len() as u32;
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
            push_u32(&mut symtab, name_off);
            symtab.push((1 << 4) | 2);
            symtab.push(0);
            push_u16(&mut symtab, *shndx);
            push_u64(&mut symtab, *value);
            push_u64(&mut symtab, 0);
        }

        let mut shstr: Vec<u8> = vec![0u8];
        let name_off = |s: &mut Vec<u8>, n: &str| -> u32 {
            let off: u32 = s.len() as u32;
            s.extend_from_slice(n.as_bytes());
            s.push(0);
            off
        };
        let n_text: u32 = name_off(&mut shstr, ".text");
        let n_rodata: u32 = name_off(&mut shstr, ".rodata");
        let n_data: u32 = name_off(&mut shstr, ".data");
        let n_symtab: u32 = name_off(&mut shstr, ".symtab");
        let n_strtab: u32 = name_off(&mut shstr, ".strtab");
        let n_shstr: u32 = name_off(&mut shstr, ".shstrtab");

        let header_len: u64 = 64;
        let text_off: u64 = header_len;
        let rodata_off: u64 = text_off + text.len() as u64;
        let data_off: u64 = rodata_off + img.rodata.len() as u64;
        let strtab_off: u64 = data_off + data.len() as u64;
        let symtab_off: u64 = strtab_off + strtab.len() as u64;
        let shstr_off: u64 = symtab_off + symtab.len() as u64;
        let shoff: u64 = shstr_off + shstr.len() as u64;

        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
        out.extend_from_slice(&[0u8; 8]);
        push_u16(&mut out, 3);
        push_u16(&mut out, 62);
        push_u32(&mut out, 1);
        push_u64(&mut out, 0);
        push_u64(&mut out, 0);
        push_u64(&mut out, shoff);
        push_u32(&mut out, 0);
        push_u16(&mut out, 64);
        push_u16(&mut out, 0);
        push_u16(&mut out, 0);
        push_u16(&mut out, 64);
        push_u16(&mut out, 7);
        push_u16(&mut out, 6);

        out.extend_from_slice(&text);
        out.extend_from_slice(&img.rodata);
        out.extend_from_slice(&data);
        out.extend_from_slice(&strtab);
        out.extend_from_slice(&symtab);
        out.extend_from_slice(&shstr);

        let sht_progbits: u32 = 1;
        let sht_symtab: u32 = 2;
        let sht_strtab: u32 = 3;
        let shf_alloc: u64 = 2;
        let shf_exec: u64 = 4;
        let shf_write: u64 = 1;

        let mut sh = |name: u32,
                      typ: u32,
                      flags: u64,
                      addr: u64,
                      off: u64,
                      size: u64,
                      link: u32,
                      info: u32,
                      entsize: u64| {
            push_u32(&mut out, name);
            push_u32(&mut out, typ);
            push_u64(&mut out, flags);
            push_u64(&mut out, addr);
            push_u64(&mut out, off);
            push_u64(&mut out, size);
            push_u32(&mut out, link);
            push_u32(&mut out, info);
            push_u64(&mut out, 8);
            push_u64(&mut out, entsize);
        };
        sh(0, 0, 0, 0, 0, 0, 0, 0, 0);
        sh(
            n_text,
            sht_progbits,
            shf_alloc | shf_exec,
            text_base,
            text_off,
            text.len() as u64,
            0,
            0,
            0,
        );
        sh(
            n_rodata,
            sht_progbits,
            shf_alloc,
            img.rodata_base,
            rodata_off,
            img.rodata.len() as u64,
            0,
            0,
            0,
        );
        sh(
            n_data,
            sht_progbits,
            shf_alloc | shf_write,
            data_base,
            data_off,
            data.len() as u64,
            0,
            0,
            0,
        );
        sh(
            n_symtab,
            sht_symtab,
            0,
            0,
            symtab_off,
            symtab.len() as u64,
            5,
            1,
            24,
        );
        sh(
            n_strtab,
            sht_strtab,
            0,
            0,
            strtab_off,
            strtab.len() as u64,
            0,
            0,
            0,
        );
        sh(
            n_shstr,
            sht_strtab,
            0,
            0,
            shstr_off,
            shstr.len() as u64,
            0,
            0,
            0,
        );

        out
    }

    #[test]
    fn recovers_from_hand_built_elf() {
        let bytes: Vec<u8> = build_min_elf(false);
        let identity: CythonIdentity = detect_cython(&bytes).expect("elf detected as cython");
        assert_eq!(identity.module_name, "elfmod");
        assert_eq!(identity.init_symbol, "PyInit_elfmod");
        assert!(identity.pyx_symbols_present);

        let module: CythonModule = recover_cython(&bytes).expect("recover elf");
        assert_eq!(module.module_name, "elfmod");
        let foo: &CythonFunction = module
            .functions
            .iter()
            .find(|f: &&CythonFunction| f.name == "foo")
            .expect("foo recovered");
        assert_eq!(foo.doc.as_deref(), Some("foo(x, y) -> int\n\nCompute foo."));
        assert_eq!(foo.signature.as_deref(), Some("foo(x, y) -> int"));
        assert!(
            module
                .functions
                .iter()
                .any(|f: &CythonFunction| f.name == "bar")
        );
        assert!(module.classes.iter().any(|c: &CythonClass| c.name == "Foo"));
        assert!(
            module
                .source_files
                .iter()
                .any(|s: &String| s == "elfmod.pyx")
        );
        assert!(!module.has_debug_line);
    }

    #[test]
    fn rejects_method_def_with_pointer_outside_executable_section() {
        let bytes: Vec<u8> = build_min_elf(true);
        let module: CythonModule = recover_cython(&bytes).expect("recover elf");
        assert!(
            module.functions.is_empty(),
            "a meth pointer outside any executable section must be rejected"
        );
    }

    fn rela_entry(offset: u64, sym: u32, r_type: u32, addend: i64) -> Vec<u8> {
        let mut rec: Vec<u8> = Vec::with_capacity(24);
        push_u64(&mut rec, offset);
        push_u64(&mut rec, (u64::from(sym) << 32) | u64::from(r_type));
        rec.extend_from_slice(&addend.to_le_bytes());
        rec
    }

    fn sym_entry(name_off: u32, info: u8, shndx: u16, value: u64) -> Vec<u8> {
        let mut rec: Vec<u8> = Vec::with_capacity(24);
        push_u32(&mut rec, name_off);
        rec.push(info);
        rec.push(0);
        push_u16(&mut rec, shndx);
        push_u64(&mut rec, value);
        push_u64(&mut rec, 0);
        rec
    }

    fn build_reloc_elf() -> Vec<u8> {
        const R_X86_64_64: u32 = 1;
        const R_X86_64_RELATIVE: u32 = 8;
        let text_base: u64 = 0x1000;
        let data_base: u64 = 0x3000;

        let mut img: ElfImage = ElfImage::new();
        let foo_name: u64 = img.intern(b"foo");
        let foo_doc: u64 = img.intern(b"foo(x, y) -> int\n\nCompute foo.");
        let bar_name: u64 = img.intern(b"bar");
        let bar_doc: u64 = img.intern(b"bar(a) -> int\n\nCompute bar.");
        let src_name: u64 = img.intern(b"relocmod.pyx");
        let _marker: u64 = img.intern(b"__pyx_reloc_marker");

        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&method_def_bytes(0, 0, 0x0001, 0));
        data.extend_from_slice(&method_def_bytes(0, 0, 0x0001, 0));
        data.extend_from_slice(&[0u8; 32]);
        let filetable_va: u64 = data_base + data.len() as u64;
        push_u64(&mut data, 0);
        push_u64(&mut data, 0);

        let text: Vec<u8> = vec![0x90u8; 16];

        let mut dynstr: Vec<u8> = vec![0u8];
        let foo_impl_name: u32 = dynstr.len() as u32;
        dynstr.extend_from_slice(b"foo_impl");
        dynstr.push(0);

        let mut dynsym: Vec<u8> = sym_entry(0, 0, 0, 0);
        dynsym.extend_from_slice(&sym_entry(foo_impl_name, (1 << 4) | 2, 1, text_base));

        let mut rela: Vec<u8> = Vec::new();
        rela.extend_from_slice(&rela_entry(
            data_base,
            0,
            R_X86_64_RELATIVE,
            foo_name as i64,
        ));
        rela.extend_from_slice(&rela_entry(data_base + 8, 1, R_X86_64_64, 0));
        rela.extend_from_slice(&rela_entry(
            data_base + 24,
            0,
            R_X86_64_RELATIVE,
            foo_doc as i64,
        ));
        rela.extend_from_slice(&rela_entry(
            data_base + 32,
            0,
            R_X86_64_RELATIVE,
            bar_name as i64,
        ));
        rela.extend_from_slice(&rela_entry(data_base + 40, 1, R_X86_64_64, 0));
        rela.extend_from_slice(&rela_entry(
            data_base + 56,
            0,
            R_X86_64_RELATIVE,
            bar_doc as i64,
        ));
        rela.extend_from_slice(&rela_entry(
            filetable_va,
            0,
            R_X86_64_RELATIVE,
            src_name as i64,
        ));

        let mut strtab: Vec<u8> = vec![0u8];
        let pyinit_name: u32 = strtab.len() as u32;
        strtab.extend_from_slice(b"PyInit_relocmod");
        strtab.push(0);
        let mdef_name: u32 = strtab.len() as u32;
        strtab.extend_from_slice(b"__pyx_mdef_8relocmod_3foo");
        strtab.push(0);
        let filetable_sym: u32 = strtab.len() as u32;
        strtab.extend_from_slice(b"__pyx_f");
        strtab.push(0);

        let mut symtab: Vec<u8> = sym_entry(0, 0, 0, 0);
        symtab.extend_from_slice(&sym_entry(pyinit_name, (1 << 4) | 2, 1, text_base));
        symtab.extend_from_slice(&sym_entry(mdef_name, (1 << 4) | 1, 3, data_base));
        symtab.extend_from_slice(&sym_entry(filetable_sym, (1 << 4) | 1, 3, filetable_va));

        let mut shstr: Vec<u8> = vec![0u8];
        let name_off = |s: &mut Vec<u8>, n: &str| -> u32 {
            let off: u32 = s.len() as u32;
            s.extend_from_slice(n.as_bytes());
            s.push(0);
            off
        };
        let n_text: u32 = name_off(&mut shstr, ".text");
        let n_rodata: u32 = name_off(&mut shstr, ".rodata");
        let n_data: u32 = name_off(&mut shstr, ".data");
        let n_dynsym: u32 = name_off(&mut shstr, ".dynsym");
        let n_dynstr: u32 = name_off(&mut shstr, ".dynstr");
        let n_rela: u32 = name_off(&mut shstr, ".rela.dyn");
        let n_symtab: u32 = name_off(&mut shstr, ".symtab");
        let n_strtab: u32 = name_off(&mut shstr, ".strtab");
        let n_shstr: u32 = name_off(&mut shstr, ".shstrtab");

        let header_len: u64 = 64;
        let text_off: u64 = header_len;
        let rodata_off: u64 = text_off + text.len() as u64;
        let data_off: u64 = rodata_off + img.rodata.len() as u64;
        let dynsym_off: u64 = data_off + data.len() as u64;
        let dynstr_off: u64 = dynsym_off + dynsym.len() as u64;
        let rela_off: u64 = dynstr_off + dynstr.len() as u64;
        let symtab_off: u64 = rela_off + rela.len() as u64;
        let strtab_off: u64 = symtab_off + symtab.len() as u64;
        let shstr_off: u64 = strtab_off + strtab.len() as u64;
        let shoff: u64 = shstr_off + shstr.len() as u64;

        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
        out.extend_from_slice(&[0u8; 8]);
        push_u16(&mut out, 3);
        push_u16(&mut out, 62);
        push_u32(&mut out, 1);
        push_u64(&mut out, 0);
        push_u64(&mut out, 0);
        push_u64(&mut out, shoff);
        push_u32(&mut out, 0);
        push_u16(&mut out, 64);
        push_u16(&mut out, 0);
        push_u16(&mut out, 0);
        push_u16(&mut out, 64);
        push_u16(&mut out, 10);
        push_u16(&mut out, 9);

        out.extend_from_slice(&text);
        out.extend_from_slice(&img.rodata);
        out.extend_from_slice(&data);
        out.extend_from_slice(&dynsym);
        out.extend_from_slice(&dynstr);
        out.extend_from_slice(&rela);
        out.extend_from_slice(&symtab);
        out.extend_from_slice(&strtab);
        out.extend_from_slice(&shstr);

        let sht_progbits: u32 = 1;
        let sht_symtab: u32 = 2;
        let sht_strtab: u32 = 3;
        let sht_rela: u32 = 4;
        let sht_dynsym: u32 = 11;
        let shf_alloc: u64 = 2;
        let shf_exec: u64 = 4;
        let shf_write: u64 = 1;

        let mut sh = |name: u32,
                      typ: u32,
                      flags: u64,
                      addr: u64,
                      off: u64,
                      size: u64,
                      link: u32,
                      info: u32,
                      entsize: u64| {
            push_u32(&mut out, name);
            push_u32(&mut out, typ);
            push_u64(&mut out, flags);
            push_u64(&mut out, addr);
            push_u64(&mut out, off);
            push_u64(&mut out, size);
            push_u32(&mut out, link);
            push_u32(&mut out, info);
            push_u64(&mut out, 8);
            push_u64(&mut out, entsize);
        };
        sh(0, 0, 0, 0, 0, 0, 0, 0, 0);
        sh(
            n_text,
            sht_progbits,
            shf_alloc | shf_exec,
            text_base,
            text_off,
            text.len() as u64,
            0,
            0,
            0,
        );
        sh(
            n_rodata,
            sht_progbits,
            shf_alloc,
            img.rodata_base,
            rodata_off,
            img.rodata.len() as u64,
            0,
            0,
            0,
        );
        sh(
            n_data,
            sht_progbits,
            shf_alloc | shf_write,
            data_base,
            data_off,
            data.len() as u64,
            0,
            0,
            0,
        );
        sh(
            n_dynsym,
            sht_dynsym,
            0,
            0,
            dynsym_off,
            dynsym.len() as u64,
            5,
            1,
            24,
        );
        sh(
            n_dynstr,
            sht_strtab,
            0,
            0,
            dynstr_off,
            dynstr.len() as u64,
            0,
            0,
            0,
        );
        sh(
            n_rela,
            sht_rela,
            0,
            0,
            rela_off,
            rela.len() as u64,
            4,
            3,
            24,
        );
        sh(
            n_symtab,
            sht_symtab,
            0,
            0,
            symtab_off,
            symtab.len() as u64,
            8,
            1,
            24,
        );
        sh(
            n_strtab,
            sht_strtab,
            0,
            0,
            strtab_off,
            strtab.len() as u64,
            0,
            0,
            0,
        );
        sh(
            n_shstr,
            sht_strtab,
            0,
            0,
            shstr_off,
            shstr.len() as u64,
            0,
            0,
            0,
        );

        out
    }

    #[test]
    fn recovers_from_hand_built_elf_via_dynamic_relocations() {
        let bytes: Vec<u8> = build_reloc_elf();

        let identity: CythonIdentity = detect_cython(&bytes).expect("reloc elf detected as cython");
        assert_eq!(identity.module_name, "relocmod");
        assert_eq!(identity.init_symbol, "PyInit_relocmod");

        let module: CythonModule = recover_cython(&bytes).expect("recover reloc elf");
        assert_eq!(module.module_name, "relocmod");

        let foo: &CythonFunction = module
            .functions
            .iter()
            .find(|f: &&CythonFunction| f.name == "foo")
            .expect("foo recovered through R_X86_64_RELATIVE and R_X86_64_64 dynamic relocations");
        assert_eq!(foo.doc.as_deref(), Some("foo(x, y) -> int\n\nCompute foo."));
        assert_eq!(foo.signature.as_deref(), Some("foo(x, y) -> int"));

        let bar: &CythonFunction = module
            .functions
            .iter()
            .find(|f: &&CythonFunction| f.name == "bar")
            .expect("bar recovered through dynamic relocations");
        assert_eq!(bar.doc.as_deref(), Some("bar(a) -> int\n\nCompute bar."));

        assert!(
            module
                .source_files
                .iter()
                .any(|s: &String| s == "relocmod.pyx")
        );
    }

    #[test]
    fn malformed_and_random_inputs_never_panic() {
        assert!(detect_cython(b"").is_none());
        assert!(detect_cython(b"not an object at all").is_none());
        assert!(recover_cython(b"").is_err());
        let mut seed: u64 = 0x1234_5678_9abc_def0;
        for len in [8usize, 64, 300, 4096] {
            let mut buf: Vec<u8> = Vec::with_capacity(len);
            for _ in 0..len {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                buf.push((seed >> 33) as u8);
            }
            let _ = detect_cython(&buf);
            let _ = recover_cython(&buf);
        }
        let mut elf: Vec<u8> = build_min_elf(false);
        for cut in (0..elf.len()).step_by(7) {
            let _ = recover_cython(&elf[..cut]);
        }
        for i in (0..elf.len()).step_by(11) {
            elf[i] ^= 0xff;
        }
        let _ = recover_cython(&elf);
    }
}
