use std::collections::{BTreeMap, BTreeSet};

use object::RelocationTarget;
use object::read::{Object, ObjectSection, ObjectSymbol, ObjectSymbolTable};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CxxAbi {
    Itanium,
    Msvc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CxxDemangled {
    pub mangled: String,
    pub demangled: String,
    pub abi: CxxAbi,
}

pub fn demangle_itanium(mangled: &str) -> Result<CxxDemangled> {
    let sym: cpp_demangle::Symbol<&str> =
        cpp_demangle::Symbol::new(mangled).map_err(|e: cpp_demangle::error::Error| {
            Error::Demangle {
                lang: "itanium-cxx",
                message: e.to_string(),
            }
        })?;
    let demangled: String = sym
        .demangle()
        .map_err(|e: std::fmt::Error| Error::Demangle {
            lang: "itanium-cxx",
            message: e.to_string(),
        })?;
    Ok(CxxDemangled {
        mangled: mangled.to_owned(),
        demangled,
        abi: CxxAbi::Itanium,
    })
}

pub fn demangle_msvc(mangled: &str) -> Result<CxxDemangled> {
    let demangled: String =
        msvc_demangler::demangle(mangled, msvc_demangler::DemangleFlags::llvm()).map_err(
            |e: msvc_demangler::Error| Error::Demangle {
                lang: "msvc-cxx",
                message: e.to_string(),
            },
        )?;
    Ok(CxxDemangled {
        mangled: mangled.to_owned(),
        demangled,
        abi: CxxAbi::Msvc,
    })
}

pub fn demangle_auto(mangled: &str) -> Result<CxxDemangled> {
    if mangled.starts_with('?') {
        demangle_msvc(mangled)
    } else {
        demangle_itanium(mangled)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RttiEntry {
    pub class_name: String,
    pub base_classes: Vec<String>,
    pub vtable_address: u64,
}

#[must_use]
pub fn recover_itanium_rtti(symbols: &[&str]) -> Vec<RttiEntry> {
    let mut by_class: BTreeMap<String, RttiEntry> = BTreeMap::new();
    for (i, s) in symbols.iter().enumerate() {
        if !(s.starts_with("_ZTV") || s.starts_with("_ZTI") || s.starts_with("_ZTS")) {
            continue;
        }
        let class_part: &str = &s[4..];
        let entry: &mut RttiEntry =
            by_class
                .entry(class_part.to_owned())
                .or_insert_with(|| RttiEntry {
                    class_name: class_part.to_owned(),
                    base_classes: Vec::new(),
                    vtable_address: 0,
                });
        if s.starts_with("_ZTV") {
            entry.vtable_address = i as u64;
        }
    }
    by_class.into_values().collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CxxInheritance {
    None,
    Single,
    Multiple,
    Virtual,
    MultipleVirtual,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CxxBaseLink {
    pub name: String,
    pub offset: i64,
    pub is_virtual: bool,
    pub is_public: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CxxVtableSlot {
    pub index: usize,
    pub function_address: u64,
    pub symbol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CxxVtable {
    pub address: u64,
    pub slot_count: usize,
    pub slots: Vec<CxxVtableSlot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CxxClass {
    pub name: String,
    pub mangled_name: String,
    pub inheritance: CxxInheritance,
    pub direct_bases: Vec<CxxBaseLink>,
    pub all_bases: Vec<String>,
    pub vtable: Option<CxxVtable>,
    pub stl_templates: Vec<StlTemplate>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StlTemplate {
    String,
    Vector,
    SharedPtr,
    UniquePtr,
    Map,
    UnorderedMap,
    Set,
    List,
    Pair,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CxxHierarchy {
    pub abi: CxxAbi,
    pub classes: Vec<CxxClass>,
}

impl CxxHierarchy {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty()
    }

    #[must_use]
    pub fn class(&self, name: &str) -> Option<&CxxClass> {
        self.classes.iter().find(|c: &&CxxClass| c.name == name)
    }
}

#[must_use]
pub fn recover_cxx_hierarchy(bytes: &[u8]) -> Option<CxxHierarchy> {
    let file: object::File<'_> = object::File::parse(bytes).ok()?;
    let hierarchy: CxxHierarchy = match file.format() {
        object::BinaryFormat::Pe => recover_msvc_hierarchy(&file)?,
        object::BinaryFormat::Elf => recover_itanium_hierarchy(&file)?,
        _ => return None,
    };
    if hierarchy.is_empty() {
        return None;
    }
    Some(hierarchy)
}

#[must_use]
pub fn detect_stl_templates(demangled: &str) -> Vec<StlTemplate> {
    const PATTERNS: [(&str, StlTemplate); 11] = [
        ("std::basic_string", StlTemplate::String),
        ("std::__cxx11::basic_string", StlTemplate::String),
        ("std::string", StlTemplate::String),
        ("std::vector", StlTemplate::Vector),
        ("std::shared_ptr", StlTemplate::SharedPtr),
        ("std::unique_ptr", StlTemplate::UniquePtr),
        ("std::unordered_map", StlTemplate::UnorderedMap),
        ("std::map", StlTemplate::Map),
        ("std::set", StlTemplate::Set),
        ("std::list", StlTemplate::List),
        ("std::pair", StlTemplate::Pair),
    ];
    let mut found: BTreeSet<StlTemplate> = BTreeSet::new();
    for (needle, tag) in PATTERNS {
        if demangled.contains(needle) {
            if matches!(tag, StlTemplate::Map)
                && demangled.contains("std::unordered_map")
                && !demangled.contains("std::map")
            {
                continue;
            }
            found.insert(tag);
        }
    }
    found.into_iter().collect()
}

impl PartialOrd for StlTemplate {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for StlTemplate {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (*self as u8).cmp(&(*other as u8))
    }
}

const ITANIUM_BASE_OFFSET_SHIFT: u32 = 8;
const ITANIUM_BASE_PUBLIC: i64 = 0x2;
const ITANIUM_BASE_VIRTUAL: i64 = 0x1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ItaniumKind {
    Base,
    Single,
    Vmi,
}

struct ItaniumTypeInfo {
    name: String,
    kind: ItaniumKind,
    bases: Vec<CxxBaseLink>,
}

fn recover_itanium_hierarchy(file: &object::File<'_>) -> Option<CxxHierarchy> {
    let typeinfo_addrs: BTreeMap<u64, String> = file
        .dynamic_symbols()
        .chain(file.symbols())
        .filter_map(|sym| {
            let name: &str = sym.name().ok()?;
            if !name.starts_with("_ZTI") {
                return None;
            }
            let addr: u64 = sym.address();
            if addr == 0 && !sym.is_definition() {
                return None;
            }
            Some((addr, name.to_owned()))
        })
        .collect();
    if typeinfo_addrs.is_empty() {
        return None;
    }
    let relocs: BTreeMap<u64, String> = collect_pointer_relocations(file);
    let vtables: BTreeMap<String, u64> = file
        .dynamic_symbols()
        .chain(file.symbols())
        .filter_map(|sym| {
            let name: &str = sym.name().ok()?;
            let class: &str = name.strip_prefix("_ZTV")?;
            Some((class.to_owned(), sym.address()))
        })
        .collect();
    let func_syms: BTreeMap<u64, String> = function_symbols(file);

    let mut classes: Vec<CxxClass> = Vec::new();
    for (addr, mangled) in &typeinfo_addrs {
        let Some(info): Option<ItaniumTypeInfo> =
            parse_itanium_typeinfo(file, *addr, &relocs, &typeinfo_addrs)
        else {
            continue;
        };
        let inheritance: CxxInheritance = itanium_inheritance(&info);
        let all_bases: Vec<String> = transitive_bases(&info.name, &info.bases, &classes);
        let class_token: &str = mangled.strip_prefix("_ZTI").unwrap_or(mangled);
        let vtable: Option<CxxVtable> = vtables.get(class_token).and_then(|vt_addr: &u64| {
            bind_itanium_vtable(file, *vt_addr, *addr, mangled, &relocs, &func_syms)
        });
        let stl_templates: Vec<StlTemplate> = detect_stl_templates(&info.name);
        classes.push(CxxClass {
            name: info.name,
            mangled_name: mangled.clone(),
            inheritance,
            direct_bases: info.bases,
            all_bases,
            vtable,
            stl_templates,
        });
    }
    classes.sort_by(|a: &CxxClass, b: &CxxClass| a.name.cmp(&b.name));
    Some(CxxHierarchy {
        abi: CxxAbi::Itanium,
        classes,
    })
}

fn itanium_inheritance(info: &ItaniumTypeInfo) -> CxxInheritance {
    match info.kind {
        ItaniumKind::Base => CxxInheritance::None,
        ItaniumKind::Single => {
            if info
                .bases
                .first()
                .is_some_and(|b: &CxxBaseLink| b.is_virtual)
            {
                CxxInheritance::Virtual
            } else {
                CxxInheritance::Single
            }
        }
        ItaniumKind::Vmi => {
            let any_virtual: bool = info.bases.iter().any(|b: &CxxBaseLink| b.is_virtual);
            if info.bases.len() > 1 {
                if any_virtual {
                    CxxInheritance::MultipleVirtual
                } else {
                    CxxInheritance::Multiple
                }
            } else if any_virtual {
                CxxInheritance::Virtual
            } else {
                CxxInheritance::Single
            }
        }
    }
}

fn parse_itanium_typeinfo(
    file: &object::File<'_>,
    addr: u64,
    relocs: &BTreeMap<u64, String>,
    typeinfo_addrs: &BTreeMap<u64, String>,
) -> Option<ItaniumTypeInfo> {
    let mangled: &str = typeinfo_addrs.get(&addr)?;
    let class_token: &str = mangled.strip_prefix("_ZTI").unwrap_or(mangled);
    let name: String =
        demangle_itanium_type(class_token).unwrap_or_else(|| format!("_ZTS{class_token}"));
    let kind: ItaniumKind = classify_itanium_kind(relocs, addr);
    let bases: Vec<CxxBaseLink> = match kind {
        ItaniumKind::Base => Vec::new(),
        ItaniumKind::Single => {
            let base_ptr_addr: u64 = addr.checked_add(16)?;
            let base_name: Option<String> =
                resolve_typeinfo_ref(file, base_ptr_addr, relocs, typeinfo_addrs);
            base_name
                .map(|n: String| CxxBaseLink {
                    name: n,
                    offset: 0,
                    is_virtual: false,
                    is_public: true,
                })
                .into_iter()
                .collect()
        }
        ItaniumKind::Vmi => parse_itanium_vmi_bases(file, addr, relocs, typeinfo_addrs)?,
    };
    Some(ItaniumTypeInfo { name, kind, bases })
}

fn parse_itanium_vmi_bases(
    file: &object::File<'_>,
    addr: u64,
    relocs: &BTreeMap<u64, String>,
    typeinfo_addrs: &BTreeMap<u64, String>,
) -> Option<Vec<CxxBaseLink>> {
    let flags_addr: u64 = addr.checked_add(16)?;
    let _flags: u32 = read_u32(file, flags_addr)?;
    let base_count: u32 = read_u32(file, flags_addr.checked_add(4)?)?;
    if base_count > 64 {
        return None;
    }
    let array_addr: u64 = flags_addr.checked_add(8)?;
    let mut bases: Vec<CxxBaseLink> = Vec::with_capacity(base_count as usize);
    for i in 0..base_count as u64 {
        let entry_addr: u64 = array_addr.checked_add(i.checked_mul(16)?)?;
        let base_name: Option<String> =
            resolve_typeinfo_ref(file, entry_addr, relocs, typeinfo_addrs);
        let Some(name): Option<String> = base_name else {
            continue;
        };
        let offset_flags: i64 = read_i64(file, entry_addr.checked_add(8)?)?;
        let is_virtual: bool = offset_flags & ITANIUM_BASE_VIRTUAL != 0;
        let is_public: bool = offset_flags & ITANIUM_BASE_PUBLIC != 0;
        let offset: i64 = offset_flags >> ITANIUM_BASE_OFFSET_SHIFT;
        bases.push(CxxBaseLink {
            name,
            offset,
            is_virtual,
            is_public,
        });
    }
    Some(bases)
}

fn classify_itanium_kind(relocs: &BTreeMap<u64, String>, addr: u64) -> ItaniumKind {
    match relocs.get(&addr) {
        Some(target) if target.contains("__vmi_class_type_info") => ItaniumKind::Vmi,
        Some(target) if target.contains("__si_class_type_info") => ItaniumKind::Single,
        Some(target) if target.contains("__class_type_info") => ItaniumKind::Base,
        _ => ItaniumKind::Base,
    }
}

fn resolve_typeinfo_ref(
    file: &object::File<'_>,
    at: u64,
    relocs: &BTreeMap<u64, String>,
    typeinfo_addrs: &BTreeMap<u64, String>,
) -> Option<String> {
    if let Some(target) = relocs.get(&at)
        && let Some(class) = target.strip_prefix("_ZTI")
    {
        return demangle_itanium_type(class).or_else(|| Some(class.to_owned()));
    }
    let inline: u64 = read_u64(file, at)?;
    if inline == 0 {
        return None;
    }
    let mangled: &str = typeinfo_addrs.get(&inline)?;
    let class: &str = mangled.strip_prefix("_ZTI").unwrap_or(mangled);
    demangle_itanium_type(class).or_else(|| Some(class.to_owned()))
}

fn bind_itanium_vtable(
    file: &object::File<'_>,
    vtable_addr: u64,
    typeinfo_addr: u64,
    typeinfo_symbol: &str,
    relocs: &BTreeMap<u64, String>,
    func_syms: &BTreeMap<u64, String>,
) -> Option<CxxVtable> {
    let typeinfo_slot: u64 =
        locate_itanium_typeinfo_slot(file, vtable_addr, typeinfo_addr, typeinfo_symbol, relocs)?;
    let first_method: u64 = typeinfo_slot.checked_add(8)?;
    let mut slots: Vec<CxxVtableSlot> = Vec::new();
    for i in 0..64u64 {
        let slot_addr: u64 = first_method.checked_add(i.checked_mul(8)?)?;
        let (func_addr, symbol): (u64, Option<String>) =
            match itanium_slot_target(file, slot_addr, relocs, func_syms) {
                Some(v) => v,
                None => break,
            };
        slots.push(CxxVtableSlot {
            index: i as usize,
            function_address: func_addr,
            symbol,
        });
    }
    if slots.is_empty() {
        return None;
    }
    Some(CxxVtable {
        address: first_method,
        slot_count: slots.len(),
        slots,
    })
}

fn locate_itanium_typeinfo_slot(
    file: &object::File<'_>,
    vtable_addr: u64,
    typeinfo_addr: u64,
    typeinfo_symbol: &str,
    relocs: &BTreeMap<u64, String>,
) -> Option<u64> {
    for i in 0..32u64 {
        let slot: u64 = vtable_addr.checked_add(i.checked_mul(8)?)?;
        if let Some(target) = relocs.get(&slot) {
            if target == typeinfo_symbol {
                return Some(slot);
            }
            continue;
        }
        if typeinfo_addr != 0 && read_u64(file, slot) == Some(typeinfo_addr) {
            return Some(slot);
        }
    }
    None
}

fn itanium_slot_target(
    file: &object::File<'_>,
    slot_addr: u64,
    relocs: &BTreeMap<u64, String>,
    func_syms: &BTreeMap<u64, String>,
) -> Option<(u64, Option<String>)> {
    if let Some(target) = relocs.get(&slot_addr) {
        if is_itanium_rtti_data_symbol(target) {
            return None;
        }
        let addr: u64 = func_syms
            .iter()
            .find_map(|(a, n): (&u64, &String)| (n == target).then_some(*a))
            .unwrap_or(0);
        return Some((addr, Some(target.clone())));
    }
    let inline: u64 = read_u64(file, slot_addr)?;
    if inline == 0 {
        return None;
    }
    if !addr_in_executable(file, inline) {
        return None;
    }
    let symbol: Option<String> = func_syms.get(&inline).cloned();
    Some((inline, symbol))
}

fn is_itanium_rtti_data_symbol(name: &str) -> bool {
    name.starts_with("_ZT")
        && matches!(
            name.as_bytes().get(3),
            Some(b'I' | b'S' | b'V' | b'T' | b'C')
        )
}

fn collect_pointer_relocations(file: &object::File<'_>) -> BTreeMap<u64, String> {
    let mut out: BTreeMap<u64, String> = BTreeMap::new();
    if let Some(dyn_relocs) = file.dynamic_relocations() {
        let dyn_table: Option<_> = file.dynamic_symbol_table();
        for (offset, reloc) in dyn_relocs {
            if let RelocationTarget::Symbol(idx) = reloc.target()
                && let Some(table) = dyn_table.as_ref()
                && let Ok(sym) = table.symbol_by_index(idx)
                && let Ok(name) = sym.name()
                && !name.is_empty()
            {
                out.entry(offset).or_insert_with(|| name.to_owned());
            }
        }
    }
    for section in file.sections() {
        for (offset, reloc) in section.relocations() {
            if let RelocationTarget::Symbol(idx) = reloc.target()
                && let Ok(sym) = file.symbol_by_index(idx)
                && let Ok(name) = sym.name()
                && !name.is_empty()
            {
                out.entry(offset).or_insert_with(|| name.to_owned());
            }
        }
    }
    out
}

fn function_symbols(file: &object::File<'_>) -> BTreeMap<u64, String> {
    file.dynamic_symbols()
        .chain(file.symbols())
        .filter_map(|sym| {
            if sym.kind() != object::SymbolKind::Text {
                return None;
            }
            let name: &str = sym.name().ok()?;
            if name.is_empty() {
                return None;
            }
            Some((sym.address(), name.to_owned()))
        })
        .collect()
}

fn transitive_bases(name: &str, direct: &[CxxBaseLink], known: &[CxxClass]) -> Vec<String> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut stack: Vec<String> = direct
        .iter()
        .map(|b: &CxxBaseLink| b.name.clone())
        .collect();
    while let Some(base) = stack.pop() {
        if base == name || !seen.insert(base.clone()) {
            continue;
        }
        if let Some(parent) = known.iter().find(|c: &&CxxClass| c.name == base) {
            for grand in &parent.direct_bases {
                stack.push(grand.name.clone());
            }
        }
    }
    seen.into_iter().collect()
}

fn demangle_itanium_type(class_token: &str) -> Option<String> {
    let synthetic: String = format!("_ZTS{class_token}");
    let sym: cpp_demangle::Symbol<&str> = cpp_demangle::Symbol::new(synthetic.as_str()).ok()?;
    let demangled: String = sym.demangle().ok()?;
    let trimmed: &str = demangled
        .strip_prefix("typeinfo name for ")
        .unwrap_or(&demangled);
    Some(trimmed.to_owned())
}

fn recover_msvc_hierarchy(file: &object::File<'_>) -> Option<CxxHierarchy> {
    let image_base: u64 = file.relative_address_base();
    let sections: Vec<MsvcSection> = msvc_sections(file);
    if sections.is_empty() {
        return None;
    }
    let is_64: bool = file.is_64();
    let descriptors: BTreeMap<u32, MsvcTypeDescriptor> = scan_type_descriptors(&sections);
    if descriptors.is_empty() {
        return None;
    }
    let locators: Vec<MsvcLocator> = scan_object_locators(&sections, &descriptors, is_64);
    if locators.is_empty() {
        return None;
    }
    let func_syms: BTreeMap<u64, String> = function_symbols(file);
    let mut by_class: BTreeMap<String, CxxClass> = BTreeMap::new();
    for locator in &locators {
        let Some(cls): Option<CxxClass> = build_msvc_class(&sections, &descriptors, locator) else {
            continue;
        };
        by_class.entry(cls.name.clone()).or_insert(cls);
    }
    bind_msvc_vtables(
        &sections,
        &locators,
        &mut by_class,
        image_base,
        is_64,
        &func_syms,
    );
    let classes: Vec<CxxClass> = by_class.into_values().collect();
    Some(CxxHierarchy {
        abi: CxxAbi::Msvc,
        classes,
    })
}

struct MsvcSection {
    rva: u32,
    data: Vec<u8>,
    executable: bool,
}

struct MsvcTypeDescriptor {
    name: String,
    demangled: String,
}

struct MsvcLocator {
    self_rva: u32,
    offset: u32,
    type_descriptor_rva: u32,
    hierarchy_rva: u32,
}

fn msvc_sections(file: &object::File<'_>) -> Vec<MsvcSection> {
    let image_base: u64 = file.relative_address_base();
    let mut out: Vec<MsvcSection> = Vec::new();
    for section in file.sections() {
        let Ok(data): core::result::Result<&[u8], object::Error> = section.data() else {
            continue;
        };
        if data.is_empty() {
            continue;
        }
        let rva: u64 = section.address().wrapping_sub(image_base);
        if rva > u64::from(u32::MAX) {
            continue;
        }
        let executable: bool = matches!(section.kind(), object::SectionKind::Text);
        out.push(MsvcSection {
            rva: rva as u32,
            data: data.to_vec(),
            executable,
        });
    }
    out
}

fn msvc_read_at(sections: &[MsvcSection], rva: u32, len: usize) -> Option<&[u8]> {
    for sec in sections {
        let end: u32 = sec.rva.checked_add(sec.data.len() as u32)?;
        if rva >= sec.rva && rva < end {
            let off: usize = (rva - sec.rva) as usize;
            let slice_end: usize = off.checked_add(len)?;
            if slice_end <= sec.data.len() {
                return Some(&sec.data[off..slice_end]);
            }
            return None;
        }
    }
    None
}

fn msvc_u32(sections: &[MsvcSection], rva: u32) -> Option<u32> {
    let b: &[u8] = msvc_read_at(sections, rva, 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn msvc_i32(sections: &[MsvcSection], rva: u32) -> Option<i32> {
    msvc_u32(sections, rva).map(|v: u32| v as i32)
}

fn msvc_cstr(sections: &[MsvcSection], rva: u32) -> Option<String> {
    for sec in sections {
        let end: u32 = sec.rva.wrapping_add(sec.data.len() as u32);
        if rva >= sec.rva && rva < end {
            let off: usize = (rva - sec.rva) as usize;
            let tail: &[u8] = &sec.data[off..];
            let stop: usize = tail.iter().position(|&c: &u8| c == 0)?;
            return Some(String::from_utf8_lossy(&tail[..stop]).into_owned());
        }
    }
    None
}

fn scan_type_descriptors(sections: &[MsvcSection]) -> BTreeMap<u32, MsvcTypeDescriptor> {
    let mut out: BTreeMap<u32, MsvcTypeDescriptor> = BTreeMap::new();
    for sec in sections {
        let data: &[u8] = &sec.data;
        let mut i: usize = 0;
        while i + 4 <= data.len() {
            if &data[i..i + 3] == b".?A" && (data[i + 3] == b'V' || data[i + 3] == b'U') {
                let name_rva: u32 = sec.rva.wrapping_add(i as u32);
                let td_rva: u32 = name_rva.wrapping_sub(16);
                if let Some(name) = msvc_cstr(sections, name_rva) {
                    let demangled: String =
                        demangle_msvc_type_descriptor(&name).unwrap_or_else(|| name.clone());
                    out.insert(td_rva, MsvcTypeDescriptor { name, demangled });
                }
                i += 4;
            } else {
                i += 1;
            }
        }
    }
    out
}

fn scan_object_locators(
    sections: &[MsvcSection],
    descriptors: &BTreeMap<u32, MsvcTypeDescriptor>,
    is_64: bool,
) -> Vec<MsvcLocator> {
    let mut out: Vec<MsvcLocator> = Vec::new();
    for sec in sections {
        let data: &[u8] = &sec.data;
        let stride: usize = 4;
        let mut off: usize = 0;
        while off + 24 <= data.len() {
            let cur_rva: u32 = sec.rva.wrapping_add(off as u32);
            if let Some(locator) = parse_object_locator(sections, cur_rva, descriptors, is_64) {
                out.push(locator);
            }
            off += stride;
        }
    }
    out
}

fn parse_object_locator(
    sections: &[MsvcSection],
    rva: u32,
    descriptors: &BTreeMap<u32, MsvcTypeDescriptor>,
    is_64: bool,
) -> Option<MsvcLocator> {
    let signature: u32 = msvc_u32(sections, rva)?;
    let expected_sig: u32 = u32::from(is_64);
    if signature != expected_sig {
        return None;
    }
    let offset: u32 = msvc_u32(sections, rva.checked_add(4)?)?;
    let type_descriptor_rva: u32 = msvc_u32(sections, rva.checked_add(12)?)?;
    let hierarchy_rva: u32 = msvc_u32(sections, rva.checked_add(16)?)?;
    if !descriptors.contains_key(&type_descriptor_rva) {
        return None;
    }
    if is_64 {
        let self_rva: u32 = msvc_u32(sections, rva.checked_add(20)?)?;
        if self_rva != rva {
            return None;
        }
    } else {
        let chd_sig: u32 = msvc_u32(sections, hierarchy_rva)?;
        if chd_sig != 0 {
            return None;
        }
    }
    Some(MsvcLocator {
        self_rva: rva,
        offset,
        type_descriptor_rva,
        hierarchy_rva,
    })
}

fn build_msvc_class(
    sections: &[MsvcSection],
    descriptors: &BTreeMap<u32, MsvcTypeDescriptor>,
    locator: &MsvcLocator,
) -> Option<CxxClass> {
    let td: &MsvcTypeDescriptor = descriptors.get(&locator.type_descriptor_rva)?;
    let attributes: u32 = msvc_u32(sections, locator.hierarchy_rva.checked_add(4)?)?;
    let num_bases: u32 = msvc_u32(sections, locator.hierarchy_rva.checked_add(8)?)?;
    if num_bases == 0 || num_bases > 1024 {
        return None;
    }
    let base_array_rva: u32 = msvc_u32(sections, locator.hierarchy_rva.checked_add(12)?)?;
    let entries: Vec<MsvcBaseEntry> =
        read_base_class_array(sections, descriptors, base_array_rva, num_bases)?;
    let direct_bases: Vec<CxxBaseLink> = msvc_direct_bases(&entries);
    let all_bases: Vec<String> = entries
        .iter()
        .skip(1)
        .map(|e: &MsvcBaseEntry| e.name.clone())
        .collect::<BTreeSet<String>>()
        .into_iter()
        .collect();
    let inheritance: CxxInheritance = msvc_inheritance(attributes, &direct_bases);
    let stl_templates: Vec<StlTemplate> = detect_stl_templates(&td.demangled);
    Some(CxxClass {
        name: td.demangled.clone(),
        mangled_name: td.name.clone(),
        inheritance,
        direct_bases,
        all_bases,
        vtable: None,
        stl_templates,
    })
}

struct MsvcBaseEntry {
    name: String,
    contained: u32,
    mdisp: i32,
    vdisp: i32,
    is_virtual: bool,
}

fn read_base_class_array(
    sections: &[MsvcSection],
    descriptors: &BTreeMap<u32, MsvcTypeDescriptor>,
    base_array_rva: u32,
    num_bases: u32,
) -> Option<Vec<MsvcBaseEntry>> {
    let mut out: Vec<MsvcBaseEntry> = Vec::with_capacity(num_bases as usize);
    for i in 0..num_bases {
        let bcd_rva: u32 = msvc_u32(sections, base_array_rva.checked_add(i.checked_mul(4)?)?)?;
        let td_rva: u32 = msvc_u32(sections, bcd_rva)?;
        let descriptor: &MsvcTypeDescriptor = descriptors.get(&td_rva)?;
        let contained: u32 = msvc_u32(sections, bcd_rva.checked_add(4)?)?;
        let mdisp: i32 = msvc_i32(sections, bcd_rva.checked_add(8)?)?;
        let pdisp: i32 = msvc_i32(sections, bcd_rva.checked_add(12)?)?;
        let vdisp: i32 = msvc_i32(sections, bcd_rva.checked_add(16)?)?;
        let is_virtual: bool = pdisp >= 0;
        out.push(MsvcBaseEntry {
            name: descriptor.demangled.clone(),
            contained,
            mdisp,
            vdisp,
            is_virtual,
        });
    }
    Some(out)
}

fn msvc_direct_bases(entries: &[MsvcBaseEntry]) -> Vec<CxxBaseLink> {
    let mut out: Vec<CxxBaseLink> = Vec::new();
    let mut i: usize = 1;
    while i < entries.len() {
        let entry: &MsvcBaseEntry = &entries[i];
        let offset: i64 = if entry.is_virtual {
            i64::from(entry.vdisp)
        } else {
            i64::from(entry.mdisp)
        };
        out.push(CxxBaseLink {
            name: entry.name.clone(),
            offset,
            is_virtual: entry.is_virtual,
            is_public: true,
        });
        i += 1 + entry.contained as usize;
    }
    out
}

fn msvc_inheritance(attributes: u32, direct_bases: &[CxxBaseLink]) -> CxxInheritance {
    let multiple: bool = attributes & 0x1 != 0;
    let virtual_inh: bool =
        attributes & 0x2 != 0 || direct_bases.iter().any(|b: &CxxBaseLink| b.is_virtual);
    match (direct_bases.len(), multiple, virtual_inh) {
        (0, _, _) => CxxInheritance::None,
        (_, true, true) => CxxInheritance::MultipleVirtual,
        (_, true, false) => CxxInheritance::Multiple,
        (_, false, true) => CxxInheritance::Virtual,
        (_, false, false) => CxxInheritance::Single,
    }
}

fn bind_msvc_vtables(
    sections: &[MsvcSection],
    locators: &[MsvcLocator],
    by_class: &mut BTreeMap<String, CxxClass>,
    image_base: u64,
    is_64: bool,
    func_syms: &BTreeMap<u64, String>,
) {
    if !is_64 {
        return;
    }
    let by_locator_rva: BTreeMap<u32, &MsvcLocator> = locators
        .iter()
        .map(|l: &MsvcLocator| (l.self_rva, l))
        .collect();
    let locator_va_to_rva: BTreeMap<u64, u32> = locators
        .iter()
        .map(|l: &MsvcLocator| (image_base.wrapping_add(u64::from(l.self_rva)), l.self_rva))
        .collect();
    let mut best: BTreeMap<String, (u32, CxxVtable)> = BTreeMap::new();
    for sec in sections {
        let data: &[u8] = &sec.data;
        let mut off: usize = 0;
        while off + 8 <= data.len() {
            let va: u64 = u64::from_le_bytes([
                data[off],
                data[off + 1],
                data[off + 2],
                data[off + 3],
                data[off + 4],
                data[off + 5],
                data[off + 6],
                data[off + 7],
            ]);
            if let Some(locator_rva) = locator_va_to_rva.get(&va)
                && let Some(locator) = by_locator_rva.get(locator_rva)
            {
                let vtable_rva: u32 = sec.rva.wrapping_add(off as u32).wrapping_add(8);
                if let Some(vtable) =
                    bind_msvc_vtable_slots(sections, vtable_rva, image_base, func_syms)
                    && let Some(td_name) = msvc_class_name_for_locator(locator, sections)
                {
                    let candidate: (u32, CxxVtable) = (locator.offset, vtable);
                    match best.get(&td_name) {
                        Some((prev_offset, _)) if *prev_offset <= candidate.0 => {}
                        _ => {
                            best.insert(td_name, candidate);
                        }
                    }
                }
            }
            off += 4;
        }
    }
    for (name, (_offset, vtable)) in best {
        if let Some(cls) = by_class.get_mut(&name) {
            cls.vtable = Some(vtable);
        }
    }
}

fn msvc_class_name_for_locator(locator: &MsvcLocator, sections: &[MsvcSection]) -> Option<String> {
    let name_rva: u32 = locator.type_descriptor_rva.checked_add(16)?;
    let raw: String = msvc_cstr(sections, name_rva)?;
    demangle_msvc_type_descriptor(&raw).or(Some(raw))
}

fn bind_msvc_vtable_slots(
    sections: &[MsvcSection],
    vtable_rva: u32,
    image_base: u64,
    func_syms: &BTreeMap<u64, String>,
) -> Option<CxxVtable> {
    let mut slots: Vec<CxxVtableSlot> = Vec::new();
    for i in 0..256u32 {
        let slot_rva: u32 = vtable_rva.checked_add(i.checked_mul(8)?)?;
        let Some(bytes): Option<&[u8]> = msvc_read_at(sections, slot_rva, 8) else {
            break;
        };
        let va: u64 = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        if va == 0 {
            break;
        }
        let target_rva: u64 = va.wrapping_sub(image_base);
        if !rva_in_executable_section(sections, target_rva) {
            break;
        }
        let symbol: Option<String> = func_syms.get(&va).cloned();
        slots.push(CxxVtableSlot {
            index: i as usize,
            function_address: va,
            symbol,
        });
    }
    if slots.is_empty() {
        return None;
    }
    let count: usize = slots.len();
    Some(CxxVtable {
        address: image_base.wrapping_add(u64::from(vtable_rva)),
        slot_count: count,
        slots,
    })
}

fn rva_in_executable_section(sections: &[MsvcSection], rva: u64) -> bool {
    if rva > u64::from(u32::MAX) {
        return false;
    }
    let rva: u32 = rva as u32;
    sections.iter().any(|sec: &MsvcSection| {
        let end: u32 = sec.rva.wrapping_add(sec.data.len() as u32);
        sec.executable && rva >= sec.rva && rva < end
    })
}

fn demangle_msvc_type_descriptor(raw: &str) -> Option<String> {
    let trimmed: &str = raw.strip_prefix('.').unwrap_or(raw);
    let symbol: String = format!("??_R0{trimmed}@8");
    let flags: msvc_demangler::DemangleFlags = msvc_demangler::DemangleFlags::NAME_ONLY;
    let demangled: String = msvc_demangler::demangle(&symbol, flags).ok()?;
    let cleaned: String = clean_msvc_type_name(&demangled);
    if cleaned.is_empty() {
        return None;
    }
    Some(cleaned)
}

fn clean_msvc_type_name(demangled: &str) -> String {
    let mut name: &str = demangled.trim();
    name = name
        .trim_end_matches("`RTTI Type Descriptor'")
        .trim_end()
        .trim_end_matches('\'')
        .trim_end_matches("`RTTI Type Descriptor");
    name = name.trim();
    for keyword in ["class ", "struct ", "union ", "enum "] {
        if let Some(rest) = name.strip_prefix(keyword) {
            name = rest;
            break;
        }
    }
    name.trim().trim_end_matches("::").to_owned()
}

fn read_u32(file: &object::File<'_>, addr: u64) -> Option<u32> {
    let bytes: [u8; 4] = read_bytes::<4>(file, addr)?;
    Some(u32::from_le_bytes(bytes))
}

fn read_u64(file: &object::File<'_>, addr: u64) -> Option<u64> {
    let bytes: [u8; 8] = read_bytes::<8>(file, addr)?;
    Some(u64::from_le_bytes(bytes))
}

fn read_i64(file: &object::File<'_>, addr: u64) -> Option<i64> {
    let bytes: [u8; 8] = read_bytes::<8>(file, addr)?;
    Some(i64::from_le_bytes(bytes))
}

fn read_bytes<const N: usize>(file: &object::File<'_>, addr: u64) -> Option<[u8; N]> {
    for section in file.sections() {
        let start: u64 = section.address();
        let Ok(data): core::result::Result<&[u8], object::Error> = section.data() else {
            continue;
        };
        let end: u64 = start.wrapping_add(data.len() as u64);
        if addr >= start && addr < end {
            let off: usize = (addr - start) as usize;
            let slice_end: usize = off.checked_add(N)?;
            if slice_end <= data.len() {
                let mut buf: [u8; N] = [0u8; N];
                buf.copy_from_slice(&data[off..slice_end]);
                return Some(buf);
            }
            return None;
        }
    }
    None
}

fn addr_in_executable(file: &object::File<'_>, addr: u64) -> bool {
    for section in file.sections() {
        let start: u64 = section.address();
        let size: u64 = section.size();
        if addr >= start && addr < start.wrapping_add(size) {
            return matches!(
                section.kind(),
                object::SectionKind::Text | object::SectionKind::Unknown
            );
        }
    }
    false
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EhEntry {
    pub start: u64,
    pub end: u64,
    pub landing_pad: u64,
    pub action: u32,
}

const MAX_ITANIUM_LSDA_ENTRIES: usize = 65_536;

pub fn parse_itanium_lsda(bytes: &[u8]) -> Result<Vec<EhEntry>> {
    if bytes.len() < 4 {
        return Err(Error::Truncated {
            needed: 4,
            had: bytes.len(),
        });
    }
    let entry_count: usize = (bytes.len() - 4) / 16;
    if entry_count > MAX_ITANIUM_LSDA_ENTRIES {
        return Err(Error::SignatureDb(format!(
            "Itanium LSDA entry count {entry_count} exceeds {MAX_ITANIUM_LSDA_ENTRIES}"
        )));
    }
    let mut out: Vec<EhEntry> = Vec::with_capacity(entry_count);
    let mut idx: usize = 4;
    while idx + 16 <= bytes.len() {
        let start: u64 =
            u32::from_le_bytes([bytes[idx], bytes[idx + 1], bytes[idx + 2], bytes[idx + 3]]) as u64;
        let end: u64 = u32::from_le_bytes([
            bytes[idx + 4],
            bytes[idx + 5],
            bytes[idx + 6],
            bytes[idx + 7],
        ]) as u64;
        let landing_pad: u64 = u32::from_le_bytes([
            bytes[idx + 8],
            bytes[idx + 9],
            bytes[idx + 10],
            bytes[idx + 11],
        ]) as u64;
        let action: u32 = u32::from_le_bytes([
            bytes[idx + 12],
            bytes[idx + 13],
            bytes[idx + 14],
            bytes[idx + 15],
        ]);
        out.push(EhEntry {
            start,
            end,
            landing_pad,
            action,
        });
        idx += 16;
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SehScopeEntry {
    pub begin_address: u32,
    pub end_address: u32,
    pub handler_address: u32,
    pub jump_target: u32,
}

const MAX_WINDOWS_SEH_SCOPE_ENTRIES: usize = 65_536;

pub fn parse_windows_seh_scope_table(bytes: &[u8]) -> Result<Vec<SehScopeEntry>> {
    if bytes.len() < 4 {
        return Err(Error::Truncated {
            needed: 4,
            had: bytes.len(),
        });
    }
    let count: usize = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if count > MAX_WINDOWS_SEH_SCOPE_ENTRIES {
        return Err(Error::SignatureDb(format!(
            "Windows SEH scope table entry count {count} exceeds {MAX_WINDOWS_SEH_SCOPE_ENTRIES}"
        )));
    }
    let needed: usize = count
        .checked_mul(16)
        .and_then(|n: usize| n.checked_add(4))
        .ok_or(Error::Truncated {
            needed: usize::MAX,
            had: bytes.len(),
        })?;
    if bytes.len() < needed {
        return Err(Error::Truncated {
            needed,
            had: bytes.len(),
        });
    }
    let mut out: Vec<SehScopeEntry> = Vec::with_capacity(count);
    let mut idx: usize = 4;
    for _ in 0..count {
        out.push(SehScopeEntry {
            begin_address: u32::from_le_bytes([
                bytes[idx],
                bytes[idx + 1],
                bytes[idx + 2],
                bytes[idx + 3],
            ]),
            end_address: u32::from_le_bytes([
                bytes[idx + 4],
                bytes[idx + 5],
                bytes[idx + 6],
                bytes[idx + 7],
            ]),
            handler_address: u32::from_le_bytes([
                bytes[idx + 8],
                bytes[idx + 9],
                bytes[idx + 10],
                bytes[idx + 11],
            ]),
            jump_target: u32::from_le_bytes([
                bytes[idx + 12],
                bytes[idx + 13],
                bytes[idx + 14],
                bytes[idx + 15],
            ]),
        });
        idx += 16;
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn itanium_demangle_basic() {
        let d: CxxDemangled = demangle_itanium("_ZN3foo3barEv").expect("itanium");
        assert!(d.demangled.contains("foo::bar"));
        assert_eq!(d.abi, CxxAbi::Itanium);
    }

    #[test]
    fn msvc_demangle_basic() {
        let d: CxxDemangled = demangle_msvc("?foo@@YAXXZ").expect("msvc");
        assert!(d.demangled.contains("foo"));
        assert_eq!(d.abi, CxxAbi::Msvc);
    }

    #[test]
    fn auto_dispatch_picks_msvc_for_question_mark() {
        let d: CxxDemangled = demangle_auto("?bar@@YAHH@Z").expect("auto-msvc");
        assert_eq!(d.abi, CxxAbi::Msvc);
    }

    #[test]
    fn auto_dispatch_picks_itanium_for_underscore_z() {
        let d: CxxDemangled = demangle_auto("_ZN1A1BEv").expect("auto-itanium");
        assert_eq!(d.abi, CxxAbi::Itanium);
    }

    #[test]
    fn rtti_recovery_groups_typed_symbols() {
        let syms: [&str; 3] = ["_ZTV3Foo", "_ZTI3Foo", "_ZTS3Foo"];
        let out: Vec<RttiEntry> = recover_itanium_rtti(&syms);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].class_name, "3Foo");
    }

    #[test]
    fn itanium_lsda_parses_minimal_entries() {
        let mut buf: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04];
        buf.extend_from_slice(&100u32.to_le_bytes());
        buf.extend_from_slice(&200u32.to_le_bytes());
        buf.extend_from_slice(&300u32.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes());
        let out: Vec<EhEntry> = parse_itanium_lsda(&buf).expect("lsda");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].start, 100);
        assert_eq!(out[0].landing_pad, 300);
    }

    #[test]
    fn itanium_lsda_rejects_excessive_entries_before_alloc() {
        let entries: usize = MAX_ITANIUM_LSDA_ENTRIES + 1;
        let buf: Vec<u8> = vec![0u8; 4 + entries * 16];
        let result: Result<Vec<EhEntry>> = parse_itanium_lsda(&buf);
        assert!(matches!(result, Err(Error::SignatureDb(_))));
    }

    #[test]
    fn windows_seh_scope_table_parses_count_prefixed() {
        let count: u32 = 1;
        let mut buf: Vec<u8> = count.to_le_bytes().to_vec();
        buf.extend_from_slice(&10u32.to_le_bytes());
        buf.extend_from_slice(&20u32.to_le_bytes());
        buf.extend_from_slice(&30u32.to_le_bytes());
        buf.extend_from_slice(&40u32.to_le_bytes());
        let out: Vec<SehScopeEntry> = parse_windows_seh_scope_table(&buf).expect("seh");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].begin_address, 10);
    }

    #[test]
    fn windows_seh_scope_table_rejects_excessive_count_before_alloc() {
        let count: u32 = 65_537;
        let needed: usize = (count as usize) * 16 + 4;
        let mut buf: Vec<u8> = vec![0; needed];
        buf[..4].copy_from_slice(&count.to_le_bytes());
        let result: Result<Vec<SehScopeEntry>> = parse_windows_seh_scope_table(&buf);
        assert!(matches!(result, Err(Error::SignatureDb(_))));
    }
}
