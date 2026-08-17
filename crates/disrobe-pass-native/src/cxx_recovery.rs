use std::collections::{BTreeMap, BTreeSet};

use disrobe_bytes::{ByteReader, Endian};
use gimli::{
    BaseAddresses, CieOrFde, CommonInformationEntry, EhFrame, EhFrameOffset, EndianSlice,
    FrameDescriptionEntry, LittleEndian, Pointer, UnwindSection as _,
};
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
    pub actions: Vec<EhAction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum EhAction {
    Cleanup,
    CatchAll,
    Catch { type_index: u64 },
    ExceptionSpecification { filter: i64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItaniumEhFunction {
    pub function_start: u64,
    pub function_end: u64,
    pub lsda_address: u64,
    pub entries: Vec<EhEntry>,
}

const MAX_ITANIUM_LSDA_ENTRIES: usize = 65_536;
const MAX_ITANIUM_ACTION_STEPS: usize = 65_536;
const DW_EH_PE_OMIT: u8 = 0xff;

type EhSlice<'a> = EndianSlice<'a, LittleEndian>;

#[derive(Debug, Clone, Copy)]
struct ItaniumLsdaContext {
    function_start: u64,
    function_end: Option<u64>,
    input_address: u64,
    text_base: Option<u64>,
    data_base: Option<u64>,
    address_size: usize,
    endian: Endian,
}

#[derive(Debug, Clone, Copy)]
struct EncodedPointer {
    value: u64,
    indirect: bool,
    raw_zero: bool,
}

fn itanium_error(message: impl Into<String>) -> Error {
    Error::Dwarf(format!("Itanium LSDA: {}", message.into()))
}

fn byte_error(error: impl std::fmt::Display) -> Error {
    itanium_error(error.to_string())
}

fn encoded_value_size(encoding: u8, address_size: usize) -> Result<Option<usize>> {
    match encoding & 0x0f {
        0x00 => Ok(Some(address_size)),
        0x01 | 0x09 => Ok(None),
        0x02 | 0x0a => Ok(Some(2)),
        0x03 | 0x0b => Ok(Some(4)),
        0x04 | 0x0c => Ok(Some(8)),
        format => Err(itanium_error(format!(
            "unsupported DW_EH_PE value format 0x{format:02x}"
        ))),
    }
}

fn read_encoded_pointer(
    reader: &mut ByteReader<'_>,
    encoding: u8,
    context: ItaniumLsdaContext,
) -> Result<EncodedPointer> {
    if encoding == DW_EH_PE_OMIT {
        return Err(itanium_error("DW_EH_PE_omit has no encoded value"));
    }
    let application: u8 = encoding & 0x70;
    if application == 0x50 {
        let field_address: u64 = context
            .input_address
            .checked_add(u64::try_from(reader.position()).map_err(byte_error)?)
            .ok_or_else(|| itanium_error("aligned pointer address overflow"))?;
        let alignment: u64 = u64::try_from(context.address_size).map_err(byte_error)?;
        let padding: u64 = (alignment - field_address % alignment) % alignment;
        reader
            .skip(usize::try_from(padding).map_err(byte_error)?)
            .map_err(byte_error)?;
    } else if !matches!(application, 0x00 | 0x10 | 0x20 | 0x30 | 0x40) {
        return Err(itanium_error(format!(
            "unsupported DW_EH_PE application 0x{application:02x}"
        )));
    }
    let field_address: u64 = context
        .input_address
        .checked_add(u64::try_from(reader.position()).map_err(byte_error)?)
        .ok_or_else(|| itanium_error("pointer field address overflow"))?;
    let (unsigned, signed, raw_zero): (Option<u64>, Option<i64>, bool) = match encoding & 0x0f {
        0x00 => match context.address_size {
            4 => {
                let value: u64 = u64::from(reader.read_u32(context.endian).map_err(byte_error)?);
                (Some(value), None, value == 0)
            }
            8 => {
                let value: u64 = reader.read_u64(context.endian).map_err(byte_error)?;
                (Some(value), None, value == 0)
            }
            size => {
                return Err(itanium_error(format!("unsupported pointer size {size}")));
            }
        },
        0x01 => {
            let value: u64 = reader.read_uleb128().map_err(byte_error)?;
            (Some(value), None, value == 0)
        }
        0x02 => {
            let value: u64 = u64::from(reader.read_u16(context.endian).map_err(byte_error)?);
            (Some(value), None, value == 0)
        }
        0x03 => {
            let value: u64 = u64::from(reader.read_u32(context.endian).map_err(byte_error)?);
            (Some(value), None, value == 0)
        }
        0x04 => {
            let value: u64 = reader.read_u64(context.endian).map_err(byte_error)?;
            (Some(value), None, value == 0)
        }
        0x09 => {
            let value: i64 = reader.read_sleb128().map_err(byte_error)?;
            (None, Some(value), value == 0)
        }
        0x0a => {
            let value: i64 = i64::from(reader.read_i16(context.endian).map_err(byte_error)?);
            (None, Some(value), value == 0)
        }
        0x0b => {
            let value: i64 = i64::from(reader.read_i32(context.endian).map_err(byte_error)?);
            (None, Some(value), value == 0)
        }
        0x0c => {
            let value: i64 = reader.read_i64(context.endian).map_err(byte_error)?;
            (None, Some(value), value == 0)
        }
        format => {
            return Err(itanium_error(format!(
                "unsupported DW_EH_PE value format 0x{format:02x}"
            )));
        }
    };
    let base: u64 = match application {
        0x00 | 0x50 => 0,
        0x10 => field_address,
        0x20 => context
            .text_base
            .ok_or_else(|| itanium_error("DW_EH_PE_textrel requires a text base"))?,
        0x30 => context
            .data_base
            .ok_or_else(|| itanium_error("DW_EH_PE_datarel requires a data base"))?,
        0x40 => context.function_start,
        _ => return Err(itanium_error("invalid pointer application")),
    };
    let value: u64 = if raw_zero {
        0
    } else if let Some(offset) = signed {
        base.checked_add_signed(offset)
            .ok_or_else(|| itanium_error("signed pointer addition overflow"))?
    } else {
        base.checked_add(unsigned.ok_or_else(|| itanium_error("encoded pointer has no value"))?)
            .ok_or_else(|| itanium_error("pointer addition overflow"))?
    };
    Ok(EncodedPointer {
        value,
        indirect: encoding & 0x80 != 0,
        raw_zero,
    })
}

fn type_entry(
    bytes: &[u8],
    type_table: usize,
    type_encoding: u8,
    type_index: u64,
    context: ItaniumLsdaContext,
) -> Result<EncodedPointer> {
    if type_encoding == DW_EH_PE_OMIT {
        return Err(itanium_error("catch action has no type table"));
    }
    let Some(width): Option<usize> = encoded_value_size(type_encoding, context.address_size)?
    else {
        return Err(itanium_error(format!(
            "variable-width type-table encoding 0x{type_encoding:02x} cannot be indexed"
        )));
    };
    let index: usize = usize::try_from(type_index).map_err(byte_error)?;
    let distance: usize = index
        .checked_mul(width)
        .ok_or_else(|| itanium_error("type-table index overflow"))?;
    let offset: usize = type_table
        .checked_sub(distance)
        .ok_or_else(|| itanium_error("type-table index is outside the LSDA"))?;
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader.seek(offset).map_err(byte_error)?;
    read_encoded_pointer(&mut reader, type_encoding, context)
}

fn exception_specification(
    bytes: &[u8],
    type_table: usize,
    filter: i64,
    type_encoding: u8,
    context: ItaniumLsdaContext,
    remaining_steps: &mut usize,
) -> Result<()> {
    let magnitude: usize = usize::try_from(filter.unsigned_abs()).map_err(byte_error)?;
    let distance: usize = magnitude
        .checked_sub(1)
        .ok_or_else(|| itanium_error("exception-specification filter is zero"))?;
    let offset: usize = type_table
        .checked_add(distance)
        .ok_or_else(|| itanium_error("exception-specification offset overflow"))?;
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader.seek(offset).map_err(byte_error)?;
    loop {
        consume_itanium_action_step(remaining_steps)?;
        let type_index: u64 = reader.read_uleb128().map_err(byte_error)?;
        if type_index == 0 {
            return Ok(());
        }
        let _: EncodedPointer = type_entry(bytes, type_table, type_encoding, type_index, context)?;
    }
}

fn consume_itanium_action_step(remaining_steps: &mut usize) -> Result<()> {
    *remaining_steps = remaining_steps
        .checked_sub(1)
        .ok_or_else(|| itanium_error("decoded action steps exceed the LSDA-wide limit"))?;
    Ok(())
}

fn parse_action_chain(
    bytes: &[u8],
    action_table: usize,
    action_offset: u64,
    type_table: Option<usize>,
    type_encoding: u8,
    context: ItaniumLsdaContext,
    remaining_steps: &mut usize,
) -> Result<Vec<EhAction>> {
    let biased: usize = usize::try_from(action_offset).map_err(byte_error)?;
    let mut cursor: usize = action_table
        .checked_add(
            biased
                .checked_sub(1)
                .ok_or_else(|| itanium_error("zero action offset has no action record"))?,
        )
        .ok_or_else(|| itanium_error("action-table offset overflow"))?;
    let action_limit: usize = type_table.unwrap_or(bytes.len());
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    let mut actions: Vec<EhAction> = Vec::new();
    loop {
        if cursor < action_table {
            return Err(itanium_error(
                "action-chain displacement moves before the action table",
            ));
        }
        if cursor >= action_limit {
            return Err(itanium_error(
                "action-chain displacement leaves the action table",
            ));
        }
        if !visited.insert(cursor) {
            return Err(itanium_error("action chain contains a cycle"));
        }
        consume_itanium_action_step(remaining_steps)?;
        let action_bytes: &[u8] = bytes
            .get(cursor..action_limit)
            .ok_or_else(|| itanium_error("action record is outside the action table"))?;
        let mut reader: ByteReader<'_> = ByteReader::new(action_bytes);
        let filter: i64 = reader.read_sleb128().map_err(byte_error)?;
        let displacement_base: usize = cursor
            .checked_add(reader.position())
            .ok_or_else(|| itanium_error("action displacement base overflow"))?;
        let displacement: i64 = reader.read_sleb128().map_err(byte_error)?;
        let action: EhAction = match filter {
            0 => EhAction::Cleanup,
            positive if positive > 0 => {
                let table: usize =
                    type_table.ok_or_else(|| itanium_error("catch action has no type table"))?;
                let type_index: u64 = u64::try_from(positive).map_err(byte_error)?;
                let pointer: EncodedPointer =
                    type_entry(bytes, table, type_encoding, type_index, context)?;
                if pointer.raw_zero {
                    EhAction::CatchAll
                } else {
                    EhAction::Catch { type_index }
                }
            }
            negative => {
                let table: usize = type_table
                    .ok_or_else(|| itanium_error("exception specification has no type table"))?;
                exception_specification(
                    bytes,
                    table,
                    negative,
                    type_encoding,
                    context,
                    remaining_steps,
                )?;
                EhAction::ExceptionSpecification { filter: negative }
            }
        };
        actions.push(action);
        if displacement == 0 {
            return Ok(actions);
        }
        cursor = displacement_base
            .checked_add_signed(isize::try_from(displacement).map_err(byte_error)?)
            .ok_or_else(|| itanium_error("action-chain displacement leaves the LSDA"))?;
    }
}

fn parse_itanium_lsda_with_context(
    bytes: &[u8],
    context: ItaniumLsdaContext,
) -> Result<Vec<EhEntry>> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    let lpstart_encoding: u8 = reader.read_u8().map_err(byte_error)?;
    let lpstart: u64 = if lpstart_encoding == DW_EH_PE_OMIT {
        context.function_start
    } else {
        let pointer: EncodedPointer = read_encoded_pointer(&mut reader, lpstart_encoding, context)?;
        if pointer.indirect {
            return Err(itanium_error(
                "indirect landing-pad bases require an image resolver",
            ));
        }
        pointer.value
    };
    let type_encoding: u8 = reader.read_u8().map_err(byte_error)?;
    let type_table: Option<usize> = if type_encoding == DW_EH_PE_OMIT {
        None
    } else {
        let offset: u64 = reader.read_uleb128().map_err(byte_error)?;
        let base: usize = reader.position();
        let offset: usize = usize::try_from(offset).map_err(byte_error)?;
        let table: usize = base
            .checked_add(offset)
            .ok_or_else(|| itanium_error("type-table offset overflow"))?;
        if table > bytes.len() {
            return Err(itanium_error("type table is outside the LSDA"));
        }
        Some(table)
    };
    let call_site_encoding: u8 = reader.read_u8().map_err(byte_error)?;
    if call_site_encoding == DW_EH_PE_OMIT {
        return Err(itanium_error("call-site table encoding is omitted"));
    }
    let table_length: usize =
        usize::try_from(reader.read_uleb128().map_err(byte_error)?).map_err(byte_error)?;
    let table_start: usize = reader.position();
    let table: &[u8] = reader.read_bytes(table_length).map_err(byte_error)?;
    let action_table: usize = reader.position();
    let table_context: ItaniumLsdaContext = ItaniumLsdaContext {
        input_address: context
            .input_address
            .checked_add(u64::try_from(table_start).map_err(byte_error)?)
            .ok_or_else(|| itanium_error("call-site table address overflow"))?,
        ..context
    };
    let call_site_value_encoding: u8 = call_site_encoding & 0x0f;
    let mut table_reader: ByteReader<'_> = ByteReader::new(table);
    let mut entries: Vec<EhEntry> = Vec::new();
    let mut remaining_action_steps: usize = MAX_ITANIUM_ACTION_STEPS;
    while !table_reader.is_empty() {
        if entries.len() >= MAX_ITANIUM_LSDA_ENTRIES {
            return Err(itanium_error(format!(
                "entry count exceeds {MAX_ITANIUM_LSDA_ENTRIES}"
            )));
        }
        let start_offset: u64 =
            read_encoded_pointer(&mut table_reader, call_site_value_encoding, table_context)?.value;
        let length: u64 =
            read_encoded_pointer(&mut table_reader, call_site_value_encoding, table_context)?.value;
        let landing_offset: u64 =
            read_encoded_pointer(&mut table_reader, call_site_value_encoding, table_context)?.value;
        let action_offset: u64 = table_reader.read_uleb128().map_err(byte_error)?;
        let start: u64 = context
            .function_start
            .checked_add(start_offset)
            .ok_or_else(|| itanium_error("call-site start overflow"))?;
        let end: u64 = start
            .checked_add(length)
            .ok_or_else(|| itanium_error("call-site end overflow"))?;
        if let Some(function_end) = context.function_end
            && end > function_end
        {
            return Err(itanium_error("call-site range leaves its FDE"));
        }
        let landing_pad: u64 = if landing_offset == 0 {
            0
        } else {
            lpstart
                .checked_add(landing_offset)
                .ok_or_else(|| itanium_error("landing-pad address overflow"))?
        };
        let actions: Vec<EhAction> = if action_offset == 0 {
            if landing_pad == 0 {
                Vec::new()
            } else {
                consume_itanium_action_step(&mut remaining_action_steps)?;
                vec![EhAction::Cleanup]
            }
        } else {
            parse_action_chain(
                bytes,
                action_table,
                action_offset,
                type_table,
                type_encoding,
                context,
                &mut remaining_action_steps,
            )?
        };
        entries.push(EhEntry {
            start,
            end,
            landing_pad,
            action: u32::try_from(action_offset).map_err(byte_error)?,
            actions,
        });
    }
    Ok(entries)
}

pub fn parse_itanium_lsda(bytes: &[u8]) -> Result<Vec<EhEntry>> {
    parse_itanium_lsda_with_context(
        bytes,
        ItaniumLsdaContext {
            function_start: 0,
            function_end: None,
            input_address: 0,
            text_base: Some(0),
            data_base: Some(0),
            address_size: 8,
            endian: Endian::Little,
        },
    )
}

fn parse_eh_cie<'a>(
    section: &EhFrame<EhSlice<'a>>,
    bases: &BaseAddresses,
    offset: EhFrameOffset<usize>,
) -> gimli::Result<CommonInformationEntry<EhSlice<'a>>> {
    section.cie_from_offset(bases, offset)
}

fn image_pointer(file: &object::File<'_>, address: u64) -> Result<u64> {
    for section in file.sections() {
        let start: u64 = section.address();
        let end: u64 = start
            .checked_add(section.size())
            .ok_or_else(|| itanium_error("section address overflow"))?;
        if !(start..end).contains(&address) {
            continue;
        }
        let data: &[u8] = section
            .data()
            .map_err(|error: object::Error| Error::ObjectParse(error.to_string()))?;
        let offset: usize = usize::try_from(address - start).map_err(byte_error)?;
        let mut reader: ByteReader<'_> = ByteReader::new(data);
        reader.seek(offset).map_err(byte_error)?;
        return reader.read_u64_le().map_err(byte_error);
    }
    Err(itanium_error(
        "indirect FDE LSDA pointer is not file-backed",
    ))
}

fn symbol_has_name_at(file: &object::File<'_>, address: u64, expected: &str) -> bool {
    address != 0
        && file
            .symbols()
            .chain(file.dynamic_symbols())
            .any(|symbol: object::Symbol<'_, '_>| {
                symbol.address() == address
                    && symbol.name().is_ok_and(|name: &str| name == expected)
            })
}

fn is_gxx_personality(
    file: &object::File<'_>,
    pointer_relocations: &BTreeMap<u64, String>,
    pointer: Pointer,
) -> bool {
    const NAME: &str = "__gxx_personality_v0";
    match pointer {
        Pointer::Direct(address) => symbol_has_name_at(file, address, NAME),
        Pointer::Indirect(address) => {
            pointer_relocations
                .get(&address)
                .is_some_and(|name: &String| name == NAME)
                || image_pointer(file, address)
                    .is_ok_and(|target: u64| symbol_has_name_at(file, target, NAME))
        }
    }
}

pub fn recover_itanium_exception_regions(object_bytes: &[u8]) -> Result<Vec<ItaniumEhFunction>> {
    if !object_bytes.starts_with(b"\x7fELF") {
        return Ok(Vec::new());
    }
    let file: object::File<'_> = object::File::parse(object_bytes)
        .map_err(|error: object::Error| Error::ObjectParse(error.to_string()))?;
    if !matches!(file.format(), object::BinaryFormat::Elf) {
        return Ok(Vec::new());
    }
    if file.architecture() != object::Architecture::X86_64 || !file.is_little_endian() {
        return Err(itanium_error(
            "this recovery slice supports little-endian x86-64 ELF; ARM EHABI and other architectures are excluded",
        ));
    }
    let Some(eh_section): Option<object::Section<'_, '_>> = file.section_by_name(".eh_frame")
    else {
        return Ok(Vec::new());
    };
    let Some(lsda_section): Option<object::Section<'_, '_>> =
        file.section_by_name(".gcc_except_table")
    else {
        return Ok(Vec::new());
    };
    let eh_bytes: &[u8] = eh_section
        .data()
        .map_err(|error: object::Error| Error::ObjectParse(error.to_string()))?;
    let lsda_bytes: &[u8] = lsda_section
        .data()
        .map_err(|error: object::Error| Error::ObjectParse(error.to_string()))?;
    let text_base: Option<u64> = file
        .section_by_name(".text")
        .map(|section| section.address());
    let data_base: Option<u64> = file
        .section_by_name(".got")
        .or_else(|| file.section_by_name(".data"))
        .map(|section| section.address());
    let mut bases: BaseAddresses = BaseAddresses::default().set_eh_frame(eh_section.address());
    if let Some(address) = text_base {
        bases = bases.set_text(address);
    }
    if let Some(address) = data_base {
        bases = bases.set_got(address);
    }
    let eh_frame: EhFrame<EhSlice<'_>> = EhFrame::new(eh_bytes, LittleEndian);
    let pointer_relocations: BTreeMap<u64, String> = collect_pointer_relocations(&file);
    let mut iterator = eh_frame.entries(&bases);
    let mut records: Vec<(u64, u64, u64)> = Vec::new();
    let mut exhausted: bool = false;
    for _ in 0..MAX_ITANIUM_LSDA_ENTRIES {
        let entry = iterator
            .next()
            .map_err(|error: gimli::Error| Error::Dwarf(error.to_string()))?;
        let Some(entry) = entry else {
            exhausted = true;
            break;
        };
        let CieOrFde::Fde(partial) = entry else {
            continue;
        };
        let fde: FrameDescriptionEntry<EhSlice<'_>> = partial
            .parse(parse_eh_cie)
            .map_err(|error: gimli::Error| Error::Dwarf(error.to_string()))?;
        let Some(personality): Option<Pointer> = fde.personality() else {
            continue;
        };
        if !is_gxx_personality(&file, &pointer_relocations, personality) {
            continue;
        }
        let Some(pointer): Option<Pointer> = fde.lsda() else {
            continue;
        };
        let address: u64 = match pointer {
            Pointer::Direct(address) => address,
            Pointer::Indirect(address) => image_pointer(&file, address)?,
        };
        records.push((fde.initial_address(), fde.end_address(), address));
    }
    if !exhausted {
        return Err(itanium_error(format!(
            ".eh_frame entry count exceeds {MAX_ITANIUM_LSDA_ENTRIES}"
        )));
    }
    records.sort_unstable_by_key(|record: &(u64, u64, u64)| record.2);
    let section_start: u64 = lsda_section.address();
    let section_end: u64 = section_start
        .checked_add(lsda_section.size())
        .ok_or_else(|| itanium_error("LSDA section range overflow"))?;
    let mut functions: Vec<ItaniumEhFunction> = Vec::with_capacity(records.len());
    for (index, (function_start, function_end, lsda_address)) in records.iter().copied().enumerate()
    {
        if !(section_start..section_end).contains(&lsda_address) {
            return Err(itanium_error(format!(
                "FDE LSDA pointer 0x{lsda_address:x} is outside .gcc_except_table"
            )));
        }
        let next_address: u64 = records
            .get(index + 1)
            .map_or(section_end, |record: &(u64, u64, u64)| record.2);
        if next_address <= lsda_address || next_address > section_end {
            return Err(itanium_error("LSDA ranges overlap or are unsorted"));
        }
        let offset: usize = usize::try_from(lsda_address - section_start).map_err(byte_error)?;
        let end: usize = usize::try_from(next_address - section_start).map_err(byte_error)?;
        let bytes: &[u8] = lsda_bytes
            .get(offset..end)
            .ok_or_else(|| itanium_error("LSDA range is not file-backed"))?;
        let entries: Vec<EhEntry> = parse_itanium_lsda_with_context(
            bytes,
            ItaniumLsdaContext {
                function_start,
                function_end: Some(function_end),
                input_address: lsda_address,
                text_base,
                data_base,
                address_size: 8,
                endian: Endian::Little,
            },
        )?;
        functions.push(ItaniumEhFunction {
            function_start,
            function_end,
            lsda_address,
            entries,
        });
    }
    functions.sort_unstable_by_key(|function: &ItaniumEhFunction| function.function_start);
    Ok(functions)
}

pub(crate) fn itanium_partial_reason(function: &ItaniumEhFunction) -> String {
    let Some(entry): Option<&EhEntry> = function
        .entries
        .iter()
        .find(|entry: &&EhEntry| entry.landing_pad != 0)
    else {
        return "control-flow-partial: Itanium LSDA contains no recoverable landing pad; try/catch emission is withheld until the landing-pad CFG is re-nested".to_owned();
    };
    let action: String = match entry.actions.first() {
        Some(EhAction::Catch { type_index }) => format!("catch type index {type_index}"),
        Some(EhAction::CatchAll) => "catch-all".to_owned(),
        Some(EhAction::Cleanup) => "cleanup".to_owned(),
        Some(EhAction::ExceptionSpecification { filter }) => {
            format!("exception specification {filter}")
        }
        None => "no action".to_owned(),
    };
    format!(
        "control-flow-partial: Itanium LSDA protects 0x{:x}..0x{:x} with landing pad 0x{:x} and {action}; try/catch emission is withheld until the landing-pad CFG is re-nested",
        entry.start, entry.end, entry.landing_pad
    )
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
        let buf: Vec<u8> = vec![0xff, 0xff, 0x01, 0x05, 0x64, 0x64, 0xac, 0x02, 0x00];
        let out: Vec<EhEntry> = parse_itanium_lsda(&buf).expect("lsda");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].start, 100);
        assert_eq!(out[0].end, 200);
        assert_eq!(out[0].landing_pad, 300);
    }

    #[test]
    fn itanium_lsda_rejects_excessive_entries_before_alloc() {
        let entries: usize = MAX_ITANIUM_LSDA_ENTRIES + 1;
        let table_length: usize = entries * 4;
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0x01];
        let mut value: usize = table_length;
        loop {
            let mut byte: u8 = u8::try_from(value & 0x7f).expect("seven-bit group");
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            buf.push(byte);
            if value == 0 {
                break;
            }
        }
        buf.resize(buf.len() + table_length, 0);
        let result: Result<Vec<EhEntry>> = parse_itanium_lsda(&buf);
        assert!(matches!(result, Err(Error::Dwarf(_))));
    }

    #[test]
    fn itanium_exception_specification_indexes_forward_from_the_type_base() {
        let bytes: [u8; 2] = [0xff, 0x00];
        let context: ItaniumLsdaContext = ItaniumLsdaContext {
            function_start: 0,
            function_end: None,
            input_address: 0,
            text_base: Some(0),
            data_base: Some(0),
            address_size: 8,
            endian: Endian::Little,
        };
        let mut remaining_steps: usize = MAX_ITANIUM_ACTION_STEPS;
        let result: Result<()> =
            exception_specification(&bytes, 1, -1, 0x03, context, &mut remaining_steps);
        assert!(result.is_ok());
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
