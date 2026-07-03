use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::binary::GoImage;
use crate::moduledata::Moduledata;
use crate::pclntab::PclntabVersion;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoTypeRef {
    pub va: u64,
    pub name: Option<String>,
    pub kind: Option<u8>,
    pub kind_label: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<GoMethod>,
}

/// One entry of a named type's method set, from the type's `abi.UncommonType`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GoMethod {
    pub name: Option<String>,
    pub func_va: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linker_name: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub exported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoItab {
    pub va: u64,
    pub interface_name: Option<String>,
    pub concrete_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoTypeMeta {
    pub types: Vec<GoTypeRef>,
    pub itabs: Vec<GoItab>,
    pub strings: Vec<String>,
    pub generics: Vec<GoGenericInstantiation>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GoGenericInstantiation {
    pub full: String,
    pub base: String,
    pub type_args: Vec<String>,
    pub shape_args: bool,
    pub from_function: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub concrete_candidates: Vec<Vec<String>>,
}

const TYPELINKS_WALK_CAP: usize = 1 << 14;
const ITABLINKS_WALK_CAP: usize = 1 << 14;

#[must_use]
pub fn extract_typemeta(image: &GoImage<'_>, md: &Moduledata) -> GoTypeMeta {
    extract_typemeta_versioned(image, md, infer_layout(md, image.ptr_size))
}

fn extract_typemeta_versioned(
    image: &GoImage<'_>,
    md: &Moduledata,
    layout: AbiTypeLayout,
) -> GoTypeMeta {
    let mut types: Vec<GoTypeRef> = Vec::new();
    let mut itabs: Vec<GoItab> = Vec::new();
    let mut strings: BTreeSet<String> = BTreeSet::new();

    if md.typelinks_va != 0 && md.typelinks_len != 0 && md.types_va != 0 {
        let n: usize = usize::try_from(md.typelinks_len).unwrap_or(0);
        types.reserve(n.min(TYPELINKS_WALK_CAP));
        let mut seen: BTreeSet<u64> = BTreeSet::new();
        for i in 0..n.min(TYPELINKS_WALK_CAP) {
            let entry_va: u64 = md.typelinks_va.wrapping_add((i as u64) * 4);
            let Some(off): Option<u32> = image.read_u32(entry_va) else {
                break;
            };
            let type_va: u64 = md.types_va.wrapping_add(u64::from(off));
            if !seen.insert(type_va) {
                continue;
            }
            let name: Option<String> = read_type_name(image, md, type_va, layout);
            let kind: Option<u8> = read_type_kind(image, type_va, layout);
            if let Some(ref n_str) = name {
                strings.insert(n_str.clone());
            }
            let kind_label: Option<String> = kind.map(|k: u8| type_kind_label(k).to_owned());
            let methods: Vec<GoMethod> = kind.map_or_else(Vec::new, |k: u8| {
                read_type_methods(image, md, type_va, k, layout)
            });
            types.push(GoTypeRef {
                va: type_va,
                name,
                kind,
                kind_label,
                methods,
            });
        }
    }

    if md.itablinks_va != 0 && md.itablinks_len != 0 {
        let n: usize = usize::try_from(md.itablinks_len).unwrap_or(0);
        itabs.reserve(n.min(ITABLINKS_WALK_CAP));
        let ps: u64 = u64::from(image.ptr_size);
        for i in 0..n.min(ITABLINKS_WALK_CAP) {
            let slot_va: u64 = md.itablinks_va.wrapping_add((i as u64) * ps);
            let Some(itab_va): Option<u64> = image.read_ptr(slot_va) else {
                break;
            };
            if itab_va == 0 {
                continue;
            }
            let inter_va: u64 = image.read_ptr(itab_va).unwrap_or(0);
            let concrete_va: u64 = image.read_ptr(itab_va.wrapping_add(ps)).unwrap_or(0);
            let inter_name: Option<String> = if inter_va != 0 {
                read_type_name(image, md, inter_va, layout)
            } else {
                None
            };
            let concrete_name: Option<String> = if concrete_va != 0 {
                read_type_name(image, md, concrete_va, layout)
            } else {
                None
            };
            if let Some(ref s) = inter_name {
                strings.insert(s.clone());
            }
            if let Some(ref s) = concrete_name {
                strings.insert(s.clone());
            }
            itabs.push(GoItab {
                va: itab_va,
                interface_name: inter_name,
                concrete_name,
            });
        }
    }

    let type_name_iter = types.iter().filter_map(|t: &GoTypeRef| t.name.as_deref());
    let generics: Vec<GoGenericInstantiation> =
        parse_generic_type_info(std::iter::empty::<&str>(), type_name_iter);

    GoTypeMeta {
        types,
        itabs,
        strings: strings.into_iter().collect(),
        generics,
    }
}

/// Cross-reference every reconstructed method against the pclntab function table by exact entry-VA match, filling `linker_name`.
pub fn link_method_functions(meta: &mut GoTypeMeta, funcs: &[(u64, &str)], text_va: u64) {
    if funcs.is_empty() {
        return;
    }
    let mut by_va: BTreeMap<u64, &str> = BTreeMap::new();
    for (entry, name) in funcs.iter().copied() {
        by_va.entry(entry).or_insert(name);
        if let Some(abs) = text_va.checked_add(entry) {
            by_va.entry(abs).or_insert(name);
        }
    }
    for ty in &mut meta.types {
        for m in &mut ty.methods {
            if m.func_va == 0 {
                continue;
            }
            if let Some(name) = by_va.get(&m.func_va) {
                m.linker_name = Some((*name).to_owned());
            }
        }
    }
}

const GENERIC_SHAPE_PREFIX: &str = "go.shape.";

#[must_use]
pub fn parse_generic_type_info<'a, F, T>(
    func_names: F,
    type_names: T,
) -> Vec<GoGenericInstantiation>
where
    F: IntoIterator<Item = &'a str>,
    T: IntoIterator<Item = &'a str>,
{
    let func_names: Vec<&str> = func_names.into_iter().collect();
    let type_names: Vec<&str> = type_names.into_iter().collect();

    let mut out: BTreeSet<GoGenericInstantiation> = BTreeSet::new();
    for &name in &func_names {
        if let Some(inst) = parse_generic_name(name, true) {
            out.insert(inst);
        }
    }
    for &name in &type_names {
        if let Some(inst) = parse_generic_name(name, false) {
            out.insert(inst);
        }
    }

    let concretes: ConcreteArgMap =
        harvest_concrete_args(func_names.iter().chain(type_names.iter()).copied());
    let mut list: Vec<GoGenericInstantiation> = out.into_iter().collect();
    disambiguate_shape_args(&mut list, &concretes);
    dedup_sorted(list)
}

#[must_use]
fn dedup_sorted(list: Vec<GoGenericInstantiation>) -> Vec<GoGenericInstantiation> {
    list.into_iter()
        .collect::<BTreeSet<GoGenericInstantiation>>()
        .into_iter()
        .collect()
}

type ConcreteArgMap = BTreeMap<String, BTreeSet<Vec<String>>>;

const COMPILER_BASE_PREFIXES: [&str; 4] = ["type:.eq.", "type:.hash.", "go:itab.", "go:noalg."];

#[must_use]
pub fn harvest_concrete_args<'a, N>(names: N) -> ConcreteArgMap
where
    N: IntoIterator<Item = &'a str>,
{
    let mut map: ConcreteArgMap = BTreeMap::new();
    for name in names {
        let Some((base, args)): Option<(String, Vec<String>)> = mine_concrete_instantiation(name)
        else {
            continue;
        };
        map.entry(base).or_default().insert(args);
    }
    map
}

fn mine_concrete_instantiation(name: &str) -> Option<(String, Vec<String>)> {
    let open: usize = first_top_level_open_bracket(name)?;
    if open == 0 {
        return None;
    }
    let close: usize = matching_close_bracket(name, open)?;
    let wrapped_base: &str = &name[..open];
    let unprefixed: &str = strip_compiler_namespace_prefix(wrapped_base);
    let base: String = normalize_base(unprefixed)?;
    if base.is_empty() || !base.contains('.') || base.starts_with('.') {
        return None;
    }
    if base.contains("type:") || base.contains("go:") {
        return None;
    }
    let inner: &str = &name[open + 1..close];
    let args: Vec<String> = split_top_level_commas(inner);
    if args.is_empty() || args.iter().any(String::is_empty) {
        return None;
    }
    if args
        .iter()
        .any(|a: &String| a.starts_with(GENERIC_SHAPE_PREFIX))
    {
        return None;
    }
    Some((base, args))
}

fn strip_compiler_namespace_prefix(base: &str) -> &str {
    let mut rest: &str = base;
    loop {
        let mut stripped: bool = false;
        for prefix in COMPILER_BASE_PREFIXES {
            if let Some(tail) = rest.strip_prefix(prefix) {
                rest = tail;
                stripped = true;
                break;
            }
        }
        if !stripped {
            return rest;
        }
    }
}

pub fn disambiguate_generics<'a, N>(list: &mut [GoGenericInstantiation], names: N)
where
    N: IntoIterator<Item = &'a str>,
{
    let concretes: ConcreteArgMap = harvest_concrete_args(names);
    disambiguate_shape_args(list, &concretes);
}

fn short_base(base: &str) -> &str {
    base.rsplit_once('/')
        .map_or(base, |(_, tail): (&str, &str)| tail)
}

fn join_concrete_for_base<'a>(
    base: &str,
    concretes: &'a ConcreteArgMap,
) -> (BTreeSet<&'a Vec<String>>, bool) {
    let exact: Option<&BTreeSet<Vec<String>>> = concretes.get(base);
    if let Some(args) = exact {
        return (args.iter().collect(), false);
    }
    let mut union: BTreeSet<&Vec<String>> = BTreeSet::new();
    let mut contributing_paths: BTreeSet<&str> = BTreeSet::new();
    for (key, args) in concretes {
        let key: &String = key;
        let args: &BTreeSet<Vec<String>> = args;
        if short_base(key.as_str()) == base {
            contributing_paths.insert(key.as_str());
            union.extend(args.iter());
        }
    }
    (union, contributing_paths.len() > 1)
}

fn disambiguate_shape_args(list: &mut [GoGenericInstantiation], concretes: &ConcreteArgMap) {
    for inst in list.iter_mut() {
        if !inst.shape_args {
            continue;
        }
        let (candidates, cross_package_collision): (BTreeSet<&Vec<String>>, bool) =
            join_concrete_for_base(&inst.base, concretes);
        if candidates.is_empty() {
            continue;
        }
        let arity: usize = inst.type_args.len();
        let matched: Vec<&Vec<String>> = candidates
            .into_iter()
            .filter(|args: &&Vec<String>| args.len() == arity)
            .collect();
        match matched.as_slice() {
            [] => {}
            [single] if !cross_package_collision => {
                inst.type_args = (*single).clone();
                inst.shape_args = false;
                inst.full = format!("{}[{}]", inst.base, inst.type_args.join(","));
                inst.concrete_candidates = Vec::new();
            }
            many => {
                inst.concrete_candidates = many
                    .iter()
                    .map(|args: &&Vec<String>| (*args).clone())
                    .collect();
            }
        }
    }
}

#[must_use]
pub fn parse_generic_name(name: &str, from_function: bool) -> Option<GoGenericInstantiation> {
    let open: usize = first_top_level_open_bracket(name)?;
    if open == 0 {
        return None;
    }
    let close: usize = matching_close_bracket(name, open)?;
    let suffix: &str = &name[close + 1..];
    if !suffix.is_empty() && !suffix.starts_with('.') && !suffix.starts_with(')') {
        return None;
    }
    let wrapped_base: &str = &name[..open];
    if wrapped_base.contains("type:") || wrapped_base.contains("go:") {
        return None;
    }
    let base: String = normalize_base(wrapped_base)?;
    if base.is_empty() || !base.contains('.') || base.starts_with('.') {
        return None;
    }
    let inner: &str = &name[open + 1..close];
    let type_args: Vec<String> = split_top_level_commas(inner);
    if type_args.is_empty() || type_args.iter().any(String::is_empty) {
        return None;
    }
    let shape_args: bool = type_args
        .iter()
        .all(|a: &String| a.starts_with(GENERIC_SHAPE_PREFIX));
    let full: String = format!("{base}{}", &name[open..=close]);
    Some(GoGenericInstantiation {
        full,
        base,
        type_args,
        shape_args,
        from_function,
        concrete_candidates: Vec::new(),
    })
}

fn strip_type_constructor_prefix(wrapped: &str) -> &str {
    let bytes: &[u8] = wrapped.as_bytes();
    let mut start: usize = wrapped.len();
    while start > 0 {
        let b: u8 = bytes[start - 1];
        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'/') {
            start -= 1;
        } else {
            break;
        }
    }
    &wrapped[start..]
}

fn normalize_base(wrapped: &str) -> Option<String> {
    let tail: &str = strip_type_constructor_prefix(wrapped);
    let head: &str = &wrapped[..wrapped.len() - tail.len()];
    let receiver: Option<&str> = head
        .strip_suffix("(*")
        .or_else(|| head.strip_suffix('('))
        .filter(|pre: &&str| pre.ends_with('.'));
    let Some(pre): Option<&str> = receiver else {
        return Some(tail.to_owned());
    };
    let pkg_raw: &str = strip_type_constructor_prefix(pre);
    let pkg: &str = pkg_raw.strip_suffix('.').unwrap_or(pkg_raw);
    if pkg.is_empty() {
        return None;
    }
    Some(format!("{pkg}.{tail}"))
}

fn first_top_level_open_bracket(name: &str) -> Option<usize> {
    let bytes: &[u8] = name.as_bytes();
    let mut depth: i32 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'[' if depth == 0 => {
                let prev: u8 = if i == 0 { 0 } else { bytes[i - 1] };
                if prev.is_ascii_alphanumeric() || prev == b'_' || prev == b'}' || prev == b')' {
                    return Some(i);
                }
                depth += 1;
            }
            b'[' => depth += 1,
            b']' if depth > 0 => depth -= 1,
            _ => {}
        }
    }
    None
}

fn matching_close_bracket(name: &str, open: usize) -> Option<usize> {
    let bytes: &[u8] = name.as_bytes();
    let mut depth: i32 = 0;
    for (i, &b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_top_level_commas(inner: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut depth: i32 = 0;
    let mut start: usize = 0;
    let bytes: &[u8] = inner.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'[' | b'{' | b'(' => depth += 1,
            b']' | b'}' | b')' => depth = (depth - 1).max(0),
            b',' if depth == 0 => {
                out.push(inner[start..i].trim().to_owned());
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(inner[start..].trim().to_owned());
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AbiTypeLayout {
    name_decoder: NameDecoder,
    kind_off: u64,
    str_off: u64,
    ptr_size: u64,
    base_type_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NameDecoder {
    Pre117BigEndianLen,

    Varint,
}

const ABI_TYPE_64_KIND_OFF: u64 = 23;
const ABI_TYPE_64_STR_OFF: u64 = 40;
const ABI_TYPE_64_BASE_SIZE: u64 = 48;
const ABI_TYPE_32_KIND_OFF: u64 = 15;
const ABI_TYPE_32_STR_OFF: u64 = 24;
const ABI_TYPE_32_BASE_SIZE: u64 = 32;

const ABI_TFLAG_UNCOMMON: u8 = 1 << 0;

const KIND_MASK: u8 = 0x1f;
const NAME_VARINT_MAX_BYTES: usize = 5;
const MAX_TYPE_NAME_LEN: usize = 1024;

const KIND_ARRAY: u8 = 17;
const KIND_CHAN: u8 = 18;
const KIND_FUNC: u8 = 19;
const KIND_INTERFACE: u8 = 20;
const KIND_MAP: u8 = 21;
const KIND_PTR: u8 = 22;
const KIND_SLICE: u8 = 23;
const KIND_STRUCT: u8 = 25;

const MAX_METHODS_PER_TYPE: u16 = 1 << 12;

fn infer_layout(md: &Moduledata, ptr_size: u8) -> AbiTypeLayout {
    let version: PclntabVersion =
        infer_version_from_build(md.buildversion.as_deref()).unwrap_or(PclntabVersion::Go120);
    layout_for_version(version, ptr_size == 8)
}

fn infer_version_from_build(build: Option<&str>) -> Option<PclntabVersion> {
    let s: &str = build?;
    let rest: &str = s.strip_prefix("go1.")?;
    let dot: usize = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    let minor: u32 = rest[..dot].parse().ok()?;
    Some(match minor {
        0..=15 => PclntabVersion::Go12,
        16..=17 => PclntabVersion::Go116,
        18..=19 => PclntabVersion::Go118,
        _ => PclntabVersion::Go120,
    })
}

const fn layout_for_version(version: PclntabVersion, sixty_four_bit: bool) -> AbiTypeLayout {
    let (kind_off, str_off, base_type_size, ptr_size): (u64, u64, u64, u64) = if sixty_four_bit {
        (
            ABI_TYPE_64_KIND_OFF,
            ABI_TYPE_64_STR_OFF,
            ABI_TYPE_64_BASE_SIZE,
            8,
        )
    } else {
        (
            ABI_TYPE_32_KIND_OFF,
            ABI_TYPE_32_STR_OFF,
            ABI_TYPE_32_BASE_SIZE,
            4,
        )
    };
    let name_decoder: NameDecoder = match version {
        PclntabVersion::Go12 | PclntabVersion::Go116 => NameDecoder::Pre117BigEndianLen,
        PclntabVersion::Go118 | PclntabVersion::Go120 => NameDecoder::Varint,
    };
    AbiTypeLayout {
        name_decoder,
        kind_off,
        str_off,
        ptr_size,
        base_type_size,
    }
}

fn read_type_kind(image: &GoImage<'_>, type_va: u64, layout: AbiTypeLayout) -> Option<u8> {
    let buf: &[u8] = image.data_at_va(type_va.wrapping_add(layout.kind_off), 1)?;
    Some(buf[0] & KIND_MASK)
}

fn read_type_name(
    image: &GoImage<'_>,
    md: &Moduledata,
    type_va: u64,
    layout: AbiTypeLayout,
) -> Option<String> {
    if md.types_va == 0 {
        return None;
    }
    let nameoff: u32 = image.read_u32(type_va.wrapping_add(layout.str_off))?;
    if nameoff == 0 {
        return None;
    }
    let nameoff_u64: u64 = u64::from(nameoff);
    if let Some(types_blob_len) = md.etypes_va.checked_sub(md.types_va)
        && types_blob_len != 0
        && nameoff_u64 >= types_blob_len
    {
        return None;
    }
    let name_va: u64 = md.types_va.wrapping_add(nameoff_u64);
    decode_go_name(image, name_va, layout.name_decoder)
}

const METHOD_ENTRY_SIZE: u64 = 16;
const METHOD_NAMEOFF_OFF: u64 = 0;
const METHOD_TFN_OFF: u64 = 12;
const UNCOMMON_MCOUNT_OFF: u64 = 4;
const UNCOMMON_XCOUNT_OFF: u64 = 6;
const UNCOMMON_MOFF_OFF: u64 = 8;
const TEXTOFF_ABSENT: u32 = u32::MAX;

const fn kind_extra_size(kind: u8, ps: u64) -> Option<u64> {
    let words: u64 = match kind {
        KIND_PTR | KIND_SLICE => 1,
        KIND_CHAN => 2,
        KIND_ARRAY | KIND_INTERFACE | KIND_STRUCT => 3,
        KIND_MAP => map_type_extra_words(ps),
        KIND_FUNC => return Some(func_type_extra_size(ps)),
        _ => 0,
    };
    words.checked_mul(ps)
}

const fn func_type_extra_size(ps: u64) -> u64 {
    if ps == 8 { 8 } else { 4 }
}

const fn map_type_extra_words(_ps: u64) -> u64 {
    8
}

fn uncommon_va(type_va: u64, kind: u8, layout: AbiTypeLayout) -> Option<u64> {
    let extra: u64 = kind_extra_size(kind, layout.ptr_size)?;
    let type_struct_size: u64 = layout.base_type_size.checked_add(extra)?;
    type_va.checked_add(type_struct_size)
}

fn read_type_methods(
    image: &GoImage<'_>,
    md: &Moduledata,
    type_va: u64,
    kind: u8,
    layout: AbiTypeLayout,
) -> Vec<GoMethod> {
    if md.types_va == 0 {
        return Vec::new();
    }
    let tflag_off: u64 = layout.kind_off.wrapping_sub(3);
    let Some(tflag_byte): Option<&[u8]> = image.data_at_va(type_va.wrapping_add(tflag_off), 1)
    else {
        return Vec::new();
    };
    if tflag_byte[0] & ABI_TFLAG_UNCOMMON == 0 {
        return Vec::new();
    }
    let Some(uncommon): Option<u64> = uncommon_va(type_va, kind, layout) else {
        return Vec::new();
    };
    let Some(mcount): Option<u16> = read_u16(image, uncommon.wrapping_add(UNCOMMON_MCOUNT_OFF))
    else {
        return Vec::new();
    };
    if mcount == 0 || mcount > MAX_METHODS_PER_TYPE {
        return Vec::new();
    }
    let xcount: u16 = read_u16(image, uncommon.wrapping_add(UNCOMMON_XCOUNT_OFF)).unwrap_or(0);
    let Some(moff): Option<u32> = image.read_u32(uncommon.wrapping_add(UNCOMMON_MOFF_OFF)) else {
        return Vec::new();
    };
    let Some(methods_base): Option<u64> = uncommon.checked_add(u64::from(moff)) else {
        return Vec::new();
    };
    let types_blob_len: Option<u64> = md
        .etypes_va
        .checked_sub(md.types_va)
        .filter(|len: &u64| *len != 0);
    let mut out: Vec<GoMethod> = Vec::with_capacity(mcount as usize);
    for i in 0..mcount {
        let Some(entry_va): Option<u64> =
            methods_base.checked_add(u64::from(i) * METHOD_ENTRY_SIZE)
        else {
            break;
        };
        let Some(method): Option<GoMethod> =
            read_one_method(image, md, entry_va, layout, types_blob_len, i < xcount)
        else {
            continue;
        };
        out.push(method);
    }
    out
}

fn read_one_method(
    image: &GoImage<'_>,
    md: &Moduledata,
    entry_va: u64,
    layout: AbiTypeLayout,
    types_blob_len: Option<u64>,
    exported: bool,
) -> Option<GoMethod> {
    let nameoff: u32 = image.read_u32(entry_va.wrapping_add(METHOD_NAMEOFF_OFF))?;
    let tfn: u32 = image
        .read_u32(entry_va.wrapping_add(METHOD_TFN_OFF))
        .unwrap_or(TEXTOFF_ABSENT);
    let name: Option<String> = if nameoff == 0 {
        None
    } else {
        let nameoff_u64: u64 = u64::from(nameoff);
        if types_blob_len.is_some_and(|len: u64| nameoff_u64 >= len) {
            None
        } else {
            let name_va: u64 = md.types_va.wrapping_add(nameoff_u64);
            decode_method_name(image, name_va, layout.name_decoder)
        }
    };
    let func_va: u64 = if tfn == TEXTOFF_ABSENT || md.text_va == 0 {
        0
    } else {
        md.text_va.wrapping_add(u64::from(tfn))
    };
    if name.is_none() && func_va == 0 {
        return None;
    }
    Some(GoMethod {
        name,
        func_va,
        linker_name: None,
        exported,
    })
}

fn read_u16(image: &GoImage<'_>, va: u64) -> Option<u16> {
    let buf: &[u8] = image.data_at_va(va, 2)?;
    let arr: [u8; 2] = buf.try_into().ok()?;
    Some(match image.endian {
        crate::binary::Endian::Little => u16::from_le_bytes(arr),
        crate::binary::Endian::Big => u16::from_be_bytes(arr),
    })
}

fn decode_method_name(image: &GoImage<'_>, name_va: u64, decoder: NameDecoder) -> Option<String> {
    let raw: String = decode_go_name(image, name_va, decoder)?;
    if plausible_method_name(&raw) {
        Some(raw)
    } else {
        None
    }
}

fn plausible_method_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_TYPE_NAME_LEN
        && s.chars()
            .next()
            .is_some_and(|c: char| c.is_ascii_alphabetic() || c == '_' || !c.is_ascii())
        && s.chars()
            .all(|c: char| c.is_ascii_alphanumeric() || c == '_' || !c.is_ascii())
}

fn decode_go_name(image: &GoImage<'_>, name_va: u64, decoder: NameDecoder) -> Option<String> {
    match decoder {
        NameDecoder::Pre117BigEndianLen => decode_pre117(image, name_va),
        NameDecoder::Varint => decode_varint(image, name_va),
    }
}

fn decode_pre117(image: &GoImage<'_>, name_va: u64) -> Option<String> {
    let header: &[u8] = image.data_at_va(name_va, 3)?;
    let len: usize = (usize::from(header[1]) << 8) | usize::from(header[2]);
    if len == 0 || len > MAX_TYPE_NAME_LEN {
        return None;
    }
    let body: &[u8] = image.data_at_va(name_va.wrapping_add(3), len)?;
    let text: &str = std::str::from_utf8(body).ok()?;
    if !plausible_type_name(text) {
        return None;
    }
    Some(text.to_owned())
}

fn decode_varint(image: &GoImage<'_>, name_va: u64) -> Option<String> {
    let header: &[u8] = image.data_at_va(name_va, 1 + NAME_VARINT_MAX_BYTES)?;
    let (consumed, len_val): (usize, u64) = read_varint(&header[1..])?;
    if len_val == 0 || len_val > MAX_TYPE_NAME_LEN as u64 {
        return None;
    }
    let len: usize = len_val as usize;
    let name_body_va: u64 = name_va.wrapping_add(1 + consumed as u64);
    let body: &[u8] = image.data_at_va(name_body_va, len)?;
    let text: &str = std::str::from_utf8(body).ok()?;
    if !plausible_type_name(text) {
        return None;
    }
    Some(text.to_owned())
}

fn read_varint(buf: &[u8]) -> Option<(usize, u64)> {
    let mut v: u64 = 0;
    for (i, &x) in buf.iter().take(NAME_VARINT_MAX_BYTES).enumerate() {
        v |= u64::from(x & 0x7f) << (7 * i);
        if x & 0x80 == 0 {
            return Some((i + 1, v));
        }
    }
    None
}

fn plausible_type_name(s: &str) -> bool {
    if s.len() < 2 {
        return false;
    }
    s.chars().all(|c: char| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '_' | '.'
                    | '/'
                    | '*'
                    | '['
                    | ']'
                    | '{'
                    | '}'
                    | '('
                    | ')'
                    | ' '
                    | '-'
                    | '<'
                    | '>'
                    | ','
                    | ';'
            )
    }) && s.chars().any(|c: char| c.is_ascii_alphabetic())
}

#[must_use]
pub const fn type_kind_label(kind: u8) -> &'static str {
    match kind & KIND_MASK {
        1 => "bool",
        2 => "int",
        3 => "int8",
        4 => "int16",
        5 => "int32",
        6 => "int64",
        7 => "uint",
        8 => "uint8",
        9 => "uint16",
        10 => "uint32",
        11 => "uint64",
        12 => "uintptr",
        13 => "float32",
        14 => "float64",
        15 => "complex64",
        16 => "complex128",
        17 => "array",
        18 => "chan",
        19 => "func",
        20 => "interface",
        21 => "map",
        22 => "ptr",
        23 => "slice",
        24 => "string",
        25 => "struct",
        26 => "unsafe.Pointer",
        _ => "invalid",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn plausible_rejects_garbage_and_control() {
        assert!(!plausible_type_name(""));
        assert!(!plausible_type_name("_"));
        assert!(!plausible_type_name("\u{1}\u{2}"));
        assert!(!plausible_type_name("123"));
    }

    #[test]
    fn generic_parse_function_instantiation() {
        let g: GoGenericInstantiation = parse_generic_name("main.Sum[go.shape.int]", true).unwrap();
        assert_eq!(g.base, "main.Sum");
        assert_eq!(g.type_args, vec!["go.shape.int".to_owned()]);
        assert!(g.shape_args);
        assert!(g.from_function);
        assert_eq!(g.full, "main.Sum[go.shape.int]");
    }

    #[test]
    fn generic_parse_multi_arg_with_commas() {
        let g: GoGenericInstantiation =
            parse_generic_name("main.MapKeys[go.shape.string,go.shape.int]", true).unwrap();
        assert_eq!(
            g.type_args,
            vec!["go.shape.string".to_owned(), "go.shape.int".to_owned()]
        );
    }

    #[test]
    fn generic_parse_method_on_generic_receiver() {
        let g: GoGenericInstantiation =
            parse_generic_name("main.Box[go.shape.int].Describe", true).unwrap();
        assert_eq!(g.base, "main.Box");
        assert_eq!(g.full, "main.Box[go.shape.int]");
        assert_eq!(g.type_args, vec!["go.shape.int".to_owned()]);
    }

    #[test]
    fn generic_parse_nested_interface_arg() {
        let g: GoGenericInstantiation =
            parse_generic_name("sync.HashTrieMap[interface {},interface {}]", false).unwrap();
        assert_eq!(g.base, "sync.HashTrieMap");
        assert_eq!(
            g.type_args,
            vec!["interface {}".to_owned(), "interface {}".to_owned()]
        );
        assert!(!g.shape_args);
    }

    #[test]
    fn generic_parse_rejects_non_generic_bracket_forms() {
        assert!(parse_generic_name("[]uint8", false).is_none());
        assert!(parse_generic_name("[8]int", false).is_none());
        assert!(parse_generic_name("map[string]int", false).is_none());
        assert!(parse_generic_name("runtime.g", false).is_none());
        assert!(parse_generic_name("type:.eq.foo[go.shape.int]", true).is_none());
    }

    #[test]
    fn generic_base_strips_pointer_constructor() {
        let g: GoGenericInstantiation = parse_generic_name("*main.Box[int]", false).unwrap();
        assert_eq!(g.base, "main.Box");
        assert_eq!(g.full, "main.Box[int]");
        assert_eq!(g.type_args, vec!["int".to_owned()]);
    }

    #[test]
    fn generic_base_strips_array_and_pointer_chain() {
        let g: GoGenericInstantiation = parse_generic_name(
            "*[16]atomic.Pointer[internal/sync.node[interface {},interface {}]]",
            false,
        )
        .unwrap();
        assert_eq!(g.base, "atomic.Pointer");
        assert_eq!(
            g.full,
            "atomic.Pointer[internal/sync.node[interface {},interface {}]]"
        );
        assert_eq!(
            g.type_args,
            vec!["internal/sync.node[interface {},interface {}]".to_owned()]
        );
    }

    #[test]
    fn generic_base_strips_func_return_constructor() {
        let g: GoGenericInstantiation =
            parse_generic_name("*func() iter.Seq[reflect.Type]", false).unwrap();
        assert_eq!(g.base, "iter.Seq");
        assert_eq!(g.full, "iter.Seq[reflect.Type]");
    }

    #[test]
    fn generic_base_strips_slice_and_keeps_import_path() {
        let g: GoGenericInstantiation =
            parse_generic_name("[]*internal/sync.entry[go.shape.interface {}]", false).unwrap();
        assert_eq!(g.base, "internal/sync.entry");
        assert!(g.shape_args);
    }

    #[test]
    fn generic_rejects_compiler_eq_and_itab_namespaces() {
        assert!(parse_generic_name("type:.eq.main.Box[int]", true).is_none());
        assert!(parse_generic_name("go:itab.main.Box[int],main.Stringer", true).is_none());
        assert!(parse_generic_name(".eq.sync/atomic.Pointer[os.dirInfo]", true).is_none());
    }

    #[test]
    fn compiler_eq_symbols_are_not_instantiations_but_their_args_are_mined() {
        let funcs: [&str; 3] = [
            "main.(*Tree[go.shape.int]).Insert",
            "type:.eq.main.Tree[int]",
            "type:.eq.main.Box[string]",
        ];
        let out: Vec<GoGenericInstantiation> = parse_generic_type_info(funcs, std::iter::empty());

        assert!(
            out.iter().all(|g: &GoGenericInstantiation| {
                !g.base.starts_with("type:")
                    && !g.base.starts_with("go:")
                    && !g.full.contains("type:")
            }),
            "type:/go: linker symbols must never appear as instantiations: {out:?}"
        );

        let tree: &GoGenericInstantiation = out
            .iter()
            .find(|g: &&GoGenericInstantiation| g.base == "main.Tree")
            .expect("the shape Tree body becomes an instantiation");
        assert_eq!(
            tree.type_args,
            vec!["int".to_owned()],
            "the concrete arg mined from type:.eq.main.Tree[int] lifts the shape body"
        );
        assert!(!tree.shape_args);
        assert_eq!(tree.full, "main.Tree[int]");
    }

    #[test]
    fn harvest_mines_concrete_args_across_namespaces() {
        let names: [&str; 5] = [
            "type:.eq.main.Box[int]",
            "main.Box[string].String",
            "main.(*Tree[go.shape.int]).Insert",
            "go:itab.main.Box[int],main.Stringer",
            "type:.eq.sync/atomic.Pointer[os.dirInfo]",
        ];
        let map: ConcreteArgMap = harvest_concrete_args(names);

        let box_concretes: &BTreeSet<Vec<String>> =
            map.get("main.Box").expect("Box concretes mined");
        assert!(box_concretes.contains(&vec!["int".to_owned()]));
        assert!(box_concretes.contains(&vec!["string".to_owned()]));

        assert!(
            !map.contains_key("main.Tree"),
            "a go.shape body is not concrete evidence and must not be mined"
        );

        let ptr: &BTreeSet<Vec<String>> = map
            .get("sync/atomic.Pointer")
            .expect("Pointer concrete mined from type:.eq descriptor");
        assert!(ptr.contains(&vec!["os.dirInfo".to_owned()]));
    }

    #[test]
    fn disambiguate_lifts_single_concrete_and_keeps_shape_when_no_sibling() {
        let funcs: [&str; 3] = [
            "main.(*Tree[go.shape.int]).InOrder",
            "type:.eq.main.Tree[int]",
            "slices.pdqsortOrdered[go.shape.string]",
        ];
        let out: Vec<GoGenericInstantiation> = parse_generic_type_info(funcs, std::iter::empty());

        let tree: &GoGenericInstantiation = out
            .iter()
            .find(|g: &&GoGenericInstantiation| g.base == "main.Tree")
            .expect("Tree present");
        assert!(!tree.shape_args);
        assert_eq!(tree.type_args, vec!["int".to_owned()]);
        assert!(tree.concrete_candidates.is_empty());

        let sorted: &GoGenericInstantiation = out
            .iter()
            .find(|g: &&GoGenericInstantiation| g.base == "slices.pdqsortOrdered")
            .expect("genuine-wall free function present");
        assert!(
            sorted.shape_args,
            "a shape-only free function with no concrete sibling stays an honest shape wall"
        );
        assert_eq!(sorted.type_args, vec!["go.shape.string".to_owned()]);
        assert!(sorted.concrete_candidates.is_empty());
    }

    #[test]
    fn disambiguate_surfaces_full_candidate_set_when_concretes_are_merged() {
        let funcs: [&str; 3] = [
            "main.Box[go.shape.int].String",
            "main.Box[int].String",
            "main.Box[string].String",
        ];
        let out: Vec<GoGenericInstantiation> = parse_generic_type_info(funcs, std::iter::empty());

        let shape_box: &GoGenericInstantiation = out
            .iter()
            .find(|g: &&GoGenericInstantiation| g.base == "main.Box" && g.shape_args)
            .expect("the go.shape Box body survives ambiguous merge");
        assert_eq!(
            shape_box.concrete_candidates,
            vec![vec!["int".to_owned()], vec!["string".to_owned()]],
            "multiple distinct concretes for one shape surface the full candidate set"
        );
        assert!(
            shape_box.shape_args,
            "an ambiguous shape->concrete merge stays shape (we never invent the pick)"
        );
    }

    #[test]
    fn same_short_name_generics_from_distinct_packages_never_wrong_single_lift() {
        let funcs: [&str; 2] = [
            "type:.eq.sync/atomic.Pointer[os.dirInfo]",
            "type:.eq.internal/runtime/atomic.Pointer[runtime.mspan]",
        ];
        let types: [&str; 1] = ["atomic.Pointer[go.shape.struct {}]"];
        let out: Vec<GoGenericInstantiation> = parse_generic_type_info(funcs, types);

        let shape: &GoGenericInstantiation = out
            .iter()
            .find(|g: &&GoGenericInstantiation| g.base == "atomic.Pointer" && g.shape_args)
            .expect("the short-named shape body survives");
        assert!(
            shape.shape_args,
            "two distinct packages share the short base atomic.Pointer, so no single concrete may \
             be picked from one package and stamped onto the other: {shape:?}"
        );
        assert!(
            shape
                .concrete_candidates
                .contains(&vec!["os.dirInfo".to_owned()])
                && shape
                    .concrete_candidates
                    .contains(&vec!["runtime.mspan".to_owned()]),
            "the colliding candidate set must surface both packages' concretes, never invent one \
             winner: {:?}",
            shape.concrete_candidates
        );
        assert!(
            out.iter().all(|g: &GoGenericInstantiation| {
                g.shape_args
                    || g.base.contains('/')
                    || g.type_args
                        .iter()
                        .all(|a: &String| a == "os.dirInfo" || a == "runtime.mspan")
            }),
            "no lift may stamp a wrong concrete onto a cross-package short-name collision: {out:?}"
        );
    }

    #[test]
    fn generic_harvest_dedups_and_sorts() {
        let funcs: [&str; 3] = [
            "main.Sum[go.shape.int]",
            "main.Sum[go.shape.int]",
            "main.Sum[go.shape.float64]",
        ];
        let types: [&str; 1] = ["sync.Map[interface {},interface {}]"];
        let out: Vec<GoGenericInstantiation> = parse_generic_type_info(funcs, types);
        assert_eq!(out.len(), 3);
        assert!(out.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn plausible_accepts_go_type_names() {
        assert!(plausible_type_name("main.buildInfo"));
        assert!(plausible_type_name("*os.File"));
        assert!(plausible_type_name("[]uint8"));
        assert!(plausible_type_name("map[string]int"));
        assert!(plausible_type_name("func(int) error"));
    }

    #[test]
    fn kind_labels_cover_scalar_and_composite() {
        assert_eq!(type_kind_label(25), "struct");
        assert_eq!(type_kind_label(20), "interface");
        assert_eq!(type_kind_label(22), "ptr");
        assert_eq!(type_kind_label(0), "invalid");
    }

    #[test]
    fn varint_single_byte() {
        let (consumed, v): (usize, u64) = read_varint(&[0x0e]).expect("varint");
        assert_eq!(consumed, 1);
        assert_eq!(v, 14);
    }

    #[test]
    fn varint_two_byte_continuation() {
        let (consumed, v): (usize, u64) = read_varint(&[0xc2, 0x01]).expect("varint");
        assert_eq!(consumed, 2);
        assert_eq!(v, 0xc2);
    }

    #[test]
    fn varint_rejects_runaway() {
        let runaway: [u8; 6] = [0x80, 0x80, 0x80, 0x80, 0x80, 0x01];
        assert!(read_varint(&runaway).is_none());
    }

    #[test]
    fn layout_for_go126_is_varint_64() {
        let layout: AbiTypeLayout = layout_for_version(PclntabVersion::Go120, true);
        assert_eq!(layout.name_decoder, NameDecoder::Varint);
        assert_eq!(layout.kind_off, ABI_TYPE_64_KIND_OFF);
        assert_eq!(layout.str_off, ABI_TYPE_64_STR_OFF);
    }

    #[test]
    fn layout_for_go115_is_be_64() {
        let layout: AbiTypeLayout = layout_for_version(PclntabVersion::Go12, true);
        assert_eq!(layout.name_decoder, NameDecoder::Pre117BigEndianLen);
    }

    #[test]
    fn buildversion_dispatch_routes_to_varint_for_go126() {
        let v: Option<PclntabVersion> = infer_version_from_build(Some("go1.26.3"));
        assert_eq!(v, Some(PclntabVersion::Go120));
    }

    #[test]
    fn buildversion_dispatch_routes_to_pre117_for_old() {
        let v: Option<PclntabVersion> = infer_version_from_build(Some("go1.15.6"));
        assert_eq!(v, Some(PclntabVersion::Go12));
    }
}
