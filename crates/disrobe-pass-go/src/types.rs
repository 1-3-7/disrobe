use std::collections::BTreeSet;

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

/// A recovered Go 1.18+ generic instantiation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GoGenericInstantiation {
    pub full: String,
    pub base: String,
    pub type_args: Vec<String>,
    pub shape_args: bool,
    pub from_function: bool,
}

const TYPELINKS_WALK_CAP: usize = 1 << 14;
const ITABLINKS_WALK_CAP: usize = 1 << 14;

pub fn extract_typemeta(image: &GoImage<'_>, md: &Moduledata) -> GoTypeMeta {
    extract_typemeta_versioned(image, md, infer_layout(md))
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
            types.push(GoTypeRef {
                va: type_va,
                name,
                kind,
                kind_label,
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

const GENERIC_SHAPE_PREFIX: &str = "go.shape.";

/// Recover Go 1.18+ generic instantiations from already-extracted names.
#[must_use]
pub fn parse_generic_type_info<'a, F, T>(
    func_names: F,
    type_names: T,
) -> Vec<GoGenericInstantiation>
where
    F: IntoIterator<Item = &'a str>,
    T: IntoIterator<Item = &'a str>,
{
    let mut out: BTreeSet<GoGenericInstantiation> = BTreeSet::new();
    for name in func_names {
        if let Some(inst) = parse_generic_name(name, true) {
            out.insert(inst);
        }
    }
    for name in type_names {
        if let Some(inst) = parse_generic_name(name, false) {
            out.insert(inst);
        }
    }
    out.into_iter().collect()
}

/// Parse a single generic instantiation string.
#[must_use]
pub fn parse_generic_name(name: &str, from_function: bool) -> Option<GoGenericInstantiation> {
    let open: usize = first_top_level_open_bracket(name)?;
    if open == 0 {
        return None;
    }
    let close: usize = matching_close_bracket(name, open)?;
    if close != name.len().saturating_sub(1) && !name[close + 1..].starts_with('.') {
        return None;
    }
    let base: &str = &name[..open];
    if base.is_empty() || !base.contains('.') {
        return None;
    }
    if base.starts_with("type:") || base.starts_with("go:") {
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
    Some(GoGenericInstantiation {
        full: name[..=close].to_owned(),
        base: base.to_owned(),
        type_args,
        shape_args,
        from_function,
    })
}

/// The first `[` that begins a generic type-arg list.
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
            b']' | b'}' | b')' => depth -= 1,
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

/// `abi.Type` field byte offsets for a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AbiTypeLayout {
    name_decoder: NameDecoder,
    kind_off: u64,
    str_off: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NameDecoder {
    /// Go 1.7..1.16: 1 byte flags + 2-byte big-endian length + bytes.
    Pre117BigEndianLen,
    /// Go 1.17+: 1 byte flags + varint length (1..=5 bytes) + bytes.
    Varint,
}

const ABI_TYPE_64_KIND_OFF: u64 = 23;
const ABI_TYPE_64_STR_OFF: u64 = 40;
const ABI_TYPE_32_KIND_OFF: u64 = 15;
const ABI_TYPE_32_STR_OFF: u64 = 24;

const KIND_MASK: u8 = 0x1f;
const NAME_VARINT_MAX_BYTES: usize = 5;
const MAX_TYPE_NAME_LEN: usize = 1024;

fn infer_layout(md: &Moduledata) -> AbiTypeLayout {
    let version: PclntabVersion =
        infer_version_from_build(md.buildversion.as_deref()).unwrap_or(PclntabVersion::Go120);
    layout_for_version(version, true)
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
    let (kind_off, str_off): (u64, u64) = if sixty_four_bit {
        (ABI_TYPE_64_KIND_OFF, ABI_TYPE_64_STR_OFF)
    } else {
        (ABI_TYPE_32_KIND_OFF, ABI_TYPE_32_STR_OFF)
    };
    let name_decoder: NameDecoder = match version {
        PclntabVersion::Go12 | PclntabVersion::Go116 => NameDecoder::Pre117BigEndianLen,
        PclntabVersion::Go118 | PclntabVersion::Go120 => NameDecoder::Varint,
    };
    AbiTypeLayout {
        name_decoder,
        kind_off,
        str_off,
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
