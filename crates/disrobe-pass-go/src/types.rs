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

    GoTypeMeta {
        types,
        itabs,
        strings: strings.into_iter().collect(),
    }
}

/// `abi.Type` (Go 1.17+ "stable") field byte offsets for a 64-bit target.
///
/// Layout reference: `internal/abi/type.go` at go1.26.3
/// (commit-pinned via `git tag go1.26.3`). Field order:
///
/// | field         | go type           | offset | size |
/// |---------------|-------------------|-------:|-----:|
/// | `Size_`       | uintptr           |     0  |   8  |
/// | `PtrBytes`    | uintptr           |     8  |   8  |
/// | `Hash`        | uint32            |    16  |   4  |
/// | `TFlag`       | uint8             |    20  |   1  |
/// | `Align_`      | uint8             |    21  |   1  |
/// | `FieldAlign_` | uint8             |    22  |   1  |
/// | `Kind_`       | uint8             |    23  |   1  |
/// | `Equal`       | func pointer      |    24  |   8  |
/// | `GCData`      | `*byte`           |    32  |   8  |
/// | `Str`         | `NameOff` (int32) |    40  |   4  |
/// | `PtrToThis`   | `TypeOff` (int32) |    44  |   4  |
///
/// Total = 48 bytes on amd64. `Str` is the `NameOff` (int32) offset into
/// `md.types` whose target is a `name` struct (1 byte flags, varint length,
/// bytes). Layout is identical from go1.18 through go1.26.3.
///
/// On 32-bit Go targets pointer/uintptr widths collapse to 4 bytes, so the
/// offsets compact to: `Size_`=0, `PtrBytes`=4, `Hash`=8, `TFlag`=12,
/// `Align_`=13, `FieldAlign_`=14, `Kind_`=15, `Equal`=16, `GCData`=20,
/// `Str`=24, `PtrToThis`=28.
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
    /// `Str` field is a `NameOff` int32 offset into the `md.types` base.
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
