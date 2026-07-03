use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::axml::{ResourceIdResolver, format_res_value};
use crate::error::{Error, Result};

pub const RES_NULL_TYPE: u16 = 0x0000;
pub const RES_STRING_POOL_TYPE: u16 = 0x0001;
pub const RES_TABLE_TYPE: u16 = 0x0002;
pub const RES_TABLE_PACKAGE_TYPE: u16 = 0x0200;
pub const RES_TABLE_TYPE_TYPE: u16 = 0x0201;
pub const RES_TABLE_TYPE_SPEC_TYPE: u16 = 0x0202;
pub const RES_STRING_POOL_UTF8_FLAG: u32 = 0x0100;

const CHUNK_HEADER_SIZE: usize = 8;
const PACKAGE_NAME_UNITS: usize = 128;
const ENTRY_FLAG_COMPLEX: u16 = 0x0001;
const NO_ENTRY: u32 = 0xFFFF_FFFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResChunkHeader {
    pub type_: u16,
    pub header_size: u16,
    pub size: u32,
}

#[inline]
fn read_u16(bytes: &[u8], off: usize) -> Result<u16> {
    bytes
        .get(off..off + 2)
        .map(|s: &[u8]| u16::from_le_bytes([s[0], s[1]]))
        .ok_or(Error::ArscTruncated {
            offset: off,
            needed: 2,
            had: bytes.len(),
        })
}

#[inline]
fn read_u32(bytes: &[u8], off: usize) -> Result<u32> {
    bytes
        .get(off..off + 4)
        .map(|s: &[u8]| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(Error::ArscTruncated {
            offset: off,
            needed: 4,
            had: bytes.len(),
        })
}

fn read_chunk_header(bytes: &[u8], off: usize) -> Result<ResChunkHeader> {
    if off
        .checked_add(CHUNK_HEADER_SIZE)
        .is_none_or(|end: usize| end > bytes.len())
    {
        return Err(Error::ArscTruncated {
            offset: off,
            needed: CHUNK_HEADER_SIZE,
            had: bytes.len(),
        });
    }
    Ok(ResChunkHeader {
        type_: read_u16(bytes, off)?,
        header_size: read_u16(bytes, off + 2)?,
        size: read_u32(bytes, off + 4)?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResStringPool {
    pub flags: u32,
    pub is_utf8: bool,
    pub strings: Vec<String>,
}

#[inline]
fn decode_utf8_len(bytes: &[u8], cursor: usize) -> Result<(usize, usize)> {
    let b0: u8 = *bytes.get(cursor).ok_or(Error::ArscTruncated {
        offset: cursor,
        needed: 1,
        had: bytes.len(),
    })?;
    if (b0 & 0x80) != 0 {
        let b1: u8 = *bytes.get(cursor + 1).ok_or(Error::ArscTruncated {
            offset: cursor + 1,
            needed: 1,
            had: bytes.len(),
        })?;
        Ok(((usize::from(b0 & 0x7F) << 8) | usize::from(b1), cursor + 2))
    } else {
        Ok((usize::from(b0), cursor + 1))
    }
}

#[inline]
fn decode_utf16_len(bytes: &[u8], cursor: usize) -> Result<(usize, usize)> {
    let first: u16 = read_u16(bytes, cursor)?;
    if (first & 0x8000) != 0 {
        let second: u16 = read_u16(bytes, cursor + 2)?;
        Ok((
            ((usize::from(first & 0x7FFF)) << 16) | usize::from(second),
            cursor + 4,
        ))
    } else {
        Ok((usize::from(first), cursor + 2))
    }
}

fn decode_modified_utf8(raw: &[u8]) -> String {
    let mut out: String = String::with_capacity(raw.len());
    let mut i: usize = 0;
    while i < raw.len() {
        let b1: u8 = raw[i];
        if b1 < 0x80 {
            out.push(b1 as char);
            i += 1;
        } else if (b1 & 0xE0) == 0xC0 && i + 1 < raw.len() {
            let cp: u32 = (u32::from(b1 & 0x1F) << 6) | u32::from(raw[i + 1] & 0x3F);
            if let Some(ch) = char::from_u32(cp) {
                out.push(ch);
            }
            i += 2;
        } else if (b1 & 0xF0) == 0xE0 && i + 2 < raw.len() {
            let cp: u32 = (u32::from(b1 & 0x0F) << 12)
                | (u32::from(raw[i + 1] & 0x3F) << 6)
                | u32::from(raw[i + 2] & 0x3F);
            if let Some(ch) = char::from_u32(cp) {
                out.push(ch);
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    out
}

fn parse_string_pool(bytes: &[u8], chunk_off: usize) -> Result<ResStringPool> {
    let header: ResChunkHeader = read_chunk_header(bytes, chunk_off)?;
    if header.type_ != RES_STRING_POOL_TYPE {
        return Err(Error::ArscTruncated {
            offset: chunk_off,
            needed: usize::from(RES_STRING_POOL_TYPE),
            had: usize::from(header.type_),
        });
    }
    let string_count: u32 = read_u32(bytes, chunk_off + 8)?;
    let _style_count: u32 = read_u32(bytes, chunk_off + 12)?;
    let flags: u32 = read_u32(bytes, chunk_off + 16)?;
    let strings_start: u32 = read_u32(bytes, chunk_off + 20)?;
    let _styles_start: u32 = read_u32(bytes, chunk_off + 24)?;
    let is_utf8: bool = (flags & RES_STRING_POOL_UTF8_FLAG) != 0;

    let index_base: usize = chunk_off
        .checked_add(usize::from(header.header_size))
        .ok_or_else(|| Error::ArscTruncated {
            offset: chunk_off,
            needed: usize::from(header.header_size),
            had: bytes.len(),
        })?;
    let data_base: usize =
        chunk_off
            .checked_add(strings_start as usize)
            .ok_or(Error::ArscTruncated {
                offset: chunk_off,
                needed: strings_start as usize,
                had: bytes.len(),
            })?;

    let mut strings: Vec<String> = Vec::with_capacity((string_count as usize).min(bytes.len()));
    for i in 0..string_count as usize {
        let index_off: usize = index_base
            .checked_add(i.checked_mul(4).ok_or(Error::ArscTruncated {
                offset: index_base,
                needed: i,
                had: bytes.len(),
            })?)
            .ok_or(Error::ArscTruncated {
                offset: index_base,
                needed: i * 4,
                had: bytes.len(),
            })?;
        let rel: u32 = read_u32(bytes, index_off)?;
        let str_off: usize = data_base
            .checked_add(rel as usize)
            .ok_or(Error::ArscTruncated {
                offset: data_base,
                needed: rel as usize,
                had: bytes.len(),
            })?;
        let decoded: String = if is_utf8 {
            let (_char_count, after_chars): (usize, usize) = decode_utf8_len(bytes, str_off)?;
            let (byte_len, after_bytes): (usize, usize) = decode_utf8_len(bytes, after_chars)?;
            let end: usize = after_bytes
                .checked_add(byte_len)
                .ok_or(Error::ArscTruncated {
                    offset: after_bytes,
                    needed: byte_len,
                    had: bytes.len(),
                })?;
            let raw: &[u8] = bytes.get(after_bytes..end).ok_or(Error::ArscTruncated {
                offset: after_bytes,
                needed: byte_len,
                had: bytes.len(),
            })?;
            decode_modified_utf8(raw)
        } else {
            let (unit_count, after_len): (usize, usize) = decode_utf16_len(bytes, str_off)?;
            let mut s: String = String::with_capacity(unit_count);
            let mut u: usize = 0;
            let mut cursor: usize = after_len;
            while u < unit_count {
                let unit: u16 = read_u16(bytes, cursor)?;
                if let Some(ch) = char::from_u32(u32::from(unit)) {
                    s.push(ch);
                }
                cursor += 2;
                u += 1;
            }
            s
        };
        strings.push(decoded);
    }

    Ok(ResStringPool {
        flags,
        is_utf8,
        strings,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResValue {
    pub data_type: u8,
    pub data: u32,
    pub formatted: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResBagItem {
    pub name_ref: u32,
    pub value: ResValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResEntryValue {
    Simple(ResValue),
    Bag { parent: u32, items: Vec<ResBagItem> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResEntry {
    pub entry_id: u32,
    pub key: String,
    pub value: ResEntryValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResTypeConfig {
    pub type_id: u8,
    pub qualifier: String,
    pub entries: Vec<ResEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResTablePackage {
    pub id: u32,
    pub name: String,
    pub type_strings: ResStringPool,
    pub key_strings: ResStringPool,
    pub types: Vec<ResTypeConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceTable {
    pub package_count: u32,
    pub global_strings: ResStringPool,
    pub packages: Vec<ResTablePackage>,
}

impl ResourceTable {
    #[must_use]
    pub fn resolve_id(&self, id: u32) -> Option<String> {
        let pkg_id: u32 = (id >> 24) & 0xFF;
        let type_id: u32 = (id >> 16) & 0xFF;
        let entry_id: u32 = id & 0xFFFF;
        let pkg: &ResTablePackage = self
            .packages
            .iter()
            .find(|p: &&ResTablePackage| p.id == pkg_id)?;
        let type_name: &str = pkg
            .type_strings
            .strings
            .get(type_id.checked_sub(1)? as usize)?;
        for ty in &pkg.types {
            if u32::from(ty.type_id) != type_id {
                continue;
            }
            if let Some(entry) = ty
                .entries
                .iter()
                .find(|e: &&ResEntry| e.entry_id == entry_id)
            {
                return Some(format!("{}.{type_name}.{}", pkg.name, entry.key));
            }
        }
        Some(format!("{}.{type_name}.0x{entry_id:04x}", pkg.name))
    }

    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.packages
            .iter()
            .flat_map(|p: &ResTablePackage| p.types.iter())
            .map(|t: &ResTypeConfig| t.entries.len())
            .sum()
    }

    #[must_use]
    pub fn id_map(&self) -> BTreeMap<u32, String> {
        let mut map: BTreeMap<u32, String> = BTreeMap::new();
        for pkg in &self.packages {
            for ty in &pkg.types {
                let Some(type_name): Option<&String> = u32::from(ty.type_id)
                    .checked_sub(1)
                    .and_then(|idx: u32| pkg.type_strings.strings.get(idx as usize))
                else {
                    continue;
                };
                for entry in &ty.entries {
                    let id: u32 = (pkg.id << 24) | (u32::from(ty.type_id) << 16) | entry.entry_id;
                    map.insert(id, format!("{}.{type_name}.{}", pkg.name, entry.key));
                }
            }
        }
        map
    }

    #[must_use]
    pub fn r_txt(&self) -> String {
        use std::fmt::Write as _;
        let mut seen: BTreeMap<(String, String), u32> = BTreeMap::new();
        for pkg in &self.packages {
            for ty in &pkg.types {
                let Some(type_name): Option<&str> = type_name_of(pkg, ty.type_id) else {
                    continue;
                };
                for entry in &ty.entries {
                    let id: u32 = (pkg.id << 24) | (u32::from(ty.type_id) << 16) | entry.entry_id;
                    seen.entry((type_name.to_owned(), entry.key.clone()))
                        .or_insert(id);
                }
            }
        }
        let mut out: String = String::new();
        for ((type_name, key), id) in seen {
            let _ = writeln!(out, "int {type_name} {key} 0x{id:08x}");
        }
        out
    }

    #[must_use]
    pub fn r_java(&self, package: &str) -> String {
        use std::fmt::Write as _;
        let mut by_type: BTreeMap<String, BTreeMap<String, u32>> = BTreeMap::new();
        for pkg in &self.packages {
            for ty in &pkg.types {
                let Some(type_name): Option<&str> = type_name_of(pkg, ty.type_id) else {
                    continue;
                };
                for entry in &ty.entries {
                    let id: u32 = (pkg.id << 24) | (u32::from(ty.type_id) << 16) | entry.entry_id;
                    by_type
                        .entry(type_name.to_owned())
                        .or_default()
                        .entry(sanitize_java_ident(&entry.key))
                        .or_insert(id);
                }
            }
        }
        let mut out: String = String::new();
        if !package.is_empty() {
            let _ = writeln!(out, "package {package};");
            let _ = writeln!(out);
        }
        let _ = writeln!(out, "public final class R {{");
        for (type_name, entries) in &by_type {
            let _ = writeln!(
                out,
                "    public static final class {} {{",
                sanitize_java_ident(type_name)
            );
            for (key, id) in entries {
                let _ = writeln!(out, "        public static final int {key} = 0x{id:08x};");
            }
            let _ = writeln!(out, "    }}");
        }
        let _ = writeln!(out, "}}");
        out
    }

    #[must_use]
    pub fn values_xml(&self) -> BTreeMap<String, String> {
        use std::fmt::Write as _;
        let mut by_qualifier: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for pkg in &self.packages {
            for ty in &pkg.types {
                let Some(type_name): Option<&str> = type_name_of(pkg, ty.type_id) else {
                    continue;
                };
                if !is_values_type(type_name) {
                    continue;
                }
                for entry in &ty.entries {
                    let Some(rendered): Option<String> =
                        self.render_value_element(type_name, entry)
                    else {
                        continue;
                    };
                    by_qualifier
                        .entry(values_dir(&ty.qualifier))
                        .or_default()
                        .push(rendered);
                }
            }
        }
        let mut files: BTreeMap<String, String> = BTreeMap::new();
        for (dir, items) in by_qualifier {
            let mut doc: String = String::new();
            let _ = writeln!(doc, "<?xml version=\"1.0\" encoding=\"utf-8\"?>");
            let _ = writeln!(doc, "<resources>");
            for item in items {
                let _ = writeln!(doc, "{item}");
            }
            let _ = writeln!(doc, "</resources>");
            files.insert(format!("res/{dir}/values.xml"), doc);
        }
        files
    }

    fn resolve_string_value(&self, value: &ResValue) -> Option<String> {
        if value.data_type == 0x03 {
            return self
                .global_strings
                .strings
                .get(value.data as usize)
                .cloned();
        }
        None
    }

    fn render_value_element(&self, type_name: &str, entry: &ResEntry) -> Option<String> {
        let key: &str = &entry.key;
        match &entry.value {
            ResEntryValue::Simple(value) => {
                let rendered: String = self
                    .resolve_string_value(value)
                    .map_or_else(|| value.formatted.clone(), |s: String| xml_escape(&s));
                let tag: &str = simple_value_tag(type_name);
                if type_name == "id" {
                    Some(format!("    <item type=\"id\" name=\"{key}\"/>"))
                } else {
                    Some(format!("    <{tag} name=\"{key}\">{rendered}</{tag}>"))
                }
            }
            ResEntryValue::Bag { items, .. } => {
                use std::fmt::Write as _;
                match type_name {
                    "array" => {
                        let mut s: String = format!("    <array name=\"{key}\">\n");
                        for item in items {
                            let v: String = self.resolve_string_value(&item.value).map_or_else(
                                || item.value.formatted.clone(),
                                |x: String| xml_escape(&x),
                            );
                            let _ = writeln!(s, "        <item>{v}</item>");
                        }
                        s.push_str("    </array>");
                        Some(s)
                    }
                    "style" => {
                        let mut s: String = format!("    <style name=\"{key}\">\n");
                        for item in items {
                            let attr: String = self
                                .resolve_id(item.name_ref)
                                .unwrap_or_else(|| format!("0x{:08x}", item.name_ref));
                            let v: String = self.resolve_string_value(&item.value).map_or_else(
                                || item.value.formatted.clone(),
                                |x: String| xml_escape(&x),
                            );
                            let _ = writeln!(s, "        <item name=\"{attr}\">{v}</item>");
                        }
                        s.push_str("    </style>");
                        Some(s)
                    }
                    "plurals" => {
                        let mut s: String = format!("    <plurals name=\"{key}\">\n");
                        for item in items {
                            let v: String = self.resolve_string_value(&item.value).map_or_else(
                                || item.value.formatted.clone(),
                                |x: String| xml_escape(&x),
                            );
                            let _ = writeln!(s, "        <item>{v}</item>");
                        }
                        s.push_str("    </plurals>");
                        Some(s)
                    }
                    _ => None,
                }
            }
        }
    }
}

fn type_name_of(pkg: &ResTablePackage, type_id: u8) -> Option<&str> {
    u32::from(type_id)
        .checked_sub(1)
        .and_then(|idx: u32| pkg.type_strings.strings.get(idx as usize))
        .map(String::as_str)
}

fn is_values_type(type_name: &str) -> bool {
    matches!(
        type_name,
        "string" | "bool" | "integer" | "color" | "dimen" | "id" | "array" | "style" | "plurals"
    )
}

fn simple_value_tag(type_name: &str) -> &'static str {
    match type_name {
        "string" => "string",
        "bool" => "bool",
        "integer" => "integer",
        "color" => "color",
        "dimen" => "dimen",
        _ => "item",
    }
}

fn values_dir(qualifier: &str) -> String {
    if qualifier.is_empty() {
        "values".to_owned()
    } else {
        format!("values-{qualifier}")
    }
}

fn sanitize_java_ident(raw: &str) -> String {
    let mut out: String = String::with_capacity(raw.len());
    for (i, ch) in raw.chars().enumerate() {
        let ok: bool = if i == 0 {
            ch.is_ascii_alphabetic() || ch == '_'
        } else {
            ch.is_ascii_alphanumeric() || ch == '_'
        };
        out.push(if ok { ch } else { '_' });
    }
    if out.is_empty() { "_".to_owned() } else { out }
}

fn xml_escape(raw: &str) -> String {
    let mut out: String = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(ch),
        }
    }
    out
}

impl ResourceIdResolver for ResourceTable {
    fn resolve(&self, id: u32) -> Option<String> {
        self.resolve_id(id)
    }
}

fn make_res_value(bytes: &[u8], off: usize) -> Result<ResValue> {
    let data_type: u8 = *bytes.get(off + 3).ok_or(Error::ArscTruncated {
        offset: off + 3,
        needed: 1,
        had: bytes.len(),
    })?;
    let data: u32 = read_u32(bytes, off + 4)?;
    Ok(ResValue {
        data_type,
        data,
        formatted: format_res_value(data_type, data, None),
    })
}

fn parse_type_chunk(
    bytes: &[u8],
    chunk_off: usize,
    chunk_size: usize,
    header_size: usize,
    key_strings: &ResStringPool,
) -> Result<ResTypeConfig> {
    let type_id: u8 = *bytes.get(chunk_off + 8).ok_or(Error::ArscTruncated {
        offset: chunk_off + 8,
        needed: 1,
        had: bytes.len(),
    })?;
    let entry_count: u32 = read_u32(bytes, chunk_off + 12)?;
    let entries_start: u32 = read_u32(bytes, chunk_off + 16)?;
    let config_size: u32 = read_u32(bytes, chunk_off + 20)?;
    let qualifier: String = decode_config_qualifier(bytes, chunk_off + 20, config_size as usize);

    let index_base: usize = chunk_off + header_size;
    let data_base: usize =
        chunk_off
            .checked_add(entries_start as usize)
            .ok_or(Error::ArscTruncated {
                offset: chunk_off,
                needed: entries_start as usize,
                had: bytes.len(),
            })?;
    let chunk_end: usize = chunk_off
        .checked_add(chunk_size)
        .ok_or(Error::ArscTruncated {
            offset: chunk_off,
            needed: chunk_size,
            had: bytes.len(),
        })?;

    let mut entries: Vec<ResEntry> = Vec::with_capacity((entry_count as usize).min(bytes.len()));
    for i in 0..entry_count as usize {
        let rel: u32 = read_u32(bytes, index_base + i * 4)?;
        if rel == NO_ENTRY {
            continue;
        }
        let entry_off: usize = data_base
            .checked_add(rel as usize)
            .ok_or(Error::ArscTruncated {
                offset: data_base,
                needed: rel as usize,
                had: bytes.len(),
            })?;
        if entry_off + 8 > chunk_end {
            return Err(Error::ArscTruncated {
                offset: entry_off,
                needed: 8,
                had: chunk_end,
            });
        }
        let entry_size: u16 = read_u16(bytes, entry_off)?;
        let entry_flags: u16 = read_u16(bytes, entry_off + 2)?;
        let key_idx: u32 = read_u32(bytes, entry_off + 4)?;
        let key: String = key_strings
            .strings
            .get(key_idx as usize)
            .cloned()
            .unwrap_or_default();
        let value: ResEntryValue = if (entry_flags & ENTRY_FLAG_COMPLEX) != 0 {
            let map_off: usize = entry_off + usize::from(entry_size);
            let parent: u32 = read_u32(bytes, map_off)?;
            let map_count: u32 = read_u32(bytes, map_off + 4)?;
            let mut items: Vec<ResBagItem> =
                Vec::with_capacity((map_count as usize).min(bytes.len()));
            let mut mo: usize = map_off + 8;
            for _ in 0..map_count {
                if mo + 12 > chunk_end {
                    break;
                }
                let name_ref: u32 = read_u32(bytes, mo)?;
                let value: ResValue = make_res_value(bytes, mo + 4)?;
                items.push(ResBagItem { name_ref, value });
                mo += 12;
            }
            ResEntryValue::Bag { parent, items }
        } else {
            let value_off: usize = entry_off + usize::from(entry_size);
            ResEntryValue::Simple(make_res_value(bytes, value_off)?)
        };
        entries.push(ResEntry {
            entry_id: i as u32,
            key,
            value,
        });
    }

    Ok(ResTypeConfig {
        type_id,
        qualifier,
        entries,
    })
}

const DENSITY_DEFAULT: u16 = 0;
const DENSITY_LOW: u16 = 120;
const DENSITY_MEDIUM: u16 = 160;
const DENSITY_TV: u16 = 213;
const DENSITY_HIGH: u16 = 240;
const DENSITY_XHIGH: u16 = 320;
const DENSITY_XXHIGH: u16 = 480;
const DENSITY_XXXHIGH: u16 = 640;
const DENSITY_ANY: u16 = 0xFFFE;
const DENSITY_NONE: u16 = 0xFFFF;

#[inline]
fn unpack_locale(bytes: &[u8], off: usize) -> Option<String> {
    let b0: u8 = bytes.get(off).copied()?;
    let b1: u8 = bytes.get(off + 1).copied()?;
    if b0 == 0 {
        return None;
    }
    if b0 & 0x80 == 0 {
        let mut s: String = String::with_capacity(2);
        s.push(b0 as char);
        if b1 != 0 {
            s.push(b1 as char);
        }
        return Some(s);
    }
    let first: u8 = b0 & 0x1F;
    let second: u8 = ((b0 & 0xE0) >> 5) | ((b1 & 0x03) << 3);
    let third: u8 = (b1 & 0x7C) >> 2;
    let base: u8 = b'a' - 1;
    Some(
        [base + first, base + second, base + third]
            .iter()
            .map(|c: &u8| *c as char)
            .collect(),
    )
}

#[inline]
fn density_qualifier(density: u16) -> Option<String> {
    match density {
        DENSITY_DEFAULT => None,
        DENSITY_LOW => Some("ldpi".to_owned()),
        DENSITY_MEDIUM => Some("mdpi".to_owned()),
        DENSITY_TV => Some("tvdpi".to_owned()),
        DENSITY_HIGH => Some("hdpi".to_owned()),
        DENSITY_XHIGH => Some("xhdpi".to_owned()),
        DENSITY_XXHIGH => Some("xxhdpi".to_owned()),
        DENSITY_XXXHIGH => Some("xxxhdpi".to_owned()),
        DENSITY_ANY => Some("anydpi".to_owned()),
        DENSITY_NONE => Some("nodpi".to_owned()),
        other => Some(format!("{other}dpi")),
    }
}

fn decode_config_qualifier(bytes: &[u8], config_off: usize, config_size: usize) -> String {
    if config_size < 12 {
        return String::new();
    }
    let read_u8 = |rel: usize| -> u8 { bytes.get(config_off + rel).copied().unwrap_or(0) };
    let read_u16le = |rel: usize| -> u16 { read_u16(bytes, config_off + rel).unwrap_or(0) };

    let mut parts: Vec<String> = Vec::new();

    let mcc: u16 = read_u16le(4);
    let mnc: u16 = read_u16le(6);
    if mcc != 0 {
        parts.push(format!("mcc{mcc}"));
    }
    if mnc != 0 {
        parts.push(format!("mnc{mnc}"));
    }

    if let Some(lang) = unpack_locale(bytes, config_off + 8) {
        let mut s: String = lang;
        if let Some(region) = unpack_locale(bytes, config_off + 10) {
            s.push('-');
            s.push('r');
            s.push_str(&region.to_uppercase());
        }
        parts.push(s);
    }

    if config_size > 30 {
        let smallest_width_dp: u16 = read_u16le(30);
        if smallest_width_dp != 0 {
            parts.push(format!("sw{smallest_width_dp}dp"));
        }
    }
    if config_size > 34 {
        let width_dp: u16 = read_u16le(32);
        let height_dp: u16 = read_u16le(34);
        if width_dp != 0 {
            parts.push(format!("w{width_dp}dp"));
        }
        if height_dp != 0 {
            parts.push(format!("h{height_dp}dp"));
        }
    }

    if config_size > 28 {
        let screen_layout: u8 = read_u8(28);
        match screen_layout & 0x0F {
            0x01 => parts.push("small".to_owned()),
            0x02 => parts.push("normal".to_owned()),
            0x03 => parts.push("large".to_owned()),
            0x04 => parts.push("xlarge".to_owned()),
            _ => {}
        }
        match screen_layout & 0x30 {
            0x10 => parts.push("notlong".to_owned()),
            0x20 => parts.push("long".to_owned()),
            _ => {}
        }
        match screen_layout & 0xC0 {
            0x40 => parts.push("ldltr".to_owned()),
            0x80 => parts.push("ldrtl".to_owned()),
            _ => {}
        }
    }

    if config_size > 48 {
        let screen_layout2: u8 = read_u8(48);
        match screen_layout2 & 0x03 {
            0x01 => parts.push("notround".to_owned()),
            0x02 => parts.push("round".to_owned()),
            _ => {}
        }
    }
    if config_size > 49 {
        let color_mode: u8 = read_u8(49);
        match color_mode & 0x03 {
            0x01 => parts.push("nowidecg".to_owned()),
            0x02 => parts.push("widecg".to_owned()),
            _ => {}
        }
        match color_mode & 0x0C {
            0x04 => parts.push("lowdr".to_owned()),
            0x08 => parts.push("highdr".to_owned()),
            _ => {}
        }
    }

    let orientation: u8 = read_u8(12);
    match orientation {
        0x01 => parts.push("port".to_owned()),
        0x02 => parts.push("land".to_owned()),
        0x03 => parts.push("square".to_owned()),
        _ => {}
    }

    if config_size > 29 {
        let ui_mode: u8 = read_u8(29);
        match ui_mode & 0x0F {
            0x01 => parts.push("desk".to_owned()),
            0x02 => parts.push("car".to_owned()),
            0x03 => parts.push("television".to_owned()),
            0x04 => parts.push("appliance".to_owned()),
            0x05 => parts.push("watch".to_owned()),
            0x06 => parts.push("vrheadset".to_owned()),
            _ => {}
        }
        match ui_mode & 0x30 {
            0x10 => parts.push("notnight".to_owned()),
            0x20 => parts.push("night".to_owned()),
            _ => {}
        }
    }

    let density: u16 = read_u16le(14);
    if let Some(d) = density_qualifier(density) {
        parts.push(d);
    }

    let touchscreen: u8 = read_u8(13);
    match touchscreen {
        0x01 => parts.push("notouch".to_owned()),
        0x03 => parts.push("finger".to_owned()),
        _ => {}
    }

    if config_size > 18 {
        let input_flags: u8 = read_u8(18);
        match input_flags & 0x03 {
            0x01 => parts.push("keysexposed".to_owned()),
            0x02 => parts.push("keyshidden".to_owned()),
            0x03 => parts.push("keyssoft".to_owned()),
            _ => {}
        }
        match input_flags & 0x0C {
            0x04 => parts.push("navexposed".to_owned()),
            0x08 => parts.push("navhidden".to_owned()),
            _ => {}
        }
    }

    let keyboard: u8 = read_u8(16);
    match keyboard {
        0x01 => parts.push("nokeys".to_owned()),
        0x02 => parts.push("qwerty".to_owned()),
        0x03 => parts.push("12key".to_owned()),
        _ => {}
    }

    let navigation: u8 = read_u8(17);
    match navigation {
        0x01 => parts.push("nonav".to_owned()),
        0x02 => parts.push("dpad".to_owned()),
        0x03 => parts.push("trackball".to_owned()),
        0x04 => parts.push("wheel".to_owned()),
        _ => {}
    }

    if config_size > 20 {
        let screen_width: u16 = read_u16le(20);
        let screen_height: u16 = read_u16le(22);
        if screen_width != 0 || screen_height != 0 {
            parts.push(format!("{screen_width}x{screen_height}"));
        }
    }

    if config_size > 24 {
        let sdk_version: u16 = read_u16le(24);
        if sdk_version != 0 {
            parts.push(format!("v{sdk_version}"));
        }
    }

    parts.join("-")
}

fn parse_package(bytes: &[u8], chunk_off: usize, chunk_size: usize) -> Result<ResTablePackage> {
    let header_size: usize = usize::from(read_u16(bytes, chunk_off + 2)?);
    let id: u32 = read_u32(bytes, chunk_off + 8)?;
    let name_base: usize = chunk_off + 12;
    let mut name: String = String::with_capacity(PACKAGE_NAME_UNITS);
    for u in 0..PACKAGE_NAME_UNITS {
        let unit: u16 = read_u16(bytes, name_base + u * 2)?;
        if unit == 0 {
            break;
        }
        if let Some(ch) = char::from_u32(u32::from(unit)) {
            name.push(ch);
        }
    }
    let type_strings_off: u32 = read_u32(bytes, name_base + PACKAGE_NAME_UNITS * 2)?;
    let key_strings_off: u32 = read_u32(bytes, name_base + PACKAGE_NAME_UNITS * 2 + 8)?;

    let type_strings: ResStringPool = if type_strings_off == 0 {
        empty_pool()
    } else {
        parse_string_pool(bytes, chunk_off + type_strings_off as usize)?
    };
    let key_strings: ResStringPool = if key_strings_off == 0 {
        empty_pool()
    } else {
        parse_string_pool(bytes, chunk_off + key_strings_off as usize)?
    };

    let pkg_end: usize = chunk_off
        .checked_add(chunk_size)
        .ok_or(Error::ArscTruncated {
            offset: chunk_off,
            needed: chunk_size,
            had: bytes.len(),
        })?;

    let mut types: Vec<ResTypeConfig> = Vec::new();
    let mut cursor: usize = chunk_off + header_size;
    while cursor + CHUNK_HEADER_SIZE <= pkg_end {
        let inner: ResChunkHeader = read_chunk_header(bytes, cursor)?;
        if inner.size == 0 {
            break;
        }
        if inner.type_ == RES_TABLE_TYPE_TYPE {
            types.push(parse_type_chunk(
                bytes,
                cursor,
                inner.size as usize,
                usize::from(inner.header_size),
                &key_strings,
            )?);
        }
        cursor = cursor
            .checked_add(inner.size as usize)
            .ok_or(Error::ArscTruncated {
                offset: cursor,
                needed: inner.size as usize,
                had: bytes.len(),
            })?;
    }

    Ok(ResTablePackage {
        id,
        name,
        type_strings,
        key_strings,
        types,
    })
}

#[inline]
const fn empty_pool() -> ResStringPool {
    ResStringPool {
        flags: 0,
        is_utf8: false,
        strings: Vec::new(),
    }
}

pub fn parse_arsc(bytes: &[u8]) -> Result<ResourceTable> {
    let top: ResChunkHeader = read_chunk_header(bytes, 0)?;
    if top.type_ != RES_TABLE_TYPE {
        return Err(Error::BadArscChunk(top.type_));
    }
    let package_count: u32 = read_u32(bytes, 8)?;
    let mut cursor: usize = usize::from(top.header_size);

    let global_header: ResChunkHeader = read_chunk_header(bytes, cursor)?;
    if global_header.type_ != RES_STRING_POOL_TYPE {
        return Err(Error::ArscTruncated {
            offset: cursor,
            needed: usize::from(RES_STRING_POOL_TYPE),
            had: usize::from(global_header.type_),
        });
    }
    let global_strings: ResStringPool = parse_string_pool(bytes, cursor)?;
    cursor = cursor
        .checked_add(global_header.size as usize)
        .ok_or(Error::ArscTruncated {
            offset: cursor,
            needed: global_header.size as usize,
            had: bytes.len(),
        })?;

    let mut packages: Vec<ResTablePackage> =
        Vec::with_capacity((package_count as usize).min(bytes.len()));
    while cursor + CHUNK_HEADER_SIZE <= bytes.len() {
        let chunk: ResChunkHeader = read_chunk_header(bytes, cursor)?;
        if chunk.size == 0 {
            break;
        }
        if chunk.type_ == RES_TABLE_PACKAGE_TYPE {
            packages.push(parse_package(bytes, cursor, chunk.size as usize)?);
        }
        cursor = cursor
            .checked_add(chunk.size as usize)
            .ok_or(Error::ArscTruncated {
                offset: cursor,
                needed: chunk.size as usize,
                had: bytes.len(),
            })?;
    }

    Ok(ResourceTable {
        package_count,
        global_strings,
        packages,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn arsc_rejects_wrong_top_chunk() {
        let bytes: [u8; 8] = [0xFF, 0x00, 12, 0, 8, 0, 0, 0];
        let err: Error = parse_arsc(&bytes).expect_err("bad top chunk");
        assert!(matches!(err, Error::BadArscChunk(0x00FF)));
    }

    #[test]
    fn arsc_rejects_truncated() {
        let err: Error = parse_arsc(&[0x02u8, 0x00]).expect_err("truncated");
        assert!(matches!(err, Error::ArscTruncated { .. }));
    }

    #[test]
    fn chunk_header_decodes() {
        let bytes: [u8; 8] = [0x02, 0x00, 0x0C, 0x00, 0x20, 0x00, 0x00, 0x00];
        let h: ResChunkHeader = read_chunk_header(&bytes, 0).expect("header");
        assert_eq!(h.type_, RES_TABLE_TYPE);
        assert_eq!(h.header_size, 12);
        assert_eq!(h.size, 0x20);
    }
}
