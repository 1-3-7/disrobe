use std::collections::BTreeMap;
use std::fmt::Arguments;

use disrobe_bytes::{ByteReadError, ByteReader};
use serde::{Deserialize, Serialize};

use crate::android_attrs::framework_attr_name;
use crate::arsc::ArscResources;
use crate::error::{Error, Result};

const CHUNK_STRING_POOL: u16 = 0x0001;
const CHUNK_XML: u16 = 0x0003;
const CHUNK_XML_RESOURCE_MAP: u16 = 0x0180;
const CHUNK_XML_START_NAMESPACE: u16 = 0x0100;
const CHUNK_XML_END_NAMESPACE: u16 = 0x0101;
const CHUNK_XML_START_ELEMENT: u16 = 0x0102;
const CHUNK_XML_END_ELEMENT: u16 = 0x0103;
const CHUNK_XML_CDATA: u16 = 0x0104;

const FLAG_UTF8: u32 = 1 << 8;

const TYPE_NULL: u8 = 0x00;
const TYPE_REFERENCE: u8 = 0x01;
const TYPE_ATTRIBUTE: u8 = 0x02;
const TYPE_STRING: u8 = 0x03;
const TYPE_FLOAT: u8 = 0x04;
const TYPE_DIMENSION: u8 = 0x05;
const TYPE_FRACTION: u8 = 0x06;
const TYPE_DYNAMIC_REFERENCE: u8 = 0x07;
const TYPE_DYNAMIC_ATTRIBUTE: u8 = 0x08;
const TYPE_INT_DEC: u8 = 0x10;
const TYPE_INT_HEX: u8 = 0x11;
const TYPE_INT_BOOL: u8 = 0x12;
const TYPE_INT_COLOR_ARGB8: u8 = 0x1c;
const TYPE_INT_COLOR_RGB8: u8 = 0x1d;
const TYPE_INT_COLOR_ARGB4: u8 = 0x1e;
const TYPE_INT_COLOR_RGB4: u8 = 0x1f;

const COMPLEX_UNIT_MASK: u32 = 0x0f;
const COMPLEX_MANTISSA_SHIFT: u32 = 8;
const COMPLEX_MANTISSA_MASK: u32 = 0x00ff_ffff;
const COMPLEX_RADIX_SHIFT: u32 = 4;
const COMPLEX_RADIX_MASK: u32 = 0x03;

const DIMENSION_UNITS: [&str; 8] = ["px", "dp", "sp", "pt", "in", "mm", "", ""];
const FRACTION_UNITS: [&str; 8] = ["%", "%p", "", "", "", "", "", ""];

const MAX_DEPTH: usize = 512;
const ANDROID_NS: &str = "http://schemas.android.com/apk/res/android";

macro_rules! push_text {
    ($output:expr, $($arg:tt)*) => {
        push_format(&mut $output, format_args!($($arg)*))
    };
}

macro_rules! push_line {
    ($output:expr, $($arg:tt)*) => {
        push_format_line(&mut $output, format_args!($($arg)*))
    };
}

fn push_format(output: &mut String, args: Arguments<'_>) {
    match std::fmt::write(output, args) {
        Ok(()) => {}
        Err(error) => unreachable!("string formatting failed: {error:?}"),
    }
}

fn push_format_line(output: &mut String, args: Arguments<'_>) {
    push_format(output, args);
    output.push('\n');
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AxmlAttribute {
    pub namespace: Option<String>,
    pub prefix: Option<String>,
    pub name: String,
    pub value: String,
    pub resource_id: Option<u32>,
    pub attr_id: Option<u32>,
    pub value_type: u8,
    pub raw_data: u32,
}

const ATTR_ID_LAYOUT_WIDTH: u32 = 0x0101_0000 | 0x00f4;
const ATTR_ID_LAYOUT_HEIGHT: u32 = 0x0101_0000 | 0x00f5;
const ATTR_ID_ORIENTATION: u32 = 0x0101_0000 | 0x00c4;

impl AxmlAttribute {
    #[must_use]
    pub fn formatted_value(&self, resources: Option<&ArscResources>) -> String {
        if matches!(self.value_type, TYPE_INT_DEC)
            && let Some(symbolic) = framework_enum_value(self.attr_id, self.raw_data as i32)
        {
            return symbolic.to_owned();
        }
        format_typed_value(self.value_type, self.raw_data, &self.value, resources)
    }
}

fn framework_enum_value(attr_id: Option<u32>, data: i32) -> Option<&'static str> {
    match (attr_id?, data) {
        (ATTR_ID_LAYOUT_WIDTH | ATTR_ID_LAYOUT_HEIGHT, -1) => Some("match_parent"),
        (ATTR_ID_LAYOUT_WIDTH | ATTR_ID_LAYOUT_HEIGHT, -2) => Some("wrap_content"),
        (ATTR_ID_ORIENTATION, 0) => Some("horizontal"),
        (ATTR_ID_ORIENTATION, 1) => Some("vertical"),
        _ => None,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AxmlElement {
    pub name: String,
    pub namespace: Option<String>,
    pub prefix: Option<String>,
    pub attributes: Vec<AxmlAttribute>,
    pub children: Vec<Self>,
    pub cdata: Vec<String>,
}

impl AxmlElement {
    #[must_use]
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|a: &&AxmlAttribute| a.name == name)
            .map(|a: &AxmlAttribute| a.value.as_str())
    }

    pub fn descendants(&self) -> impl Iterator<Item = &Self> {
        let mut stack: Vec<&Self> = vec![self];
        std::iter::from_fn(move || {
            let node: &Self = stack.pop()?;
            for child in node.children.iter().rev() {
                stack.push(child);
            }
            Some(node)
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AxmlDocument {
    pub root: AxmlElement,
    pub namespaces: Vec<NamespaceBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceBinding {
    pub prefix: String,
    pub uri: String,
}

impl AxmlDocument {
    #[must_use]
    pub fn to_xml(&self) -> String {
        self.to_xml_with_resources(None)
    }

    #[must_use]
    pub fn to_xml_with_resources(&self, resources: Option<&ArscResources>) -> String {
        let mut out: String = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
        self.write_element(&mut out, &self.root, 0, true, resources);
        out
    }

    fn write_element(
        &self,
        mut out: &mut String,
        el: &AxmlElement,
        depth: usize,
        is_root: bool,
        resources: Option<&ArscResources>,
    ) {
        let indent: String = "    ".repeat(depth);
        let tag: String = qualified_name(el.prefix.as_deref(), &el.name);
        push_text!(out, "{indent}<{tag}");

        if is_root {
            for ns in &self.namespaces {
                push_text!(out, " xmlns:{}=\"{}\"", ns.prefix, escape_attr(&ns.uri));
            }
        }

        for attr in &el.attributes {
            let attr_name: String = qualified_name(attr.prefix.as_deref(), &attr.name);
            let value: String = attr.formatted_value(resources);
            push_text!(out, " {attr_name}=\"{}\"", escape_attr(&value));
        }

        let has_children: bool = !el.children.is_empty() || !el.cdata.is_empty();
        if has_children {
            out.push_str(">\n");
            for text in &el.cdata {
                push_line!(out, "{indent}    {}", escape_text(text));
            }
            for child in &el.children {
                self.write_element(out, child, depth + 1, false, resources);
            }
            push_line!(out, "{indent}</{tag}>");
        } else {
            out.push_str(" />\n");
        }
    }
}

fn qualified_name(prefix: Option<&str>, local: &str) -> String {
    match prefix {
        Some(p) if !p.is_empty() => format!("{p}:{local}"),
        _ => local.to_owned(),
    }
}

fn axml_truncated(_: ByteReadError) -> Error {
    Error::AxmlTruncated
}

fn read_chunk_header(reader: &mut ByteReader<'_>) -> Result<(u16, u16, u32)> {
    let chunk_type: u16 = reader.read_u16_le().map_err(axml_truncated)?;
    let header_size: u16 = reader.read_u16_le().map_err(axml_truncated)?;
    let chunk_size: u32 = reader.read_u32_le().map_err(axml_truncated)?;
    Ok((chunk_type, header_size, chunk_size))
}

#[derive(Debug)]
struct StringPool {
    strings: Vec<String>,
}

impl StringPool {
    fn optional(&self, index: i32) -> Result<Option<&str>> {
        if index < 0 {
            return Ok(None);
        }
        Ok(Some(self.required_i32(index)?))
    }

    fn required_i32(&self, index: i32) -> Result<&str> {
        if index < 0 {
            return Err(Error::AxmlBadStringPool);
        }
        self.strings
            .get(index as usize)
            .map(String::as_str)
            .ok_or(Error::AxmlBadStringPool)
    }

    fn required_u32(&self, index: u32) -> Result<&str> {
        self.strings
            .get(index as usize)
            .map(String::as_str)
            .ok_or(Error::AxmlBadStringPool)
    }
}

fn parse_string_pool(bytes: &[u8], chunk_off: usize) -> Result<StringPool> {
    let mut r: ByteReader<'_> = ByteReader::new(bytes);
    r.seek(chunk_off).map_err(axml_truncated)?;
    let (chunk_type, header_size, chunk_size): (u16, u16, u32) = read_chunk_header(&mut r)?;
    if chunk_type != CHUNK_STRING_POOL {
        return Err(Error::AxmlBadStringPool);
    }
    let chunk_end: usize = chunk_off
        .checked_add(chunk_size as usize)
        .filter(|end: &usize| *end <= bytes.len())
        .ok_or(Error::AxmlTruncated)?;
    let string_count: u32 = r.read_u32_le().map_err(axml_truncated)?;
    let _style_count: u32 = r.read_u32_le().map_err(axml_truncated)?;
    let flags: u32 = r.read_u32_le().map_err(axml_truncated)?;
    let strings_start: u32 = r.read_u32_le().map_err(axml_truncated)?;
    let _styles_start: u32 = r.read_u32_le().map_err(axml_truncated)?;
    let is_utf8: bool = flags & FLAG_UTF8 != 0;

    let offsets_base: usize = chunk_off + header_size as usize;
    let mut offsets: Vec<u32> = Vec::with_capacity(string_count.min(1 << 20) as usize);
    let mut off_reader: ByteReader<'_> = ByteReader::new(bytes);
    off_reader.seek(offsets_base).map_err(axml_truncated)?;
    for _ in 0..string_count {
        offsets.push(off_reader.read_u32_le().map_err(axml_truncated)?);
    }

    let data_base: usize = chunk_off + strings_start as usize;
    let mut strings: Vec<String> = Vec::with_capacity(offsets.len());
    for off in offsets {
        let start: usize = data_base
            .checked_add(off as usize)
            .filter(|s: &usize| *s < chunk_end)
            .ok_or(Error::AxmlTruncated)?;
        let s: String = if is_utf8 {
            decode_utf8_string(bytes, start, chunk_end)?
        } else {
            decode_utf16_string(bytes, start, chunk_end)?
        };
        strings.push(s);
    }
    Ok(StringPool { strings })
}

fn read_len_utf8(bytes: &[u8], pos: usize, end: usize) -> Result<(usize, usize)> {
    let b0: u8 = *bytes.get(pos).ok_or(Error::AxmlTruncated)?;
    if b0 & 0x80 != 0 {
        let b1: u8 = *bytes.get(pos + 1).ok_or(Error::AxmlTruncated)?;
        let len: usize = (((b0 & 0x7f) as usize) << 8) | b1 as usize;
        if pos + 2 > end {
            return Err(Error::AxmlTruncated);
        }
        Ok((len, pos + 2))
    } else {
        Ok((b0 as usize, pos + 1))
    }
}

fn decode_utf8_string(bytes: &[u8], pos: usize, end: usize) -> Result<String> {
    let (_char_len, after_char): (usize, usize) = read_len_utf8(bytes, pos, end)?;
    let (byte_len, data_start): (usize, usize) = read_len_utf8(bytes, after_char, end)?;
    let data_end: usize = data_start
        .checked_add(byte_len)
        .filter(|e: &usize| *e <= end)
        .ok_or(Error::AxmlTruncated)?;
    let raw: &[u8] = &bytes[data_start..data_end];
    Ok(String::from_utf8_lossy(raw).into_owned())
}

fn read_len_utf16(bytes: &[u8], pos: usize, end: usize) -> Result<(usize, usize)> {
    let lo: u8 = *bytes.get(pos).ok_or(Error::AxmlTruncated)?;
    let hi: u8 = *bytes.get(pos + 1).ok_or(Error::AxmlTruncated)?;
    let first: u16 = u16::from_le_bytes([lo, hi]);
    if first & 0x8000 != 0 {
        let lo2: u8 = *bytes.get(pos + 2).ok_or(Error::AxmlTruncated)?;
        let hi2: u8 = *bytes.get(pos + 3).ok_or(Error::AxmlTruncated)?;
        let second: u16 = u16::from_le_bytes([lo2, hi2]);
        let len: usize = (((first & 0x7fff) as usize) << 16) | second as usize;
        if pos + 4 > end {
            return Err(Error::AxmlTruncated);
        }
        Ok((len, pos + 4))
    } else {
        Ok((first as usize, pos + 2))
    }
}

fn decode_utf16_string(bytes: &[u8], pos: usize, end: usize) -> Result<String> {
    let (char_len, data_start): (usize, usize) = read_len_utf16(bytes, pos, end)?;
    let byte_len: usize = char_len.checked_mul(2).ok_or(Error::AxmlTruncated)?;
    let data_end: usize = data_start
        .checked_add(byte_len)
        .filter(|e: &usize| *e <= end)
        .ok_or(Error::AxmlTruncated)?;
    let units: Vec<u16> = bytes[data_start..data_end]
        .chunks_exact(2)
        .map(|c: &[u8]| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Ok(String::from_utf16_lossy(&units))
}

fn format_complex(data: u32, units: &[&str; 8]) -> String {
    let radix_table: [f32; 4] = [
        1.0 / (1 << 8) as f32,
        1.0 / (1 << 15) as f32,
        1.0 / (1 << 23) as f32,
        1.0 / (1u64 << 31) as f32,
    ];
    let mantissa_in_place: u32 = data & (COMPLEX_MANTISSA_MASK << COMPLEX_MANTISSA_SHIFT);
    let radix: usize = ((data >> COMPLEX_RADIX_SHIFT) & COMPLEX_RADIX_MASK) as usize;
    let value: f32 = mantissa_in_place as f32 * radix_table[radix];
    let unit: &str = units
        .get((data & COMPLEX_UNIT_MASK) as usize)
        .copied()
        .unwrap_or("");
    format_float(value) + unit
}

fn format_float(value: f32) -> String {
    let mut s: String = format!("{value}");
    if !s.contains('.') && !s.contains('e') && !s.contains("inf") && !s.contains("NaN") {
        s.push_str(".0");
    }
    s
}

fn format_reference(id: u32, sigil: char, resources: Option<&ArscResources>) -> String {
    if id == 0 && sigil == '@' {
        return "@null".to_owned();
    }
    if let Some(res) = resources
        && let Some(name) = res.resolve(id)
    {
        return format!("{sigil}{name}");
    }
    if (id >> 24) == 0x01 {
        if let Some(name) = framework_attr_name(id) {
            return format!("{sigil}android:attr/{name}");
        }
        return format!("{sigil}android:{id:08x}");
    }
    format!("{sigil}0x{id:08x}")
}

fn format_typed_value(
    data_type: u8,
    data: u32,
    raw_string: &str,
    resources: Option<&ArscResources>,
) -> String {
    match data_type {
        TYPE_STRING => raw_string.to_owned(),
        TYPE_NULL => {
            if data == 0 {
                String::new()
            } else {
                "@empty".to_owned()
            }
        }
        TYPE_REFERENCE | TYPE_DYNAMIC_REFERENCE => format_reference(data, '@', resources),
        TYPE_ATTRIBUTE | TYPE_DYNAMIC_ATTRIBUTE => format_reference(data, '?', resources),
        TYPE_INT_BOOL => {
            if data == 0 {
                "false".to_owned()
            } else {
                "true".to_owned()
            }
        }
        TYPE_INT_HEX => format!("0x{data:x}"),
        TYPE_INT_DEC => (data as i32).to_string(),
        TYPE_FLOAT => format_float(f32::from_bits(data)),
        TYPE_DIMENSION => format_complex(data, &DIMENSION_UNITS),
        TYPE_FRACTION => format_complex(data, &FRACTION_UNITS),
        TYPE_INT_COLOR_ARGB8 | TYPE_INT_COLOR_RGB8 => format!("#{data:08x}"),
        TYPE_INT_COLOR_ARGB4 | TYPE_INT_COLOR_RGB4 => format!("#{data:04x}"),
        _ => (data as i32).to_string(),
    }
}

pub fn parse(bytes: &[u8]) -> Result<AxmlDocument> {
    let mut r: ByteReader<'_> = ByteReader::new(bytes);
    let (chunk_type, header_size, _file_size): (u16, u16, u32) = read_chunk_header(&mut r)?;
    if chunk_type != CHUNK_XML {
        return Err(Error::AxmlBadMagic);
    }
    let mut off: usize = header_size as usize;

    let mut pool: Option<StringPool> = None;
    let mut resource_ids: Vec<u32> = Vec::new();
    let mut element_stack: Vec<AxmlElement> = Vec::new();
    let mut root: Option<AxmlElement> = None;
    let mut ns_uri_to_prefix: BTreeMap<String, String> = BTreeMap::new();
    let mut namespaces: Vec<NamespaceBinding> = Vec::new();

    while off + 8 <= bytes.len() {
        let mut hr: ByteReader<'_> = ByteReader::new(bytes);
        hr.seek(off).map_err(axml_truncated)?;
        let (ctype, chunk_header_size, csize): (u16, u16, u32) = read_chunk_header(&mut hr)?;
        if csize < 8 {
            return Err(Error::AxmlTruncated);
        }
        let next: usize = off
            .checked_add(csize as usize)
            .filter(|n: &usize| *n <= bytes.len())
            .ok_or(Error::AxmlTruncated)?;

        match ctype {
            CHUNK_STRING_POOL => {
                pool = Some(parse_string_pool(bytes, off)?);
            }
            CHUNK_XML_RESOURCE_MAP => {
                let count: usize = (csize as usize - 8) / 4;
                let mut mr: ByteReader<'_> = ByteReader::new(bytes);
                mr.seek(off + 8).map_err(axml_truncated)?;
                resource_ids = Vec::with_capacity(count);
                for _ in 0..count {
                    resource_ids.push(mr.read_u32_le().map_err(axml_truncated)?);
                }
            }
            CHUNK_XML_START_NAMESPACE => {
                let p: &StringPool = pool.as_ref().ok_or(Error::AxmlBadStringPool)?;
                let (prefix, uri): (String, String) =
                    parse_namespace(bytes, off, chunk_header_size, p)?;
                if !uri.is_empty() && !ns_uri_to_prefix.contains_key(&uri) {
                    ns_uri_to_prefix.insert(uri.clone(), prefix.clone());
                    namespaces.push(NamespaceBinding { prefix, uri });
                }
            }
            CHUNK_XML_END_NAMESPACE => {}
            CHUNK_XML_START_ELEMENT => {
                let p: &StringPool = pool.as_ref().ok_or(Error::AxmlBadStringPool)?;
                let element: AxmlElement = parse_start_element(
                    bytes,
                    off,
                    chunk_header_size,
                    p,
                    &resource_ids,
                    &ns_uri_to_prefix,
                )?;
                if element_stack.len() >= MAX_DEPTH {
                    return Err(Error::AxmlTruncated);
                }
                element_stack.push(element);
            }
            CHUNK_XML_END_ELEMENT => {
                let finished: AxmlElement = element_stack.pop().ok_or(Error::AxmlTruncated)?;
                match element_stack.last_mut() {
                    Some(parent) => parent.children.push(finished),
                    None => root = Some(finished),
                }
            }
            CHUNK_XML_CDATA => {
                let p: &StringPool = pool.as_ref().ok_or(Error::AxmlBadStringPool)?;
                if let Some(text) = parse_cdata(bytes, off, chunk_header_size, p)?
                    && let Some(parent) = element_stack.last_mut()
                {
                    parent.cdata.push(text);
                }
            }
            _ => {}
        }
        off = next;
    }

    let root: AxmlElement = root.ok_or(Error::AxmlTruncated)?;
    Ok(AxmlDocument { root, namespaces })
}

fn parse_namespace(
    bytes: &[u8],
    chunk_off: usize,
    header_size: u16,
    pool: &StringPool,
) -> Result<(String, String)> {
    let body: usize = chunk_off + header_size as usize;
    let mut r: ByteReader<'_> = ByteReader::new(bytes);
    r.seek(body).map_err(axml_truncated)?;
    let prefix_idx: i32 = r.read_i32_le().map_err(axml_truncated)?;
    let uri_idx: i32 = r.read_i32_le().map_err(axml_truncated)?;
    let prefix: String = pool.optional(prefix_idx)?.unwrap_or("").to_owned();
    let uri: String = pool.required_i32(uri_idx)?.to_owned();
    Ok((prefix, uri))
}

fn parse_cdata(
    bytes: &[u8],
    chunk_off: usize,
    header_size: u16,
    pool: &StringPool,
) -> Result<Option<String>> {
    let body: usize = chunk_off + header_size as usize;
    let mut r: ByteReader<'_> = ByteReader::new(bytes);
    r.seek(body).map_err(axml_truncated)?;
    let data_idx: i32 = r.read_i32_le().map_err(axml_truncated)?;
    Ok(pool
        .optional(data_idx)?
        .map(str::to_owned)
        .filter(|s: &String| !s.trim().is_empty()))
}

fn parse_start_element(
    bytes: &[u8],
    chunk_off: usize,
    header_size: u16,
    pool: &StringPool,
    resource_ids: &[u32],
    ns_uri_to_prefix: &BTreeMap<String, String>,
) -> Result<AxmlElement> {
    let body: usize = chunk_off + header_size as usize;
    let mut r: ByteReader<'_> = ByteReader::new(bytes);
    r.seek(body).map_err(axml_truncated)?;
    let ns_idx: i32 = r.read_i32_le().map_err(axml_truncated)?;
    let name_idx: i32 = r.read_i32_le().map_err(axml_truncated)?;
    let _attr_start: u16 = r.read_u16_le().map_err(axml_truncated)?;
    let _attr_size: u16 = r.read_u16_le().map_err(axml_truncated)?;
    let attr_count: u16 = r.read_u16_le().map_err(axml_truncated)?;
    let _id_index: u16 = r.read_u16_le().map_err(axml_truncated)?;
    let _class_index: u16 = r.read_u16_le().map_err(axml_truncated)?;
    let _style_index: u16 = r.read_u16_le().map_err(axml_truncated)?;

    let name: String = pool.required_i32(name_idx)?.to_owned();
    let el_namespace: Option<String> = pool.optional(ns_idx)?.map(str::to_owned);
    let el_prefix: Option<String> = el_namespace
        .as_deref()
        .and_then(|u: &str| ns_uri_to_prefix.get(u).cloned());

    let mut attributes: Vec<AxmlAttribute> = Vec::with_capacity(attr_count as usize);
    for _ in 0..attr_count {
        let attr_ns_idx: i32 = r.read_i32_le().map_err(axml_truncated)?;
        let attr_name_idx: i32 = r.read_i32_le().map_err(axml_truncated)?;
        let raw_value_idx: i32 = r.read_i32_le().map_err(axml_truncated)?;
        let _value_size: u16 = r.read_u16_le().map_err(axml_truncated)?;
        let _res0: u8 = r.read_u8().map_err(axml_truncated)?;
        let data_type: u8 = r.read_u8().map_err(axml_truncated)?;
        let data: u32 = r.read_u32_le().map_err(axml_truncated)?;

        let attr_id: Option<u32> = if attr_name_idx >= 0 {
            resource_ids.get(attr_name_idx as usize).copied()
        } else {
            None
        };
        let attr_name: String = resolve_attr_name(pool, attr_name_idx, attr_id)?;

        let namespace: Option<String> = pool.optional(attr_ns_idx)?.map(str::to_owned);
        let prefix: Option<String> = namespace
            .as_deref()
            .and_then(|u: &str| ns_uri_to_prefix.get(u).cloned());

        let raw_string: String = if raw_value_idx >= 0 {
            pool.required_i32(raw_value_idx)?.to_owned()
        } else {
            String::new()
        };
        let value: String = if data_type == TYPE_STRING {
            if raw_value_idx >= 0 {
                raw_string.clone()
            } else {
                pool.required_u32(data)?.to_owned()
            }
        } else {
            format_typed_value(data_type, data, &raw_string, None)
        };
        let resource_id: Option<u32> =
            if matches!(data_type, TYPE_REFERENCE | TYPE_DYNAMIC_REFERENCE) {
                Some(data)
            } else {
                None
            };
        attributes.push(AxmlAttribute {
            namespace,
            prefix,
            name: attr_name,
            value,
            resource_id,
            attr_id,
            value_type: data_type,
            raw_data: data,
        });
    }

    Ok(AxmlElement {
        name,
        namespace: el_namespace,
        prefix: el_prefix,
        attributes,
        children: Vec::new(),
        cdata: Vec::new(),
    })
}

fn resolve_attr_name(pool: &StringPool, name_idx: i32, attr_id: Option<u32>) -> Result<String> {
    let from_pool: Option<&str> = pool.optional(name_idx)?.filter(|s: &&str| !s.is_empty());
    if let Some(name) = from_pool {
        return Ok(name.to_owned());
    }
    if let Some(id) = attr_id
        && let Some(name) = framework_attr_name(id)
    {
        return Ok(name.to_owned());
    }
    match attr_id {
        Some(id) => Ok(format!("attr_{id:08x}")),
        None => Err(Error::AxmlBadStringPool),
    }
}

fn escape_attr(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len());
    for ch in s.chars() {
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

fn escape_text(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(ch),
        }
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidManifestSummary {
    pub package: Option<String>,
    pub version_code: Option<String>,
    pub version_name: Option<String>,
    pub compile_sdk_version: Option<String>,
    pub min_sdk_version: Option<String>,
    pub target_sdk_version: Option<String>,
    pub max_sdk_version: Option<String>,
    pub permissions: Vec<String>,
    pub uses_features: Vec<String>,
    pub activities: Vec<ComponentSummary>,
    pub services: Vec<ComponentSummary>,
    pub receivers: Vec<ComponentSummary>,
    pub providers: Vec<ComponentSummary>,
    pub uses_cleartext_traffic: Option<bool>,
    pub debuggable: Option<bool>,
    pub allow_backup: Option<bool>,
    pub network_security_config: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentSummary {
    pub name: String,
    pub exported: Option<bool>,
    pub permission: Option<String>,
    pub intent_actions: Vec<String>,
}

#[must_use]
pub fn summarise_manifest(doc: &AxmlDocument) -> AndroidManifestSummary {
    let root: &AxmlElement = &doc.root;
    let package: Option<String> = root.attribute("package").map(str::to_owned);
    let version_code: Option<String> = android_attr(root, "versionCode").map(str::to_owned);
    let version_name: Option<String> = android_attr(root, "versionName").map(str::to_owned);
    let compile_sdk_version: Option<String> =
        android_attr(root, "compileSdkVersion").map(str::to_owned);

    let mut min_sdk_version: Option<String> = None;
    let mut target_sdk_version: Option<String> = None;
    let mut max_sdk_version: Option<String> = None;
    let mut permissions: Vec<String> = Vec::new();
    let mut uses_features: Vec<String> = Vec::new();
    let mut uses_cleartext_traffic: Option<bool> = None;
    let mut debuggable: Option<bool> = None;
    let mut allow_backup: Option<bool> = None;
    let mut network_security_config: Option<String> = None;
    let mut activities: Vec<ComponentSummary> = Vec::new();
    let mut services: Vec<ComponentSummary> = Vec::new();
    let mut receivers: Vec<ComponentSummary> = Vec::new();
    let mut providers: Vec<ComponentSummary> = Vec::new();

    for el in root.descendants() {
        match el.name.as_str() {
            "uses-permission" | "uses-permission-sdk-23" => {
                if let Some(name) = android_attr(el, "name") {
                    permissions.push(name.to_owned());
                }
            }
            "uses-feature" => {
                if let Some(name) = android_attr(el, "name") {
                    uses_features.push(name.to_owned());
                }
            }
            "uses-sdk" => {
                min_sdk_version = android_attr(el, "minSdkVersion").map(str::to_owned);
                target_sdk_version = android_attr(el, "targetSdkVersion").map(str::to_owned);
                max_sdk_version = android_attr(el, "maxSdkVersion").map(str::to_owned);
            }
            "application" => {
                uses_cleartext_traffic = android_attr(el, "usesCleartextTraffic").map(parse_bool);
                debuggable = android_attr(el, "debuggable").map(parse_bool);
                allow_backup = android_attr(el, "allowBackup").map(parse_bool);
                network_security_config =
                    android_attr(el, "networkSecurityConfig").map(str::to_owned);
            }
            "activity" | "activity-alias" => activities.push(component(el)),
            "service" => services.push(component(el)),
            "receiver" => receivers.push(component(el)),
            "provider" => providers.push(component(el)),
            _ => {}
        }
    }

    permissions.sort_unstable();
    permissions.dedup();
    uses_features.sort_unstable();
    uses_features.dedup();

    AndroidManifestSummary {
        package,
        version_code,
        version_name,
        compile_sdk_version,
        min_sdk_version,
        target_sdk_version,
        max_sdk_version,
        permissions,
        uses_features,
        activities,
        services,
        receivers,
        providers,
        uses_cleartext_traffic,
        debuggable,
        allow_backup,
        network_security_config,
    }
}

fn component(el: &AxmlElement) -> ComponentSummary {
    let name: String = android_attr(el, "name").unwrap_or_default().to_owned();
    let exported: Option<bool> = android_attr(el, "exported").map(parse_bool);
    let permission: Option<String> = android_attr(el, "permission").map(str::to_owned);
    let mut intent_actions: Vec<String> = Vec::new();
    for child in el.descendants() {
        if child.name == "action"
            && let Some(action) = android_attr(child, "name")
        {
            intent_actions.push(action.to_owned());
        }
    }
    intent_actions.sort_unstable();
    intent_actions.dedup();
    ComponentSummary {
        name,
        exported,
        permission,
        intent_actions,
    }
}

fn android_attr<'a>(el: &'a AxmlElement, name: &str) -> Option<&'a str> {
    el.attributes
        .iter()
        .find(|a: &&AxmlAttribute| {
            a.name == name
                && a.namespace
                    .as_deref()
                    .is_none_or(|ns: &str| ns == ANDROID_NS)
        })
        .map(|a: &AxmlAttribute| a.value.as_str())
}

fn parse_bool(value: &str) -> bool {
    matches!(value, "true" | "1" | "0xffffffff")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use disrobe_bytes::ByteReader;

    use super::*;

    #[test]
    fn rejects_non_axml() {
        let err: Error = parse(b"not axml at all").expect_err("must reject");
        assert!(matches!(err, Error::AxmlBadMagic | Error::AxmlTruncated));
    }

    #[test]
    fn chunk_header_reads_little_endian_and_preserves_position_on_error() {
        let bytes: [u8; 8] = [0x03, 0x00, 0x08, 0x00, 0x78, 0x56, 0x34, 0x12];
        let mut reader: ByteReader<'_> = ByteReader::new(&bytes);
        let header: (u16, u16, u32) = read_chunk_header(&mut reader).expect("header reads");
        assert_eq!(header, (0x0003, 0x0008, 0x1234_5678));

        let mut truncated_reader: ByteReader<'_> = ByteReader::new(&bytes[..7]);
        let error: Error = read_chunk_header(&mut truncated_reader).expect_err("header truncates");
        assert!(matches!(error, Error::AxmlTruncated));
        assert_eq!(truncated_reader.position(), 4);
    }

    #[test]
    fn parse_bool_variants() {
        assert!(parse_bool("true"));
        assert!(parse_bool("1"));
        assert!(parse_bool("0xffffffff"));
        assert!(!parse_bool("false"));
        assert!(!parse_bool("0"));
    }

    #[test]
    fn qualified_name_with_prefix() {
        assert_eq!(qualified_name(Some("android"), "label"), "android:label");
        assert_eq!(qualified_name(None, "package"), "package");
        assert_eq!(qualified_name(Some(""), "name"), "name");
    }

    #[test]
    fn dimension_formatting() {
        let v: String = format_typed_value(TYPE_DIMENSION, (16 << 8) | 1, "", None);
        assert_eq!(v, "16.0dp");
    }

    #[test]
    fn color_formatting() {
        let v: String = format_typed_value(TYPE_INT_COLOR_ARGB8, 0xff00_ff00, "", None);
        assert_eq!(v, "#ff00ff00");
    }

    #[test]
    fn null_reference_formats_as_null() {
        let v: String = format_typed_value(TYPE_REFERENCE, 0, "", None);
        assert_eq!(v, "@null");
    }

    #[test]
    fn framework_attr_reference_resolves() {
        let v: String = format_typed_value(TYPE_ATTRIBUTE, 0x0101_0000, "", None);
        assert_eq!(v, "?android:attr/theme");
    }

    fn push_u16(out: &mut Vec<u8>, value: u16) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn push_i32(out: &mut Vec<u8>, value: i32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn start_element_bytes(name_idx: i32, attr_count: u16) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![0u8; 8];
        push_i32(&mut bytes, -1);
        push_i32(&mut bytes, name_idx);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 20);
        push_u16(&mut bytes, attr_count);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        bytes
    }

    #[test]
    fn start_element_rejects_missing_element_name() {
        let pool: StringPool = StringPool {
            strings: vec!["manifest".to_owned()],
        };
        let bytes: Vec<u8> = start_element_bytes(7, 0);
        let err: Error = parse_start_element(&bytes, 0, 8, &pool, &[], &BTreeMap::new())
            .expect_err("missing element name must fail");
        assert!(matches!(err, Error::AxmlBadStringPool));
    }

    #[test]
    fn typed_string_attribute_uses_data_index_when_raw_value_absent() -> Result<()> {
        let pool: StringPool = StringPool {
            strings: vec![
                "manifest".to_owned(),
                "package".to_owned(),
                "com.example.app".to_owned(),
            ],
        };
        let mut bytes: Vec<u8> = start_element_bytes(0, 1);
        push_i32(&mut bytes, -1);
        push_i32(&mut bytes, 1);
        push_i32(&mut bytes, -1);
        push_u16(&mut bytes, 8);
        bytes.push(0);
        bytes.push(TYPE_STRING);
        push_u32(&mut bytes, 2);
        let element: AxmlElement = parse_start_element(&bytes, 0, 8, &pool, &[], &BTreeMap::new())?;
        assert_eq!(element.attributes[0].value, "com.example.app");
        Ok(())
    }
}
