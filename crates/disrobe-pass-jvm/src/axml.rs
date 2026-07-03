use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const RES_XML_TYPE: u16 = 0x0003;
const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;
const RES_XML_START_NAMESPACE_TYPE: u16 = 0x0100;
const RES_XML_END_NAMESPACE_TYPE: u16 = 0x0101;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
const RES_XML_CDATA_TYPE: u16 = 0x0104;
const UTF8_FLAG: u32 = 1 << 8;

pub const TYPE_NULL: u8 = 0x00;
pub const TYPE_REFERENCE: u8 = 0x01;
pub const TYPE_ATTRIBUTE: u8 = 0x02;
pub const TYPE_STRING: u8 = 0x03;
pub const TYPE_FLOAT: u8 = 0x04;
pub const TYPE_DIMENSION: u8 = 0x05;
pub const TYPE_FRACTION: u8 = 0x06;
pub const TYPE_DYNAMIC_REFERENCE: u8 = 0x07;
pub const TYPE_DYNAMIC_ATTRIBUTE: u8 = 0x08;
pub const TYPE_INT_DEC: u8 = 0x10;
pub const TYPE_INT_HEX: u8 = 0x11;
pub const TYPE_INT_BOOLEAN: u8 = 0x12;
pub const TYPE_INT_COLOR_ARGB8: u8 = 0x1c;
pub const TYPE_INT_COLOR_RGB8: u8 = 0x1d;
pub const TYPE_INT_COLOR_ARGB4: u8 = 0x1e;
pub const TYPE_INT_COLOR_RGB4: u8 = 0x1f;

const COMPLEX_UNIT_MASK: u32 = 0x0F;
const COMPLEX_UNIT_SHIFT: u32 = 0;
const COMPLEX_RADIX_MASK: u32 = 0x03;
const COMPLEX_RADIX_SHIFT: u32 = 4;
const COMPLEX_MANTISSA_SHIFT: u32 = 8;
const COMPLEX_MANTISSA_MASK: u32 = 0x00FF_FFFF;

const DIMENSION_UNITS: [&str; 8] = ["px", "dip", "sp", "pt", "in", "mm", "", ""];
const FRACTION_UNITS: [&str; 2] = ["%", "%p"];

const RADIX_MULTIPLIERS: [f64; 4] = [
    1.0 / (1u64 << 23) as f64,
    1.0 / (1u64 << 15) as f64,
    1.0 / (1u64 << 7) as f64,
    1.0,
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AxmlAttribute {
    pub ns: Option<String>,
    pub name: String,
    pub raw_value: Option<String>,
    pub typed_value: u32,
    pub value_type: u8,
    pub resource_id: Option<u32>,
}

impl AxmlAttribute {
    #[must_use]
    pub fn formatted_value(&self, resolver: Option<&dyn ResourceIdResolver>) -> String {
        if self.value_type == TYPE_STRING
            && let Some(raw) = self.raw_value.as_deref()
        {
            return raw.to_owned();
        }
        format_res_value(self.value_type, self.typed_value, resolver)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AxmlNode {
    StartNamespace {
        prefix: String,
        uri: String,
    },
    EndNamespace {
        prefix: String,
        uri: String,
    },
    StartElement {
        ns: Option<String>,
        name: String,
        attributes: Vec<AxmlAttribute>,
    },
    EndElement {
        ns: Option<String>,
        name: String,
    },
    CharData(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AxmlTree {
    pub strings: Vec<String>,
    pub events: Vec<AxmlNode>,
}

pub trait ResourceIdResolver {
    fn resolve(&self, id: u32) -> Option<String>;
}

impl std::fmt::Debug for dyn ResourceIdResolver + '_ {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ResourceIdResolver")
    }
}

#[must_use]
pub fn format_res_value(
    value_type: u8,
    data: u32,
    resolver: Option<&dyn ResourceIdResolver>,
) -> String {
    match value_type {
        TYPE_NULL => {
            if data == 0 {
                "@null".to_owned()
            } else {
                "@empty".to_owned()
            }
        }
        TYPE_REFERENCE | TYPE_DYNAMIC_REFERENCE => format_reference(data, resolver, '@'),
        TYPE_ATTRIBUTE | TYPE_DYNAMIC_ATTRIBUTE => format_reference(data, resolver, '?'),
        TYPE_STRING => data.to_string(),
        TYPE_FLOAT => format_float(f32::from_bits(data)),
        TYPE_DIMENSION => format_complex(data, &DIMENSION_UNITS),
        TYPE_FRACTION => format_complex(data, &FRACTION_UNITS),
        TYPE_INT_DEC => (data as i32).to_string(),
        TYPE_INT_HEX => format!("0x{data:x}"),
        TYPE_INT_BOOLEAN => {
            if data == 0 {
                "false".to_owned()
            } else {
                "true".to_owned()
            }
        }
        TYPE_INT_COLOR_ARGB8 | TYPE_INT_COLOR_RGB8 => format!("#{data:08x}"),
        TYPE_INT_COLOR_ARGB4 | TYPE_INT_COLOR_RGB4 => format!("#{:04x}", data & 0xFFFF),
        _ => format!("(type 0x{value_type:02x}) 0x{data:08x}"),
    }
}

fn format_reference(id: u32, resolver: Option<&dyn ResourceIdResolver>, sigil: char) -> String {
    if let Some(r) = resolver
        && let Some(name) = r.resolve(id)
    {
        return format!("{sigil}{name}");
    }
    if id == 0 {
        return format!("{sigil}null");
    }
    format!("{sigil}0x{id:08x}")
}

fn format_complex(data: u32, units: &[&str]) -> String {
    let mantissa: u32 = (data >> COMPLEX_MANTISSA_SHIFT) & COMPLEX_MANTISSA_MASK;
    let radix: usize = ((data >> COMPLEX_RADIX_SHIFT) & COMPLEX_RADIX_MASK) as usize;
    let unit: usize = ((data >> COMPLEX_UNIT_SHIFT) & COMPLEX_UNIT_MASK) as usize;
    let value: f64 = f64::from(mantissa) * RADIX_MULTIPLIERS[radix];
    let suffix: &str = units.get(unit).copied().unwrap_or("");
    format!("{}{suffix}", format_float(value as f32))
}

fn format_float(value: f32) -> String {
    let is_integral: bool =
        value.is_finite() && value.abs() < 1e16 && (value - value.trunc()).abs() < f32::EPSILON;
    if is_integral {
        format!("{value:.1}")
    } else {
        let mut s: String = format!("{value}");
        if !s.contains('.') && !s.contains('e') && !s.contains("inf") && !s.contains("NaN") {
            s.push_str(".0");
        }
        s
    }
}

pub fn parse(bytes: &[u8]) -> Result<AxmlTree> {
    if bytes.len() < 8 {
        return Err(Error::BadAxmlMagic);
    }
    let chunk_type: u16 = u16::from_le_bytes([bytes[0], bytes[1]]);
    if chunk_type != RES_XML_TYPE {
        return Err(Error::BadAxmlMagic);
    }
    let header_size: u16 = u16::from_le_bytes([bytes[2], bytes[3]]);
    let total_size: u32 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if total_size as usize > bytes.len() || (header_size as usize) > bytes.len() {
        return Err(Error::BadAxml(4));
    }
    let mut cursor: usize = header_size as usize;
    let mut strings: Vec<String> = Vec::new();
    let mut resource_map: Vec<u32> = Vec::new();
    let mut events: Vec<AxmlNode> = Vec::new();
    while cursor + 8 <= bytes.len() {
        let c_type: u16 = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]);
        let c_header_size: u16 = u16::from_le_bytes([bytes[cursor + 2], bytes[cursor + 3]]);
        let c_size: u32 = u32::from_le_bytes([
            bytes[cursor + 4],
            bytes[cursor + 5],
            bytes[cursor + 6],
            bytes[cursor + 7],
        ]);
        if c_size == 0 || cursor + c_size as usize > bytes.len() {
            return Err(Error::BadAxml(cursor));
        }
        let chunk: &[u8] = &bytes[cursor..cursor + c_size as usize];
        match c_type {
            RES_STRING_POOL_TYPE => {
                strings = parse_string_pool(chunk, c_header_size as usize)?;
            }
            RES_XML_RESOURCE_MAP_TYPE => {
                resource_map = parse_resource_map(chunk, c_header_size as usize);
            }
            RES_XML_START_NAMESPACE_TYPE => {
                if let Some(event) = parse_namespace(chunk, &strings, true) {
                    events.push(event);
                }
            }
            RES_XML_END_NAMESPACE_TYPE => {
                if let Some(event) = parse_namespace(chunk, &strings, false) {
                    events.push(event);
                }
            }
            RES_XML_START_ELEMENT_TYPE => {
                let event: AxmlNode = parse_start_element(chunk, &strings, &resource_map)?;
                events.push(event);
            }
            RES_XML_END_ELEMENT_TYPE => {
                let event: AxmlNode = parse_end_element(chunk, &strings)?;
                events.push(event);
            }
            RES_XML_CDATA_TYPE => {
                let event: AxmlNode = parse_cdata(chunk, &strings)?;
                events.push(event);
            }
            _ => {}
        }
        cursor += c_size as usize;
    }
    Ok(AxmlTree { strings, events })
}

fn parse_namespace(chunk: &[u8], strings: &[String], start: bool) -> Option<AxmlNode> {
    if chunk.len() < 24 {
        return None;
    }
    let read_u32 = |o: usize| -> u32 {
        u32::from_le_bytes([chunk[o], chunk[o + 1], chunk[o + 2], chunk[o + 3]])
    };
    let prefix: String = lookup_string(strings, read_u32(16)).unwrap_or_default();
    let uri: String = lookup_string(strings, read_u32(20)).unwrap_or_default();
    if start {
        Some(AxmlNode::StartNamespace { prefix, uri })
    } else {
        Some(AxmlNode::EndNamespace { prefix, uri })
    }
}

fn parse_string_pool(chunk: &[u8], header_size: usize) -> Result<Vec<String>> {
    if header_size < 28 || chunk.len() < header_size {
        return Err(Error::BadAxml(0));
    }
    let read_u32 = |o: usize| -> u32 {
        u32::from_le_bytes([chunk[o], chunk[o + 1], chunk[o + 2], chunk[o + 3]])
    };
    let string_count: u32 = read_u32(8);
    let _style_count: u32 = read_u32(12);
    let flags: u32 = read_u32(16);
    let strings_start: u32 = read_u32(20);
    let is_utf8: bool = (flags & UTF8_FLAG) != 0;
    let count: usize = string_count as usize;
    let alloc_cap: usize = count.min(chunk.len() / 4);
    let mut offsets: Vec<u32> = Vec::with_capacity(alloc_cap);
    for i in 0..count {
        let o: usize = header_size + i * 4;
        if o + 4 > chunk.len() {
            return Err(Error::BadAxml(o));
        }
        offsets.push(read_u32(o));
    }
    let mut out: Vec<String> = Vec::with_capacity(alloc_cap);
    for off in offsets {
        let abs: usize = strings_start as usize + off as usize;
        if abs >= chunk.len() {
            out.push(String::new());
            continue;
        }
        let s: String = if is_utf8 {
            read_utf8_string(&chunk[abs..])
        } else {
            read_utf16_string(&chunk[abs..])
        };
        out.push(s);
    }
    Ok(out)
}

fn read_utf8_string(buf: &[u8]) -> String {
    if buf.len() < 2 {
        return String::new();
    }
    let mut cursor: usize = 0;
    let _u16len: u8 = buf[cursor];
    cursor += 1;
    if (buf[cursor - 1] & 0x80) != 0 {
        if cursor >= buf.len() {
            return String::new();
        }
        cursor += 1;
    }
    let byte_len: u8 = buf[cursor];
    cursor += 1;
    let actual_len: usize = if (byte_len & 0x80) != 0 {
        if cursor >= buf.len() {
            return String::new();
        }
        let extra: u8 = buf[cursor];
        cursor += 1;
        (usize::from(byte_len & 0x7F) << 8) | usize::from(extra)
    } else {
        usize::from(byte_len)
    };
    let end: usize = cursor + actual_len;
    if end > buf.len() {
        return String::new();
    }
    String::from_utf8_lossy(&buf[cursor..end]).into_owned()
}

fn read_utf16_string(buf: &[u8]) -> String {
    if buf.len() < 2 {
        return String::new();
    }
    let mut cursor: usize = 0;
    let first: u16 = u16::from_le_bytes([buf[cursor], buf[cursor + 1]]);
    cursor += 2;
    let len_u16: usize = if (first & 0x8000) != 0 {
        if cursor + 2 > buf.len() {
            return String::new();
        }
        let extra: u16 = u16::from_le_bytes([buf[cursor], buf[cursor + 1]]);
        cursor += 2;
        (usize::from(first & 0x7FFF) << 16) | usize::from(extra)
    } else {
        usize::from(first)
    };
    let end: usize = cursor + len_u16 * 2;
    if end > buf.len() {
        return String::new();
    }
    let mut u16s: Vec<u16> = Vec::with_capacity(len_u16);
    for i in 0..len_u16 {
        let o: usize = cursor + i * 2;
        u16s.push(u16::from_le_bytes([buf[o], buf[o + 1]]));
    }
    String::from_utf16_lossy(&u16s)
}

fn parse_resource_map(chunk: &[u8], header_size: usize) -> Vec<u32> {
    let start: usize = header_size.max(8);
    if chunk.len() <= start {
        return Vec::new();
    }
    let count: usize = (chunk.len() - start) / 4;
    let mut ids: Vec<u32> = Vec::with_capacity(count);
    for i in 0..count {
        let o: usize = start + i * 4;
        ids.push(u32::from_le_bytes([
            chunk[o],
            chunk[o + 1],
            chunk[o + 2],
            chunk[o + 3],
        ]));
    }
    ids
}

fn parse_start_element(chunk: &[u8], strings: &[String], resource_map: &[u32]) -> Result<AxmlNode> {
    if chunk.len() < 36 {
        return Err(Error::BadAxml(0));
    }
    let read_u32 = |o: usize| -> u32 {
        u32::from_le_bytes([chunk[o], chunk[o + 1], chunk[o + 2], chunk[o + 3]])
    };
    let read_u16 = |o: usize| -> u16 { u16::from_le_bytes([chunk[o], chunk[o + 1]]) };
    let ns_idx: u32 = read_u32(16);
    let name_idx: u32 = read_u32(20);
    let attr_start: u16 = read_u16(24);
    let _attr_size: u16 = read_u16(26);
    let attr_count: u16 = read_u16(28);
    let ns: Option<String> = lookup_string(strings, ns_idx);
    let name: String = lookup_string(strings, name_idx).unwrap_or_default();
    let mut attributes: Vec<AxmlAttribute> = Vec::with_capacity(usize::from(attr_count));
    let body_start: usize = 16 + usize::from(attr_start);
    let attr_record: usize = 20;
    for i in 0..usize::from(attr_count) {
        let o: usize = body_start + i * attr_record;
        if o + attr_record > chunk.len() {
            break;
        }
        let a_ns_idx: u32 = read_u32(o);
        let a_name_idx: u32 = read_u32(o + 4);
        let a_raw_idx: u32 = read_u32(o + 8);
        let value_type: u8 = chunk[o + 15];
        let typed_value: u32 = read_u32(o + 16);
        let resource_id: Option<u32> = if a_name_idx == u32::MAX {
            None
        } else {
            resource_map.get(a_name_idx as usize).copied()
        };
        let name: String = resolve_attr_name(strings, a_name_idx, resource_id);
        attributes.push(AxmlAttribute {
            ns: lookup_string(strings, a_ns_idx),
            name,
            raw_value: lookup_string(strings, a_raw_idx),
            typed_value,
            value_type,
            resource_id,
        });
    }
    Ok(AxmlNode::StartElement {
        ns,
        name,
        attributes,
    })
}

fn resolve_attr_name(strings: &[String], name_idx: u32, resource_id: Option<u32>) -> String {
    let from_pool: String = lookup_string(strings, name_idx).unwrap_or_default();
    if !from_pool.is_empty() {
        return from_pool;
    }
    if let Some(id) = resource_id {
        if let Some(known) = crate::android_attrs::framework_attr_name(id) {
            return known.to_owned();
        }
        return format!("attr_0x{id:08x}");
    }
    from_pool
}

fn parse_end_element(chunk: &[u8], strings: &[String]) -> Result<AxmlNode> {
    if chunk.len() < 24 {
        return Err(Error::BadAxml(0));
    }
    let read_u32 = |o: usize| -> u32 {
        u32::from_le_bytes([chunk[o], chunk[o + 1], chunk[o + 2], chunk[o + 3]])
    };
    let ns_idx: u32 = read_u32(16);
    let name_idx: u32 = read_u32(20);
    Ok(AxmlNode::EndElement {
        ns: lookup_string(strings, ns_idx),
        name: lookup_string(strings, name_idx).unwrap_or_default(),
    })
}

fn parse_cdata(chunk: &[u8], strings: &[String]) -> Result<AxmlNode> {
    if chunk.len() < 20 {
        return Err(Error::BadAxml(0));
    }
    let read_u32 = |o: usize| -> u32 {
        u32::from_le_bytes([chunk[o], chunk[o + 1], chunk[o + 2], chunk[o + 3]])
    };
    let data_idx: u32 = read_u32(16);
    Ok(AxmlNode::CharData(
        lookup_string(strings, data_idx).unwrap_or_default(),
    ))
}

fn lookup_string(strings: &[String], idx: u32) -> Option<String> {
    if idx == u32::MAX {
        return None;
    }
    strings.get(idx as usize).cloned()
}

impl AxmlTree {
    #[must_use]
    pub fn to_xml(&self) -> String {
        self.to_xml_with_resolver(None)
    }

    #[must_use]
    pub fn to_xml_with_resolver(&self, resolver: Option<&dyn ResourceIdResolver>) -> String {
        let mut prefixes: BTreeMap<String, String> = BTreeMap::new();
        let mut pending_ns: Vec<(String, String)> = Vec::new();
        for ev in &self.events {
            if let AxmlNode::StartNamespace { prefix, uri } = ev {
                prefixes.insert(uri.clone(), prefix.clone());
            }
        }
        let mut out: String = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
        let mut depth: usize = 0;
        for ev in &self.events {
            match ev {
                AxmlNode::StartNamespace { prefix, uri } => {
                    pending_ns.push((prefix.clone(), uri.clone()));
                }
                AxmlNode::EndNamespace { .. } => {}
                AxmlNode::StartElement {
                    ns: _,
                    name,
                    attributes,
                } => {
                    for _ in 0..depth {
                        out.push_str("    ");
                    }
                    out.push('<');
                    out.push_str(name);
                    for (prefix, uri) in std::mem::take(&mut pending_ns) {
                        let _ = write!(out, " xmlns:{prefix}=\"{}\"", escape_attr(&uri));
                    }
                    for attr in attributes {
                        let prefix: Option<&String> =
                            attr.ns.as_ref().and_then(|u: &String| prefixes.get(u));
                        let value: String = attr.formatted_value(resolver);
                        match prefix {
                            Some(p) => {
                                let _ =
                                    write!(out, " {p}:{}=\"{}\"", attr.name, escape_attr(&value));
                            }
                            None => {
                                let _ = write!(out, " {}=\"{}\"", attr.name, escape_attr(&value));
                            }
                        }
                    }
                    out.push('>');
                    out.push('\n');
                    depth += 1;
                }
                AxmlNode::EndElement { ns: _, name } => {
                    depth = depth.saturating_sub(1);
                    for _ in 0..depth {
                        out.push_str("    ");
                    }
                    let _ = write!(out, "</{name}>");
                    out.push('\n');
                }
                AxmlNode::CharData(text) => {
                    for _ in 0..depth {
                        out.push_str("    ");
                    }
                    out.push_str(&escape_text(text));
                    out.push('\n');
                }
            }
        }
        out
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rejects_too_short() {
        let err: Error = parse(&[0u8; 4]).expect_err("too short");
        assert!(matches!(err, Error::BadAxmlMagic));
    }

    #[test]
    fn rejects_wrong_chunk_type() {
        let mut bytes: Vec<u8> = Vec::with_capacity(8);
        bytes.extend_from_slice(&0x0001u16.to_le_bytes());
        bytes.extend_from_slice(&0x0008u16.to_le_bytes());
        bytes.extend_from_slice(&8u32.to_le_bytes());
        let err: Error = parse(&bytes).expect_err("not xml");
        assert!(matches!(err, Error::BadAxmlMagic));
    }

    #[test]
    fn decodes_int_dec() {
        assert_eq!(format_res_value(TYPE_INT_DEC, 34, None), "34");
        assert_eq!(format_res_value(TYPE_INT_DEC, (-7i32) as u32, None), "-7");
    }

    #[test]
    fn decodes_int_hex() {
        assert_eq!(format_res_value(TYPE_INT_HEX, 0x7f01, None), "0x7f01");
    }

    #[test]
    fn decodes_bool() {
        assert_eq!(format_res_value(TYPE_INT_BOOLEAN, 0, None), "false");
        assert_eq!(format_res_value(TYPE_INT_BOOLEAN, 1, None), "true");
        assert_eq!(
            format_res_value(TYPE_INT_BOOLEAN, 0xffff_ffff, None),
            "true"
        );
    }

    #[test]
    fn decodes_float() {
        assert_eq!(format_res_value(TYPE_FLOAT, 1.5f32.to_bits(), None), "1.5");
        assert_eq!(format_res_value(TYPE_FLOAT, 2.0f32.to_bits(), None), "2.0");
    }

    #[test]
    fn decodes_reference_unresolved() {
        assert_eq!(
            format_res_value(TYPE_REFERENCE, 0x7f01_0000, None),
            "@0x7f010000"
        );
        assert_eq!(
            format_res_value(TYPE_ATTRIBUTE, 0x0101_0001, None),
            "?0x01010001"
        );
    }

    #[test]
    fn decodes_reference_resolved() {
        struct R;
        impl ResourceIdResolver for R {
            fn resolve(&self, id: u32) -> Option<String> {
                (id == 0x7f01_0000).then(|| "com.x.string.app_name".to_owned())
            }
        }
        let r: R = R;
        assert_eq!(
            format_res_value(TYPE_REFERENCE, 0x7f01_0000, Some(&r)),
            "@com.x.string.app_name"
        );
    }

    #[test]
    fn decodes_dimension() {
        let data: u32 = (16u32 << COMPLEX_MANTISSA_SHIFT) | (3u32 << COMPLEX_RADIX_SHIFT) | 1u32;
        assert_eq!(format_res_value(TYPE_DIMENSION, data, None), "16.0dip");
    }

    #[test]
    fn decodes_color() {
        assert_eq!(
            format_res_value(TYPE_INT_COLOR_ARGB8, 0xffaa_bbcc, None),
            "#ffaabbcc"
        );
    }
}
