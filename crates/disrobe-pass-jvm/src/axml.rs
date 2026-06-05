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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AxmlAttribute {
    pub ns: Option<String>,
    pub name: String,
    pub raw_value: Option<String>,
    pub typed_value: u32,
    pub value_type: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AxmlNode {
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
            RES_XML_RESOURCE_MAP_TYPE => {}
            RES_XML_START_NAMESPACE_TYPE | RES_XML_END_NAMESPACE_TYPE => {}
            RES_XML_START_ELEMENT_TYPE => {
                let event: AxmlNode = parse_start_element(chunk, &strings)?;
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

fn parse_start_element(chunk: &[u8], strings: &[String]) -> Result<AxmlNode> {
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
        attributes.push(AxmlAttribute {
            ns: lookup_string(strings, a_ns_idx),
            name: lookup_string(strings, a_name_idx).unwrap_or_default(),
            raw_value: lookup_string(strings, a_raw_idx),
            typed_value,
            value_type,
        });
    }
    Ok(AxmlNode::StartElement {
        ns,
        name,
        attributes,
    })
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
}
