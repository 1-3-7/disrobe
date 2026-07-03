use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const CHUNK_TABLE: u16 = 0x0002;
const CHUNK_STRING_POOL: u16 = 0x0001;
const CHUNK_PACKAGE: u16 = 0x0200;
const CHUNK_TYPE_SPEC: u16 = 0x0202;
const CHUNK_TYPE: u16 = 0x0201;
const CHUNK_LIBRARY: u16 = 0x0203;

const FLAG_UTF8: u32 = 1 << 8;
const MAX_POOL_STRINGS: u32 = 1 << 22;
const MAX_TYPE_ENTRIES: u32 = 1 << 20;
const NO_ENTRY: u32 = 0xffff_ffff;
const ENTRY_FLAG_COMPLEX: u16 = 0x0001;
const PACKAGE_NAME_UNITS: usize = 128;

const TYPE_NULL: u8 = 0x00;
const TYPE_REFERENCE: u8 = 0x01;
const TYPE_ATTRIBUTE: u8 = 0x02;
const TYPE_STRING: u8 = 0x03;
const TYPE_FLOAT: u8 = 0x04;
const TYPE_DIMENSION: u8 = 0x05;
const TYPE_FRACTION: u8 = 0x06;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArscEntry {
    pub id: u32,
    pub type_name: String,
    pub key_name: String,
    pub value: Option<String>,
    pub is_complex: bool,
    pub config: String,
    pub value_type: u8,
    pub raw_data: u32,
}

impl ArscEntry {
    #[must_use]
    pub fn qualified_name(&self) -> String {
        format!("{}/{}", self.type_name, self.key_name)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArscPackageSummary {
    pub id: u32,
    pub name: String,
    pub type_names: Vec<String>,
    pub key_count: usize,
    pub entries: Vec<ArscEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArscResources {
    pub value_strings: Vec<String>,
    pub packages: Vec<ArscPackageSummary>,
}

impl ArscResources {
    #[must_use]
    pub fn resolve(&self, id: u32) -> Option<String> {
        let package_id: u32 = id >> 24;
        for pkg in &self.packages {
            if pkg.id != package_id {
                continue;
            }
            for entry in &pkg.entries {
                if entry.id == id {
                    return Some(format!("{}:{}", pkg.name, entry.qualified_name()));
                }
            }
        }
        None
    }

    #[must_use]
    pub fn resource_count(&self) -> usize {
        self.packages
            .iter()
            .map(|p: &ArscPackageSummary| p.entries.len())
            .sum()
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8], pos: usize) -> Self {
        Self { bytes, pos }
    }

    fn u8(&mut self) -> Result<u8> {
        let b: u8 = *self.bytes.get(self.pos).ok_or(Error::ArscTruncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn u16(&mut self) -> Result<u16> {
        let end: usize = self.pos.checked_add(2).ok_or(Error::ArscTruncated)?;
        let slice: &[u8] = self.bytes.get(self.pos..end).ok_or(Error::ArscTruncated)?;
        self.pos = end;
        Ok(u16::from_le_bytes([slice[0], slice[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let end: usize = self.pos.checked_add(4).ok_or(Error::ArscTruncated)?;
        let slice: &[u8] = self.bytes.get(self.pos..end).ok_or(Error::ArscTruncated)?;
        self.pos = end;
        Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    }
}

fn parse_string_pool(bytes: &[u8], chunk_off: usize) -> Result<Vec<String>> {
    let mut r: Reader<'_> = Reader::new(bytes, chunk_off);
    let chunk_type: u16 = r.u16()?;
    if chunk_type != CHUNK_STRING_POOL {
        return Err(Error::ArscBadStringPool);
    }
    let header_size: u16 = r.u16()?;
    let chunk_size: u32 = r.u32()?;
    let chunk_end: usize = chunk_off
        .checked_add(chunk_size as usize)
        .filter(|end: &usize| *end <= bytes.len())
        .ok_or(Error::ArscTruncated)?;
    let string_count: u32 = r.u32()?;
    if string_count > MAX_POOL_STRINGS {
        return Err(Error::ArscTruncated);
    }
    let _style_count: u32 = r.u32()?;
    let flags: u32 = r.u32()?;
    let strings_start: u32 = r.u32()?;
    let _styles_start: u32 = r.u32()?;
    let is_utf8: bool = flags & FLAG_UTF8 != 0;

    let offsets_base: usize = chunk_off + header_size as usize;
    let mut off_reader: Reader<'_> = Reader::new(bytes, offsets_base);
    let mut offsets: Vec<u32> = Vec::with_capacity(string_count as usize);
    for _ in 0..string_count {
        offsets.push(off_reader.u32()?);
    }

    let data_base: usize = chunk_off + strings_start as usize;
    let mut strings: Vec<String> = Vec::with_capacity(offsets.len());
    for off in offsets {
        let start: usize = data_base
            .checked_add(off as usize)
            .filter(|s: &usize| *s < chunk_end)
            .ok_or(Error::ArscTruncated)?;
        let s: String = if is_utf8 {
            decode_utf8_string(bytes, start, chunk_end)?
        } else {
            decode_utf16_string(bytes, start, chunk_end)?
        };
        strings.push(s);
    }
    Ok(strings)
}

fn read_len_utf8(bytes: &[u8], pos: usize, end: usize) -> Result<(usize, usize)> {
    let b0: u8 = *bytes.get(pos).ok_or(Error::ArscTruncated)?;
    if b0 & 0x80 != 0 {
        let b1: u8 = *bytes.get(pos + 1).ok_or(Error::ArscTruncated)?;
        let len: usize = (((b0 & 0x7f) as usize) << 8) | b1 as usize;
        if pos + 2 > end {
            return Err(Error::ArscTruncated);
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
        .ok_or(Error::ArscTruncated)?;
    Ok(String::from_utf8_lossy(&bytes[data_start..data_end]).into_owned())
}

fn read_len_utf16(bytes: &[u8], pos: usize, end: usize) -> Result<(usize, usize)> {
    let lo: u8 = *bytes.get(pos).ok_or(Error::ArscTruncated)?;
    let hi: u8 = *bytes.get(pos + 1).ok_or(Error::ArscTruncated)?;
    let first: u16 = u16::from_le_bytes([lo, hi]);
    if first & 0x8000 != 0 {
        let lo2: u8 = *bytes.get(pos + 2).ok_or(Error::ArscTruncated)?;
        let hi2: u8 = *bytes.get(pos + 3).ok_or(Error::ArscTruncated)?;
        let second: u16 = u16::from_le_bytes([lo2, hi2]);
        let len: usize = (((first & 0x7fff) as usize) << 16) | second as usize;
        if pos + 4 > end {
            return Err(Error::ArscTruncated);
        }
        Ok((len, pos + 4))
    } else {
        Ok((first as usize, pos + 2))
    }
}

fn decode_utf16_string(bytes: &[u8], pos: usize, end: usize) -> Result<String> {
    let (char_len, data_start): (usize, usize) = read_len_utf16(bytes, pos, end)?;
    let byte_len: usize = char_len.checked_mul(2).ok_or(Error::ArscTruncated)?;
    let data_end: usize = data_start
        .checked_add(byte_len)
        .filter(|e: &usize| *e <= end)
        .ok_or(Error::ArscTruncated)?;
    let units: Vec<u16> = bytes[data_start..data_end]
        .chunks_exact(2)
        .map(|c: &[u8]| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Ok(String::from_utf16_lossy(&units))
}

pub fn parse(bytes: &[u8]) -> Result<ArscResources> {
    let mut r: Reader<'_> = Reader::new(bytes, 0);
    let chunk_type: u16 = r.u16()?;
    if chunk_type != CHUNK_TABLE {
        return Err(Error::ArscBadMagic);
    }
    let header_size: u16 = r.u16()?;
    let _table_size: u32 = r.u32()?;
    let _package_count: u32 = r.u32()?;

    let mut value_strings: Vec<String> = Vec::new();
    let mut packages: Vec<ArscPackageSummary> = Vec::new();

    let mut off: usize = header_size as usize;
    let mut first_pool: bool = true;
    while off + 8 <= bytes.len() {
        let mut hr: Reader<'_> = Reader::new(bytes, off);
        let ctype: u16 = hr.u16()?;
        let _chsize_hdr: u16 = hr.u16()?;
        let csize: u32 = hr.u32()?;
        if csize < 8 {
            return Err(Error::ArscTruncated);
        }
        let next: usize = off
            .checked_add(csize as usize)
            .filter(|n: &usize| *n <= bytes.len())
            .ok_or(Error::ArscTruncated)?;

        match ctype {
            CHUNK_STRING_POOL if first_pool => {
                value_strings = parse_string_pool(bytes, off)?;
                first_pool = false;
            }
            CHUNK_PACKAGE => {
                packages.push(parse_package(bytes, off, next, &value_strings)?);
            }
            _ => {}
        }
        off = next;
    }

    Ok(ArscResources {
        value_strings,
        packages,
    })
}

fn parse_package(
    bytes: &[u8],
    chunk_off: usize,
    chunk_end: usize,
    value_strings: &[String],
) -> Result<ArscPackageSummary> {
    let mut r: Reader<'_> = Reader::new(bytes, chunk_off + 8);
    let id: u32 = r.u32()?;
    let name: String = read_package_name(bytes, r.pos)?;
    r.pos += PACKAGE_NAME_UNITS * 2;
    let type_strings_off: u32 = r.u32()?;
    let _last_public_type: u32 = r.u32()?;
    let key_strings_off: u32 = r.u32()?;
    let _last_public_key: u32 = r.u32()?;

    let type_names: Vec<String> =
        parse_declared_package_string_pool(bytes, chunk_off, chunk_end, type_strings_off)?;
    let key_names: Vec<String> =
        parse_declared_package_string_pool(bytes, chunk_off, chunk_end, key_strings_off)?;
    let key_count: usize = key_names.len();

    let mut entries: BTreeMap<(u32, String), ArscEntry> = BTreeMap::new();
    let header_size: u16 = u16::from_le_bytes([
        *bytes.get(chunk_off + 2).ok_or(Error::ArscTruncated)?,
        *bytes.get(chunk_off + 3).ok_or(Error::ArscTruncated)?,
    ]);
    let mut off: usize = chunk_off + header_size as usize;
    while off + 8 <= chunk_end {
        let mut hr: Reader<'_> = Reader::new(bytes, off);
        let ctype: u16 = hr.u16()?;
        let _chsize_hdr: u16 = hr.u16()?;
        let csize: u32 = hr.u32()?;
        if csize < 8 {
            return Err(Error::ArscTruncated);
        }
        let next: usize = off
            .checked_add(csize as usize)
            .filter(|n: &usize| *n <= chunk_end)
            .ok_or(Error::ArscTruncated)?;

        match ctype {
            CHUNK_TYPE => {
                parse_type_chunk(
                    bytes,
                    off,
                    next,
                    id,
                    &type_names,
                    &key_names,
                    value_strings,
                    &mut entries,
                )?;
            }
            CHUNK_TYPE_SPEC | CHUNK_LIBRARY | CHUNK_STRING_POOL => {}
            _ => {}
        }
        off = next;
    }

    Ok(ArscPackageSummary {
        id,
        name,
        type_names,
        key_count,
        entries: entries.into_values().collect(),
    })
}

fn parse_declared_package_string_pool(
    bytes: &[u8],
    package_off: usize,
    package_end: usize,
    relative_off: u32,
) -> Result<Vec<String>> {
    if relative_off == 0 {
        return Ok(Vec::new());
    }
    let pool_off: usize = package_off
        .checked_add(relative_off as usize)
        .filter(|off: &usize| {
            off.checked_add(8)
                .is_some_and(|end: usize| end <= package_end)
        })
        .ok_or(Error::ArscTruncated)?;
    let mut r: Reader<'_> = Reader::new(bytes, pool_off);
    let _chunk_type: u16 = r.u16()?;
    let _header_size: u16 = r.u16()?;
    let chunk_size: u32 = r.u32()?;
    pool_off
        .checked_add(chunk_size as usize)
        .filter(|end: &usize| *end <= package_end)
        .ok_or(Error::ArscTruncated)?;
    parse_string_pool(bytes, pool_off)
}

#[allow(clippy::too_many_arguments)]
fn parse_type_chunk(
    bytes: &[u8],
    chunk_off: usize,
    chunk_end: usize,
    package_id: u32,
    type_names: &[String],
    key_names: &[String],
    value_strings: &[String],
    out: &mut BTreeMap<(u32, String), ArscEntry>,
) -> Result<()> {
    let mut r: Reader<'_> = Reader::new(bytes, chunk_off);
    let _ctype: u16 = r.u16()?;
    let header_size: u16 = r.u16()?;
    let _csize: u32 = r.u32()?;
    let type_id: u8 = r.u8()?;
    let _res0: u8 = r.u8()?;
    let _res1: u16 = r.u16()?;
    let entry_count: u32 = r.u32()?;
    let entries_start: u32 = r.u32()?;
    if entry_count > MAX_TYPE_ENTRIES {
        return Err(Error::ArscTruncated);
    }
    if type_id == 0 {
        return Ok(());
    }

    let config: String = read_config_qualifier(bytes, r.pos, chunk_end);

    let type_name: String = type_names
        .get((type_id - 1) as usize)
        .cloned()
        .unwrap_or_else(|| format!("type{type_id}"));

    let index_base: usize = chunk_off + header_size as usize;
    let data_base: usize = chunk_off
        .checked_add(entries_start as usize)
        .filter(|b: &usize| *b <= chunk_end)
        .ok_or(Error::ArscTruncated)?;

    let mut index_reader: Reader<'_> = Reader::new(bytes, index_base);
    for entry_index in 0..entry_count {
        let entry_off: u32 = index_reader.u32()?;
        if entry_off == NO_ENTRY {
            continue;
        }
        let entry_pos: usize = data_base
            .checked_add(entry_off as usize)
            .filter(|p: &usize| *p + 8 <= chunk_end)
            .ok_or(Error::ArscTruncated)?;
        let mut er: Reader<'_> = Reader::new(bytes, entry_pos);
        let _entry_size: u16 = er.u16()?;
        let entry_flags: u16 = er.u16()?;
        let key_idx: u32 = er.u32()?;
        let is_complex: bool = entry_flags & ENTRY_FLAG_COMPLEX != 0;

        let key_name: String = key_names
            .get(key_idx as usize)
            .cloned()
            .unwrap_or_else(|| format!("key{key_idx}"));

        let (value, value_type, raw_data): (Option<String>, u8, u32) = if is_complex {
            (None, TYPE_NULL, 0)
        } else {
            read_res_value(bytes, er.pos, chunk_end, value_strings)
                .map(|(s, t, d): (String, u8, u32)| (Some(s), t, d))
                .unwrap_or((None, TYPE_NULL, 0))
        };

        let id: u32 = (package_id << 24) | ((type_id as u32) << 16) | entry_index;
        out.insert(
            (id, config.clone()),
            ArscEntry {
                id,
                type_name: type_name.clone(),
                key_name,
                value,
                is_complex,
                config: config.clone(),
                value_type,
                raw_data,
            },
        );
    }
    Ok(())
}

fn read_config_qualifier(bytes: &[u8], pos: usize, end: usize) -> String {
    let Some(slice) = bytes.get(pos..end) else {
        return String::new();
    };
    if slice.len() < 4 {
        return String::new();
    }
    let size: u32 = u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]);
    if size < 28 || (size as usize) > slice.len() {
        return String::new();
    }
    let read_u16 = |off: usize| -> u16 {
        slice
            .get(off..off + 2)
            .map(|b: &[u8]| u16::from_le_bytes([b[0], b[1]]))
            .unwrap_or(0)
    };
    let mut parts: Vec<String> = Vec::new();
    let orientation: u8 = slice.get(16).copied().unwrap_or(0);
    match orientation {
        1 => parts.push("port".to_owned()),
        2 => parts.push("land".to_owned()),
        _ => {}
    }
    let density: u16 = read_u16(22);
    match density {
        0 => {}
        120 => parts.push("ldpi".to_owned()),
        160 => parts.push("mdpi".to_owned()),
        213 => parts.push("tvdpi".to_owned()),
        240 => parts.push("hdpi".to_owned()),
        320 => parts.push("xhdpi".to_owned()),
        480 => parts.push("xxhdpi".to_owned()),
        640 => parts.push("xxxhdpi".to_owned()),
        other => parts.push(format!("{other}dpi")),
    }
    let sdk_version: u16 = read_u16(24);
    if sdk_version != 0 {
        parts.push(format!("v{sdk_version}"));
    }
    parts.join("-")
}

fn read_res_value(
    bytes: &[u8],
    pos: usize,
    end: usize,
    value_strings: &[String],
) -> Result<(String, u8, u32)> {
    if pos + 8 > end {
        return Err(Error::ArscTruncated);
    }
    let mut r: Reader<'_> = Reader::new(bytes, pos);
    let _size: u16 = r.u16()?;
    let _res0: u8 = r.u8()?;
    let data_type: u8 = r.u8()?;
    let data: u32 = r.u32()?;
    Ok((
        format_arsc_value(data_type, data, value_strings),
        data_type,
        data,
    ))
}

fn format_arsc_value(data_type: u8, data: u32, value_strings: &[String]) -> String {
    match data_type {
        TYPE_NULL => String::new(),
        TYPE_STRING => value_strings
            .get(data as usize)
            .cloned()
            .unwrap_or_else(|| format!("@string-pool#{data}")),
        TYPE_INT_BOOL => {
            if data == 0 {
                "false".to_owned()
            } else {
                "true".to_owned()
            }
        }
        TYPE_INT_HEX => format!("0x{data:x}"),
        TYPE_INT_DEC => (data as i32).to_string(),
        TYPE_REFERENCE => format!("@0x{data:08x}"),
        TYPE_ATTRIBUTE => format!("?0x{data:08x}"),
        TYPE_FLOAT => f32::from_bits(data).to_string(),
        TYPE_DIMENSION => format_complex(data, &DIMENSION_UNITS),
        TYPE_FRACTION => format_complex(data, &FRACTION_UNITS),
        TYPE_INT_COLOR_ARGB8 | TYPE_INT_COLOR_RGB8 => format!("#{data:08x}"),
        TYPE_INT_COLOR_ARGB4 | TYPE_INT_COLOR_RGB4 => format!("#{data:04x}"),
        _ => (data as i32).to_string(),
    }
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
    let mut s: String = format!("{value}");
    if !s.contains('.') && !s.contains('e') {
        s.push_str(".0");
    }
    s + unit
}

fn read_package_name(bytes: &[u8], pos: usize) -> Result<String> {
    let end: usize = pos
        .checked_add(PACKAGE_NAME_UNITS * 2)
        .ok_or(Error::ArscTruncated)?;
    let slice: &[u8] = bytes.get(pos..end).ok_or(Error::ArscTruncated)?;
    let units: Vec<u16> = slice
        .chunks_exact(2)
        .map(|c: &[u8]| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|u: &u16| *u != 0)
        .collect();
    Ok(String::from_utf16_lossy(&units))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_arsc() {
        let err: Error = parse(b"not a resource table").expect_err("must reject");
        assert!(matches!(err, Error::ArscBadMagic | Error::ArscTruncated));
    }

    #[test]
    fn qualified_name_joins_type_and_key() {
        let entry: ArscEntry = ArscEntry {
            id: 0x7f03_0000,
            type_name: "string".to_owned(),
            key_name: "app_name".to_owned(),
            value: Some("Hi".to_owned()),
            is_complex: false,
            config: String::new(),
            value_type: TYPE_STRING,
            raw_data: 0,
        };
        assert_eq!(entry.qualified_name(), "string/app_name");
    }

    #[test]
    fn declared_package_string_pool_must_stay_inside_package_chunk() {
        let bytes: Vec<u8> = vec![0u8; 64];
        let err: Error = parse_declared_package_string_pool(&bytes, 16, 32, 20)
            .expect_err("declared pool outside package must fail");
        assert!(matches!(err, Error::ArscTruncated));
    }
}
