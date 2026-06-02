use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const RES_NULL_TYPE: u16 = 0x0000;
pub const RES_STRING_POOL_TYPE: u16 = 0x0001;
pub const RES_TABLE_TYPE: u16 = 0x0002;
pub const RES_TABLE_PACKAGE_TYPE: u16 = 0x0200;
pub const RES_STRING_POOL_UTF8_FLAG: u32 = 0x0100;

const CHUNK_HEADER_SIZE: usize = 8;
const PACKAGE_NAME_UNITS: usize = 128;

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
pub struct ResTablePackage {
    pub id: u32,
    pub name: String,
    pub type_strings: ResStringPool,
    pub key_strings: ResStringPool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceTable {
    pub package_count: u32,
    pub global_strings: ResStringPool,
    pub packages: Vec<ResTablePackage>,
}

fn parse_package(bytes: &[u8], chunk_off: usize, chunk_size: usize) -> Result<ResTablePackage> {
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

    let _bound: usize = chunk_off
        .checked_add(chunk_size)
        .ok_or(Error::ArscTruncated {
            offset: chunk_off,
            needed: chunk_size,
            had: bytes.len(),
        })?;

    Ok(ResTablePackage {
        id,
        name,
        type_strings,
        key_strings,
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
