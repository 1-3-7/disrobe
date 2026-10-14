use serde::Serialize;

use super::SqliteError;

pub(super) const HEADER_MAGIC: &[u8; 16] = b"SQLite format 3\0";
pub(super) const HEADER_LEN: usize = 100;
pub(super) const PAGE_LEAF_TABLE: u8 = 13;
pub(super) const PAGE_INTERIOR_TABLE: u8 = 5;
pub(super) const PAGE_LEAF_INDEX: u8 = 10;
pub(super) const PAGE_INTERIOR_INDEX: u8 = 2;
const MIN_PAGE_SIZE: u32 = 512;
const MAX_PAGE_SIZE: u32 = 65_536;
const MAX_VARINT_BYTES: usize = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TextEncoding {
    Utf8,
    Utf16le,
    Utf16be,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SqliteHeader {
    pub page_size: u32,
    pub write_version: u8,
    pub read_version: u8,
    pub reserved_bytes: u8,
    pub change_counter: u32,
    pub header_page_count: u32,
    pub freelist_trunk: u32,
    pub freelist_count: u32,
    pub schema_cookie: u32,
    pub schema_format: u32,
    pub default_cache_size: i32,
    pub autovacuum_top_root: u32,
    pub text_encoding: TextEncoding,
    pub user_version: i32,
    pub incremental_vacuum: bool,
    pub application_id: u32,
    pub version_valid_for: u32,
    pub sqlite_version_number: u32,
}

impl SqliteHeader {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, SqliteError> {
        let header: &[u8] = bytes.get(..HEADER_LEN).ok_or(SqliteError::NotSqlite)?;
        if header.get(..16) != Some(HEADER_MAGIC.as_slice()) {
            return Err(SqliteError::NotSqlite);
        }
        let raw_page_size: u32 = u32::from(be16(header, 16));
        let page_size: u32 = if raw_page_size == 1 {
            MAX_PAGE_SIZE
        } else {
            raw_page_size
        };
        if !(MIN_PAGE_SIZE..=MAX_PAGE_SIZE).contains(&page_size) || !page_size.is_power_of_two() {
            return Err(SqliteError::BadHeader {
                field: "page size",
                value: u64::from(raw_page_size),
            });
        }
        let reserved_bytes: u8 = header[20];
        if u32::from(reserved_bytes) + 480 > page_size {
            return Err(SqliteError::BadHeader {
                field: "reserved bytes per page",
                value: u64::from(reserved_bytes),
            });
        }
        let text_encoding: TextEncoding = match be32(header, 56) {
            0 | 1 => TextEncoding::Utf8,
            2 => TextEncoding::Utf16le,
            3 => TextEncoding::Utf16be,
            other => {
                return Err(SqliteError::BadHeader {
                    field: "text encoding",
                    value: u64::from(other),
                });
            }
        };
        Ok(Self {
            page_size,
            write_version: header[18],
            read_version: header[19],
            reserved_bytes,
            change_counter: be32(header, 24),
            header_page_count: be32(header, 28),
            freelist_trunk: be32(header, 32),
            freelist_count: be32(header, 36),
            schema_cookie: be32(header, 40),
            schema_format: be32(header, 44),
            default_cache_size: be32(header, 48) as i32,
            autovacuum_top_root: be32(header, 52),
            text_encoding,
            user_version: be32(header, 60) as i32,
            incremental_vacuum: be32(header, 64) != 0,
            application_id: be32(header, 68),
            version_valid_for: be32(header, 92),
            sqlite_version_number: be32(header, 96),
        })
    }

    pub(super) fn usable_size(&self) -> usize {
        (self.page_size - u32::from(self.reserved_bytes)) as usize
    }
}

pub(super) fn be16(bytes: &[u8], at: usize) -> u16 {
    bytes
        .get(at..at + 2)
        .and_then(|b: &[u8]| <[u8; 2]>::try_from(b).ok())
        .map_or(0, u16::from_be_bytes)
}

pub(super) fn be32(bytes: &[u8], at: usize) -> u32 {
    bytes
        .get(at..at + 4)
        .and_then(|b: &[u8]| <[u8; 4]>::try_from(b).ok())
        .map_or(0, u32::from_be_bytes)
}

pub(super) fn varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    for (index, byte) in bytes.iter().take(MAX_VARINT_BYTES).enumerate() {
        if index == MAX_VARINT_BYTES - 1 {
            return Some(((value << 8) | u64::from(*byte), MAX_VARINT_BYTES));
        }
        value = (value << 7) | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
    }
    None
}

pub(super) const fn local_payload(total: usize, usable: usize, table_leaf: bool) -> usize {
    let max_local: usize = if table_leaf {
        usable - 35
    } else {
        ((usable - 12) * 64 / 255) - 23
    };
    if total <= max_local {
        return total;
    }
    let min_local: usize = ((usable - 12) * 32 / 255) - 23;
    let spill: usize = min_local + ((total - min_local) % (usable - 4));
    if spill <= max_local { spill } else { min_local }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_decode_one_to_nine_bytes() {
        assert_eq!(varint(&[0x05]), Some((5, 1)));
        assert_eq!(varint(&[0x81, 0x00]), Some((128, 2)));
        assert_eq!(varint(&[0xff; 9]), Some((u64::MAX, 9)));
        assert_eq!(varint(&[0x81]), None);
        assert_eq!(varint(&[]), None);
    }

    #[test]
    fn local_payload_follows_the_spill_rule_for_a_4096_byte_page() {
        assert_eq!(local_payload(100, 4096, true), 100);
        assert_eq!(local_payload(4061, 4096, true), 4061);
        let spilled: usize = local_payload(10_000, 4096, true);
        assert!(spilled < 4061 && spilled >= 489, "{spilled}");
        assert_eq!(local_payload(1002, 4096, false), 1002);
        assert!(local_payload(5000, 4096, false) <= 1002);
    }
}
