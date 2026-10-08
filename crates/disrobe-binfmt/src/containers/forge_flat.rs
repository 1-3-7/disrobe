use serde::{Deserialize, Serialize};

use crate::containers::forge::{FILE_NAME_KEY_STEP, name_xor};
use crate::error::{Error, Result};
use disrobe_bytes::ByteReader;

pub const MAX_SUBFILES_PER_ENTRY: usize = 1 << 22;
pub const MAX_FLAT_RECORDS: usize = 1 << 22;
pub const MAX_FLAT_NAME_BYTES: usize = 1024;
pub const SUBFILE_RECORD_LEN: usize = 12;
pub const WIDE_SUBFILE_RECORD_LEN: usize = 28;
const WIDE_LENGTH_MASK: u32 = 0x3FFF_FFFF;
pub const FLAT_RECORD_FIXED_LEN: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgeSubFile {
    pub uid: u64,
    pub length: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ForgeSubFileIndex {
    Records(Vec<ForgeSubFile>),
    WideRecords(Vec<ForgeWideSubFile>),
    Opaque { declared_count: i32, bytes: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgeWideSubFile {
    pub uid: u64,
    pub length: i32,
    pub flags: u8,
    pub trailer: [u8; 16],
}

impl ForgeSubFileIndex {
    #[must_use]
    pub fn single_uid(&self) -> Option<u64> {
        match self {
            Self::Records(records) if records.len() == 1 => records.first().map(|r| r.uid),
            Self::WideRecords(records) if records.len() == 1 => records.first().map(|r| r.uid),
            _ => None,
        }
    }

    #[must_use]
    pub fn lengths(&self) -> Option<Vec<i32>> {
        match self {
            Self::Records(records) => Some(records.iter().map(|r| r.length).collect()),
            Self::WideRecords(records) => Some(records.iter().map(|r| r.length).collect()),
            Self::Opaque { .. } => None,
        }
    }
}

const fn malformed(detail: String) -> Error {
    Error::ForgeMalformed(detail)
}

pub fn parse_subfile_index(bytes: &[u8]) -> Result<ForgeSubFileIndex> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    let declared_count: i32 = reader
        .read_i32_le()
        .map_err(|_| malformed("sub-file index shorter than its count".to_owned()))?;
    let count: usize = usize::try_from(declared_count)
        .map_err(|_| malformed(format!("sub-file index declares {declared_count} records")))?;
    if count > MAX_SUBFILES_PER_ENTRY {
        return Err(malformed(format!(
            "sub-file index declares {count} records, above the {MAX_SUBFILES_PER_ENTRY}-record cap"
        )));
    }
    let truncated = || malformed("sub-file record truncated".to_owned());
    if count > 0 && reader.remaining() == count * WIDE_SUBFILE_RECORD_LEN {
        let mut records: Vec<ForgeWideSubFile> = Vec::with_capacity(count);
        for _ in 0..count {
            let uid: u64 = reader.read_u64_le().map_err(|_| truncated())?;
            let raw: u32 = reader.read_u32_le().map_err(|_| truncated())?;
            let trailer: [u8; 16] = reader
                .read_bytes(16)
                .map_err(|_| truncated())?
                .try_into()
                .map_err(|_| truncated())?;
            records.push(ForgeWideSubFile {
                uid,
                length: (raw & WIDE_LENGTH_MASK) as i32,
                flags: (raw >> 30) as u8,
                trailer,
            });
        }
        return Ok(ForgeSubFileIndex::WideRecords(records));
    }
    if reader.remaining() != count * SUBFILE_RECORD_LEN {
        return Ok(ForgeSubFileIndex::Opaque {
            declared_count,
            bytes: bytes.len(),
        });
    }
    let mut records: Vec<ForgeSubFile> = Vec::with_capacity(count);
    for _ in 0..count {
        let uid: u64 = reader
            .read_u64_le()
            .map_err(|_| malformed("sub-file record truncated".to_owned()))?;
        let length: i32 = reader
            .read_i32_le()
            .map_err(|_| malformed("sub-file record truncated".to_owned()))?;
        records.push(ForgeSubFile { uid, length });
    }
    Ok(ForgeSubFileIndex::Records(records))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgeFlatRecord {
    pub name: Option<String>,
    pub name_flags: u16,
    pub name_length: usize,
    pub file_type: u32,
    pub uid: u64,
    pub payload_offset: usize,
    pub payload_len: usize,
}

pub fn parse_flat_archive(bytes: &[u8], entry: &str) -> Result<Vec<ForgeFlatRecord>> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    let mut records: Vec<ForgeFlatRecord> = Vec::new();
    while !reader.is_empty() {
        if records.len() >= MAX_FLAT_RECORDS {
            return Err(malformed(format!(
                "entry `{entry}` carries more than {MAX_FLAT_RECORDS} flat-archive records"
            )));
        }
        let at: usize = reader.position();
        let err = || {
            malformed(format!(
                "entry `{entry}` flat-archive record at {at} truncated"
            ))
        };
        let name_field: u32 = reader.read_u32_le().map_err(|_| err())?;
        let name_length: usize = (name_field & 0xFFFF) as usize;
        let name_flags: u16 = (name_field >> 16) as u16;
        if name_length > MAX_FLAT_NAME_BYTES {
            return Err(malformed(format!(
                "entry `{entry}` record at {at} declares a {name_length}-byte name, above the {MAX_FLAT_NAME_BYTES}-byte cap"
            )));
        }
        let encoded_name: &[u8] = reader.read_bytes(name_length).map_err(|_| err())?;
        let container_size: u32 = reader.read_u32_le().map_err(|_| err())?;
        let file_type: u32 = reader.read_u32_le().map_err(|_| err())?;
        let uid: u64 = reader.read_u64_le().map_err(|_| err())?;
        let payload_len: usize = (container_size as usize).checked_sub(8).ok_or_else(|| {
            malformed(format!(
                "entry `{entry}` record at {at} declares container size {container_size}, below the 8-byte header"
            ))
        })?;
        let payload_offset: usize = reader.position();
        reader.skip(payload_len).map_err(|_| {
            malformed(format!(
                "entry `{entry}` record at {at} declares {payload_len} payload bytes but only {} remain",
                bytes.len().saturating_sub(payload_offset)
            ))
        })?;
        let name: Option<String> = (name_length > 0 && name_flags == 0).then(|| {
            let mut decoded: Vec<u8> = encoded_name.to_vec();
            name_xor(&mut decoded, uid, 0, file_type, FILE_NAME_KEY_STEP);
            String::from_utf8_lossy(&decoded).into_owned()
        });
        records.push(ForgeFlatRecord {
            name,
            name_flags,
            name_length,
            file_type,
            uid,
            payload_offset,
            payload_len,
        });
    }
    Ok(records)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn flat_archive_refusals_are_typed() {
        let mut flagged: Vec<u8> = (0x0002_0004u32).to_le_bytes().to_vec();
        flagged.extend_from_slice(b"\x01\x02\x03\x04");
        flagged.extend_from_slice(&9u32.to_le_bytes());
        flagged.extend_from_slice(&0x415D_9568u32.to_le_bytes());
        flagged.extend_from_slice(&7u64.to_le_bytes());
        flagged.push(0xAB);
        let records: Vec<ForgeFlatRecord> = parse_flat_archive(&flagged, "e").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, None);
        assert_eq!(records[0].name_flags, 2);
        assert_eq!(records[0].name_length, 4);
        assert_eq!(records[0].payload_len, 1);
        let mut short_container: Vec<u8> = 0u32.to_le_bytes().to_vec();
        short_container.extend_from_slice(&4u32.to_le_bytes());
        short_container.extend_from_slice(&[0u8; 12]);
        assert!(matches!(
            parse_flat_archive(&short_container, "e").unwrap_err(),
            Error::ForgeMalformed(_)
        ));
        let mut overlong: Vec<u8> = 0u32.to_le_bytes().to_vec();
        overlong.extend_from_slice(&40u32.to_le_bytes());
        overlong.extend_from_slice(&[0u8; 12]);
        assert!(parse_flat_archive(&overlong, "e").is_err());
        let huge_name: Vec<u8> = ((MAX_FLAT_NAME_BYTES as u32) + 1).to_le_bytes().to_vec();
        assert!(parse_flat_archive(&huge_name, "e").is_err());
        assert!(parse_flat_archive(&[1, 2, 3], "e").is_err());
    }
}
