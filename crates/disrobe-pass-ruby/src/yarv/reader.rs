use serde::{Deserialize, Serialize};

use crate::detect::YARV_MAGIC;
use crate::error::{Result, RubyError};
use crate::yarv::opcodes::YarvVersion;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct YarvBinaryHeader {
    pub magic: [u8; 4],
    pub major: u32,
    pub minor: u32,
    pub size: u32,
    pub extra_size: u32,
    pub iseq_list_size: u32,
    pub global_object_list_size: u32,
    pub iseq_list_offset: u32,
    pub global_object_list_offset: u32,
}

pub(crate) const HEADER_SIZE: usize = 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4;

pub(crate) fn read_header(bytes: &[u8]) -> Result<YarvBinaryHeader> {
    if bytes.len() < HEADER_SIZE {
        return Err(RubyError::Truncated {
            got: bytes.len(),
            need: HEADER_SIZE,
        });
    }
    let magic: [u8; 4] = bytes[0..4]
        .try_into()
        .map_err(|_| RubyError::YarvHeaderTruncated { field: "magic" })?;
    if &magic != YARV_MAGIC {
        return Err(RubyError::YarvBadMagic { got: magic });
    }
    let major: u32 = u32_le(&bytes[4..8], "major")?;
    let minor: u32 = u32_le(&bytes[8..12], "minor")?;
    let version: YarvVersion = YarvVersion::new(major, minor);
    if !version.is_supported() {
        return Err(RubyError::YarvUnsupportedVersion { major, minor });
    }
    let size: u32 = u32_le(&bytes[12..16], "size")?;
    let extra_size: u32 = u32_le(&bytes[16..20], "extra_size")?;
    let iseq_list_size: u32 = u32_le(&bytes[20..24], "iseq_list_size")?;
    let global_object_list_size: u32 = u32_le(&bytes[24..28], "global_object_list_size")?;
    let iseq_list_offset: u32 = u32_le(&bytes[28..32], "iseq_list_offset")?;
    let global_object_list_offset: u32 = u32_le(&bytes[32..36], "global_object_list_offset")?;
    Ok(YarvBinaryHeader {
        magic,
        major,
        minor,
        size,
        extra_size,
        iseq_list_size,
        global_object_list_size,
        iseq_list_offset,
        global_object_list_offset,
    })
}

#[inline]
fn u32_le(slice: &[u8], field: &'static str) -> Result<u32> {
    let arr: [u8; 4] = slice
        .try_into()
        .map_err(|_| RubyError::YarvHeaderTruncated { field })?;
    Ok(u32::from_le_bytes(arr))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn synth_header(major: u32, minor: u32) -> Vec<u8> {
        let header_size_u32: u32 = u32::try_from(HEADER_SIZE).expect("size fits u32");
        let mut v: Vec<u8> = Vec::with_capacity(HEADER_SIZE);
        v.extend_from_slice(YARV_MAGIC);
        v.extend_from_slice(&major.to_le_bytes());
        v.extend_from_slice(&minor.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&header_size_u32.to_le_bytes());
        v.extend_from_slice(&header_size_u32.to_le_bytes());
        v
    }

    #[test]
    fn parses_valid_header() {
        let bytes: Vec<u8> = synth_header(3, 2);
        let h: YarvBinaryHeader = read_header(&bytes).expect("header");
        assert_eq!(h.major, 3);
        assert_eq!(h.minor, 2);
        assert_eq!(h.iseq_list_size, 1);
    }

    #[test]
    fn rejects_truncated() {
        let err: RubyError = read_header(b"YARB\x00").expect_err("truncated");
        assert!(matches!(err, RubyError::Truncated { .. }));
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes: Vec<u8> = synth_header(3, 2);
        bytes[0] = b'X';
        let err: RubyError = read_header(&bytes).expect_err("bad magic");
        assert!(matches!(err, RubyError::YarvBadMagic { .. }));
    }

    #[test]
    fn rejects_unsupported_version() {
        let bytes: Vec<u8> = synth_header(4, 0);
        let err: RubyError = read_header(&bytes).expect_err("unsupported");
        assert!(matches!(
            err,
            RubyError::YarvUnsupportedVersion { major: 4, minor: 0 }
        ));
    }
}
