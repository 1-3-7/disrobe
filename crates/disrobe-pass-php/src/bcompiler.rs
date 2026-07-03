use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

pub const BCG_MIN_HEADER: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BcgKind {
    Bcg,
    BcSerialized,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BcgHeader {
    pub kind: BcgKind,
    pub php_major: Option<u8>,
    pub php_minor: Option<u8>,
    pub flags: u32,
    pub class_count: Option<u32>,
    pub function_count: Option<u32>,
    pub op_array_count: Option<u32>,
    pub payload_offset: usize,
}

pub fn read_header(bytes: &[u8]) -> Result<BcgHeader> {
    if bytes.len() < BCG_MIN_HEADER {
        return Err(Error::BcgTooSmall(bytes.len()));
    }
    let mut magic: [u8; 4] = [0u8; 4];
    magic.copy_from_slice(&bytes[..4]);
    let kind: BcgKind = match &magic[..3] {
        b"BCG" => BcgKind::Bcg,
        b"BC\x01" => BcgKind::BcSerialized,
        _ => return Err(Error::BcgBadMagic(magic)),
    };
    let php_major: Option<u8> = bytes.get(4).copied();
    let php_minor: Option<u8> = bytes.get(5).copied();
    let flags_raw: [u8; 4] = [bytes[6], bytes[7], bytes[8], bytes[9]];
    let flags: u32 = u32::from_le_bytes(flags_raw);
    let cc_raw: [u8; 4] = [bytes[10], bytes[11], bytes[12], bytes[13]];
    let class_count: Option<u32> = Some(u32::from_le_bytes(cc_raw));
    let fc_raw: [u8; 2] = [bytes[14], bytes[15]];
    let function_count: Option<u32> = Some(u32::from(u16::from_le_bytes(fc_raw)));
    Ok(BcgHeader {
        kind,
        php_major,
        php_minor,
        flags,
        class_count,
        function_count,
        op_array_count: None,
        payload_offset: BCG_MIN_HEADER,
    })
}
