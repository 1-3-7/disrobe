use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeVersion {
    Node18,
    Node20,
    Node22,
    Node24,
    Unknown,
}

impl NodeVersion {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Node18 => "node-18",
            Self::Node20 => "node-20",
            Self::Node22 => "node-22",
            Self::Node24 => "node-24",
            Self::Unknown => "unknown",
        }
    }

    #[must_use]
    pub const fn from_v8_version_hash(hash: u32) -> Self {
        match hash {
            0xA5A5_18A5 => Self::Node18,
            0xA5A5_20A5 => Self::Node20,
            0xA5A5_22A5 => Self::Node22,
            0xA5A5_24A5 => Self::Node24,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteVersion {
    pub raw: u32,
    pub node: NodeVersion,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BytenodeCacheHeader {
    pub magic_number: u32,
    pub version_hash: ByteVersion,
    pub source_hash: u32,
    pub flag_hash: u32,
    pub payload_length: u32,
    pub checksum: u32,
    pub raw_prefix: Vec<u8>,
}

pub const BYTENODE_PREFIX_BYTES: usize = 24;
pub const V8_CACHED_DATA_MAGIC: u32 = 0xC0DE_0BAD;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BytenodeCacheBody {
    pub header: BytenodeCacheHeader,
    pub bytecode_offset: usize,
    pub bytecode_length: usize,
    pub bytecode: Vec<u8>,
}

pub fn parse_bytenode_full(bytes: &[u8]) -> Result<BytenodeCacheBody> {
    let header: BytenodeCacheHeader = parse_bytenode_header(bytes)?;
    let bytecode_offset: usize = BYTENODE_PREFIX_BYTES;
    let payload_len: usize = header.payload_length as usize;
    let bytecode_length: usize = payload_len.min(bytes.len().saturating_sub(bytecode_offset));
    let bytecode: Vec<u8> =
        bytes[bytecode_offset..bytecode_offset.saturating_add(bytecode_length)].to_vec();
    Ok(BytenodeCacheBody {
        header,
        bytecode_offset,
        bytecode_length,
        bytecode,
    })
}

pub fn parse_bytenode_header(bytes: &[u8]) -> Result<BytenodeCacheHeader> {
    if bytes.len() < BYTENODE_PREFIX_BYTES {
        return Err(Error::OxcParse(format!(
            "bytenode header too short: need {BYTENODE_PREFIX_BYTES}, got {}",
            bytes.len()
        )));
    }
    let prefix: &[u8] = &bytes[..BYTENODE_PREFIX_BYTES];
    let magic_number: u32 = u32::from_le_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]);
    let version_raw: u32 = u32::from_le_bytes([prefix[4], prefix[5], prefix[6], prefix[7]]);
    let source_hash: u32 = u32::from_le_bytes([prefix[8], prefix[9], prefix[10], prefix[11]]);
    let flag_hash: u32 = u32::from_le_bytes([prefix[12], prefix[13], prefix[14], prefix[15]]);
    let payload_length: u32 = u32::from_le_bytes([prefix[16], prefix[17], prefix[18], prefix[19]]);
    let checksum: u32 = u32::from_le_bytes([prefix[20], prefix[21], prefix[22], prefix[23]]);
    Ok(BytenodeCacheHeader {
        magic_number,
        version_hash: ByteVersion {
            raw: version_raw,
            node: NodeVersion::from_v8_version_hash(version_raw),
        },
        source_hash,
        flag_hash,
        payload_length,
        checksum,
        raw_prefix: prefix.to_vec(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn synth_jsc(version: u32, payload_len: u32) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(BYTENODE_PREFIX_BYTES + 32);
        out.extend_from_slice(&V8_CACHED_DATA_MAGIC.to_le_bytes());
        out.extend_from_slice(&version.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&payload_len.to_le_bytes());
        out.extend_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());
        out.extend(std::iter::repeat_n(0u8, payload_len as usize));
        out
    }

    #[test]
    fn parses_node_18_jsc_header() {
        let bytes: Vec<u8> = synth_jsc(0xA5A5_18A5, 100);
        let header: BytenodeCacheHeader = parse_bytenode_header(&bytes).expect("parse jsc");
        assert_eq!(header.magic_number, V8_CACHED_DATA_MAGIC);
        assert_eq!(header.version_hash.node, NodeVersion::Node18);
        assert_eq!(header.payload_length, 100);
        assert_eq!(header.checksum, 0xDEAD_BEEF);
    }

    #[test]
    fn parses_node_20_jsc_header() {
        let bytes: Vec<u8> = synth_jsc(0xA5A5_20A5, 50);
        let header: BytenodeCacheHeader = parse_bytenode_header(&bytes).expect("v20");
        assert_eq!(header.version_hash.node, NodeVersion::Node20);
    }

    #[test]
    fn parses_node_22_jsc_header() {
        let bytes: Vec<u8> = synth_jsc(0xA5A5_22A5, 50);
        let header: BytenodeCacheHeader = parse_bytenode_header(&bytes).expect("v22");
        assert_eq!(header.version_hash.node, NodeVersion::Node22);
    }

    #[test]
    fn parses_node_24_jsc_header() {
        let bytes: Vec<u8> = synth_jsc(0xA5A5_24A5, 50);
        let header: BytenodeCacheHeader = parse_bytenode_header(&bytes).expect("v24");
        assert_eq!(header.version_hash.node, NodeVersion::Node24);
    }

    #[test]
    fn unknown_version_is_marked_unknown() {
        let bytes: Vec<u8> = synth_jsc(0xDEAD_BEEF, 8);
        let header: BytenodeCacheHeader = parse_bytenode_header(&bytes).expect("unknown");
        assert_eq!(header.version_hash.node, NodeVersion::Unknown);
    }

    #[test]
    fn errors_on_short_header() {
        let bytes: Vec<u8> = vec![0u8; 10];
        let err: Error = parse_bytenode_header(&bytes).unwrap_err();
        assert!(matches!(err, Error::OxcParse(_)));
    }

    #[test]
    fn node_version_label_round_trip() {
        assert_eq!(NodeVersion::Node18.label(), "node-18");
        assert_eq!(NodeVersion::Node24.label(), "node-24");
        assert_eq!(NodeVersion::Unknown.label(), "unknown");
    }
}
