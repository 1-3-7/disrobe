use serde::{Deserialize, Serialize};

use crate::containers::forge_block::{BlockDecoder, ForgeBlock, parse_block};
use crate::error::{Error, Result};
use disrobe_bytes::ByteReader;

pub const DEPGRAPH_TAG: u8 = 0x02;
pub const DEPGRAPH_RECORD_LEN: usize = 24;
pub const MAX_DEPGRAPH_RECORDS: usize = 1 << 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepGraphLink {
    pub parent_uid: u64,
    pub child_uid: u64,
    pub child_type: i32,
    pub unknown: u16,
    pub flags: u8,
    pub unknown_tail: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepGraph {
    pub block: ForgeBlock,
    pub links: Vec<DepGraphLink>,
}

const fn malformed(detail: String) -> Error {
    Error::ForgeMalformed(detail)
}

#[must_use]
pub fn looks_like_depgraph_payload(payload: &[u8]) -> bool {
    payload.first() == Some(&DEPGRAPH_TAG)
        && (payload.len() - 1).is_multiple_of(DEPGRAPH_RECORD_LEN)
}

pub fn parse_depgraph_payload(payload: &[u8]) -> Result<Vec<DepGraphLink>> {
    let mut reader: ByteReader<'_> = ByteReader::new(payload);
    let tag: u8 = reader
        .read_u8()
        .map_err(|_| malformed("depgraph payload is empty".to_owned()))?;
    if tag != DEPGRAPH_TAG {
        return Err(malformed(format!(
            "depgraph payload tag is {tag:#04x}, expected {DEPGRAPH_TAG:#04x}"
        )));
    }
    if !reader.remaining().is_multiple_of(DEPGRAPH_RECORD_LEN) {
        return Err(malformed(format!(
            "depgraph payload of {} bytes is not one tag plus whole {DEPGRAPH_RECORD_LEN}-byte links",
            payload.len()
        )));
    }
    let count: usize = reader.remaining() / DEPGRAPH_RECORD_LEN;
    if count > MAX_DEPGRAPH_RECORDS {
        return Err(malformed(format!(
            "depgraph carries {count} links, above the {MAX_DEPGRAPH_RECORDS}-link cap"
        )));
    }
    let mut links: Vec<DepGraphLink> = Vec::with_capacity(count);
    for _ in 0..count {
        let err = || malformed("depgraph link truncated".to_owned());
        links.push(DepGraphLink {
            parent_uid: reader.read_u64_le().map_err(|_| err())?,
            child_uid: reader.read_u64_le().map_err(|_| err())?,
            child_type: reader.read_i32_le().map_err(|_| err())?,
            unknown: reader.read_u16_le().map_err(|_| err())?,
            flags: reader.read_u8().map_err(|_| err())?,
            unknown_tail: reader.read_u8().map_err(|_| err())?,
        });
    }
    Ok(links)
}

pub fn parse_depgraph(bytes: &[u8], max_unpacked: u64) -> Result<DepGraph> {
    let block: ForgeBlock = parse_block(bytes)?;
    if block.total_len != bytes.len() {
        return Err(malformed(format!(
            "depgraph file carries {} bytes after its single block",
            bytes.len() - block.total_len
        )));
    }
    let payload: Vec<u8> = BlockDecoder::new().decode(bytes, &block, "depgraph", max_unpacked)?;
    let links: Vec<DepGraphLink> = parse_depgraph_payload(&payload)?;
    Ok(DepGraph { block, links })
}
