use crate::containers::lz4_block;
use crate::error::{Error, Result};

pub const XALZ_MAGIC: &[u8; 4] = b"XALZ";

const HEADER_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XalzAssembly {
    pub descriptor_index: u32,
    pub uncompressed_size: u32,
    pub data: Vec<u8>,
}

#[must_use]
pub fn detect_xalz(bytes: &[u8]) -> bool {
    bytes.len() >= HEADER_LEN && bytes.starts_with(XALZ_MAGIC)
}

pub fn parse_xalz(bytes: &[u8], max_total: u64) -> Result<XalzAssembly> {
    if !detect_xalz(bytes) {
        return Err(Error::Xalz(
            "xalz: missing XALZ header or truncated".to_owned(),
        ));
    }
    let descriptor_index: u32 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let uncompressed_size: u32 = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    if u64::from(uncompressed_size) > max_total {
        return Err(Error::Xalz(format!(
            "xalz: declared size {uncompressed_size} exceeds quota {max_total}"
        )));
    }
    let payload: &[u8] = &bytes[HEADER_LEN..];
    let data: Vec<u8> = lz4_block::decompress(payload, uncompressed_size as usize)
        .map_err(|e: Error| Error::Xalz(format!("xalz: lz4 block decode failed: {e}")))?;
    Ok(XalzAssembly {
        descriptor_index,
        uncompressed_size,
        data,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn lz4_compress_block(input: &[u8]) -> Vec<u8> {
        lz4_flex::block::compress(input)
    }

    #[test]
    fn detect_matches_header() {
        let mut bytes: Vec<u8> = XALZ_MAGIC.to_vec();
        bytes.extend([0u8; 8]);
        assert!(detect_xalz(&bytes));
        assert!(!detect_xalz(b"MZ short"));
    }

    #[test]
    fn round_trips_a_managed_assembly_payload() {
        let payload: Vec<u8> = {
            let mut v: Vec<u8> = b"MZ".to_vec();
            v.extend(b"this is a fake .NET PE body for the XALZ round-trip".repeat(8));
            v
        };
        let compressed: Vec<u8> = lz4_compress_block(&payload);
        let mut blob: Vec<u8> = XALZ_MAGIC.to_vec();
        blob.extend_from_slice(&7u32.to_le_bytes());
        blob.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        blob.extend_from_slice(&compressed);
        let asm: XalzAssembly = parse_xalz(&blob, 1 << 20).expect("parse xalz");
        assert_eq!(asm.descriptor_index, 7);
        assert_eq!(asm.uncompressed_size as usize, payload.len());
        assert_eq!(asm.data, payload);
    }
}
