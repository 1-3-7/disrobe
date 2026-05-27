use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const NSIS_FIRSTHEADER_MAGIC: [u8; 16] = [
    0xEF, 0xBE, 0xAD, 0xDE, b'N', b'u', b'l', b'l', b's', b'o', b'f', b't', b'I', b'n', b's', b't',
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NsisHeader {
    pub offset: u64,
    pub flags: u32,
    pub siginfo: u32,
    pub header_size: u32,
    pub archive_size: u32,
}

pub fn detect_nsis(bytes: &[u8]) -> Option<NsisHeader> {
    bytes
        .windows(NSIS_FIRSTHEADER_MAGIC.len())
        .enumerate()
        .find_map(|(i, w): (usize, &[u8])| {
            if w == NSIS_FIRSTHEADER_MAGIC {
                read_firstheader(bytes, i)
            } else {
                None
            }
        })
}

fn read_firstheader(bytes: &[u8], offset: usize) -> Option<NsisHeader> {
    if offset < 4 || offset + 28 > bytes.len() {
        return None;
    }
    let flags: u32 = u32::from_le_bytes([
        bytes[offset - 4],
        bytes[offset - 3],
        bytes[offset - 2],
        bytes[offset - 1],
    ]);
    let siginfo: u32 = u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]);
    let header_size: u32 = u32::from_le_bytes([
        bytes[offset + 16],
        bytes[offset + 17],
        bytes[offset + 18],
        bytes[offset + 19],
    ]);
    let archive_size: u32 = u32::from_le_bytes([
        bytes[offset + 20],
        bytes[offset + 21],
        bytes[offset + 22],
        bytes[offset + 23],
    ]);
    Some(NsisHeader {
        offset: offset as u64,
        flags,
        siginfo,
        header_size,
        archive_size,
    })
}

pub fn parse_nsis(bytes: &[u8]) -> Result<NsisHeader> {
    detect_nsis(bytes).ok_or_else(|| {
        Error::Decompression(
            "nsis first-header signature `NullsoftInst` not found in input".to_owned(),
        )
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn synth_pe_with_nsis(header_size: u32, archive_size: u32) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![0u8; 1024];
        let offset: usize = 512;
        let flags: u32 = 0;
        bytes[offset - 4..offset].copy_from_slice(&flags.to_le_bytes());
        bytes[offset..offset + 16].copy_from_slice(&NSIS_FIRSTHEADER_MAGIC);
        bytes[offset + 16..offset + 20].copy_from_slice(&header_size.to_le_bytes());
        bytes[offset + 20..offset + 24].copy_from_slice(&archive_size.to_le_bytes());
        bytes
    }

    #[test]
    fn detects_signature_in_pe_tail() {
        let bytes: Vec<u8> = synth_pe_with_nsis(0x1234, 0x10_000);
        let header: NsisHeader = parse_nsis(&bytes).expect("nsis header");
        assert_eq!(header.offset, 512);
        assert_eq!(header.header_size, 0x1234);
        assert_eq!(header.archive_size, 0x10_000);
    }

    #[test]
    fn rejects_non_nsis() {
        let bytes: Vec<u8> = vec![0u8; 512];
        let err: Error = parse_nsis(&bytes).unwrap_err();
        assert!(matches!(err, Error::Decompression(_)));
    }
}
