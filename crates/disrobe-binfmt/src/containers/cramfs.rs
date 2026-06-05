use serde::{Deserialize, Serialize};

pub const CRAMFS_MAGIC: u32 = 0x28cd_3d45;
pub const CRAMFS_HEADER_SIZE: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CramfsHeader {
    pub magic: u32,
    pub size: u32,
    pub flags: u32,
    pub future: u32,
}

#[must_use]
pub fn detect_cramfs(bytes: &[u8]) -> Option<CramfsHeader> {
    if bytes.len() < CRAMFS_HEADER_SIZE {
        return None;
    }
    let magic: u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if magic != CRAMFS_MAGIC {
        return None;
    }
    let size: u32 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let flags: u32 = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let future: u32 = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    Some(CramfsHeader {
        magic,
        size,
        flags,
        future,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_cramfs_magic() {
        let mut bytes: Vec<u8> = vec![0u8; CRAMFS_HEADER_SIZE];
        bytes[0..4].copy_from_slice(&CRAMFS_MAGIC.to_le_bytes());
        bytes[4..8].copy_from_slice(&4096u32.to_le_bytes());
        let header: CramfsHeader = detect_cramfs(&bytes).expect("cramfs");
        assert_eq!(header.magic, CRAMFS_MAGIC);
        assert_eq!(header.size, 4096);
    }

    #[test]
    fn rejects_short() {
        assert!(detect_cramfs(&[0u8; 4]).is_none());
    }

    #[test]
    fn rejects_non_cramfs() {
        let bytes: Vec<u8> = vec![0u8; 32];
        assert!(detect_cramfs(&bytes).is_none());
    }
}
