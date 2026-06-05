use serde::{Deserialize, Serialize};

pub const EXT4_SUPERBLOCK_OFFSET: usize = 1024;
pub const EXT4_MAGIC: u16 = 0xEF53;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ext4SuperblockSummary {
    pub inodes_count: u32,
    pub blocks_count_lo: u32,
    pub block_size_log: u32,
    pub magic: u16,
    pub state: u16,
    pub creator_os: u32,
    pub rev_level: u32,
}

#[must_use]
pub fn detect_ext4(bytes: &[u8]) -> Option<Ext4SuperblockSummary> {
    let end: usize = EXT4_SUPERBLOCK_OFFSET + 0x400;
    if bytes.len() < end {
        return None;
    }
    let magic: u16 = u16::from_le_bytes([
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x38],
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x39],
    ]);
    if magic != EXT4_MAGIC {
        return None;
    }
    let inodes_count: u32 = u32::from_le_bytes([
        bytes[EXT4_SUPERBLOCK_OFFSET],
        bytes[EXT4_SUPERBLOCK_OFFSET + 1],
        bytes[EXT4_SUPERBLOCK_OFFSET + 2],
        bytes[EXT4_SUPERBLOCK_OFFSET + 3],
    ]);
    let blocks_count_lo: u32 = u32::from_le_bytes([
        bytes[EXT4_SUPERBLOCK_OFFSET + 4],
        bytes[EXT4_SUPERBLOCK_OFFSET + 5],
        bytes[EXT4_SUPERBLOCK_OFFSET + 6],
        bytes[EXT4_SUPERBLOCK_OFFSET + 7],
    ]);
    let block_size_log: u32 = u32::from_le_bytes([
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x18],
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x19],
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x1A],
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x1B],
    ]);
    let state: u16 = u16::from_le_bytes([
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x3A],
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x3B],
    ]);
    let creator_os: u32 = u32::from_le_bytes([
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x48],
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x49],
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x4A],
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x4B],
    ]);
    let rev_level: u32 = u32::from_le_bytes([
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x4C],
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x4D],
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x4E],
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x4F],
    ]);
    Some(Ext4SuperblockSummary {
        inodes_count,
        blocks_count_lo,
        block_size_log,
        magic,
        state,
        creator_os,
        rev_level,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn synth_ext4_image() -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![0u8; EXT4_SUPERBLOCK_OFFSET + 0x400];
        bytes[EXT4_SUPERBLOCK_OFFSET..EXT4_SUPERBLOCK_OFFSET + 4]
            .copy_from_slice(&64u32.to_le_bytes());
        bytes[EXT4_SUPERBLOCK_OFFSET + 4..EXT4_SUPERBLOCK_OFFSET + 8]
            .copy_from_slice(&1024u32.to_le_bytes());
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x18..EXT4_SUPERBLOCK_OFFSET + 0x1C]
            .copy_from_slice(&2u32.to_le_bytes());
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x38..EXT4_SUPERBLOCK_OFFSET + 0x3A]
            .copy_from_slice(&EXT4_MAGIC.to_le_bytes());
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x3A..EXT4_SUPERBLOCK_OFFSET + 0x3C]
            .copy_from_slice(&1u16.to_le_bytes());
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x4C..EXT4_SUPERBLOCK_OFFSET + 0x50]
            .copy_from_slice(&1u32.to_le_bytes());
        bytes
    }

    #[test]
    fn detects_ext4_magic_at_offset_1024() {
        let bytes: Vec<u8> = synth_ext4_image();
        let sb: Ext4SuperblockSummary = detect_ext4(&bytes).expect("ext4");
        assert_eq!(sb.magic, EXT4_MAGIC);
        assert_eq!(sb.inodes_count, 64);
        assert_eq!(sb.blocks_count_lo, 1024);
        assert_eq!(sb.block_size_log, 2);
        assert_eq!(sb.rev_level, 1);
    }

    #[test]
    fn rejects_short_buffer() {
        let bytes: Vec<u8> = vec![0u8; 256];
        assert!(detect_ext4(&bytes).is_none());
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut bytes: Vec<u8> = vec![0u8; EXT4_SUPERBLOCK_OFFSET + 0x400];
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x38..EXT4_SUPERBLOCK_OFFSET + 0x3A]
            .copy_from_slice(&0xDEAD_u16.to_le_bytes());
        assert!(detect_ext4(&bytes).is_none());
    }
}
