use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const SQUASHFS_MAGIC_LE: u32 = 0x7371_7368;
pub const SQUASHFS_MAGIC_BE: u32 = 0x6873_7173;
pub const SUPERBLOCK_MIN_BYTES: usize = 96;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SquashfsCompression {
    Gzip,
    Lzma,
    Lzo,
    Xz,
    Lz4,
    Zstd,
    Unknown(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SquashfsSuperblock {
    pub inode_count: u32,
    pub block_size: u32,
    pub fragment_count: u32,
    pub compression: SquashfsCompression,
    pub version_major: u16,
    pub version_minor: u16,
    pub bytes_used: u64,
    pub little_endian: bool,
}

pub fn parse_squashfs_superblock(bytes: &[u8], offset: usize) -> Result<SquashfsSuperblock> {
    let end: usize = offset
        .checked_add(SUPERBLOCK_MIN_BYTES)
        .ok_or_else(|| Error::Decompression("squashfs offset overflow".to_owned()))?;
    if bytes.len() < end {
        return Err(Error::Decompression(
            "squashfs superblock truncated".to_owned(),
        ));
    }
    let header: &[u8] = &bytes[offset..end];
    let magic_little: u32 = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    let magic_big: u32 = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    let little_endian: bool = magic_little == SQUASHFS_MAGIC_LE;
    if !little_endian && magic_big != SQUASHFS_MAGIC_BE {
        return Err(Error::Decompression(format!(
            "squashfs magic mismatch: 0x{magic_little:08x}"
        )));
    }
    let read_u16 = |off: usize| -> u16 {
        if little_endian {
            u16::from_le_bytes([header[off], header[off + 1]])
        } else {
            u16::from_be_bytes([header[off], header[off + 1]])
        }
    };
    let read_u32 = |off: usize| -> u32 {
        if little_endian {
            u32::from_le_bytes([
                header[off],
                header[off + 1],
                header[off + 2],
                header[off + 3],
            ])
        } else {
            u32::from_be_bytes([
                header[off],
                header[off + 1],
                header[off + 2],
                header[off + 3],
            ])
        }
    };
    let read_u64 = |off: usize| -> u64 {
        let bytes_slice: [u8; 8] = [
            header[off],
            header[off + 1],
            header[off + 2],
            header[off + 3],
            header[off + 4],
            header[off + 5],
            header[off + 6],
            header[off + 7],
        ];
        if little_endian {
            u64::from_le_bytes(bytes_slice)
        } else {
            u64::from_be_bytes(bytes_slice)
        }
    };
    let inode_count: u32 = read_u32(4);
    let block_size: u32 = read_u32(12);
    let fragment_count: u32 = read_u32(16);
    let compression_id: u16 = read_u16(20);
    let version_major: u16 = read_u16(28);
    let version_minor: u16 = read_u16(30);
    let bytes_used: u64 = read_u64(40);
    let compression: SquashfsCompression = match compression_id {
        1 => SquashfsCompression::Gzip,
        2 => SquashfsCompression::Lzma,
        3 => SquashfsCompression::Lzo,
        4 => SquashfsCompression::Xz,
        5 => SquashfsCompression::Lz4,
        6 => SquashfsCompression::Zstd,
        other => SquashfsCompression::Unknown(other),
    };
    Ok(SquashfsSuperblock {
        inode_count,
        block_size,
        fragment_count,
        compression,
        version_major,
        version_minor,
        bytes_used,
        little_endian,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn synth_superblock_le() -> Vec<u8> {
        let mut out: Vec<u8> = vec![0u8; SUPERBLOCK_MIN_BYTES];
        out[0..4].copy_from_slice(&SQUASHFS_MAGIC_LE.to_le_bytes());
        out[4..8].copy_from_slice(&123u32.to_le_bytes());
        out[12..16].copy_from_slice(&131_072u32.to_le_bytes());
        out[16..20].copy_from_slice(&7u32.to_le_bytes());
        out[20..22].copy_from_slice(&6u16.to_le_bytes());
        out[28..30].copy_from_slice(&4u16.to_le_bytes());
        out[30..32].copy_from_slice(&0u16.to_le_bytes());
        out[40..48].copy_from_slice(&999_999u64.to_le_bytes());
        out
    }

    #[test]
    fn parse_le_superblock_zstd() {
        let bytes: Vec<u8> = synth_superblock_le();
        let sb: SquashfsSuperblock =
            parse_squashfs_superblock(&bytes, 0).expect("parse superblock");
        assert_eq!(sb.inode_count, 123);
        assert_eq!(sb.block_size, 131_072);
        assert_eq!(sb.fragment_count, 7);
        assert_eq!(sb.compression, SquashfsCompression::Zstd);
        assert_eq!(sb.version_major, 4);
        assert!(sb.little_endian);
    }

    #[test]
    fn truncated_superblock_errors() {
        let err: Error = parse_squashfs_superblock(&[0u8; 10], 0).unwrap_err();
        assert!(matches!(err, Error::Decompression(_)));
    }

    #[test]
    fn bad_magic_errors() {
        let mut bytes: Vec<u8> = vec![0u8; SUPERBLOCK_MIN_BYTES];
        bytes[0..4].copy_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());
        let err: Error = parse_squashfs_superblock(&bytes, 0).unwrap_err();
        assert!(matches!(err, Error::Decompression(_)));
    }

    #[test]
    fn parse_with_nonzero_offset() {
        let mut bytes: Vec<u8> = vec![0u8; 200];
        let sb: Vec<u8> = synth_superblock_le();
        bytes[64..64 + SUPERBLOCK_MIN_BYTES].copy_from_slice(&sb);
        let parsed: SquashfsSuperblock =
            parse_squashfs_superblock(&bytes, 64).expect("offset parse");
        assert_eq!(parsed.inode_count, 123);
    }
}
