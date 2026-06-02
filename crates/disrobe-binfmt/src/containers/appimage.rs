use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::squashfs::{SQUASHFS_MAGIC_LE, SquashfsSuperblock, parse_squashfs_superblock};

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const APPIMAGE_TYPE_OFFSET: usize = 8;
const APPIMAGE_MAGIC: [u8; 3] = [b'A', b'I', 0x02];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppImageLayout {
    pub elf_present: bool,
    pub appimage_magic_present: bool,
    pub squashfs_offset: u64,
    pub superblock: SquashfsSuperblock,
}

pub fn parse_appimage(bytes: &[u8]) -> Result<AppImageLayout> {
    if bytes.len() < 64 {
        return Err(Error::Decompression(
            "appimage too small for ELF + AI magic".to_owned(),
        ));
    }
    let elf_present: bool = bytes[0..4] == ELF_MAGIC;
    let appimage_magic_present: bool =
        bytes[APPIMAGE_TYPE_OFFSET..APPIMAGE_TYPE_OFFSET + 3] == APPIMAGE_MAGIC;
    if !elf_present {
        return Err(Error::Decompression(
            "appimage missing ELF header (only AppImage type 2 supported)".to_owned(),
        ));
    }
    let offset: usize = locate_squashfs_offset(bytes).ok_or_else(|| {
        Error::Decompression("appimage squashfs offset not found in binary tail".to_owned())
    })?;
    let superblock: SquashfsSuperblock = parse_squashfs_superblock(bytes, offset)?;
    Ok(AppImageLayout {
        elf_present,
        appimage_magic_present,
        squashfs_offset: offset as u64,
        superblock,
    })
}

fn locate_squashfs_offset(bytes: &[u8]) -> Option<usize> {
    let needle: [u8; 4] = SQUASHFS_MAGIC_LE.to_le_bytes();
    let scan_start: usize = 0x10_000.min(bytes.len());
    bytes
        .windows(4)
        .enumerate()
        .skip(scan_start.saturating_sub(4))
        .find_map(|(i, w): (usize, &[u8])| if w == needle { Some(i) } else { None })
        .or_else(|| {
            bytes
                .windows(4)
                .enumerate()
                .find_map(|(i, w): (usize, &[u8])| if w == needle { Some(i) } else { None })
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::containers::squashfs::SUPERBLOCK_MIN_BYTES;

    fn synth_appimage_with_offset(offset: usize) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![0u8; offset + SUPERBLOCK_MIN_BYTES + 16];
        bytes[0..4].copy_from_slice(&ELF_MAGIC);
        bytes[APPIMAGE_TYPE_OFFSET..APPIMAGE_TYPE_OFFSET + 3].copy_from_slice(&APPIMAGE_MAGIC);
        bytes[offset..offset + 4].copy_from_slice(&SQUASHFS_MAGIC_LE.to_le_bytes());
        bytes[offset + 28..offset + 30].copy_from_slice(&4u16.to_le_bytes());
        bytes[offset + 20..offset + 22].copy_from_slice(&6u16.to_le_bytes());
        bytes[offset + 12..offset + 16].copy_from_slice(&131_072u32.to_le_bytes());
        bytes
    }

    #[test]
    fn parses_synthetic_appimage_at_64k() {
        let bytes: Vec<u8> = synth_appimage_with_offset(0x10_000);
        let layout: AppImageLayout = parse_appimage(&bytes).expect("parse");
        assert!(layout.elf_present);
        assert!(layout.appimage_magic_present);
        assert_eq!(layout.squashfs_offset, 0x10_000);
        assert_eq!(layout.superblock.version_major, 4);
    }

    #[test]
    fn rejects_non_elf() {
        let bytes: Vec<u8> = vec![0u8; 256];
        let err: Error = parse_appimage(&bytes).unwrap_err();
        assert!(matches!(err, Error::Decompression(_)));
    }

    #[test]
    fn rejects_short_input() {
        let err: Error = parse_appimage(&[0u8; 8]).unwrap_err();
        assert!(matches!(err, Error::Decompression(_)));
    }
}
