use object::read::ObjectKind;
use object::{BinaryFormat, Object as _, ObjectSegment as _, SegmentFlags};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::{
    iso::{IsoEntryKind, parse_iso},
    squashfs::{SQUASHFS_MAGIC_LE, SquashfsSuperblock, parse_squashfs_superblock},
};

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const APPIMAGE_TYPE_OFFSET: usize = 8;
const APPIMAGE_TYPE1_MAGIC: [u8; 3] = [b'A', b'I', 0x01];
const APPIMAGE_TYPE2_MAGIC: [u8; 3] = [b'A', b'I', 0x02];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppImageFormat {
    Type1Marked,
    Type1Legacy,
    Type2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppImagePayloadLayout {
    Iso9660,
    Squashfs {
        offset: u64,
        superblock: SquashfsSuperblock,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppImageLayout {
    pub format: AppImageFormat,
    pub payload: AppImagePayloadLayout,
}

pub fn parse_appimage(bytes: &[u8]) -> Result<AppImageLayout> {
    if !valid_elf_header(bytes) {
        return Err(Error::Decompression(
            "appimage ELF header is malformed or truncated".to_owned(),
        ));
    }
    let marker: &[u8] = &bytes[APPIMAGE_TYPE_OFFSET..APPIMAGE_TYPE_OFFSET + 3];
    if marker == APPIMAGE_TYPE1_MAGIC {
        let image: super::iso::IsoImage = parse_iso(bytes)?;
        if !image.rock_ridge || !has_root_app_run(&image) {
            return Err(Error::Decompression(
                "type 1 appimage requires Rock Ridge and an executable regular root AppRun entry"
                    .to_owned(),
            ));
        }
        return Ok(AppImageLayout {
            format: AppImageFormat::Type1Marked,
            payload: AppImagePayloadLayout::Iso9660,
        });
    }
    if marker != APPIMAGE_TYPE2_MAGIC {
        if marker.starts_with(b"AI") {
            return Err(Error::Decompression(
                "appimage type marker is unsupported".to_owned(),
            ));
        }
        let image: super::iso::IsoImage = parse_iso(bytes)?;
        if !image.rock_ridge || !has_root_app_run(&image) {
            return Err(Error::Decompression(
                "legacy appimage requires Rock Ridge and an executable regular root AppRun entry"
                    .to_owned(),
            ));
        }
        return Ok(AppImageLayout {
            format: AppImageFormat::Type1Legacy,
            payload: AppImagePayloadLayout::Iso9660,
        });
    }
    let offset: usize = locate_squashfs_offset(bytes).ok_or_else(|| {
        Error::Decompression("appimage squashfs offset not found in binary tail".to_owned())
    })?;
    let superblock: SquashfsSuperblock = parse_squashfs_superblock(bytes, offset)?;
    Ok(AppImageLayout {
        format: AppImageFormat::Type2,
        payload: AppImagePayloadLayout::Squashfs {
            offset: offset as u64,
            superblock,
        },
    })
}

fn has_root_app_run(image: &super::iso::IsoImage) -> bool {
    image.files.iter().any(|entry: &super::iso::IsoEntry| {
        entry.kind == IsoEntryKind::Regular
            && entry.path == "AppRun"
            && entry.mode.is_some_and(|mode: u32| mode & 0o111 != 0)
    })
}

pub fn detect_appimage(bytes: &[u8]) -> Option<AppImageFormat> {
    parse_appimage(bytes)
        .ok()
        .map(|layout: AppImageLayout| layout.format)
}

fn valid_elf_header(bytes: &[u8]) -> bool {
    let Some(version): Option<&[u8]> = bytes.get(20..24) else {
        return false;
    };
    let header_version: u32 = match bytes.get(5) {
        Some(1) => u32::from_le_bytes([version[0], version[1], version[2], version[3]]),
        Some(2) => u32::from_be_bytes([version[0], version[1], version[2], version[3]]),
        _ => return false,
    };
    if bytes.get(..4) != Some(ELF_MAGIC.as_slice())
        || bytes.get(6) != Some(&1)
        || header_version != 1
    {
        return false;
    }
    let Ok(file): std::result::Result<object::File<'_, &[u8]>, object::Error> =
        object::File::parse(bytes)
    else {
        return false;
    };
    if file.format() != BinaryFormat::Elf
        || !matches!(file.kind(), ObjectKind::Executable | ObjectKind::Dynamic)
        || file.architecture() == object::Architecture::Unknown
    {
        return false;
    }
    let entry: u64 = file.entry();
    let input_len: u64 = bytes.len() as u64;
    entry != 0
        && file.segments().any(|segment| {
            let (file_offset, file_size): (u64, u64) = segment.file_range();
            let Some(file_end): Option<u64> = file_offset.checked_add(file_size) else {
                return false;
            };
            let address: u64 = segment.address();
            let memory_size: u64 = segment.size();
            let Some(address_end): Option<u64> = address.checked_add(memory_size) else {
                return false;
            };
            matches!(
                segment.flags(),
                SegmentFlags::Elf { p_flags } if p_flags & object::elf::PF_X != 0
            ) && file_size <= memory_size
                && file_end <= input_len
                && entry >= address
                && entry < address_end
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
        let bytes_len: u64 = bytes.len() as u64;
        bytes[0..4].copy_from_slice(&ELF_MAGIC);
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x40_0000u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&5u32.to_le_bytes());
        bytes[80..88].copy_from_slice(&0x40_0000u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&bytes_len.to_le_bytes());
        bytes[104..112].copy_from_slice(&bytes_len.to_le_bytes());
        bytes[APPIMAGE_TYPE_OFFSET..APPIMAGE_TYPE_OFFSET + 3]
            .copy_from_slice(&APPIMAGE_TYPE2_MAGIC);
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
        assert_eq!(layout.format, AppImageFormat::Type2);
        let AppImagePayloadLayout::Squashfs { offset, superblock } = layout.payload else {
            panic!("type 2 payload was not squashfs");
        };
        assert_eq!(offset, 0x10_000);
        assert_eq!(superblock.version_major, 4);
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
