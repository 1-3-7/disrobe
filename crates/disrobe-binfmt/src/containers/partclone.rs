use crate::error::{Error, Result};

const MAGIC: &[u8; 15] = b"partclone-image";
const ENDIAN_MAGIC: u16 = 0xC0DE;

const BITMAP_BIT: u8 = 0x01;
const BITMAP_BYTE: u8 = 0x08;

#[derive(Debug, Clone)]
pub struct PartcloneV2 {
    pub fs: String,
    pub device_size: u64,
    pub total_blocks: u64,
    pub used_blocks: u64,
    pub block_size: u32,
    pub checksum_size: u16,
    pub blocks_per_checksum: u32,
    pub bitmap_mode: u8,
    pub bitmap_offset: usize,
}

fn rd_u16(b: &[u8], at: usize) -> Result<u16> {
    let s: &[u8] = b
        .get(at..at + 2)
        .ok_or_else(|| Error::Partclone("partclone: truncated u16".to_owned()))?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn rd_u32(b: &[u8], at: usize) -> Result<u32> {
    let s: &[u8] = b
        .get(at..at + 4)
        .ok_or_else(|| Error::Partclone("partclone: truncated u32".to_owned()))?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn rd_u64(b: &[u8], at: usize) -> Result<u64> {
    let s: &[u8] = b
        .get(at..at + 8)
        .ok_or_else(|| Error::Partclone("partclone: truncated u64".to_owned()))?;
    Ok(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

pub fn parse_v2(bytes: &[u8]) -> Result<PartcloneV2> {
    if !bytes.starts_with(MAGIC) {
        return Err(Error::Partclone(
            "partclone: missing image magic".to_owned(),
        ));
    }
    let version: &[u8] = bytes
        .get(30..34)
        .ok_or_else(|| Error::Partclone("partclone: truncated version".to_owned()))?;
    if version != b"0002" {
        return Err(Error::Partclone(format!(
            "partclone: version {} is not the v2 on-disk format",
            String::from_utf8_lossy(version)
        )));
    }
    let fs_info_off: usize = 36;
    let fs_name: String =
        bytes
            .get(fs_info_off..fs_info_off + 16)
            .map_or_else(String::new, |fs_bytes: &[u8]| {
                let end: usize = fs_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .map_or(16, |value: usize| value);
                String::from_utf8_lossy(&fs_bytes[..end]).into_owned()
            });
    let device_size: u64 = rd_u64(bytes, fs_info_off + 16)?;
    let total_blocks: u64 = rd_u64(bytes, fs_info_off + 24)?;
    let used_blocks: u64 = rd_u64(bytes, fs_info_off + 32)?;
    let block_size: u32 = rd_u32(bytes, fs_info_off + 48)?;

    let opt_off: usize = fs_info_off + 52;
    let checksum_mode: u16 = rd_u16(bytes, opt_off + 8)?;
    let checksum_size: u16 = rd_u16(bytes, opt_off + 10)?;
    let blocks_per_checksum: u32 = rd_u32(bytes, opt_off + 12)?;
    let bitmap_mode: u8 = *bytes
        .get(opt_off + 17)
        .ok_or_else(|| Error::Partclone("partclone: truncated bitmap mode".to_owned()))?;

    if block_size == 0 {
        return Err(Error::Partclone("partclone: block size of zero".to_owned()));
    }
    let effective_checksum: u16 = if checksum_mode == 0 { 0 } else { checksum_size };
    let bitmap_offset: usize = opt_off + 22;
    Ok(PartcloneV2 {
        fs: fs_name,
        device_size,
        total_blocks,
        used_blocks,
        block_size,
        checksum_size: effective_checksum,
        blocks_per_checksum,
        bitmap_mode,
        bitmap_offset,
    })
}

fn bitmap_byte_len(image: &PartcloneV2) -> Result<usize> {
    let total: usize =
        usize::try_from(image.total_blocks).map_err(|_e: std::num::TryFromIntError| {
            Error::Partclone("partclone: block count overflow".to_owned())
        })?;
    match image.bitmap_mode {
        BITMAP_BIT => Ok(total.div_ceil(8)),
        BITMAP_BYTE => Ok(total),
        other => Err(Error::Partclone(format!(
            "partclone: unknown bitmap mode 0x{other:02x}"
        ))),
    }
}

fn block_is_used(bitmap: &[u8], mode: u8, index: usize) -> bool {
    if mode == BITMAP_BYTE {
        bitmap.get(index).is_some_and(|&b| b != 0)
    } else {
        let byte: usize = index / 8;
        let bit: u32 = (index % 8) as u32;
        bitmap.get(byte).is_some_and(|&b| (b >> bit) & 1 == 1)
    }
}

pub fn reconstruct(bytes: &[u8], max_total: u64) -> Result<Vec<u8>> {
    let image: PartcloneV2 = parse_v2(bytes)?;
    let total_blocks: usize =
        usize::try_from(image.total_blocks).map_err(|_e: std::num::TryFromIntError| {
            Error::Partclone("partclone: block count overflow".to_owned())
        })?;
    let block_size: usize = image.block_size as usize;
    let out_len: u64 = image
        .total_blocks
        .saturating_mul(u64::from(image.block_size));
    if out_len > max_total {
        return Err(Error::Partclone(format!(
            "partclone: reconstructed image {out_len} exceeds cap {max_total}"
        )));
    }
    let bitmap_len: usize = bitmap_byte_len(&image)?;
    let bitmap: &[u8] = bytes
        .get(image.bitmap_offset..image.bitmap_offset + bitmap_len)
        .ok_or_else(|| Error::Partclone("partclone: bitmap runs past end".to_owned()))?;

    let data_offset: usize = image.bitmap_offset + bitmap_len + 4;
    let mut cursor: usize = data_offset;
    let mut out: Vec<u8> = vec![0u8; total_blocks * block_size];
    let mut emitted_in_group: u32 = 0;
    for index in 0..total_blocks {
        if !block_is_used(bitmap, image.bitmap_mode, index) {
            continue;
        }
        let block: &[u8] = bytes.get(cursor..cursor + block_size).ok_or_else(|| {
            Error::Partclone(format!(
                "partclone: used block {index} data runs past end of image"
            ))
        })?;
        let dst: usize = index * block_size;
        out[dst..dst + block_size].copy_from_slice(block);
        cursor += block_size;
        emitted_in_group += 1;
        if image.checksum_size > 0
            && image.blocks_per_checksum > 0
            && emitted_in_group == image.blocks_per_checksum
        {
            cursor += image.checksum_size as usize;
            emitted_in_group = 0;
        }
    }
    Ok(out)
}

const _: u16 = ENDIAN_MAGIC;

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    struct V2Builder {
        block_size: u32,
        total_blocks: u64,
        bitmap_mode: u8,
        blocks_per_checksum: u32,
        checksum_size: u16,
    }

    impl V2Builder {
        fn build(&self, blocks: &[(bool, Vec<u8>)]) -> Vec<u8> {
            let mut out: Vec<u8> = Vec::new();
            out.extend_from_slice(MAGIC);
            out.resize(30, 0);
            out.extend_from_slice(b"0002");
            out.extend_from_slice(&[0u8; 2]);

            let mut fs: [u8; 16] = [0u8; 16];
            fs[..4].copy_from_slice(b"ext4");
            out.extend_from_slice(&fs);
            let used: u64 = blocks.iter().filter(|(u, _)| *u).count() as u64;
            out.extend_from_slice(&(self.total_blocks * u64::from(self.block_size)).to_le_bytes());
            out.extend_from_slice(&self.total_blocks.to_le_bytes());
            out.extend_from_slice(&used.to_le_bytes());
            out.extend_from_slice(&0u64.to_le_bytes());
            out.extend_from_slice(&self.block_size.to_le_bytes());

            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&2u16.to_le_bytes());
            out.extend_from_slice(&64u16.to_le_bytes());
            let checksum_mode: u16 = u16::from(self.checksum_size > 0);
            out.extend_from_slice(&checksum_mode.to_le_bytes());
            out.extend_from_slice(&self.checksum_size.to_le_bytes());
            out.extend_from_slice(&self.blocks_per_checksum.to_le_bytes());
            out.push(0);
            out.push(self.bitmap_mode);
            out.extend_from_slice(&0u32.to_le_bytes());

            let total: usize = self.total_blocks as usize;
            if self.bitmap_mode == BITMAP_BYTE {
                for (used_flag, _) in blocks {
                    out.push(u8::from(*used_flag));
                }
            } else {
                let mut bitmap: Vec<u8> = vec![0u8; total.div_ceil(8)];
                for (i, (used_flag, _)) in blocks.iter().enumerate() {
                    if *used_flag {
                        bitmap[i / 8] |= 1 << (i % 8);
                    }
                }
                out.extend_from_slice(&bitmap);
            }
            out.extend_from_slice(&0u32.to_le_bytes());

            let mut emitted: u32 = 0;
            for (used_flag, data) in blocks {
                if !used_flag {
                    continue;
                }
                out.extend_from_slice(data);
                emitted += 1;
                if self.checksum_size > 0
                    && self.blocks_per_checksum > 0
                    && emitted == self.blocks_per_checksum
                {
                    out.extend(std::iter::repeat_n(0xAAu8, self.checksum_size as usize));
                    emitted = 0;
                }
            }
            out
        }
    }

    #[test]
    fn reconstructs_bit_bitmap_image_byte_exact() {
        let builder: V2Builder = V2Builder {
            block_size: 8,
            total_blocks: 5,
            bitmap_mode: BITMAP_BIT,
            blocks_per_checksum: 0,
            checksum_size: 0,
        };
        let blocks: Vec<(bool, Vec<u8>)> = vec![
            (true, b"AAAAAAAA".to_vec()),
            (false, vec![]),
            (true, b"CCCCCCCC".to_vec()),
            (false, vec![]),
            (true, b"EEEEEEEE".to_vec()),
        ];
        let image: Vec<u8> = builder.build(&blocks);
        let raw: Vec<u8> = reconstruct(&image, 1 << 20).expect("reconstruct");
        let mut expected: Vec<u8> = Vec::new();
        expected.extend_from_slice(b"AAAAAAAA");
        expected.extend_from_slice(&[0u8; 8]);
        expected.extend_from_slice(b"CCCCCCCC");
        expected.extend_from_slice(&[0u8; 8]);
        expected.extend_from_slice(b"EEEEEEEE");
        assert_eq!(raw, expected);
    }

    #[test]
    fn reconstructs_with_per_block_checksums() {
        let builder: V2Builder = V2Builder {
            block_size: 4,
            total_blocks: 4,
            bitmap_mode: BITMAP_BIT,
            blocks_per_checksum: 1,
            checksum_size: 4,
        };
        let blocks: Vec<(bool, Vec<u8>)> = vec![
            (true, b"wxyz".to_vec()),
            (true, b"1234".to_vec()),
            (false, vec![]),
            (true, b"abcd".to_vec()),
        ];
        let image: Vec<u8> = builder.build(&blocks);
        let raw: Vec<u8> = reconstruct(&image, 1 << 20).expect("reconstruct");
        let mut expected: Vec<u8> = Vec::new();
        expected.extend_from_slice(b"wxyz");
        expected.extend_from_slice(b"1234");
        expected.extend_from_slice(&[0u8; 4]);
        expected.extend_from_slice(b"abcd");
        assert_eq!(raw, expected);
    }

    #[test]
    fn reconstructs_byte_bitmap_mode() {
        let builder: V2Builder = V2Builder {
            block_size: 3,
            total_blocks: 3,
            bitmap_mode: BITMAP_BYTE,
            blocks_per_checksum: 0,
            checksum_size: 0,
        };
        let blocks: Vec<(bool, Vec<u8>)> =
            vec![(false, vec![]), (true, b"mid".to_vec()), (false, vec![])];
        let image: Vec<u8> = builder.build(&blocks);
        let raw: Vec<u8> = reconstruct(&image, 1 << 20).expect("reconstruct");
        assert_eq!(&raw[0..3], &[0u8; 3]);
        assert_eq!(&raw[3..6], b"mid");
        assert_eq!(&raw[6..9], &[0u8; 3]);
    }

    #[test]
    fn rejects_non_partclone() {
        assert!(parse_v2(b"not a partclone image at all..........").is_err());
    }

    #[test]
    fn extract_to_writes_reconstructed_image() {
        let builder: V2Builder = V2Builder {
            block_size: 8,
            total_blocks: 4,
            bitmap_mode: BITMAP_BIT,
            blocks_per_checksum: 0,
            checksum_size: 0,
        };
        let blocks: Vec<(bool, Vec<u8>)> = vec![
            (true, b"PARTCLON".to_vec()),
            (false, vec![]),
            (true, b"E-IMAGE!".to_vec()),
            (false, vec![]),
        ];
        let image: Vec<u8> = builder.build(&blocks);
        let dir: std::path::PathBuf =
            std::env::temp_dir().join(format!("disrobe-partclone-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let result: crate::extract::ExtractionResult =
            crate::extract::extract_to(crate::container::ContainerKind::Partclone, &image, &dir)
                .expect("partclone extract");
        assert_eq!(result.kind, crate::container::ContainerKind::Partclone);
        let written: Vec<u8> = std::fs::read(dir.join("partclone.img")).expect("img");
        assert_eq!(&written[0..8], b"PARTCLON");
        assert_eq!(&written[8..16], &[0u8; 8]);
        assert_eq!(&written[16..24], b"E-IMAGE!");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_v2_fields_match_builder() {
        let builder: V2Builder = V2Builder {
            block_size: 8,
            total_blocks: 5,
            bitmap_mode: BITMAP_BIT,
            blocks_per_checksum: 0,
            checksum_size: 0,
        };
        let blocks: Vec<(bool, Vec<u8>)> = vec![
            (true, b"AAAAAAAA".to_vec()),
            (false, vec![]),
            (true, b"CCCCCCCC".to_vec()),
            (false, vec![]),
            (true, b"EEEEEEEE".to_vec()),
        ];
        let image: Vec<u8> = builder.build(&blocks);
        let parsed: PartcloneV2 = parse_v2(&image).expect("parse");
        assert_eq!(parsed.total_blocks, 5, "total_blocks");
        assert_eq!(parsed.block_size, 8, "block_size");
        assert_eq!(parsed.bitmap_mode, BITMAP_BIT, "bitmap_mode");
        assert_eq!(parsed.used_blocks, 3, "used_blocks");
        assert_eq!(image[parsed.bitmap_offset], 0b0001_0101, "bitmap byte");
    }
}
