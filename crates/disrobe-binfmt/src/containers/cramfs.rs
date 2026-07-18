use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const CRAMFS_MAGIC: u32 = 0x28cd_3d45;
pub const CRAMFS_HEADER_SIZE: usize = 16;

const CRAMFS_SUPER_LEN: usize = 76;
const CRAMFS_INODE_LEN: usize = 12;
const CRAMFS_BLOCK_SIZE: usize = 4096;
const CRAMFS_MODE_DIR: u16 = 0o040_000;
const CRAMFS_MODE_FILE: u16 = 0o100_000;
const CRAMFS_MODE_SYMLINK: u16 = 0o120_000;
const CRAMFS_TYPE_MASK: u16 = 0o170_000;
const MAX_CRAMFS_FILES: usize = 500_000;
const MAX_CRAMFS_DEPTH: usize = 256;

#[derive(Debug, Clone, Copy)]
struct CramfsInode {
    mode: u16,
    size: u32,
    namelen_bytes: usize,
    data_offset: usize,
}

#[derive(Debug, Clone)]
pub struct CramfsFile {
    pub path: String,
    pub data: Vec<u8>,
    pub is_executable: bool,
    pub is_symlink: bool,
}

#[derive(Debug, Clone)]
pub struct CramfsWalk {
    pub header: CramfsHeader,
    pub files: Vec<CramfsFile>,
}

pub fn walk_cramfs(bytes: &[u8], max_total: u64) -> Result<CramfsWalk> {
    let header: CramfsHeader = detect_cramfs(bytes)
        .ok_or_else(|| Error::Cramfs("cramfs magic 0x28cd3d45 not found at offset 0".to_owned()))?;
    if bytes.len() < CRAMFS_SUPER_LEN {
        return Err(Error::Cramfs("cramfs superblock truncated".to_owned()));
    }
    let root: CramfsInode = read_inode(bytes, 64)?;
    let mut files: Vec<CramfsFile> = Vec::new();
    let mut total: u64 = 0;
    let mut stack: Vec<(CramfsInode, String, usize)> = vec![(root, String::new(), 0)];
    let mut visited: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    while let Some((inode, prefix, depth)) = stack.pop() {
        if depth > MAX_CRAMFS_DEPTH || files.len() > MAX_CRAMFS_FILES {
            break;
        }
        let kind: u16 = inode.mode & CRAMFS_TYPE_MASK;
        if kind == CRAMFS_MODE_DIR {
            if !visited.insert(inode.data_offset) {
                continue;
            }
            read_directory(bytes, &inode, &prefix, depth, &mut stack)?;
        } else if kind == CRAMFS_MODE_FILE {
            let data: Vec<u8> = read_file_data(bytes, &inode, max_total)?;
            total = total.saturating_add(data.len() as u64);
            if total > max_total {
                return Err(Error::Cramfs(format!(
                    "cramfs walk exceeds total cap {max_total}"
                )));
            }
            files.push(CramfsFile {
                path: prefix,
                is_executable: inode.mode & 0o111 != 0,
                data,
                is_symlink: false,
            });
        } else if kind == CRAMFS_MODE_SYMLINK {
            let data: Vec<u8> = read_file_data(bytes, &inode, max_total)?;
            files.push(CramfsFile {
                path: prefix,
                data,
                is_executable: false,
                is_symlink: true,
            });
        }
    }
    Ok(CramfsWalk { header, files })
}

fn read_inode(bytes: &[u8], at: usize) -> Result<CramfsInode> {
    let raw: &[u8] = bytes
        .get(at..at + CRAMFS_INODE_LEN)
        .ok_or_else(|| Error::Cramfs("cramfs inode out of bounds".to_owned()))?;
    let word0: u32 = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let word1: u32 = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let word2: u32 = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
    let mode: u16 = (word0 & 0xFFFF) as u16;
    let size: u32 = word1 & 0x00FF_FFFF;
    let namelen: u32 = word2 & 0x3F;
    let offset: u32 = word2 >> 6;
    Ok(CramfsInode {
        mode,
        size,
        namelen_bytes: (namelen as usize) * 4,
        data_offset: (offset as usize) * 4,
    })
}

fn read_directory(
    bytes: &[u8],
    dir: &CramfsInode,
    prefix: &str,
    depth: usize,
    stack: &mut Vec<(CramfsInode, String, usize)>,
) -> Result<()> {
    let start: usize = dir.data_offset;
    let end: usize = start
        .checked_add(dir.size as usize)
        .ok_or_else(|| Error::Cramfs("cramfs directory span overflow".to_owned()))?;
    let mut pos: usize = start;
    let mut children: Vec<(CramfsInode, String, usize)> = Vec::new();
    while pos + CRAMFS_INODE_LEN <= end.min(bytes.len()) {
        let child: CramfsInode = read_inode(bytes, pos)?;
        let name_start: usize = pos + CRAMFS_INODE_LEN;
        let name_end: usize = name_start + child.namelen_bytes;
        let name_bytes: &[u8] = bytes
            .get(name_start..name_end.min(bytes.len()))
            .map_or(&[] as &[u8], |value: &[u8]| value);
        let trimmed: &[u8] = name_bytes
            .iter()
            .position(|&b: &u8| b == 0)
            .map_or(name_bytes, |z: usize| &name_bytes[..z]);
        let name: String = String::from_utf8_lossy(trimmed).into_owned();
        pos = name_end;
        if name.is_empty() || name == "." || name == ".." {
            continue;
        }
        let child_path: String = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        children.push((child, child_path, depth + 1));
    }
    for child in children.into_iter().rev() {
        stack.push(child);
    }
    Ok(())
}

fn read_file_data(bytes: &[u8], inode: &CramfsInode, max_total: u64) -> Result<Vec<u8>> {
    use std::io::Read as _;
    if inode.size == 0 {
        return Ok(Vec::new());
    }
    if u64::from(inode.size) > max_total {
        return Err(Error::Cramfs("cramfs file exceeds total cap".to_owned()));
    }
    let nblocks: usize = (inode.size as usize).div_ceil(CRAMFS_BLOCK_SIZE);
    let ptr_table_start: usize = inode.data_offset;
    let ptr_table_end: usize = ptr_table_start
        .checked_add(nblocks * 4)
        .ok_or_else(|| Error::Cramfs("cramfs block pointer table overflow".to_owned()))?;
    let ptr_table: &[u8] = bytes
        .get(ptr_table_start..ptr_table_end)
        .ok_or_else(|| Error::Cramfs("cramfs block pointer table out of bounds".to_owned()))?;
    let mut out: Vec<u8> = Vec::with_capacity(inode.size as usize);
    let mut block_start: usize = ptr_table_end;
    for i in 0..nblocks {
        let block_end: usize = u32::from_le_bytes([
            ptr_table[i * 4],
            ptr_table[i * 4 + 1],
            ptr_table[i * 4 + 2],
            ptr_table[i * 4 + 3],
        ]) as usize;
        if block_end < block_start || block_end > bytes.len() {
            return Err(Error::Cramfs(format!(
                "cramfs block {i} end {block_end} out of order or past input"
            )));
        }
        let compressed: &[u8] = &bytes[block_start..block_end];
        let mut decoder: flate2::read::ZlibDecoder<&[u8]> =
            flate2::read::ZlibDecoder::new(compressed);
        let mut block: Vec<u8> = Vec::with_capacity(CRAMFS_BLOCK_SIZE);
        decoder
            .by_ref()
            .take(CRAMFS_BLOCK_SIZE as u64 + 1)
            .read_to_end(&mut block)
            .map_err(|e: std::io::Error| Error::Cramfs(format!("cramfs block {i} inflate: {e}")))?;
        if block.len() > CRAMFS_BLOCK_SIZE {
            return Err(Error::Cramfs(format!(
                "cramfs block {i} exceeds {CRAMFS_BLOCK_SIZE}-byte cap"
            )));
        }
        out.extend_from_slice(&block);
        block_start = block_end;
    }
    out.truncate(inode.size as usize);
    Ok(out)
}

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

    fn zlib_compress(input: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut enc: flate2::write::ZlibEncoder<Vec<u8>> =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(input).expect("zlib write");
        enc.finish().expect("zlib finish")
    }

    fn encode_inode(mode: u16, size: u32, namelen_div4: u32, offset_div4: u32) -> [u8; 12] {
        let mut buf: [u8; 12] = [0u8; 12];
        buf[0..4].copy_from_slice(&u32::from(mode).to_le_bytes());
        buf[4..8].copy_from_slice(&(size & 0x00FF_FFFF).to_le_bytes());
        let word2: u32 = (namelen_div4 & 0x3F) | (offset_div4 << 6);
        buf[8..12].copy_from_slice(&word2.to_le_bytes());
        buf
    }

    fn build_real_cramfs(file_name: &str, file_body: &[u8]) -> Vec<u8> {
        assert!(
            file_name.len().is_multiple_of(4),
            "test name must be 4-byte aligned"
        );
        let mut image: Vec<u8> = vec![0u8; CRAMFS_SUPER_LEN];
        image[0..4].copy_from_slice(&CRAMFS_MAGIC.to_le_bytes());
        image[16..32].copy_from_slice(b"Compressed ROMFS");

        let root_dir_offset: usize = CRAMFS_SUPER_LEN;
        let root_inode: [u8; 12] = encode_inode(
            CRAMFS_MODE_DIR | 0o755,
            (CRAMFS_INODE_LEN + file_name.len()) as u32,
            0,
            (root_dir_offset / 4) as u32,
        );
        image[64..76].copy_from_slice(&root_inode);

        let compressed: Vec<u8> = zlib_compress(file_body);
        let ptr_table_offset: usize = root_dir_offset + CRAMFS_INODE_LEN + file_name.len();
        let block_data_offset: usize = ptr_table_offset + 4;
        let block_end: usize = block_data_offset + compressed.len();

        let file_inode: [u8; 12] = encode_inode(
            CRAMFS_MODE_FILE | 0o755,
            file_body.len() as u32,
            (file_name.len() / 4) as u32,
            (ptr_table_offset / 4) as u32,
        );

        image.extend_from_slice(&file_inode);
        image.extend_from_slice(file_name.as_bytes());
        assert_eq!(image.len(), ptr_table_offset);
        image.extend_from_slice(&(block_end as u32).to_le_bytes());
        image.extend_from_slice(&compressed);
        assert_eq!(image.len(), block_end);
        image
    }

    #[test]
    fn walks_real_format_cramfs_and_recovers_file() {
        let body: &[u8] = &b"cramfs zlib block payload exact recovery test ".repeat(8);
        let image: Vec<u8> = build_real_cramfs("data.bin", body);
        let walk: CramfsWalk = walk_cramfs(&image, 64 * 1024 * 1024).expect("walk cramfs");
        assert_eq!(walk.files.len(), 1);
        assert_eq!(walk.files[0].path, "data.bin");
        assert_eq!(walk.files[0].data, body);
        assert!(walk.files[0].is_executable);
    }

    #[test]
    fn rejects_block_inflated_past_cramfs_block_size() {
        let body: Vec<u8> = vec![b'x'; CRAMFS_BLOCK_SIZE + 1];
        let compressed: Vec<u8> = zlib_compress(&body);
        let block_end: usize = 4 + compressed.len();
        let mut image: Vec<u8> = Vec::with_capacity(block_end);
        image.extend_from_slice(&(block_end as u32).to_le_bytes());
        image.extend_from_slice(&compressed);
        let inode: CramfsInode = CramfsInode {
            mode: CRAMFS_MODE_FILE,
            size: 1,
            namelen_bytes: 0,
            data_offset: 0,
        };
        let err: Error = read_file_data(&image, &inode, 64 * 1024 * 1024).expect_err("block cap");
        assert!(matches!(err, Error::Cramfs(_)));
    }

    #[test]
    fn extract_to_writes_cramfs_file() {
        let body: &[u8] = b"cramfs end to end extraction 0123456789abcdef";
        let image: Vec<u8> = build_real_cramfs("note.txt", body);
        let dir: std::path::PathBuf =
            std::env::temp_dir().join(format!("disrobe-cramfs-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let result: crate::extract::ExtractionResult =
            crate::extract::extract_to(crate::container::ContainerKind::Cramfs, &image, &dir)
                .expect("cramfs extract");
        assert_eq!(result.kind, crate::container::ContainerKind::Cramfs);
        assert_eq!(std::fs::read(dir.join("note.txt")).expect("note"), body);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn self_referential_directory_terminates() {
        let region_start: usize = CRAMFS_SUPER_LEN;
        let entry_count: usize = 4;
        let entry_len: usize = CRAMFS_INODE_LEN + 4;
        let region_size: usize = entry_count * entry_len;
        let mut image: Vec<u8> = vec![0u8; region_start + region_size];
        image[0..4].copy_from_slice(&CRAMFS_MAGIC.to_le_bytes());
        image[16..32].copy_from_slice(b"Compressed ROMFS");
        let root: [u8; 12] = encode_inode(
            CRAMFS_MODE_DIR | 0o755,
            region_size as u32,
            0,
            (region_start / 4) as u32,
        );
        image[64..76].copy_from_slice(&root);
        for k in 0..entry_count {
            let at: usize = region_start + k * entry_len;
            let child: [u8; 12] = encode_inode(
                CRAMFS_MODE_DIR | 0o755,
                region_size as u32,
                1,
                (region_start / 4) as u32,
            );
            image[at..at + CRAMFS_INODE_LEN].copy_from_slice(&child);
            let name: String = format!("dir{k}");
            image[at + CRAMFS_INODE_LEN..at + CRAMFS_INODE_LEN + 4]
                .copy_from_slice(name.as_bytes());
        }
        let walk: CramfsWalk =
            walk_cramfs(&image, 64 * 1024 * 1024).expect("self-referential cramfs terminates");
        assert!(walk.files.is_empty());
    }

    #[test]
    fn nested_directory_recovers_file() {
        let body: &[u8] = b"cramfs nested file payload 0123456789abcdef";
        let compressed: Vec<u8> = zlib_compress(body);

        let root_region: usize = CRAMFS_SUPER_LEN;
        let subdir_inode_off: usize = root_region;
        let subdir_name_off: usize = subdir_inode_off + CRAMFS_INODE_LEN;
        let subdir_region: usize = subdir_name_off + 4;
        let file_inode_off: usize = subdir_region;
        let file_name_off: usize = file_inode_off + CRAMFS_INODE_LEN;
        let ptr_table_off: usize = file_name_off + 4;
        let block_data_off: usize = ptr_table_off + 4;
        let block_end: usize = block_data_off + compressed.len();

        let mut image: Vec<u8> = vec![0u8; block_end];
        image[0..4].copy_from_slice(&CRAMFS_MAGIC.to_le_bytes());
        image[16..32].copy_from_slice(b"Compressed ROMFS");

        let root: [u8; 12] = encode_inode(
            CRAMFS_MODE_DIR | 0o755,
            (CRAMFS_INODE_LEN + 4) as u32,
            0,
            (root_region / 4) as u32,
        );
        image[64..76].copy_from_slice(&root);

        let subdir: [u8; 12] = encode_inode(
            CRAMFS_MODE_DIR | 0o755,
            (CRAMFS_INODE_LEN + 4) as u32,
            1,
            (subdir_region / 4) as u32,
        );
        image[subdir_inode_off..subdir_inode_off + CRAMFS_INODE_LEN].copy_from_slice(&subdir);
        image[subdir_name_off..subdir_name_off + 4].copy_from_slice(b"subd");

        let file: [u8; 12] = encode_inode(
            CRAMFS_MODE_FILE | 0o755,
            body.len() as u32,
            1,
            (ptr_table_off / 4) as u32,
        );
        image[file_inode_off..file_inode_off + CRAMFS_INODE_LEN].copy_from_slice(&file);
        image[file_name_off..file_name_off + 4].copy_from_slice(b"file");

        image[ptr_table_off..ptr_table_off + 4].copy_from_slice(&(block_end as u32).to_le_bytes());
        image[block_data_off..block_end].copy_from_slice(&compressed);

        let walk: CramfsWalk = walk_cramfs(&image, 64 * 1024 * 1024).expect("nested cramfs walk");
        assert_eq!(walk.files.len(), 1);
        assert_eq!(walk.files[0].path, "subd/file");
        assert_eq!(walk.files[0].data, body);
    }
}
