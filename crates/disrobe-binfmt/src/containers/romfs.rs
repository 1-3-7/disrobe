use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const ROMFS_MAGIC: &[u8; 8] = b"-rom1fs-";

const ROMFS_HEADER_MIN: usize = 16;
const ROMFS_FILE_HEADER_LEN: usize = 16;
const ROMFS_ALIGN: usize = 16;
const ROMFS_TYPE_MASK: u32 = 0x7;
const ROMFS_EXEC_FLAG: u32 = 0x8;
const ROMFS_OFFSET_MASK: u32 = !0xF;
const MAX_ROMFS_FILES: usize = 500_000;
const MAX_ROMFS_DEPTH: usize = 256;

const TYPE_DIRECTORY: u32 = 1;
const TYPE_REGULAR_FILE: u32 = 2;
const TYPE_SYMBOLIC_LINK: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RomfsHeader {
    pub full_size: u32,
    pub checksum: u32,
    pub volume_name: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct RomfsFile {
    pub path: String,
    pub data: Vec<u8>,
    pub is_executable: bool,
    pub is_symlink: bool,
}

#[derive(Debug, Clone)]
pub struct RomfsWalk {
    pub header: RomfsHeader,
    pub files: Vec<RomfsFile>,
}

#[derive(Debug, Clone, Copy)]
struct RomfsNode {
    next_offset: usize,
    file_type: u32,
    is_executable: bool,
    spec_info: u32,
    size: usize,
    name_offset: usize,
    name_len: usize,
    data_offset: usize,
}

#[must_use]
pub fn detect_romfs(bytes: &[u8]) -> Option<RomfsHeader> {
    if bytes.len() < ROMFS_HEADER_MIN + 16 || !bytes.starts_with(ROMFS_MAGIC) {
        return None;
    }
    let full_size: u32 = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let checksum: u32 = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let mut volume_name: [u8; 16] = [0u8; 16];
    volume_name.copy_from_slice(&bytes[16..32]);
    Some(RomfsHeader {
        full_size,
        checksum,
        volume_name,
    })
}

fn volume_name_len(bytes: &[u8]) -> usize {
    let mut len: usize = 0;
    let mut pos: usize = 16;
    while pos < bytes.len() && bytes[pos] != 0 {
        len += 1;
        pos += 1;
    }
    len
}

const fn align16(value: usize) -> usize {
    value.div_ceil(ROMFS_ALIGN) * ROMFS_ALIGN
}

fn read_node(bytes: &[u8], at: usize) -> Result<RomfsNode> {
    let raw: &[u8] = bytes
        .get(at..at + ROMFS_FILE_HEADER_LEN)
        .ok_or_else(|| Error::Romfs(format!("file header at {at} out of bounds")))?;
    let next_raw: u32 = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let spec_info: u32 = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let size: u32 = u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]);
    let file_type: u32 = next_raw & ROMFS_TYPE_MASK;
    let is_executable: bool = next_raw & ROMFS_EXEC_FLAG != 0;
    let next_offset: usize = (next_raw & ROMFS_OFFSET_MASK) as usize;
    let name_offset: usize = at + ROMFS_FILE_HEADER_LEN;
    let mut name_len: usize = 0;
    let mut name_pos: usize = name_offset;
    while name_pos < bytes.len() && bytes[name_pos] != 0 {
        name_len += 1;
        name_pos += 1;
    }
    let data_offset: usize = align16(name_offset + name_len + 1);
    Ok(RomfsNode {
        next_offset,
        file_type,
        is_executable,
        spec_info,
        size: size as usize,
        name_offset,
        name_len,
        data_offset,
    })
}

fn node_name(bytes: &[u8], node: &RomfsNode) -> String {
    let raw: &[u8] = bytes
        .get(node.name_offset..node.name_offset + node.name_len)
        .map_or(&[] as &[u8], |value: &[u8]| value);
    String::from_utf8_lossy(raw).into_owned()
}

pub fn walk_romfs(bytes: &[u8], max_total: u64) -> Result<RomfsWalk> {
    let header: RomfsHeader = detect_romfs(bytes)
        .ok_or_else(|| Error::Romfs("romfs magic -rom1fs- not found".to_owned()))?;
    let root_first: usize = align16(16 + volume_name_len(bytes) + 1);
    let mut files: Vec<RomfsFile> = Vec::new();
    let mut total: u64 = 0;
    let mut stack: Vec<(usize, String, usize)> = vec![(root_first, String::new(), 0)];
    let mut visited: usize = 0;
    while let Some((first_offset, prefix, depth)) = stack.pop() {
        if depth > MAX_ROMFS_DEPTH {
            continue;
        }
        let mut cursor: usize = first_offset;
        while cursor != 0 && cursor + ROMFS_FILE_HEADER_LEN <= bytes.len() {
            visited += 1;
            if visited > MAX_ROMFS_FILES || files.len() > MAX_ROMFS_FILES {
                return Ok(RomfsWalk { header, files });
            }
            let node: RomfsNode = read_node(bytes, cursor)?;
            let name: String = node_name(bytes, &node);
            let next: usize = node.next_offset;
            if name.is_empty() || name == "." || name == ".." {
                if next == cursor || next == 0 {
                    break;
                }
                cursor = next;
                continue;
            }
            let child_path: String = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            match node.file_type {
                TYPE_DIRECTORY => {
                    let child_first: usize = node.spec_info as usize;
                    if child_first != 0 {
                        stack.push((child_first, child_path, depth + 1));
                    }
                }
                TYPE_REGULAR_FILE => {
                    let data: Vec<u8> = read_file_data(bytes, &node, max_total)?;
                    total = total.saturating_add(data.len() as u64);
                    if total > max_total {
                        return Err(Error::Romfs(format!("walk exceeds total cap {max_total}")));
                    }
                    files.push(RomfsFile {
                        path: child_path,
                        data,
                        is_executable: node.is_executable,
                        is_symlink: false,
                    });
                }
                TYPE_SYMBOLIC_LINK => {
                    let data: Vec<u8> = read_file_data(bytes, &node, max_total)?;
                    files.push(RomfsFile {
                        path: child_path,
                        data,
                        is_executable: false,
                        is_symlink: true,
                    });
                }
                _ => {}
            }
            if next == cursor || next == 0 {
                break;
            }
            cursor = next;
        }
    }
    Ok(RomfsWalk { header, files })
}

fn read_file_data(bytes: &[u8], node: &RomfsNode, max_total: u64) -> Result<Vec<u8>> {
    if node.size == 0 {
        return Ok(Vec::new());
    }
    if node.size as u64 > max_total {
        return Err(Error::Romfs("file exceeds total cap".to_owned()));
    }
    let start: usize = node.data_offset;
    let end: usize = start
        .checked_add(node.size)
        .ok_or_else(|| Error::Romfs("file data span overflow".to_owned()))?;
    let slice: &[u8] = bytes
        .get(start..end)
        .ok_or_else(|| Error::Romfs("file data out of bounds".to_owned()))?;
    Ok(slice.to_vec())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn pad16(buf: &mut Vec<u8>) {
        while !buf.len().is_multiple_of(ROMFS_ALIGN) {
            buf.push(0);
        }
    }

    fn checksum_be(region: &[u8]) -> u32 {
        let mut sum: u32 = 0;
        let words: usize = (region.len() / 4).min(128);
        for i in 0..words {
            let w: u32 = u32::from_be_bytes([
                region[i * 4],
                region[i * 4 + 1],
                region[i * 4 + 2],
                region[i * 4 + 3],
            ]);
            sum = sum.wrapping_add(w);
        }
        sum.wrapping_neg()
    }

    struct EncodedNode {
        file_type: u32,
        executable: bool,
        spec_info: u32,
        name: String,
        data: Vec<u8>,
    }

    fn encode_node(out: &mut Vec<u8>, node: &EncodedNode, next_offset: usize) {
        let next_raw: u32 = (next_offset as u32 & ROMFS_OFFSET_MASK)
            | (if node.executable { ROMFS_EXEC_FLAG } else { 0 })
            | (node.file_type & ROMFS_TYPE_MASK);
        out.extend_from_slice(&next_raw.to_be_bytes());
        out.extend_from_slice(&node.spec_info.to_be_bytes());
        out.extend_from_slice(&(node.data.len() as u32).to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(node.name.as_bytes());
        out.push(0);
        pad16(out);
        out.extend_from_slice(&node.data);
        pad16(out);
    }

    fn build_real_romfs_two_files() -> Vec<u8> {
        let mut image: Vec<u8> = Vec::new();
        image.extend_from_slice(ROMFS_MAGIC);
        image.extend_from_slice(&0u32.to_be_bytes());
        image.extend_from_slice(&0u32.to_be_bytes());
        let vol: &[u8] = b"rom";
        image.extend_from_slice(vol);
        image.push(0);
        pad16(&mut image);

        let file_a_body: &[u8] = &b"first romfs file byte-exact payload ".repeat(4);
        let file_b_body: &[u8] = &b"SECOND".repeat(10);

        let header_a: usize = image.len();
        let name_a: &str = "first.txt";
        let a_body_pad: usize =
            align16(ROMFS_FILE_HEADER_LEN + name_a.len() + 1) + align16(file_a_body.len());
        let header_b: usize = header_a + a_body_pad;

        encode_node(
            &mut image,
            &EncodedNode {
                file_type: TYPE_REGULAR_FILE,
                executable: true,
                spec_info: 0,
                name: name_a.to_owned(),
                data: file_a_body.to_vec(),
            },
            header_b,
        );
        assert_eq!(image.len(), header_b);
        encode_node(
            &mut image,
            &EncodedNode {
                file_type: TYPE_REGULAR_FILE,
                executable: false,
                spec_info: 0,
                name: "second.bin".to_owned(),
                data: file_b_body.to_vec(),
            },
            0,
        );

        let full_size: u32 = image.len() as u32;
        image[8..12].copy_from_slice(&full_size.to_be_bytes());
        let csum: u32 = checksum_be(&image[..512.min(image.len())]);
        image[12..16].copy_from_slice(&csum.to_be_bytes());
        image
    }

    fn build_real_romfs_with_subdir() -> Vec<u8> {
        let mut image: Vec<u8> = Vec::new();
        image.extend_from_slice(ROMFS_MAGIC);
        image.extend_from_slice(&0u32.to_be_bytes());
        image.extend_from_slice(&0u32.to_be_bytes());
        image.extend_from_slice(b"rom");
        image.push(0);
        pad16(&mut image);

        let nested_body: &[u8] = b"nested directory file content 9876543210";

        let dir_header: usize = image.len();
        let dir_name: &str = "sub";
        let dir_span: usize = align16(ROMFS_FILE_HEADER_LEN + dir_name.len() + 1);
        let child_header: usize = dir_header + dir_span;

        let next_raw: u32 = TYPE_DIRECTORY;
        image.extend_from_slice(&next_raw.to_be_bytes());
        image.extend_from_slice(&(child_header as u32).to_be_bytes());
        image.extend_from_slice(&0u32.to_be_bytes());
        image.extend_from_slice(&0u32.to_be_bytes());
        image.extend_from_slice(dir_name.as_bytes());
        image.push(0);
        pad16(&mut image);
        assert_eq!(image.len(), child_header);

        encode_node(
            &mut image,
            &EncodedNode {
                file_type: TYPE_REGULAR_FILE,
                executable: false,
                spec_info: 0,
                name: "deep.dat".to_owned(),
                data: nested_body.to_vec(),
            },
            0,
        );

        let full_size: u32 = image.len() as u32;
        image[8..12].copy_from_slice(&full_size.to_be_bytes());
        image
    }

    #[test]
    fn detects_romfs_magic() {
        let image: Vec<u8> = build_real_romfs_two_files();
        let header: RomfsHeader = detect_romfs(&image).expect("romfs header");
        assert_eq!(&header.volume_name[..3], b"rom");
        assert_eq!(header.full_size as usize, image.len());
    }

    #[test]
    fn rejects_short_and_non_romfs() {
        assert!(detect_romfs(&[0u8; 8]).is_none());
        assert!(detect_romfs(&[0xAAu8; 64]).is_none());
    }

    #[test]
    fn walks_two_files_byte_exact() {
        let image: Vec<u8> = build_real_romfs_two_files();
        let walk: RomfsWalk = walk_romfs(&image, 64 * 1024 * 1024).expect("walk romfs");
        assert_eq!(walk.files.len(), 2);
        assert_eq!(walk.files[0].path, "first.txt");
        assert_eq!(
            walk.files[0].data,
            b"first romfs file byte-exact payload ".repeat(4)
        );
        assert!(walk.files[0].is_executable);
        assert_eq!(walk.files[1].path, "second.bin");
        assert_eq!(walk.files[1].data, b"SECOND".repeat(10));
        assert!(!walk.files[1].is_executable);
    }

    #[test]
    fn walks_subdirectory_byte_exact() {
        let image: Vec<u8> = build_real_romfs_with_subdir();
        let walk: RomfsWalk = walk_romfs(&image, 64 * 1024 * 1024).expect("walk romfs");
        assert_eq!(walk.files.len(), 1);
        assert_eq!(walk.files[0].path, "sub/deep.dat");
        assert_eq!(
            walk.files[0].data,
            b"nested directory file content 9876543210"
        );
    }

    #[test]
    fn extract_to_writes_romfs_files() {
        let image: Vec<u8> = build_real_romfs_two_files();
        let dir: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("binfmt-romfs-e2e")
                .expect("create scratch dir");
        let result: crate::extract::ExtractionResult =
            crate::extract::extract_to(crate::container::ContainerKind::Romfs, &image, dir.path())
                .expect("romfs extract");
        assert_eq!(result.kind, crate::container::ContainerKind::Romfs);
        assert_eq!(
            std::fs::read(dir.path().join("first.txt")).expect("first"),
            b"first romfs file byte-exact payload ".repeat(4)
        );
        assert_eq!(
            std::fs::read(dir.path().join("second.bin")).expect("second"),
            b"SECOND".repeat(10)
        );
    }
}
