use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::quota::ExtractionQuota;

use super::wim::{
    RESHDR_FLAG_COMPRESSED, RESHDR_FLAG_METADATA, WimHeader, WimResource, parse_reshdr_at,
};
use super::wim_codec::decompress_wim_resource;

const LOOKUP_ENTRY_LEN: usize = 50;
const SHA1_LEN: usize = 20;
const DENTRY_FIXED_LEN: usize = 102;
const SECURITY_HEADER_LEN: usize = 8;
const ATTR_DIRECTORY: u32 = 0x0000_0010;
const ATTR_REPARSE_POINT: u32 = 0x0000_0400;
const MAX_DENTRY_COUNT: usize = 1_000_000;
const MAX_TREE_DEPTH: u32 = 512;
const DEFAULT_CHUNK_SIZE: u32 = 32_768;

type BlobMap = BTreeMap<[u8; SHA1_LEN], WimResource>;

#[derive(Debug, Clone)]
pub struct WimExtractedFile {
    pub path: String,
    pub data: Vec<u8>,
    pub compressed: bool,
    pub original_size: u64,
    pub compressed_size: u64,
}

#[derive(Debug, Default)]
pub struct WimImageExtraction {
    pub files: Vec<WimExtractedFile>,
    pub notes: Vec<String>,
}

fn lookup_table_bytes(bytes: &[u8], header: &WimHeader) -> Result<Vec<u8>> {
    let resource: WimResource = header.offset_table;
    if resource.size == 0 {
        return Err(Error::Decompression(
            "wim lookup table resource is empty".to_owned(),
        ));
    }
    let chunk_size: u32 = if header.chunk_size == 0 {
        DEFAULT_CHUNK_SIZE
    } else {
        header.chunk_size
    };
    let offset: usize =
        usize::try_from(resource.offset).map_err(|_e: std::num::TryFromIntError| {
            Error::Decompression("wim lookup table offset overflow".to_owned())
        })?;
    let size: usize = usize::try_from(resource.size).map_err(|_e: std::num::TryFromIntError| {
        Error::Decompression("wim lookup table size overflow".to_owned())
    })?;
    let end: usize = offset
        .checked_add(size)
        .ok_or_else(|| Error::Decompression("wim lookup table range overflow".to_owned()))?;
    let slice: &[u8] = bytes
        .get(offset..end)
        .ok_or_else(|| Error::Decompression("wim lookup table out of bounds".to_owned()))?;
    if resource.flags & RESHDR_FLAG_COMPRESSED == 0 {
        return Ok(slice.to_vec());
    }
    decompress_wim_resource(
        slice,
        header.compression,
        resource.original_size,
        chunk_size,
        &ExtractionQuota::unrestricted(),
    )
}

fn parse_lookup_table(table: &[u8]) -> (BlobMap, Option<WimResource>) {
    let mut blobs: BlobMap = BlobMap::new();
    let mut metadata: Option<WimResource> = None;
    let entry_count: usize = table.len() / LOOKUP_ENTRY_LEN;
    for index in 0..entry_count {
        let base: usize = index * LOOKUP_ENTRY_LEN;
        let resource: WimResource = parse_reshdr_at(table, base);
        let mut sha1: [u8; SHA1_LEN] = [0u8; SHA1_LEN];
        let hash_start: usize = base + 30;
        if let Some(slice) = table.get(hash_start..hash_start + SHA1_LEN) {
            sha1.copy_from_slice(slice);
        }
        if resource.flags & RESHDR_FLAG_METADATA != 0 {
            if metadata.is_none() {
                metadata = Some(resource);
            }
            continue;
        }
        if sha1 != [0u8; SHA1_LEN] {
            blobs.entry(sha1).or_insert(resource);
        }
    }
    (blobs, metadata)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let slice: &[u8] = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| Error::Decompression("wim dentry field truncated".to_owned()))?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let slice: &[u8] = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| Error::Decompression("wim dentry field truncated".to_owned()))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let slice: &[u8] = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| Error::Decompression("wim dentry field truncated".to_owned()))?;
    let mut buf: [u8; 8] = [0u8; 8];
    buf.copy_from_slice(slice);
    Ok(u64::from_le_bytes(buf))
}

const fn align8(value: usize) -> usize {
    value.wrapping_add(7) & !7
}

fn security_data_size(metadata: &[u8]) -> Result<usize> {
    let total_length: u32 = read_u32(metadata, 0)?;
    let total: usize = total_length as usize;
    let bounded: usize = total.max(SECURITY_HEADER_LEN);
    Ok(align8(bounded))
}

#[derive(Debug, Clone)]
struct Dentry {
    length: u64,
    attributes: u32,
    subdir_offset: u64,
    hash: [u8; SHA1_LEN],
    name: String,
}

fn decode_utf16le_name(bytes: &[u8]) -> String {
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len() / 2);
    let mut index: usize = 0;
    while index + 1 < bytes.len() {
        units.push(u16::from_le_bytes([bytes[index], bytes[index + 1]]));
        index += 2;
    }
    String::from_utf16_lossy(&units)
}

fn parse_dentry(metadata: &[u8], offset: usize) -> Result<Option<Dentry>> {
    let length: u64 = read_u64(metadata, offset)?;
    if length == 0 {
        return Ok(None);
    }
    if (length as usize) < DENTRY_FIXED_LEN {
        return Err(Error::Decompression(
            "wim dentry shorter than fixed header".to_owned(),
        ));
    }
    let attributes: u32 = read_u32(metadata, offset + 8)?;
    let subdir_offset: u64 = read_u64(metadata, offset + 16)?;
    let mut hash: [u8; SHA1_LEN] = [0u8; SHA1_LEN];
    let hash_start: usize = offset + 64;
    let hash_slice: &[u8] = metadata
        .get(hash_start..hash_start + SHA1_LEN)
        .ok_or_else(|| Error::Decompression("wim dentry hash truncated".to_owned()))?;
    hash.copy_from_slice(hash_slice);
    let short_name_nbytes: u16 = read_u16(metadata, offset + 98)?;
    let name_nbytes: u16 = read_u16(metadata, offset + 100)?;
    let name: String = if name_nbytes == 0 {
        String::new()
    } else {
        let name_start: usize = offset + DENTRY_FIXED_LEN;
        let name_end: usize = name_start
            .checked_add(name_nbytes as usize)
            .ok_or_else(|| Error::Decompression("wim dentry name range overflow".to_owned()))?;
        let raw: &[u8] = metadata
            .get(name_start..name_end)
            .ok_or_else(|| Error::Decompression("wim dentry name out of bounds".to_owned()))?;
        decode_utf16le_name(raw)
    };
    let _ = short_name_nbytes;
    Ok(Some(Dentry {
        length,
        attributes,
        subdir_offset,
        hash,
        name,
    }))
}

fn join_path(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.to_owned()
    } else {
        format!("{parent}/{child}")
    }
}

struct WalkState<'a> {
    metadata: &'a [u8],
    blobs: &'a BlobMap,
    files: Vec<WimExtractedFile>,
    notes: Vec<String>,
    visited_dirs: usize,
    source: &'a [u8],
    header: &'a WimHeader,
    quota: &'a ExtractionQuota,
}

impl WalkState<'_> {
    fn materialize(&self, resource: WimResource) -> Result<Vec<u8>> {
        let offset: usize =
            usize::try_from(resource.offset).map_err(|_e: std::num::TryFromIntError| {
                Error::Decompression("wim blob offset overflow".to_owned())
            })?;
        let size: usize =
            usize::try_from(resource.size).map_err(|_e: std::num::TryFromIntError| {
                Error::Decompression("wim blob size overflow".to_owned())
            })?;
        let end: usize = offset
            .checked_add(size)
            .ok_or_else(|| Error::Decompression("wim blob range overflow".to_owned()))?;
        let slice: &[u8] = self
            .source
            .get(offset..end)
            .ok_or_else(|| Error::Decompression("wim blob out of bounds".to_owned()))?;
        let chunk_size: u32 = if self.header.chunk_size == 0 {
            DEFAULT_CHUNK_SIZE
        } else {
            self.header.chunk_size
        };
        let compression: super::wim::WimCompression =
            if resource.flags & RESHDR_FLAG_COMPRESSED != 0 {
                self.header.compression
            } else {
                super::wim::WimCompression::None
            };
        decompress_wim_resource(
            slice,
            compression,
            resource.original_size,
            chunk_size,
            self.quota,
        )
    }

    fn walk(&mut self, child_offset: u64, parent_path: &str, depth: u32) -> Result<()> {
        if depth > MAX_TREE_DEPTH {
            return Err(Error::Decompression(
                "wim dentry tree exceeds maximum depth".to_owned(),
            ));
        }
        let mut cursor: usize =
            usize::try_from(child_offset).map_err(|_e: std::num::TryFromIntError| {
                Error::Decompression("wim subdir offset overflow".to_owned())
            })?;
        loop {
            if self.visited_dirs > MAX_DENTRY_COUNT {
                return Err(Error::Decompression(
                    "wim dentry count exceeds sanity bound".to_owned(),
                ));
            }
            let dentry: Dentry = match parse_dentry(self.metadata, cursor)? {
                Some(d) => d,
                None => break,
            };
            self.visited_dirs += 1;
            let entry_path: String = if dentry.name.is_empty() {
                parent_path.to_owned()
            } else {
                join_path(parent_path, &dentry.name.replace('\\', "/"))
            };
            let is_dir: bool = dentry.attributes & ATTR_DIRECTORY != 0;
            let is_reparse: bool = dentry.attributes & ATTR_REPARSE_POINT != 0;
            if is_dir {
                if dentry.subdir_offset != 0 && !dentry.name.is_empty() {
                    self.walk(dentry.subdir_offset, &entry_path, depth + 1)?;
                } else if dentry.subdir_offset != 0 && dentry.name.is_empty() {
                    self.walk(dentry.subdir_offset, parent_path, depth + 1)?;
                }
            } else if is_reparse {
                self.notes.push(format!(
                    "wim-reparse `{entry_path}`: reparse-point file skipped (target is metadata, not a data stream)"
                ));
            } else if dentry.hash == [0u8; SHA1_LEN] {
                self.files.push(WimExtractedFile {
                    path: entry_path,
                    data: Vec::new(),
                    compressed: false,
                    original_size: 0,
                    compressed_size: 0,
                });
            } else if let Some(&blob) = self.blobs.get(&dentry.hash) {
                match self.materialize(blob) {
                    Ok(data) => self.files.push(WimExtractedFile {
                        path: entry_path,
                        compressed: blob.flags & RESHDR_FLAG_COMPRESSED != 0,
                        original_size: blob.original_size,
                        compressed_size: blob.size,
                        data,
                    }),
                    Err(e) => self.notes.push(format!("wim-stream `{entry_path}`: {e}")),
                }
            } else {
                self.notes.push(format!(
                    "wim-stream `{entry_path}`: data blob {} not present in the lookup table",
                    hex_sha1(&dentry.hash)
                ));
            }
            let advance: usize = align8(dentry.length as usize);
            cursor = cursor
                .checked_add(advance)
                .ok_or_else(|| Error::Decompression("wim dentry cursor overflow".to_owned()))?;
        }
        Ok(())
    }
}

fn hex_sha1(hash: &[u8; SHA1_LEN]) -> String {
    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
    let mut out: String = String::with_capacity(SHA1_LEN * 2);
    for byte in hash.iter().copied() {
        out.push(char::from(HEX_LOWER[usize::from(byte >> 4)]));
        out.push(char::from(HEX_LOWER[usize::from(byte & 0x0f)]));
    }
    out
}

pub fn extract_wim_files(
    bytes: &[u8],
    header: &WimHeader,
    quota: &ExtractionQuota,
) -> Result<WimImageExtraction> {
    let table: Vec<u8> = lookup_table_bytes(bytes, header)?;
    let (blobs, metadata_resource): (BlobMap, Option<WimResource>) = parse_lookup_table(&table);
    let metadata_resource: WimResource = metadata_resource.ok_or_else(|| {
        Error::Decompression("wim lookup table has no metadata resource".to_owned())
    })?;
    let metadata_offset: usize =
        usize::try_from(metadata_resource.offset).map_err(|_e: std::num::TryFromIntError| {
            Error::Decompression("wim metadata offset overflow".to_owned())
        })?;
    let metadata_size: usize =
        usize::try_from(metadata_resource.size).map_err(|_e: std::num::TryFromIntError| {
            Error::Decompression("wim metadata size overflow".to_owned())
        })?;
    let metadata_end: usize = metadata_offset
        .checked_add(metadata_size)
        .ok_or_else(|| Error::Decompression("wim metadata range overflow".to_owned()))?;
    let metadata_slice: &[u8] = bytes
        .get(metadata_offset..metadata_end)
        .ok_or_else(|| Error::Decompression("wim metadata resource out of bounds".to_owned()))?;
    let chunk_size: u32 = if header.chunk_size == 0 {
        DEFAULT_CHUNK_SIZE
    } else {
        header.chunk_size
    };
    let metadata_compression: super::wim::WimCompression =
        if metadata_resource.flags & RESHDR_FLAG_COMPRESSED != 0 {
            header.compression
        } else {
            super::wim::WimCompression::None
        };
    let metadata: Vec<u8> = decompress_wim_resource(
        metadata_slice,
        metadata_compression,
        metadata_resource.original_size,
        chunk_size,
        quota,
    )?;
    let security_size: usize = security_data_size(&metadata)?;
    if security_size > metadata.len() {
        return Err(Error::Decompression(
            "wim security data overruns metadata resource".to_owned(),
        ));
    }
    let root: Dentry = match parse_dentry(&metadata, security_size)? {
        Some(d) => d,
        None => {
            return Ok(WimImageExtraction {
                files: Vec::new(),
                notes: vec!["wim-image: metadata root dentry is empty".to_owned()],
            });
        }
    };
    let mut state: WalkState<'_> = WalkState {
        metadata: &metadata,
        blobs: &blobs,
        files: Vec::new(),
        notes: Vec::new(),
        visited_dirs: 0,
        source: bytes,
        header,
        quota,
    };
    if root.subdir_offset != 0 {
        state.walk(root.subdir_offset, "", 0)?;
    }
    Ok(WimImageExtraction {
        files: state.files,
        notes: state.notes,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn align8_rounds_up_to_multiple_of_eight() {
        assert_eq!(align8(0), 0);
        assert_eq!(align8(1), 8);
        assert_eq!(align8(8), 8);
        assert_eq!(align8(9), 16);
        assert_eq!(align8(352), 352);
    }

    #[test]
    fn join_path_handles_root_and_nested() {
        assert_eq!(join_path("", "hello.txt"), "hello.txt");
        assert_eq!(join_path("sub", "nested.bin"), "sub/nested.bin");
    }

    #[test]
    fn security_data_size_aligns_total_length() {
        let mut meta: [u8; 16] = [0u8; 16];
        meta[0..4].copy_from_slice(&352u32.to_le_bytes());
        assert_eq!(security_data_size(&meta).expect("size"), 352);
        meta[0..4].copy_from_slice(&8u32.to_le_bytes());
        assert_eq!(security_data_size(&meta).expect("size"), 8);
        meta[0..4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(security_data_size(&meta).expect("size"), 8);
    }
}
