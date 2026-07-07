use serde::{Deserialize, Serialize};
use std::io::Write;

use crate::error::{Error, Result};
use crate::quota::bounded_prealloc;

pub const UNITYFS_MAGIC: &[u8; 8] = b"UnityFS\x00";

const FLAG_COMPRESSION_MASK: u32 = 0x3F;
const FLAG_BLOCKS_INFO_AT_END: u32 = 0x40;
const FLAG_BLOCKS_INFO_PADDING: u32 = 0x80;
const BLOCK_FLAG_COMPRESSION_MASK: u16 = 0x3F;
const BLOCKS_INFO_HASH_LEN: usize = 16;
const MAX_STRING_SCAN: usize = 4096;
const MAX_BLOCK_COUNT: usize = 1 << 20;
const MAX_NODE_COUNT: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnityCompression {
    None,
    Lzma,
    Lz4,
    Lz4Hc,
    Unknown,
}

impl UnityCompression {
    #[must_use]
    const fn from_code(code: u32) -> Self {
        match code {
            0 | 1 => Self::None,
            2 => Self::Lzma,
            3 => Self::Lz4,
            4 => Self::Lz4Hc,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Lzma => "lzma",
            Self::Lz4 => "lz4",
            Self::Lz4Hc => "lz4hc",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnityBlockInfo {
    pub uncompressed_size: u32,
    pub compressed_size: u32,
    pub compression: UnityCompression,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnityNode {
    pub offset: i64,
    pub size: i64,
    pub flags: u32,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnityFsHeader {
    pub version: u32,
    pub unity_version: String,
    pub unity_revision: String,
    pub size: i64,
    pub compressed_blocks_info_size: u32,
    pub uncompressed_blocks_info_size: u32,
    pub flags: u32,
    pub blocks_info_compression: UnityCompression,
    pub blocks_info_at_end: bool,
    pub header_end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnityFsArchive {
    pub header: UnityFsHeader,
    pub blocks: Vec<UnityBlockInfo>,
    pub nodes: Vec<UnityNode>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnityExtractedNode {
    pub path: String,
    pub data: Vec<u8>,
}

#[must_use]
pub fn detect_unityfs(bytes: &[u8]) -> bool {
    bytes.starts_with(UNITYFS_MAGIC)
}

struct BeReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> BeReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    const fn with_pos(bytes: &'a [u8], pos: usize) -> Self {
        Self { bytes, pos }
    }

    fn read_u16(&mut self) -> Result<u16> {
        let slice: &[u8] = self
            .bytes
            .get(self.pos..self.pos + 2)
            .ok_or_else(|| Error::Decompression("unityfs: truncated u16".to_owned()))?;
        self.pos += 2;
        Ok(u16::from_be_bytes([slice[0], slice[1]]))
    }

    fn read_u32(&mut self) -> Result<u32> {
        let slice: &[u8] = self
            .bytes
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| Error::Decompression("unityfs: truncated u32".to_owned()))?;
        self.pos += 4;
        Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
    }

    fn read_i32(&mut self) -> Result<i32> {
        Ok(self.read_u32()? as i32)
    }

    fn read_i64(&mut self) -> Result<i64> {
        let slice: &[u8] = self
            .bytes
            .get(self.pos..self.pos + 8)
            .ok_or_else(|| Error::Decompression("unityfs: truncated i64".to_owned()))?;
        self.pos += 8;
        Ok(i64::from_be_bytes([
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
        ]))
    }

    fn read_cstring(&mut self) -> Result<String> {
        let start: usize = self.pos;
        let limit: usize = (start + MAX_STRING_SCAN).min(self.bytes.len());
        let mut end: usize = start;
        while end < limit {
            if self.bytes[end] == 0 {
                let text: String = String::from_utf8_lossy(&self.bytes[start..end]).into_owned();
                self.pos = end + 1;
                return Ok(text);
            }
            end += 1;
        }
        Err(Error::Decompression(
            "unityfs: unterminated c-string in header".to_owned(),
        ))
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8]> {
        let slice: &[u8] = self
            .bytes
            .get(self.pos..self.pos + len)
            .ok_or_else(|| Error::Decompression("unityfs: truncated byte run".to_owned()))?;
        self.pos += len;
        Ok(slice)
    }
}

pub fn parse_header(bytes: &[u8]) -> Result<UnityFsHeader> {
    let mut r: BeReader<'_> = BeReader::new(bytes);
    let magic: &[u8] = r.read_exact(UNITYFS_MAGIC.len())?;
    if magic != UNITYFS_MAGIC {
        return Err(Error::Decompression(
            "unityfs: missing `UnityFS` signature".to_owned(),
        ));
    }
    let version: u32 = r.read_u32()?;
    let unity_version: String = r.read_cstring()?;
    let unity_revision: String = r.read_cstring()?;
    let size: i64 = r.read_i64()?;
    let compressed_blocks_info_size: u32 = r.read_u32()?;
    let uncompressed_blocks_info_size: u32 = r.read_u32()?;
    let flags: u32 = r.read_u32()?;
    if version >= 7 {
        r.pos = align_up(r.pos, 16);
    }
    let blocks_info_compression: UnityCompression =
        UnityCompression::from_code(flags & FLAG_COMPRESSION_MASK);
    let blocks_info_at_end: bool = flags & FLAG_BLOCKS_INFO_AT_END != 0;
    Ok(UnityFsHeader {
        version,
        unity_version,
        unity_revision,
        size,
        compressed_blocks_info_size,
        uncompressed_blocks_info_size,
        flags,
        blocks_info_compression,
        blocks_info_at_end,
        header_end: r.pos,
    })
}

#[must_use]
const fn align_up(value: usize, align: usize) -> usize {
    let rem: usize = value % align;
    if rem == 0 {
        value
    } else {
        value + (align - rem)
    }
}

fn blocks_info_slice<'a>(bytes: &'a [u8], header: &UnityFsHeader) -> Result<&'a [u8]> {
    let compressed_len: usize = header.compressed_blocks_info_size as usize;
    let start: usize = if header.blocks_info_at_end {
        let total: usize =
            usize::try_from(header.size).map_err(|_: std::num::TryFromIntError| {
                Error::Decompression("unityfs: negative bundle size".to_owned())
            })?;
        total.checked_sub(compressed_len).ok_or_else(|| {
            Error::Decompression("unityfs: blocks-info-at-end underflow".to_owned())
        })?
    } else {
        header.header_end
    };
    bytes
        .get(start..start + compressed_len)
        .ok_or_else(|| Error::Decompression("unityfs: blocks info slice out of range".to_owned()))
}

fn decompress_blob(
    compression: UnityCompression,
    src: &[u8],
    uncompressed_size: usize,
) -> Result<Vec<u8>> {
    match compression {
        UnityCompression::None => Ok(src.to_vec()),
        UnityCompression::Lz4 | UnityCompression::Lz4Hc => {
            crate::containers::lz4_block::decompress(src, uncompressed_size)
        }
        UnityCompression::Lzma => decompress_lzma_stream(src, uncompressed_size),
        UnityCompression::Unknown => Err(Error::Decompression(
            "unityfs: unknown blocks-info compression code".to_owned(),
        )),
    }
}

fn decompress_lzma_stream(src: &[u8], uncompressed_size: usize) -> Result<Vec<u8>> {
    if src.len() < 5 {
        return Err(Error::Decompression(
            "unityfs: lzma stream too short for props+dict header".to_owned(),
        ));
    }
    let uncompressed_size_u64: u64 = u64::try_from(uncompressed_size)
        .map_err(|_| Error::Decompression("unityfs: lzma declared size overflow".to_owned()))?;
    let mut full: Vec<u8> = Vec::with_capacity(src.len() + 8);
    full.extend_from_slice(&src[..5]);
    full.extend_from_slice(&uncompressed_size_u64.to_le_bytes());
    full.extend_from_slice(&src[5..]);
    let mut cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(full);
    let mut writer: BoundedVecWriter = BoundedVecWriter::new(uncompressed_size);
    lzma_rs::lzma_decompress(&mut cursor, &mut writer)
        .map_err(|e| Error::Decompression(format!("unityfs: lzma decode failed: {e}")))?;
    writer.finish_exact("lzma")
}

struct BoundedVecWriter {
    out: Vec<u8>,
    cap: usize,
}

impl BoundedVecWriter {
    fn new(cap: usize) -> Self {
        let declared: u64 = u64::try_from(cap).map_or(u64::MAX, |value: u64| value);
        Self {
            out: Vec::with_capacity(bounded_prealloc(declared)),
            cap,
        }
    }

    fn finish_exact(self, label: &'static str) -> Result<Vec<u8>> {
        if self.out.len() != self.cap {
            return Err(Error::Decompression(format!(
                "unityfs: {label} block decoded to {} bytes, expected {}",
                self.out.len(),
                self.cap
            )));
        }
        Ok(self.out)
    }
}

impl Write for BoundedVecWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let remaining: usize = self.cap.saturating_sub(self.out.len());
        if buf.len() > remaining {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unityfs block exceeds declared size",
            ));
        }
        self.out.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn parse(bytes: &[u8]) -> Result<UnityFsArchive> {
    let header: UnityFsHeader = parse_header(bytes)?;
    let raw_info: &[u8] = blocks_info_slice(bytes, &header)?;
    let info: Vec<u8> = decompress_blob(
        header.blocks_info_compression,
        raw_info,
        header.uncompressed_blocks_info_size as usize,
    )?;

    let mut r: BeReader<'_> = BeReader::with_pos(&info, 0);
    let _hash: &[u8] = r.read_exact(BLOCKS_INFO_HASH_LEN)?;
    let block_count_raw: i32 = r.read_i32()?;
    let block_count: usize =
        usize::try_from(block_count_raw).map_err(|_: std::num::TryFromIntError| {
            Error::Decompression("unityfs: negative block count".to_owned())
        })?;
    if block_count > MAX_BLOCK_COUNT {
        return Err(Error::Decompression(format!(
            "unityfs: block count {block_count} exceeds sane cap"
        )));
    }
    let mut blocks: Vec<UnityBlockInfo> = Vec::with_capacity(block_count.min(1024));
    for _ in 0..block_count {
        let uncompressed_size: u32 = r.read_u32()?;
        let compressed_size: u32 = r.read_u32()?;
        let block_flags: u16 = r.read_u16()?;
        let compression: UnityCompression =
            UnityCompression::from_code(u32::from(block_flags & BLOCK_FLAG_COMPRESSION_MASK));
        blocks.push(UnityBlockInfo {
            uncompressed_size,
            compressed_size,
            compression,
        });
    }

    let node_count_raw: i32 = r.read_i32()?;
    let node_count: usize =
        usize::try_from(node_count_raw).map_err(|_: std::num::TryFromIntError| {
            Error::Decompression("unityfs: negative node count".to_owned())
        })?;
    if node_count > MAX_NODE_COUNT {
        return Err(Error::Decompression(format!(
            "unityfs: node count {node_count} exceeds sane cap"
        )));
    }
    let mut nodes: Vec<UnityNode> = Vec::with_capacity(node_count.min(1024));
    for _ in 0..node_count {
        let offset: i64 = r.read_i64()?;
        let size: i64 = r.read_i64()?;
        let flags: u32 = r.read_u32()?;
        let path: String = r.read_cstring()?;
        nodes.push(UnityNode {
            offset,
            size,
            flags,
            path,
        });
    }

    Ok(UnityFsArchive {
        header,
        blocks,
        nodes,
    })
}

const fn data_region_start(header: &UnityFsHeader) -> usize {
    if header.blocks_info_at_end {
        header.header_end
    } else {
        let after_info: usize = header.header_end + header.compressed_blocks_info_size as usize;
        if header.flags & FLAG_BLOCKS_INFO_PADDING != 0 {
            align_up(after_info, 16)
        } else {
            after_info
        }
    }
}

pub fn assemble_data(bytes: &[u8], archive: &UnityFsArchive, max_total: u64) -> Result<Vec<u8>> {
    let mut cursor: usize = data_region_start(&archive.header);
    let total_uncompressed: u64 = archive
        .blocks
        .iter()
        .map(|b: &UnityBlockInfo| u64::from(b.uncompressed_size))
        .sum();
    if total_uncompressed > max_total {
        return Err(Error::Decompression(format!(
            "unityfs: blob stream {total_uncompressed} bytes exceeds quota {max_total}"
        )));
    }
    let mut out: Vec<u8> = Vec::with_capacity(bounded_prealloc(total_uncompressed));
    for block in &archive.blocks {
        let compressed_len: usize = usize::try_from(block.compressed_size).map_err(|_| {
            Error::Decompression("unityfs: compressed block length overflow".to_owned())
        })?;
        let chunk_end: usize = cursor.checked_add(compressed_len).ok_or_else(|| {
            Error::Decompression("unityfs: compressed block range overflow".to_owned())
        })?;
        let chunk: &[u8] = bytes.get(cursor..chunk_end).ok_or_else(|| {
            Error::Decompression("unityfs: data block runs past end of bundle".to_owned())
        })?;
        cursor = chunk_end;
        let expected_len: usize = usize::try_from(block.uncompressed_size).map_err(|_| {
            Error::Decompression("unityfs: uncompressed block length overflow".to_owned())
        })?;
        let decoded: Vec<u8> = decompress_blob(block.compression, chunk, expected_len)?;
        if decoded.len() != expected_len {
            return Err(Error::Decompression(format!(
                "unityfs: block decoded to {} bytes, header declared {}",
                decoded.len(),
                block.uncompressed_size
            )));
        }
        out.extend_from_slice(&decoded);
    }
    Ok(out)
}

pub fn extract_nodes(
    bytes: &[u8],
    archive: &UnityFsArchive,
    max_total: u64,
) -> Result<Vec<UnityExtractedNode>> {
    let blob: Vec<u8> = assemble_data(bytes, archive, max_total)?;
    let mut out: Vec<UnityExtractedNode> = Vec::with_capacity(archive.nodes.len());
    for node in &archive.nodes {
        let start: usize =
            usize::try_from(node.offset).map_err(|_: std::num::TryFromIntError| {
                Error::Decompression("unityfs: negative node offset".to_owned())
            })?;
        let len: usize = usize::try_from(node.size).map_err(|_: std::num::TryFromIntError| {
            Error::Decompression("unityfs: negative node size".to_owned())
        })?;
        let end: usize = start.checked_add(len).ok_or_else(|| {
            Error::Decompression(format!("unityfs: node `{}` range overflow", node.path))
        })?;
        let slice: &[u8] = blob.get(start..end).ok_or_else(|| {
            Error::Decompression(format!(
                "unityfs: node `{}` range {start}..{end} out of assembled blob",
                node.path
            ))
        })?;
        out.push(UnityExtractedNode {
            path: node.path.clone(),
            data: slice.to_vec(),
        });
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnityTextAsset {
    pub name: String,
    pub script: Vec<u8>,
}

pub fn extract_text_assets(
    bytes: &[u8],
    archive: &UnityFsArchive,
    max_total: u64,
) -> Result<Vec<UnityTextAsset>> {
    let nodes: Vec<UnityExtractedNode> = extract_nodes(bytes, archive, max_total)?;
    let mut assets: Vec<UnityTextAsset> = Vec::new();
    for node in &nodes {
        if is_serialized_file(&node.data) {
            collect_text_assets_from_serialized(&node.data, &mut assets)?;
        }
    }
    Ok(assets)
}

fn is_serialized_file(bytes: &[u8]) -> bool {
    if bytes.len() < 20 {
        return false;
    }
    let metadata_size: u32 = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let version: u32 = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    metadata_size > 0 && (1..=100).contains(&version)
}

const SERIALIZED_VERSION: u32 = 22;
const SERIALIZED_HEADER_LEN_V22: usize = 0x30;

#[must_use]
pub fn build_serialized_textasset(name: &str, script: &[u8]) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&(name.len() as u32).to_le_bytes());
    body.extend_from_slice(name.as_bytes());
    let name_pad: usize = align_up(body.len(), 4) - body.len();
    body.extend(std::iter::repeat_n(0u8, name_pad));
    body.extend_from_slice(&(script.len() as u32).to_le_bytes());
    body.extend_from_slice(script);
    let script_pad: usize = align_up(body.len(), 4) - body.len();
    body.extend(std::iter::repeat_n(0u8, script_pad));

    let mut metadata: Vec<u8> = Vec::new();
    metadata.extend_from_slice(b"2021.3.0f1\x00");
    metadata.extend_from_slice(&5u32.to_le_bytes());
    metadata.push(0);
    metadata.extend_from_slice(&0u32.to_le_bytes());
    metadata.extend_from_slice(&1u32.to_le_bytes());
    let object_align_pad: usize = align_up(metadata.len(), 4) - metadata.len();
    metadata.extend(std::iter::repeat_n(0u8, object_align_pad));
    metadata.extend_from_slice(&1i64.to_le_bytes());
    let byte_start_pos: usize = metadata.len();
    metadata.extend_from_slice(&0i64.to_le_bytes());
    metadata.extend_from_slice(&(body.len() as u32).to_le_bytes());
    metadata.extend_from_slice(&TEXTASSET_CLASS_ID.to_le_bytes());

    let header_and_metadata: usize = SERIALIZED_HEADER_LEN_V22 + metadata.len();
    let data_offset: u64 = align_up(header_and_metadata, 16) as u64;
    let byte_start: i64 = 0;
    metadata[byte_start_pos..byte_start_pos + 8].copy_from_slice(&byte_start.to_le_bytes());

    let mut file: Vec<u8> = Vec::new();
    file.extend_from_slice(&0u32.to_be_bytes());
    let total_size: u64 = data_offset + body.len() as u64;
    file.extend_from_slice(&(total_size as u32).to_be_bytes());
    file.extend_from_slice(&SERIALIZED_VERSION.to_be_bytes());
    file.extend_from_slice(&0u32.to_be_bytes());
    file.extend_from_slice(&total_size.to_le_bytes());
    file.extend_from_slice(&data_offset.to_le_bytes());
    file.push(0);
    file.extend_from_slice(&[0u8; 7]);
    while file.len() < SERIALIZED_HEADER_LEN_V22 {
        file.push(0);
    }
    debug_assert_eq!(file.len(), SERIALIZED_HEADER_LEN_V22);
    let metadata_size: u32 = metadata.len() as u32;
    file[0..4].copy_from_slice(&metadata_size.to_be_bytes());
    file.extend_from_slice(&metadata);

    let pad: usize =
        usize::try_from(data_offset).map_or(file.len(), |value: usize| value) - file.len();
    file.extend(std::iter::repeat_n(0u8, pad));
    file.extend_from_slice(&body);
    file
}

#[must_use]
pub fn build_bundle_uncompressed(node_path: &str, node_data: &[u8]) -> Vec<u8> {
    let mut info: Vec<u8> = Vec::new();
    info.extend_from_slice(&[0u8; BLOCKS_INFO_HASH_LEN]);
    info.extend_from_slice(&1i32.to_be_bytes());
    info.extend_from_slice(&(node_data.len() as u32).to_be_bytes());
    info.extend_from_slice(&(node_data.len() as u32).to_be_bytes());
    info.extend_from_slice(&0u16.to_be_bytes());
    info.extend_from_slice(&1i32.to_be_bytes());
    info.extend_from_slice(&0i64.to_be_bytes());
    info.extend_from_slice(&(node_data.len() as i64).to_be_bytes());
    info.extend_from_slice(&4u32.to_be_bytes());
    info.extend_from_slice(node_path.as_bytes());
    info.push(0);

    let mut header: Vec<u8> = Vec::new();
    header.extend_from_slice(UNITYFS_MAGIC);
    header.extend_from_slice(&7u32.to_be_bytes());
    header.extend_from_slice(b"5.x.x\x00");
    header.extend_from_slice(b"2021.3.0f1\x00");
    let size_pos: usize = header.len();
    header.extend_from_slice(&0i64.to_be_bytes());
    header.extend_from_slice(&(info.len() as u32).to_be_bytes());
    header.extend_from_slice(&(info.len() as u32).to_be_bytes());
    header.extend_from_slice(&0u32.to_be_bytes());

    let mut bundle: Vec<u8> = header;
    let pad: usize = align_up(bundle.len(), 16) - bundle.len();
    bundle.extend(std::iter::repeat_n(0u8, pad));
    bundle.extend_from_slice(&info);
    bundle.extend_from_slice(node_data);
    let total: i64 = bundle.len() as i64;
    bundle[size_pos..size_pos + 8].copy_from_slice(&total.to_be_bytes());
    bundle
}

struct SerializedReader<'a> {
    bytes: &'a [u8],
    pos: usize,
    little_endian: bool,
}

impl<'a> SerializedReader<'a> {
    const fn new(bytes: &'a [u8], little_endian: bool) -> Self {
        Self {
            bytes,
            pos: 0,
            little_endian,
        }
    }

    fn read_u32(&mut self) -> Option<u32> {
        let slice: &[u8] = self.bytes.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        let arr: [u8; 4] = [slice[0], slice[1], slice[2], slice[3]];
        Some(if self.little_endian {
            u32::from_le_bytes(arr)
        } else {
            u32::from_be_bytes(arr)
        })
    }

    fn read_i64(&mut self) -> Option<i64> {
        let slice: &[u8] = self.bytes.get(self.pos..self.pos + 8)?;
        self.pos += 8;
        let arr: [u8; 8] = [
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
        ];
        Some(if self.little_endian {
            i64::from_le_bytes(arr)
        } else {
            i64::from_be_bytes(arr)
        })
    }
}

fn unityfs_textasset_error(reason: &'static str) -> Error {
    Error::Decompression(format!("unityfs: serialized TextAsset {reason}"))
}

fn collect_text_assets_from_serialized(file: &[u8], out: &mut Vec<UnityTextAsset>) -> Result<()> {
    let scan: Vec<UnityTextAsset> = scan_serialized_textassets(file)?;
    out.extend(scan);
    Ok(())
}

const TEXTASSET_CLASS_ID: i32 = 49;

fn scan_serialized_textassets(file: &[u8]) -> Result<Vec<UnityTextAsset>> {
    if file.len() < 48 {
        return Err(unityfs_textasset_error("header is truncated"));
    }
    let version: u32 = u32::from_be_bytes([file[8], file[9], file[10], file[11]]);
    if version < 9 {
        return Ok(Vec::new());
    }
    let little_endian: bool = file.get(0x20).copied().map_or(0, |value: u8| value) == 0;
    let header_len: usize = if version >= 22 { 0x30 } else { 0x14 };
    let data_offset: u64 = read_data_offset(file, version, little_endian)
        .ok_or_else(|| unityfs_textasset_error("data offset is truncated"))?;
    let objects: Vec<SerializedObject> =
        parse_object_table(file, version, little_endian, header_len)
            .ok_or_else(|| unityfs_textasset_error("object table is truncated"))?;
    let mut out: Vec<UnityTextAsset> = Vec::new();
    for obj in &objects {
        if obj.class_id != TEXTASSET_CLASS_ID {
            continue;
        }
        let body_start: u64 = data_offset
            .checked_add(obj.byte_start)
            .ok_or_else(|| unityfs_textasset_error("object body offset overflowed"))?;
        let abs: usize = usize::try_from(body_start)
            .map_err(|_| unityfs_textasset_error("object body offset is too large"))?;
        let len: usize = usize::try_from(obj.byte_size)
            .map_err(|_| unityfs_textasset_error("object body size is too large"))?;
        let end: usize = abs
            .checked_add(len)
            .ok_or_else(|| unityfs_textasset_error("object body range overflowed"))?;
        let body: &[u8] = file
            .get(abs..end)
            .ok_or_else(|| unityfs_textasset_error("object body is truncated"))?;
        let asset: UnityTextAsset = parse_textasset_body(body, little_endian)
            .ok_or_else(|| unityfs_textasset_error("body is truncated"))?;
        out.push(asset);
    }
    Ok(out)
}

fn read_data_offset(file: &[u8], version: u32, little_endian: bool) -> Option<u64> {
    if version >= 22 {
        let slice: &[u8] = file.get(0x18..0x20)?;
        let arr: [u8; 8] = [
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
        ];
        Some(if little_endian {
            u64::from_le_bytes(arr)
        } else {
            u64::from_be_bytes(arr)
        })
    } else {
        let slice: &[u8] = file.get(0x0C..0x10)?;
        let arr: [u8; 4] = [slice[0], slice[1], slice[2], slice[3]];
        let value: u32 = if little_endian {
            u32::from_le_bytes(arr)
        } else {
            u32::from_be_bytes(arr)
        };
        Some(u64::from(value))
    }
}

#[derive(Debug, Clone, Copy)]
struct SerializedObject {
    class_id: i32,
    byte_start: u64,
    byte_size: u64,
}

fn parse_object_table(
    file: &[u8],
    version: u32,
    little_endian: bool,
    header_len: usize,
) -> Option<Vec<SerializedObject>> {
    let mut r: SerializedReader<'_> = SerializedReader::new(file, little_endian);
    r.pos = header_len;
    let _unity_version: String = read_cstring_at(&mut r)?;
    let _target_platform: u32 = r.read_u32()?;
    if version >= 13 {
        let _enable_type_tree: u8 = *file.get(r.pos)?;
        r.pos += 1;
    }
    let type_count: u32 = r.read_u32()?;
    if type_count > 1 << 20 {
        return None;
    }
    for _ in 0..type_count {
        skip_serialized_type(&mut r, version, file)?;
    }
    let object_count: u32 = r.read_u32()?;
    if object_count > 1 << 20 {
        return None;
    }
    let mut objects: Vec<SerializedObject> = Vec::with_capacity(object_count.min(4096) as usize);
    for _ in 0..object_count {
        if version >= 14 {
            align_serialized(&mut r, 4);
            let _path_id: i64 = r.read_i64()?;
        } else {
            let _path_id: u32 = r.read_u32()?;
        }
        let byte_start: u64 = if version >= 22 {
            let v: i64 = r.read_i64()?;
            u64::try_from(v).ok()?
        } else {
            u64::from(r.read_u32()?)
        };
        let byte_size: u64 = u64::from(r.read_u32()?);
        let type_id: i32 = r.read_u32()? as i32;
        let class_id: i32 = if version < 16 {
            let raw: u16 = read_u16(&mut r, little_endian)?;
            i32::from(raw)
        } else {
            type_id
        };
        if version < 16 {
            let _script_type: u16 = read_u16(&mut r, little_endian)?;
        }
        if version == 15 || version == 16 {
            let _stripped: u8 = *file.get(r.pos)?;
            r.pos += 1;
        }
        objects.push(SerializedObject {
            class_id,
            byte_start,
            byte_size,
        });
    }
    Some(objects)
}

fn skip_serialized_type(r: &mut SerializedReader<'_>, version: u32, file: &[u8]) -> Option<()> {
    let _class_id: i32 = r.read_u32()? as i32;
    if version >= 16 {
        let _is_stripped: u8 = *file.get(r.pos)?;
        r.pos += 1;
        let _script_type_index: u16 = read_u16(r, r.little_endian)?;
    }
    if version >= 13 {
        r.pos = r.pos.checked_add(16)?;
        if version >= 16 {
            r.pos = r.pos.checked_add(16)?;
        }
    }
    Some(())
}

fn parse_textasset_body(body: &[u8], little_endian: bool) -> Option<UnityTextAsset> {
    let mut r: SerializedReader<'_> = SerializedReader::new(body, little_endian);
    let name: String = read_aligned_string(&mut r)?;
    let script_len: u32 = r.read_u32()?;
    let len: usize = script_len as usize;
    let script: &[u8] = body.get(r.pos..r.pos.checked_add(len)?)?;
    Some(UnityTextAsset {
        name,
        script: script.to_vec(),
    })
}

fn read_aligned_string(r: &mut SerializedReader<'_>) -> Option<String> {
    let len: u32 = r.read_u32()?;
    let n: usize = len as usize;
    let slice: &[u8] = r.bytes.get(r.pos..r.pos.checked_add(n)?)?;
    r.pos += n;
    align_serialized(r, 4);
    Some(String::from_utf8_lossy(slice).into_owned())
}

fn read_cstring_at(r: &mut SerializedReader<'_>) -> Option<String> {
    let start: usize = r.pos;
    let limit: usize = (start + MAX_STRING_SCAN).min(r.bytes.len());
    let mut end: usize = start;
    while end < limit {
        if r.bytes[end] == 0 {
            let text: String = String::from_utf8_lossy(&r.bytes[start..end]).into_owned();
            r.pos = end + 1;
            return Some(text);
        }
        end += 1;
    }
    None
}

fn read_u16(r: &mut SerializedReader<'_>, little_endian: bool) -> Option<u16> {
    let slice: &[u8] = r.bytes.get(r.pos..r.pos + 2)?;
    r.pos += 2;
    let arr: [u8; 2] = [slice[0], slice[1]];
    Some(if little_endian {
        u16::from_le_bytes(arr)
    } else {
        u16::from_be_bytes(arr)
    })
}

const fn align_serialized(r: &mut SerializedReader<'_>, align: usize) {
    r.pos = align_up(r.pos, align);
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn align_up_rounds() {
        assert_eq!(align_up(0, 16), 0);
        assert_eq!(align_up(1, 16), 16);
        assert_eq!(align_up(16, 16), 16);
        assert_eq!(align_up(17, 16), 32);
    }

    #[test]
    fn compression_codes_map() {
        assert_eq!(UnityCompression::from_code(0), UnityCompression::None);
        assert_eq!(UnityCompression::from_code(1), UnityCompression::None);
        assert_eq!(UnityCompression::from_code(2), UnityCompression::Lzma);
        assert_eq!(UnityCompression::from_code(3), UnityCompression::Lz4);
        assert_eq!(UnityCompression::from_code(4), UnityCompression::Lz4Hc);
        assert_eq!(UnityCompression::from_code(9), UnityCompression::Unknown);
    }

    #[test]
    fn detect_requires_magic() {
        assert!(detect_unityfs(b"UnityFS\x00rest"));
        assert!(!detect_unityfs(b"UnityWeb\x00"));
        assert!(!detect_unityfs(b"short"));
    }

    fn lz4_compress_literal_only(input: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        let len: usize = input.len();
        let token: u8 = if len >= 0x0F { 0xF0 } else { (len as u8) << 4 };
        out.push(token);
        if len >= 0x0F {
            let mut remaining: usize = len - 0x0F;
            while remaining >= 0xFF {
                out.push(0xFF);
                remaining -= 0xFF;
            }
            out.push(remaining as u8);
        }
        out.extend_from_slice(input);
        out
    }

    fn build_blocks_info(blocks: &[(u32, u32, u16)], nodes: &[(i64, i64, u32, &str)]) -> Vec<u8> {
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&[0u8; BLOCKS_INFO_HASH_LEN]);
        info.extend_from_slice(&(blocks.len() as i32).to_be_bytes());
        for (uncompressed, compressed, flags) in blocks {
            info.extend_from_slice(&uncompressed.to_be_bytes());
            info.extend_from_slice(&compressed.to_be_bytes());
            info.extend_from_slice(&flags.to_be_bytes());
        }
        info.extend_from_slice(&(nodes.len() as i32).to_be_bytes());
        for (offset, size, flags, path) in nodes {
            info.extend_from_slice(&offset.to_be_bytes());
            info.extend_from_slice(&size.to_be_bytes());
            info.extend_from_slice(&flags.to_be_bytes());
            info.extend_from_slice(path.as_bytes());
            info.push(0);
        }
        info
    }

    fn build_bundle(
        version: u32,
        info_compression: u32,
        data_blocks: &[(Vec<u8>, u32)],
        nodes: &[(i64, i64, u32, &str)],
    ) -> Vec<u8> {
        let block_descs: Vec<(u32, u32, u16)> = data_blocks
            .iter()
            .map(|(payload, code): &(Vec<u8>, u32)| {
                let uncompressed: u32 = match *code {
                    3 => {
                        let decompressed: usize = lz4_decompressed_len(payload);
                        decompressed as u32
                    }
                    _ => payload.len() as u32,
                };
                (uncompressed, payload.len() as u32, *code as u16)
            })
            .collect();
        let info_plain: Vec<u8> = build_blocks_info(&block_descs, nodes);
        let info_stored: Vec<u8> = match info_compression {
            3 => lz4_compress_literal_only(&info_plain),
            _ => info_plain.clone(),
        };

        let mut header: Vec<u8> = Vec::new();
        header.extend_from_slice(UNITYFS_MAGIC);
        header.extend_from_slice(&version.to_be_bytes());
        header.extend_from_slice(b"5.x.x\x00");
        header.extend_from_slice(b"2021.3.0f1\x00");
        let size_pos: usize = header.len();
        header.extend_from_slice(&0i64.to_be_bytes());
        header.extend_from_slice(&(info_stored.len() as u32).to_be_bytes());
        header.extend_from_slice(&(info_plain.len() as u32).to_be_bytes());
        header.extend_from_slice(&info_compression.to_be_bytes());

        let mut bundle: Vec<u8> = header;
        if version >= 7 {
            let pad: usize = align_up(bundle.len(), 16) - bundle.len();
            bundle.extend(std::iter::repeat_n(0u8, pad));
        }
        bundle.extend_from_slice(&info_stored);
        for (payload, _code) in data_blocks {
            bundle.extend_from_slice(payload);
        }
        let total: i64 = bundle.len() as i64;
        bundle[size_pos..size_pos + 8].copy_from_slice(&total.to_be_bytes());
        bundle
    }

    fn lz4_decompressed_len(payload: &[u8]) -> usize {
        let token: u8 = payload[0];
        let mut literal_len: usize = (token >> 4) as usize;
        let mut ip: usize = 1;
        if literal_len == 0x0F {
            loop {
                let b: u8 = payload[ip];
                ip += 1;
                literal_len += b as usize;
                if b != 0xFF {
                    break;
                }
            }
        }
        literal_len
    }

    #[test]
    fn round_trips_uncompressed_bundle() {
        let data: Vec<u8> = b"this is the asset blob payload".to_vec();
        let nodes: &[(i64, i64, u32, &str)] = &[(0, data.len() as i64, 4, "CAB-abcdef")];
        let bundle: Vec<u8> = build_bundle(6, 0, &[(data.clone(), 0)], nodes);

        let archive: UnityFsArchive = parse(&bundle).expect("parse bundle");
        assert_eq!(archive.header.version, 6);
        assert_eq!(archive.blocks.len(), 1);
        assert_eq!(archive.nodes.len(), 1);
        assert_eq!(archive.nodes[0].path, "CAB-abcdef");

        let extracted: Vec<UnityExtractedNode> =
            extract_nodes(&bundle, &archive, 1 << 30).expect("extract");
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn round_trips_lz4_blocks_info_and_data() {
        let data: Vec<u8> = b"compressed asset blob with repeated repeated repeated bytes".to_vec();
        let data_lz4: Vec<u8> = lz4_compress_literal_only(&data);
        let nodes: &[(i64, i64, u32, &str)] = &[(0, data.len() as i64, 4, "CAB-deadbeef")];
        let bundle: Vec<u8> = build_bundle(7, 3, &[(data_lz4, 3)], nodes);

        let archive: UnityFsArchive = parse(&bundle).expect("parse bundle");
        assert_eq!(
            archive.header.blocks_info_compression,
            UnityCompression::Lz4
        );
        assert_eq!(archive.blocks[0].compression, UnityCompression::Lz4);

        let extracted: Vec<UnityExtractedNode> =
            extract_nodes(&bundle, &archive, 1 << 30).expect("extract");
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn textasset_bundle_round_trips_through_parser() {
        let script: Vec<u8> = b"\x1bLua\x53 fake bytecode body for the text asset payload".to_vec();
        let serialized: Vec<u8> = build_serialized_textasset("payload", &script);
        assert!(is_serialized_file(&serialized));
        let bundle: Vec<u8> = build_bundle_uncompressed("CAB-roundtrip", &serialized);

        let archive: UnityFsArchive = parse(&bundle).expect("parse bundle");
        let nodes: Vec<UnityExtractedNode> =
            extract_nodes(&bundle, &archive, 1 << 30).expect("extract nodes");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].data, serialized);

        let assets: Vec<UnityTextAsset> =
            extract_text_assets(&bundle, &archive, 1 << 30).expect("extract text assets");
        assert_eq!(assets.len(), 1, "exactly one TextAsset should be recovered");
        assert_eq!(assets[0].name, "payload");
        assert_eq!(assets[0].script, script);
    }

    #[test]
    fn textasset_parser_rejects_truncated_serialized_body() {
        let script: Vec<u8> = b"\x1bLua\x53 fake bytecode body".to_vec();
        let mut serialized: Vec<u8> = build_serialized_textasset("payload", &script);
        serialized.truncate(serialized.len() - 1);
        assert!(is_serialized_file(&serialized));
        let bundle: Vec<u8> = build_bundle_uncompressed("CAB-truncated", &serialized);
        let archive: UnityFsArchive = parse(&bundle).expect("parse bundle");
        let err: Error = extract_text_assets(&bundle, &archive, 1 << 30).expect_err("must reject");
        assert!(matches!(err, Error::Decompression(message) if message.contains("object body")));
    }

    #[test]
    fn rejects_block_running_past_end() {
        let data: Vec<u8> = b"short".to_vec();
        let nodes: &[(i64, i64, u32, &str)] = &[(0, 5, 4, "CAB-x")];
        let mut bundle: Vec<u8> = build_bundle(6, 0, &[(data, 0)], nodes);
        bundle.truncate(bundle.len() - 2);
        let archive: UnityFsArchive = parse(&bundle).expect("header still parses");
        let err: Error = extract_nodes(&bundle, &archive, 1 << 30).expect_err("must reject");
        assert!(matches!(err, Error::Decompression(_)));
    }
}
