use std::io::Read as _;

use disrobe_core::codec::crc32_ieee;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::native_image::{NativeImage, parse_native_image};
use disrobe_bytes::ByteReader;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InnosetupExternalHint {
    pub tool_binary: &'static str,
    pub install_hint: &'static str,
}

#[must_use]
pub const fn innosetup_external_hint() -> InnosetupExternalHint {
    InnosetupExternalHint {
        tool_binary: "innoextract",
        install_hint: "install `innoextract` (`apt install innoextract` / `brew install innoextract` / `winget install innoextract`) and re-run; older Inno Setup data versions outside the in-tree deserializer are still served by the external `innoextract` CLI",
    }
}

const INNO_DATA_ID_PREFIX: &[u8] = b"Inno Setup Setup Data (";
const INNO_HEADER_ID_LEN: usize = 64;
const INNO_CHUNK_SIZE: usize = 4096;
const ZLIB_HEADER_BYTES: [u8; 2] = [0x78, 0x9C];
const MAX_INNO_OUTPUT: u64 = 4 * 1024 * 1024 * 1024;

const SETUP_LOADER_RESOURCE_ID: u32 = 11111;
const LEGACY_LOADER_OFFSET: usize = 0x30;
const LOADER_TABLE_LEN: usize = 64;

const LOADER_MAGIC_RDLPTS: &[u8] = b"rDlPtS";
const LOADER_MAGIC_NS5W7DT: &[u8] = b"nS5W7dT";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupLoaderOffsets {
    pub revision: u32,
    pub exe_offset: u64,
    pub exe_compressed_size: u64,
    pub exe_uncompressed_size: u64,
    pub exe_checksum: u32,
    pub header_offset: u64,
    pub data_offset: u64,
    pub table_crc_valid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InnoSetupInfo {
    pub version_string: String,
    pub version: Option<(u16, u16, u16)>,
    pub unicode: bool,
    pub data_id_offset: u64,
    pub block_stream_offset: u64,
    pub compression: InnoCompression,
    pub stored_size: u32,
    pub loader: Option<SetupLoaderOffsets>,
}

fn parse_inno_version(version_string: &str) -> (Option<(u16, u16, u16)>, bool) {
    let unicode: bool = version_string.contains("(u)") || version_string.ends_with("(u)");
    let open: Option<usize> = version_string.find('(');
    let close: Option<usize> = version_string.find(')');
    let triple: Option<(u16, u16, u16)> = match (open, close) {
        (Some(o), Some(c)) if c > o + 1 => {
            let inner: &str = &version_string[o + 1..c];
            let digits: String = inner
                .chars()
                .map(|ch: char| {
                    if ch == '.' {
                        '.'
                    } else if ch.is_ascii_digit() {
                        ch
                    } else {
                        ' '
                    }
                })
                .collect();
            let parts: Vec<u16> = digits
                .split('.')
                .filter_map(|p: &str| p.trim().parse::<u16>().ok())
                .collect();
            match parts.as_slice() {
                [a, b, c, ..] => Some((*a, *b, *c)),
                [a, b] => Some((*a, *b, 0)),
                _ => None,
            }
        }
        _ => None,
    };
    (triple, unicode)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InnoCompression {
    Stored,
    Zlib,
    Lzma1,
    Lzma2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InnoFilter {
    None,
    Instruction4108,
    Instruction5200,
    Instruction5309,
    Zlib,
}

fn inno_id_field(bytes: &[u8], id_at: usize) -> Option<String> {
    let id_block: &[u8] = bytes.get(id_at..id_at + INNO_HEADER_ID_LEN)?;
    let terminator: usize = id_block.iter().position(|b: &u8| *b == 0)?;
    if id_block[terminator..].iter().any(|b: &u8| *b != 0) {
        return None;
    }
    let version_string: String = id_block[..terminator]
        .iter()
        .map(|&b: &u8| char::from(b))
        .collect::<String>()
        .trim()
        .to_owned();
    version_string
        .starts_with("Inno Setup")
        .then_some(version_string)
}

fn inno_info_at(
    bytes: &[u8],
    id_at: usize,
    loader: Option<SetupLoaderOffsets>,
) -> Option<InnoSetupInfo> {
    let version_string: String = inno_id_field(bytes, id_at)?;
    let (version, unicode): (Option<(u16, u16, u16)>, bool) = parse_inno_version(&version_string);
    version?;
    let stream_at: usize = id_at + INNO_HEADER_ID_LEN;
    let header: &[u8] = bytes.get(stream_at..stream_at + 9)?;
    let stored_size: u32 = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    let block_at: usize = stream_at + 9;
    if block_at.checked_add(stored_size as usize)? > bytes.len() {
        return None;
    }
    let compression: InnoCompression = infer_compression(bytes, block_at, header[8]);
    Some(InnoSetupInfo {
        version_string,
        version,
        unicode,
        data_id_offset: id_at as u64,
        block_stream_offset: block_at as u64,
        compression,
        stored_size,
        loader,
    })
}

pub fn detect_innosetup(bytes: &[u8]) -> Option<InnoSetupInfo> {
    let loader: Option<SetupLoaderOffsets> = locate_setup_loader(bytes);
    if let Some(offsets) = loader
        && let Some(info) = usize::try_from(offsets.header_offset)
            .ok()
            .and_then(|at: usize| inno_info_at(bytes, at, loader))
    {
        return Some(info);
    }
    let mut from: usize = 0;
    while let Some(rest) = bytes.get(from..) {
        let offset: usize = find_subslice(rest, INNO_DATA_ID_PREFIX)?;
        let id_at: usize = from + offset;
        if let Some(info) = inno_info_at(bytes, id_at, loader) {
            return Some(info);
        }
        from = id_at + 1;
    }
    None
}

fn infer_compression(bytes: &[u8], chunk_start: usize, flag: u8) -> InnoCompression {
    let first_chunk: Option<&[u8]> = bytes.get(chunk_start + 4..chunk_start + 6);
    if let Some(prefix) = first_chunk
        && prefix == ZLIB_HEADER_BYTES
    {
        return InnoCompression::Zlib;
    }
    match flag {
        0 => InnoCompression::Stored,
        1 => InnoCompression::Zlib,
        _ => InnoCompression::Lzma1,
    }
}

fn locate_setup_loader(bytes: &[u8]) -> Option<SetupLoaderOffsets> {
    if let Some(table) = legacy_loader_table(bytes)
        && let Some(offsets) = decode_loader_table(table)
    {
        return Some(offsets);
    }
    if let Some(table) = resource_loader_table(bytes)
        && let Some(offsets) = decode_loader_table(&table)
    {
        return Some(offsets);
    }
    None
}

fn legacy_loader_table(bytes: &[u8]) -> Option<&[u8]> {
    let block: &[u8] = bytes.get(LEGACY_LOADER_OFFSET..LEGACY_LOADER_OFFSET + 12)?;
    let id: u32 = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
    let table_offset: u32 = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);
    let not_table_offset: u32 = u32::from_le_bytes([block[8], block[9], block[10], block[11]]);
    if id == 0 || table_offset != !not_table_offset {
        return None;
    }
    let at: usize = table_offset as usize;
    bytes.get(at..at + LOADER_TABLE_LEN)
}

fn decode_loader_table(table: &[u8]) -> Option<SetupLoaderOffsets> {
    if table.len() < LOADER_TABLE_LEN {
        return None;
    }
    let magic: &[u8] = &table[..12];
    let magic_ok: bool =
        magic.starts_with(LOADER_MAGIC_RDLPTS) || magic.starts_with(LOADER_MAGIC_NS5W7DT);
    if !magic_ok {
        return None;
    }
    let mut cur: ByteReader<'_> = ByteReader::new(table);
    cur.skip(12).ok()?;
    let revision: u32 = cur.read_u32_le().ok()?;
    let exe_offset: u64;
    let exe_compressed_size: u64;
    let exe_uncompressed_size: u64;
    let header_offset: u64;
    let data_offset: u64;
    if revision >= 2 {
        exe_offset = cur.read_u64_le().ok()?;
        exe_compressed_size = cur.read_u64_le().ok()?;
        exe_uncompressed_size = u64::from(cur.read_u32_le().ok()?);
        let exe_checksum: u32 = cur.read_u32_le().ok()?;
        header_offset = cur.read_u64_le().ok()?;
        data_offset = cur.read_u64_le().ok()?;
        cur.skip(4).ok()?;
        let table_crc: u32 = cur.read_u32_le().ok()?;
        let table_crc_valid: bool = crc32(&table[..60]) == table_crc;
        return Some(SetupLoaderOffsets {
            revision,
            exe_offset,
            exe_compressed_size,
            exe_uncompressed_size,
            exe_checksum,
            header_offset,
            data_offset,
            table_crc_valid,
        });
    }
    if revision >= 1 {
        cur.skip(4).ok()?;
        exe_offset = u64::from(cur.read_u32_le().ok()?);
        exe_compressed_size = u64::from(cur.read_u32_le().ok()?);
        exe_uncompressed_size = u64::from(cur.read_u32_le().ok()?);
        let exe_checksum: u32 = cur.read_u32_le().ok()?;
        header_offset = u64::from(cur.read_u32_le().ok()?);
        data_offset = u64::from(cur.read_u32_le().ok()?);
        let table_crc: u32 = cur.read_u32_le().ok()?;
        let consumed: usize = cur.position();
        let table_crc_valid: bool = consumed >= 4 && crc32(&table[..consumed - 4]) == table_crc;
        return Some(SetupLoaderOffsets {
            revision,
            exe_offset,
            exe_compressed_size,
            exe_uncompressed_size,
            exe_checksum,
            header_offset,
            data_offset,
            table_crc_valid,
        });
    }
    exe_offset = u64::from(cur.read_u32_le().ok()?);
    exe_compressed_size = u64::from(cur.read_u32_le().ok()?);
    exe_uncompressed_size = u64::from(cur.read_u32_le().ok()?);
    let exe_checksum: u32 = cur.read_u32_le().ok()?;
    cur.skip(4).ok()?;
    header_offset = u64::from(cur.read_u32_le().ok()?);
    data_offset = u64::from(cur.read_u32_le().ok()?);
    Some(SetupLoaderOffsets {
        revision,
        exe_offset,
        exe_compressed_size,
        exe_uncompressed_size,
        exe_checksum,
        header_offset,
        data_offset,
        table_crc_valid: false,
    })
}

fn resource_loader_table(bytes: &[u8]) -> Option<Vec<u8>> {
    if !bytes.starts_with(b"MZ") {
        return None;
    }
    let e_lfanew_u32: u32 = disrobe_bytes::read_u32_le_at(bytes, 0x3C).ok()?;
    let e_lfanew: usize = usize::try_from(e_lfanew_u32).ok()?;
    let signature_end: usize = e_lfanew.checked_add(4)?;
    if bytes.get(e_lfanew..signature_end)? != b"PE\0\0" {
        return None;
    }
    let coff: usize = signature_end;
    let optional_size_offset: usize = coff.checked_add(16)?;
    let optional_size: usize =
        usize::from(disrobe_bytes::read_u16_le_at(bytes, optional_size_offset).ok()?);
    let optional: usize = coff.checked_add(20)?;
    let optional_end: usize = optional.checked_add(optional_size)?;
    let magic: u16 = disrobe_bytes::read_u16_le_at(bytes, optional).ok()?;
    let data_dir_delta: usize = match magic {
        0x10B => 96,
        0x20B => 112,
        _ => return None,
    };
    let directory_count_delta: usize = data_dir_delta.checked_sub(4)?;
    let directory_count_offset: usize = optional.checked_add(directory_count_delta)?;
    let directory_count: u32 = disrobe_bytes::read_u32_le_at(bytes, directory_count_offset).ok()?;
    if directory_count <= 2 {
        return None;
    }
    let data_dir: usize = optional.checked_add(data_dir_delta)?;
    let resource_rva_offset: usize = data_dir.checked_add(16)?;
    let resource_size_offset: usize = resource_rva_offset.checked_add(4)?;
    let resource_entry_end: usize = resource_size_offset.checked_add(4)?;
    if resource_entry_end > optional_end {
        return None;
    }
    let resource_rva: u32 = disrobe_bytes::read_u32_le_at(bytes, resource_rva_offset).ok()?;
    let resource_size_u32: u32 = disrobe_bytes::read_u32_le_at(bytes, resource_size_offset).ok()?;
    let resource_size: usize = usize::try_from(resource_size_u32).ok()?;
    if resource_rva == 0 || resource_size == 0 {
        return None;
    }
    let image: NativeImage<'_> = parse_native_image(bytes).ok()?;
    let resource_address: u64 = image.virtual_address_from_relative(resource_rva)?;
    let resource: &[u8] = image.bytes_at(resource_address)?.get(..resource_size)?;
    let rcdata_dir: usize = resource_dir_subdir(resource, 0, 10)?;
    let id_dir: usize = resource_dir_subdir(resource, rcdata_dir, SETUP_LOADER_RESOURCE_ID)?;
    let lang_entry: u32 = resource_dir_first_entry(resource, id_dir)?;
    if lang_entry & 0x8000_0000 != 0 {
        return None;
    }
    let data_entry_relative: usize = usize::try_from(lang_entry).ok()?;
    let (data_rva, data_size): (u32, usize) = resource_data_entry(
        resource,
        data_entry_relative,
        resource_rva,
        resource_size_u32,
    )?;
    if data_size == 0 || data_size > 4096 {
        return None;
    }
    let data_address: u64 = image.virtual_address_from_relative(data_rva)?;
    let data: &[u8] = image.bytes_at(data_address)?;
    data.get(..data_size).map(<[u8]>::to_vec)
}

fn resource_data_entry(
    resource: &[u8],
    entry_offset: usize,
    resource_rva: u32,
    resource_size: u32,
) -> Option<(u32, usize)> {
    let entry_end: usize = entry_offset.checked_add(16)?;
    let entry: &[u8] = resource.get(entry_offset..entry_end)?;
    let data_rva: u32 = disrobe_bytes::read_u32_le_at(entry, 0).ok()?;
    let data_size_u32: u32 = disrobe_bytes::read_u32_le_at(entry, 4).ok()?;
    let reserved: u32 = disrobe_bytes::read_u32_le_at(entry, 12).ok()?;
    if reserved != 0 {
        return None;
    }
    let resource_end: u32 = resource_rva.checked_add(resource_size)?;
    let data_end: u32 = data_rva.checked_add(data_size_u32)?;
    if data_rva < resource_rva || data_end > resource_end {
        return None;
    }
    let data_size: usize = usize::try_from(data_size_u32).ok()?;
    Some((data_rva, data_size))
}

fn resource_dir_subdir(bytes: &[u8], dir_off: usize, want_id: u32) -> Option<usize> {
    let named_offset: usize = dir_off.checked_add(12)?;
    let ids_offset: usize = dir_off.checked_add(14)?;
    let named: u16 = disrobe_bytes::read_u16_le_at(bytes, named_offset).ok()?;
    let ids: u16 = disrobe_bytes::read_u16_le_at(bytes, ids_offset).ok()?;
    let total: usize = usize::from(named).checked_add(usize::from(ids))?;
    let base: usize = dir_off.checked_add(16)?;
    for i in 0..total {
        let entry_delta: usize = i.checked_mul(8)?;
        let eo: usize = base.checked_add(entry_delta)?;
        let off_offset: usize = eo.checked_add(4)?;
        let id: u32 = disrobe_bytes::read_u32_le_at(bytes, eo).ok()?;
        let off: u32 = disrobe_bytes::read_u32_le_at(bytes, off_offset).ok()?;
        if id & 0x8000_0000 != 0 {
            continue;
        }
        if id == want_id && off & 0x8000_0000 != 0 {
            let relative: usize = usize::try_from(off & 0x7FFF_FFFF).ok()?;
            return Some(relative);
        }
    }
    None
}

fn resource_dir_first_entry(bytes: &[u8], dir_off: usize) -> Option<u32> {
    let named_offset: usize = dir_off.checked_add(12)?;
    let ids_offset: usize = dir_off.checked_add(14)?;
    let named: u16 = disrobe_bytes::read_u16_le_at(bytes, named_offset).ok()?;
    let ids: u16 = disrobe_bytes::read_u16_le_at(bytes, ids_offset).ok()?;
    let total: usize = usize::from(named).checked_add(usize::from(ids))?;
    if total == 0 {
        return None;
    }
    let eo: usize = dir_off.checked_add(16)?;
    let off_offset: usize = eo.checked_add(4)?;
    disrobe_bytes::read_u32_le_at(bytes, off_offset).ok()
}

pub fn extract_inno_block_stream(bytes: &[u8], info: &InnoSetupInfo) -> Result<Vec<u8>> {
    let start: usize = usize::try_from(info.block_stream_offset)
        .map_err(|_e: std::num::TryFromIntError| inno_err("block stream offset overflow"))?;
    let compressed: Vec<u8> = read_crc_framed_chunks(bytes, start)?;
    match info.compression {
        InnoCompression::Stored => Ok(compressed),
        InnoCompression::Zlib => inflate_zlib(&compressed),
        InnoCompression::Lzma1 | InnoCompression::Lzma2 => Err(inno_err(
            "inno lzma setup-data block reader differs by data version; the version-gated header framing for this build is not decoded in-tree (file content is still carved from the data area)",
        )),
    }
}

fn read_crc_framed_chunks(bytes: &[u8], start: usize) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let mut pos: usize = start;
    while pos + 4 <= bytes.len() {
        let expected_crc: u32 =
            u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
        pos += 4;
        let remaining: usize = bytes.len() - pos;
        let chunk_len: usize = remaining.min(INNO_CHUNK_SIZE);
        if chunk_len == 0 {
            break;
        }
        let chunk: &[u8] = &bytes[pos..pos + chunk_len];
        let actual_crc: u32 = crc32(chunk);
        if actual_crc != expected_crc {
            if out.is_empty() {
                return Err(inno_err(
                    "inno block-stream chunk CRC32 mismatch at first chunk (not a CRC-framed inno block stream)",
                ));
            }
            break;
        }
        out.extend_from_slice(chunk);
        pos += chunk_len;
        if out.len() as u64 > MAX_INNO_OUTPUT {
            break;
        }
        if chunk_len < INNO_CHUNK_SIZE {
            break;
        }
    }
    if out.is_empty() {
        return Err(inno_err("inno block stream produced no validated chunks"));
    }
    Ok(out)
}

fn inflate_zlib(input: &[u8]) -> Result<Vec<u8>> {
    let mut decoder: flate2::read::ZlibDecoder<&[u8]> = flate2::read::ZlibDecoder::new(input);
    let mut out: Vec<u8> = Vec::new();
    decoder
        .by_ref()
        .take(MAX_INNO_OUTPUT + 1)
        .read_to_end(&mut out)
        .map_err(|e: std::io::Error| Error::InnoSetup(format!("inno zlib inflate: {e}")))?;
    Ok(out)
}

const INNO_CHUNK_MAGIC: [u8; 4] = [b'z', b'l', b'b', 0x1a];

#[derive(Debug, Clone)]
pub struct InnoFileChunk {
    pub offset: u64,
    pub compression: InnoCompression,
    pub data: Vec<u8>,
}

#[must_use]
pub fn data_area_start(bytes: &[u8], info: &InnoSetupInfo) -> usize {
    if let Some(loader) = info.loader
        && (loader.data_offset as usize) < bytes.len()
        && bytes
            .get(loader.data_offset as usize..loader.data_offset as usize + INNO_CHUNK_MAGIC.len())
            .is_some_and(|w: &[u8]| w == INNO_CHUNK_MAGIC)
    {
        return loader.data_offset as usize;
    }
    let header_end: usize =
        usize::try_from(info.block_stream_offset).map_or(bytes.len(), |value: usize| value);
    let consumed: usize = read_crc_framed_chunks(bytes, header_end)
        .map_or(header_end, |chunks: Vec<u8>| {
            crc_framed_consumed(bytes, header_end, chunks.len())
        });
    consumed.min(bytes.len())
}

fn crc_framed_consumed(bytes: &[u8], start: usize, payload_len: usize) -> usize {
    let full_chunks: usize = payload_len / INNO_CHUNK_SIZE;
    let remainder: usize = payload_len % INNO_CHUNK_SIZE;
    let mut consumed: usize = start;
    for _ in 0..full_chunks {
        consumed += 4 + INNO_CHUNK_SIZE;
    }
    if remainder != 0 {
        consumed += 4 + remainder;
    }
    consumed.min(bytes.len())
}

pub fn extract_inno_file_chunks(
    bytes: &[u8],
    info: &InnoSetupInfo,
    max_total: u64,
) -> Vec<InnoFileChunk> {
    let scan_floor: usize = data_area_start(bytes, info);
    let mut chunks: Vec<InnoFileChunk> = Vec::new();
    let mut pos: usize = scan_floor;
    let mut total: u64 = 0;
    while let Some(rel) = find_subslice(&bytes[pos..], &INNO_CHUNK_MAGIC) {
        let chunk_start: usize = pos + rel + INNO_CHUNK_MAGIC.len();
        let Some(body) = bytes.get(chunk_start..) else {
            break;
        };
        let next_magic: usize =
            find_subslice(body, &INNO_CHUNK_MAGIC).map_or(body.len(), |rel: usize| rel);
        let budget: u64 = max_total.saturating_sub(total);
        let Some((decoded, consumed, compression)) = decode_inno_chunk(body, next_magic, budget)
        else {
            pos = chunk_start + next_magic.max(1);
            continue;
        };
        if decoded.is_empty() {
            pos = chunk_start + next_magic.max(1);
            continue;
        }
        total = total.saturating_add(decoded.len() as u64);
        chunks.push(InnoFileChunk {
            offset: chunk_start as u64,
            compression,
            data: decoded,
        });
        pos = chunk_start + consumed.max(1);
        if total >= max_total {
            break;
        }
    }
    chunks
}

fn decode_inno_chunk(
    body: &[u8],
    bound: usize,
    budget: u64,
) -> Option<(Vec<u8>, usize, InnoCompression)> {
    if body.len() >= 2
        && body[0] == 0x78
        && (u16::from(body[0]) * 256 + u16::from(body[1])) % 31 == 0
        && let Ok((out, consumed)) = inflate_zlib_stream(body, budget)
    {
        return Some((out, consumed, InnoCompression::Zlib));
    }
    let span: &[u8] = body.get(..bound).map_or(body, |value: &[u8]| value);
    if let Some((out, consumed)) = decode_lzma1_chunk(span, budget) {
        return Some((out, consumed, InnoCompression::Lzma1));
    }
    if let Some((out, consumed)) = decode_lzma2_chunk(span, budget) {
        return Some((out, consumed, InnoCompression::Lzma2));
    }
    if bound > 0 && (bound as u64) <= budget.min(MAX_INNO_OUTPUT) {
        return Some((span.to_vec(), bound, InnoCompression::Stored));
    }
    None
}

fn inflate_zlib_stream(input: &[u8], budget: u64) -> Result<(Vec<u8>, usize)> {
    let mut decoder: flate2::read::ZlibDecoder<&[u8]> = flate2::read::ZlibDecoder::new(input);
    let mut out: Vec<u8> = Vec::new();
    let cap: u64 = budget.min(MAX_INNO_OUTPUT);
    decoder
        .by_ref()
        .take(cap + 1)
        .read_to_end(&mut out)
        .map_err(|e: std::io::Error| Error::InnoSetup(format!("inno chunk inflate: {e}")))?;
    if out.len() as u64 > cap {
        return Err(inno_err("inno data chunk exceeds budget"));
    }
    let consumed: usize = decoder.total_in() as usize;
    Ok((out, consumed))
}

fn decode_lzma1_chunk(body: &[u8], budget: u64) -> Option<(Vec<u8>, usize)> {
    let props: &[u8] = body.get(..5)?;
    if props[0] >= 9 * 5 * 5 {
        return None;
    }
    let stream: &[u8] = body.get(5..)?;
    let out: Vec<u8> = raw_lzma_decode(props, stream, budget, true)?;
    Some((out, body.len()))
}

fn decode_lzma2_chunk(body: &[u8], budget: u64) -> Option<(Vec<u8>, usize)> {
    let prop: u8 = *body.first()?;
    if prop > 40 {
        return None;
    }
    let stream: &[u8] = body.get(1..)?;
    let out: Vec<u8> = raw_lzma_decode(&[prop], stream, budget, false)?;
    Some((out, body.len()))
}

fn raw_lzma_decode(props: &[u8], stream: &[u8], budget: u64, lzma1: bool) -> Option<Vec<u8>> {
    let mut filters: liblzma::stream::Filters = liblzma::stream::Filters::new();
    let prepared: std::result::Result<&mut liblzma::stream::Filters, liblzma::stream::Error> =
        if lzma1 {
            filters.lzma1_properties(props)
        } else {
            filters.lzma2_properties(props)
        };
    prepared.ok()?;
    let decoder: liblzma::stream::Stream =
        liblzma::stream::Stream::new_raw_decoder(&filters).ok()?;
    let mut reader: liblzma::read::XzDecoder<&[u8]> =
        liblzma::read::XzDecoder::new_stream(stream, decoder);
    let cap: u64 = budget.min(MAX_INNO_OUTPUT);
    let mut out: Vec<u8> = Vec::new();
    match reader.by_ref().take(cap + 1).read_to_end(&mut out) {
        Ok(_) => {}
        Err(_e) if !out.is_empty() => {}
        Err(_e) => return None,
    }
    if out.is_empty() || out.len() as u64 > cap {
        return None;
    }
    Some(out)
}

#[must_use]
pub fn unfilter_instructions(data: &[u8], filter: InnoFilter) -> Vec<u8> {
    match filter {
        InnoFilter::None | InnoFilter::Zlib => data.to_vec(),
        InnoFilter::Instruction4108 | InnoFilter::Instruction5200 | InnoFilter::Instruction5309 => {
            bcj_x86_decode(data)
        }
    }
}

fn bcj_x86_decode(data: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = data.to_vec();
    if out.len() < 5 {
        return out;
    }
    let mut i: usize = 0;
    let last: usize = out.len() - 5;
    while i <= last {
        let op: u8 = out[i];
        if op != 0xE8 && op != 0xE9 {
            i += 1;
            continue;
        }
        let rel: u32 = u32::from_le_bytes([out[i + 1], out[i + 2], out[i + 3], out[i + 4]]);
        let addr: u32 = (i as u32).wrapping_add(5);
        let abs: u32 = rel.wrapping_sub(addr);
        let bytes: [u8; 4] = abs.to_le_bytes();
        out[i + 1] = bytes[0];
        out[i + 2] = bytes[1];
        out[i + 3] = bytes[2];
        out[i + 4] = bytes[3];
        i += 5;
    }
    out
}

fn crc32(data: &[u8]) -> u32 {
    crc32_ieee(data)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let first: u8 = needle[0];
    let mut from: usize = 0;
    while let Some(rel) = haystack[from..].iter().position(|&b: &u8| b == first) {
        let at: usize = from + rel;
        if haystack[at..].starts_with(needle) {
            return Some(at);
        }
        from = at + 1;
    }
    None
}

#[inline]
fn inno_err(msg: &'static str) -> Error {
    Error::InnoSetup(msg.to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const ZLIB_TABLE: &[u8] = include_bytes!("../../tests/fixtures/innosetup/real6_zlib.table");
    const ZLIB_CHUNKS: &[u8] = include_bytes!("../../tests/fixtures/innosetup/real6_zlib.chunks");
    const LZMA1_TABLE: &[u8] = include_bytes!("../../tests/fixtures/innosetup/real6_lzma1.table");
    const LZMA1_CHUNKS: &[u8] = include_bytes!("../../tests/fixtures/innosetup/real6_lzma1.chunks");
    const LZMA2_TABLE: &[u8] = include_bytes!("../../tests/fixtures/innosetup/real6_lzma2.table");
    const LZMA2_CHUNKS: &[u8] = include_bytes!("../../tests/fixtures/innosetup/real6_lzma2.chunks");
    const STORED_TABLE: &[u8] = include_bytes!("../../tests/fixtures/innosetup/real6_stored.table");
    const STORED_CHUNKS: &[u8] =
        include_bytes!("../../tests/fixtures/innosetup/real6_stored.chunks");

    const ORIG_APP: &[u8] = include_bytes!("../../tests/fixtures/innosetup/orig_app.py");
    const ORIG_UTIL: &[u8] = include_bytes!("../../tests/fixtures/innosetup/orig_util.py");
    const ORIG_README: &[u8] = include_bytes!("../../tests/fixtures/innosetup/orig_readme.txt");
    const ORIG_DATA: &[u8] = include_bytes!("../../tests/fixtures/innosetup/orig_data.bin");

    fn originals() -> [&'static [u8]; 4] {
        [ORIG_APP, ORIG_UTIL, ORIG_README, ORIG_DATA]
    }

    #[test]
    fn hint_points_to_innoextract() {
        assert_eq!(innosetup_external_hint().tool_binary, "innoextract");
    }

    #[test]
    fn traverses_real_pe_resources_without_fabricating_loader_data() {
        let bytes: &[u8] = include_bytes!("../../../../corpus/dotnet/cff/DecryptSample.exe");
        let image: NativeImage<'_> =
            parse_native_image(bytes).expect("real resource pe should parse");
        let resource_address: u64 = image
            .virtual_address_from_relative(0x4000)
            .expect("resource address should fit");
        let resource: &[u8] = image
            .bytes_at(resource_address)
            .expect("resource directory should be file-backed");
        let root_id_count: u16 =
            disrobe_bytes::read_u16_le_at(resource, 14).expect("resource root should parse");

        assert_eq!(root_id_count, 2);
        assert!(resource_dir_subdir(resource, 0, 16).is_some());
        assert!(resource_dir_subdir(resource, 0, 24).is_some());
        assert!(resource_loader_table(bytes).is_none());
    }

    fn resource_entry(data_rva: u32, data_size: u32, reserved: u32) -> [u8; 16] {
        let mut entry: [u8; 16] = [0; 16];
        let data_rva_field: &mut [u8] = entry
            .get_mut(0..4)
            .expect("resource data rva field should exist");
        data_rva_field.copy_from_slice(&data_rva.to_le_bytes());
        let data_size_field: &mut [u8] = entry
            .get_mut(4..8)
            .expect("resource data size field should exist");
        data_size_field.copy_from_slice(&data_size.to_le_bytes());
        let reserved_field: &mut [u8] = entry
            .get_mut(12..16)
            .expect("resource reserved field should exist");
        reserved_field.copy_from_slice(&reserved.to_le_bytes());
        entry
    }

    #[test]
    fn resource_data_entry_requires_complete_valid_leaf() {
        let valid: [u8; 16] = resource_entry(0x4040, 0x20, 0);
        let truncated: &[u8] = valid
            .get(..15)
            .expect("truncated resource entry range should exist");
        let reserved: [u8; 16] = resource_entry(0x4040, 0x20, 1);
        let outside: [u8; 16] = resource_entry(0x4100, 1, 0);

        assert_eq!(
            resource_data_entry(&valid, 0, 0x4000, 0x100),
            Some((0x4040, 0x20))
        );
        assert!(resource_data_entry(truncated, 0, 0x4000, 0x100).is_none());
        assert!(resource_data_entry(&reserved, 0, 0x4000, 0x100).is_none());
        assert!(resource_data_entry(&outside, 0, 0x4000, 0x100).is_none());
    }

    #[test]
    fn parses_inno_version_triples() {
        assert_eq!(
            parse_inno_version("Inno Setup Setup Data (5.6.1)"),
            (Some((5, 6, 1)), false)
        );
        assert_eq!(
            parse_inno_version("Inno Setup Setup Data (6.2.0) (u)"),
            (Some((6, 2, 0)), true)
        );
        assert_eq!(
            parse_inno_version("Inno Setup Setup Data (4.0)"),
            (Some((4, 0, 0)), false)
        );
        assert_eq!(parse_inno_version("garbage no parens"), (None, false));
    }

    #[test]
    fn decodes_real_setup_loader_table_with_valid_crc() {
        for table in [ZLIB_TABLE, LZMA1_TABLE, LZMA2_TABLE, STORED_TABLE] {
            let offsets: SetupLoaderOffsets =
                decode_loader_table(table).expect("decode loader table");
            assert_eq!(offsets.revision, 2);
            assert!(
                offsets.table_crc_valid,
                "table_crc must validate over the real loader table"
            );
            assert!(offsets.data_offset > 0);
            assert!(offsets.header_offset > 0);
            assert!(offsets.exe_offset > 0);
        }
    }

    #[test]
    fn rejects_garbage_loader_table() {
        let table: [u8; 64] = [0u8; 64];
        assert!(decode_loader_table(&table).is_none());
    }

    fn carve(chunks_bytes: &[u8]) -> Vec<Vec<u8>> {
        let info: InnoSetupInfo = InnoSetupInfo {
            version_string: "Inno Setup Setup Data (6.7.0)".to_owned(),
            version: Some((6, 7, 0)),
            unicode: false,
            data_id_offset: 0,
            block_stream_offset: 0,
            compression: InnoCompression::Zlib,
            stored_size: 0,
            loader: None,
        };
        let mut info: InnoSetupInfo = info;
        info.loader = Some(SetupLoaderOffsets {
            revision: 2,
            exe_offset: 1,
            exe_compressed_size: 1,
            exe_uncompressed_size: 1,
            exe_checksum: 0,
            header_offset: 1,
            data_offset: 0,
            table_crc_valid: true,
        });
        extract_inno_file_chunks(chunks_bytes, &info, 64 * 1024 * 1024)
            .into_iter()
            .map(|c: InnoFileChunk| c.data)
            .collect()
    }

    fn assert_all_originals_recovered(bodies: &[Vec<u8>]) {
        let solid: Vec<u8> = bodies.iter().flatten().copied().collect();
        for orig in originals() {
            let separate: bool = bodies.iter().any(|b: &Vec<u8>| b.as_slice() == orig);
            let in_solid: bool = solid.windows(orig.len()).any(|w: &[u8]| w == orig);
            assert!(
                separate || in_solid,
                "original ({} bytes) must be byte-exact in carved output",
                orig.len()
            );
        }
    }

    #[test]
    fn carves_zlib_installer_byte_exact_per_file() {
        let bodies: Vec<Vec<u8>> = carve(ZLIB_CHUNKS);
        assert!(bodies.iter().any(|b: &Vec<u8>| b.as_slice() == ORIG_APP));
        assert!(bodies.iter().any(|b: &Vec<u8>| b.as_slice() == ORIG_UTIL));
        assert!(bodies.iter().any(|b: &Vec<u8>| b.as_slice() == ORIG_README));
        assert!(bodies.iter().any(|b: &Vec<u8>| b.as_slice() == ORIG_DATA));
    }

    #[test]
    fn carves_stored_installer_byte_exact_per_file() {
        let bodies: Vec<Vec<u8>> = carve(STORED_CHUNKS);
        assert_all_originals_recovered(&bodies);
    }

    #[test]
    fn carves_lzma1_solid_chunk_recovers_all_originals() {
        let bodies: Vec<Vec<u8>> = carve(LZMA1_CHUNKS);
        assert!(!bodies.is_empty());
        assert_all_originals_recovered(&bodies);
    }

    #[test]
    fn carves_lzma2_solid_chunk_recovers_all_originals() {
        let bodies: Vec<Vec<u8>> = carve(LZMA2_CHUNKS);
        assert!(!bodies.is_empty());
        assert_all_originals_recovered(&bodies);
    }

    #[test]
    fn bcj_unfilter_is_involutive_with_encoder() {
        let original: Vec<u8> = vec![
            0xE8, 0x10, 0x20, 0x30, 0x40, 0x90, 0xE9, 0x00, 0x01, 0x00, 0x00, 0x55, 0x8B, 0xEC,
        ];
        let mut encoded: Vec<u8> = original.clone();
        let mut i: usize = 0;
        let last: usize = encoded.len() - 5;
        while i <= last {
            if encoded[i] == 0xE8 || encoded[i] == 0xE9 {
                let abs: u32 = u32::from_le_bytes([
                    encoded[i + 1],
                    encoded[i + 2],
                    encoded[i + 3],
                    encoded[i + 4],
                ]);
                let addr: u32 = (i as u32).wrapping_add(5);
                let rel: [u8; 4] = abs.wrapping_add(addr).to_le_bytes();
                encoded[i + 1] = rel[0];
                encoded[i + 2] = rel[1];
                encoded[i + 3] = rel[2];
                encoded[i + 4] = rel[3];
                i += 5;
            } else {
                i += 1;
            }
        }
        let decoded: Vec<u8> = unfilter_instructions(&encoded, InnoFilter::Instruction5309);
        assert_eq!(decoded, original);
    }

    #[test]
    fn rejects_non_inno() {
        let bytes: Vec<u8> = vec![0u8; 4096];
        assert!(detect_innosetup(&bytes).is_none());
    }

    fn zlib_compress(input: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut enc: flate2::write::ZlibEncoder<Vec<u8>> =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(input).expect("zlib write");
        enc.finish().expect("zlib finish")
    }

    fn build_test_inno(version: &str, setup_blob: &[u8]) -> Vec<u8> {
        let compressed: Vec<u8> = zlib_compress(setup_blob);
        let mut out: Vec<u8> = b"MZ".to_vec();
        out.extend(std::iter::repeat_n(0u8, 256));
        let mut id: Vec<u8> = format!("Inno Setup Setup Data ({version})").into_bytes();
        id.resize(INNO_HEADER_ID_LEN, 0);
        out.extend_from_slice(&id);
        out.extend_from_slice(&crc32(&id[..4]).to_le_bytes());
        out.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        out.push(1);
        for chunk in compressed.chunks(INNO_CHUNK_SIZE) {
            out.extend_from_slice(&crc32(chunk).to_le_bytes());
            out.extend_from_slice(chunk);
        }
        out
    }

    #[test]
    fn detects_and_decodes_zlib_block_stream() {
        let blob: &[u8] = &b"Inno setup header payload recovered verbatim ".repeat(40);
        let image: Vec<u8> = build_test_inno("6.2.0", blob);
        let info: InnoSetupInfo = detect_innosetup(&image).expect("detect inno");
        assert!(info.version_string.contains("6.2.0"));
        assert_eq!(info.compression, InnoCompression::Zlib);
        let recovered: Vec<u8> = extract_inno_block_stream(&image, &info).expect("decode stream");
        assert_eq!(recovered, blob);
    }

    #[test]
    fn extract_to_writes_decoded_header_blob() {
        let blob: &[u8] = &b"inno end-to-end setup-data stream 0xCAFEBABE ".repeat(30);
        let image: Vec<u8> = build_test_inno("6.3.0", blob);
        let dir: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("binfmt-inno-e2e")
                .expect("create scratch dir");
        let result: crate::extract::ExtractionResult = crate::extract::extract_to(
            crate::container::ContainerKind::InnoSetup,
            &image,
            dir.path(),
        )
        .expect("inno extract");
        assert_eq!(result.kind, crate::container::ContainerKind::InnoSetup);
        assert_eq!(
            std::fs::read(dir.path().join("setup-headers.bin")).expect("header blob"),
            blob
        );
    }
}
