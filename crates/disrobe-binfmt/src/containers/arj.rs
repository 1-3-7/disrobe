use std::collections::BTreeSet;

use disrobe_core::codec::crc32_ieee;

use crate::error::{Error, Result};

pub const ARJ_MAGIC: &[u8; 2] = &[0x60, 0xEA];

const MIN_FIRST_HDR_SIZE: usize = 30;
const MAX_BASIC_HEADER: usize = 2600;
const MAX_EXT_HEADER_BLOCKS: usize = 256;
const MAX_EXT_HEADER_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_MAX_ENTRIES: usize = 100_000;

const FLAG_GARBLED: u8 = 0x01;
const FLAG_VOLUME: u8 = 0x04;
const FLAG_EXTFILE: u8 = 0x08;

const FILE_TYPE_COMMENT: u8 = 2;
const FILE_TYPE_DIRECTORY: u8 = 3;

const OFS_FIRST_HDR_SIZE: usize = 0;
const OFS_ARCHIVER_VERSION: usize = 1;
const OFS_MIN_VERSION: usize = 2;
const OFS_HOST_OS: usize = 3;
const OFS_FLAGS: usize = 4;
const OFS_METHOD: usize = 5;
const OFS_FILE_TYPE: usize = 6;
const OFS_COMPRESSED: usize = 12;
const OFS_ORIGINAL: usize = 16;
const OFS_CRC: usize = 20;

const METHOD_STORED: u8 = 0;
const METHOD_FASTEST: u8 = 4;

const F_THRESHOLD: usize = 3;
const F_LEN_STOP_WIDTH: u32 = 7;
const F_PTR_START_WIDTH: u32 = 9;
const F_PTR_STOP_WIDTH: u32 = 13;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArjEntry {
    pub name: String,
    pub method: u8,
    pub host_os: u8,
    pub archiver_version: u8,
    pub min_version: u8,
    pub file_type: u8,
    pub is_directory: bool,
    pub encrypted: bool,
    pub split: bool,
    pub compressed_size: u32,
    pub original_size: u32,
    pub crc32: u32,
    pub data_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArjArchive {
    pub name: String,
    pub archiver_version: u8,
    pub min_version: u8,
    pub host_os: u8,
    pub multivolume: bool,
    pub entries: Vec<ArjEntry>,
}

#[must_use]
pub fn detect_arj(bytes: &[u8]) -> bool {
    let Ok(basic_size) = basic_header_size(bytes, 0) else {
        return false;
    };
    let Some(block): Option<&[u8]> = bytes.get(4..4 + basic_size) else {
        return false;
    };
    let Some(&first_hdr_size) = block.get(OFS_FIRST_HDR_SIZE) else {
        return false;
    };
    if usize::from(first_hdr_size) < MIN_FIRST_HDR_SIZE || usize::from(first_hdr_size) > block.len()
    {
        return false;
    }
    block.get(OFS_FILE_TYPE) == Some(&FILE_TYPE_COMMENT)
}

fn basic_header_size(bytes: &[u8], at: usize) -> Result<usize> {
    let head: &[u8] = bytes
        .get(at..at.saturating_add(4))
        .ok_or_else(|| Error::Arj("arj: truncated block header".to_owned()))?;
    if &head[..2] != ARJ_MAGIC {
        return Err(Error::Arj("arj: missing 0x60 0xEA header id".to_owned()));
    }
    let basic_size: usize = usize::from(u16::from_le_bytes([head[2], head[3]]));
    if basic_size == 0 {
        return Ok(0);
    }
    if !(MIN_FIRST_HDR_SIZE..=MAX_BASIC_HEADER).contains(&basic_size) {
        return Err(Error::Arj(format!(
            "arj: basic header size {basic_size} outside the {MIN_FIRST_HDR_SIZE}..={MAX_BASIC_HEADER} range"
        )));
    }
    Ok(basic_size)
}

fn read_u32_at(block: &[u8], at: usize) -> Result<u32> {
    disrobe_bytes::read_u32_le_at(block, at)
        .map_err(|_| Error::Arj("arj: truncated basic header field".to_owned()))
}

struct RawBlock {
    block: Vec<u8>,
    next: usize,
}

fn read_block(bytes: &[u8], at: usize) -> Result<Option<RawBlock>> {
    let basic_size: usize = basic_header_size(bytes, at)?;
    if basic_size == 0 {
        return Ok(None);
    }
    let block_start: usize = at + 4;
    let block_end: usize = block_start
        .checked_add(basic_size)
        .ok_or_else(|| Error::Arj("arj: basic header size overflow".to_owned()))?;
    let block: &[u8] = bytes
        .get(block_start..block_end)
        .ok_or_else(|| Error::Arj("arj: basic header runs past end of input".to_owned()))?;
    let declared: u32 = read_u32_at(bytes, block_end)?;
    let computed: u32 = crc32_ieee(block);
    if declared != computed {
        return Err(Error::Arj(format!(
            "arj: basic header crc32 mismatch at offset {at}: stored 0x{declared:08x}, computed 0x{computed:08x}"
        )));
    }
    let mut cursor: usize = block_end + 4;
    let mut ext_blocks: usize = 0;
    let mut ext_bytes: usize = 0;
    loop {
        let size_field: &[u8] = bytes
            .get(cursor..cursor.saturating_add(2))
            .ok_or_else(|| Error::Arj("arj: truncated extended header size".to_owned()))?;
        let ext_size: usize = usize::from(u16::from_le_bytes([size_field[0], size_field[1]]));
        cursor += 2;
        if ext_size == 0 {
            break;
        }
        ext_blocks += 1;
        if ext_blocks > MAX_EXT_HEADER_BLOCKS {
            return Err(Error::Arj(format!(
                "arj: extended header chain exceeds {MAX_EXT_HEADER_BLOCKS} blocks"
            )));
        }
        ext_bytes = ext_bytes
            .checked_add(ext_size)
            .ok_or_else(|| Error::Arj("arj: extended header size overflow".to_owned()))?;
        if ext_bytes > MAX_EXT_HEADER_BYTES {
            return Err(Error::Arj(format!(
                "arj: extended header chain exceeds {MAX_EXT_HEADER_BYTES} bytes"
            )));
        }
        let ext_end: usize = cursor
            .checked_add(ext_size)
            .ok_or_else(|| Error::Arj("arj: extended header extent overflow".to_owned()))?;
        let payload: &[u8] = bytes
            .get(cursor..ext_end)
            .ok_or_else(|| Error::Arj("arj: extended header runs past end of input".to_owned()))?;
        let declared_ext: u32 = read_u32_at(bytes, ext_end)?;
        let computed_ext: u32 = crc32_ieee(payload);
        if declared_ext != computed_ext {
            return Err(Error::Arj(format!(
                "arj: extended header crc32 mismatch at offset {cursor}: stored 0x{declared_ext:08x}, computed 0x{computed_ext:08x}"
            )));
        }
        cursor = ext_end
            .checked_add(4)
            .ok_or_else(|| Error::Arj("arj: extended header extent overflow".to_owned()))?;
    }
    Ok(Some(RawBlock {
        block: block.to_vec(),
        next: cursor,
    }))
}

fn header_name(block: &[u8]) -> Result<String> {
    let first_hdr_size: usize = usize::from(
        *block
            .get(OFS_FIRST_HDR_SIZE)
            .ok_or_else(|| Error::Arj("arj: empty basic header".to_owned()))?,
    );
    if first_hdr_size < MIN_FIRST_HDR_SIZE {
        return Err(Error::Arj(format!(
            "arj: first header size {first_hdr_size} below the {MIN_FIRST_HDR_SIZE}-byte minimum"
        )));
    }
    let tail: &[u8] = block.get(first_hdr_size..).ok_or_else(|| {
        Error::Arj(format!(
            "arj: first header size {first_hdr_size} exceeds the {}-byte basic header",
            block.len()
        ))
    })?;
    let end: usize = tail
        .iter()
        .position(|&byte: &u8| byte == 0)
        .ok_or_else(|| Error::Arj("arj: unterminated header name".to_owned()))?;
    Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
}

pub fn parse_arj(bytes: &[u8]) -> Result<ArjArchive> {
    parse_arj_with_entry_limit(bytes, DEFAULT_MAX_ENTRIES)
}

pub fn parse_arj_with_entry_limit(bytes: &[u8], max_entries: usize) -> Result<ArjArchive> {
    if !detect_arj(bytes) {
        return Err(Error::Arj(
            "arj: input does not open with an ARJ main header".to_owned(),
        ));
    }
    let main: RawBlock = read_block(bytes, 0)?
        .ok_or_else(|| Error::Arj("arj: input opens with an end-of-archive marker".to_owned()))?;
    let main_flags: u8 = block_byte(&main.block, OFS_FLAGS)?;
    let name: String = header_name(&main.block)?;
    let archiver_version: u8 = block_byte(&main.block, OFS_ARCHIVER_VERSION)?;
    let min_version: u8 = block_byte(&main.block, OFS_MIN_VERSION)?;
    let host_os: u8 = block_byte(&main.block, OFS_HOST_OS)?;
    let mut entries: Vec<ArjEntry> = Vec::new();
    let mut cursor: usize = main.next;
    while let Some(local) = read_block(bytes, cursor)? {
        if entries.len() == max_entries {
            return Err(Error::Arj(format!(
                "arj: member count exceeds the {max_entries}-entry cap"
            )));
        }
        let block: &[u8] = &local.block;
        let flags: u8 = block_byte(block, OFS_FLAGS)?;
        let file_type: u8 = block_byte(block, OFS_FILE_TYPE)?;
        let compressed_size: u32 = read_u32_at(block, OFS_COMPRESSED)?;
        let original_size: u32 = read_u32_at(block, OFS_ORIGINAL)?;
        let name: String = header_name(block)?;
        let data_offset: usize = local.next;
        let data_end: usize = data_offset
            .checked_add(compressed_size as usize)
            .ok_or_else(|| Error::Arj("arj: compressed extent overflow".to_owned()))?;
        if data_end > bytes.len() {
            return Err(Error::Arj(format!(
                "arj: member `{name}` declares {compressed_size} compressed bytes at offset {data_offset}, past the {} available",
                bytes.len()
            )));
        }
        entries.push(ArjEntry {
            name,
            method: block_byte(block, OFS_METHOD)?,
            host_os: block_byte(block, OFS_HOST_OS)?,
            archiver_version: block_byte(block, OFS_ARCHIVER_VERSION)?,
            min_version: block_byte(block, OFS_MIN_VERSION)?,
            file_type,
            is_directory: file_type == FILE_TYPE_DIRECTORY,
            encrypted: flags & FLAG_GARBLED != 0,
            split: flags & FLAG_EXTFILE != 0,
            compressed_size,
            original_size,
            crc32: read_u32_at(block, OFS_CRC)?,
            data_offset,
        });
        cursor = data_end;
    }
    Ok(ArjArchive {
        name,
        archiver_version,
        min_version,
        host_os,
        multivolume: main_flags & FLAG_VOLUME != 0,
        entries,
    })
}

fn block_byte(block: &[u8], at: usize) -> Result<u8> {
    block
        .get(at)
        .copied()
        .ok_or_else(|| Error::Arj(format!("arj: basic header shorter than offset {at}")))
}

#[must_use]
pub const fn entry_is_stored(entry: &ArjEntry) -> bool {
    entry.method == METHOD_STORED
}

pub(crate) fn admit_output_path(paths: &mut BTreeSet<String>, name: &str) -> Result<()> {
    let key: String = name.to_lowercase();
    if !paths.insert(key) {
        return Err(Error::Arj(format!(
            "arj: normalized output path collision at `{name}`"
        )));
    }
    Ok(())
}

pub(crate) fn preflight_entry_quota(
    entry: &ArjEntry,
    quota: crate::quota::ExtractionQuota,
) -> Result<()> {
    let mut guard: crate::quota::QuotaGuard =
        crate::quota::QuotaGuard::new(crate::quota::ExtractionQuota {
            max_entries: 1,
            max_total_uncompressed: quota.max_per_entry_uncompressed,
            max_per_entry_uncompressed: quota.max_per_entry_uncompressed,
            max_per_entry_ratio: quota.max_per_entry_ratio,
            max_aggregate_ratio: u64::MAX,
        });
    guard.admit_entry(
        &entry.name,
        u64::from(entry.original_size),
        u64::from(entry.compressed_size),
    )
}

fn entry_raw<'a>(bytes: &'a [u8], entry: &ArjEntry) -> Result<&'a [u8]> {
    let end: usize = entry
        .data_offset
        .checked_add(entry.compressed_size as usize)
        .ok_or_else(|| Error::Arj("arj: compressed extent overflow".to_owned()))?;
    bytes
        .get(entry.data_offset..end)
        .ok_or_else(|| Error::Arj(format!("arj: member `{}` data out of bounds", entry.name)))
}

pub fn entry_bytes(bytes: &[u8], entry: &ArjEntry, max_out: u64) -> Result<Vec<u8>> {
    if entry.encrypted {
        return Err(Error::Arj(format!(
            "arj: member `{}` is password-garbled; the archive carries no key",
            entry.name
        )));
    }
    if entry.split {
        return Err(Error::Arj(format!(
            "arj: member `{}` continues across volumes; the companion volume bytes are not in this input",
            entry.name
        )));
    }
    if u64::from(entry.original_size) > max_out {
        return Err(Error::Arj(format!(
            "arj: member `{}` declares {} decompressed bytes, exceeding the per-entry extraction cap {max_out}",
            entry.name, entry.original_size
        )));
    }
    let raw: &[u8] = entry_raw(bytes, entry)?;
    let expected: usize = usize::try_from(entry.original_size)
        .map_err(|_| Error::Arj("arj: declared original size exceeds usize".to_owned()))?;
    let decoded: Vec<u8> = match entry.method {
        METHOD_STORED => {
            if entry.compressed_size != entry.original_size {
                return Err(Error::Arj(format!(
                    "arj: stored member `{}` declares {} compressed and {} original bytes",
                    entry.name, entry.compressed_size, entry.original_size
                )));
            }
            raw.to_vec()
        }
        1..=3 => crate::containers::lha_huff::decode(ARJ_LZ_PARAMS, raw, expected).map_err(
            |error: Error| {
                Error::Arj(format!(
                    "arj: member `{}` method {}: {error}",
                    entry.name, entry.method
                ))
            },
        )?,
        METHOD_FASTEST => decode_method4(raw, expected).map_err(|error: Error| {
            Error::Arj(format!("arj: member `{}` method 4: {error}", entry.name))
        })?,
        other => {
            return Err(Error::Arj(format!(
                "arj: member `{}` uses method {other}, which the ARJ 2.x/3.x stream format does not define",
                entry.name
            )));
        }
    };
    if decoded.len() != expected {
        return Err(Error::Arj(format!(
            "arj: member `{}` decoded to {} bytes, not the declared {expected}",
            entry.name,
            decoded.len()
        )));
    }
    let computed: u32 = crc32_ieee(&decoded);
    if computed != entry.crc32 {
        return Err(Error::Arj(format!(
            "arj: member `{}` crc32 mismatch: stored 0x{:08x}, computed 0x{computed:08x}",
            entry.name, entry.crc32
        )));
    }
    Ok(decoded)
}

const ARJ_LZ_PARAMS: crate::containers::lha_huff::LhaParams =
    crate::containers::lha_huff::LhaParams {
        history_bits: 16,
        offset_bits: 5,
    };

struct BitReader<'a> {
    src: &'a [u8],
    bit: usize,
}

impl<'a> BitReader<'a> {
    const fn new(src: &'a [u8]) -> Self {
        Self { src, bit: 0 }
    }

    fn read_bit(&mut self) -> Result<u32> {
        let byte: u8 = *self
            .src
            .get(self.bit >> 3)
            .ok_or_else(|| Error::Arj("bitstream underrun".to_owned()))?;
        let mask: u8 = 0b1000_0000 >> (self.bit & 7);
        self.bit += 1;
        Ok(u32::from(byte & mask != 0))
    }

    fn read_bits(&mut self, count: u32) -> Result<u32> {
        let mut value: u32 = 0;
        for _ in 0..count {
            value = (value << 1) | self.read_bit()?;
        }
        Ok(value)
    }

    const fn consumed_bits(&self) -> usize {
        self.bit
    }
}

fn read_tiered(
    reader: &mut BitReader<'_>,
    start_width: u32,
    stop_width: u32,
    start_step: u32,
) -> Result<u32> {
    let mut plus: u32 = 0;
    let mut step: u32 = start_step;
    let mut width: u32 = start_width;
    while width < stop_width {
        if reader.read_bit()? == 0 {
            break;
        }
        plus += step;
        step <<= 1;
        width += 1;
    }
    if width == 0 {
        return Ok(plus);
    }
    Ok(reader.read_bits(width)? + plus)
}

pub fn decode_method4(src: &[u8], expected: usize) -> Result<Vec<u8>> {
    decode_fastest_observed(src, expected, |_length: usize, _distance: usize| {})
}

fn decode_fastest_observed<O: FnMut(usize, usize)>(
    src: &[u8],
    expected: usize,
    mut observe: O,
) -> Result<Vec<u8>> {
    let mut reader: BitReader<'_> = BitReader::new(src);
    let mut out: Vec<u8> = Vec::with_capacity(crate::quota::bounded_prealloc(expected as u64));
    while out.len() < expected {
        let code: u32 = read_tiered(&mut reader, 0, F_LEN_STOP_WIDTH, 1)?;
        if code == 0 {
            let literal: u32 = reader.read_bits(8)?;
            out.push(literal as u8);
            continue;
        }
        let length: usize = code as usize + F_THRESHOLD - 1;
        let pointer: u32 = read_tiered(
            &mut reader,
            F_PTR_START_WIDTH,
            F_PTR_STOP_WIDTH,
            1 << F_PTR_START_WIDTH,
        )?;
        let distance: usize = pointer as usize + 1;
        if distance > out.len() {
            return Err(Error::Arj(format!(
                "match distance {distance} reaches before the {} bytes produced so far",
                out.len()
            )));
        }
        let produced: usize = out
            .len()
            .checked_add(length)
            .ok_or_else(|| Error::Arj("output length overflow".to_owned()))?;
        if produced > expected {
            return Err(Error::Arj(format!(
                "match of {length} bytes overruns the declared {expected}-byte output"
            )));
        }
        observe(length, distance);
        for source in (out.len() - distance..).take(length) {
            let byte: u8 = out[source];
            out.push(byte);
        }
    }
    let consumed: usize = reader.consumed_bits();
    let used_bytes: usize = consumed.div_ceil(8);
    if used_bytes != src.len() {
        return Err(Error::Arj(format!(
            "stream consumed {consumed} bits ({used_bytes} bytes) of the {} compressed bytes declared",
            src.len()
        )));
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) fn build_block(fields: &[u8], name: &str, data: &[u8]) -> Vec<u8> {
    let mut basic: Vec<u8> = Vec::new();
    basic.push(MIN_FIRST_HDR_SIZE as u8);
    basic.extend_from_slice(fields);
    while basic.len() < MIN_FIRST_HDR_SIZE {
        basic.push(0);
    }
    basic.extend_from_slice(name.as_bytes());
    basic.push(0);
    basic.push(0);

    let mut out: Vec<u8> = ARJ_MAGIC.to_vec();
    out.extend_from_slice(&(basic.len() as u16).to_le_bytes());
    out.extend_from_slice(&basic);
    out.extend_from_slice(&crc32_ieee(&basic).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(data);
    out
}

#[cfg(test)]
pub(crate) fn file_fields(method: u8, file_type: u8, comp: u32, orig: u32) -> Vec<u8> {
    let mut fields: Vec<u8> = vec![0u8; MIN_FIRST_HDR_SIZE - 1];
    fields[OFS_ARCHIVER_VERSION - 1] = 11;
    fields[OFS_MIN_VERSION - 1] = 1;
    fields[OFS_HOST_OS - 1] = 2;
    fields[OFS_METHOD - 1] = method;
    fields[OFS_FILE_TYPE - 1] = file_type;
    fields[(OFS_COMPRESSED - 1)..(OFS_COMPRESSED + 3)].copy_from_slice(&comp.to_le_bytes());
    fields[(OFS_ORIGINAL - 1)..(OFS_ORIGINAL + 3)].copy_from_slice(&orig.to_le_bytes());
    fields
}

#[cfg(test)]
pub(crate) fn main_block() -> Vec<u8> {
    build_block(&file_fields(0, FILE_TYPE_COMMENT, 0, 0), "", &[])
}

#[cfg(test)]
pub(crate) fn stored_member_block(name: &str, body: &[u8]) -> Vec<u8> {
    let size: u32 = u32::try_from(body.len()).unwrap_or(u32::MAX);
    let mut fields: Vec<u8> = file_fields(0, 0, size, size);
    fields[(OFS_CRC - 1)..(OFS_CRC + 3)].copy_from_slice(&crc32_ieee(body).to_le_bytes());
    build_block(&fields, name, body)
}

#[cfg(test)]
pub(crate) fn synth_stored_arj(name: &str, body: &[u8]) -> Vec<u8> {
    let mut blob: Vec<u8> = main_block();
    blob.extend(stored_member_block(name, body));
    blob.extend_from_slice(ARJ_MAGIC);
    blob.extend_from_slice(&0u16.to_le_bytes());
    blob
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detect_requires_a_main_comment_header() {
        let archive: Vec<u8> = synth_stored_arj("hello.txt", b"payload");
        assert!(detect_arj(&archive));
        assert!(!detect_arj(b"PK\x03\x04"));
        let mut wrong_type: Vec<u8> = archive;
        wrong_type[4 + OFS_FILE_TYPE] = 0;
        assert!(!detect_arj(&wrong_type));
    }

    #[test]
    fn stored_member_round_trips_with_header_and_member_crc() {
        let payload: &[u8] = b"stored arj member, verbatim bytes here";
        let blob: Vec<u8> = synth_stored_arj("hello.txt", payload);
        let archive: ArjArchive = parse_arj(&blob).expect("parse arj");
        assert_eq!(archive.entries.len(), 1);
        let entry: &ArjEntry = &archive.entries[0];
        assert_eq!(entry.name, "hello.txt");
        assert_eq!(entry.method, 0);
        assert!(entry_is_stored(entry));
        assert_eq!(
            entry_bytes(&blob, entry, u64::MAX).expect("bytes"),
            payload.to_vec()
        );
    }

    #[test]
    fn corrupt_basic_header_crc_is_refused() {
        let mut blob: Vec<u8> = synth_stored_arj("hello.txt", b"payload");
        blob[4 + OFS_HOST_OS] ^= 0xFF;
        let error: Error = parse_arj(&blob).expect_err("corrupt header crc must fail");
        assert!(
            error.to_string().contains("basic header crc32 mismatch"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn member_crc_mismatch_is_refused() {
        let payload: &[u8] = b"stored arj member, verbatim bytes here";
        let mut blob: Vec<u8> = synth_stored_arj("hello.txt", payload);
        let archive: ArjArchive = parse_arj(&blob).expect("parse arj");
        let offset: usize = archive.entries[0].data_offset;
        blob[offset] ^= 0x20;
        let error: Error =
            entry_bytes(&blob, &archive.entries[0], u64::MAX).expect_err("crc must fail");
        assert!(
            error.to_string().contains("crc32 mismatch"),
            "unexpected error: {error}"
        );
    }

    const REAL_METHOD4: &[u8] = include_bytes!("../../../../corpus/binfmt/arj/method4.arj");

    const F_MAX_DISTANCE: usize = 15_872;
    const POINTER_TIER_BASE: [usize; 5] = [0, 512, 1536, 3584, 7680];

    fn length_tier(length: usize) -> usize {
        let code: usize = length + 1 - F_THRESHOLD;
        usize::BITS as usize - 1 - (code + 1).leading_zeros() as usize
    }

    fn pointer_tier(distance: usize) -> usize {
        let code: usize = distance - 1;
        POINTER_TIER_BASE
            .iter()
            .rposition(|base: &usize| code >= *base)
            .unwrap_or(0)
    }

    #[test]
    fn real_method4_stream_covers_every_length_and_distance_tier() {
        let archive: ArjArchive = parse_arj(REAL_METHOD4).expect("parse method4.arj");
        let entry: &ArjEntry = archive
            .entries
            .iter()
            .find(|candidate: &&ArjEntry| candidate.name == "tiers.bin")
            .expect("tiers.bin member");
        assert_eq!(entry.method, METHOD_FASTEST);
        let raw: &[u8] = entry_raw(REAL_METHOD4, entry).expect("member extent");
        let mut length_tiers: [u32; 8] = [0; 8];
        let mut pointer_tiers: [u32; 5] = [0; 5];
        let mut overlapping: u32 = 0;
        let mut shortest: usize = usize::MAX;
        let mut longest: usize = 0;
        let mut farthest: usize = 0;
        let decoded: Vec<u8> = decode_fastest_observed(
            raw,
            entry.original_size as usize,
            |length: usize, distance: usize| {
                length_tiers[length_tier(length)] += 1;
                pointer_tiers[pointer_tier(distance)] += 1;
                if distance < length {
                    overlapping += 1;
                }
                shortest = shortest.min(length);
                longest = longest.max(length);
                farthest = farthest.max(distance);
            },
        )
        .expect("decode tiers.bin");
        assert_eq!(crc32_ieee(&decoded), entry.crc32);
        for tier in 1..8 {
            assert!(
                length_tiers[tier] > 0,
                "length tier {tier} unexercised: {length_tiers:?}"
            );
        }
        for tier in 0..5 {
            assert!(
                pointer_tiers[tier] > 0,
                "distance tier {tier} unexercised: {pointer_tiers:?}"
            );
        }
        assert!(overlapping > 0, "no overlapping match in the fixture");
        assert_eq!(shortest, F_THRESHOLD, "shortest match must be 3 bytes");
        assert_eq!(longest, 256, "longest match must reach 256 bytes");
        assert!(
            farthest > POINTER_TIER_BASE[4],
            "farthest distance {farthest} must land in the widest tier"
        );
    }

    #[test]
    fn two_names_that_differ_only_by_case_are_refused_whatever_the_alphabet() {
        for (first, second) in [
            ("README.txt", "readme.txt"),
            ("\u{c4}.txt", "\u{e4}.txt"),
            ("STRASSE\u{c9}.dat", "strasse\u{e9}.dat"),
        ] {
            let mut seen: BTreeSet<String> = BTreeSet::new();
            admit_output_path(&mut seen, first).expect("the first name must be admitted");
            let clash: Result<()> = admit_output_path(&mut seen, second);
            assert!(
                clash.is_err(),
                "`{first}` and `{second}` fold to one name on a case-insensitive filesystem, so \
                 the second must be refused rather than silently overwriting the first"
            );
        }
    }

    #[test]
    fn two_names_that_differ_by_more_than_case_are_both_admitted() {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        admit_output_path(&mut seen, "readme.txt").expect("the first name must be admitted");
        admit_output_path(&mut seen, "readme2.txt")
            .expect("a distinct name must not be refused as a collision");
        admit_output_path(&mut seen, "\u{e4}.txt")
            .expect("a name that folds to nothing already seen must be admitted");
        admit_output_path(&mut seen, "\u{130}\u{131}.txt")
            .expect("a dotted capital I must be admitted beside a plain one");
        admit_output_path(&mut seen, "i\u{131}.txt").expect(
            "the dotted capital I lowercases to i followed by a combining dot above, not to a \
             plain i, so these two names do not fold together and neither may be refused as a \
             collision",
        );
    }

    #[test]
    fn the_pointer_encoding_cannot_reach_past_the_declared_window() {
        let tier_total: usize = (F_PTR_START_WIDTH..F_PTR_STOP_WIDTH)
            .map(|width: u32| 1usize << width)
            .sum();
        let widest_field: usize = (1usize << F_PTR_STOP_WIDTH) - 1;
        assert_eq!(
            tier_total + widest_field + 1,
            F_MAX_DISTANCE,
            "the widest distance the tiered pointer encoding can express must be exactly the \
             declared window, so no runtime guard is needed and none is written; a change to any \
             of the three width constants must break this rather than silently widen the window"
        );
        assert_eq!(
            POINTER_TIER_BASE[4] + widest_field + 1,
            F_MAX_DISTANCE,
            "the widest tier must start where the four narrower tiers end"
        );
    }

    #[test]
    fn method4_rejects_a_full_trailing_compressed_byte() {
        let archive: ArjArchive = parse_arj(REAL_METHOD4).expect("parse method4.arj");
        let entry: &ArjEntry = archive
            .entries
            .iter()
            .find(|candidate: &&ArjEntry| candidate.name == "readme.txt")
            .expect("readme.txt member");
        let raw: &[u8] = entry_raw(REAL_METHOD4, entry).expect("member extent");
        let mut padded: Vec<u8> = raw.to_vec();
        padded.push(0);
        let error: Error = decode_method4(&padded, entry.original_size as usize)
            .expect_err("a whole unused trailing byte must be refused");
        assert!(
            error.to_string().contains("compressed bytes declared"),
            "unexpected error: {error}"
        );
        let truncated: &[u8] = &raw[..raw.len() - 1];
        assert!(
            decode_method4(truncated, entry.original_size as usize).is_err(),
            "a truncated method 4 stream must be refused"
        );
        assert!(
            decode_method4(raw, entry.original_size as usize - 1).is_err(),
            "a short declared output must be refused"
        );
    }

    struct BitWriter {
        bits: Vec<bool>,
    }

    impl BitWriter {
        const fn new() -> Self {
            Self { bits: Vec::new() }
        }

        fn push(&mut self, value: u32, count: u32) {
            for index in (0..count).rev() {
                self.bits.push((value >> index) & 1 == 1);
            }
        }

        fn ones(&mut self, count: u32) {
            for _ in 0..count {
                self.bits.push(true);
            }
        }

        fn literal(&mut self, byte: u8) {
            self.push(u32::from(byte), 9);
        }

        fn match_token(&mut self, length: usize, distance: usize) {
            let code: u32 = (length + 1 - F_THRESHOLD) as u32;
            let mut width: u32 = 0;
            let mut plus: u32 = 0;
            let mut step: u32 = 1;
            while code >= plus + step && width < F_LEN_STOP_WIDTH {
                plus += step;
                step <<= 1;
                width += 1;
            }
            self.ones(width);
            let field: u32 = if width < F_LEN_STOP_WIDTH {
                width + 1
            } else {
                width
            };
            self.push(code - plus, field);
            let pointer: u32 = (distance - 1) as u32;
            let mut tier: u32 = 0;
            let mut base: u32 = 0;
            let mut span: u32 = 1 << F_PTR_START_WIDTH;
            while pointer >= base + span && tier < F_PTR_STOP_WIDTH - F_PTR_START_WIDTH {
                base += span;
                span <<= 1;
                tier += 1;
            }
            self.ones(tier);
            let ptr_width: u32 = if tier < F_PTR_STOP_WIDTH - F_PTR_START_WIDTH {
                F_PTR_START_WIDTH + tier + 1
            } else {
                F_PTR_STOP_WIDTH
            };
            self.push(pointer - base, ptr_width);
        }

        fn finish(self) -> Vec<u8> {
            let mut out: Vec<u8> = vec![0u8; self.bits.len().div_ceil(8)];
            for (index, bit) in self.bits.iter().enumerate() {
                if *bit {
                    out[index >> 3] |= 1 << (7 - (index & 7));
                }
            }
            out
        }
    }

    #[test]
    fn method4_round_trips_a_crafted_tier_boundary_stream() {
        let mut writer: BitWriter = BitWriter::new();
        for byte in 0u8..=15 {
            writer.literal(byte);
        }
        writer.match_token(3, 16);
        writer.match_token(256, 19);
        let stream: Vec<u8> = writer.finish();
        let decoded: Vec<u8> = decode_method4(&stream, 16 + 3 + 256).expect("crafted stream");
        let mut want: Vec<u8> = (0u8..=15).collect();
        for _ in 0..3 {
            let byte: u8 = want[want.len() - 16];
            want.push(byte);
        }
        for _ in 0..256 {
            let byte: u8 = want[want.len() - 19];
            want.push(byte);
        }
        assert_eq!(want.len(), 16 + 3 + 256);
        assert_eq!(decoded, want);
    }

    #[test]
    fn method4_refuses_a_distance_before_the_start_of_output() {
        let mut writer: BitWriter = BitWriter::new();
        writer.match_token(3, 1);
        let stream: Vec<u8> = writer.finish();
        let error: Error =
            decode_method4(&stream, 8).expect_err("a match before any output must be refused");
        assert!(
            error.to_string().contains("reaches before"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn method4_refuses_a_match_that_overruns_the_declared_output() {
        let mut writer: BitWriter = BitWriter::new();
        writer.literal(b'A');
        writer.match_token(4, 1);
        let stream: Vec<u8> = writer.finish();
        let error: Error = decode_method4(&stream, 4)
            .expect_err("a match past the declared output must be refused");
        assert!(
            error.to_string().contains("overruns the declared"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn extended_header_chain_is_bounded() {
        let payload: &[u8] = b"payload";
        let mut basic: Vec<u8> = vec![MIN_FIRST_HDR_SIZE as u8];
        basic.extend_from_slice(&file_fields(0, FILE_TYPE_COMMENT, 0, 0));
        basic.push(0);
        basic.push(0);
        let mut blob: Vec<u8> = ARJ_MAGIC.to_vec();
        blob.extend_from_slice(&(basic.len() as u16).to_le_bytes());
        blob.extend_from_slice(&basic);
        blob.extend_from_slice(&crc32_ieee(&basic).to_le_bytes());
        for _ in 0..257 {
            let ext: [u8; 2] = [0xAA, 0xBB];
            blob.extend_from_slice(&(ext.len() as u16).to_le_bytes());
            blob.extend_from_slice(&ext);
            blob.extend_from_slice(&crc32_ieee(&ext).to_le_bytes());
        }
        blob.extend_from_slice(&0u16.to_le_bytes());
        blob.extend(stored_member_block("hello.txt", payload));
        blob.extend_from_slice(ARJ_MAGIC);
        blob.extend_from_slice(&0u16.to_le_bytes());
        let error: Error = parse_arj(&blob).expect_err("an unbounded extended chain must fail");
        assert!(
            error.to_string().contains("extended header chain exceeds"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn extended_header_crc_is_verified() {
        let payload: &[u8] = b"payload";
        let mut basic: Vec<u8> = vec![MIN_FIRST_HDR_SIZE as u8];
        basic.extend_from_slice(&file_fields(0, FILE_TYPE_COMMENT, 0, 0));
        basic.push(0);
        basic.push(0);
        let mut blob: Vec<u8> = ARJ_MAGIC.to_vec();
        blob.extend_from_slice(&(basic.len() as u16).to_le_bytes());
        blob.extend_from_slice(&basic);
        blob.extend_from_slice(&crc32_ieee(&basic).to_le_bytes());
        let ext: [u8; 3] = [1, 2, 3];
        blob.extend_from_slice(&(ext.len() as u16).to_le_bytes());
        blob.extend_from_slice(&ext);
        blob.extend_from_slice(&crc32_ieee(&ext).wrapping_add(1).to_le_bytes());
        blob.extend_from_slice(&0u16.to_le_bytes());
        blob.extend(stored_member_block("hello.txt", payload));
        blob.extend_from_slice(ARJ_MAGIC);
        blob.extend_from_slice(&0u16.to_le_bytes());
        let error: Error = parse_arj(&blob).expect_err("a bad extended header crc must fail");
        assert!(
            error.to_string().contains("extended header crc32 mismatch"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn unknown_method_names_the_boundary() {
        let payload: &[u8] = b"\x01\x02\x03";
        let mut blob: Vec<u8> = main_block();
        blob.extend(build_block(
            &file_fields(9, 0, payload.len() as u32, 3),
            "odd.bin",
            payload,
        ));
        blob.extend_from_slice(ARJ_MAGIC);
        blob.extend_from_slice(&0u16.to_le_bytes());
        let archive: ArjArchive = parse_arj(&blob).expect("parse arj");
        let error: Error =
            entry_bytes(&blob, &archive.entries[0], u64::MAX).expect_err("method 9 must fail");
        assert!(
            error.to_string().contains("uses method 9"),
            "unexpected error: {error}"
        );
    }
}
