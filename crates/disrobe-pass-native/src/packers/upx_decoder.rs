use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::packers::pe_sections::{find_subsequence, read_u16, read_u32};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpxMethod {
    Nrv2b,
    Nrv2d,
    Nrv2e,
    Lzma,
}

impl UpxMethod {
    const fn from_id(id: u8) -> Option<Self> {
        match id {
            2 => Some(Self::Nrv2b),
            5 => Some(Self::Nrv2d),
            8 => Some(Self::Nrv2e),
            14 => Some(Self::Lzma),
            _ => None,
        }
    }

    const fn id(self) -> u8 {
        match self {
            Self::Nrv2b => 2,
            Self::Nrv2d => 5,
            Self::Nrv2e => 8,
            Self::Lzma => 14,
        }
    }
}

const UPX_MAGIC: &[u8; 4] = b"UPX!";
const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const PACK_HEADER_LEN: usize = 32;
const B_INFO_LEN: usize = 12;
const MAX_DECOMPRESSED: usize = 256 * 1024 * 1024;
const MAX_BLOCKS: usize = 1 << 16;
const MAX_BRUTE_FORCE_OFFSETS: usize = 1 << 16;
const MAX_VERIFY_CANDIDATES: usize = 4096;
const MAX_VERIFY_EXPANSION: u64 = 64;
const L_INFO_MAGIC_TO_FIRST_BLOCK: usize = 20;
const L_INFO_MAGIC_TO_FILESIZE: usize = 12;
const MAX_L_INFO_SCAN: usize = 64 * 1024;
const MAX_TAIL_SCAN: usize = 4096;
const MAX_RESYNC_OFFSETS: usize = 1 << 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpxPackHeader {
    pub version: u8,
    pub format: u8,
    pub method: UpxMethod,
    pub level: u8,
    pub u_adler: u32,
    pub c_adler: u32,
    pub u_len: u32,
    pub c_len: u32,
    pub u_file_size: u32,
    pub filter_id: u8,
    pub filter_cto: u8,
    pub header_offset: usize,
}

impl UpxPackHeader {
    pub fn locate_and_parse(packed: &[u8]) -> Result<Self> {
        let mut search_from: usize = 0;
        while let Some(rel) = find_subsequence(&packed[search_from..], UPX_MAGIC) {
            let offset: usize = search_from + rel;
            if let Some(header) = Self::parse_at(packed, offset) {
                return Ok(header);
            }
            search_from = offset + 1;
        }
        Self::locate_structural(packed).ok_or_else(|| Error::UpxDecode {
            stage: "packheader",
            detail: "no UPX! magic and no structurally valid PackHeader window found in input"
                .to_owned(),
        })
    }

    fn locate_structural(packed: &[u8]) -> Option<Self> {
        if packed.len() < PACK_HEADER_LEN {
            return None;
        }
        let last: usize = packed.len() - PACK_HEADER_LEN;
        let scan_last: usize = last.min(MAX_BRUTE_FORCE_OFFSETS);
        let mut version_plausible: Vec<Self> = Vec::new();
        let mut version_tampered: Vec<Self> = Vec::new();
        for offset in 0..=scan_last {
            let Some(header): Option<Self> = Self::parse_at(packed, offset) else {
                continue;
            };
            if !header.is_length_consistent(packed.len()) || !header.is_verification_affordable() {
                continue;
            }
            if header.version != 0 && header.version <= 16 {
                version_plausible.push(header);
            } else {
                version_tampered.push(header);
            }
            if version_plausible.len() + version_tampered.len() >= MAX_VERIFY_CANDIDATES {
                break;
            }
        }
        version_plausible
            .into_iter()
            .chain(version_tampered)
            .find(|header: &Self| header.verifies_by_decompression(packed))
    }

    fn is_length_consistent(&self, file_len: usize) -> bool {
        let c_len: usize = self.c_len as usize;
        let u_len: usize = self.u_len as usize;
        c_len >= 8 && c_len <= file_len && u_len >= c_len && u_len <= MAX_DECOMPRESSED
    }

    fn is_verification_affordable(&self) -> bool {
        u64::from(self.u_len) <= u64::from(self.c_len).saturating_mul(MAX_VERIFY_EXPANSION)
    }

    fn verifies_by_decompression(&self, packed: &[u8]) -> bool {
        let target: usize = self.u_len as usize;
        let mut bases: Vec<usize> = Vec::with_capacity(2);
        if let Some(off) = section_data_offset(packed) {
            bases.push(off);
        }
        bases.push(0);
        let single_ok: bool = bases
            .iter()
            .flat_map(|&base: &usize| [base, base.saturating_add(B_INFO_LEN)])
            .filter(|&start: &usize| start < packed.len())
            .any(|start: usize| {
                decompress_block(self.method, &packed[start..], target).is_ok_and(|out: Vec<u8>| {
                    out.len() == target && ucl_adler32(1, &out) == self.u_adler
                })
            });
        if single_ok {
            return true;
        }
        bases
            .into_iter()
            .filter(|&start: &usize| start < packed.len())
            .any(|start: usize| {
                walk_block_chain(packed, self, start).is_some_and(
                    |(image, _, _): (Vec<u8>, usize, usize)| ucl_adler32(1, &image) == self.u_adler,
                )
            })
    }

    fn parse_at(packed: &[u8], offset: usize) -> Option<Self> {
        let slice: &[u8] = packed.get(offset..offset + PACK_HEADER_LEN)?;
        let method: UpxMethod = UpxMethod::from_id(slice[6])?;
        let u_adler: u32 = u32::from_le_bytes([slice[8], slice[9], slice[10], slice[11]]);
        let c_adler: u32 = u32::from_le_bytes([slice[12], slice[13], slice[14], slice[15]]);
        let u_len: u32 = u32::from_le_bytes([slice[16], slice[17], slice[18], slice[19]]);
        let c_len: u32 = u32::from_le_bytes([slice[20], slice[21], slice[22], slice[23]]);
        let u_file_size: u32 = u32::from_le_bytes([slice[24], slice[25], slice[26], slice[27]]);
        if u_len == 0 || c_len == 0 || u_len as usize > MAX_DECOMPRESSED {
            return None;
        }
        if (c_len as usize) > packed.len() {
            return None;
        }
        Some(Self {
            version: slice[4],
            format: slice[5],
            method,
            level: slice[7],
            u_adler,
            c_adler,
            u_len,
            c_len,
            u_file_size,
            filter_id: slice[28],
            filter_cto: slice[29],
            header_offset: offset,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BInfo {
    pub u_len: u32,
    pub c_len: u32,
    pub method: u8,
    pub filter_id: u8,
    pub filter_cto: u8,
    pub extra: u8,
}

impl BInfo {
    fn parse_at(packed: &[u8], offset: usize) -> Option<Self> {
        let slice: &[u8] = packed.get(offset..offset + B_INFO_LEN)?;
        Some(Self {
            u_len: u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]),
            c_len: u32::from_le_bytes([slice[4], slice[5], slice[6], slice[7]]),
            method: slice[8],
            filter_id: slice[9],
            filter_cto: slice[10],
            extra: slice[11],
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpxUnpackOutput {
    pub method: UpxMethod,
    pub filter_id: u8,
    pub recovered_image: Vec<u8>,
    pub block_count: usize,
    pub adler_verified: bool,
}

pub fn unpack_upx(packed: &[u8]) -> Result<UpxUnpackOutput> {
    crate::debug::dbg_section("upx unpack");
    if packed.starts_with(ELF_MAGIC)
        && let Some(out) = unpack_upx_elf(packed)
    {
        return Ok(out);
    }
    let header: UpxPackHeader =
        UpxPackHeader::locate_and_parse(packed).inspect_err(|e: &Error| {
            crate::debug::dbg_kv("upx-wall", || {
                format!("pack-header locate/parse failed: {e}")
            });
        })?;
    crate::debug::dbg_kv("upx-header", || {
        format!(
            "method={:?} version={} format={} level={} u_len={} c_len={} u_adler={:#x} \
             filter_id={} filter_cto={} header_offset={:#x}",
            header.method,
            header.version,
            header.format,
            header.level,
            header.u_len,
            header.c_len,
            header.u_adler,
            header.filter_id,
            header.filter_cto,
            header.header_offset
        )
    });
    let (mut image, data_off, block_count): (Vec<u8>, usize, usize) = decode_image(packed, &header)
        .inspect_err(|e: &Error| {
            crate::debug::dbg_kv("upx-wall", || format!("decode_image failed: {e}"));
        })?;
    crate::debug::dbg_kv("upx-decode", || {
        format!(
            "blocks={block_count} data_offset={data_off:#x} decoded_bytes={}",
            image.len()
        )
    });
    let adler_verified: bool = ucl_adler32(1, &image) == header.u_adler;
    crate::debug::dbg_kv("upx-adler", || {
        format!(
            "verified={adler_verified} computed={:#x} expected={:#x}",
            ucl_adler32(1, &image),
            header.u_adler
        )
    });
    let (filter_id, filter_cto): (u8, u8) = match BInfo::parse_at(packed, data_off) {
        Some(info) if info.method == header.method.id() && info.filter_id != 0 => {
            (info.filter_id, info.filter_cto)
        }
        _ => (header.filter_id, header.filter_cto),
    };
    if filter_id != 0 {
        unfilter_ct(&mut image, filter_id, filter_cto)?;
    }
    Ok(UpxUnpackOutput {
        method: header.method,
        filter_id,
        recovered_image: image,
        block_count,
        adler_verified,
    })
}

struct ElfBlock {
    bytes: Vec<u8>,
    next: usize,
}

fn tail_pack_header(packed: &[u8]) -> Option<UpxPackHeader> {
    let last: usize = packed.len().checked_sub(PACK_HEADER_LEN)?;
    let first: usize = last.saturating_sub(MAX_TAIL_SCAN);
    (first..=last).rev().find_map(|offset: usize| {
        if packed.get(offset..offset + 4)? != &UPX_MAGIC[..] {
            return None;
        }
        let header: UpxPackHeader = UpxPackHeader::parse_at(packed, offset)?;
        (header.u_len == header.u_file_size && header.version != 0 && header.version <= 16)
            .then_some(header)
    })
}

fn elf_first_block_offset(packed: &[u8], u_len: u32) -> Option<usize> {
    let limit: usize = MAX_L_INFO_SCAN.min(packed.len());
    let mut from: usize = 0;
    while let Some(rel) = find_subsequence(packed.get(from..limit)?, UPX_MAGIC) {
        let magic: usize = from + rel;
        let at: usize = magic + L_INFO_MAGIC_TO_FILESIZE;
        if let Some(raw) = packed.get(at..at + 4)
            && u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) == u_len
        {
            return Some(magic + L_INFO_MAGIC_TO_FIRST_BLOCK);
        }
        from = magic + 1;
    }
    None
}

fn elf_block_at(
    packed: &[u8],
    offset: usize,
    remaining: usize,
    method: UpxMethod,
) -> Option<ElfBlock> {
    let info: BInfo = BInfo::parse_at(packed, offset)?;
    let u_len: usize = info.u_len as usize;
    let c_len: usize = info.c_len as usize;
    if u_len == 0 || u_len > remaining || c_len == 0 || c_len > u_len || info.extra != 0 {
        return None;
    }
    let data_start: usize = offset.checked_add(B_INFO_LEN)?;
    let data_end: usize = data_start.checked_add(c_len)?;
    let comp: &[u8] = packed.get(data_start..data_end)?;
    let mut bytes: Vec<u8> = if c_len == u_len {
        comp.to_vec()
    } else {
        if info.method != method.id() {
            return None;
        }
        let decoded: Vec<u8> = decompress_block(method, comp, u_len).ok()?;
        if decoded.len() != u_len {
            return None;
        }
        decoded
    };
    if info.filter_id != 0 {
        unfilter_ct(&mut bytes, info.filter_id, info.filter_cto).ok()?;
    }
    Some(ElfBlock {
        bytes,
        next: data_end,
    })
}

fn decode_elf_extents(packed: &[u8], header: &UpxPackHeader) -> Option<(Vec<u8>, usize)> {
    let target: usize = header.u_len as usize;
    let start: usize = elf_first_block_offset(packed, header.u_len)?;
    let mut image: Vec<u8> = Vec::with_capacity(target.min(MAX_DECOMPRESSED));
    let mut cursor: usize = start;
    let mut blocks: usize = 0;
    let mut scanned: usize = 0;
    while image.len() < target {
        let remaining: usize = target - image.len();
        let mut block: Option<ElfBlock> = elf_block_at(packed, cursor, remaining, header.method);
        if block.is_none() {
            let mut probe: usize = (cursor + 4) & !3usize;
            while probe + B_INFO_LEN <= packed.len() && scanned < MAX_RESYNC_OFFSETS {
                if let Some(candidate) = elf_block_at(packed, probe, remaining, header.method) {
                    block = Some(candidate);
                    break;
                }
                scanned += 1;
                probe += 4;
            }
        }
        let found: ElfBlock = block?;
        image.extend_from_slice(&found.bytes);
        cursor = found.next;
        blocks += 1;
        if blocks > MAX_BLOCKS {
            return None;
        }
    }
    Some((image, blocks))
}

fn elf_load_ranges(image: &[u8]) -> Option<Vec<(usize, usize)>> {
    let total: usize = image.len();
    let elf64: bool = match image.get(4)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    if *image.get(5)? != 1 {
        return None;
    }
    let (ph_off, ph_ent, ph_num): (usize, usize, usize) = if elf64 {
        (
            usize::try_from(read_u64(image, 0x20)?).ok()?,
            read_u16(image, 0x36).ok()? as usize,
            read_u16(image, 0x38).ok()? as usize,
        )
    } else {
        (
            read_u32(image, 0x1c).ok()? as usize,
            read_u16(image, 0x2a).ok()? as usize,
            read_u16(image, 0x2c).ok()? as usize,
        )
    };
    let min_ent: usize = if elf64 { 56 } else { 32 };
    if ph_ent < min_ent || ph_num == 0 {
        return None;
    }
    let mut loads: Vec<(usize, usize)> = Vec::with_capacity(ph_num);
    for i in 0..ph_num {
        let base: usize = ph_off.checked_add(i.checked_mul(ph_ent)?)?;
        if read_u32(image, base).ok()? != 1 {
            continue;
        }
        let (offset, filesz): (usize, usize) = if elf64 {
            (
                usize::try_from(read_u64(image, base + 8)?).ok()?,
                usize::try_from(read_u64(image, base + 0x20)?).ok()?,
            )
        } else {
            (
                read_u32(image, base + 4).ok()? as usize,
                read_u32(image, base + 0x10).ok()? as usize,
            )
        };
        if filesz == 0 {
            continue;
        }
        if offset.checked_add(filesz)? > total {
            return None;
        }
        if loads
            .last()
            .is_some_and(|&(o, l): &(usize, usize)| o + l > offset)
        {
            return None;
        }
        loads.push((offset, filesz));
    }
    if loads.first().map(|&(o, _): &(usize, usize)| o) != Some(0) {
        return None;
    }
    let mut order: Vec<(usize, usize)> = loads.clone();
    let mut cursor: usize = 0;
    for &(offset, filesz) in &loads {
        if offset > cursor {
            order.push((cursor, offset - cursor));
        }
        cursor = offset + filesz;
    }
    if cursor < total {
        order.push((cursor, total - cursor));
    }
    (order
        .iter()
        .map(|&(_, l): &(usize, usize)| l)
        .sum::<usize>()
        == total)
        .then_some(order)
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let raw: &[u8] = bytes.get(offset..offset + 8)?;
    Some(u64::from_le_bytes(raw.try_into().ok()?))
}

fn relayout_elf_extents(stream: &[u8]) -> Option<Vec<u8>> {
    let order: Vec<(usize, usize)> = elf_load_ranges(stream)?;
    let mut out: Vec<u8> = vec![0u8; stream.len()];
    let mut cursor: usize = 0;
    for &(offset, len) in &order {
        let src: &[u8] = stream.get(cursor..cursor.checked_add(len)?)?;
        out.get_mut(offset..offset.checked_add(len)?)?
            .copy_from_slice(src);
        cursor += len;
    }
    Some(out)
}

fn unpack_upx_elf(packed: &[u8]) -> Option<UpxUnpackOutput> {
    let header: UpxPackHeader = tail_pack_header(packed)?;
    let (image, blocks): (Vec<u8>, usize) = decode_elf_extents(packed, &header)?;
    let adler: u32 = ucl_adler32(1, &image);
    crate::debug::dbg_kv("upx-elf", || {
        format!(
            "blocks={blocks} recovered={} u_len={} adler={adler:#x} expected={:#x}",
            image.len(),
            header.u_len,
            header.u_adler
        )
    });
    if adler != header.u_adler {
        return None;
    }
    let recovered_image: Vec<u8> = relayout_elf_extents(&image).unwrap_or(image);
    Some(UpxUnpackOutput {
        method: header.method,
        filter_id: header.filter_id,
        recovered_image,
        block_count: blocks,
        adler_verified: true,
    })
}

fn decode_image(packed: &[u8], header: &UpxPackHeader) -> Result<(Vec<u8>, usize, usize)> {
    let target: usize = header.u_len as usize;
    let mut candidates: Vec<usize> = Vec::new();
    if let Some(off) = section_data_offset(packed) {
        candidates.push(off);
    }
    candidates.push(0);
    for base in candidates {
        for skip in [0usize, B_INFO_LEN] {
            let start: usize = base + skip;
            if start >= packed.len() {
                continue;
            }
            let Ok(out): Result<Vec<u8>> =
                decompress_block(header.method, &packed[start..], target)
            else {
                continue;
            };
            if out.len() == target && ucl_adler32(1, &out) == header.u_adler {
                return Ok((out, start, 1));
            }
        }
    }
    let scan_limit: usize = packed.len().saturating_sub(16).min(MAX_BRUTE_FORCE_OFFSETS);
    for start in 0..scan_limit {
        let affordable: u64 =
            (packed.len().saturating_sub(start) as u64).saturating_mul(MAX_VERIFY_EXPANSION);
        if (target as u64) > affordable {
            continue;
        }
        let Ok(out): Result<Vec<u8>> = decompress_block(header.method, &packed[start..], target)
        else {
            continue;
        };
        if out.len() == target && ucl_adler32(1, &out) == header.u_adler {
            return Ok((out, start, 1));
        }
    }
    if let Some((image, start, blocks)) = decode_multiblock(packed, header) {
        return Ok((image, start, blocks));
    }
    Err(Error::UpxDecode {
        stage: "block-stream",
        detail: format!(
            "no {method:?} stream offset yields u_adler {adler:#x} for u_len {target}",
            method = header.method,
            adler = header.u_adler,
        ),
    })
}

fn decode_multiblock(packed: &[u8], header: &UpxPackHeader) -> Option<(Vec<u8>, usize, usize)> {
    let target: usize = header.u_len as usize;
    let mut starts: Vec<usize> = Vec::new();
    if let Some(off) = section_data_offset(packed) {
        starts.push(off);
    }
    starts.push(0);
    for start in starts {
        if let Some(result) = walk_block_chain(packed, header, start) {
            return Some(result);
        }
    }
    let scan_limit: usize = packed
        .len()
        .saturating_sub(B_INFO_LEN)
        .min(MAX_BRUTE_FORCE_OFFSETS);
    for start in 0..scan_limit {
        let Some(first): Option<BInfo> = BInfo::parse_at(packed, start) else {
            continue;
        };
        if first.method != header.method.id()
            || first.u_len == 0
            || first.u_len as usize > target
            || first.c_len == 0
            || first.c_len as usize > packed.len().saturating_sub(start + B_INFO_LEN)
        {
            continue;
        }
        if let Some(result) = walk_block_chain(packed, header, start) {
            return Some(result);
        }
    }
    None
}

fn walk_block_chain(
    packed: &[u8],
    header: &UpxPackHeader,
    start: usize,
) -> Option<(Vec<u8>, usize, usize)> {
    let target: usize = header.u_len as usize;
    let mut image: Vec<u8> = Vec::with_capacity(target);
    let mut cursor: usize = start;
    let mut blocks: usize = 0;
    while image.len() < target {
        let info: BInfo = BInfo::parse_at(packed, cursor)?;
        let u_len: usize = info.u_len as usize;
        let c_len: usize = info.c_len as usize;
        if u_len == 0 || c_len == 0 || image.len() + u_len > target {
            return None;
        }
        let data_start: usize = cursor.checked_add(B_INFO_LEN)?;
        let data_end: usize = data_start.checked_add(c_len)?;
        let comp: &[u8] = packed.get(data_start..data_end)?;
        if c_len >= u_len {
            image.extend_from_slice(comp.get(..u_len)?);
        } else {
            let method: UpxMethod = UpxMethod::from_id(info.method)?;
            let decoded: Vec<u8> = decompress_block(method, comp, u_len).ok()?;
            if decoded.len() != u_len {
                return None;
            }
            image.extend_from_slice(&decoded);
        }
        cursor = data_end;
        blocks += 1;
        if blocks > MAX_BLOCKS {
            return None;
        }
    }
    if image.len() == target && ucl_adler32(1, &image) == header.u_adler {
        Some((image, start, blocks))
    } else {
        None
    }
}

fn section_data_offset(packed: &[u8]) -> Option<usize> {
    if packed.len() < 0x40 {
        return None;
    }
    let pe_off: usize = disrobe_binfmt::locate_pe_header(packed)?;
    let coff: usize = pe_off + 4;
    let num_sections: usize = read_u16(packed, coff + 2).ok()? as usize;
    let opt_size: usize = read_u16(packed, coff + 16).ok()? as usize;
    let sect_table: usize = coff + 20 + opt_size;
    let mut best: Option<usize> = None;
    for i in 0..num_sections {
        let entry: usize = sect_table + i * 40;
        let raw_size: u32 = read_u32(packed, entry + 16).ok()?;
        let raw_off: u32 = read_u32(packed, entry + 20).ok()?;
        if raw_size != 0 && (raw_off as usize) < packed.len() {
            best = Some(best.map_or(raw_off as usize, |b: usize| b.min(raw_off as usize)));
        }
    }
    best
}

fn decompress_block(method: UpxMethod, src: &[u8], out_len: usize) -> Result<Vec<u8>> {
    match method {
        UpxMethod::Nrv2b => nrv2b_decompress(src, out_len),
        UpxMethod::Nrv2d => nrv2d_decompress(src, out_len),
        UpxMethod::Nrv2e => nrv2e_decompress(src, out_len),
        UpxMethod::Lzma => lzma_decompress(src, out_len),
    }
}

struct Nrv2Bits<'a> {
    src: &'a [u8],
    pos: usize,
    bb: u32,
    bc: u32,
}

impl<'a> Nrv2Bits<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            pos: 0,
            bb: 0,
            bc: 0,
        }
    }

    fn next_byte(&mut self) -> Result<u8> {
        let b: u8 = *self.src.get(self.pos).ok_or(Error::Truncated {
            needed: self.pos + 1,
            had: self.src.len(),
        })?;
        self.pos += 1;
        Ok(b)
    }

    fn get_bit(&mut self) -> Result<u32> {
        if self.bc == 0 {
            let b0: u32 = u32::from(self.next_byte()?);
            let b1: u32 = u32::from(self.next_byte()?);
            let b2: u32 = u32::from(self.next_byte()?);
            let b3: u32 = u32::from(self.next_byte()?);
            self.bb = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
            self.bc = 32;
        }
        self.bc -= 1;
        let bit: u32 = (self.bb >> 31) & 1;
        self.bb <<= 1;
        Ok(bit)
    }
}

fn nrv2b_decompress(src: &[u8], out_len: usize) -> Result<Vec<u8>> {
    let mut bits: Nrv2Bits<'_> = Nrv2Bits::new(src);
    let mut out: Vec<u8> = Vec::with_capacity(out_len);
    let mut last_m_off: usize = 1;
    while out.len() < out_len {
        if bits.get_bit()? == 1 {
            out.push(bits.next_byte()?);
            continue;
        }
        let mut m_off: usize = 1;
        loop {
            m_off = (m_off << 1) + bits.get_bit()? as usize;
            if bits.get_bit()? == 1 {
                break;
            }
        }
        let m_off_final: usize;
        if m_off == 2 {
            m_off_final = last_m_off;
        } else {
            let byte: usize = bits.next_byte()? as usize;
            let raw: usize = (m_off.checked_sub(3).ok_or_else(|| Error::UpxDecode {
                stage: "nrv2-offset",
                detail: String::from("m_off underflowed below 3 (corrupt or misaligned stream)"),
            })? << 8)
                + byte;
            if raw == 0xffff_ffff {
                break;
            }
            m_off_final = raw + 1;
            last_m_off = m_off_final;
        }
        let mut m_len: usize = bits.get_bit()? as usize;
        m_len = (m_len << 1) + bits.get_bit()? as usize;
        if m_len == 0 {
            m_len += 1;
            loop {
                m_len = (m_len << 1) + bits.get_bit()? as usize;
                if bits.get_bit()? == 1 {
                    break;
                }
            }
            m_len += 2;
        }
        m_len += usize::from(m_off_final > 0xd00);
        copy_match(&mut out, m_off_final, m_len + 1, out_len)?;
    }
    Ok(out)
}

fn nrv2d_decompress(src: &[u8], out_len: usize) -> Result<Vec<u8>> {
    let mut bits: Nrv2Bits<'_> = Nrv2Bits::new(src);
    let mut out: Vec<u8> = Vec::with_capacity(out_len);
    let mut last_m_off: usize = 1;
    while out.len() < out_len {
        if bits.get_bit()? == 1 {
            out.push(bits.next_byte()?);
            continue;
        }
        let mut m_off: usize = 1;
        loop {
            m_off = (m_off << 1) + bits.get_bit()? as usize;
            if bits.get_bit()? == 1 {
                break;
            }
            m_off = (m_off << 1) + bits.get_bit()? as usize;
        }
        let (m_off_final, mut m_len): (usize, usize) = if m_off == 2 {
            (last_m_off, bits.get_bit()? as usize)
        } else {
            let byte: usize = bits.next_byte()? as usize;
            let raw: usize = (m_off.checked_sub(3).ok_or_else(|| Error::UpxDecode {
                stage: "nrv2-offset",
                detail: String::from("m_off underflowed below 3 (corrupt or misaligned stream)"),
            })? << 8)
                + byte;
            if raw == 0xffff_ffff {
                break;
            }
            last_m_off = raw + 1;
            (raw + 1, raw & 1)
        };
        m_len = (m_len << 1) + bits.get_bit()? as usize;
        if m_len == 0 {
            m_len += 1;
            loop {
                m_len = (m_len << 1) + bits.get_bit()? as usize;
                if bits.get_bit()? == 1 {
                    break;
                }
            }
            m_len += 2;
        }
        m_len += usize::from(m_off_final > 0x500);
        copy_match(&mut out, m_off_final, m_len + 1, out_len)?;
    }
    Ok(out)
}

fn nrv2e_decompress(src: &[u8], out_len: usize) -> Result<Vec<u8>> {
    let mut bits: Nrv2Bits<'_> = Nrv2Bits::new(src);
    let mut out: Vec<u8> = Vec::with_capacity(out_len);
    let mut last_m_off: usize = 1;
    while out.len() < out_len {
        if bits.get_bit()? == 1 {
            out.push(bits.next_byte()?);
            continue;
        }
        let mut m_off: usize = 1;
        loop {
            m_off = (m_off << 1) + bits.get_bit()? as usize;
            if bits.get_bit()? == 1 {
                break;
            }
            m_off = ((m_off - 1) << 1) + bits.get_bit()? as usize;
        }
        let (m_off_final, mut m_len): (usize, usize) = if m_off == 2 {
            (last_m_off, bits.get_bit()? as usize)
        } else {
            let byte: usize = bits.next_byte()? as usize;
            let raw: usize = (m_off.checked_sub(3).ok_or_else(|| Error::UpxDecode {
                stage: "nrv2-offset",
                detail: String::from("m_off underflowed below 3 (corrupt or misaligned stream)"),
            })? << 8)
                + byte;
            if raw == 0xffff_ffff {
                break;
            }
            let len_bit: usize = (raw ^ 0xffff_ffff) & 1;
            let off: usize = (raw >> 1) + 1;
            last_m_off = off;
            (off, len_bit)
        };
        if m_len != 0 {
            m_len = 1 + bits.get_bit()? as usize;
        } else if bits.get_bit()? == 1 {
            m_len = 3 + bits.get_bit()? as usize;
        } else {
            m_len += 1;
            loop {
                m_len = (m_len << 1) + bits.get_bit()? as usize;
                if bits.get_bit()? == 1 {
                    break;
                }
            }
            m_len += 3;
        }
        m_len += usize::from(m_off_final > 0x500);
        copy_match(&mut out, m_off_final, m_len + 1, out_len)?;
    }
    Ok(out)
}

fn lzma_decompress(src: &[u8], out_len: usize) -> Result<Vec<u8>> {
    if src.len() < 3 {
        return Err(Error::Truncated {
            needed: 3,
            had: src.len(),
        });
    }
    let pb: u8 = src[0] & 7;
    let lp: u8 = src[1] >> 4;
    let lc: u8 = src[1] & 0x0F;
    if pb >= 5 || lp >= 5 || lc >= 9 || (src[0] >> 3) != lc + lp {
        return Err(Error::UpxDecode {
            stage: "lzma-props",
            detail: format!(
                "UPX LZMA property bytes {b0:#04x} {b1:#04x} are inconsistent (pb={pb} lp={lp} \
                 lc={lc}, high5={high5} != lc+lp)",
                b0 = src[0],
                b1 = src[1],
                high5 = src[0] >> 3,
            ),
        });
    }
    crate::debug::dbg_line(|| {
        format!(
            "upx-lzma-props: pb={pb} lp={lp} lc={lc} (canonical 2-byte layout) out_len={out_len}"
        )
    });
    let mut framed: Vec<u8> = Vec::with_capacity(src.len());
    framed.push((pb << 4) | lp);
    framed.push(lc);
    framed.extend_from_slice(&src[2..]);
    crate::packers::mpress_lzma::decode_mpress_lzma(&framed, out_len).map_err(|e| {
        Error::UpxDecode {
            stage: "lzma",
            detail: e.to_string(),
        }
    })
}

#[inline]
fn copy_match(out: &mut Vec<u8>, m_off: usize, m_len: usize, out_len: usize) -> Result<()> {
    if out.len() + m_len > out_len {
        return Err(Error::UpxDecode {
            stage: "copy-match",
            detail: format!(
                "match length {m_len} overruns target (out.len={}, target={out_len})",
                out.len()
            ),
        });
    }
    if m_off == 0 || m_off > out.len() {
        return Err(Error::UpxDecode {
            stage: "copy-match",
            detail: format!("offset {m_off} out of range (out.len={})", out.len()),
        });
    }
    let start: usize = out.len() - m_off;
    for i in 0..m_len {
        let b: u8 = out[start + i];
        out.push(b);
    }
    Ok(())
}

fn unfilter_ct(code: &mut [u8], filter_id: u8, cto: u8) -> Result<()> {
    match filter_id {
        0x11 | 0x12 | 0x13 | 0x14 | 0x15 | 0x16 | 0x24 | 0x25 | 0x26 | 0x36 | 0x46 | 0x49
        | 0x4a | 0x4b | 0x4c | 0x4d | 0x4e | 0x4f => unfilter_ctok(code, filter_id, cto),
        other => Err(Error::UpxDecode {
            stage: "unfilter",
            detail: format!("unsupported CT filter id {other:#x}"),
        }),
    }
}

fn unfilter_ctok(code: &mut [u8], filter_id: u8, cto: u8) -> Result<()> {
    let n: usize = code.len();
    if n < 5 {
        return Ok(());
    }
    let size5: usize = n - 5;
    let cto_hi: u32 = u32::from(cto) << 24;
    let jcc_enabled: bool = (filter_id & 0x0f) >= 9;
    let mut last_call: usize = 0;
    let mut i: usize = 0;
    while i < size5 {
        let op: u8 = code[i];
        let is_branch: bool = op == 0xe8 || op == 0xe9;
        let is_jcc: bool = jcc_enabled
            && i != last_call
            && i > 0
            && code[i - 1] == 0x0f
            && (0x80..=0x8f).contains(&op);
        if (is_branch || is_jcc) && code[i + 1] == cto {
            let abs: u32 = (u32::from(code[i + 1]) << 24)
                | (u32::from(code[i + 2]) << 16)
                | (u32::from(code[i + 3]) << 8)
                | u32::from(code[i + 4]);
            let rel: u32 = abs
                .wrapping_sub(i as u32)
                .wrapping_sub(1)
                .wrapping_sub(cto_hi);
            code[i + 1] = (rel & 0xff) as u8;
            code[i + 2] = ((rel >> 8) & 0xff) as u8;
            code[i + 3] = ((rel >> 16) & 0xff) as u8;
            code[i + 4] = ((rel >> 24) & 0xff) as u8;
            i += 4;
            last_call = i + 1;
        }
        i += 1;
    }
    Ok(())
}

fn ucl_adler32(seed: u32, data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut s1: u32 = seed & 0xffff;
    let mut s2: u32 = (seed >> 16) & 0xffff;
    for &b in data {
        s1 = (s1 + u32::from(b)) % MOD;
        s2 = (s2 + s1) % MOD;
    }
    (s2 << 16) | s1
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn ucl_adler32_matches_known_vector() {
        assert_eq!(ucl_adler32(1, b""), 1);
        assert_eq!(ucl_adler32(1, b"a"), 0x0062_0062);
        assert_eq!(ucl_adler32(1, b"abc"), 0x024d_0127);
    }

    #[test]
    fn packheader_rejects_input_without_magic() {
        let buf: Vec<u8> = vec![0u8; 256];
        assert!(UpxPackHeader::locate_and_parse(&buf).is_err());
    }

    #[test]
    fn method_ids_match_upx_le32_constants() {
        assert_eq!(UpxMethod::from_id(2), Some(UpxMethod::Nrv2b));
        assert_eq!(UpxMethod::from_id(5), Some(UpxMethod::Nrv2d));
        assert_eq!(UpxMethod::from_id(8), Some(UpxMethod::Nrv2e));
        assert_eq!(UpxMethod::from_id(14), Some(UpxMethod::Lzma));
        assert_eq!(UpxMethod::Nrv2b.id(), 2);
        assert_eq!(UpxMethod::Nrv2d.id(), 5);
        assert_eq!(UpxMethod::Nrv2e.id(), 8);
        assert_eq!(UpxMethod::Lzma.id(), 14);
        assert_eq!(UpxMethod::from_id(3), None);
        assert_eq!(UpxMethod::from_id(6), None);
    }

    #[test]
    fn nrv2b_eof_marker_terminates() {
        let mut stream: Vec<u8> = Vec::new();
        stream.extend_from_slice(&0x4000_0000u32.to_le_bytes());
        stream.push(0xff);
        let out: Result<Vec<u8>> = nrv2b_decompress(&stream, 64);
        assert!(out.is_ok() || matches!(out, Err(Error::Truncated { .. })));
    }

    fn header_with_lengths(u_len: u32, c_len: u32, version: u8) -> UpxPackHeader {
        UpxPackHeader {
            version,
            format: 1,
            method: UpxMethod::Nrv2b,
            level: 9,
            u_adler: 0,
            c_adler: 0,
            u_len,
            c_len,
            u_file_size: u_len,
            filter_id: 0,
            filter_cto: 0,
            header_offset: 0,
        }
    }

    #[test]
    fn real_upx_expansion_ratio_is_verification_affordable() {
        assert!(header_with_lengths(4_301_163, 1_457_759, 255).is_verification_affordable());
        assert!(header_with_lengths(116_810, 49_950, 0).is_verification_affordable());
    }

    #[test]
    fn spurious_giant_u_len_window_is_screened_before_decompression() {
        let spurious: UpxPackHeader = header_with_lengths(135_987_207, 598_784, 1);
        assert!(
            spurious.is_length_consistent(usize::MAX),
            "the rg false-positive window passes a length-only screen, which is why it needs the \
             expansion bound"
        );
        assert!(
            !spurious.is_verification_affordable(),
            "a 227x expansion window must be screened so it never drives a 135MB speculative \
             decompress allocation during the tamper-resilient locate scan"
        );
    }

    #[test]
    fn version_byte_is_not_a_locate_gate() {
        let tampered_version: UpxPackHeader = header_with_lengths(116_810, 49_950, 0xFF);
        assert!(tampered_version.is_length_consistent(usize::MAX));
        assert!(tampered_version.is_verification_affordable());
    }

    #[test]
    fn brute_force_decode_does_not_amplify_on_huge_u_len() {
        let header: UpxPackHeader = header_with_lengths(MAX_DECOMPRESSED as u32, 4096, 1);
        let packed: Vec<u8> = vec![0u8; 8192];
        let start: std::time::Instant = std::time::Instant::now();
        let r: Result<(Vec<u8>, usize, usize)> = decode_image(&packed, &header);
        assert!(
            r.is_err(),
            "a 256MB declared u_len over an 8KB packed input cannot decode and must fault"
        );
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "the brute-force fallback must skip offsets that cannot affordably expand to u_len, \
             never run thousands of 256MB decompress allocations"
        );
    }

    #[test]
    fn brute_force_keeps_affordable_offsets_in_range() {
        let header: UpxPackHeader = header_with_lengths(64, 32, 1);
        let packed: Vec<u8> = vec![0u8; 256];
        let r: Result<(Vec<u8>, usize, usize)> = decode_image(&packed, &header);
        assert!(
            r.is_err(),
            "noise cannot decode to the declared adler, but the affordable offsets must still be \
             attempted (the bound only screens the implausible tail)"
        );
    }

    #[test]
    fn multiblock_offset_scan_is_capped_to_the_brute_force_window() {
        let header: UpxPackHeader = header_with_lengths(64, 32, 1);
        let packed: Vec<u8> = vec![0u8; 600_000_000];
        let start: std::time::Instant = std::time::Instant::now();
        let r: Option<(Vec<u8>, usize, usize)> = decode_multiblock(&packed, &header);
        assert!(
            r.is_none(),
            "an all-zero image cannot form a valid block chain at any offset"
        );
        assert!(
            start.elapsed() < std::time::Duration::from_millis(150),
            "the multiblock offset scan must stop at the brute-force window, never walk the whole \
             attacker-sized input"
        );
    }
}
