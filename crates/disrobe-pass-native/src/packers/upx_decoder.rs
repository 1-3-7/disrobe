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
const MAX_TOTAL_DECOMPRESSED_OUTPUT: usize = MAX_DECOMPRESSED * 2;
const MAX_DECOMPRESSION_ATTEMPTS: usize = 4096;
const MAX_STRUCTURAL_CHECKSUM_BYTES: usize = 64 * 1024 * 1024;
const ADLER_MODULUS: i128 = 65_521;
const L_INFO_MAGIC_TO_FIRST_BLOCK: usize = 20;
const L_INFO_MAGIC_TO_FILESIZE: usize = 12;
const MAX_L_INFO_SCAN: usize = 64 * 1024;
const MAX_TAIL_SCAN: usize = 4096;
const MAX_RESYNC_OFFSETS: usize = 1 << 16;

#[derive(Debug, Clone, Copy)]
enum DecodeRoute {
    ElfExtents,
    Generic,
}

#[derive(Debug)]
struct DecodeQuota {
    remaining_attempts: usize,
    remaining_output_bytes: usize,
    attempts: usize,
}

impl DecodeQuota {
    const fn new(remaining_attempts: usize, remaining_output_bytes: usize) -> Self {
        Self {
            remaining_attempts,
            remaining_output_bytes,
            attempts: 0,
        }
    }

    fn reserve(&mut self, output_bytes: usize) -> Option<DecompressionPermit> {
        let remaining_attempts: usize = self.remaining_attempts.checked_sub(1)?;
        let remaining_output_bytes: usize =
            self.remaining_output_bytes.checked_sub(output_bytes)?;
        self.remaining_attempts = remaining_attempts;
        self.remaining_output_bytes = remaining_output_bytes;
        self.attempts += 1;
        Some(DecompressionPermit { output_bytes })
    }
}

#[derive(Debug)]
struct DecompressionBudget {
    elf_extents: DecodeQuota,
    generic: DecodeQuota,
}

#[derive(Debug)]
struct DecompressionPermit {
    output_bytes: usize,
}

#[derive(Debug)]
struct ChecksumBudget {
    remaining_bytes: usize,
}

impl ChecksumBudget {
    const fn new() -> Self {
        Self {
            remaining_bytes: MAX_STRUCTURAL_CHECKSUM_BYTES,
        }
    }

    #[cfg(test)]
    const fn with_remaining_bytes(remaining_bytes: usize) -> Self {
        Self { remaining_bytes }
    }

    fn reserve(&mut self, bytes: usize) -> bool {
        let Some(remaining_bytes): Option<usize> = self.remaining_bytes.checked_sub(bytes) else {
            return false;
        };
        self.remaining_bytes = remaining_bytes;
        true
    }
}

impl DecompressionBudget {
    const fn new() -> Self {
        Self::with_quotas(
            DecodeQuota::new(
                MAX_DECOMPRESSION_ATTEMPTS / 2,
                MAX_TOTAL_DECOMPRESSED_OUTPUT / 2,
            ),
            DecodeQuota::new(
                MAX_DECOMPRESSION_ATTEMPTS / 2,
                MAX_TOTAL_DECOMPRESSED_OUTPUT / 2,
            ),
        )
    }

    const fn with_quotas(elf_extents: DecodeQuota, generic: DecodeQuota) -> Self {
        Self {
            elf_extents,
            generic,
        }
    }

    fn reserve(&mut self, route: DecodeRoute, output_bytes: usize) -> Option<DecompressionPermit> {
        self.quota_mut(route).reserve(output_bytes)
    }

    fn quota_mut(&mut self, route: DecodeRoute) -> &mut DecodeQuota {
        match route {
            DecodeRoute::ElfExtents => &mut self.elf_extents,
            DecodeRoute::Generic => &mut self.generic,
        }
    }

    #[cfg(test)]
    const fn quota(&self, route: DecodeRoute) -> &DecodeQuota {
        match route {
            DecodeRoute::ElfExtents => &self.elf_extents,
            DecodeRoute::Generic => &self.generic,
        }
    }

    #[cfg(test)]
    const fn attempts(&self, route: DecodeRoute) -> usize {
        self.quota(route).attempts
    }

    #[cfg(test)]
    const fn remaining_output_bytes(&self, route: DecodeRoute) -> usize {
        self.quota(route).remaining_output_bytes
    }
}

#[derive(Debug)]
struct VerifiedStream {
    image: Vec<u8>,
    data_off: usize,
    block_count: usize,
}

#[derive(Debug)]
struct LocatedPackHeader {
    header: UpxPackHeader,
    verified: Option<VerifiedStream>,
}

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
        let mut budget: DecompressionBudget = DecompressionBudget::new();
        Ok(Self::locate_for_unpack(packed, &mut budget)?.header)
    }

    fn locate_for_unpack(
        packed: &[u8],
        budget: &mut DecompressionBudget,
    ) -> Result<LocatedPackHeader> {
        let mut search_from: usize = 0;
        while let Some(rel) = find_subsequence(&packed[search_from..], UPX_MAGIC) {
            let offset: usize = search_from + rel;
            if let Some(header) = Self::parse_at(packed, offset) {
                return Ok(LocatedPackHeader {
                    header,
                    verified: None,
                });
            }
            search_from = offset + 1;
        }
        let mut checksums: ChecksumBudget = ChecksumBudget::new();
        Self::locate_structural(packed, budget, &mut checksums).ok_or_else(|| Error::UpxDecode {
            stage: "packheader",
            detail: "no UPX! magic and no structurally valid PackHeader window found in input"
                .to_owned(),
        })
    }

    fn locate_structural(
        packed: &[u8],
        budget: &mut DecompressionBudget,
        checksums: &mut ChecksumBudget,
    ) -> Option<LocatedPackHeader> {
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
        for header in version_plausible.into_iter().chain(version_tampered) {
            if let Some(verified) = header.verify_by_decompression(packed, budget, checksums) {
                return Some(LocatedPackHeader {
                    header,
                    verified: Some(verified),
                });
            }
        }
        None
    }

    fn is_length_consistent(&self, file_len: usize) -> bool {
        let c_len: usize = self.c_len as usize;
        let u_len: usize = self.u_len as usize;
        c_len >= 8 && c_len <= file_len && u_len >= c_len && u_len <= MAX_DECOMPRESSED
    }

    fn is_verification_affordable(&self) -> bool {
        u64::from(self.u_len) <= u64::from(self.c_len).saturating_mul(MAX_VERIFY_EXPANSION)
    }

    fn verify_by_decompression(
        &self,
        packed: &[u8],
        budget: &mut DecompressionBudget,
        checksums: &mut ChecksumBudget,
    ) -> Option<VerifiedStream> {
        let target: usize = self.u_len as usize;
        let mut bases: Vec<usize> = Vec::with_capacity(2);
        if let Some(off) = section_data_offset(packed) {
            bases.push(off);
        }
        bases.push(0);
        for &base in &bases {
            for start in [base, base.saturating_add(B_INFO_LEN)] {
                if !output_is_affordable(packed, start, target) {
                    continue;
                }
                let Some(comp): Option<&[u8]> = compressed_window(packed, start, self) else {
                    continue;
                };
                if !checksums.reserve(comp.len()) {
                    return None;
                }
                if ucl_adler32(1, comp) != self.c_adler {
                    continue;
                }
                let permit: DecompressionPermit = budget.reserve(DecodeRoute::Generic, target)?;
                if let Ok(image) = decompress_block(self.method, comp, permit)
                    && image.len() == target
                    && ucl_adler32(1, &image) == self.u_adler
                {
                    return Some(VerifiedStream {
                        image,
                        data_off: start,
                        block_count: 1,
                    });
                }
            }
        }
        bases
            .into_iter()
            .filter(|&start: &usize| start < packed.len())
            .find_map(|start: usize| {
                walk_block_chain(packed, self, start, budget, DecodeRoute::Generic).map(
                    |(image, data_off, block_count): (Vec<u8>, usize, usize)| VerifiedStream {
                        image,
                        data_off,
                        block_count,
                    },
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
    let mut budget: DecompressionBudget = DecompressionBudget::new();
    unpack_upx_with_budget(packed, &mut budget)
}

fn unpack_upx_with_budget(
    packed: &[u8],
    budget: &mut DecompressionBudget,
) -> Result<UpxUnpackOutput> {
    if packed.starts_with(ELF_MAGIC)
        && let Some(recovered) = unpack_upx_elf(packed, budget)?
    {
        return Ok(recovered);
    }
    unpack_upx_generic(packed, budget)
}

fn unpack_upx_generic(packed: &[u8], budget: &mut DecompressionBudget) -> Result<UpxUnpackOutput> {
    let located: LocatedPackHeader =
        UpxPackHeader::locate_for_unpack(packed, budget).inspect_err(|e: &Error| {
            crate::debug::dbg_kv("upx-wall", || {
                format!("pack-header locate/parse failed: {e}")
            });
        })?;
    let header: UpxPackHeader = located.header;
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
    let VerifiedStream {
        mut image,
        data_off,
        block_count,
    }: VerifiedStream = match located.verified {
        Some(verified) => verified,
        None => {
            let (image, data_off, block_count): (Vec<u8>, usize, usize) =
                decode_image_with_budget(packed, &header, budget).inspect_err(|e: &Error| {
                    crate::debug::dbg_kv("upx-wall", || format!("decode_image failed: {e}"));
                })?;
            VerifiedStream {
                image,
                data_off,
                block_count,
            }
        }
    };
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
    budget: &mut DecompressionBudget,
) -> Option<ElfBlock> {
    let info: BInfo = BInfo::parse_at(packed, offset)?;
    let u_len: usize = info.u_len as usize;
    let c_len: usize = info.c_len as usize;
    if u_len == 0
        || u_len > remaining
        || c_len == 0
        || c_len > u_len
        || !output_matches_compressed_extent(u_len, c_len)
        || info.extra != 0
    {
        return None;
    }
    if c_len < u_len && info.method != method.id() {
        return None;
    }
    let data_start: usize = offset.checked_add(B_INFO_LEN)?;
    let data_end: usize = data_start.checked_add(c_len)?;
    let comp: &[u8] = packed.get(data_start..data_end)?;
    let permit: DecompressionPermit = budget.reserve(DecodeRoute::ElfExtents, u_len)?;
    let mut bytes: Vec<u8> = if c_len == u_len {
        comp.to_vec()
    } else {
        let decoded: Vec<u8> = decompress_block(method, comp, permit).ok()?;
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

fn output_is_affordable(packed: &[u8], start: usize, target: usize) -> bool {
    let Some(available): Option<usize> = packed.len().checked_sub(start) else {
        return false;
    };
    let Ok(available): core::result::Result<u64, _> = u64::try_from(available) else {
        return false;
    };
    let Ok(target): core::result::Result<u64, _> = u64::try_from(target) else {
        return false;
    };
    target <= available.saturating_mul(MAX_VERIFY_EXPANSION)
}

fn output_matches_compressed_extent(output: usize, compressed: usize) -> bool {
    let Ok(output): core::result::Result<u64, _> = u64::try_from(output) else {
        return false;
    };
    let Ok(compressed): core::result::Result<u64, _> = u64::try_from(compressed) else {
        return false;
    };
    output <= compressed.saturating_mul(MAX_VERIFY_EXPANSION)
}

fn compressed_window<'a>(
    packed: &'a [u8],
    start: usize,
    header: &UpxPackHeader,
) -> Option<&'a [u8]> {
    let c_len: usize = header.c_len as usize;
    let end: usize = start.checked_add(c_len)?;
    packed.get(start..end)
}

#[derive(Debug)]
struct Adler32Window<'a> {
    packed: &'a [u8],
    width: usize,
    start: usize,
    end_exclusive: usize,
    s1: u32,
    s2: u32,
}

impl<'a> Adler32Window<'a> {
    fn new(packed: &'a [u8], width: usize, end_exclusive: usize) -> Option<Self> {
        if width == 0 {
            return None;
        }
        let last_start: usize = packed.len().checked_sub(width)?.checked_add(1)?;
        let end_exclusive: usize = end_exclusive.min(last_start);
        if end_exclusive == 0 {
            return None;
        }
        let checksum: u32 = ucl_adler32(1, packed.get(..width)?);
        Some(Self {
            packed,
            width,
            start: 0,
            end_exclusive,
            s1: checksum & 0xffff,
            s2: checksum >> 16,
        })
    }

    const fn checksum(&self) -> u32 {
        (self.s2 << 16) | self.s1
    }

    const fn start(&self) -> usize {
        self.start
    }

    fn advance(&mut self) -> bool {
        if self.start.checked_add(1) >= Some(self.end_exclusive) {
            return false;
        }
        let outgoing: u32 = u32::from(self.packed[self.start]);
        let incoming: u32 = u32::from(self.packed[self.start + self.width]);
        let Ok(width): core::result::Result<i128, _> = i128::try_from(self.width) else {
            return false;
        };
        let s1: i128 = (i128::from(self.s1) - i128::from(outgoing) + i128::from(incoming))
            .rem_euclid(ADLER_MODULUS);
        let s2: i128 =
            (i128::from(self.s2) - width * i128::from(outgoing) + s1 - 1).rem_euclid(ADLER_MODULUS);
        let Ok(s1): core::result::Result<u32, _> = u32::try_from(s1) else {
            return false;
        };
        let Ok(s2): core::result::Result<u32, _> = u32::try_from(s2) else {
            return false;
        };
        self.start += 1;
        self.s1 = s1;
        self.s2 = s2;
        true
    }
}

fn matching_compressed_starts(
    packed: &[u8],
    header: &UpxPackHeader,
    scan_limit: usize,
) -> Vec<usize> {
    let mut matches: Vec<usize> = Vec::new();
    let Some(mut window): Option<Adler32Window<'_>> =
        Adler32Window::new(packed, header.c_len as usize, scan_limit)
    else {
        return matches;
    };
    loop {
        let start: usize = window.start();
        if output_is_affordable(packed, start, header.u_len as usize)
            && window.checksum() == header.c_adler
        {
            matches.push(start);
        }
        if !window.advance() {
            return matches;
        }
    }
}

#[cfg(test)]
fn decode_elf_extents(packed: &[u8], header: &UpxPackHeader) -> Option<(Vec<u8>, usize)> {
    let mut budget: DecompressionBudget = DecompressionBudget::new();
    decode_elf_extents_with_budget(packed, header, &mut budget)
}

fn decode_elf_extents_with_budget(
    packed: &[u8],
    header: &UpxPackHeader,
    budget: &mut DecompressionBudget,
) -> Option<(Vec<u8>, usize)> {
    if !header.is_verification_affordable() {
        return None;
    }
    let target: usize = header.u_len as usize;
    let start: usize = elf_first_block_offset(packed, header.u_len)?;
    if !output_is_affordable(packed, start, target) {
        return None;
    }
    let mut image: Vec<u8> = Vec::new();
    let mut cursor: usize = start;
    let mut blocks: usize = 0;
    let mut scanned: usize = 0;
    while image.len() < target {
        let remaining: usize = target - image.len();
        let mut block: Option<ElfBlock> =
            elf_block_at(packed, cursor, remaining, header.method, budget);
        if block.is_none() {
            let mut probe: usize = (cursor + 4) & !3usize;
            while probe + B_INFO_LEN <= packed.len() && scanned < MAX_RESYNC_OFFSETS {
                if let Some(candidate) =
                    elf_block_at(packed, probe, remaining, header.method, budget)
                {
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

fn unpack_upx_elf(
    packed: &[u8],
    budget: &mut DecompressionBudget,
) -> Result<Option<UpxUnpackOutput>> {
    let valid_elf: bool = crate::elf::is_well_formed_elf_executable(packed);
    let Some(header): Option<UpxPackHeader> = tail_pack_header(packed) else {
        if valid_elf {
            return Ok(None);
        }
        return Err(Error::UpxDecode {
            stage: "elf-extents",
            detail: String::from("invalid ELF before UPX generic fallback"),
        });
    };
    if elf_first_block_offset(packed, header.u_len).is_none() {
        if valid_elf {
            return Ok(None);
        }
        return Err(Error::UpxDecode {
            stage: "elf-extents",
            detail: String::from("invalid ELF before UPX generic fallback"),
        });
    }
    let Some((image, blocks)): Option<(Vec<u8>, usize)> =
        decode_elf_extents_with_budget(packed, &header, budget)
    else {
        if valid_elf {
            return Ok(None);
        }
        return Err(Error::UpxDecode {
            stage: "elf-extents",
            detail: String::from("recognized UPX ELF extents could not be decoded"),
        });
    };
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
        if valid_elf {
            return Ok(None);
        }
        return Err(Error::UpxDecode {
            stage: "elf-extents",
            detail: String::from("UPX ELF extents failed checksum verification"),
        });
    }
    let recovered_image: Vec<u8> = relayout_elf_extents(&image).unwrap_or(image);
    Ok(Some(UpxUnpackOutput {
        method: header.method,
        filter_id: header.filter_id,
        recovered_image,
        block_count: blocks,
        adler_verified: true,
    }))
}

#[cfg(test)]
fn decode_image(packed: &[u8], header: &UpxPackHeader) -> Result<(Vec<u8>, usize, usize)> {
    let mut budget: DecompressionBudget = DecompressionBudget::new();
    decode_image_with_budget(packed, header, &mut budget)
}

fn decode_image_with_budget(
    packed: &[u8],
    header: &UpxPackHeader,
    budget: &mut DecompressionBudget,
) -> Result<(Vec<u8>, usize, usize)> {
    if !header.is_verification_affordable() {
        return Err(Error::UpxDecode {
            stage: "block-stream",
            detail: String::from("declared expansion exceeds the verification cap"),
        });
    }
    let target: usize = header.u_len as usize;
    let mut candidates: Vec<usize> = Vec::new();
    if let Some(off) = section_data_offset(packed) {
        candidates.push(off);
    }
    candidates.push(0);
    for base in candidates {
        for skip in [0usize, B_INFO_LEN] {
            let Some(start): Option<usize> = base.checked_add(skip) else {
                continue;
            };
            if !output_is_affordable(packed, start, target) {
                continue;
            }
            let Some(comp): Option<&[u8]> = compressed_window(packed, start, header) else {
                continue;
            };
            if ucl_adler32(1, comp) != header.c_adler {
                continue;
            }
            let Some(permit): Option<DecompressionPermit> =
                budget.reserve(DecodeRoute::Generic, target)
            else {
                return Err(Error::UpxDecode {
                    stage: "block-stream",
                    detail: String::from("decompression budget exhausted"),
                });
            };
            let Ok(out): Result<Vec<u8>> = decompress_block(header.method, comp, permit) else {
                continue;
            };
            if out.len() == target && ucl_adler32(1, &out) == header.u_adler {
                return Ok((out, start, 1));
            }
        }
    }
    let scan_limit: usize = packed
        .len()
        .saturating_sub(header.c_len as usize)
        .saturating_add(1)
        .min(MAX_BRUTE_FORCE_OFFSETS);
    let checksum_matches: Vec<usize> = matching_compressed_starts(packed, header, scan_limit);
    let brute_force_starts: Vec<usize> = if checksum_matches.is_empty() {
        (0..scan_limit)
            .filter(|&start: &usize| output_is_affordable(packed, start, target))
            .collect()
    } else {
        checksum_matches
    };
    for start in brute_force_starts {
        let Some(comp): Option<&[u8]> = compressed_window(packed, start, header) else {
            continue;
        };
        let Some(permit): Option<DecompressionPermit> =
            budget.reserve(DecodeRoute::Generic, target)
        else {
            break;
        };
        let Ok(out): Result<Vec<u8>> = decompress_block(header.method, comp, permit) else {
            continue;
        };
        if out.len() == target && ucl_adler32(1, &out) == header.u_adler {
            return Ok((out, start, 1));
        }
    }
    if let Some((image, start, blocks)) = decode_multiblock_with_budget(packed, header, budget) {
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

#[cfg(test)]
fn decode_multiblock(packed: &[u8], header: &UpxPackHeader) -> Option<(Vec<u8>, usize, usize)> {
    let mut budget: DecompressionBudget = DecompressionBudget::new();
    decode_multiblock_with_budget(packed, header, &mut budget)
}

fn decode_multiblock_with_budget(
    packed: &[u8],
    header: &UpxPackHeader,
    budget: &mut DecompressionBudget,
) -> Option<(Vec<u8>, usize, usize)> {
    let target: usize = header.u_len as usize;
    let mut starts: Vec<usize> = Vec::new();
    if let Some(off) = section_data_offset(packed) {
        starts.push(off);
    }
    starts.push(0);
    for start in starts {
        if let Some(result) = walk_block_chain(packed, header, start, budget, DecodeRoute::Generic)
        {
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
        if let Some(result) = walk_block_chain(packed, header, start, budget, DecodeRoute::Generic)
        {
            return Some(result);
        }
    }
    None
}

fn walk_block_chain(
    packed: &[u8],
    header: &UpxPackHeader,
    start: usize,
    budget: &mut DecompressionBudget,
    route: DecodeRoute,
) -> Option<(Vec<u8>, usize, usize)> {
    let target: usize = header.u_len as usize;
    if !output_is_affordable(packed, start, target) {
        return None;
    }
    let mut image: Vec<u8> = Vec::new();
    let mut cursor: usize = start;
    let mut blocks: usize = 0;
    while image.len() < target {
        let info: BInfo = BInfo::parse_at(packed, cursor)?;
        let u_len: usize = info.u_len as usize;
        let c_len: usize = info.c_len as usize;
        if u_len == 0
            || c_len == 0
            || !output_matches_compressed_extent(u_len, c_len)
            || image.len().checked_add(u_len)? > target
        {
            return None;
        }
        let data_start: usize = cursor.checked_add(B_INFO_LEN)?;
        let data_end: usize = data_start.checked_add(c_len)?;
        let comp: &[u8] = packed.get(data_start..data_end)?;
        if c_len >= u_len {
            let _permit: DecompressionPermit = budget.reserve(route, u_len)?;
            image.extend_from_slice(comp.get(..u_len)?);
        } else {
            let method: UpxMethod = UpxMethod::from_id(info.method)?;
            let permit: DecompressionPermit = budget.reserve(route, u_len)?;
            let decoded: Vec<u8> = decompress_block(method, comp, permit).ok()?;
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

fn decompress_block(method: UpxMethod, src: &[u8], permit: DecompressionPermit) -> Result<Vec<u8>> {
    let out_len: usize = permit.output_bytes;
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
    let mut out: Vec<u8> = Vec::new();
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
    let mut out: Vec<u8> = Vec::new();
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
    let mut out: Vec<u8> = Vec::new();
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
    fn rolling_adler_matches_scalar_windows() {
        let bytes: Vec<u8> = (0u8..=u8::MAX).collect();
        for width in [1usize, 2, 5, 31, 64, 255, 256] {
            let mut window: Adler32Window<'_> =
                Adler32Window::new(&bytes, width, bytes.len()).expect("window must initialize");
            loop {
                let start: usize = window.start();
                assert_eq!(
                    window.checksum(),
                    ucl_adler32(1, &bytes[start..start + width])
                );
                if !window.advance() {
                    break;
                }
            }
        }
    }

    #[test]
    fn structural_header_verification_respects_checksum_byte_budget() {
        let stream: [u8; 5] = [0, 0, 0, 0x80, b'a'];
        let mut header: UpxPackHeader = header_with_lengths(1, stream.len() as u32, 1);
        header.u_adler = ucl_adler32(1, b"a");
        header.c_adler = ucl_adler32(1, &stream);
        let mut decompression: DecompressionBudget =
            DecompressionBudget::with_quotas(DecodeQuota::new(0, 0), DecodeQuota::new(1, 1));
        let mut checksums: ChecksumBudget = ChecksumBudget::with_remaining_bytes(stream.len() - 1);
        assert!(
            header
                .verify_by_decompression(&stream, &mut decompression, &mut checksums)
                .is_none()
        );
        assert_eq!(checksums.remaining_bytes, stream.len() - 1);
        assert_eq!(decompression.attempts(DecodeRoute::Generic), 0);
    }

    #[test]
    fn packheader_rejects_input_without_magic() {
        let buf: Vec<u8> = vec![0u8; 256];
        assert!(UpxPackHeader::locate_and_parse(&buf).is_err());
    }

    fn generic_elf_fixture(valid_header: bool) -> Vec<u8> {
        generic_elf_fixture_with_layout(valid_header, 56, 1)
    }

    fn generic_elf_fixture_with_layout(
        valid_header: bool,
        program_header_size: u16,
        program_header_count: u16,
    ) -> Vec<u8> {
        let program_table_offset: usize = 64;
        let stream_offset: usize = program_table_offset
            + usize::from(program_header_size) * usize::from(program_header_count);
        let header_offset: usize = stream_offset + 8;
        let mut packed: Vec<u8> = vec![0u8; header_offset + PACK_HEADER_LEN];
        packed[..ELF_MAGIC.len()].copy_from_slice(ELF_MAGIC);
        if valid_header {
            packed[4] = 2;
            packed[5] = 1;
            packed[6] = 1;
            packed[16..18].copy_from_slice(&2u16.to_le_bytes());
            packed[18..20].copy_from_slice(&62u16.to_le_bytes());
            packed[20..24].copy_from_slice(&1u32.to_le_bytes());
            packed[24..32].copy_from_slice(&0x400000u64.to_le_bytes());
            packed[32..40].copy_from_slice(&(program_table_offset as u64).to_le_bytes());
            packed[52..54].copy_from_slice(&64u16.to_le_bytes());
            packed[54..56].copy_from_slice(&program_header_size.to_le_bytes());
            packed[56..58].copy_from_slice(&program_header_count.to_le_bytes());
            packed[64..68].copy_from_slice(&1u32.to_le_bytes());
            packed[68..72].copy_from_slice(&5u32.to_le_bytes());
            packed[80..88].copy_from_slice(&0x400000u64.to_le_bytes());
            packed[88..96].copy_from_slice(&0x400000u64.to_le_bytes());
            let size: u64 = packed.len() as u64;
            packed[96..104].copy_from_slice(&size.to_le_bytes());
            packed[104..112].copy_from_slice(&size.to_le_bytes());
            packed[112..120].copy_from_slice(&0x1000u64.to_le_bytes());
        }
        let stream: [u8; 5] = [0, 0, 0, 0x80, b'a'];
        packed[stream_offset..stream_offset + stream.len()].copy_from_slice(&stream);
        let header: &mut [u8] = &mut packed[header_offset..];
        header[..UPX_MAGIC.len()].copy_from_slice(UPX_MAGIC);
        header[4] = 1;
        header[6] = UpxMethod::Nrv2b.id();
        header[8..12].copy_from_slice(&ucl_adler32(1, b"a").to_le_bytes());
        header[12..16].copy_from_slice(&ucl_adler32(1, &stream).to_le_bytes());
        header[16..20].copy_from_slice(&1u32.to_le_bytes());
        header[20..24].copy_from_slice(&(stream.len() as u32).to_le_bytes());
        header[24..28].copy_from_slice(&1u32.to_le_bytes());
        packed
    }

    #[test]
    fn malformed_elf_does_not_fall_back_to_generic_upx_decode() {
        let packed: Vec<u8> = generic_elf_fixture(false);
        let parsed: UpxPackHeader = tail_pack_header(&packed).expect("tail header must parse");
        let generic: (Vec<u8>, usize, usize) =
            decode_image(&packed, &parsed).expect("generic decode must recover the literal stream");
        assert_eq!(generic.0, b"a");
        let result: Result<UpxUnpackOutput> = unpack_upx(&packed);
        assert!(matches!(
            result,
            Err(Error::UpxDecode {
                stage: "elf-extents",
                ..
            })
        ));
    }

    #[test]
    fn valid_unsupported_elf_falls_back_to_generic_upx_decode() {
        let packed: Vec<u8> = generic_elf_fixture(true);
        let parsed: object::File<'_> =
            object::File::parse(&*packed).expect("fixture must parse as an ELF object");
        assert!(crate::elf::is_well_formed_elf_executable(&packed));
        assert!(
            parsed.format() == object::BinaryFormat::Elf,
            "fixture must be a structurally valid ELF before generic fallback is permitted"
        );
        let recovered: UpxUnpackOutput =
            unpack_upx(&packed).expect("valid unsupported ELF must retain generic UPX recovery");
        assert_eq!(recovered.recovered_image, b"a");
        assert!(recovered.adler_verified);
    }

    #[test]
    fn valid_elf_with_extended_program_header_entries_falls_back_to_generic_upx_decode() {
        let packed: Vec<u8> = generic_elf_fixture_with_layout(true, 64, 1);
        assert!(crate::elf::is_well_formed_elf_executable(&packed));
        let recovered: UpxUnpackOutput = unpack_upx(&packed).expect(
            "valid ELF with extended program header entries must retain generic UPX recovery",
        );
        assert_eq!(recovered.recovered_image, b"a");
    }

    #[test]
    fn valid_elf_without_an_entry_point_falls_back_to_generic_upx_decode() {
        let mut packed: Vec<u8> = generic_elf_fixture(true);
        packed[24..32].copy_from_slice(&0u64.to_le_bytes());
        assert!(crate::elf::is_well_formed_elf_executable(&packed));
        let recovered: UpxUnpackOutput =
            unpack_upx(&packed).expect("an entry-less valid ELF must retain generic UPX recovery");
        assert_eq!(recovered.recovered_image, b"a");
    }

    #[test]
    fn malformed_elf_without_a_tail_header_does_not_fall_back_to_generic_upx_decode() {
        let mut packed: Vec<u8> = generic_elf_fixture(false);
        packed.resize(packed.len() + MAX_TAIL_SCAN + PACK_HEADER_LEN + 1, 0);
        assert!(tail_pack_header(&packed).is_none());
        let parsed: UpxPackHeader =
            UpxPackHeader::locate_and_parse(&packed).expect("generic header must remain visible");
        let generic: (Vec<u8>, usize, usize) =
            decode_image(&packed, &parsed).expect("generic decoder must accept the literal stream");
        assert_eq!(generic.0, b"a");
        let result: Result<UpxUnpackOutput> = unpack_upx(&packed);
        assert!(matches!(
            result,
            Err(Error::UpxDecode {
                stage: "elf-extents",
                ..
            })
        ));
    }

    #[test]
    fn elf_with_noncanonical_header_size_does_not_fall_back_to_generic_upx_decode() {
        let mut packed: Vec<u8> = generic_elf_fixture(true);
        packed[52..54].copy_from_slice(&65u16.to_le_bytes());
        assert!(
            !crate::elf::is_well_formed_elf_executable(&packed),
            "an ELF header that overlaps its program table must not use generic UPX fallback"
        );
        let parsed: UpxPackHeader = tail_pack_header(&packed).expect("tail header must parse");
        let generic: (Vec<u8>, usize, usize) =
            decode_image(&packed, &parsed).expect("generic decoder must accept the literal stream");
        assert_eq!(generic.0, b"a");
        let result: Result<UpxUnpackOutput> = unpack_upx(&packed);
        assert!(matches!(
            result,
            Err(Error::UpxDecode {
                stage: "elf-extents",
                ..
            })
        ));
    }

    #[test]
    fn elf_with_program_table_inside_its_header_does_not_fall_back_to_generic_upx_decode() {
        let mut packed: Vec<u8> = generic_elf_fixture(true);
        packed[32..40].copy_from_slice(&63u64.to_le_bytes());
        assert!(!crate::elf::is_well_formed_elf_executable(&packed));
        let parsed: UpxPackHeader = tail_pack_header(&packed).expect("tail header must parse");
        let generic: (Vec<u8>, usize, usize) =
            decode_image(&packed, &parsed).expect("generic decoder must accept the literal stream");
        assert_eq!(generic.0, b"a");
        let result: Result<UpxUnpackOutput> = unpack_upx(&packed);
        assert!(matches!(
            result,
            Err(Error::UpxDecode {
                stage: "elf-extents",
                ..
            })
        ));
    }

    #[test]
    fn elf_with_out_of_file_section_table_does_not_fall_back_to_generic_upx_decode() {
        let mut packed: Vec<u8> = generic_elf_fixture(true);
        let section_table_offset: u64 = packed.len() as u64;
        packed[40..48].copy_from_slice(&section_table_offset.to_le_bytes());
        packed[58..60].copy_from_slice(&64u16.to_le_bytes());
        packed[60..62].copy_from_slice(&1u16.to_le_bytes());
        assert!(!crate::elf::is_well_formed_elf_executable(&packed));
        let parsed: UpxPackHeader = tail_pack_header(&packed).expect("tail header must parse");
        let generic: (Vec<u8>, usize, usize) =
            decode_image(&packed, &parsed).expect("generic decoder must accept the literal stream");
        assert_eq!(generic.0, b"a");
        let result: Result<UpxUnpackOutput> = unpack_upx(&packed);
        assert!(matches!(
            result,
            Err(Error::UpxDecode {
                stage: "elf-extents",
                ..
            })
        ));
    }

    #[test]
    fn valid_elf_with_a_false_extent_probe_falls_back_to_generic_upx_decode() {
        let mut packed: Vec<u8> = generic_elf_fixture(true);
        let header: UpxPackHeader = tail_pack_header(&packed).expect("tail header must parse");
        packed[header.header_offset + 12..header.header_offset + 16]
            .copy_from_slice(&header.u_len.to_le_bytes());
        let mutated: UpxPackHeader =
            tail_pack_header(&packed).expect("mutated tail header must parse");
        assert!(crate::elf::is_well_formed_elf_executable(&packed));
        assert!(elf_first_block_offset(&packed, mutated.u_len).is_some());
        let recovered: UpxUnpackOutput =
            unpack_upx(&packed).expect("a false extent probe must retain generic UPX recovery");
        assert_eq!(recovered.recovered_image, b"a");
    }

    #[test]
    fn valid_elf_with_a_corrupted_checksum_falls_back_to_generic_upx_decode() {
        let mut packed: Vec<u8> = generic_elf_fixture(true);
        let header: UpxPackHeader = tail_pack_header(&packed).expect("tail header must parse");
        packed[header.header_offset + 12..header.header_offset + 16]
            .copy_from_slice(&header.u_len.to_le_bytes());
        let mutated: UpxPackHeader =
            tail_pack_header(&packed).expect("mutated tail header must parse");
        assert!(crate::elf::is_well_formed_elf_executable(&packed));
        assert!(matching_compressed_starts(&packed, &mutated, packed.len()).is_empty());
        let recovered: UpxUnpackOutput =
            unpack_upx(&packed).expect("a corrupted checksum must retain generic UPX recovery");
        assert_eq!(recovered.recovered_image, b"a");
    }

    #[test]
    fn unaffordable_elf_extents_are_rejected_before_output_allocation() {
        let header: UpxPackHeader = header_with_lengths(65, 1, 1);
        let mut packed: Vec<u8> = vec![0u8; 20 + B_INFO_LEN + 65];
        packed[..UPX_MAGIC.len()].copy_from_slice(UPX_MAGIC);
        packed[12..16].copy_from_slice(&header.u_len.to_le_bytes());
        packed[20..24].copy_from_slice(&65u32.to_le_bytes());
        packed[24..28].copy_from_slice(&65u32.to_le_bytes());
        packed[28] = header.method.id();
        packed[32..].fill(b'a');
        assert!(elf_first_block_offset(&packed, header.u_len).is_some());
        assert!(!header.is_verification_affordable());
        assert!(decode_elf_extents(&packed, &header).is_none());
    }

    #[test]
    fn malformed_elf_program_headers_do_not_fall_back_to_generic_upx_decode() {
        let mut packed: Vec<u8> = generic_elf_fixture_with_layout(true, 56, 2);
        packed[120..124].copy_from_slice(&5u32.to_le_bytes());
        assert!(
            !crate::elf::is_well_formed_elf_executable(&packed),
            "an ELF with PT_SHLIB must not use generic UPX fallback"
        );
        let parsed: UpxPackHeader = tail_pack_header(&packed).expect("tail header must parse");
        let generic: (Vec<u8>, usize, usize) =
            decode_image(&packed, &parsed).expect("generic decoder must accept the literal stream");
        assert_eq!(generic.0, b"a");
        let result: Result<UpxUnpackOutput> = unpack_upx(&packed);
        assert!(matches!(
            result,
            Err(Error::UpxDecode {
                stage: "elf-extents",
                ..
            })
        ));
    }

    #[test]
    fn elf_with_header_mapping_and_later_load_falls_back_to_generic_upx_decode() {
        let mut packed: Vec<u8> = generic_elf_fixture_with_layout(true, 56, 3);
        let load: Vec<u8> = packed[64..120].to_vec();
        packed[120..176].copy_from_slice(&load);
        packed[64..68].copy_from_slice(&6u32.to_le_bytes());
        packed[72..80].copy_from_slice(&64u64.to_le_bytes());
        packed[80..88].copy_from_slice(&0x400040u64.to_le_bytes());
        packed[96..104].copy_from_slice(&168u64.to_le_bytes());
        packed[104..112].copy_from_slice(&168u64.to_le_bytes());
        packed[112..120].copy_from_slice(&8u64.to_le_bytes());
        packed[176..180].copy_from_slice(&1u32.to_le_bytes());
        packed[180..184].copy_from_slice(&5u32.to_le_bytes());
        packed[184..192].copy_from_slice(&240u64.to_le_bytes());
        packed[192..200].copy_from_slice(&0x401000u64.to_le_bytes());
        packed[200..208].copy_from_slice(&0x401000u64.to_le_bytes());
        packed[208..216].copy_from_slice(&1u64.to_le_bytes());
        packed[216..224].copy_from_slice(&1u64.to_le_bytes());
        packed[224..232].copy_from_slice(&1u64.to_le_bytes());
        let parsed: object::File<'_> =
            object::File::parse(&*packed).expect("fixture must parse as an ELF object");
        assert_eq!(parsed.format(), object::BinaryFormat::Elf);
        assert!(crate::elf::is_well_formed_elf_executable(&packed));
        let recovered: UpxUnpackOutput = unpack_upx(&packed)
            .expect("an ELF with a later unrelated load must retain generic UPX recovery");
        assert_eq!(recovered.recovered_image, b"a");
    }

    #[test]
    fn misaligned_elf_program_header_mapping_does_not_fall_back_to_generic_upx_decode() {
        let mut packed: Vec<u8> = generic_elf_fixture_with_layout(true, 56, 2);
        let load: Vec<u8> = packed[64..120].to_vec();
        packed[120..176].copy_from_slice(&load);
        packed[64..68].copy_from_slice(&6u32.to_le_bytes());
        packed[72..80].copy_from_slice(&64u64.to_le_bytes());
        packed[80..88].copy_from_slice(&0x400040u64.to_le_bytes());
        packed[96..104].copy_from_slice(&112u64.to_le_bytes());
        packed[104..112].copy_from_slice(&112u64.to_le_bytes());
        packed[112..120].copy_from_slice(&8u64.to_le_bytes());
        assert!(
            crate::elf::is_well_formed_elf_executable(&packed),
            "a correctly mapped PT_PHDR must retain generic UPX recovery"
        );
        let baseline: UpxUnpackOutput =
            unpack_upx(&packed).expect("mapped PT_PHDR fixture must recover through generic UPX");
        assert_eq!(baseline.recovered_image, b"a");
        packed[80..88].copy_from_slice(&0x400041u64.to_le_bytes());
        assert!(
            !crate::elf::is_well_formed_elf_executable(&packed),
            "a PT_PHDR virtual address outside the load translation must not use generic fallback"
        );
        let parsed: UpxPackHeader = tail_pack_header(&packed).expect("tail header must parse");
        let generic: (Vec<u8>, usize, usize) =
            decode_image(&packed, &parsed).expect("generic decoder must accept the literal stream");
        assert_eq!(generic.0, b"a");
        let result: Result<UpxUnpackOutput> = unpack_upx(&packed);
        assert!(matches!(
            result,
            Err(Error::UpxDecode {
                stage: "elf-extents",
                ..
            })
        ));
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
    fn decode_image_rejects_unaffordable_header_before_output_allocation() {
        let header: UpxPackHeader = header_with_lengths(65, 1, 1);
        let packed: Vec<u8> = vec![0u8; PACK_HEADER_LEN];
        let result: Result<(Vec<u8>, usize, usize)> = decode_image(&packed, &header);
        assert!(matches!(
            result,
            Err(Error::UpxDecode {
                stage: "block-stream",
                detail,
            }) if detail == "declared expansion exceeds the verification cap"
        ));
    }

    #[test]
    fn version_byte_is_not_a_locate_gate() {
        let tampered_version: UpxPackHeader = header_with_lengths(116_810, 49_950, 0xFF);
        assert!(tampered_version.is_length_consistent(usize::MAX));
        assert!(tampered_version.is_verification_affordable());
    }

    #[test]
    fn generic_budget_stops_affordable_brute_force_candidates() {
        let c_len: usize = MAX_DECOMPRESSED / MAX_VERIFY_EXPANSION as usize;
        let mut header: UpxPackHeader =
            header_with_lengths(MAX_DECOMPRESSED as u32, c_len as u32, 1);
        header.method = UpxMethod::Lzma;
        let packed: Vec<u8> = vec![0xff; c_len + MAX_BRUTE_FORCE_OFFSETS];
        header.c_adler = ucl_adler32(1, &packed[..c_len]);
        let mut budget: DecompressionBudget = DecompressionBudget::new();
        let result: Result<(Vec<u8>, usize, usize)> =
            decode_image_with_budget(&packed, &header, &mut budget);
        assert!(result.is_err());
        assert_eq!(budget.attempts(DecodeRoute::Generic), 1);
        assert_eq!(budget.remaining_output_bytes(DecodeRoute::Generic), 0);
    }

    #[test]
    fn checksum_matched_later_stream_skips_decoys() {
        let stream: [u8; 5] = [0, 0, 0, 0x80, b'a'];
        let mut header: UpxPackHeader = header_with_lengths(1, stream.len() as u32, 1);
        header.u_adler = ucl_adler32(1, b"a");
        header.c_adler = ucl_adler32(1, &stream);
        let mut packed: Vec<u8> = vec![0xff; 17];
        packed.extend_from_slice(&stream);
        packed.resize(packed.len() + 16, 0);
        assert_eq!(
            matching_compressed_starts(&packed, &header, packed.len()),
            vec![17]
        );
        let mut budget: DecompressionBudget =
            DecompressionBudget::with_quotas(DecodeQuota::new(0, 0), DecodeQuota::new(1, 1));
        let recovered: (Vec<u8>, usize, usize) =
            decode_image_with_budget(&packed, &header, &mut budget)
                .expect("matched later stream must use the sole generic attempt");
        assert_eq!(recovered.0, b"a");
        assert_eq!(recovered.1, 17);
        assert_eq!(budget.attempts(DecodeRoute::Generic), 1);
    }

    #[test]
    fn decode_image_cannot_read_beyond_declared_compressed_window() {
        let stream: [u8; 5] = [0, 0, 0, 0x80, b'a'];
        let mut header: UpxPackHeader = header_with_lengths(1, 4, 1);
        header.u_adler = ucl_adler32(1, b"a");
        header.c_adler = ucl_adler32(1, &stream[..4]);
        assert!(decode_image(&stream, &header).is_err());
    }

    #[test]
    fn block_chain_rejects_overexpanded_block_without_charging_budget() {
        let header: UpxPackHeader = header_with_lengths(65, 1, 1);
        let mut packed: Vec<u8> = vec![0u8; B_INFO_LEN + 1];
        packed[..4].copy_from_slice(&65u32.to_le_bytes());
        packed[4..8].copy_from_slice(&1u32.to_le_bytes());
        packed[8] = UpxMethod::Nrv2b.id();
        let mut budget: DecompressionBudget =
            DecompressionBudget::with_quotas(DecodeQuota::new(0, 0), DecodeQuota::new(1, 65));
        assert!(walk_block_chain(&packed, &header, 0, &mut budget, DecodeRoute::Generic).is_none());
        assert_eq!(budget.attempts(DecodeRoute::Generic), 0);
    }

    #[test]
    fn invalid_block_metadata_does_not_spend_the_next_recovery_attempt() {
        let mut header: UpxPackHeader = header_with_lengths(2, 2, 1);
        header.u_adler = ucl_adler32(1, b"ab");
        let mut packed: Vec<u8> = vec![0u8; 16 + B_INFO_LEN + 2];
        packed[..4].copy_from_slice(&2u32.to_le_bytes());
        packed[4..8].copy_from_slice(&1u32.to_le_bytes());
        packed[8] = 0xff;
        packed[16..20].copy_from_slice(&2u32.to_le_bytes());
        packed[20..24].copy_from_slice(&2u32.to_le_bytes());
        packed[24] = UpxMethod::Nrv2b.id();
        packed[28] = b'a';
        packed[29] = b'b';
        let mut budget: DecompressionBudget =
            DecompressionBudget::with_quotas(DecodeQuota::new(0, 0), DecodeQuota::new(1, 2));
        let recovered: (Vec<u8>, usize, usize) =
            decode_multiblock_with_budget(&packed, &header, &mut budget)
                .expect("later valid block must retain the sole generic attempt");
        assert_eq!(recovered.0, b"ab");
        assert_eq!(recovered.1, 16);
        assert_eq!(budget.attempts(DecodeRoute::Generic), 1);
    }

    #[test]
    fn structural_recovery_reuses_verified_stream() {
        let intact: Vec<u8> =
            include_bytes!("../../../../corpus/native/packers/upx/hello.packed.nrv2b.exe").to_vec();
        let header: UpxPackHeader =
            UpxPackHeader::locate_and_parse(&intact).expect("fixture header must parse");
        let baseline: UpxUnpackOutput = unpack_upx(&intact).expect("fixture must unpack");
        let mut scrambled: Vec<u8> = intact;
        for offset in 0..=scrambled.len() - UPX_MAGIC.len() {
            if scrambled[offset..offset + UPX_MAGIC.len()] == UPX_MAGIC[..] {
                scrambled[offset..offset + UPX_MAGIC.len()].copy_from_slice(b"ZZZZ");
            }
        }
        assert!(
            !scrambled
                .windows(UPX_MAGIC.len())
                .any(|window: &[u8]| window == UPX_MAGIC)
        );
        let mut budget: DecompressionBudget = DecompressionBudget::with_quotas(
            DecodeQuota::new(0, 0),
            DecodeQuota::new(1, header.u_len as usize),
        );
        let recovered: UpxUnpackOutput = unpack_upx_with_budget(&scrambled, &mut budget)
            .expect("structural locate must retain its sole verified decode");
        assert_eq!(recovered.recovered_image, baseline.recovered_image);
        assert_eq!(budget.attempts(DecodeRoute::Generic), 1);
    }

    #[test]
    fn route_quotas_preserve_generic_capacity_after_elf_extent_failure() {
        let mut budget: DecompressionBudget =
            DecompressionBudget::with_quotas(DecodeQuota::new(1, 1), DecodeQuota::new(1, 1));

        assert!(budget.reserve(DecodeRoute::ElfExtents, 1).is_some());
        assert!(budget.reserve(DecodeRoute::Generic, 1).is_some());
        assert!(budget.reserve(DecodeRoute::ElfExtents, 1).is_none());
        assert!(budget.reserve(DecodeRoute::Generic, 1).is_none());
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
