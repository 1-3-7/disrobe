use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

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
            3 => Some(Self::Nrv2d),
            6 => Some(Self::Nrv2e),
            14 => Some(Self::Lzma),
            _ => None,
        }
    }

    const fn id(self) -> u8 {
        match self {
            Self::Nrv2b => 2,
            Self::Nrv2d => 3,
            Self::Nrv2e => 6,
            Self::Lzma => 14,
        }
    }
}

const UPX_MAGIC: &[u8; 4] = b"UPX!";
const PACK_HEADER_LEN: usize = 32;
const B_INFO_LEN: usize = 12;
const MAX_DECOMPRESSED: usize = 256 * 1024 * 1024;

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
        loop {
            let Some(rel): Option<usize> = find_subslice(&packed[search_from..], UPX_MAGIC) else {
                return Err(Error::UpxDecode {
                    stage: "packheader",
                    detail: "no UPX! magic found in input".to_owned(),
                });
            };
            let offset: usize = search_from + rel;
            if let Some(header) = Self::parse_at(packed, offset) {
                return Ok(header);
            }
            search_from = offset + 1;
        }
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
    let header: UpxPackHeader = UpxPackHeader::locate_and_parse(packed)?;
    let (mut image, data_off): (Vec<u8>, usize) = decode_image(packed, &header)?;
    let adler_verified: bool = ucl_adler32(1, &image) == header.u_adler;
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
        block_count: 1,
        adler_verified,
    })
}

fn decode_image(packed: &[u8], header: &UpxPackHeader) -> Result<(Vec<u8>, usize)> {
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
                return Ok((out, start));
            }
        }
    }
    let scan_limit: usize = packed.len().saturating_sub(16);
    for start in 0..scan_limit {
        let Ok(out): Result<Vec<u8>> = decompress_block(header.method, &packed[start..], target)
        else {
            continue;
        };
        if out.len() == target && ucl_adler32(1, &out) == header.u_adler {
            return Ok((out, start));
        }
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

fn section_data_offset(packed: &[u8]) -> Option<usize> {
    if packed.len() < 0x40 || &packed[0..2] != b"MZ" {
        return None;
    }
    let pe_off: usize = u32::from_le_bytes([
        *packed.get(0x3c)?,
        *packed.get(0x3d)?,
        *packed.get(0x3e)?,
        *packed.get(0x3f)?,
    ]) as usize;
    if packed.get(pe_off..pe_off + 4)? != b"PE\0\0" {
        return None;
    }
    let coff: usize = pe_off + 4;
    let num_sections: usize =
        u16::from_le_bytes([*packed.get(coff + 2)?, *packed.get(coff + 3)?]) as usize;
    let opt_size: usize =
        u16::from_le_bytes([*packed.get(coff + 16)?, *packed.get(coff + 17)?]) as usize;
    let sect_table: usize = coff + 20 + opt_size;
    let mut best: Option<usize> = None;
    for i in 0..num_sections {
        let entry: usize = sect_table + i * 40;
        let raw_size: u32 = u32::from_le_bytes([
            *packed.get(entry + 16)?,
            *packed.get(entry + 17)?,
            *packed.get(entry + 18)?,
            *packed.get(entry + 19)?,
        ]);
        let raw_off: u32 = u32::from_le_bytes([
            *packed.get(entry + 20)?,
            *packed.get(entry + 21)?,
            *packed.get(entry + 22)?,
            *packed.get(entry + 23)?,
        ]);
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
            let raw: usize = ((m_off - 3) << 8) + byte;
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
            let raw: usize = ((m_off - 3) << 8) + byte;
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
            m_off = (m_off << 1) + bits.get_bit()? as usize;
        }
        let (m_off_final, mut m_len): (usize, usize) = if m_off == 2 {
            (last_m_off, bits.get_bit()? as usize)
        } else {
            let byte: usize = bits.next_byte()? as usize;
            let raw: usize = ((m_off - 3) << 8) + byte;
            if raw == 0xffff_ffff {
                break;
            }
            last_m_off = raw + 1;
            (raw + 1, raw & 1)
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
    if src.len() < 2 {
        return Err(Error::Truncated {
            needed: 2,
            had: src.len(),
        });
    }
    crate::packers::mpress_lzma::decode_mpress_lzma(src, out_len).map_err(|e| Error::UpxDecode {
        stage: "lzma",
        detail: e.to_string(),
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
        0x11 | 0x12 | 0x13 | 0x14 | 0x15 | 0x16 | 0x24 | 0x25 | 0x26 | 0x36 | 0x46 | 0x49 => {
            unfilter_ctok(code, filter_id, cto)
        }
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

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w: &[u8]| w == needle)
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
    fn nrv2b_eof_marker_terminates() {
        let mut stream: Vec<u8> = Vec::new();
        stream.extend_from_slice(&0x4000_0000u32.to_le_bytes());
        stream.push(0xff);
        let out: Result<Vec<u8>> = nrv2b_decompress(&stream, 64);
        assert!(out.is_ok() || matches!(out, Err(Error::Truncated { .. })));
    }
}
