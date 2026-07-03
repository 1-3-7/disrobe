use std::io::Read;

use flate2::read::{DeflateDecoder, ZlibDecoder};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const MAGIC: &[u8; 6] = b"IDASGN";
const VERSION_MIN: u8 = 5;
const VERSION_MAX: u8 = 10;
const FEATURE_COMPRESSED: u16 = 0x10;
const VERSION_ZLIB_MIN: u8 = 7;
const MAX_DECOMPRESSED_BODY: usize = 256 * 1024 * 1024;
const MAX_PATTERN_LEN: u8 = 64;
const MAX_TREE_DEPTH: u32 = 256;
const CTYPE_LEN: usize = 12;
const LIBRARY_NAME_CAP: usize = 1024;

const PNAME_LOCAL: u8 = 0x02;
const PNAME_UNRESOLVED_COLLISION: u8 = 0x08;

const MORE_PUBLIC_NAMES: u8 = 0x01;
const READ_TAIL_BYTES: u8 = 0x02;
const READ_REFERENCED_FUNCTIONS: u8 = 0x04;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FlirtArch {
    X86,
    X86_64,
    Arm,
    Arm64,
    Mips,
    Ppc,
    Other(u8),
}

impl FlirtArch {
    #[must_use]
    pub const fn from_processor(b: u8) -> Self {
        match b {
            0 => Self::X86,
            6 => Self::Ppc,
            7 => Self::Mips,
            12 => Self::Arm,
            64 => Self::Arm64,
            _ => Self::Other(b),
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86-64",
            Self::Arm => "arm",
            Self::Arm64 => "arm64",
            Self::Mips => "mips",
            Self::Ppc => "ppc",
            Self::Other(_) => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlirtHeader {
    pub version: u8,
    pub arch: FlirtArch,
    pub file_types: u32,
    pub os_types: u16,
    pub app_types: u16,
    pub feature_flags: u16,
    pub old_n_functions: u16,
    pub crc16: u16,
    pub ctype: [u8; CTYPE_LEN],
    pub library_name: String,
    pub n_functions: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlirtPublicName {
    pub offset: u32,
    pub is_local: bool,
    pub is_collision: bool,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlirtPattern {
    pub bytes: Vec<u8>,
    pub variant_mask: u64,
    pub len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlirtModule {
    pub pattern: FlirtPattern,
    pub crc16_len: u8,
    pub crc16: u16,
    pub total_length: u32,
    pub public_names: Vec<FlirtPublicName>,
    pub tail_bytes: Vec<(u16, u8)>,
    pub referenced: Vec<FlirtPublicName>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlirtSig {
    pub header: FlirtHeader,
    pub modules: Vec<FlirtModule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlirtMatch {
    pub module_index: usize,
    pub image_offset: u64,
    pub name: String,
}

type PublicNameSection = (Vec<FlirtPublicName>, Vec<(u16, u8)>, Vec<FlirtPublicName>);

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end: usize = self.pos.checked_add(n).ok_or_else(|| Error::Truncated {
            needed: n,
            had: self.buf.len().saturating_sub(self.pos),
        })?;
        if end > self.buf.len() {
            return Err(Error::Truncated {
                needed: n,
                had: self.buf.len().saturating_sub(self.pos),
            });
        }
        let slice: &'a [u8] = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8> {
        let slice: &[u8] = self.take(1)?;
        Ok(slice[0])
    }

    fn u16_le(&mut self) -> Result<u16> {
        let slice: &[u8] = self.take(2)?;
        Ok(u16::from_le_bytes([slice[0], slice[1]]))
    }

    fn u32_le(&mut self) -> Result<u32> {
        let slice: &[u8] = self.take(4)?;
        Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    }

    fn u16_be(&mut self) -> Result<u16> {
        let slice: &[u8] = self.take(2)?;
        Ok(u16::from_be_bytes([slice[0], slice[1]]))
    }

    fn read_max_2_bytes(&mut self) -> Result<u16> {
        let b: u8 = self.u8()?;
        if b & 0x80 == 0 {
            return Ok(u16::from(b));
        }
        let next: u8 = self.u8()?;
        Ok((u16::from(b & 0x7f) << 8) | u16::from(next))
    }

    fn read_multiple_bytes(&mut self) -> Result<u32> {
        let b: u8 = self.u8()?;
        if b & 0x80 == 0 {
            return Ok(u32::from(b));
        }
        if b & 0xc0 != 0xc0 {
            let next: u8 = self.u8()?;
            return Ok((u32::from(b & 0x7f) << 8) | u32::from(next));
        }
        if b & 0xe0 != 0xe0 {
            let lo: u16 = self.u16_be()?;
            return Ok((u32::from(b & 0x3f) << 16) | u32::from(lo));
        }
        self.u32_le()
    }
}

fn parse_header(c: &mut Cursor) -> Result<FlirtHeader> {
    let magic: &[u8] = c.take(MAGIC.len())?;
    if magic != MAGIC {
        return Err(Error::SignatureDb("bad magic".into()));
    }
    let version: u8 = c.u8()?;
    if !(VERSION_MIN..=VERSION_MAX).contains(&version) {
        return Err(Error::SignatureDb(format!("unsupported version {version}")));
    }
    let processor: u8 = c.u8()?;
    let arch: FlirtArch = FlirtArch::from_processor(processor);
    let file_types: u32 = c.u32_le()?;
    let os_types: u16 = c.u16_le()?;
    let app_types: u16 = c.u16_le()?;
    let feature_flags: u16 = c.u16_le()?;
    let old_n_functions: u16 = c.u16_le()?;
    let crc16: u16 = c.u16_le()?;
    let ctype_slice: &[u8] = c.take(CTYPE_LEN)?;
    let mut ctype: [u8; CTYPE_LEN] = [0u8; CTYPE_LEN];
    ctype.copy_from_slice(ctype_slice);
    let library_name_sz: u8 = c.u8()?;
    let _alt_ctype_crc: u16 = c.u16_le()?;
    let n_functions: u32 = if version >= 6 { c.u32_le()? } else { 0 };
    if (8..=9).contains(&version) {
        let _pattern_size: u16 = c.u16_le()?;
    } else if version >= 10 {
        let _pattern_size: u16 = c.u16_le()?;
        let _unknown: u16 = c.u16_le()?;
    }
    let name_len: usize = usize::from(library_name_sz);
    if name_len > LIBRARY_NAME_CAP {
        return Err(Error::SignatureDb("library name too long".into()));
    }
    let name_slice: &[u8] = c.take(name_len)?;
    let library_name: String = String::from_utf8_lossy(name_slice).into_owned();
    Ok(FlirtHeader {
        version,
        arch,
        file_types,
        os_types,
        app_types,
        feature_flags,
        old_n_functions,
        crc16,
        ctype,
        library_name,
        n_functions,
    })
}

fn read_variant_mask(c: &mut Cursor, len: u8) -> Result<u64> {
    if len > MAX_PATTERN_LEN {
        return Err(Error::SignatureDb("pattern length out of range".into()));
    }
    if len < 16 {
        Ok(u64::from(c.read_max_2_bytes()?))
    } else if len <= 32 {
        Ok(u64::from(c.read_multiple_bytes()?))
    } else {
        let hi: u32 = c.read_multiple_bytes()?;
        let lo: u32 = c.read_multiple_bytes()?;
        Ok((u64::from(hi) << 32) | u64::from(lo))
    }
}

fn read_pattern(c: &mut Cursor, prefix: &FlirtPattern) -> Result<FlirtPattern> {
    let len: u8 = c.u8()?;
    if len > MAX_PATTERN_LEN {
        return Err(Error::SignatureDb("pattern length out of range".into()));
    }
    let variant_mask: u64 = read_variant_mask(c, len)?;
    let mut bytes: Vec<u8> = Vec::with_capacity(usize::from(len));
    for pos in 0..len {
        if variant_mask & (1u64 << pos) != 0 {
            bytes.push(0u8);
        } else {
            bytes.push(c.u8()?);
        }
    }
    let mut merged_bytes: Vec<u8> = Vec::with_capacity(prefix.bytes.len() + bytes.len());
    merged_bytes.extend_from_slice(&prefix.bytes);
    merged_bytes.extend_from_slice(&bytes);
    let prefix_bits: u32 = u32::from(prefix.len);
    let merged_mask: u64 = prefix.variant_mask | (variant_mask << prefix_bits);
    let merged_len: u8 = prefix.len.saturating_add(len);
    Ok(FlirtPattern {
        bytes: merged_bytes,
        variant_mask: merged_mask,
        len: merged_len,
    })
}

fn parse_public_names(c: &mut Cursor) -> Result<PublicNameSection> {
    let mut publics: Vec<FlirtPublicName> = Vec::new();
    let mut tail_bytes: Vec<(u16, u8)> = Vec::new();
    let mut referenced: Vec<FlirtPublicName> = Vec::new();
    loop {
        let offset: u32 = c.read_multiple_bytes()?;
        let mut is_local: bool = false;
        let mut is_collision: bool = false;
        let mut lead: u8 = c.u8()?;
        while lead < 0x20 {
            if lead & PNAME_LOCAL != 0 {
                is_local = true;
            }
            if lead & PNAME_UNRESOLVED_COLLISION != 0 {
                is_collision = true;
            }
            lead = c.u8()?;
        }
        let mut name_bytes: Vec<u8> = vec![lead];
        loop {
            let b: u8 = c.u8()?;
            if b < 0x20 {
                publics.push(FlirtPublicName {
                    offset,
                    is_local,
                    is_collision,
                    name: String::from_utf8_lossy(&name_bytes).into_owned(),
                });
                let flags: u8 = b;
                if flags & READ_TAIL_BYTES != 0 {
                    let count: u8 = c.u8()?;
                    for _ in 0..count {
                        let tail_off: u16 = c.read_max_2_bytes()?;
                        let value: u8 = c.u8()?;
                        tail_bytes.push((tail_off, value));
                    }
                }
                if flags & READ_REFERENCED_FUNCTIONS != 0 {
                    let count: u8 = c.u8()?;
                    for _ in 0..count {
                        let ref_off: u32 = c.read_multiple_bytes()?;
                        let name_len: u8 = c.u8()?;
                        let ref_name_bytes: &[u8] = c.take(usize::from(name_len))?;
                        referenced.push(FlirtPublicName {
                            offset: ref_off,
                            is_local: false,
                            is_collision: false,
                            name: String::from_utf8_lossy(ref_name_bytes).into_owned(),
                        });
                    }
                }
                if flags & MORE_PUBLIC_NAMES != 0 {
                    break;
                }
                return Ok((publics, tail_bytes, referenced));
            }
            name_bytes.push(b);
        }
    }
}

fn parse_leaf(c: &mut Cursor, pattern: &FlirtPattern, out: &mut Vec<FlirtModule>) -> Result<()> {
    let crc16_len: u8 = c.u8()?;
    let crc16: u16 = c.u16_be()?;
    let total_length: u32 = c.read_multiple_bytes()?;
    let (public_names, tail_bytes, referenced): PublicNameSection = parse_public_names(c)?;
    out.push(FlirtModule {
        pattern: pattern.clone(),
        crc16_len,
        crc16,
        total_length,
        public_names,
        tail_bytes,
        referenced,
    });
    Ok(())
}

fn parse_node(
    c: &mut Cursor,
    prefix: &FlirtPattern,
    out: &mut Vec<FlirtModule>,
    depth: u32,
) -> Result<()> {
    if depth > MAX_TREE_DEPTH {
        return Err(Error::SignatureDb(format!(
            "FLIRT tree nesting exceeds {MAX_TREE_DEPTH}-level depth cap"
        )));
    }
    let pattern: FlirtPattern = read_pattern(c, prefix)?;
    let child_count: u32 = c.read_multiple_bytes()?;
    if child_count == 0 {
        parse_leaf(c, &pattern, out)?;
    } else {
        for _ in 0..child_count {
            parse_node(c, &pattern, out, depth + 1)?;
        }
    }
    Ok(())
}

fn parse_tree(c: &mut Cursor, out: &mut Vec<FlirtModule>) -> Result<()> {
    let root_count: u32 = c.read_multiple_bytes()?;
    let root_prefix: FlirtPattern = FlirtPattern {
        bytes: Vec::new(),
        variant_mask: 0,
        len: 0,
    };
    for _ in 0..root_count {
        parse_node(c, &root_prefix, out, 0)?;
    }
    Ok(())
}

pub fn parse_flirt(bytes: &[u8]) -> Result<FlirtSig> {
    let mut c: Cursor = Cursor::new(bytes);
    let header: FlirtHeader = parse_header(&mut c)?;
    let mut modules: Vec<FlirtModule> = Vec::new();
    if header.feature_flags & FEATURE_COMPRESSED != 0 {
        let compressed: &[u8] = &bytes[c.pos..];
        let body: Vec<u8> = inflate_flirt_body(compressed, header.version)?;
        let mut body_cursor: Cursor = Cursor::new(&body);
        parse_tree(&mut body_cursor, &mut modules)?;
    } else {
        parse_tree(&mut c, &mut modules)?;
    }
    Ok(FlirtSig { header, modules })
}

fn inflate_flirt_body(compressed: &[u8], version: u8) -> Result<Vec<u8>> {
    inflate_flirt_body_with_limit(compressed, version, MAX_DECOMPRESSED_BODY)
}

fn inflate_flirt_body_with_limit(
    compressed: &[u8],
    version: u8,
    max_body: usize,
) -> Result<Vec<u8>> {
    let max_read: u64 = u64::try_from(max_body)
        .map_err(|_| Error::SignatureDb("FLIRT inflate cap exceeds u64".to_owned()))?
        .saturating_add(1u64);
    let mut out: Vec<u8> = Vec::new();
    let read_result: std::io::Result<usize> = if version >= VERSION_ZLIB_MIN {
        ZlibDecoder::new(compressed)
            .take(max_read)
            .read_to_end(&mut out)
    } else {
        DeflateDecoder::new(compressed)
            .take(max_read)
            .read_to_end(&mut out)
    };
    read_result.map_err(|e: std::io::Error| {
        Error::SignatureDb(format!("compressed FLIRT body inflate failed: {e}"))
    })?;
    if out.len() > max_body {
        return Err(Error::SignatureDb(format!(
            "compressed FLIRT body exceeds {max_body}-byte safety cap"
        )));
    }
    Ok(out)
}

#[must_use]
pub fn crc16_flirt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        let mut x: u16 = (crc ^ u16::from(b)) & 0x00FF;
        for _ in 0..8 {
            x = if x & 1 != 0 {
                (x >> 1) ^ 0x8408
            } else {
                x >> 1
            };
        }
        crc = (crc >> 8) ^ x;
    }
    crc.swap_bytes()
}

#[must_use]
pub fn match_flirt(sig: &FlirtSig, image: &[u8]) -> Vec<FlirtMatch> {
    let mut matches: Vec<FlirtMatch> = Vec::new();
    for (module_index, module) in sig.modules.iter().enumerate() {
        let pat_len: usize = module.pattern.bytes.len();
        let crc_len: usize = usize::from(module.crc16_len);
        let span: usize = pat_len + crc_len;
        if span == 0 || span > image.len() {
            continue;
        }
        for off in 0..=image.len() - span {
            let window: &[u8] = &image[off..off + pat_len];
            let mut pattern_ok: bool = true;
            for (i, &pat_byte) in module.pattern.bytes.iter().enumerate() {
                if module.pattern.variant_mask & (1u64 << i) != 0 {
                    continue;
                }
                if window[i] != pat_byte {
                    pattern_ok = false;
                    break;
                }
            }
            if !pattern_ok {
                continue;
            }
            let crc_region: &[u8] = &image[off + pat_len..off + pat_len + crc_len];
            if crc16_flirt(crc_region) != module.crc16 {
                continue;
            }
            for public in &module.public_names {
                matches.push(FlirtMatch {
                    module_index,
                    image_offset: off as u64 + u64::from(public.offset),
                    name: public.name.clone(),
                });
            }
        }
    }
    matches
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn read_multiple_bytes_one_byte_branch() {
        let buf: [u8; 1] = [0x42];
        let mut c: Cursor = Cursor::new(&buf);
        assert_eq!(c.read_multiple_bytes().unwrap(), 0x42);
    }

    #[test]
    fn read_multiple_bytes_two_byte_branch() {
        let buf: [u8; 2] = [0x81, 0x23];
        let mut c: Cursor = Cursor::new(&buf);
        assert_eq!(c.read_multiple_bytes().unwrap(), 0x0123);
    }

    #[test]
    fn read_multiple_bytes_four_byte_branch() {
        let buf: [u8; 3] = [0xc1, 0x23, 0x45];
        let mut c: Cursor = Cursor::new(&buf);
        assert_eq!(c.read_multiple_bytes().unwrap(), 0x0001_2345);
    }

    #[test]
    fn crc16_flirt_known_vector() {
        assert_eq!(crc16_flirt(&[0x55, 0x8B]), 0x2C67);
        assert_eq!(crc16_flirt(&[0x90, 0x90, 0x90, 0x90]), 0x43E9);
    }

    fn write_multiple_bytes(out: &mut Vec<u8>, value: u32) {
        if value < 0x80 {
            out.push(value as u8);
        } else if value < 0x4000 {
            out.push(0x80 | (value >> 8) as u8);
            out.push((value & 0xFF) as u8);
        } else if value < 0x2000_0000 {
            out.push(0xC0 | (value >> 16) as u8);
            out.push(((value >> 8) & 0xFF) as u8);
            out.push((value & 0xFF) as u8);
        } else {
            out.push(0xE0);
            out.extend_from_slice(&value.to_le_bytes());
        }
    }

    fn serialize_short_pattern(out: &mut Vec<u8>, bytes: &[u8]) {
        let len: u8 = bytes.len() as u8;
        assert!(len < 16, "test helper only emits short patterns");
        out.push(len);
        out.push(0);
        out.extend_from_slice(bytes);
    }

    fn serialize_leaf(out: &mut Vec<u8>, crc_len: u8, crc: u16, total: u32, name: &str, off: u32) {
        out.push(crc_len);
        out.extend_from_slice(&crc.to_be_bytes());
        write_multiple_bytes(out, total);
        write_multiple_bytes(out, off);
        out.push(0x00);
        out.extend_from_slice(name.as_bytes());
        out.push(0x00);
    }

    fn serialize_flirt_body() -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        write_multiple_bytes(&mut body, 2);
        serialize_short_pattern(&mut body, &[0x55, 0x8B, 0xEC]);
        write_multiple_bytes(&mut body, 0);
        serialize_leaf(
            &mut body,
            2,
            crc16_flirt(&[0x90, 0x90]),
            0x40,
            "first_func",
            0,
        );
        serialize_short_pattern(&mut body, &[0x53, 0x56, 0x57]);
        write_multiple_bytes(&mut body, 0);
        serialize_leaf(
            &mut body,
            4,
            crc16_flirt(&[0xCC; 4]),
            0x80,
            "second_func",
            4,
        );
        body
    }

    fn serialize_header(version: u8, feature_flags: u16, name: &str) -> Vec<u8> {
        let mut hdr: Vec<u8> = Vec::new();
        hdr.extend_from_slice(MAGIC);
        hdr.push(version);
        hdr.push(0);
        hdr.extend_from_slice(&0u32.to_le_bytes());
        hdr.extend_from_slice(&0u16.to_le_bytes());
        hdr.extend_from_slice(&0u16.to_le_bytes());
        hdr.extend_from_slice(&feature_flags.to_le_bytes());
        hdr.extend_from_slice(&0u16.to_le_bytes());
        hdr.extend_from_slice(&0u16.to_le_bytes());
        hdr.extend_from_slice(&[0u8; CTYPE_LEN]);
        hdr.push(name.len() as u8);
        hdr.extend_from_slice(&0u16.to_le_bytes());
        if version >= 6 {
            hdr.extend_from_slice(&2u32.to_le_bytes());
        }
        if (8..=9).contains(&version) {
            hdr.extend_from_slice(&0u16.to_le_bytes());
        } else if version >= 10 {
            hdr.extend_from_slice(&0u16.to_le_bytes());
            hdr.extend_from_slice(&0u16.to_le_bytes());
        }
        hdr.extend_from_slice(name.as_bytes());
        hdr
    }

    fn zlib_compress(raw: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc: flate2::write::ZlibEncoder<Vec<u8>> =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(raw).expect("zlib encode");
        enc.finish().expect("zlib finish")
    }

    fn raw_deflate_compress(raw: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc: flate2::write::DeflateEncoder<Vec<u8>> =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(raw).expect("deflate encode");
        enc.finish().expect("deflate finish")
    }

    #[test]
    fn uncompressed_sig_round_trips_two_modules() {
        let mut sig: Vec<u8> = serialize_header(7, 0, "libtest");
        sig.extend_from_slice(&serialize_flirt_body());
        let parsed: FlirtSig = parse_flirt(&sig).expect("uncompressed parse");
        assert_eq!(parsed.header.version, 7);
        assert_eq!(parsed.header.n_functions, 2);
        assert_eq!(parsed.modules.len(), 2);
        assert_eq!(parsed.modules[0].public_names[0].name, "first_func");
        assert_eq!(parsed.modules[0].pattern.bytes, vec![0x55, 0x8B, 0xEC]);
        assert_eq!(parsed.modules[1].public_names[0].name, "second_func");
    }

    #[test]
    fn zlib_compressed_v7_body_decodes_to_same_tree() {
        let body: Vec<u8> = serialize_flirt_body();
        let plain_sig: Vec<u8> = {
            let mut s: Vec<u8> = serialize_header(7, 0, "libtest");
            s.extend_from_slice(&body);
            s
        };
        let reference: FlirtSig = parse_flirt(&plain_sig).expect("uncompressed reference parse");
        let mut compressed_sig: Vec<u8> = serialize_header(7, FEATURE_COMPRESSED, "libtest");
        compressed_sig.extend_from_slice(&zlib_compress(&body));
        let recovered: FlirtSig = parse_flirt(&compressed_sig).expect("zlib compressed parse");
        assert_eq!(recovered.modules, reference.modules);
        assert!(recovered.header.feature_flags & FEATURE_COMPRESSED != 0);
    }

    #[test]
    fn raw_deflate_compressed_v6_body_decodes_to_same_tree() {
        let body: Vec<u8> = serialize_flirt_body();
        let plain_sig: Vec<u8> = {
            let mut s: Vec<u8> = serialize_header(6, 0, "libv6");
            s.extend_from_slice(&body);
            s
        };
        let reference: FlirtSig = parse_flirt(&plain_sig).expect("uncompressed v6 reference");
        let mut compressed_sig: Vec<u8> = serialize_header(6, FEATURE_COMPRESSED, "libv6");
        compressed_sig.extend_from_slice(&raw_deflate_compress(&body));
        let recovered: FlirtSig = parse_flirt(&compressed_sig).expect("raw-deflate v6 parse");
        assert_eq!(recovered.modules, reference.modules);
    }

    #[test]
    fn compressed_flag_uses_correct_bit_0x10() {
        assert_eq!(FEATURE_COMPRESSED, 0x10);
        let body: Vec<u8> = serialize_flirt_body();
        let mut sig_startup_bit: Vec<u8> = serialize_header(7, 0x01, "lib");
        sig_startup_bit.extend_from_slice(&body);
        let parsed: FlirtSig = parse_flirt(&sig_startup_bit)
            .expect("STARTUP (0x01) flag must not be mistaken for COMPRESSED");
        assert_eq!(parsed.modules.len(), 2);
    }

    #[test]
    fn corrupt_compressed_body_errors_not_panics() {
        let mut sig: Vec<u8> = serialize_header(7, FEATURE_COMPRESSED, "lib");
        sig.extend_from_slice(&[0x00, 0x01, 0x02, 0x03, 0x04]);
        let err: Error = parse_flirt(&sig).expect_err("garbage zlib body must error");
        match err {
            Error::SignatureDb(msg) => assert!(msg.contains("inflate")),
            other => panic!("expected SignatureDb inflate error, got {other:?}"),
        }
    }

    #[test]
    fn compressed_body_allows_exact_limit() {
        let raw: [u8; 4] = [1u8, 2u8, 3u8, 4u8];
        let compressed: Vec<u8> = zlib_compress(&raw);
        let inflated: Vec<u8> =
            inflate_flirt_body_with_limit(&compressed, VERSION_ZLIB_MIN, raw.len())
                .expect("exact cap body inflates");
        assert_eq!(inflated, raw);
    }

    #[test]
    fn compressed_body_rejects_sentinel_over_limit() {
        let raw: [u8; 5] = [1u8, 2u8, 3u8, 4u8, 5u8];
        let compressed: Vec<u8> = zlib_compress(&raw);
        let err: Error = inflate_flirt_body_with_limit(&compressed, VERSION_ZLIB_MIN, 4usize)
            .expect_err("over cap body must fail");
        match err {
            Error::SignatureDb(msg) => assert!(msg.contains("safety cap")),
            other => panic!("expected SignatureDb cap error, got {other:?}"),
        }
    }

    #[test]
    fn deeply_nested_tree_hits_depth_cap_without_stack_overflow() {
        let mut sig: Vec<u8> = serialize_header(7, 0, "deep");
        write_multiple_bytes(&mut sig, 1);
        let levels: u32 = MAX_TREE_DEPTH + 200;
        for _ in 0..levels {
            sig.push(0x00);
            sig.push(0x00);
            write_multiple_bytes(&mut sig, 1);
        }
        let start: std::time::Instant = std::time::Instant::now();
        let err: Error =
            parse_flirt(&sig).expect_err("a tree nested past the cap must error, not overflow");
        match err {
            Error::SignatureDb(msg) => assert!(
                msg.contains("depth cap"),
                "expected the depth-cap guard to fire, got: {msg}"
            ),
            other => panic!("expected SignatureDb depth-cap error, got {other:?}"),
        }
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "hostile recursion must bail fast, never hang"
        );
    }
}
