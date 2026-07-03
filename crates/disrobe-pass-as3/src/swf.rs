use std::collections::BTreeMap;
use std::io::Read;

use serde::{Deserialize, Serialize};

use crate::debug::{dbg_hex, dbg_kv, dbg_line, dbg_section};
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SwfCompression {
    None,
    Zlib,
    Lzma,
}

impl SwfCompression {
    #[inline]
    #[must_use]
    pub const fn signature_byte(self) -> u8 {
        match self {
            Self::None => b'F',
            Self::Zlib => b'C',
            Self::Lzma => b'Z',
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Rect {
    pub x_min: i32,
    pub x_max: i32,
    pub y_min: i32,
    pub y_max: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwfHeader {
    pub compression: SwfCompression,
    pub version: u8,
    pub file_length: u32,
    pub frame_size: Rect,
    pub frame_rate_q8: u16,
    pub frame_count: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct TagCode(pub u16);

impl TagCode {
    pub const END: Self = Self(0);
    pub const SHOW_FRAME: Self = Self(1);
    pub const DEFINE_SHAPE: Self = Self(2);
    pub const SET_BACKGROUND_COLOR: Self = Self(9);
    pub const PROTECT: Self = Self(24);
    pub const DEFINE_SPRITE: Self = Self(39);
    pub const FRAME_LABEL: Self = Self(43);
    pub const EXPORT_ASSETS: Self = Self(56);
    pub const ENABLE_DEBUGGER: Self = Self(58);
    pub const ENABLE_DEBUGGER2: Self = Self(64);
    pub const SCRIPT_LIMITS: Self = Self(65);
    pub const FILE_ATTRIBUTES: Self = Self(69);
    pub const DO_ABC_DEFINE: Self = Self(72);
    pub const SYMBOL_CLASS: Self = Self(76);
    pub const METADATA: Self = Self(77);
    pub const DO_ABC: Self = Self(82);
    pub const DEFINE_SCENE_AND_FRAME_LABEL_DATA: Self = Self(86);
    pub const DEFINE_BINARY_DATA: Self = Self(87);

    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self.0 {
            0 => "End",
            1 => "ShowFrame",
            2 => "DefineShape",
            4 => "PlaceObject",
            5 => "RemoveObject",
            6 => "DefineBitsJPEG",
            7 => "DefineButton",
            8 => "JPEGTables",
            9 => "SetBackgroundColor",
            10 => "DefineFont",
            11 => "DefineText",
            12 => "DoAction",
            13 => "DefineFontInfo",
            14 => "DefineSound",
            18 => "SoundStreamHead",
            20 => "DefineBitsLossless",
            21 => "DefineBitsJPEG2",
            22 => "DefineShape2",
            24 => "Protect",
            26 => "PlaceObject2",
            28 => "RemoveObject2",
            32 => "DefineShape3",
            33 => "DefineText2",
            34 => "DefineButton2",
            35 => "DefineBitsJPEG3",
            37 => "DefineEditText",
            39 => "DefineSprite",
            43 => "FrameLabel",
            45 => "SoundStreamHead2",
            48 => "DefineFont2",
            56 => "ExportAssets",
            57 => "ImportAssets",
            58 => "EnableDebugger",
            59 => "DoInitAction",
            60 => "DefineVideoStream",
            64 => "EnableDebugger2",
            65 => "ScriptLimits",
            69 => "FileAttributes",
            70 => "PlaceObject3",
            71 => "ImportAssets2",
            72 => "DoABCDefine",
            73 => "DefineFontAlignZones",
            74 => "CSMTextSettings",
            75 => "DefineFont3",
            76 => "SymbolClass",
            77 => "Metadata",
            78 => "DefineScalingGrid",
            82 => "DoABC",
            83 => "DefineShape4",
            86 => "DefineSceneAndFrameLabelData",
            87 => "DefineBinaryData",
            88 => "DefineFontName",
            89 => "StartSound2",
            90 => "DefineBitsJPEG4",
            91 => "DefineFont4",
            _ => "Unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwfTag {
    pub code: TagCode,
    pub offset: usize,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefineSprite {
    pub character_id: u16,
    pub frame_count: u16,
    pub tags: Vec<SwfTag>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoAbc {
    pub flags: u32,
    pub name: String,
    pub abc_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolClassEntry {
    pub character_id: u16,
    pub class_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileAttributes {
    pub use_direct_blit: bool,
    pub use_gpu: bool,
    pub has_metadata: bool,
    pub action_script3: bool,
    pub use_network: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Swf {
    pub header: SwfHeader,
    pub tags: Vec<SwfTag>,
}

impl Swf {
    #[must_use]
    pub fn tag_counts(&self) -> BTreeMap<TagCode, usize> {
        let mut out: BTreeMap<TagCode, usize> = BTreeMap::new();
        Self::accumulate_counts(&self.tags, &mut out, MAX_SPRITE_NESTING);
        out
    }

    fn accumulate_counts(tags: &[SwfTag], out: &mut BTreeMap<TagCode, usize>, depth_budget: usize) {
        for tag in tags {
            *out.entry(tag.code).or_insert(0) += 1;
            if tag.code == TagCode::DEFINE_SPRITE
                && depth_budget > 0
                && let Ok(sprite) = parse_define_sprite(tag)
            {
                Self::accumulate_counts(&sprite.tags, out, depth_budget - 1);
            }
        }
    }

    #[must_use]
    pub fn collect_do_abc(&self) -> Vec<DoAbc> {
        let mut out: Vec<DoAbc> = Vec::new();
        for tag in &self.tags {
            match tag.code {
                TagCode::DO_ABC => {
                    if let Ok(blob) = parse_do_abc(tag) {
                        out.push(blob);
                    }
                }
                TagCode::DO_ABC_DEFINE => {
                    if let Ok(blob) = parse_do_abc_legacy(tag) {
                        out.push(blob);
                    }
                }
                _ => {}
            }
        }
        out
    }

    #[must_use]
    pub fn file_attributes(&self) -> Option<FileAttributes> {
        self.tags
            .iter()
            .find(|t: &&SwfTag| t.code == TagCode::FILE_ATTRIBUTES)
            .and_then(|t: &SwfTag| parse_file_attributes(t).ok())
    }

    #[must_use]
    pub fn symbol_classes(&self) -> Vec<SymbolClassEntry> {
        self.tags
            .iter()
            .filter(|t: &&SwfTag| t.code == TagCode::SYMBOL_CLASS)
            .filter_map(|t: &SwfTag| parse_symbol_class(t).ok())
            .flatten()
            .collect()
    }
}

const MAX_SPRITE_NESTING: usize = 256;

const MAX_SWF_VERSION: u8 = 40;

const MAX_DECOMPRESSED_BODY: u64 = 512 * 1024 * 1024;

const MAX_LZMA_MEMLIMIT: u64 = 256 * 1024 * 1024;

const MAX_DECOMPRESS_PREALLOC: usize = 4 * 1024 * 1024;

const DECOMPRESS_PREALLOC_RATIO: usize = 4;

const DECOMPRESS_PREALLOC_FLOOR: usize = 1024;

#[must_use]
pub fn detect(bytes: &[u8]) -> Option<SwfCompression> {
    if bytes.len() < 3 {
        return None;
    }
    match (bytes[0], bytes[1], bytes[2]) {
        (b'F', b'W', b'S') => Some(SwfCompression::None),
        (b'C', b'W', b'S') => Some(SwfCompression::Zlib),
        (b'Z', b'W', b'S') => Some(SwfCompression::Lzma),
        _ => None,
    }
}

pub fn parse(bytes: &[u8]) -> Result<Swf> {
    dbg_section("swf.parse");
    dbg_kv("input_len", || bytes.len().to_string());
    dbg_hex("swf.header", bytes, 16);
    if bytes.len() < 8 {
        dbg_line(|| format!("wall: header truncated, have {} need 8", bytes.len()));
        return Err(Error::SwfTruncated {
            offset: 0,
            needed: 8,
            had: bytes.len(),
        });
    }
    let sig: [u8; 3] = [bytes[0], bytes[1], bytes[2]];
    let compression: SwfCompression = match sig {
        [b'F', b'W', b'S'] => SwfCompression::None,
        [b'C', b'W', b'S'] => SwfCompression::Zlib,
        [b'Z', b'W', b'S'] => SwfCompression::Lzma,
        other => {
            dbg_line(|| format!("wall: bad signature {other:02x?}"));
            return Err(Error::BadSwfSignature(other));
        }
    };
    dbg_kv("compression", || format!("{compression:?}"));
    let version: u8 = bytes[3];
    if version == 0 || version > MAX_SWF_VERSION {
        dbg_line(|| format!("wall: unsupported version {version}"));
        return Err(Error::SwfUnsupportedVersion(version));
    }
    dbg_kv("version", || version.to_string());
    let file_length: u32 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    dbg_kv("file_length", || file_length.to_string());

    let body: Vec<u8> = decompress_body(compression, &bytes[8..], file_length)?;
    dbg_kv("body_len", || body.len().to_string());
    let mut r: BitReader<'_> = BitReader::new(&body);
    let frame_size: Rect = parse_rect(&mut r)?;
    r.align();
    let frame_rate_q8: u16 = r.read_u16_le()?;
    let frame_count: u16 = r.read_u16_le()?;
    dbg_kv("frame_count", || frame_count.to_string());

    let mut tags: Vec<SwfTag> = Vec::new();
    let body_start: usize = 8;
    loop {
        let tag_offset: usize = body_start + r.byte_pos();
        let tag: SwfTag = read_tag(&mut r, tag_offset)?;
        let end_reached: bool = tag.code == TagCode::END;
        tags.push(tag);
        if end_reached {
            break;
        }
    }
    dbg_kv("tag_count", || tags.len().to_string());
    Ok(Swf {
        header: SwfHeader {
            compression,
            version,
            file_length,
            frame_size,
            frame_rate_q8,
            frame_count,
        },
        tags,
    })
}

fn read_bounded<R: Read>(
    reader: R,
    ceiling: u64,
    kind: &'static str,
    hint: usize,
    compressed_len: usize,
) -> Result<Vec<u8>> {
    let ceiling_hint: usize = u64_to_usize_saturating(ceiling);
    let cap: usize = compressed_body_capacity_hint(compressed_len, hint.min(ceiling_hint));
    let mut out: Vec<u8> = Vec::with_capacity(cap);
    let read_len: usize = reader
        .take(ceiling.saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|e: std::io::Error| Error::SwfDecompress {
            kind,
            message: e.to_string(),
        })?;
    let read: u64 = match u64::try_from(read_len) {
        Ok(value) => value,
        Err(_) => {
            return Err(Error::SwfDecompress {
                kind,
                message: "decompressed output length exceeds u64".to_owned(),
            });
        }
    };
    if read > ceiling {
        return Err(Error::SwfDecompress {
            kind,
            message: format!("decompressed output exceeds {MAX_DECOMPRESSED_BODY}-byte ceiling"),
        });
    }
    Ok(out)
}

#[inline]
fn compressed_body_capacity_hint(compressed_len: usize, declared_hint: usize) -> usize {
    let compressed_hint: usize = compressed_len
        .saturating_mul(DECOMPRESS_PREALLOC_RATIO)
        .clamp(DECOMPRESS_PREALLOC_FLOOR, MAX_DECOMPRESS_PREALLOC);
    let chosen: usize = declared_hint.min(compressed_hint);
    dbg_kv("prealloc_clamp", || {
        format!(
            "compressed={compressed_len} declared={declared_hint} compressed_hint={compressed_hint} chosen={chosen}"
        )
    });
    chosen
}

#[inline]
fn swf_declared_body_len(file_length: u32) -> usize {
    u64_to_usize_saturating(u64::from(file_length).saturating_sub(8))
}

#[inline]
fn u64_to_usize_saturating(value: u64) -> usize {
    usize::try_from(value).map_or(usize::MAX, |out: usize| out)
}

fn decompress_body(
    compression: SwfCompression,
    payload: &[u8],
    file_length: u32,
) -> Result<Vec<u8>> {
    dbg_kv("decompress", || {
        format!("kind={compression:?} compressed_len={}", payload.len())
    });
    match compression {
        SwfCompression::None => read_uncompressed_body(payload, file_length),
        SwfCompression::Zlib => {
            let decoder: flate2::read::ZlibDecoder<&[u8]> = flate2::read::ZlibDecoder::new(payload);
            let declared_len: usize = swf_declared_body_len(file_length);
            read_bounded(
                decoder,
                MAX_DECOMPRESSED_BODY,
                "zlib",
                declared_len,
                payload.len(),
            )
        }
        SwfCompression::Lzma => {
            if payload.len() < 9 {
                return Err(Error::SwfDecompress {
                    kind: "lzma",
                    message: "header too short".to_owned(),
                });
            }
            let props: &[u8] = &payload[4..9];
            let stream: &[u8] = &payload[9..];
            let mut raw: Vec<u8> = Vec::with_capacity(props.len() + 8 + stream.len());
            raw.extend_from_slice(props);
            let uncompressed_size: u64 = u64::from(file_length).saturating_sub(8);
            raw.extend_from_slice(&uncompressed_size.to_le_bytes());
            raw.extend_from_slice(stream);
            let lzma_stream: liblzma::stream::Stream = liblzma::stream::Stream::new_lzma_decoder(
                MAX_LZMA_MEMLIMIT,
            )
            .map_err(|e: liblzma::stream::Error| Error::SwfDecompress {
                kind: "lzma",
                message: e.to_string(),
            })?;
            let decoder: liblzma::read::XzDecoder<&[u8]> =
                liblzma::read::XzDecoder::new_stream(&raw[..], lzma_stream);
            let hint: usize = u64_to_usize_saturating(uncompressed_size.min(MAX_DECOMPRESSED_BODY));
            read_bounded(decoder, MAX_DECOMPRESSED_BODY, "lzma", hint, payload.len())
        }
    }
}

fn read_uncompressed_body(payload: &[u8], file_length: u32) -> Result<Vec<u8>> {
    let declared_len: usize = swf_declared_body_len(file_length);
    let ceiling: usize = u64_to_usize_saturating(MAX_DECOMPRESSED_BODY);
    if declared_len > ceiling || payload.len() > ceiling {
        return Err(Error::SwfDecompress {
            kind: "uncompressed",
            message: format!("uncompressed output exceeds {MAX_DECOMPRESSED_BODY}-byte ceiling"),
        });
    }
    if declared_len > payload.len() {
        return Err(Error::SwfTruncated {
            offset: 8,
            needed: declared_len,
            had: payload.len(),
        });
    }
    Ok(payload.to_vec())
}

struct BitReader<'a> {
    bytes: &'a [u8],
    byte_pos: usize,
    bit_pos: u8,
}

impl<'a> BitReader<'a> {
    #[inline]
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    #[inline]
    fn byte_pos(&self) -> usize {
        self.byte_pos
    }

    #[inline]
    fn align(&mut self) {
        if self.bit_pos != 0 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
    }

    fn read_ub(&mut self, n: u8) -> Result<u32> {
        let mut acc: u32 = 0;
        let mut remaining: u8 = n;
        while remaining > 0 {
            if self.byte_pos >= self.bytes.len() {
                return Err(Error::SwfTruncated {
                    offset: self.byte_pos,
                    needed: 1,
                    had: 0,
                });
            }
            let avail: u8 = 8 - self.bit_pos;
            let take: u8 = remaining.min(avail);
            let byte: u8 = self.bytes[self.byte_pos];
            let shift: u8 = avail - take;
            let mask: u8 = u8::try_from((1u16 << take) - 1).unwrap_or(u8::MAX);
            let chunk: u8 = (byte >> shift) & mask;
            acc = (acc << take) | u32::from(chunk);
            self.bit_pos += take;
            if self.bit_pos == 8 {
                self.bit_pos = 0;
                self.byte_pos += 1;
            }
            remaining -= take;
        }
        Ok(acc)
    }

    fn read_sb(&mut self, n: u8) -> Result<i32> {
        if n == 0 {
            return Ok(0);
        }
        let raw: u32 = self.read_ub(n)?;
        let shift: u32 = 32 - u32::from(n);
        Ok((raw << shift).cast_signed() >> shift)
    }

    fn need_bytes(&self, n: usize) -> Result<()> {
        let avail: usize = self.bytes.len().saturating_sub(self.byte_pos);
        if avail < n {
            return Err(Error::SwfTruncated {
                offset: self.byte_pos,
                needed: n,
                had: avail,
            });
        }
        Ok(())
    }

    fn read_u16_le(&mut self) -> Result<u16> {
        self.align();
        self.need_bytes(2)?;
        let v: u16 = u16::from_le_bytes([self.bytes[self.byte_pos], self.bytes[self.byte_pos + 1]]);
        self.byte_pos += 2;
        Ok(v)
    }

    fn read_u32_le(&mut self) -> Result<u32> {
        self.align();
        self.need_bytes(4)?;
        let v: u32 = u32::from_le_bytes([
            self.bytes[self.byte_pos],
            self.bytes[self.byte_pos + 1],
            self.bytes[self.byte_pos + 2],
            self.bytes[self.byte_pos + 3],
        ]);
        self.byte_pos += 4;
        Ok(v)
    }

    fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        self.align();
        self.need_bytes(n)?;
        let out: Vec<u8> = self.bytes[self.byte_pos..self.byte_pos + n].to_vec();
        self.byte_pos += n;
        Ok(out)
    }
}

fn parse_rect(r: &mut BitReader<'_>) -> Result<Rect> {
    let nbits: u32 = r.read_ub(5)?;
    if nbits > 31 {
        return Err(Error::BadRect(r.byte_pos()));
    }
    let nb: u8 = u8::try_from(nbits).map_err(|_| Error::BadRect(r.byte_pos()))?;
    let x_min: i32 = r.read_sb(nb)?;
    let x_max: i32 = r.read_sb(nb)?;
    let y_min: i32 = r.read_sb(nb)?;
    let y_max: i32 = r.read_sb(nb)?;
    Ok(Rect {
        x_min,
        x_max,
        y_min,
        y_max,
    })
}

fn read_tag(r: &mut BitReader<'_>, offset: usize) -> Result<SwfTag> {
    let header: u16 = r.read_u16_le()?;
    let code: u16 = header >> 6;
    let short_len: u16 = header & 0x3F;
    let length: u32 = if short_len == 0x3F {
        r.read_u32_le()?
    } else {
        u32::from(short_len)
    };
    let payload: Vec<u8> = r.read_bytes(length as usize).map_err(|_| Error::BadTag {
        offset,
        reason: "payload exceeds remaining buffer",
    })?;
    Ok(SwfTag {
        code: TagCode(code),
        offset,
        payload,
    })
}

pub fn parse_define_sprite(tag: &SwfTag) -> Result<DefineSprite> {
    if tag.code != TagCode::DEFINE_SPRITE {
        return Err(Error::BadTag {
            offset: tag.offset,
            reason: "not a DefineSprite tag",
        });
    }
    if tag.payload.len() < 4 {
        return Err(Error::SwfTruncated {
            offset: tag.offset,
            needed: 4,
            had: tag.payload.len(),
        });
    }
    let character_id: u16 = u16::from_le_bytes([tag.payload[0], tag.payload[1]]);
    let frame_count: u16 = u16::from_le_bytes([tag.payload[2], tag.payload[3]]);
    let mut r: BitReader<'_> = BitReader::new(&tag.payload[4..]);
    let mut tags: Vec<SwfTag> = Vec::new();
    loop {
        let nested_offset: usize = tag.offset + 4 + r.byte_pos();
        let nested: SwfTag = read_tag(&mut r, nested_offset)?;
        let end_reached: bool = nested.code == TagCode::END;
        tags.push(nested);
        if end_reached {
            break;
        }
    }
    Ok(DefineSprite {
        character_id,
        frame_count,
        tags,
    })
}

pub fn parse_do_abc(tag: &SwfTag) -> Result<DoAbc> {
    if tag.code != TagCode::DO_ABC {
        return Err(Error::BadTag {
            offset: tag.offset,
            reason: "not a DoABC tag",
        });
    }
    if tag.payload.len() < 4 {
        return Err(Error::SwfTruncated {
            offset: tag.offset,
            needed: 4,
            had: tag.payload.len(),
        });
    }
    let flags: u32 = u32::from_le_bytes([
        tag.payload[0],
        tag.payload[1],
        tag.payload[2],
        tag.payload[3],
    ]);
    let name_start: usize = 4;
    let mut name_end: usize = name_start;
    while name_end < tag.payload.len() && tag.payload[name_end] != 0 {
        name_end += 1;
    }
    if name_end >= tag.payload.len() {
        return Err(Error::BadTag {
            offset: tag.offset,
            reason: "DoABC name not null-terminated",
        });
    }
    let name: String = String::from_utf8_lossy(&tag.payload[name_start..name_end]).into_owned();
    let abc_bytes: Vec<u8> = tag.payload[name_end + 1..].to_vec();
    Ok(DoAbc {
        flags,
        name,
        abc_bytes,
    })
}

pub fn parse_do_abc_legacy(tag: &SwfTag) -> Result<DoAbc> {
    if tag.code != TagCode::DO_ABC_DEFINE {
        return Err(Error::BadTag {
            offset: tag.offset,
            reason: "not a DoABCDefine tag",
        });
    }
    Ok(DoAbc {
        flags: 0,
        name: String::new(),
        abc_bytes: tag.payload.clone(),
    })
}

pub fn parse_symbol_class(tag: &SwfTag) -> Result<Vec<SymbolClassEntry>> {
    if tag.code != TagCode::SYMBOL_CLASS {
        return Err(Error::BadTag {
            offset: tag.offset,
            reason: "not a SymbolClass tag",
        });
    }
    if tag.payload.len() < 2 {
        return Err(Error::SwfTruncated {
            offset: tag.offset,
            needed: 2,
            had: tag.payload.len(),
        });
    }
    let count: u16 = u16::from_le_bytes([tag.payload[0], tag.payload[1]]);
    let remaining: usize = tag.payload.len() - 2;
    let count_usize: usize = usize::from(count);
    if count_usize > remaining / 3 {
        return Err(Error::BadTag {
            offset: tag.offset,
            reason: "SymbolClass count exceeds payload",
        });
    }
    let mut out: Vec<SymbolClassEntry> = Vec::with_capacity(count_usize);
    let mut cursor: usize = 2;
    for _ in 0..count_usize {
        if cursor + 2 > tag.payload.len() {
            return Err(Error::SwfTruncated {
                offset: tag.offset + cursor,
                needed: 2,
                had: tag.payload.len() - cursor,
            });
        }
        let character_id: u16 = u16::from_le_bytes([tag.payload[cursor], tag.payload[cursor + 1]]);
        cursor += 2;
        let start: usize = cursor;
        while cursor < tag.payload.len() && tag.payload[cursor] != 0 {
            cursor += 1;
        }
        if cursor >= tag.payload.len() {
            return Err(Error::BadTag {
                offset: tag.offset + start,
                reason: "SymbolClass name not null-terminated",
            });
        }
        let class_name: String = String::from_utf8_lossy(&tag.payload[start..cursor]).into_owned();
        cursor += 1;
        out.push(SymbolClassEntry {
            character_id,
            class_name,
        });
    }
    Ok(out)
}

pub fn parse_file_attributes(tag: &SwfTag) -> Result<FileAttributes> {
    if tag.code != TagCode::FILE_ATTRIBUTES {
        return Err(Error::BadTag {
            offset: tag.offset,
            reason: "not a FileAttributes tag",
        });
    }
    if tag.payload.len() < 4 {
        return Err(Error::SwfTruncated {
            offset: tag.offset,
            needed: 4,
            had: tag.payload.len(),
        });
    }
    let flags: u8 = tag.payload[0];
    Ok(FileAttributes {
        use_direct_blit: (flags & 0b0100_0000) != 0,
        use_gpu: (flags & 0b0010_0000) != 0,
        has_metadata: (flags & 0b0001_0000) != 0,
        action_script3: (flags & 0b0000_1000) != 0,
        use_network: (flags & 0b0000_0001) != 0,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Write;

    fn build_minimal_swf_body() -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        body.push(0x08);
        body.push(0x00);
        body.extend_from_slice(&24_u16.to_le_bytes());
        body.extend_from_slice(&1_u16.to_le_bytes());
        let end_header: u16 = 0;
        body.extend_from_slice(&end_header.to_le_bytes());
        body
    }

    fn build_minimal_swf() -> Vec<u8> {
        let body: Vec<u8> = build_minimal_swf_body();
        let mut swf: Vec<u8> = Vec::new();
        swf.extend_from_slice(b"FWS");
        swf.push(10);
        let file_length: u32 = u32::try_from(8 + body.len()).expect("test fixture fits in u32");
        swf.extend_from_slice(&file_length.to_le_bytes());
        swf.extend_from_slice(&body);
        swf
    }

    fn set_file_length(bytes: &mut [u8], file_length: u32) {
        bytes[4..8].copy_from_slice(&file_length.to_le_bytes());
    }

    fn zlib_compress(bytes: &[u8]) -> Vec<u8> {
        let mut encoder: flate2::write::ZlibEncoder<Vec<u8>> =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        encoder
            .write_all(bytes)
            .expect("test fixture zlib write succeeds");
        encoder.finish().expect("test fixture zlib finish succeeds")
    }

    #[test]
    fn detect_signatures() {
        assert_eq!(detect(b"FWS\x0a"), Some(SwfCompression::None));
        assert_eq!(detect(b"CWS\x0a"), Some(SwfCompression::Zlib));
        assert_eq!(detect(b"ZWS\x0d"), Some(SwfCompression::Lzma));
        assert_eq!(detect(b"???"), None);
    }

    #[test]
    fn parse_minimal_uncompressed_swf() {
        let bytes: Vec<u8> = build_minimal_swf();
        let swf: Swf = parse(&bytes).expect("parse should succeed");
        assert_eq!(swf.header.compression, SwfCompression::None);
        assert_eq!(swf.header.version, 10);
        assert_eq!(swf.header.frame_count, 1);
        assert!(swf.tags.iter().any(|t| t.code == TagCode::END));
    }

    #[test]
    fn rejects_bad_signature() {
        let bytes: [u8; 8] = *b"XYZ\x0a\x00\x00\x00\x00";
        let err: Error = parse(&bytes).expect_err("bad signature must fail");
        assert!(matches!(err, Error::BadSwfSignature(_)));
    }

    #[test]
    fn rejects_truncated_header() {
        let bytes: [u8; 3] = *b"FWS";
        let err: Error = parse(&bytes).expect_err("truncated header must fail");
        assert!(matches!(err, Error::SwfTruncated { .. }));
    }

    #[test]
    fn cws_huge_file_length_uses_compressed_capacity_hint() {
        let body: Vec<u8> = build_minimal_swf_body();
        let compressed: Vec<u8> = zlib_compress(&body);
        assert!(compressed.len() < 64, "fixture must stay tiny");

        let hint: usize = compressed_body_capacity_hint(compressed.len(), usize::MAX);
        assert_eq!(hint, DECOMPRESS_PREALLOC_FLOOR);

        let mut bytes: Vec<u8> = Vec::with_capacity(8 + compressed.len());
        bytes.extend_from_slice(b"CWS");
        bytes.push(10);
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        bytes.extend_from_slice(&compressed);

        let swf: Swf = parse(&bytes).expect("huge declared length must not drive allocation");
        assert_eq!(swf.header.compression, SwfCompression::Zlib);
        assert_eq!(swf.header.file_length, u32::MAX);
        assert_eq!(swf.header.frame_count, 1);
        assert!(swf.tags.iter().any(|t: &SwfTag| t.code == TagCode::END));
    }

    #[test]
    fn fws_declared_body_past_cap_is_rejected() {
        let mut bytes: Vec<u8> = build_minimal_swf();
        set_file_length(&mut bytes, u32::MAX);
        let err: Error = parse(&bytes).expect_err("huge FWS declared body must reject");
        assert!(
            matches!(
                err,
                Error::SwfDecompress {
                    kind: "uncompressed",
                    ..
                }
            ),
            "got {err}"
        );
    }

    #[test]
    fn swf_missing_end_tag_is_rejected() {
        let mut bytes: Vec<u8> = build_minimal_swf();
        bytes.truncate(bytes.len() - 2);
        let file_length: u32 = u32::try_from(bytes.len()).expect("test fixture fits in u32");
        set_file_length(&mut bytes, file_length);
        let err: Error = parse(&bytes).expect_err("missing End tag must reject");
        assert!(matches!(err, Error::SwfTruncated { .. }), "got {err}");
    }

    #[test]
    fn define_sprite_missing_end_tag_is_rejected() {
        let tag: SwfTag = SwfTag {
            code: TagCode::DEFINE_SPRITE,
            offset: 0,
            payload: vec![1, 0, 1, 0],
        };
        let err: Error = parse_define_sprite(&tag).expect_err("missing nested End tag must reject");
        assert!(matches!(err, Error::SwfTruncated { .. }), "got {err}");
    }

    fn encode_long_tag(code: u16, payload: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(payload.len() + 6);
        let header: u16 = (code << 6) | 0x3F;
        out.extend_from_slice(&header.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn nested_sprite_bomb(depth: usize) -> SwfTag {
        let mut inner: Vec<u8> = Vec::new();
        inner.extend_from_slice(&1_u16.to_le_bytes());
        inner.extend_from_slice(&1_u16.to_le_bytes());
        for _ in 0..depth {
            let mut payload: Vec<u8> = Vec::with_capacity(inner.len() + 4);
            payload.extend_from_slice(&1_u16.to_le_bytes());
            payload.extend_from_slice(&1_u16.to_le_bytes());
            payload.extend_from_slice(&encode_long_tag(TagCode::DEFINE_SPRITE.0, &inner));
            inner = payload;
        }
        SwfTag {
            code: TagCode::DEFINE_SPRITE,
            offset: 0,
            payload: inner,
        }
    }

    #[test]
    fn deeply_nested_sprite_tag_counts_stay_bounded() {
        let swf: Swf = Swf {
            header: SwfHeader {
                compression: SwfCompression::None,
                version: 10,
                file_length: 0,
                frame_size: Rect {
                    x_min: 0,
                    x_max: 0,
                    y_min: 0,
                    y_max: 0,
                },
                frame_rate_q8: 0,
                frame_count: 0,
            },
            tags: vec![nested_sprite_bomb(2_000)],
        };
        let counts: BTreeMap<TagCode, usize> = swf.tag_counts();
        let sprite_count: usize = counts.get(&TagCode::DEFINE_SPRITE).copied().unwrap_or(0);
        assert!(sprite_count >= 1, "outer sprite counted");
        assert!(
            sprite_count <= MAX_SPRITE_NESTING + 1,
            "recursion must stop at the depth cap, counted {sprite_count} sprites"
        );
    }
}
