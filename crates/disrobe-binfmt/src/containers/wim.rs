use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const WIM_MAGIC: &[u8; 8] = b"MSWIM\x00\x00\x00";
pub const WIM_HEADER_LEN: usize = 208;
pub const RESHDR_LEN: usize = 24;

pub const WIM_FLAG_COMPRESSION: u32 = 0x0000_0002;
pub const WIM_FLAG_READONLY: u32 = 0x0000_0004;
pub const WIM_FLAG_SPANNED: u32 = 0x0000_0008;
pub const WIM_FLAG_RESOURCE_ONLY: u32 = 0x0000_0010;
pub const WIM_FLAG_METADATA_ONLY: u32 = 0x0000_0020;
pub const WIM_FLAG_WRITE_IN_PROGRESS: u32 = 0x0000_0040;
pub const WIM_FLAG_COMPRESS_XPRESS: u32 = 0x0002_0000;
pub const WIM_FLAG_COMPRESS_LZX: u32 = 0x0004_0000;
pub const WIM_FLAG_COMPRESS_LZMS: u32 = 0x0008_0000;

pub const RESHDR_FLAG_FREE: u8 = 0x01;
pub const RESHDR_FLAG_METADATA: u8 = 0x02;
pub const RESHDR_FLAG_COMPRESSED: u8 = 0x04;
pub const RESHDR_FLAG_SPANNED: u8 = 0x08;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WimResource {
    pub size: u64,
    pub flags: u8,
    pub offset: u64,
    pub original_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WimCompression {
    None,
    Xpress,
    Lzx,
    Lzms,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WimHeader {
    pub header_size: u32,
    pub version: u32,
    pub flags: u32,
    pub compression: WimCompression,
    pub chunk_size: u32,
    pub guid: [u8; 16],
    pub part_number: u16,
    pub total_parts: u16,
    pub image_count: u32,
    pub offset_table: WimResource,
    pub xml_data: WimResource,
    pub boot_metadata: WimResource,
    pub boot_index: u32,
    pub integrity: WimResource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WimImageEntry {
    pub index: u32,
    pub name: Option<String>,
    pub dir_count: Option<u64>,
    pub file_count: Option<u64>,
    pub total_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WimArchive {
    pub header: WimHeader,
    pub images: Vec<WimImageEntry>,
}

fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64_le(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn parse_reshdr(bytes: &[u8], offset: usize) -> WimResource {
    let size: u64 = u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        0,
    ]);
    let flags: u8 = bytes[offset + 7];
    let file_offset: u64 = read_u64_le(bytes, offset + 8);
    let original_size: u64 = read_u64_le(bytes, offset + 16);
    WimResource {
        size,
        flags,
        offset: file_offset,
        original_size,
    }
}

#[must_use]
pub fn parse_reshdr_at(bytes: &[u8], offset: usize) -> WimResource {
    if offset.saturating_add(RESHDR_LEN) > bytes.len() {
        return WimResource {
            size: 0,
            flags: 0,
            offset: 0,
            original_size: 0,
        };
    }
    parse_reshdr(bytes, offset)
}

pub fn parse_wim_header(bytes: &[u8]) -> Result<WimHeader> {
    if bytes.len() < WIM_HEADER_LEN {
        return Err(Error::Decompression("wim header truncated".to_owned()));
    }
    if &bytes[0..8] != WIM_MAGIC {
        return Err(Error::Decompression("wim magic mismatch".to_owned()));
    }
    let header_size: u32 = read_u32_le(bytes, 8);
    let version: u32 = read_u32_le(bytes, 12);
    let flags: u32 = read_u32_le(bytes, 16);
    let chunk_size: u32 = read_u32_le(bytes, 20);
    let mut guid: [u8; 16] = [0u8; 16];
    guid.copy_from_slice(&bytes[24..40]);
    let part_number: u16 = read_u16_le(bytes, 40);
    let total_parts: u16 = read_u16_le(bytes, 42);
    let image_count: u32 = read_u32_le(bytes, 44);
    let offset_table: WimResource = parse_reshdr(bytes, 48);
    let xml_data: WimResource = parse_reshdr(bytes, 72);
    let boot_metadata: WimResource = parse_reshdr(bytes, 96);
    let boot_index: u32 = read_u32_le(bytes, 120);
    let integrity: WimResource = parse_reshdr(bytes, 124);
    let compression: WimCompression = if flags & WIM_FLAG_COMPRESSION == 0 {
        WimCompression::None
    } else if flags & WIM_FLAG_COMPRESS_LZX != 0 {
        WimCompression::Lzx
    } else if flags & WIM_FLAG_COMPRESS_XPRESS != 0 {
        WimCompression::Xpress
    } else if flags & WIM_FLAG_COMPRESS_LZMS != 0 {
        WimCompression::Lzms
    } else {
        WimCompression::Unknown
    };
    Ok(WimHeader {
        header_size,
        version,
        flags,
        compression,
        chunk_size,
        guid,
        part_number,
        total_parts,
        image_count,
        offset_table,
        xml_data,
        boot_metadata,
        boot_index,
        integrity,
    })
}

fn decode_utf16le_lossy(bytes: &[u8]) -> String {
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len() / 2);
    let start: usize = if bytes.len() >= 2 && bytes[0] == 0xff && bytes[1] == 0xfe {
        2
    } else {
        0
    };
    let mut index: usize = start;
    while index + 1 < bytes.len() {
        units.push(u16::from_le_bytes([bytes[index], bytes[index + 1]]));
        index += 2;
    }
    String::from_utf16_lossy(&units)
}

fn extract_tag<'a>(xml: &'a str, tag: &str, from: usize) -> Option<(&'a str, usize)> {
    let open: String = format!("<{tag}");
    let open_pos: usize = xml[from..].find(&open)? + from;
    let after_open: usize = xml[open_pos..].find('>')? + open_pos + 1;
    let close: String = format!("</{tag}>");
    let close_pos: usize = xml[after_open..].find(&close)? + after_open;
    Some((xml[after_open..close_pos].trim(), close_pos))
}

fn parse_xml_images(xml: &str, image_count: u32) -> Vec<WimImageEntry> {
    let mut images: Vec<WimImageEntry> = Vec::new();
    let mut cursor: usize = 0;
    while let Some(image_open) = xml[cursor..].find("<IMAGE") {
        let image_start: usize = cursor + image_open;
        let header_end: usize = match xml[image_start..].find('>') {
            Some(pos) => image_start + pos + 1,
            None => break,
        };
        let image_tag: &str = &xml[image_start..header_end];
        let index: u32 = image_tag
            .find("INDEX=\"")
            .and_then(|p: usize| {
                let value_start: usize = image_start + p + "INDEX=\"".len();
                xml[value_start..]
                    .find('"')
                    .map(|q: usize| &xml[value_start..value_start + q])
            })
            .and_then(|s: &str| s.parse::<u32>().ok())
            .map_or(images.len() as u32 + 1, |value: u32| value);
        let block_end: usize = xml[header_end..]
            .find("</IMAGE>")
            .map_or(xml.len(), |p: usize| header_end + p);
        let block: &str = &xml[header_end..block_end];
        let name: Option<String> = extract_tag(block, "NAME", 0)
            .map(|(value, _)| value.to_owned())
            .or_else(|| extract_tag(block, "DISPLAYNAME", 0).map(|(value, _)| value.to_owned()));
        let dir_count: Option<u64> =
            extract_tag(block, "DIRCOUNT", 0).and_then(|(v, _)| v.parse().ok());
        let file_count: Option<u64> =
            extract_tag(block, "FILECOUNT", 0).and_then(|(v, _)| v.parse().ok());
        let total_bytes: Option<u64> =
            extract_tag(block, "TOTALBYTES", 0).and_then(|(v, _)| v.parse().ok());
        images.push(WimImageEntry {
            index,
            name,
            dir_count,
            file_count,
            total_bytes,
        });
        cursor = block_end + "</IMAGE>".len();
        if images.len() as u32 >= image_count && image_count > 0 {
            break;
        }
    }
    images
}

#[derive(Debug, Clone)]
pub struct WimCarvedResource {
    pub name: String,
    pub data: Vec<u8>,
    pub compressed: bool,
}

impl WimResource {
    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        self.flags & RESHDR_FLAG_COMPRESSED != 0
    }

    fn carve<'a>(&self, bytes: &'a [u8]) -> Option<&'a [u8]> {
        let off: usize = usize::try_from(self.offset).ok()?;
        let len: usize = usize::try_from(self.size).ok()?;
        bytes.get(off..off.checked_add(len)?)
    }
}

#[must_use]
pub fn carve_wim_resources(bytes: &[u8], header: &WimHeader, cap: u64) -> Vec<WimCarvedResource> {
    let named: [(&str, WimResource); 4] = [
        (".disrobe-wim-offset-table.bin", header.offset_table),
        (".disrobe-wim-xml.bin", header.xml_data),
        (".disrobe-wim-boot-metadata.bin", header.boot_metadata),
        (".disrobe-wim-integrity.bin", header.integrity),
    ];
    let mut out: Vec<WimCarvedResource> = Vec::new();
    for (name, resource) in named {
        if resource.size == 0 || resource.size > cap {
            continue;
        }
        if resource.is_compressed() {
            continue;
        }
        if let Some(slice) = resource.carve(bytes) {
            out.push(WimCarvedResource {
                name: name.to_owned(),
                data: slice.to_vec(),
                compressed: false,
            });
        }
    }
    out
}

pub fn parse_wim(bytes: &[u8]) -> Result<WimArchive> {
    let header: WimHeader = parse_wim_header(bytes)?;
    let xml_off: usize = usize::try_from(header.xml_data.offset)
        .map_err(|_| Error::Decompression("wim xml offset overflow".to_owned()))?;
    let xml_size: usize = usize::try_from(header.xml_data.size)
        .map_err(|_| Error::Decompression("wim xml size overflow".to_owned()))?;
    let images: Vec<WimImageEntry> = if xml_size == 0 {
        Vec::new()
    } else {
        let xml_end: usize = xml_off
            .checked_add(xml_size)
            .ok_or_else(|| Error::Decompression("wim xml range overflow".to_owned()))?;
        bytes
            .get(xml_off..xml_end.min(bytes.len()))
            .map_or_else(Vec::new, |raw: &[u8]| {
                let xml: String = decode_utf16le_lossy(raw);
                parse_xml_images(&xml, header.image_count)
            })
    };
    Ok(WimArchive { header, images })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn encode_utf16le_with_bom(text: &str) -> Vec<u8> {
        let mut out: Vec<u8> = vec![0xff, 0xfe];
        for unit in text.encode_utf16() {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out
    }

    fn build_wim(xml: &[u8]) -> Vec<u8> {
        let xml_offset: u64 = WIM_HEADER_LEN as u64;
        let mut header: Vec<u8> = vec![0u8; WIM_HEADER_LEN];
        header[0..8].copy_from_slice(WIM_MAGIC);
        header[8..12].copy_from_slice(&(WIM_HEADER_LEN as u32).to_le_bytes());
        header[12..16].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        let flags: u32 = WIM_FLAG_COMPRESSION | WIM_FLAG_COMPRESS_LZX;
        header[16..20].copy_from_slice(&flags.to_le_bytes());
        header[20..24].copy_from_slice(&32_768u32.to_le_bytes());
        header[40..42].copy_from_slice(&1u16.to_le_bytes());
        header[42..44].copy_from_slice(&1u16.to_le_bytes());
        header[44..48].copy_from_slice(&2u32.to_le_bytes());
        let xml_size: u64 = xml.len() as u64;
        header[72..79].copy_from_slice(&xml_size.to_le_bytes()[..7]);
        header[79] = 0;
        header[80..88].copy_from_slice(&xml_offset.to_le_bytes());
        header[88..96].copy_from_slice(&xml_size.to_le_bytes());
        let mut image: Vec<u8> = header;
        image.extend_from_slice(xml);
        image
    }

    #[test]
    fn parses_header_and_images() {
        let xml_text: &str = "<WIM><TOTALBYTES>1000</TOTALBYTES>\
<IMAGE INDEX=\"1\"><NAME>Windows Setup</NAME><DIRCOUNT>10</DIRCOUNT>\
<FILECOUNT>42</FILECOUNT><TOTALBYTES>500</TOTALBYTES></IMAGE>\
<IMAGE INDEX=\"2\"><NAME>Windows PE</NAME><DIRCOUNT>5</DIRCOUNT>\
<FILECOUNT>21</FILECOUNT><TOTALBYTES>400</TOTALBYTES></IMAGE></WIM>";
        let xml: Vec<u8> = encode_utf16le_with_bom(xml_text);
        let image: Vec<u8> = build_wim(&xml);

        let parsed: WimArchive = parse_wim(&image).expect("parse wim");
        assert_eq!(parsed.header.image_count, 2);
        assert_eq!(parsed.header.compression, WimCompression::Lzx);
        assert_eq!(parsed.header.version, 0x0001_0000);
        assert_eq!(parsed.header.part_number, 1);
        assert_eq!(parsed.images.len(), 2);
        assert_eq!(parsed.images[0].index, 1);
        assert_eq!(parsed.images[0].name.as_deref(), Some("Windows Setup"));
        assert_eq!(parsed.images[0].file_count, Some(42));
        assert_eq!(parsed.images[0].dir_count, Some(10));
        assert_eq!(parsed.images[1].index, 2);
        assert_eq!(parsed.images[1].name.as_deref(), Some("Windows PE"));
    }

    #[test]
    fn reshdr_packs_size_and_flags() {
        let xml: Vec<u8> = encode_utf16le_with_bom("<WIM></WIM>");
        let image: Vec<u8> = build_wim(&xml);
        let parsed: WimArchive = parse_wim(&image).expect("parse wim");
        assert_eq!(parsed.header.xml_data.size, xml.len() as u64);
        assert_eq!(parsed.header.xml_data.offset, WIM_HEADER_LEN as u64);
        assert!(parsed.images.is_empty());
    }

    #[test]
    fn rejects_bad_magic() {
        let mut image: Vec<u8> = build_wim(&encode_utf16le_with_bom("<WIM></WIM>"));
        image[0] = b'X';
        assert!(parse_wim(&image).is_err());
    }

    #[test]
    fn rejects_truncated() {
        assert!(parse_wim(&[0u8; 32]).is_err());
    }
}
