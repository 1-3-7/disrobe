use disrobe_bytes::{ByteReadError, read_bytes_at, read_u16_le_at, read_u32_le_at, read_u64_le_at};
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

fn truncated(context: &'static str, e: &ByteReadError) -> Error {
    Error::Decompression(format!(
        "{context} truncated at offset {} (needed {}, available {})",
        e.offset, e.needed, e.available
    ))
}

const RESHDR_SIZE_MASK: u64 = 0x00ff_ffff_ffff_ffff;
const RESHDR_FLAG_SHIFT: u32 = 56;

fn parse_reshdr(bytes: &[u8], offset: usize) -> std::result::Result<WimResource, ByteReadError> {
    let packed: u64 = read_u64_le_at(bytes, offset)?;
    let size: u64 = packed & RESHDR_SIZE_MASK;
    let flags: u8 = (packed >> RESHDR_FLAG_SHIFT) as u8;
    let file_offset: u64 = read_u64_le_at(bytes, offset.saturating_add(8))?;
    let original_size: u64 = read_u64_le_at(bytes, offset.saturating_add(16))?;
    Ok(WimResource {
        size,
        flags,
        offset: file_offset,
        original_size,
    })
}

#[must_use]
pub fn parse_reshdr_at(bytes: &[u8], offset: usize) -> WimResource {
    parse_reshdr(bytes, offset).unwrap_or(WimResource {
        size: 0,
        flags: 0,
        offset: 0,
        original_size: 0,
    })
}

fn reject_overlapping_resource(name: &'static str, resource: &WimResource) -> Result<()> {
    if resource.size == 0 {
        return Ok(());
    }
    if resource.offset < WIM_HEADER_LEN as u64 {
        return Err(Error::Decompression(format!(
            "wim {name} at offset {} overlaps the {WIM_HEADER_LEN}-byte header",
            resource.offset
        )));
    }
    Ok(())
}

pub fn parse_wim_header(bytes: &[u8]) -> Result<WimHeader> {
    if bytes.len() < WIM_HEADER_LEN {
        return Err(Error::Decompression("wim header truncated".to_owned()));
    }
    let magic: &[u8] =
        read_bytes_at(bytes, 0, 8).map_err(|e: ByteReadError| truncated("wim magic", &e))?;
    if magic != WIM_MAGIC {
        return Err(Error::Decompression("wim magic mismatch".to_owned()));
    }
    let field = |e: ByteReadError| truncated("wim header field", &e);
    let header_size: u32 = read_u32_le_at(bytes, 8).map_err(field)?;
    let version: u32 = read_u32_le_at(bytes, 12).map_err(field)?;
    let flags: u32 = read_u32_le_at(bytes, 16).map_err(field)?;
    let chunk_size: u32 = read_u32_le_at(bytes, 20).map_err(field)?;
    let mut guid: [u8; 16] = [0u8; 16];
    guid.copy_from_slice(
        read_bytes_at(bytes, 24, 16).map_err(|e: ByteReadError| truncated("wim guid", &e))?,
    );
    let part_number: u16 = read_u16_le_at(bytes, 40).map_err(field)?;
    let total_parts: u16 = read_u16_le_at(bytes, 42).map_err(field)?;
    if total_parts > 0 && (part_number == 0 || part_number > total_parts) {
        return Err(Error::Decompression(format!(
            "wim part number {part_number} is outside the declared span of {total_parts} parts"
        )));
    }
    let image_count: u32 = read_u32_le_at(bytes, 44).map_err(field)?;
    let reshdr = |e: ByteReadError| truncated("wim resource header", &e);
    let offset_table: WimResource = parse_reshdr(bytes, 48).map_err(reshdr)?;
    let xml_data: WimResource = parse_reshdr(bytes, 72).map_err(reshdr)?;
    let boot_metadata: WimResource = parse_reshdr(bytes, 96).map_err(reshdr)?;
    let boot_index: u32 = read_u32_le_at(bytes, 120).map_err(field)?;
    let integrity: WimResource = parse_reshdr(bytes, 124).map_err(reshdr)?;
    reject_overlapping_resource("lookup table", &offset_table)?;
    reject_overlapping_resource("xml data", &xml_data)?;
    reject_overlapping_resource("boot metadata", &boot_metadata)?;
    reject_overlapping_resource("integrity table", &integrity)?;
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
    let tail: &[u8] = bytes.get(start..).unwrap_or_default();
    for pair in tail.chunks_exact(2) {
        units.push(u16::from_le_bytes([pair[0], pair[1]]));
    }
    String::from_utf16_lossy(&units)
}

fn extract_tag<'a>(xml: &'a str, tag: &str, from: usize) -> Option<(&'a str, usize)> {
    let open: String = format!("<{tag}");
    let open_pos: usize = xml.get(from..)?.find(&open)? + from;
    let after_open: usize = xml.get(open_pos..)?.find('>')? + open_pos + 1;
    let close: String = format!("</{tag}>");
    let close_pos: usize = xml.get(after_open..)?.find(&close)? + after_open;
    Some((xml.get(after_open..close_pos)?.trim(), close_pos))
}

const IMAGE_OPEN_TAG: &str = "<IMAGE";
const IMAGE_CLOSE_TAG: &str = "</IMAGE>";
const IMAGE_INDEX_ATTRIBUTE: &str = "INDEX=\"";

fn parse_xml_images(xml: &str, image_count: u32) -> Vec<WimImageEntry> {
    let mut images: Vec<WimImageEntry> = Vec::new();
    let mut cursor: usize = 0;
    while let Some(image_open) = xml
        .get(cursor..)
        .and_then(|rest: &str| rest.find(IMAGE_OPEN_TAG))
    {
        let image_start: usize = cursor + image_open;
        let header_end: usize = match xml.get(image_start..).and_then(|rest: &str| rest.find('>')) {
            Some(pos) => image_start + pos + 1,
            None => break,
        };
        let image_tag: &str = xml.get(image_start..header_end).unwrap_or_default();
        let index: u32 = image_tag
            .find(IMAGE_INDEX_ATTRIBUTE)
            .and_then(|p: usize| {
                let value_start: usize = image_start + p + IMAGE_INDEX_ATTRIBUTE.len();
                let rest: &str = xml.get(value_start..)?;
                rest.find('"').and_then(|q: usize| rest.get(..q))
            })
            .and_then(|s: &str| s.parse::<u32>().ok())
            .map_or(images.len() as u32 + 1, |value: u32| value);
        let closing: Option<usize> = xml
            .get(header_end..)
            .and_then(|rest: &str| rest.find(IMAGE_CLOSE_TAG))
            .map(|p: usize| header_end + p);
        let block_end: usize = closing.unwrap_or(xml.len());
        let block: &str = xml.get(header_end..block_end).unwrap_or_default();
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
        let Some(next_cursor): Option<usize> =
            closing.and_then(|end: usize| end.checked_add(IMAGE_CLOSE_TAG.len()))
        else {
            break;
        };
        cursor = next_cursor;
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
    fn wim_parse_output_is_stable_for_a_spec_correct_image() {
        let xml: Vec<u8> =
            encode_utf16le_with_bom("<WIM><IMAGE INDEX=\"1\"><NAME>Setup</NAME></IMAGE></WIM>");
        let image: Vec<u8> = build_wim(&xml);
        let parsed: WimArchive = parse_wim(&image).expect("parse wim");
        let encoded: String = serde_json::to_string(&parsed).expect("encode wim archive");
        assert_eq!(
            encoded,
            r#"{"header":{"header_size":208,"version":65536,"flags":262146,"compression":"lzx","chunk_size":32768,"guid":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"part_number":1,"total_parts":1,"image_count":2,"offset_table":{"size":0,"flags":0,"offset":0,"original_size":0},"xml_data":{"size":110,"flags":0,"offset":208,"original_size":110},"boot_metadata":{"size":0,"flags":0,"offset":0,"original_size":0},"boot_index":0,"integrity":{"size":0,"flags":0,"offset":0,"original_size":0}},"images":[{"index":1,"name":"Setup","dir_count":null,"file_count":null,"total_bytes":null}]}"#
        );
    }

    #[test]
    fn the_packed_resource_header_splits_size_from_flags_at_every_boundary() {
        let cases: [(u64, u8); 6] = [
            (0, 0),
            (1, RESHDR_FLAG_COMPRESSED),
            (208, RESHDR_FLAG_METADATA),
            (0x00ff_ffff_ffff_ffff, 0xff),
            (0x00ff_ffff_ffff_ffff, 0),
            (
                0x0000_0000_0000_00ff,
                RESHDR_FLAG_FREE | RESHDR_FLAG_SPANNED,
            ),
        ];
        for (size, flags) in cases {
            let mut raw: Vec<u8> = vec![0u8; RESHDR_LEN];
            let packed: u64 = size | (u64::from(flags) << RESHDR_FLAG_SHIFT);
            raw[0..8].copy_from_slice(&packed.to_le_bytes());
            raw[8..16].copy_from_slice(&0xdead_beefu64.to_le_bytes());
            raw[16..24].copy_from_slice(&0x1234_5678u64.to_le_bytes());
            let resource: WimResource = parse_reshdr(&raw, 0).expect("packed resource header");
            assert_eq!(resource.size, size, "size for flags {flags:#x}");
            assert_eq!(resource.flags, flags, "flags for size {size:#x}");
            assert_eq!(resource.offset, 0xdead_beef);
            assert_eq!(resource.original_size, 0x1234_5678);
            let legacy_size: u64 =
                u64::from_le_bytes([raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], 0]);
            assert_eq!(resource.size, legacy_size);
            assert_eq!(resource.flags, raw[7]);
        }
        assert!(parse_reshdr(&[0u8; RESHDR_LEN - 1], 0).is_err());
    }

    #[test]
    fn rejects_a_lookup_table_that_overlaps_the_header() {
        let mut image: Vec<u8> = build_wim(&encode_utf16le_with_bom("<WIM></WIM>"));
        image[48..55].copy_from_slice(&64u64.to_le_bytes()[..7]);
        image[56..64].copy_from_slice(&16u64.to_le_bytes());
        let err: Error = parse_wim(&image).expect_err("overlapping lookup table must be refused");
        assert!(
            matches!(&err, Error::Decompression(m) if m.contains("overlaps the")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_a_part_number_outside_the_declared_span() {
        for (part, total) in [(0u16, 1u16), (2, 1), (5, 3), (u16::MAX, 2)] {
            let mut image: Vec<u8> = build_wim(&encode_utf16le_with_bom("<WIM></WIM>"));
            image[40..42].copy_from_slice(&part.to_le_bytes());
            image[42..44].copy_from_slice(&total.to_le_bytes());
            let err: Error = parse_wim(&image).expect_err("swm part number must be checked");
            assert!(
                matches!(&err, Error::Decompression(m) if m.contains("outside the declared span")),
                "part={part} total={total} got {err:?}"
            );
        }
    }

    #[test]
    fn accepts_every_in_range_spanned_part_number() {
        for part in 1u16..=3 {
            let mut image: Vec<u8> = build_wim(&encode_utf16le_with_bom("<WIM></WIM>"));
            image[40..42].copy_from_slice(&part.to_le_bytes());
            image[42..44].copy_from_slice(&3u16.to_le_bytes());
            let parsed: WimArchive = parse_wim(&image).expect("in-range part must parse");
            assert_eq!(parsed.header.part_number, part);
            assert_eq!(parsed.header.total_parts, 3);
        }
    }

    #[test]
    fn every_truncation_of_a_valid_image_errors_without_panicking() {
        let image: Vec<u8> = build_wim(&encode_utf16le_with_bom("<WIM></WIM>"));
        for len in 0..image.len() {
            let view: &[u8] = &image[..len];
            let _: Result<WimArchive> = parse_wim(view);
            let _: Result<WimHeader> = parse_wim_header(view);
            let _: WimResource = parse_reshdr_at(view, 48);
        }
        assert!(parse_wim(&image[..WIM_HEADER_LEN - 1]).is_err());
        assert_eq!(parse_reshdr_at(&image, usize::MAX).size, 0);
        assert_eq!(parse_reshdr_at(&image, image.len() - 1).size, 0);
    }

    #[test]
    fn every_declared_compression_flag_maps_to_a_named_codec() {
        let cases: [(u32, WimCompression); 5] = [
            (0, WimCompression::None),
            (
                WIM_FLAG_COMPRESSION | WIM_FLAG_COMPRESS_LZX,
                WimCompression::Lzx,
            ),
            (
                WIM_FLAG_COMPRESSION | WIM_FLAG_COMPRESS_XPRESS,
                WimCompression::Xpress,
            ),
            (
                WIM_FLAG_COMPRESSION | WIM_FLAG_COMPRESS_LZMS,
                WimCompression::Lzms,
            ),
            (WIM_FLAG_COMPRESSION, WimCompression::Unknown),
        ];
        for (flags, expected) in cases {
            let mut image: Vec<u8> = build_wim(&encode_utf16le_with_bom("<WIM></WIM>"));
            image[16..20].copy_from_slice(&flags.to_le_bytes());
            let parsed: WimArchive = parse_wim(&image).expect("parse wim");
            assert_eq!(parsed.header.compression, expected, "flags={flags:#x}");
        }
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

    #[test]
    fn an_image_element_that_is_never_closed_stops_the_walk_instead_of_running_off_the_xml() {
        let xml: Vec<u8> = encode_utf16le_with_bom("<WIM><IMAGE INDEX=\"1\"><NAME>only</NAME>");
        let image: Vec<u8> = build_wim(&xml);

        let parsed: WimArchive = parse_wim(&image).expect("parse wim");
        assert_eq!(
            parsed.header.image_count, 2,
            "the header must still claim two images, so the walk cannot stop because it was satisfied"
        );
        assert_eq!(
            parsed.images.len(),
            1,
            "the one unterminated IMAGE element is the last one the walk can read: {:?}",
            parsed.images
        );
        assert_eq!(parsed.images[0].name.as_deref(), Some("only"));
    }

    #[test]
    fn an_unclosed_image_element_followed_by_more_xml_still_stops_at_that_element() {
        let xml: Vec<u8> = encode_utf16le_with_bom(
            "<WIM><IMAGE INDEX=\"1\"><NAME>first</NAME><IMAGE INDEX=\"2\"><NAME>second</NAME>",
        );
        let image: Vec<u8> = build_wim(&xml);

        let parsed: WimArchive = parse_wim(&image).expect("parse wim");
        assert_eq!(parsed.images.len(), 1);
        assert_eq!(parsed.images[0].index, 1);
    }

    #[test]
    fn a_multibyte_xml_body_around_an_unclosed_image_does_not_split_a_character() {
        let xml: Vec<u8> = encode_utf16le_with_bom(
            "<WIM><NAME>日本語のテキスト</NAME><IMAGE INDEX=\"7\"><NAME>ünïcode</NAME>",
        );
        let image: Vec<u8> = build_wim(&xml);

        let parsed: WimArchive = parse_wim(&image).expect("parse wim");
        assert_eq!(parsed.images.len(), 1);
        assert_eq!(parsed.images[0].index, 7);
        assert_eq!(parsed.images[0].name.as_deref(), Some("ünïcode"));
    }
}
