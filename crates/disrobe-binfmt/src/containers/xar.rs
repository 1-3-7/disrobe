use std::io::Read as _;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const XAR_MAGIC: &[u8; 4] = b"xar!";
const HEADER_LEN: usize = 28;
const MAX_TOC_BYTES: u64 = 256 * 1024 * 1024;
const MAX_FILES: usize = 2_000_000;
const MAX_MEMBER_BYTES: u64 = 8 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum XarEncoding {
    Gzip,
    Bzip2,
    Xz,
    Lzma,
    None,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XarFile {
    pub path: String,
    pub offset: u64,
    pub length: u64,
    pub size: u64,
    pub encoding: XarEncoding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XarArchive {
    pub toc_xml: String,
    pub heap_offset: u64,
    pub files: Vec<XarFile>,
}

#[inline]
fn read_u16_be(bytes: &[u8], at: usize) -> Option<u16> {
    disrobe_bytes::read_u16_be_at(bytes, at).ok()
}

#[inline]
fn read_u64_be(bytes: &[u8], at: usize) -> Option<u64> {
    disrobe_bytes::read_u64_be_at(bytes, at).ok()
}

pub fn detect_xar(bytes: &[u8]) -> bool {
    bytes.starts_with(XAR_MAGIC)
}

pub fn parse_xar(bytes: &[u8]) -> Result<XarArchive> {
    if !detect_xar(bytes) {
        return Err(Error::Decompression(
            "xar magic `xar!` not found".to_owned(),
        ));
    }
    let header_size: usize = read_u16_be(bytes, 4)
        .ok_or_else(|| Error::Decompression("xar header truncated".to_owned()))?
        as usize;
    let toc_compressed: u64 = read_u64_be(bytes, 8)
        .ok_or_else(|| Error::Decompression("xar toc compressed length truncated".to_owned()))?;
    let toc_uncompressed: u64 = read_u64_be(bytes, 16)
        .ok_or_else(|| Error::Decompression("xar toc uncompressed length truncated".to_owned()))?;
    if toc_compressed > MAX_TOC_BYTES || toc_uncompressed > MAX_TOC_BYTES {
        return Err(Error::Decompression(
            "xar toc length exceeds sanity bound".to_owned(),
        ));
    }
    let header_size: usize = header_size.max(HEADER_LEN);
    let toc_start: usize = header_size;
    let toc_end: usize = toc_start
        .checked_add(toc_compressed as usize)
        .ok_or_else(|| Error::Decompression("xar toc range overflow".to_owned()))?;
    let toc_compressed_bytes: &[u8] = bytes
        .get(toc_start..toc_end)
        .ok_or_else(|| Error::Decompression("xar toc out of bounds".to_owned()))?;

    let mut toc_xml_bytes: Vec<u8> =
        Vec::with_capacity(toc_uncompressed.min(MAX_TOC_BYTES) as usize);
    let mut decoder: flate2::read::ZlibDecoder<&[u8]> =
        flate2::read::ZlibDecoder::new(toc_compressed_bytes);
    decoder
        .by_ref()
        .take(MAX_TOC_BYTES + 1)
        .read_to_end(&mut toc_xml_bytes)
        .map_err(|e: std::io::Error| {
            Error::Decompression(format!("xar toc inflate failed: {e}"))
        })?;
    if toc_xml_bytes.len() as u64 > MAX_TOC_BYTES {
        return Err(Error::Decompression(
            "xar toc inflated beyond sanity bound".to_owned(),
        ));
    }
    let toc_xml: String = String::from_utf8_lossy(&toc_xml_bytes).into_owned();
    let heap_offset: u64 = toc_end as u64;

    let mut files: Vec<XarFile> = Vec::new();
    parse_toc_files(&toc_xml, String::new(), &mut files)?;
    Ok(XarArchive {
        toc_xml,
        heap_offset,
        files,
    })
}

fn parse_toc_files(xml: &str, prefix: String, out: &mut Vec<XarFile>) -> Result<()> {
    let mut cursor: usize = 0;
    while let Some(rel) = xml[cursor..]
        .find("<file ")
        .or_else(|| xml[cursor..].find("<file>"))
    {
        if out.len() > MAX_FILES {
            return Err(Error::Decompression(
                "xar file count exceeds sanity bound".to_owned(),
            ));
        }
        let open: usize = cursor + rel;
        let body_start: usize = match xml[open..].find('>') {
            Some(gt) => open + gt + 1,
            None => break,
        };
        let close: usize = match find_matching_close(xml, body_start, "file") {
            Some(c) => c,
            None => break,
        };
        let body: &str = &xml[body_start..close];
        let name: String = inner_text(body, "name").into_iter().collect();
        let kind: Option<String> = inner_text(body, "type");
        let full: String = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };

        if kind.as_deref() == Some("directory") {
            let child_region: &str = direct_children_region(body);
            parse_toc_files(child_region, full, out)?;
        } else if let Some(data) = extract_block(body, "data") {
            let offset: u64 = inner_text(data, "offset")
                .and_then(|s: String| s.trim().parse::<u64>().ok())
                .map_or(0, |value: u64| value);
            let length: u64 = inner_text(data, "length")
                .and_then(|s: String| s.trim().parse::<u64>().ok())
                .map_or(0, |value: u64| value);
            let size: u64 = inner_text(data, "size")
                .and_then(|s: String| s.trim().parse::<u64>().ok())
                .map_or(length, |value: u64| value);
            let encoding: XarEncoding = encoding_of(data);
            out.push(XarFile {
                path: full,
                offset,
                length,
                size,
                encoding,
            });
        }

        cursor = close + "</file>".len();
    }
    Ok(())
}

const fn direct_children_region(body: &str) -> &str {
    body
}

fn find_matching_close(xml: &str, from: usize, tag: &str) -> Option<usize> {
    let open_tag_a: String = format!("<{tag} ");
    let open_tag_b: String = format!("<{tag}>");
    let close_tag: String = format!("</{tag}>");
    let mut depth: usize = 1;
    let mut pos: usize = from;
    while pos < xml.len() {
        let next_open_a: Option<usize> = xml[pos..].find(&open_tag_a).map(|i: usize| pos + i);
        let next_open_b: Option<usize> = xml[pos..].find(&open_tag_b).map(|i: usize| pos + i);
        let next_close: Option<usize> = xml[pos..].find(&close_tag).map(|i: usize| pos + i);
        let next_open: Option<usize> = match (next_open_a, next_open_b) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        match (next_open, next_close) {
            (Some(o), Some(c)) if o < c => {
                depth += 1;
                pos = o + open_tag_a.len();
            }
            (_, Some(c)) => {
                depth -= 1;
                if depth == 0 {
                    return Some(c);
                }
                pos = c + close_tag.len();
            }
            _ => return None,
        }
    }
    None
}

fn extract_block<'a>(body: &'a str, tag: &str) -> Option<&'a str> {
    let open_a: String = format!("<{tag} ");
    let open_b: String = format!("<{tag}>");
    let start_open: usize = body.find(&open_a).or_else(|| body.find(&open_b))?;
    let inner_start: usize = start_open + body[start_open..].find('>')? + 1;
    let close: usize = find_matching_close(body, inner_start, tag)?;
    body.get(inner_start..close)
}

fn inner_text(body: &str, tag: &str) -> Option<String> {
    let inner: &str = extract_block(body, tag)?;
    Some(unescape_xml(inner.trim()))
}

fn encoding_of(data: &str) -> XarEncoding {
    let style: Option<String> = attr_value(data, "encoding", "style");
    match style.as_deref() {
        Some("application/x-gzip") => XarEncoding::Gzip,
        Some("application/x-bzip2") => XarEncoding::Bzip2,
        Some("application/x-xz") => XarEncoding::Xz,
        Some("application/x-lzma") => XarEncoding::Lzma,
        Some("application/octet-stream") | None => XarEncoding::None,
        Some(_) => XarEncoding::Other,
    }
}

fn attr_value(body: &str, tag: &str, attr: &str) -> Option<String> {
    let open: usize = body.find(&format!("<{tag}"))?;
    let tag_end: usize = open + body[open..].find('>')?;
    let tag_str: &str = &body[open..tag_end];
    let needle: String = format!("{attr}=\"");
    let attr_start: usize = tag_str.find(&needle)? + needle.len();
    let attr_end: usize = tag_str[attr_start..].find('"')? + attr_start;
    Some(tag_str[attr_start..attr_end].to_owned())
}

fn unescape_xml(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

pub fn file_data(bytes: &[u8], archive: &XarArchive, file: &XarFile) -> Result<Vec<u8>> {
    let start: usize = (archive.heap_offset + file.offset) as usize;
    let end: usize = start
        .checked_add(file.length as usize)
        .ok_or_else(|| Error::Decompression("xar file range overflow".to_owned()))?;
    let raw: &[u8] = bytes
        .get(start..end)
        .ok_or_else(|| Error::Decompression("xar file data out of bounds".to_owned()))?;
    match file.encoding {
        XarEncoding::None | XarEncoding::Other => Ok(raw.to_vec()),
        XarEncoding::Gzip => {
            let mut out: Vec<u8> = Vec::new();
            let mut d: flate2::read::ZlibDecoder<&[u8]> = flate2::read::ZlibDecoder::new(raw);
            let read: u64 = std::io::copy(&mut d.by_ref().take(file.size + 1), &mut out).map_err(
                |e: std::io::Error| {
                    Error::Decompression(format!("xar gzip member inflate failed: {e}"))
                },
            )?;
            if read > file.size.max(1).saturating_add(1) && file.size != 0 {
                return Err(Error::Decompression(
                    "xar file inflated beyond declared size".to_owned(),
                ));
            }
            Ok(out)
        }
        XarEncoding::Bzip2 => {
            let mut out: Vec<u8> = Vec::new();
            let mut d: bzip2_rs::DecoderReader<&[u8]> = bzip2_rs::DecoderReader::new(raw);
            std::io::copy(&mut d.by_ref().take(file.size + 1), &mut out).map_err(
                |e: std::io::Error| {
                    Error::Decompression(format!("xar bzip2 member decode failed: {e}"))
                },
            )?;
            Ok(out)
        }
        XarEncoding::Xz => decode_xz(raw, file.size),
        XarEncoding::Lzma => decode_lzma(raw, file.size),
    }
}

fn member_cap(declared: u64) -> u64 {
    declared.saturating_add(1).min(MAX_MEMBER_BYTES)
}

fn decode_xz(raw: &[u8], declared: u64) -> Result<Vec<u8>> {
    let decoder: liblzma::read::XzDecoder<&[u8]> = liblzma::read::XzDecoder::new(raw);
    let mut out: Vec<u8> = Vec::new();
    decoder
        .take(member_cap(declared))
        .read_to_end(&mut out)
        .map_err(|e: std::io::Error| {
            Error::Decompression(format!("xar xz member decode failed: {e}"))
        })?;
    Ok(out)
}

fn decode_lzma(raw: &[u8], declared: u64) -> Result<Vec<u8>> {
    if let Ok(out) = decode_xz(raw, declared) {
        return Ok(out);
    }
    let mut reader: std::io::Cursor<&[u8]> = std::io::Cursor::new(raw);
    let mut out: Vec<u8> = Vec::new();
    lzma_rs::lzma_decompress(&mut reader, &mut out).map_err(|e: lzma_rs::error::Error| {
        Error::Decompression(format!("xar lzma member decode failed: {e}"))
    })?;
    if out.len() as u64 > MAX_MEMBER_BYTES {
        return Err(Error::Decompression(
            "xar lzma member exceeds sanity bound".to_owned(),
        ));
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::io::Write as _;

    use super::*;

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e: flate2::write::ZlibEncoder<Vec<u8>> =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).expect("zlib write");
        e.finish().expect("zlib finish")
    }

    fn build_xar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut heap: Vec<u8> = Vec::new();
        let mut file_xml: String = String::new();
        for (name, body) in files {
            let compressed: Vec<u8> = zlib(body);
            let offset: usize = heap.len();
            heap.extend_from_slice(&compressed);
            push_xar_file_xml(&mut file_xml, name, compressed.len(), offset, body.len());
        }
        let toc: String = format!("<?xml version=\"1.0\"?><xar><toc>{file_xml}</toc></xar>");
        let toc_compressed: Vec<u8> = zlib(toc.as_bytes());

        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(XAR_MAGIC);
        out.extend_from_slice(&(HEADER_LEN as u16).to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&(toc_compressed.len() as u64).to_be_bytes());
        out.extend_from_slice(&(toc.len() as u64).to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&toc_compressed);
        out.extend_from_slice(&heap);
        out
    }

    fn push_xar_file_xml(
        out: &mut String,
        name: &str,
        compressed_len: usize,
        offset: usize,
        body_len: usize,
    ) {
        out.push_str("<file id=\"1\"><name>");
        out.push_str(name);
        out.push_str("</name><type>file</type><data><length>");
        out.push_str(&compressed_len.to_string());
        out.push_str("</length><offset>");
        out.push_str(&offset.to_string());
        out.push_str("</offset><size>");
        out.push_str(&body_len.to_string());
        out.push_str("</size><encoding style=\"application/x-gzip\"/></data></file>");
    }

    #[test]
    fn detects_and_extracts_xar_files() {
        let image: Vec<u8> = build_xar(&[
            ("Distribution", b"<installer-script/>"),
            ("PackageInfo", b"<pkg-info identifier=\"com.test\"/>"),
        ]);
        assert!(detect_xar(&image));
        let xar: XarArchive = parse_xar(&image).expect("parse xar");
        assert_eq!(xar.files.len(), 2);
        let dist: &XarFile = xar
            .files
            .iter()
            .find(|f: &&XarFile| f.path == "Distribution")
            .expect("Distribution");
        assert_eq!(dist.encoding, XarEncoding::Gzip);
        let data: Vec<u8> = file_data(&image, &xar, dist).expect("data");
        assert_eq!(data, b"<installer-script/>");
    }

    #[test]
    fn rejects_non_xar() {
        assert!(!detect_xar(&[0u8; 64]));
        assert!(parse_xar(&[0u8; 64]).is_err());
    }

    #[test]
    fn truncated_xar_does_not_panic() {
        let full: Vec<u8> = build_xar(&[("A", b"alpha")]);
        for cut in (HEADER_LEN..full.len()).step_by(3) {
            let _ = parse_xar(&full[..cut]);
        }
    }
}
