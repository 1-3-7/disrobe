use std::io::{Cursor, Read};

use serde::Serialize;
use zip::ZipArchive;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Serialize)]
pub struct ExtractedModule {
    pub name: String,
    pub raw_bytes_len: usize,
    pub recovered_source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtractedProject {
    pub container_kind: ContainerKind,
    pub modules: Vec<ExtractedModule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ContainerKind {
    OoxmlZip,
    OleCompoundFile,
    RawVbaProject,
}

const OOXML_MAGIC: &[u8] = b"PK\x03\x04";
const OLE_MAGIC: &[u8; 8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1";

pub fn extract_from_bytes(data: &[u8]) -> Result<ExtractedProject> {
    if data.starts_with(OOXML_MAGIC) {
        return extract_from_ooxml(data);
    }
    if data.starts_with(OLE_MAGIC) {
        return extract_from_ole(data);
    }
    Ok(ExtractedProject {
        container_kind: ContainerKind::RawVbaProject,
        modules: vec![ExtractedModule {
            name: "raw".to_owned(),
            raw_bytes_len: data.len(),
            recovered_source: String::from_utf8_lossy(data).into_owned(),
        }],
    })
}

fn extract_from_ooxml(data: &[u8]) -> Result<ExtractedProject> {
    let cursor: Cursor<&[u8]> = Cursor::new(data);
    let mut zip: ZipArchive<Cursor<&[u8]>> = ZipArchive::new(cursor)?;
    let mut modules: Vec<ExtractedModule> = Vec::new();
    for i in 0..zip.len() {
        let mut entry: zip::read::ZipFile<'_> = zip.by_index(i)?;
        let name: String = entry.name().to_owned();
        if name.ends_with("vbaProject.bin") {
            let mut buf: Vec<u8> = Vec::with_capacity(entry.size() as usize);
            entry.read_to_end(&mut buf)?;
            drop(entry);
            let inner: ExtractedProject = extract_from_ole(&buf)?;
            modules.extend(inner.modules);
        }
    }
    Ok(ExtractedProject {
        container_kind: ContainerKind::OoxmlZip,
        modules,
    })
}

fn extract_from_ole(data: &[u8]) -> Result<ExtractedProject> {
    let cursor: Cursor<&[u8]> = Cursor::new(data);
    let mut comp: cfb::CompoundFile<Cursor<&[u8]>> = cfb::CompoundFile::open(cursor)
        .map_err(|e: std::io::Error| Error::OleCfb(e.to_string()))?;
    let stream_paths: Vec<String> = comp
        .walk()
        .filter(|e: &cfb::Entry| e.is_stream())
        .map(|e: cfb::Entry| normalise_cfb_path(&e.path().display().to_string()))
        .collect();
    let mut modules: Vec<ExtractedModule> = Vec::new();
    for path in stream_paths {
        if !looks_like_vba_module(&path) {
            continue;
        }
        let mut stream: cfb::Stream<Cursor<&[u8]>> = comp
            .open_stream(&path)
            .map_err(|e: std::io::Error| Error::OleCfb(e.to_string()))?;
        let mut buf: Vec<u8> = Vec::new();
        stream.read_to_end(&mut buf).map_err(Error::Gzip)?;
        let recovered: String = decompress_mscompressed(&buf)
            .unwrap_or_else(|| String::from_utf8_lossy(&buf).into_owned());
        let name: String = path.rsplit('/').next().unwrap_or(&path).to_owned();
        modules.push(ExtractedModule {
            name,
            raw_bytes_len: buf.len(),
            recovered_source: recovered,
        });
    }
    Ok(ExtractedProject {
        container_kind: ContainerKind::OleCompoundFile,
        modules,
    })
}

fn normalise_cfb_path(p: &str) -> String {
    let unified: String = p.replace('\\', "/");
    if unified.starts_with('/') {
        unified
    } else {
        format!("/{unified}")
    }
}

fn looks_like_vba_module(path: &str) -> bool {
    let lower: String = path.to_ascii_lowercase();
    if lower == "/" || lower.is_empty() {
        return false;
    }
    lower.contains("/vba/")
        || lower.starts_with("/vba/")
        || lower.ends_with("/module1")
        || lower.ends_with("/thisdocument")
        || lower.ends_with("/thisworkbook")
        || lower.ends_with("/sheet1")
}

fn decompress_mscompressed(data: &[u8]) -> Option<String> {
    if data.first().copied() != Some(0x01) {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(data.len() * 2);
    let mut i: usize = 1;
    while i + 1 < data.len() {
        let sig: u16 = u16::from_le_bytes([data[i], data[i + 1]]);
        i += 2;
        if sig & 0x7000 != 0x3000 {
            return None;
        }
        let block_len: usize = ((sig & 0x0FFF) + 3) as usize;
        let compressed: bool = (sig & 0x8000) != 0;
        let block_end: usize = i + block_len - 2;
        if block_end > data.len() {
            return None;
        }
        if !compressed {
            out.extend_from_slice(&data[i..block_end]);
            i = block_end;
            continue;
        }
        let mut p: usize = i;
        while p < block_end {
            let token_tag: u8 = data[p];
            p += 1;
            for bit in 0..8u8 {
                if p >= block_end {
                    break;
                }
                let is_copy: bool = (token_tag >> bit) & 1 == 1;
                if !is_copy {
                    out.push(data[p]);
                    p += 1;
                } else {
                    if p + 1 >= block_end {
                        return Some(String::from_utf8_lossy(&out).into_owned());
                    }
                    let raw: u16 = u16::from_le_bytes([data[p], data[p + 1]]);
                    p += 2;
                    let length_mask: u16 = bit_mask_for_offset(out.len());
                    let length: usize = ((raw & length_mask) + 3) as usize;
                    let offset_shift: u32 = 16 - length_mask.leading_zeros();
                    let offset: usize = ((raw >> offset_shift) + 1) as usize;
                    if offset > out.len() {
                        return Some(String::from_utf8_lossy(&out).into_owned());
                    }
                    let copy_from: usize = out.len() - offset;
                    for k in 0..length {
                        let b: u8 = out[copy_from + k];
                        out.push(b);
                    }
                }
            }
        }
        i = block_end;
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

fn bit_mask_for_offset(decompressed_len: usize) -> u16 {
    let mut limit: usize = 16;
    while limit < 4096 && decompressed_len > limit {
        limit <<= 1;
    }
    let length_bits: u32 = (4 + limit.trailing_zeros()).min(15);
    (1u16 << (16 - length_bits)) - 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_passthrough() -> Result<()> {
        let r: ExtractedProject = extract_from_bytes(b"Attribute VB_Name = \"M\"\n")?;
        assert_eq!(r.container_kind, ContainerKind::RawVbaProject);
        assert_eq!(r.modules.len(), 1);
        Ok(())
    }
}
