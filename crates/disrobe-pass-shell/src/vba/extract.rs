use std::io::{Cursor, Read};

use serde::Serialize;
use zip::ZipArchive;

use crate::error::{Error, Result};

use super::pcode_real::decompress_ovba;

#[derive(Debug, Clone, Serialize)]
pub struct ExtractedModule {
    pub name: String,
    pub raw_bytes_len: usize,
    pub text_offset: Option<usize>,
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

const MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENTRY_RESERVE: usize = 4 * 1024 * 1024;
const MAX_CFB_STREAM_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CFB_STREAM_RESERVE: usize = 4 * 1024 * 1024;

const REC_MODULENAME: u16 = 0x0019;
const REC_MODULESTREAMNAME: u16 = 0x001A;
const REC_MODULEOFFSET: u16 = 0x0031;
const REC_PROJECTMODULES: u16 = 0x000F;

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
            text_offset: None,
            recovered_source: String::from_utf8_lossy(data).into_owned(),
        }],
    })
}

fn read_zip_entry_bounded(entry: &mut zip::read::ZipFile<'_>) -> Result<Vec<u8>> {
    let reserve: usize = (entry.size() as usize).min(MAX_ENTRY_RESERVE);
    let mut buf: Vec<u8> = Vec::with_capacity(reserve);
    let read: u64 = entry
        .take(MAX_ENTRY_BYTES.saturating_add(1))
        .read_to_end(&mut buf)
        .map(|n: usize| n as u64)
        .map_err(Error::Gzip)?;
    if read > MAX_ENTRY_BYTES {
        return Err(Error::VbaPcode {
            reason: format!("zip entry exceeds {MAX_ENTRY_BYTES}-byte decompression cap"),
        });
    }
    Ok(buf)
}

pub fn vba_project_bin_from_bytes(data: &[u8]) -> Result<Vec<u8>> {
    if data.starts_with(OLE_MAGIC) {
        return Ok(data.to_vec());
    }
    if data.starts_with(OOXML_MAGIC) {
        let cursor: Cursor<&[u8]> = Cursor::new(data);
        let mut zip: ZipArchive<Cursor<&[u8]>> = ZipArchive::new(cursor)?;
        for i in 0..zip.len() {
            let mut entry: zip::read::ZipFile<'_> = zip.by_index(i)?;
            if entry.name().ends_with("vbaProject.bin") {
                return read_zip_entry_bounded(&mut entry);
            }
        }
        return Err(Error::VbaPcode {
            reason: "OOXML container has no vbaProject.bin".to_owned(),
        });
    }
    Ok(data.to_vec())
}

fn extract_from_ooxml(data: &[u8]) -> Result<ExtractedProject> {
    let cursor: Cursor<&[u8]> = Cursor::new(data);
    let mut zip: ZipArchive<Cursor<&[u8]>> = ZipArchive::new(cursor)?;
    let mut modules: Vec<ExtractedModule> = Vec::new();
    for i in 0..zip.len() {
        let mut entry: zip::read::ZipFile<'_> = zip.by_index(i)?;
        let name: String = entry.name().to_owned();
        if name.ends_with("vbaProject.bin") {
            let buf: Vec<u8> = read_zip_entry_bounded(&mut entry)?;
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

#[derive(Debug, Clone)]
struct ModuleRef {
    name: String,
    stream: String,
    text_offset: usize,
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
    let module_refs: Vec<ModuleRef> = read_module_refs(&mut comp, &stream_paths);
    let mut modules: Vec<ExtractedModule> = Vec::new();
    if !module_refs.is_empty() {
        for module_ref in &module_refs {
            let stream_path: String = locate_module_stream(&stream_paths, &module_ref.stream);
            let Ok(buf): Result<Vec<u8>> = read_stream(&mut comp, &stream_path) else {
                continue;
            };
            let recovered: String = decompress_source_at(&buf, module_ref.text_offset)?;
            modules.push(ExtractedModule {
                name: module_ref.name.clone(),
                raw_bytes_len: buf.len(),
                text_offset: Some(module_ref.text_offset),
                recovered_source: recovered,
            });
        }
        return Ok(ExtractedProject {
            container_kind: ContainerKind::OleCompoundFile,
            modules,
        });
    }
    for path in stream_paths {
        if !looks_like_vba_module(&path) {
            continue;
        }
        let buf: Vec<u8> = read_stream(&mut comp, &path)?;
        let recovered: String = decompress_ovba(&buf)
            .ok()
            .map(|bytes: Vec<u8>| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_else(|| String::from_utf8_lossy(&buf).into_owned());
        let name: String = path.rsplit('/').next().unwrap_or(&path).to_owned();
        modules.push(ExtractedModule {
            name,
            raw_bytes_len: buf.len(),
            text_offset: None,
            recovered_source: recovered,
        });
    }
    Ok(ExtractedProject {
        container_kind: ContainerKind::OleCompoundFile,
        modules,
    })
}

fn read_stream(comp: &mut cfb::CompoundFile<Cursor<&[u8]>>, path: &str) -> Result<Vec<u8>> {
    let stream: cfb::Stream<Cursor<&[u8]>> = comp
        .open_stream(path)
        .map_err(|e: std::io::Error| Error::OleCfb(e.to_string()))?;
    let mut buf: Vec<u8> = Vec::with_capacity(MAX_CFB_STREAM_RESERVE);
    let read: u64 = stream
        .take(MAX_CFB_STREAM_BYTES.saturating_add(1))
        .read_to_end(&mut buf)
        .map(|n: usize| n as u64)
        .map_err(Error::Gzip)?;
    if read > MAX_CFB_STREAM_BYTES {
        return Err(Error::VbaPcode {
            reason: format!("OLE stream {path} exceeds {MAX_CFB_STREAM_BYTES}-byte cap"),
        });
    }
    Ok(buf)
}

fn read_module_refs(
    comp: &mut cfb::CompoundFile<Cursor<&[u8]>>,
    stream_paths: &[String],
) -> Vec<ModuleRef> {
    let dir_path: String = locate_dir_stream(stream_paths);
    let Ok(dir_compressed): Result<Vec<u8>> = read_stream(comp, &dir_path) else {
        return Vec::new();
    };
    let Ok(dir): Result<Vec<u8>> = decompress_ovba(&dir_compressed) else {
        return Vec::new();
    };
    parse_module_table(&dir)
}

fn locate_module_section(dir: &[u8]) -> Option<usize> {
    let signature: [u8; 6] = [
        (REC_PROJECTMODULES & 0xFF) as u8,
        (REC_PROJECTMODULES >> 8) as u8,
        0x02,
        0x00,
        0x00,
        0x00,
    ];
    let mut offset: usize = 0;
    while let Some(record_end) = offset
        .checked_add(8)
        .filter(|end: &usize| *end <= dir.len())
    {
        let signature_end: usize = offset + 6;
        if dir[offset..signature_end] == signature {
            return Some(record_end);
        }
        offset += 1;
    }
    None
}

fn parse_module_table(dir: &[u8]) -> Vec<ModuleRef> {
    let Some(start): Option<usize> = locate_module_section(dir) else {
        return Vec::new();
    };
    let mut modules: Vec<ModuleRef> = Vec::new();
    let mut name: Option<String> = None;
    let mut stream: Option<String> = None;
    let mut cursor: usize = start;
    while let Some(body) = cursor
        .checked_add(6)
        .filter(|body: &usize| *body <= dir.len())
    {
        let tag: u16 = u16::from_le_bytes([dir[cursor], dir[cursor + 1]]);
        let size: usize = u32::from_le_bytes([
            dir[cursor + 2],
            dir[cursor + 3],
            dir[cursor + 4],
            dir[cursor + 5],
        ]) as usize;
        let Some(body_end): Option<usize> = body.checked_add(size) else {
            break;
        };
        if body_end > dir.len() {
            break;
        }
        match tag {
            REC_MODULENAME => {
                name = Some(decode_mbcs(&dir[body..body_end]));
            }
            REC_MODULESTREAMNAME => {
                stream = Some(decode_mbcs(&dir[body..body_end]));
            }
            REC_MODULEOFFSET if size >= 4 => {
                let text_offset: usize =
                    u32::from_le_bytes([dir[body], dir[body + 1], dir[body + 2], dir[body + 3]])
                        as usize;
                if let Some(stream_name) = stream.clone() {
                    let module_name: String = name.clone().unwrap_or_else(|| stream_name.clone());
                    modules.push(ModuleRef {
                        name: module_name,
                        stream: stream_name,
                        text_offset,
                    });
                }
                name = None;
                stream = None;
            }
            _ => {}
        }
        cursor = body_end;
    }
    modules
}

fn decompress_source_at(stream: &[u8], text_offset: usize) -> Result<String> {
    if text_offset >= stream.len() {
        return Err(Error::VbaPcode {
            reason: format!(
                "module TextOffset {text_offset} outside stream length {}",
                stream.len()
            ),
        });
    }
    let compressed: &[u8] = &stream[text_offset..];
    let bytes: Vec<u8> = decompress_ovba(compressed)?;
    Ok(decode_mbcs(&bytes))
}

fn decode_mbcs(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_owned(),
        Err(_) => bytes.iter().map(|b: &u8| *b as char).collect(),
    }
}

fn locate_dir_stream(stream_paths: &[String]) -> String {
    for path in stream_paths {
        if path.to_ascii_lowercase().ends_with("/dir") {
            return path.clone();
        }
    }
    "/VBA/dir".to_owned()
}

fn locate_module_stream(stream_paths: &[String], stream_name: &str) -> String {
    let target: String = stream_name.to_ascii_lowercase();
    for path in stream_paths {
        let lower: String = path.to_ascii_lowercase();
        if lower
            .rsplit('/')
            .next()
            .is_some_and(|leaf: &str| leaf == target)
        {
            return path.clone();
        }
    }
    format!("/VBA/{stream_name}")
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
    if lower.ends_with("/dir") || lower.ends_with("/_vba_project") {
        return false;
    }
    lower.contains("/vba/")
        || lower.starts_with("/vba/")
        || lower.ends_with("/module1")
        || lower.ends_with("/thisdocument")
        || lower.ends_with("/thisworkbook")
        || lower.ends_with("/sheet1")
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

    #[test]
    fn module_table_parses_name_stream_offset() {
        let mut dir: Vec<u8> = Vec::new();
        push_record(&mut dir, REC_PROJECTMODULES, &1u16.to_le_bytes());
        push_record(&mut dir, REC_MODULENAME, b"Module1");
        push_record(&mut dir, REC_MODULESTREAMNAME, b"Module1");
        push_record(&mut dir, REC_MODULEOFFSET, &1234u32.to_le_bytes());
        let refs: Vec<ModuleRef> = parse_module_table(&dir);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, "Module1");
        assert_eq!(refs[0].stream, "Module1");
        assert_eq!(refs[0].text_offset, 1234);
    }

    #[test]
    fn module_table_without_projectmodules_is_empty() {
        let mut dir: Vec<u8> = Vec::new();
        push_record(&mut dir, REC_MODULENAME, b"Module1");
        assert!(parse_module_table(&dir).is_empty());
    }

    #[test]
    fn module_table_truncated_large_record_is_empty() {
        let mut dir: Vec<u8> = Vec::new();
        push_record(&mut dir, REC_PROJECTMODULES, &1u16.to_le_bytes());
        dir.extend_from_slice(&REC_MODULENAME.to_le_bytes());
        dir.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_module_table(&dir).is_empty());
    }

    #[test]
    fn invalid_text_offset_is_explicit_error() {
        assert!(matches!(
            decompress_source_at(b"short", 99),
            Err(Error::VbaPcode { reason }) if reason.contains("TextOffset")
        ));
    }

    #[test]
    fn malformed_compressed_source_is_explicit_error() {
        assert!(matches!(
            decompress_source_at(b"not an ovba compressed stream", 0),
            Err(Error::VbaPcode { .. })
        ));
    }

    fn push_record(buf: &mut Vec<u8>, tag: u16, body: &[u8]) {
        buf.extend_from_slice(&tag.to_le_bytes());
        buf.extend_from_slice(&(body.len() as u32).to_le_bytes());
        buf.extend_from_slice(body);
    }
}
