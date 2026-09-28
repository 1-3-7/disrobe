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
    pub source_error: Option<String>,
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
const MAX_MODULE_REFS: usize = 512;
const MAX_TOTAL_MODULE_STREAM_BYTES: u64 = 256 * 1024 * 1024;

const REC_MODULENAME: u16 = 0x0019;
const REC_MODULESTREAMNAME: u16 = 0x001A;
const REC_MODULEOFFSET: u16 = 0x0031;
const REC_PROJECTMODULES: u16 = 0x000F;
const REC_PROJECTCODEPAGE: u16 = 0x0003;
const PROJECT_INFORMATION_RECORD_LIMIT: usize = 32;

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
            source_error: None,
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
        .map(|e: cfb::Entry| normalize_cfb_path(&e.path().display().to_string()))
        .collect();
    let (module_refs, codepage): (Vec<ModuleRef>, Option<u16>) =
        read_module_refs(&mut comp, &stream_paths);
    if module_refs.len() > MAX_MODULE_REFS {
        return Err(Error::VbaPcode {
            reason: format!(
                "VBA project declares {} modules, above the {MAX_MODULE_REFS}-module cap",
                module_refs.len()
            ),
        });
    }
    let mut modules: Vec<ExtractedModule> = Vec::new();
    if !module_refs.is_empty() {
        let mut stream_budget: u64 = MAX_TOTAL_MODULE_STREAM_BYTES;
        for module_ref in &module_refs {
            let stream_path: String = locate_module_stream(&stream_paths, &module_ref.stream);
            let read: Result<Vec<u8>> = read_stream(&mut comp, &stream_path);
            let (buf, read_error): (Vec<u8>, Option<String>) = match read {
                Ok(bytes) => (bytes, None),
                Err(e) => (Vec::new(), Some(e.to_string())),
            };
            let Some(remaining): Option<u64> = stream_budget.checked_sub(buf.len() as u64) else {
                return Err(Error::VbaPcode {
                    reason: format!(
                        "VBA module streams exceed the {MAX_TOTAL_MODULE_STREAM_BYTES}-byte total cap"
                    ),
                });
            };
            stream_budget = remaining;
            let (recovered, source_error): (String, Option<String>) = match read_error {
                Some(reason) => (String::new(), Some(reason)),
                None => match decompress_source_at(&buf, module_ref.text_offset, codepage) {
                    Ok(text) => (text, None),
                    Err(e) => (String::new(), Some(e.to_string())),
                },
            };
            modules.push(ExtractedModule {
                name: module_ref.name.clone(),
                raw_bytes_len: buf.len(),
                text_offset: Some(module_ref.text_offset),
                recovered_source: recovered,
                source_error,
            });
        }
        return Ok(ExtractedProject {
            container_kind: ContainerKind::OleCompoundFile,
            modules,
        });
    }
    let mut stream_budget: u64 = MAX_TOTAL_MODULE_STREAM_BYTES;
    for path in stream_paths {
        if !looks_like_vba_module(&path) {
            continue;
        }
        if modules.len() >= MAX_MODULE_REFS {
            return Err(Error::VbaPcode {
                reason: format!(
                    "VBA container holds more than {MAX_MODULE_REFS} module-shaped streams"
                ),
            });
        }
        let name: String = path.rsplit('/').next().unwrap_or(&path).to_owned();
        let buf: Vec<u8> = match read_stream(&mut comp, &path) {
            Ok(bytes) => bytes,
            Err(e) => {
                modules.push(ExtractedModule {
                    name,
                    raw_bytes_len: 0,
                    text_offset: None,
                    recovered_source: String::new(),
                    source_error: Some(e.to_string()),
                });
                continue;
            }
        };
        let Some(remaining): Option<u64> = stream_budget.checked_sub(buf.len() as u64) else {
            return Err(Error::VbaPcode {
                reason: format!(
                    "VBA module streams exceed the {MAX_TOTAL_MODULE_STREAM_BYTES}-byte total cap"
                ),
            });
        };
        stream_budget = remaining;
        let (recovered, source_error): (String, Option<String>) = match decompress_ovba(&buf) {
            Ok(bytes) => (decode_mbcs(&bytes, codepage), None),
            Err(e) => (String::new(), Some(e.to_string())),
        };
        modules.push(ExtractedModule {
            name,
            raw_bytes_len: buf.len(),
            text_offset: None,
            recovered_source: recovered,
            source_error,
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
) -> (Vec<ModuleRef>, Option<u16>) {
    let dir_path: String = locate_dir_stream(stream_paths);
    let Ok(dir_compressed): Result<Vec<u8>> = read_stream(comp, &dir_path) else {
        return (Vec::new(), None);
    };
    let Ok(dir): Result<Vec<u8>> = decompress_ovba(&dir_compressed) else {
        return (Vec::new(), None);
    };
    let codepage: Option<u16> = project_codepage(&dir);
    (parse_module_table(&dir, codepage), codepage)
}

pub(super) fn project_codepage(dir: &[u8]) -> Option<u16> {
    let mut cursor: usize = 0;
    for _ in 0..PROJECT_INFORMATION_RECORD_LIMIT {
        let header: &[u8] = dir.get(cursor..cursor.checked_add(6)?)?;
        let tag: u16 = u16::from_le_bytes([header[0], header[1]]);
        let size: usize = usize::try_from(u32::from_le_bytes([
            header[2], header[3], header[4], header[5],
        ]))
        .ok()?;
        let body: usize = cursor + 6;
        if tag == REC_PROJECTCODEPAGE {
            let value: &[u8] = dir.get(body..body.checked_add(2)?)?;
            return Some(u16::from_le_bytes([value[0], value[1]]));
        }
        cursor = body.checked_add(size)?;
    }
    None
}

fn codepage_encoding(codepage: u16) -> Option<&'static encoding_rs::Encoding> {
    let label: String = match codepage {
        65001 => "utf-8".to_owned(),
        932 => "shift_jis".to_owned(),
        936 => "gbk".to_owned(),
        949 => "euc-kr".to_owned(),
        950 => "big5".to_owned(),
        874 | 1250..=1258 => format!("windows-{codepage}"),
        10000 => "macintosh".to_owned(),
        20866 => "koi8-r".to_owned(),
        21866 => "koi8-u".to_owned(),
        28591..=28606 => format!("iso-8859-{}", codepage - 28590),
        _ => return None,
    };
    encoding_rs::Encoding::for_label(label.as_bytes())
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

fn parse_module_table(dir: &[u8], codepage: Option<u16>) -> Vec<ModuleRef> {
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
                name = Some(decode_mbcs(&dir[body..body_end], codepage));
            }
            REC_MODULESTREAMNAME => {
                stream = Some(decode_mbcs(&dir[body..body_end], codepage));
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
                    if modules.len() > MAX_MODULE_REFS {
                        return modules;
                    }
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

fn decompress_source_at(
    stream: &[u8],
    text_offset: usize,
    codepage: Option<u16>,
) -> Result<String> {
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
    Ok(decode_mbcs(&bytes, codepage))
}

pub(super) fn decode_mbcs(bytes: &[u8], codepage: Option<u16>) -> String {
    if let Some(encoding) = codepage.and_then(codepage_encoding) {
        return encoding.decode_without_bom_handling(bytes).0.into_owned();
    }
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_owned(),
        Err(_) => encoding_rs::WINDOWS_1252
            .decode_without_bom_handling(bytes)
            .0
            .into_owned(),
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

fn normalize_cfb_path(p: &str) -> String {
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

    fn dir_record(tag: u16, body: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = tag.to_le_bytes().to_vec();
        out.extend_from_slice(&u32::try_from(body.len()).unwrap_or(0).to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn the_project_codepage_is_read_from_the_information_records() {
        let mut dir: Vec<u8> = dir_record(0x0001, &3u32.to_le_bytes());
        dir.extend(dir_record(0x0002, &0x0411u32.to_le_bytes()));
        dir.extend(dir_record(0x0014, &0x0411u32.to_le_bytes()));
        dir.extend(dir_record(REC_PROJECTCODEPAGE, &932u16.to_le_bytes()));
        assert_eq!(project_codepage(&dir), Some(932));
        assert_eq!(project_codepage(&dir[..10]), None);
    }

    #[test]
    fn module_text_decodes_through_the_declared_codepage() {
        let shift_jis: &[u8] = b"MsgBox \"\x93\xfa\x96\x7b\"";
        assert_eq!(decode_mbcs(shift_jis, Some(932)), "MsgBox \"日本\"");
        let cp1251: &[u8] = b"s = \"\xcf\xf0\xe8\xe2\xe5\xf2\"";
        assert_eq!(decode_mbcs(cp1251, Some(1251)), "s = \"Привет\"");
        assert_eq!(decode_mbcs(b"caf\xe9", None), "café");
    }

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
        let refs: Vec<ModuleRef> = parse_module_table(&dir, None);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, "Module1");
        assert_eq!(refs[0].stream, "Module1");
        assert_eq!(refs[0].text_offset, 1234);
    }

    #[test]
    fn module_table_without_projectmodules_is_empty() {
        let mut dir: Vec<u8> = Vec::new();
        push_record(&mut dir, REC_MODULENAME, b"Module1");
        assert!(parse_module_table(&dir, None).is_empty());
    }

    #[test]
    fn module_table_truncated_large_record_is_empty() {
        let mut dir: Vec<u8> = Vec::new();
        push_record(&mut dir, REC_PROJECTMODULES, &1u16.to_le_bytes());
        dir.extend_from_slice(&REC_MODULENAME.to_le_bytes());
        dir.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_module_table(&dir, None).is_empty());
    }

    #[test]
    fn invalid_text_offset_is_explicit_error() {
        assert!(matches!(
            decompress_source_at(b"short", 99, None),
            Err(Error::VbaPcode { reason }) if reason.contains("TextOffset")
        ));
    }

    #[test]
    fn malformed_compressed_source_is_explicit_error() {
        assert!(matches!(
            decompress_source_at(b"not an ovba compressed stream", 0, None),
            Err(Error::VbaPcode { .. })
        ));
    }

    fn push_record(buf: &mut Vec<u8>, tag: u16, body: &[u8]) {
        buf.extend_from_slice(&tag.to_le_bytes());
        buf.extend_from_slice(&(body.len() as u32).to_le_bytes());
        buf.extend_from_slice(body);
    }
}
