use std::io::{Cursor, Read};

use zip::ZipArchive;

use super::limits::{MAX_WORKBOOK_BYTES, MAX_ZIP_ENTRIES, MAX_ZIP_ENTRY_BYTES};

const OLE_MAGIC: &[u8; 8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1";
const ZIP_MAGIC: &[u8] = b"PK\x03\x04";

const MACROSHEET_CONTENT_TYPE: &str = "application/vnd.ms-excel.macrosheet";
const WORKSHEET_CONTENT_TYPE: &str = "application/vnd.ms-excel.worksheet";
const OFFICE_DOCUMENT_REL: &str = "officeDocument";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SheetKindHint {
    Macro,
    Worksheet,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Biff12SheetPart {
    pub name_hint: Option<String>,
    pub kind_hint: SheetKindHint,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum XlmSource {
    Biff8 { workbook: Vec<u8> },
    Biff12 { sheets: Vec<Biff12SheetPart> },
}

pub fn open_source(data: &[u8]) -> Option<XlmSource> {
    if data.starts_with(OLE_MAGIC) {
        return open_biff8(data);
    }
    if data.starts_with(ZIP_MAGIC) {
        return open_biff12(data);
    }
    None
}

fn open_biff8(data: &[u8]) -> Option<XlmSource> {
    let cursor: Cursor<&[u8]> = Cursor::new(data);
    let mut comp: cfb::CompoundFile<Cursor<&[u8]>> = cfb::CompoundFile::open(cursor).ok()?;
    let target: String = comp
        .walk()
        .filter(|e: &cfb::Entry| e.is_stream())
        .map(|e: cfb::Entry| e.path().display().to_string())
        .find(|p: &String| {
            let leaf: &str = p.rsplit(['/', '\\']).next().unwrap_or(p);
            leaf.eq_ignore_ascii_case("Workbook") || leaf.eq_ignore_ascii_case("Book")
        })?;
    let workbook: Vec<u8> = read_cfb_stream(&mut comp, &target)?;
    Some(XlmSource::Biff8 { workbook })
}

fn read_cfb_stream(comp: &mut cfb::CompoundFile<Cursor<&[u8]>>, path: &str) -> Option<Vec<u8>> {
    let stream: cfb::Stream<Cursor<&[u8]>> = comp.open_stream(path).ok()?;
    let mut buf: Vec<u8> = Vec::new();
    let read: u64 = stream
        .take(MAX_WORKBOOK_BYTES.saturating_add(1))
        .read_to_end(&mut buf)
        .ok()? as u64;
    if read > MAX_WORKBOOK_BYTES {
        return None;
    }
    Some(buf)
}

fn read_zip_entry(archive: &mut ZipArchive<Cursor<&[u8]>>, name: &str) -> Option<Vec<u8>> {
    let mut entry: zip::read::ZipFile<'_> = archive.by_name(name).ok()?;
    let mut buf: Vec<u8> = Vec::new();
    let read: u64 = entry
        .by_ref()
        .take(MAX_ZIP_ENTRY_BYTES.saturating_add(1))
        .read_to_end(&mut buf)
        .ok()? as u64;
    if read > MAX_ZIP_ENTRY_BYTES {
        return None;
    }
    Some(buf)
}

fn read_zip_text(archive: &mut ZipArchive<Cursor<&[u8]>>, name: &str) -> Option<String> {
    let bytes: Vec<u8> = read_zip_entry(archive, name)?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn open_biff12(data: &[u8]) -> Option<XlmSource> {
    let cursor: Cursor<&[u8]> = Cursor::new(data);
    let mut archive: ZipArchive<Cursor<&[u8]>> = ZipArchive::new(cursor).ok()?;
    if archive.len() > MAX_ZIP_ENTRIES {
        return None;
    }
    let entry_names: Vec<String> = (0..archive.len())
        .filter_map(|i: usize| archive.by_index(i).ok().map(|e| e.name().to_owned()))
        .collect();
    let content_types: Vec<(String, String)> = read_zip_text(&mut archive, "[Content_Types].xml")
        .map(|xml: String| parse_overrides(&xml))
        .unwrap_or_default();
    let workbook_part: String =
        resolve_workbook_part(&mut archive).unwrap_or_else(|| "xl/workbook.bin".to_owned());
    let name_by_rel: Vec<(String, String)> = read_workbook_rels(&mut archive, &workbook_part);
    let sheet_targets: Vec<String> = collect_sheet_targets(&name_by_rel, &workbook_part);
    let mut sheets: Vec<Biff12SheetPart> = Vec::new();
    let candidates: Vec<String> = if sheet_targets.is_empty() {
        entry_names
            .iter()
            .filter(|n: &&String| is_sheet_part(n))
            .cloned()
            .collect()
    } else {
        sheet_targets
    };
    for part in candidates {
        let Some(bytes): Option<Vec<u8>> = read_zip_entry(&mut archive, &part) else {
            continue;
        };
        let kind_hint: SheetKindHint = classify_part(&part, &content_types);
        sheets.push(Biff12SheetPart {
            name_hint: Some(leaf_name(&part)),
            kind_hint,
            bytes,
        });
    }
    if sheets.is_empty() {
        return None;
    }
    Some(XlmSource::Biff12 { sheets })
}

fn is_sheet_part(name: &str) -> bool {
    let lower: String = name.to_ascii_lowercase();
    let is_bin: bool = std::path::Path::new(&lower)
        .extension()
        .is_some_and(|ext: &std::ffi::OsStr| ext == "bin");
    is_bin
        && (lower.contains("/worksheets/")
            || lower.contains("/macrosheets/")
            || lower.contains("/chartsheets/"))
}

fn leaf_name(part: &str) -> String {
    part.rsplit(['/', '\\']).next().unwrap_or(part).to_owned()
}

fn classify_part(part: &str, content_types: &[(String, String)]) -> SheetKindHint {
    let normalised: String = normalise_part_name(part);
    for (name, ctype) in content_types {
        if normalise_part_name(name) == normalised {
            if ctype.eq_ignore_ascii_case(MACROSHEET_CONTENT_TYPE) {
                return SheetKindHint::Macro;
            }
            if ctype.eq_ignore_ascii_case(WORKSHEET_CONTENT_TYPE) {
                return SheetKindHint::Worksheet;
            }
        }
    }
    if part.to_ascii_lowercase().contains("/macrosheets/") {
        return SheetKindHint::Macro;
    }
    if part.to_ascii_lowercase().contains("/worksheets/") {
        return SheetKindHint::Worksheet;
    }
    SheetKindHint::Unknown
}

fn normalise_part_name(name: &str) -> String {
    name.trim_start_matches('/').to_ascii_lowercase()
}

fn resolve_workbook_part(archive: &mut ZipArchive<Cursor<&[u8]>>) -> Option<String> {
    let xml: String = read_zip_text(archive, "_rels/.rels")?;
    for (rel_type, target) in parse_relationships(&xml) {
        if rel_type.contains(OFFICE_DOCUMENT_REL) {
            return Some(normalise_target(&target, ""));
        }
    }
    None
}

fn read_workbook_rels(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    workbook_part: &str,
) -> Vec<(String, String)> {
    let (dir, leaf): (&str, &str) = split_dir(workbook_part);
    let rels_path: String = if dir.is_empty() {
        format!("_rels/{leaf}.rels")
    } else {
        format!("{dir}/_rels/{leaf}.rels")
    };
    let Some(xml): Option<String> = read_zip_text(archive, &rels_path) else {
        return Vec::new();
    };
    parse_relationships_with_id(&xml)
        .into_iter()
        .map(|(id, _rel_type, target): (String, String, String)| {
            (id, normalise_target(&target, dir))
        })
        .collect()
}

fn collect_sheet_targets(name_by_rel: &[(String, String)], workbook_part: &str) -> Vec<String> {
    let _ = workbook_part;
    name_by_rel
        .iter()
        .map(|(_id, target): &(String, String)| target.clone())
        .filter(|t: &String| is_sheet_part(t))
        .collect()
}

fn split_dir(part: &str) -> (&str, &str) {
    match part.rsplit_once('/') {
        Some((dir, leaf)) => (dir, leaf),
        None => ("", part),
    }
}

fn normalise_target(target: &str, base_dir: &str) -> String {
    if let Some(stripped) = target.strip_prefix('/') {
        return stripped.to_owned();
    }
    if base_dir.is_empty() {
        return target.to_owned();
    }
    let mut segments: Vec<&str> = base_dir.split('/').collect();
    for part in target.split('/') {
        match part {
            "." | "" => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    segments.join("/")
}

fn attr(fragment: &str, key: &str) -> Option<String> {
    let needle: String = format!("{key}=\"");
    let start: usize = fragment.find(&needle)? + needle.len();
    let rest: &str = fragment.get(start..)?;
    let end: usize = rest.find('"')?;
    Some(rest.get(..end)?.to_owned())
}

fn parse_overrides(xml: &str) -> Vec<(String, String)> {
    xml.split('<')
        .filter(|frag: &&str| frag.starts_with("Override"))
        .filter_map(|frag: &str| {
            let part: String = attr(frag, "PartName")?;
            let ctype: String = attr(frag, "ContentType")?;
            Some((part, ctype))
        })
        .collect()
}

fn parse_relationships(xml: &str) -> Vec<(String, String)> {
    xml.split('<')
        .filter(|frag: &&str| frag.starts_with("Relationship"))
        .filter_map(|frag: &str| {
            let rel_type: String = attr(frag, "Type")?;
            let target: String = attr(frag, "Target")?;
            Some((rel_type, target))
        })
        .collect()
}

fn parse_relationships_with_id(xml: &str) -> Vec<(String, String, String)> {
    xml.split('<')
        .filter(|frag: &&str| frag.starts_with("Relationship"))
        .filter_map(|frag: &str| {
            let id: String = attr(frag, "Id")?;
            let rel_type: String = attr(frag, "Type").unwrap_or_default();
            let target: String = attr(frag, "Target")?;
            Some((id, rel_type, target))
        })
        .collect()
}
