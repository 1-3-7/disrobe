use std::io::{Cursor, Read};

use zip::ZipArchive;

use super::limits::{MAX_WORKBOOK_BYTES, MAX_ZIP_ENTRIES, MAX_ZIP_ENTRY_BYTES};

const OLE_MAGIC: &[u8; 8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1";
const ZIP_MAGIC: &[u8] = b"PK\x03\x04";

const MACROSHEET_CONTENT_TYPE: &str = "application/vnd.ms-excel.macrosheet";
const INTL_MACROSHEET_CONTENT_TYPE: &str = "application/vnd.ms-excel.intlmacrosheet";
const WORKSHEET_CONTENT_TYPE: &str = "application/vnd.ms-excel.worksheet";
const CHARTSHEET_CONTENT_TYPE: &str = "application/vnd.ms-excel.chartsheet";
const DIALOGSHEET_CONTENT_TYPE: &str = "application/vnd.ms-excel.dialogsheet";

const SHEET_CONTENT_TYPES: [&str; 5] = [
    MACROSHEET_CONTENT_TYPE,
    INTL_MACROSHEET_CONTENT_TYPE,
    WORKSHEET_CONTENT_TYPE,
    CHARTSHEET_CONTENT_TYPE,
    DIALOGSHEET_CONTENT_TYPE,
];

const OFFICE_DOCUMENT_REL: &str = "officeDocument";

const SHEET_RELATIONSHIPS: [&str; 5] = [
    "worksheet",
    "chartsheet",
    "dialogsheet",
    "xlMacrosheet",
    "xlIntlMacrosheet",
];

const SHEET_DIRECTORIES: [&str; 4] = [
    "/worksheets/",
    "/macrosheets/",
    "/chartsheets/",
    "/dialogsheets/",
];

const BINARY_INDEX_LEAF_PREFIX: &str = "binaryindex";
const BINARY_INDEX_CONTENT_TYPE_MARKER: &str = "binindex";

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
    let rels: Vec<PartRelationship> = read_part_rels(&mut archive, &workbook_part);
    let bundled: Vec<(String, String)> = read_bundled_sheets(&mut archive, &workbook_part);
    let sheet_targets: Vec<(String, Option<String>)> = collect_sheet_targets(&bundled, &rels);
    let mut sheets: Vec<Biff12SheetPart> = Vec::new();
    let candidates: Vec<(String, Option<String>)> = if sheet_targets.is_empty() {
        entry_names
            .iter()
            .filter(|n: &&String| is_sheet_part(n, &content_types))
            .map(|n: &String| (n.clone(), None))
            .collect()
    } else {
        sheet_targets
    };
    for (part, tab_name) in candidates {
        let Some(bytes): Option<Vec<u8>> = read_zip_entry(&mut archive, &part) else {
            continue;
        };
        let kind_hint: SheetKindHint = classify_part(&part, &content_types);
        sheets.push(Biff12SheetPart {
            name_hint: Some(tab_name.unwrap_or_else(|| leaf_name(&part))),
            kind_hint,
            bytes,
        });
    }
    if sheets.is_empty() {
        return None;
    }
    Some(XlmSource::Biff12 { sheets })
}

const BRT_BUNDLE_SH: u32 = 156;
const NULL_STRING_LEN: u32 = 0xFFFF_FFFF;

fn read_bundled_sheets(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    workbook_part: &str,
) -> Vec<(String, String)> {
    let Some(bytes): Option<Vec<u8>> = read_zip_entry(archive, workbook_part) else {
        return Vec::new();
    };
    super::biff::iter_biff12(&bytes)
        .iter()
        .filter(|rec: &&super::biff::BiffRecord| rec.rt == BRT_BUNDLE_SH)
        .filter_map(|rec: &super::biff::BiffRecord| parse_bundle_sh(&rec.data))
        .collect()
}

fn parse_bundle_sh(data: &[u8]) -> Option<(String, String)> {
    let rel_len: u32 = super::biff::read_u32(data, 8)?;
    if rel_len == NULL_STRING_LEN {
        return None;
    }
    let (rel_id, consumed): (String, usize) = super::biff::read_wide_string32(data, 8)?;
    let (name, _consumed): (String, usize) = super::biff::read_wide_string32(data, 8 + consumed)?;
    Some((rel_id, name))
}

fn is_sheet_part(name: &str, content_types: &[(String, String)]) -> bool {
    let declared: Option<&str> = content_type_of(name, content_types);
    if declared.is_some_and(is_sheet_content_type) {
        return true;
    }
    if declared.is_some_and(is_index_content_type) {
        return false;
    }
    let lower: String = name.to_ascii_lowercase();
    let is_bin: bool = std::path::Path::new(&lower)
        .extension()
        .is_some_and(|ext: &std::ffi::OsStr| ext == "bin");
    is_bin
        && !leaf_name(&lower).starts_with(BINARY_INDEX_LEAF_PREFIX)
        && SHEET_DIRECTORIES
            .iter()
            .any(|dir: &&str| lower.contains(dir))
}

fn is_sheet_content_type(declared: &str) -> bool {
    SHEET_CONTENT_TYPES
        .iter()
        .any(|kind: &&str| declared.eq_ignore_ascii_case(kind))
}

fn is_index_content_type(declared: &str) -> bool {
    declared
        .to_ascii_lowercase()
        .contains(BINARY_INDEX_CONTENT_TYPE_MARKER)
}

fn content_type_of<'a>(part: &str, content_types: &'a [(String, String)]) -> Option<&'a str> {
    let normalized: String = normalize_part_name(part);
    content_types
        .iter()
        .find(|(name, _ctype): &&(String, String)| normalize_part_name(name) == normalized)
        .map(|(_name, ctype): &(String, String)| ctype.as_str())
}

fn leaf_name(part: &str) -> String {
    part.rsplit(['/', '\\']).next().unwrap_or(part).to_owned()
}

fn classify_part(part: &str, content_types: &[(String, String)]) -> SheetKindHint {
    if let Some(declared) = content_type_of(part, content_types) {
        if declared.eq_ignore_ascii_case(MACROSHEET_CONTENT_TYPE)
            || declared.eq_ignore_ascii_case(INTL_MACROSHEET_CONTENT_TYPE)
        {
            return SheetKindHint::Macro;
        }
        if declared.eq_ignore_ascii_case(WORKSHEET_CONTENT_TYPE) {
            return SheetKindHint::Worksheet;
        }
    }
    let lower: String = part.to_ascii_lowercase();
    if lower.contains("/macrosheets/") {
        return SheetKindHint::Macro;
    }
    if lower.contains("/worksheets/") {
        return SheetKindHint::Worksheet;
    }
    SheetKindHint::Unknown
}

fn normalize_part_name(name: &str) -> String {
    name.trim_start_matches('/').to_ascii_lowercase()
}

#[derive(Debug, Clone)]
struct PartRelationship {
    id: String,
    kind: String,
    target: String,
}

fn relationship_kind(rel_type: &str) -> &str {
    rel_type
        .rsplit('/')
        .next()
        .filter(|segment: &&str| !segment.is_empty())
        .unwrap_or(rel_type)
}

fn is_sheet_relationship(kind: &str) -> bool {
    SHEET_RELATIONSHIPS
        .iter()
        .any(|known: &&str| kind.eq_ignore_ascii_case(known))
}

fn resolve_workbook_part(archive: &mut ZipArchive<Cursor<&[u8]>>) -> Option<String> {
    let xml: String = read_zip_text(archive, "_rels/.rels")?;
    parse_relationships(&xml)
        .into_iter()
        .find(|(rel_type, _target): &(String, String)| {
            relationship_kind(rel_type).eq_ignore_ascii_case(OFFICE_DOCUMENT_REL)
        })
        .map(|(_rel_type, target): (String, String)| normalize_target(&target, ""))
}

fn read_part_rels(archive: &mut ZipArchive<Cursor<&[u8]>>, part: &str) -> Vec<PartRelationship> {
    let (dir, leaf): (&str, &str) = split_dir(part);
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
        .map(
            |(id, rel_type, target): (String, String, String)| PartRelationship {
                id,
                kind: relationship_kind(&rel_type).to_owned(),
                target: normalize_target(&target, dir),
            },
        )
        .collect()
}

fn collect_sheet_targets(
    bundled: &[(String, String)],
    rels: &[PartRelationship],
) -> Vec<(String, Option<String>)> {
    let mut out: Vec<(String, Option<String>)> = Vec::new();
    let mut claimed: Vec<&str> = Vec::new();
    for (rel_id, tab_name) in bundled {
        let Some(rel): Option<&PartRelationship> = rels
            .iter()
            .find(|rel: &&PartRelationship| rel.id == *rel_id && is_sheet_relationship(&rel.kind))
        else {
            continue;
        };
        claimed.push(rel.id.as_str());
        out.push((rel.target.clone(), Some(tab_name.clone())));
    }
    for rel in rels {
        if is_sheet_relationship(&rel.kind) && !claimed.contains(&rel.id.as_str()) {
            out.push((rel.target.clone(), None));
        }
    }
    out
}

fn split_dir(part: &str) -> (&str, &str) {
    match part.rsplit_once('/') {
        Some((dir, leaf)) => (dir, leaf),
        None => ("", part),
    }
}

fn normalize_target(target: &str, base_dir: &str) -> String {
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
