use std::collections::BTreeSet;

use serde::Serialize;

use super::btree::{PageHeader, read_cell};
use super::format::{PAGE_LEAF_TABLE, TextEncoding, be16, be32, varint};
use super::pager::Pager;
use super::record::{RecordHeader, SqlValue, decode_body, parse_header};
use super::{Limits, TableReport};

const MIN_CARVED_COLUMNS: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecoveryConfidence {
    Exact,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RecoverySource {
    FreelistPage { page: u32 },
    Freeblock { page: u32, offset: usize },
    Unallocated { page: u32, offset: usize },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RecoveredRecord {
    pub source: RecoverySource,
    pub confidence: RecoveryConfidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub candidate_tables: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rowid: Option<i64>,
    pub values: Vec<SqlValue>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FreelistReport {
    pub trunk_pages: Vec<u32>,
    pub leaf_pages: Vec<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
}

pub(super) struct Shape<'a> {
    pub(super) name: &'a str,
    pub(super) columns: usize,
    pub(super) rowid_alias: Option<usize>,
}

pub(super) fn shapes(tables: &[TableReport]) -> Vec<Shape<'_>> {
    tables
        .iter()
        .filter(|table: &&TableReport| {
            !table.without_rowid && table.columns.len() >= MIN_CARVED_COLUMNS
        })
        .map(|table: &TableReport| Shape {
            name: &table.name,
            columns: table.columns.len(),
            rowid_alias: table.rowid_alias,
        })
        .collect()
}

pub(super) fn read_freelist(
    pager: &Pager<'_>,
    first_trunk: u32,
    limits: &Limits,
) -> FreelistReport {
    let mut report: FreelistReport = FreelistReport::default();
    let mut seen: BTreeSet<u32> = BTreeSet::new();
    let mut trunk: u32 = first_trunk;
    while trunk != 0 {
        if !seen.insert(trunk) || report.trunk_pages.len() + report.leaf_pages.len() > limits.pages
        {
            report.problem = Some(format!(
                "freelist trunk chain revisits or exceeds the limit at page {trunk}"
            ));
            break;
        }
        let page: &[u8] = match pager.page(trunk) {
            Ok(page) => page,
            Err(error) => {
                report.problem = Some(error.to_string());
                break;
            }
        };
        report.trunk_pages.push(trunk);
        let count: usize = be32(page, 4) as usize;
        if 8 + count * 4 > page.len() {
            report.problem = Some(format!(
                "freelist trunk {trunk} lists {count} leaves, more than fit"
            ));
            break;
        }
        for index in 0..count {
            let leaf: u32 = be32(page, 8 + index * 4);
            if leaf != 0 && leaf <= pager.page_count && seen.insert(leaf) {
                report.leaf_pages.push(leaf);
            }
        }
        trunk = be32(page, 0);
    }
    report
}

pub(super) fn recover(
    pager: &Pager<'_>,
    freelist: &FreelistReport,
    live_leaves: &[u32],
    shapes: &[Shape<'_>],
    encoding: TextEncoding,
    limits: &Limits,
) -> Vec<RecoveredRecord> {
    let mut found: Vec<RecoveredRecord> = Vec::new();
    for page_number in &freelist.leaf_pages {
        let Ok(page) = pager.page(*page_number) else {
            continue;
        };
        let page_number: u32 = *page_number;
        let source = |_: usize| RecoverySource::FreelistPage { page: page_number };
        match PageHeader::parse(page, page_number) {
            Some(header) if header.kind == PAGE_LEAF_TABLE => {
                for offset in header.cell_offsets(page) {
                    if let Ok(cell) = read_cell(pager, page, offset, header.kind, limits)
                        && let Some(payload) = cell.payload
                        && let Some(record) = attribute(
                            &payload,
                            cell.rowid,
                            shapes,
                            encoding,
                            RecoveryConfidence::Exact,
                            source(offset),
                        )
                    {
                        found.push(record);
                    }
                }
            }
            _ => carve(page, 0, page.len(), shapes, encoding, &mut found, &source),
        }
        if found.len() >= limits.recovered {
            return found;
        }
    }
    for page_number in live_leaves {
        let Ok(page) = pager.page(*page_number) else {
            continue;
        };
        let Some(header) = PageHeader::parse(page, *page_number) else {
            continue;
        };
        let unallocated_end: usize = header.content_start.min(page.len());
        if header.pointer_array_end() < unallocated_end {
            let page_number: u32 = *page_number;
            carve(
                page,
                header.pointer_array_end(),
                unallocated_end,
                shapes,
                encoding,
                &mut found,
                &|offset: usize| RecoverySource::Unallocated {
                    page: page_number,
                    offset,
                },
            );
        }
        let mut block: usize = header.first_freeblock;
        let mut hops: usize = 0;
        while block != 0 && block + 4 <= page.len() && hops < page.len() / 4 {
            let size: usize = usize::from(be16(page, block + 2));
            let end: usize = (block + size).min(page.len());
            if end > block + 4 {
                let page_number: u32 = *page_number;
                carve(
                    page,
                    block + 4,
                    end,
                    shapes,
                    encoding,
                    &mut found,
                    &|offset: usize| RecoverySource::Freeblock {
                        page: page_number,
                        offset,
                    },
                );
            }
            let next: usize = usize::from(be16(page, block));
            if next <= block {
                break;
            }
            block = next;
            hops += 1;
        }
        if found.len() >= limits.recovered {
            break;
        }
    }
    found.truncate(limits.recovered);
    found
}

fn carve(
    page: &[u8],
    start: usize,
    end: usize,
    shapes: &[Shape<'_>],
    encoding: TextEncoding,
    found: &mut Vec<RecoveredRecord>,
    source: &dyn Fn(usize) -> RecoverySource,
) {
    let region: &[u8] = &page[start..end];
    let mut at: usize = 0;
    while at + 2 < region.len() {
        if let Some((record, consumed)) =
            exact_cell(&region[at..], shapes, encoding, source(start + at))
        {
            found.push(record);
            at += consumed;
            continue;
        }
        if let Some((record, consumed)) =
            bare_record(&region[at..], shapes, encoding, source(start + at))
        {
            found.push(record);
            at += consumed;
            continue;
        }
        at += 1;
    }
}

fn exact_cell(
    bytes: &[u8],
    shapes: &[Shape<'_>],
    encoding: TextEncoding,
    source: RecoverySource,
) -> Option<(RecoveredRecord, usize)> {
    let (total, a): (u64, usize) = varint(bytes)?;
    let (rowid, b): (u64, usize) = varint(bytes.get(a..)?)?;
    let total: usize = usize::try_from(total).ok()?;
    let payload: &[u8] = bytes.get(a + b..a + b + total)?;
    let header: RecordHeader = parse_header(payload, 4096)?;
    if header.header_len + header.body_len != total {
        return None;
    }
    let record: RecoveredRecord = attribute(
        payload,
        Some(rowid as i64),
        shapes,
        encoding,
        RecoveryConfidence::Exact,
        source,
    )?;
    Some((record, a + b + total))
}

fn bare_record(
    bytes: &[u8],
    shapes: &[Shape<'_>],
    encoding: TextEncoding,
    source: RecoverySource,
) -> Option<(RecoveredRecord, usize)> {
    let header: RecordHeader = parse_header(bytes, 4096)?;
    if header.header_len < 1 + MIN_CARVED_COLUMNS {
        return None;
    }
    let total: usize = header.header_len + header.body_len;
    let payload: &[u8] = bytes.get(..total)?;
    let record: RecoveredRecord = attribute(
        payload,
        None,
        shapes,
        encoding,
        RecoveryConfidence::Partial,
        source,
    )?;
    Some((record, total))
}

fn attribute(
    payload: &[u8],
    rowid: Option<i64>,
    shapes: &[Shape<'_>],
    encoding: TextEncoding,
    confidence: RecoveryConfidence,
    source: RecoverySource,
) -> Option<RecoveredRecord> {
    let header: RecordHeader = parse_header(payload, 4096)?;
    let matches: Vec<&Shape<'_>> = shapes
        .iter()
        .filter(|shape: &&Shape<'_>| shape.columns == header.types.len())
        .collect();
    if matches.is_empty() {
        return None;
    }
    let mut values: Vec<SqlValue> =
        decode_body(payload.get(header.header_len..)?, &header.types, encoding)?;
    if !plausible(&values) {
        return None;
    }
    let table: Option<&Shape<'_>> = (matches.len() == 1).then(|| matches[0]);
    if let (Some(shape), Some(id)) = (table, rowid)
        && let Some(alias) = shape.rowid_alias
        && values.get(alias) == Some(&SqlValue::Null)
    {
        values[alias] = SqlValue::Integer(id);
    }
    Some(RecoveredRecord {
        source,
        confidence,
        table: table.map(|shape: &Shape<'_>| shape.name.to_owned()),
        candidate_tables: if matches.len() > 1 {
            matches
                .iter()
                .map(|shape: &&Shape<'_>| shape.name.to_owned())
                .collect()
        } else {
            Vec::new()
        },
        rowid,
        values,
    })
}

fn plausible(values: &[SqlValue]) -> bool {
    let substantive: bool = values
        .iter()
        .any(|value: &SqlValue| !matches!(value, SqlValue::Null));
    let clean_text: bool = values.iter().all(|value: &SqlValue| match value {
        SqlValue::Text(text) => {
            !text.is_empty()
                && !text
                    .chars()
                    .any(|c: char| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
        }
        SqlValue::Real(real) => real.is_finite(),
        _ => true,
    });
    substantive && clean_text
}
