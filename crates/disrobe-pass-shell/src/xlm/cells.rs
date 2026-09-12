use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::biff::{BiffRecord, read_u16, read_u32};
use super::boundsheet::{REC_BOF, REC_EOF, SheetEntry, SheetKind, enumerate_sheets};
use super::container::{Biff12SheetPart, SheetKindHint};
use super::limits::MAX_RGCE;
use super::ptg::{
    BiffVersion, DecodedFormula, PtgContext, column_letters, decode_formula, parse_ptg_exp,
};
use super::scope::XtiScope;

const REC_FORMULA: u32 = 0x0006;
const REC_SHRFMLA: u32 = 0x04BC;
const REC_ARRAY: u32 = 0x0221;
const REC_NAME: u32 = 0x0018;

const BRT_ROW_HDR: u32 = 0x0000;
const BRT_FMLA_STRING: u32 = 8;
const BRT_FMLA_NUM: u32 = 9;
const BRT_FMLA_BOOL: u32 = 10;
const BRT_FMLA_ERROR: u32 = 11;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XlmCell {
    pub cell: String,
    pub formula: String,
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub unknown: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XlmSheet {
    pub name: String,
    pub kind: String,
    pub cells: Vec<XlmCell>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XlmEntryPoint {
    pub name: String,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XlmDefinedName {
    pub name: String,
    pub refers_to: String,
}

#[derive(Debug, Clone)]
struct Shared {
    row_first: u32,
    col_first: u32,
    rgce: Vec<u8>,
    rgcb: Vec<u8>,
}

pub fn recover_biff8(
    records: &[BiffRecord],
) -> (Vec<XlmSheet>, Vec<XlmEntryPoint>, Vec<XlmDefinedName>) {
    let sheets_meta: Vec<SheetEntry> = enumerate_sheets(records);
    let scope: XtiScope = XtiScope::build(records, &sheets_meta);
    let (names, entry_points, defined_names): (
        Vec<String>,
        Vec<XlmEntryPoint>,
        Vec<XlmDefinedName>,
    ) = collect_global_names(records, &scope);
    let mut bof_index: BTreeMap<usize, usize> = BTreeMap::new();
    for (idx, rec) in records.iter().enumerate() {
        if rec.rt == REC_BOF {
            bof_index.entry(rec.pos).or_insert(idx);
        }
    }
    let mut sheets: Vec<XlmSheet> = Vec::new();
    for meta in &sheets_meta {
        if !matches!(meta.kind, SheetKind::Macro | SheetKind::Worksheet) {
            continue;
        }
        let Some(&start): Option<&usize> = bof_index.get(&meta.bof_pos) else {
            continue;
        };
        let cells: Vec<XlmCell> = walk_sheet_biff8(records, start + 1, &names, &scope);
        sheets.push(XlmSheet {
            name: meta.name.clone(),
            kind: meta.kind.label().to_owned(),
            cells,
        });
    }
    (sheets, entry_points, defined_names)
}

fn walk_sheet_biff8(
    records: &[BiffRecord],
    start: usize,
    names: &[String],
    scope: &XtiScope,
) -> Vec<XlmCell> {
    let mut shared: Vec<Shared> = Vec::new();
    let mut pending: Vec<(u32, u32, Vec<u8>, Vec<u8>)> = Vec::new();
    for rec in &records[start.min(records.len())..] {
        if rec.rt == REC_EOF {
            break;
        }
        match rec.rt {
            REC_FORMULA => {
                if let Some(entry) = parse_formula_biff8(&rec.data) {
                    pending.push(entry);
                }
            }
            REC_SHRFMLA => {
                if let Some(entry) = parse_master_biff8(&rec.data, SHRFMLA_CCE_AT) {
                    shared.push(entry);
                }
            }
            REC_ARRAY => {
                if let Some(entry) = parse_master_biff8(&rec.data, ARRAY_CCE_AT) {
                    shared.push(entry);
                }
            }
            _ => {}
        }
    }
    let mut shared_index: BTreeMap<(u32, u32), &Shared> = BTreeMap::new();
    for entry in &shared {
        shared_index
            .entry((entry.row_first, entry.col_first))
            .or_insert(entry);
    }
    let mut cells: Vec<XlmCell> = Vec::with_capacity(pending.len());
    for (row, col, rgce, rgcb) in pending {
        let ctx: PtgContext<'_> = PtgContext {
            version: BiffVersion::Biff8,
            base_row: row,
            base_col: col,
            names,
            scope,
        };
        let decoded: DecodedFormula = resolve_formula(&rgce, &rgcb, &ctx, &shared_index);
        cells.push(XlmCell {
            cell: format_cell(row, col),
            formula: format!("={}", decoded.text),
            unknown: decoded.unknown,
        });
    }
    cells
}

const SHRFMLA_CCE_AT: usize = 8;
const ARRAY_CCE_AT: usize = 12;

fn parse_formula_biff8(data: &[u8]) -> Option<(u32, u32, Vec<u8>, Vec<u8>)> {
    let row: u32 = u32::from(read_u16(data, 0)?);
    let col: u32 = u32::from(read_u16(data, 2)?);
    let cce: usize = read_u16(data, 20)? as usize;
    if cce > MAX_RGCE {
        return None;
    }
    let end: usize = 22usize.checked_add(cce)?;
    let rgce: &[u8] = data.get(22..end)?;
    let rgcb: &[u8] = data.get(end..).unwrap_or_default();
    Some((row, col, rgce.to_vec(), rgcb.to_vec()))
}

fn parse_master_biff8(data: &[u8], cce_at: usize) -> Option<Shared> {
    let row_first: u32 = u32::from(read_u16(data, 0)?);
    let col_first: u32 = u32::from(*data.get(4)?);
    let cce: usize = read_u16(data, cce_at)? as usize;
    if cce > MAX_RGCE {
        return None;
    }
    let start: usize = cce_at.checked_add(2)?;
    let end: usize = start.checked_add(cce)?;
    let rgce: &[u8] = data.get(start..end)?;
    let rgcb: &[u8] = data.get(end..).unwrap_or_default();
    Some(Shared {
        row_first,
        col_first,
        rgce: rgce.to_vec(),
        rgcb: rgcb.to_vec(),
    })
}

fn resolve_formula(
    rgce: &[u8],
    rgcb: &[u8],
    ctx: &PtgContext<'_>,
    shared: &BTreeMap<(u32, u32), &Shared>,
) -> DecodedFormula {
    if let Some((anchor_row, anchor_col)) = parse_ptg_exp(rgce, ctx.version) {
        if let Some(master) = shared.get(&(anchor_row, anchor_col)) {
            return decode_formula(&master.rgce, &master.rgcb, ctx);
        }
        return DecodedFormula {
            text: format!("[[shared-formula@{}]]", format_cell(anchor_row, anchor_col)),
            unknown: true,
        };
    }
    decode_formula(rgce, rgcb, ctx)
}

fn collect_global_names(
    records: &[BiffRecord],
    scope: &XtiScope,
) -> (Vec<String>, Vec<XlmEntryPoint>, Vec<XlmDefinedName>) {
    let mut names: Vec<String> = Vec::new();
    let mut entry_points: Vec<XlmEntryPoint> = Vec::new();
    let mut defined_names: Vec<XlmDefinedName> = Vec::new();
    for rec in records {
        if rec.rt == REC_EOF {
            break;
        }
        if rec.rt != REC_NAME {
            continue;
        }
        let Some((name, rgce)): Option<(String, Vec<u8>)> = parse_lbl(&rec.data) else {
            names.push(String::new());
            continue;
        };
        let ctx: PtgContext<'_> = PtgContext {
            version: BiffVersion::Biff8,
            base_row: 0,
            base_col: 0,
            names: &[],
            scope,
        };
        let target: DecodedFormula = decode_formula(&rgce, &[], &ctx);
        if is_auto_entry(&name) {
            entry_points.push(XlmEntryPoint {
                name: name.clone(),
                target: target.text.clone(),
            });
        }
        defined_names.push(XlmDefinedName {
            name: name.clone(),
            refers_to: target.text,
        });
        names.push(name);
    }
    (names, entry_points, defined_names)
}

const LBL_GRBIT_FBUILTIN: u16 = 0x0020;

fn parse_lbl(data: &[u8]) -> Option<(String, Vec<u8>)> {
    let record_grbit: u16 = read_u16(data, 0)?;
    let cch: usize = *data.get(3)? as usize;
    let cce: usize = read_u16(data, 4)? as usize;
    let name_grbit: u8 = *data.get(14)?;
    let high_byte: bool = name_grbit & 0x01 != 0;
    let char_bytes: usize = if high_byte { cch.checked_mul(2)? } else { cch };
    let name_start: usize = 15;
    let name_end: usize = name_start.checked_add(char_bytes)?;
    let name_slice: &[u8] = data.get(name_start..name_end)?;
    let builtin: bool = record_grbit & LBL_GRBIT_FBUILTIN != 0;
    let name: String = match builtin_name(builtin, cch, name_slice) {
        Some(resolved) => resolved.to_owned(),
        None if high_byte => {
            let units: Vec<u16> = name_slice
                .chunks_exact(2)
                .map(|c: &[u8]| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        }
        None => name_slice.iter().map(|b: &u8| char::from(*b)).collect(),
    };
    if cce > MAX_RGCE {
        return Some((name, Vec::new()));
    }
    let rgce: Vec<u8> = data
        .get(name_end..name_end.checked_add(cce)?)
        .map(<[u8]>::to_vec)
        .unwrap_or_default();
    Some((name, rgce))
}

fn builtin_name(builtin: bool, cch: usize, name_slice: &[u8]) -> Option<&'static str> {
    if !builtin || cch != 1 {
        return None;
    }
    let name: &'static str = match *name_slice.first()? {
        0x00 => "Consolidate_Area",
        0x01 => "Auto_Open",
        0x02 => "Auto_Close",
        0x03 => "Extract",
        0x04 => "Database",
        0x05 => "Criteria",
        0x06 => "Print_Area",
        0x07 => "Print_Titles",
        0x08 => "Recorder",
        0x09 => "Data_Form",
        0x0A => "Auto_Activate",
        0x0B => "Auto_Deactivate",
        0x0C => "Sheet_Title",
        0x0D => "_FilterDatabase",
        _ => return None,
    };
    Some(name)
}

fn is_auto_entry(name: &str) -> bool {
    let lower: String = name.to_ascii_lowercase();
    lower.starts_with("auto_open")
        || lower.starts_with("auto_close")
        || lower.starts_with("auto_activate")
        || lower.starts_with("auto_deactivate")
}

pub fn recover_biff12(parts: &[Biff12SheetPart]) -> Vec<XlmSheet> {
    let scope: XtiScope = XtiScope::default();
    let mut sheets: Vec<XlmSheet> = Vec::new();
    for part in parts {
        let records: Vec<BiffRecord> = super::biff::iter_biff12(&part.bytes);
        let cells: Vec<XlmCell> = walk_sheet_biff12(&records, &scope);
        if cells.is_empty() && part.kind_hint != SheetKindHint::Macro {
            continue;
        }
        sheets.push(XlmSheet {
            name: part.name_hint.clone().unwrap_or_else(|| "sheet".to_owned()),
            kind: kind_hint_label(part.kind_hint).to_owned(),
            cells,
        });
    }
    sheets
}

const fn kind_hint_label(hint: SheetKindHint) -> &'static str {
    match hint {
        SheetKindHint::Macro => "macro",
        SheetKindHint::Worksheet => "worksheet",
        SheetKindHint::Unknown => "unknown",
    }
}

fn walk_sheet_biff12(records: &[BiffRecord], scope: &XtiScope) -> Vec<XlmCell> {
    let mut cells: Vec<XlmCell> = Vec::new();
    let mut row: u32 = 0;
    for rec in records {
        if rec.rt == BRT_ROW_HDR {
            if let Some(value) = read_u32(&rec.data, 0) {
                row = value;
            }
            continue;
        }
        let value_size: Option<usize> = match rec.rt {
            BRT_FMLA_NUM => Some(8),
            BRT_FMLA_BOOL | BRT_FMLA_ERROR => Some(1),
            BRT_FMLA_STRING => brt_string_value_size(&rec.data),
            _ => None,
        };
        let Some(value_size): Option<usize> = value_size else {
            continue;
        };
        if let Some(cell) = parse_fmla_biff12(&rec.data, row, value_size, scope) {
            cells.push(cell);
        }
    }
    cells
}

fn brt_string_value_size(data: &[u8]) -> Option<usize> {
    let cch: usize = read_u32(data, 8)? as usize;
    4usize.checked_add(cch.checked_mul(2)?)
}

fn parse_fmla_biff12(
    data: &[u8],
    row: u32,
    value_size: usize,
    scope: &XtiScope,
) -> Option<XlmCell> {
    let col: u32 = read_u32(data, 0)?;
    let cce_at: usize = 8usize.checked_add(value_size)?.checked_add(2)?;
    let cce: usize = read_u32(data, cce_at)? as usize;
    if cce > MAX_RGCE {
        return None;
    }
    let rgce_start: usize = cce_at.checked_add(4)?;
    let rgce_end: usize = rgce_start.checked_add(cce)?;
    let rgce: &[u8] = data.get(rgce_start..rgce_end)?;
    let rgcb: &[u8] = data.get(rgce_end.checked_add(4)?..).unwrap_or_default();
    let ctx: PtgContext<'_> = PtgContext {
        version: BiffVersion::Biff12,
        base_row: row,
        base_col: col,
        names: &[],
        scope,
    };
    let decoded: DecodedFormula = decode_formula(rgce, rgcb, &ctx);
    Some(XlmCell {
        cell: format_cell(row, col),
        formula: format!("={}", decoded.text),
        unknown: decoded.unknown,
    })
}

fn format_cell(row: u32, col: u32) -> String {
    format!("{}{}", column_letters(col), row + 1)
}
