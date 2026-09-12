pub mod biff;
pub mod boundsheet;
pub mod cells;
pub mod container;
pub mod ftab;
pub mod limits;
pub mod ptg;
pub mod scope;

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use container::XlmSource;

pub use cells::{XlmCell, XlmDefinedName, XlmEntryPoint, XlmSheet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XlmContainerKind {
    Xls,
    Xlsb,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XlmRecovery {
    pub container: XlmContainerKind,
    pub sheets: Vec<XlmSheet>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub entry_points: Vec<XlmEntryPoint>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub defined_names: Vec<XlmDefinedName>,
}

impl XlmRecovery {
    #[must_use]
    pub fn has_macro_sheet(&self) -> bool {
        self.sheets.iter().any(|s: &XlmSheet| s.kind == "macro")
    }

    #[must_use]
    pub fn total_formulas(&self) -> usize {
        self.sheets.iter().map(|s: &XlmSheet| s.cells.len()).sum()
    }
}

#[must_use]
pub fn recover_xlm(data: &[u8]) -> Option<XlmRecovery> {
    match container::open_source(data)? {
        XlmSource::Biff8 { workbook } => {
            let records: Vec<biff::BiffRecord> = biff::iter_biff8(&workbook);
            let (sheets, entry_points, defined_names): (
                Vec<XlmSheet>,
                Vec<XlmEntryPoint>,
                Vec<XlmDefinedName>,
            ) = cells::recover_biff8(&records);
            Some(XlmRecovery {
                container: XlmContainerKind::Xls,
                sheets,
                entry_points,
                defined_names,
            })
        }
        XlmSource::Biff12 { sheets: parts } => {
            let sheets: Vec<XlmSheet> = cells::recover_biff12(&parts);
            Some(XlmRecovery {
                container: XlmContainerKind::Xlsb,
                sheets,
                entry_points: Vec::new(),
                defined_names: Vec::new(),
            })
        }
    }
}

#[must_use]
pub fn is_xlm_macro_document(data: &[u8]) -> bool {
    recover_xlm(data).is_some_and(|report: XlmRecovery| report.has_macro_sheet())
}

#[must_use]
pub fn render_source(report: &XlmRecovery) -> Option<String> {
    if report.total_formulas() == 0 && report.entry_points.is_empty() {
        return None;
    }
    let mut out: String = String::new();
    for entry in &report.entry_points {
        let _ = writeln!(out, "' entry: {} -> {}", entry.name, entry.target);
    }
    for sheet in &report.sheets {
        let _ = writeln!(out, "' ===== {} sheet: {} =====", sheet.kind, sheet.name);
        for cell in &sheet.cells {
            let _ = writeln!(out, "{}!{}\t{}", sheet.name, cell.cell, cell.formula);
        }
    }
    out.truncate(out.trim_end().len());
    Some(out)
}
