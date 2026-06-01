use disrobe_pass_swift_objc::macho::{
    FatArchEntry, MachoKind, ParsedSlice, detect_magic, parse_slice, walk_fat,
};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde::Serialize;

use crate::err::{DisrobeError, map};
use crate::llm::report_with_null_bundle;

#[derive(Debug, Clone, Serialize)]
struct MachoReport {
    kind: String,
    fat_entries: Vec<FatArchEntry>,
    slices: Vec<ParsedSlice>,
}

/// Parse a Mach-O image (single-arch or universal fat) & return the
/// header(s), segment layout, load-command list, & encryption metadata.
#[pyfunction]
#[pyo3(text_signature = "(macho_bytes)")]
fn macho_dump<'py>(py: Python<'py>, macho_bytes: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let kind: MachoKind = detect_magic(macho_bytes).ok_or_else(|| {
        DisrobeError::new_err("not a Mach-O image (no recognised magic)".to_owned())
    })?;
    let (fat_entries, slices): (Vec<FatArchEntry>, Vec<ParsedSlice>) = match kind {
        MachoKind::Fat32 | MachoKind::Fat64 => {
            let entries: Vec<FatArchEntry> =
                walk_fat(macho_bytes).map_err(map("macho fat walk"))?;
            let mut parsed: Vec<ParsedSlice> = Vec::with_capacity(entries.len());
            for e in &entries {
                let start: usize = usize::try_from(e.offset).unwrap_or(0);
                let end: usize = start.saturating_add(usize::try_from(e.size).unwrap_or(0));
                let slice: &[u8] = macho_bytes.get(start..end).ok_or_else(|| {
                    DisrobeError::new_err(format!("fat slice {start}..{end} OOB"))
                })?;
                parsed.push(parse_slice(slice).map_err(map("macho slice parse"))?);
            }
            (entries, parsed)
        }
        _ => (
            Vec::new(),
            vec![parse_slice(macho_bytes).map_err(map("macho slice parse"))?],
        ),
    };
    let report: MachoReport = MachoReport {
        kind: format!("{kind:?}"),
        fat_entries,
        slices,
    };
    report_with_null_bundle(py, &report)
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(macho_dump, m)?)?;
    Ok(())
}
