use disrobe_pass_swift_objc::macho::{
    FatArchEntry, MachoKind, ParsedSlice, detect_magic, parse_slice, walk_fat,
};
use disrobe_pass_swift_objc::{SwiftObjcReport, analyze as analyze_swift_objc};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde::Serialize;

use crate::err::{DisrobeError, map};
use crate::llm::null_bundled_value;
use crate::typed::{MachoReport as PyMachoReport, SwiftReport};

#[derive(Debug, Clone, Serialize)]
struct MachoReport {
    kind: String,
    fat_entries: Vec<FatArchEntry>,
    slices: Vec<ParsedSlice>,
}

#[pyfunction]
#[pyo3(text_signature = "(macho_bytes)")]
fn macho_dump(macho_bytes: &[u8]) -> PyResult<PyMachoReport> {
    let kind: MachoKind = detect_magic(macho_bytes).ok_or_else(|| {
        DisrobeError::new_err("not a Mach-O image (no recognized magic)".to_owned())
    })?;
    let (fat_entries, slices): (Vec<FatArchEntry>, Vec<ParsedSlice>) = match kind {
        MachoKind::Fat32 | MachoKind::Fat64 => {
            let entries: Vec<FatArchEntry> =
                walk_fat(macho_bytes).map_err(map("macho fat walk"))?;
            let mut parsed: Vec<ParsedSlice> = Vec::with_capacity(entries.len());
            for e in &entries {
                let slice: &[u8] = fat_slice(macho_bytes, e)?;
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
    Ok(PyMachoReport::from_value(null_bundled_value(&report)?))
}

fn fat_slice<'a>(macho_bytes: &'a [u8], entry: &FatArchEntry) -> PyResult<&'a [u8]> {
    let start: usize = usize::try_from(entry.offset).map_err(|_| {
        DisrobeError::new_err(format!(
            "fat slice offset {} does not fit usize",
            entry.offset
        ))
    })?;
    let len: usize = usize::try_from(entry.size).map_err(|_| {
        DisrobeError::new_err(format!("fat slice size {} does not fit usize", entry.size))
    })?;
    let end: usize = start.checked_add(len).ok_or_else(|| {
        DisrobeError::new_err(format!("fat slice range {start}+{len} overflows usize"))
    })?;
    macho_bytes
        .get(start..end)
        .ok_or_else(|| DisrobeError::new_err(format!("fat slice {start}..{end} OOB")))
}

#[pyfunction]
#[pyo3(text_signature = "(macho_bytes)")]
fn swift_analyze(macho_bytes: &[u8]) -> PyResult<SwiftReport> {
    let report: SwiftObjcReport =
        analyze_swift_objc(macho_bytes).map_err(map("swift/objc analyze"))?;
    Ok(SwiftReport::from_value(null_bundled_value(&report)?))
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(macho_dump, m)?)?;
    m.add_function(wrap_pyfunction!(swift_analyze, m)?)?;
    Ok(())
}
