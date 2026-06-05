use disrobe_pass_pyinstaller::{Cookie, ExtractOutput, ExtractedEntry, extract_archive};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde::Serialize;

use crate::err::map;
use crate::llm::report_with_null_bundle;

#[derive(Debug, Clone, Serialize)]
struct PyInstallerExtractReport {
    cookie: CookieReport,
    entry_count: usize,
    encrypted: bool,
    encryption_key_present: bool,
    bare_pyc_paths: Vec<String>,
    entries: Vec<EntryReport>,
}

#[derive(Debug, Clone, Serialize)]
struct CookieReport {
    variant: String,
    magic_offset: usize,
    python_major: u8,
    python_minor: u8,
    length_of_package: u32,
    toc_offset: u32,
    toc_length: u32,
}

impl From<&Cookie> for CookieReport {
    fn from(c: &Cookie) -> Self {
        Self {
            variant: format!("{:?}", c.variant),
            magic_offset: c.magic_offset,
            python_major: c.python_major,
            python_minor: c.python_minor,
            length_of_package: c.length_of_package,
            toc_offset: c.toc_offset,
            toc_length: c.toc_length,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct EntryReport {
    name: String,
    entry_type: String,
    compressed_size: u32,
    uncompressed_size: u32,
    decrypted: bool,
    blake3_hex: String,
    bytes_len: usize,
}

/// Extract a PyInstaller-bundled binary (onefile or onedir image bytes).
#[pyfunction]
#[pyo3(text_signature = "(image_bytes)")]
fn pyinstaller_extract<'py>(py: Python<'py>, image_bytes: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let out: ExtractOutput = extract_archive(image_bytes).map_err(map("pyinstaller extract"))?;
    let entries: Vec<EntryReport> = out
        .entries
        .iter()
        .map(|e: &ExtractedEntry| EntryReport {
            name: e.toc.name.clone(),
            entry_type: format!("{:?}", e.toc.entry_type),
            compressed_size: e.toc.compressed_size,
            uncompressed_size: e.toc.uncompressed_size,
            decrypted: e.decrypted,
            blake3_hex: blake3::hash(&e.data).to_hex().to_string(),
            bytes_len: e.data.len(),
        })
        .collect();
    let report: PyInstallerExtractReport = PyInstallerExtractReport {
        cookie: CookieReport::from(&out.cookie),
        entry_count: out.entries.len(),
        encrypted: out.entries.iter().any(|e: &ExtractedEntry| e.decrypted),
        encryption_key_present: out.encryption_key.is_some(),
        bare_pyc_paths: out.bare_pyc_paths,
        entries,
    };
    report_with_null_bundle(py, &report)
}

/// Return the raw bytes for a single entry by name.
#[pyfunction]
#[pyo3(text_signature = "(image_bytes, entry_name)")]
fn pyinstaller_entry_bytes<'py>(
    py: Python<'py>,
    image_bytes: &[u8],
    entry_name: &str,
) -> PyResult<Bound<'py, pyo3::types::PyBytes>> {
    let out: ExtractOutput = extract_archive(image_bytes).map_err(map("pyinstaller extract"))?;
    let entry: &ExtractedEntry = out
        .entries
        .iter()
        .find(|e: &&ExtractedEntry| e.toc.name == entry_name)
        .ok_or_else(|| {
            crate::err::DisrobeError::new_err(format!("entry not found: {entry_name}"))
        })?;
    Ok(pyo3::types::PyBytes::new(py, &entry.data))
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(pyinstaller_extract, m)?)?;
    m.add_function(wrap_pyfunction!(pyinstaller_entry_bytes, m)?)?;
    Ok(())
}
