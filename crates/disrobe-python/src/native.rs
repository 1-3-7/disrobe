use std::collections::BTreeMap;

use disrobe_pass_native::{
    DecompilerBackend, DetectedFormat, ObfuscatorHit, Probe, detect_format, detect_obfuscators,
    probe_all,
};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde::Serialize;

use crate::convert::to_py;
use crate::err::map;
use crate::llm::report_with_null_bundle;

/// Detect the native binary format (PE/ELF/Mach-O/COFF/raw) of `binary_bytes`.
#[pyfunction]
#[pyo3(text_signature = "(binary_bytes)")]
fn native_format<'py>(py: Python<'py>, binary_bytes: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let f: DetectedFormat = detect_format(binary_bytes).map_err(map("native detect_format"))?;
    report_with_null_bundle(py, &f)
}

/// Run all native obfuscator detectors (OLLVM-BCF, OLLVM-substitution,
/// OLLVM-flatten, Tigress-flatten, Emotet CFG, generic CFF). Returns the
/// matched families with markers.
#[pyfunction]
#[pyo3(text_signature = "(binary_bytes)")]
fn native_detect<'py>(py: Python<'py>, binary_bytes: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let hits: Vec<ObfuscatorHit> = detect_obfuscators(binary_bytes);
    to_py(py, &hits)
}

/// Probe the host for installed native decompiler backends (Ghidra,
/// Rizin, Binary Ninja, IDA, angr, RetDec, llvm-dis). Returns the
/// per-backend probe result.
#[pyfunction]
#[pyo3(text_signature = "()")]
fn native_probe_backends<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
    let probes: BTreeMap<DecompilerBackend, Probe> = probe_all();
    let rows: Vec<ProbeRow> = probes
        .into_iter()
        .map(|(b, p): (DecompilerBackend, Probe)| ProbeRow {
            backend: b.label().to_owned(),
            binary_name: b.binary_name().to_owned(),
            license_required: b.license_required(),
            override_env: b.override_env().to_owned(),
            found: p.found,
            path: p.path.map(|p: std::path::PathBuf| p.display().to_string()),
            note: p.note,
        })
        .collect();
    to_py(py, &rows)
}

#[derive(Debug, Clone, Serialize)]
struct ProbeRow {
    backend: String,
    binary_name: String,
    license_required: bool,
    override_env: String,
    found: bool,
    path: Option<String>,
    note: Option<String>,
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(native_format, m)?)?;
    m.add_function(wrap_pyfunction!(native_detect, m)?)?;
    m.add_function(wrap_pyfunction!(native_probe_backends, m)?)?;
    Ok(())
}
