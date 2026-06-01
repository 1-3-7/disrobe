use disrobe_pass_wasm_deob::{ModuleSummary, WasmDetection, analyze_module, detect};
use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::err::map;
use crate::llm::report_with_null_bundle;

/// Analyze a WebAssembly module & return a typed summary (imports,
/// exports, function/global/memory counts, recovered name section,
/// DWARF presence).
#[pyfunction]
#[pyo3(text_signature = "(wasm_bytes)")]
fn wasm_analyze<'py>(py: Python<'py>, wasm_bytes: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let summary: ModuleSummary = analyze_module(wasm_bytes).map_err(map("wasm analyze"))?;
    report_with_null_bundle(py, &summary)
}

/// Run all wasm obfuscator detectors (wasm-obfuscator, wobfuscator,
/// emcrypt, cryptic-bytes wrappers). Returns the obfuscator family and
/// markers (or `Plain` if no protector is present).
#[pyfunction]
#[pyo3(text_signature = "(wasm_bytes)")]
fn wasm_detect<'py>(py: Python<'py>, wasm_bytes: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let det: WasmDetection = detect(wasm_bytes).map_err(map("wasm detect"))?;
    report_with_null_bundle(py, &det)
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(wasm_analyze, m)?)?;
    m.add_function(wrap_pyfunction!(wasm_detect, m)?)?;
    Ok(())
}
