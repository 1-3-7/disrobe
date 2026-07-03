use disrobe_pass_wasm_deob::{ModuleSummary, WasmDetection, analyze_module, detect};
use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::err::map;
use crate::llm::null_bundled_value;
use crate::typed::{WasmAnalysis, WasmDetection as PyWasmDetection};

#[pyfunction]
#[pyo3(text_signature = "(wasm_bytes)")]
fn wasm_analyze(wasm_bytes: &[u8]) -> PyResult<WasmAnalysis> {
    let summary: ModuleSummary = analyze_module(wasm_bytes).map_err(map("wasm analyze"))?;
    Ok(WasmAnalysis::from_value(null_bundled_value(&summary)?))
}

#[pyfunction]
#[pyo3(text_signature = "(wasm_bytes)")]
fn wasm_detect(wasm_bytes: &[u8]) -> PyResult<PyWasmDetection> {
    let det: WasmDetection = detect(wasm_bytes).map_err(map("wasm detect"))?;
    Ok(PyWasmDetection::from_value(null_bundled_value(&det)?))
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(wasm_analyze, m)?)?;
    m.add_function(wrap_pyfunction!(wasm_detect, m)?)?;
    Ok(())
}
