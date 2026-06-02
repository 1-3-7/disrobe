use disrobe_pass_pickle::{
    Disassembly, MlReport, PolyglotReport, SafetyReport, VmTrace, analyze_polyglot, analyze_safety,
    disassemble, execute, extract_ml, render_disasm, to_python_assignment,
};
use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::err::map;
use crate::llm::report_with_null_bundle;

#[derive(Debug, serde::Serialize)]
struct DecompileReport {
    source: String,
    graph: disrobe_pass_pickle::PickleValue,
}

/// Disassemble a pickle stream into an offset-annotated opcode listing.
#[pyfunction]
#[pyo3(text_signature = "(pickle_bytes)")]
fn pickle_disasm(pickle_bytes: &[u8]) -> PyResult<String> {
    let dis: Disassembly = disassemble(pickle_bytes).map_err(map("pickle disasm"))?;
    Ok(render_disasm(&dis))
}

/// Decompile a pickle into equivalent Python source plus the symbolic
/// object graph. Returns `{"source": str, "graph": dict, "llm": None}`.
#[pyfunction]
#[pyo3(text_signature = "(pickle_bytes)")]
fn pickle_decompile<'py>(py: Python<'py>, pickle_bytes: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let dis: Disassembly = disassemble(pickle_bytes).map_err(map("pickle disasm"))?;
    let trace: VmTrace = execute(&dis).map_err(map("pickle vm"))?;
    let report: DecompileReport = DecompileReport {
        source: to_python_assignment(&trace.result),
        graph: trace.result,
    };
    report_with_null_bundle(py, &report)
}

/// Static safety analysis: severity tier, dangerous-import / REDUCE / memo
/// findings, and the resolved import list.
#[pyfunction]
#[pyo3(text_signature = "(pickle_bytes)")]
fn pickle_safety<'py>(py: Python<'py>, pickle_bytes: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let dis: Disassembly = disassemble(pickle_bytes).map_err(map("pickle disasm"))?;
    let trace: VmTrace = execute(&dis).map_err(map("pickle vm"))?;
    let report: SafetyReport = analyze_safety(&trace);
    report_with_null_bundle(py, &report)
}

/// Symbolic VM trace: object graph, memo stats, global refs, reduce count.
#[pyfunction]
#[pyo3(text_signature = "(pickle_bytes)")]
fn pickle_trace<'py>(py: Python<'py>, pickle_bytes: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let dis: Disassembly = disassemble(pickle_bytes).map_err(map("pickle disasm"))?;
    let trace: VmTrace = execute(&dis).map_err(map("pickle vm"))?;
    report_with_null_bundle(py, &trace)
}

/// Detect pickle/zip/zip64/tar polyglot files (weaponized model archives).
#[pyfunction]
#[pyo3(text_signature = "(file_bytes)")]
fn pickle_polyglot<'py>(py: Python<'py>, file_bytes: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let report: PolyglotReport = analyze_polyglot(file_bytes);
    report_with_null_bundle(py, &report)
}

/// Detect ML model formats (PyTorch / TorchScript / numpy) & list embedded
/// pickle streams.
#[pyfunction]
#[pyo3(text_signature = "(file_bytes)")]
fn pickle_ml_detect<'py>(py: Python<'py>, file_bytes: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let report: MlReport = extract_ml(file_bytes).map_err(map("pickle ml-detect"))?;
    report_with_null_bundle(py, &report)
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(pickle_disasm, m)?)?;
    m.add_function(wrap_pyfunction!(pickle_decompile, m)?)?;
    m.add_function(wrap_pyfunction!(pickle_safety, m)?)?;
    m.add_function(wrap_pyfunction!(pickle_trace, m)?)?;
    m.add_function(wrap_pyfunction!(pickle_polyglot, m)?)?;
    m.add_function(wrap_pyfunction!(pickle_ml_detect, m)?)?;
    Ok(())
}
