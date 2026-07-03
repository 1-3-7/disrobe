use disrobe_pass_pickle::{
    Disassembly, MlReport, PolyglotReport, SafetyReport, VmTrace, analyze_polyglot, analyze_safety,
    disassemble, execute, extract_ml, render_disasm, to_python_assignment,
};
use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::err::map;
use crate::llm::null_bundled_value;
use crate::typed::{
    PickleDecompilation, PickleMlReport, PicklePolyglot, PickleSafety, PickleTrace,
};

#[derive(Debug, serde::Serialize)]
struct DecompileReport {
    source: String,
    graph: disrobe_pass_pickle::PickleValue,
}

#[pyfunction]
#[pyo3(text_signature = "(pickle_bytes)")]
fn pickle_disasm(pickle_bytes: &[u8]) -> PyResult<String> {
    let dis: Disassembly = disassemble(pickle_bytes).map_err(map("pickle disasm"))?;
    Ok(render_disasm(&dis))
}

#[pyfunction]
#[pyo3(text_signature = "(pickle_bytes)")]
fn pickle_decompile(pickle_bytes: &[u8]) -> PyResult<PickleDecompilation> {
    let dis: Disassembly = disassemble(pickle_bytes).map_err(map("pickle disasm"))?;
    let trace: VmTrace = execute(&dis).map_err(map("pickle vm"))?;
    let report: DecompileReport = DecompileReport {
        source: to_python_assignment(&trace.result),
        graph: trace.result,
    };
    Ok(PickleDecompilation::from_value(null_bundled_value(
        &report,
    )?))
}

#[pyfunction]
#[pyo3(text_signature = "(pickle_bytes)")]
fn pickle_safety(pickle_bytes: &[u8]) -> PyResult<PickleSafety> {
    let dis: Disassembly = disassemble(pickle_bytes).map_err(map("pickle disasm"))?;
    let trace: VmTrace = execute(&dis).map_err(map("pickle vm"))?;
    let report: SafetyReport = analyze_safety(&trace);
    Ok(PickleSafety::from_value(null_bundled_value(&report)?))
}

#[pyfunction]
#[pyo3(text_signature = "(pickle_bytes)")]
fn pickle_trace(pickle_bytes: &[u8]) -> PyResult<PickleTrace> {
    let dis: Disassembly = disassemble(pickle_bytes).map_err(map("pickle disasm"))?;
    let trace: VmTrace = execute(&dis).map_err(map("pickle vm"))?;
    Ok(PickleTrace::from_value(null_bundled_value(&trace)?))
}

#[pyfunction]
#[pyo3(text_signature = "(file_bytes)")]
fn pickle_polyglot(file_bytes: &[u8]) -> PyResult<PicklePolyglot> {
    let report: PolyglotReport = analyze_polyglot(file_bytes);
    Ok(PicklePolyglot::from_value(null_bundled_value(&report)?))
}

#[pyfunction]
#[pyo3(text_signature = "(file_bytes)")]
fn pickle_ml_detect(file_bytes: &[u8]) -> PyResult<PickleMlReport> {
    let report: MlReport = extract_ml(file_bytes).map_err(map("pickle ml-detect"))?;
    Ok(PickleMlReport::from_value(null_bundled_value(&report)?))
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
