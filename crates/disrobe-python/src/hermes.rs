use disrobe_pass_mobile::hermes::{
    DisassemblyReport, HermesHeader, HermesModule, JsLiftReport, disassemble,
    header_size_for_version, lift_to_js_surface, parse as parse_hermes_module, parse_header,
};
use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::err::map;
use crate::llm::report_with_null_bundle;

/// Parse a Hermes JS bundle & return a disassembly report (function
/// count, identifier count, string count, per-function metadata).
#[pyfunction]
#[pyo3(text_signature = "(bundle_bytes)")]
fn hermes_disasm<'py>(py: Python<'py>, bundle_bytes: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let module: HermesModule = parse_hermes_module(bundle_bytes).map_err(map("hermes parse"))?;
    let report: DisassemblyReport = disassemble(&module);
    report_with_null_bundle(py, &report)
}

/// Lift a Hermes JS bundle to a JavaScript surface (recovered strings,
/// identifiers, function signatures with parameter slots & body size).
/// Body opcodes are not decompiled here; this is the lift surface that
/// downstream JS deobfuscation passes consume.
#[pyfunction]
#[pyo3(text_signature = "(bundle_bytes)")]
fn hermes_lift<'py>(py: Python<'py>, bundle_bytes: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let module: HermesModule = parse_hermes_module(bundle_bytes).map_err(map("hermes parse"))?;
    let lift: JsLiftReport = lift_to_js_surface(&module);
    report_with_null_bundle(py, &lift)
}

/// Parse the Hermes file header (version, function count, string counts,
/// debug-info offset, flags). Returns the typed header plus the byte
/// length of the parsed header region.
#[pyfunction]
#[pyo3(text_signature = "(bundle_bytes)")]
fn hermes_info<'py>(py: Python<'py>, bundle_bytes: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let header: HermesHeader = parse_header(bundle_bytes).map_err(map("hermes header"))?;
    let header_size: usize = header_size_for_version(header.version);
    let payload: HermesHeaderReport = HermesHeaderReport {
        header,
        header_size,
    };
    report_with_null_bundle(py, &payload)
}

#[derive(Debug, Clone, serde::Serialize)]
struct HermesHeaderReport {
    header: HermesHeader,
    header_size: usize,
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hermes_disasm, m)?)?;
    m.add_function(wrap_pyfunction!(hermes_lift, m)?)?;
    m.add_function(wrap_pyfunction!(hermes_info, m)?)?;
    Ok(())
}
