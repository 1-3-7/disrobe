use disrobe_pass_mobile::hermes::{
    DisassemblyReport, HermesHeader, HermesModule, JsLiftReport, disassemble,
    header_size_for_version, lift_to_js_surface, parse as parse_hermes_module, parse_header,
};
use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::err::map;
use crate::llm::null_bundled_value;
use crate::typed::{HermesDisassembly, HermesInfo, HermesLift};

#[pyfunction]
#[pyo3(text_signature = "(bundle_bytes)")]
fn hermes_disasm(bundle_bytes: &[u8]) -> PyResult<HermesDisassembly> {
    let module: HermesModule = parse_hermes_module(bundle_bytes).map_err(map("hermes parse"))?;
    let report: DisassemblyReport = disassemble(&module);
    Ok(HermesDisassembly::from_value(null_bundled_value(&report)?))
}

#[pyfunction]
#[pyo3(text_signature = "(bundle_bytes)")]
fn hermes_lift(bundle_bytes: &[u8]) -> PyResult<HermesLift> {
    let module: HermesModule = parse_hermes_module(bundle_bytes).map_err(map("hermes parse"))?;
    let lift: JsLiftReport = lift_to_js_surface(&module);
    Ok(HermesLift::from_value(null_bundled_value(&lift)?))
}

#[pyfunction]
#[pyo3(text_signature = "(bundle_bytes)")]
fn hermes_info(bundle_bytes: &[u8]) -> PyResult<HermesInfo> {
    let header: HermesHeader = parse_header(bundle_bytes).map_err(map("hermes header"))?;
    let header_size: usize = header_size_for_version(header.version);
    let payload: HermesHeaderReport = HermesHeaderReport {
        header,
        header_size,
    };
    Ok(HermesInfo::from_value(null_bundled_value(&payload)?))
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
