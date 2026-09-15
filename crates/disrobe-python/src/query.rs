use disrobe_query::{
    CallGraph, Capability, Module, Query, QueryResult, module_from_bytes, run as run_query,
};
use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::err::{DisrobeError, map};
use crate::typed::{
    CallGraph as PyCallGraph, FunctionList as PyFunctionList, QueryReport as PyQueryReport,
};

fn load_module(dr_bytes: &[u8]) -> PyResult<Module> {
    module_from_bytes(dr_bytes).map_err(map("query load module"))
}

#[pyfunction]
#[pyo3(text_signature = "(dr_bytes)")]
fn query_functions(dr_bytes: &[u8]) -> PyResult<PyFunctionList> {
    let module: Module = load_module(dr_bytes)?;
    let result: QueryResult = run_query(&module, &Query::Functions);
    PyFunctionList::from_serialize(&result)
}

#[pyfunction]
#[pyo3(text_signature = "(dr_bytes, target)")]
fn query_calls_to(dr_bytes: &[u8], target: &str) -> PyResult<PyQueryReport> {
    let module: Module = load_module(dr_bytes)?;
    let result: QueryResult = run_query(
        &module,
        &Query::CallsTo {
            target: target.to_owned(),
        },
    );
    PyQueryReport::from_serialize(&result)
}

#[pyfunction]
#[pyo3(text_signature = "(dr_bytes, symbol)")]
fn query_xrefs_to(dr_bytes: &[u8], symbol: &str) -> PyResult<PyQueryReport> {
    let module: Module = load_module(dr_bytes)?;
    let result: QueryResult = run_query(
        &module,
        &Query::XrefsTo {
            symbol: symbol.to_owned(),
        },
    );
    PyQueryReport::from_serialize(&result)
}

#[pyfunction]
#[pyo3(text_signature = "(dr_bytes)")]
fn query_string_decoders(dr_bytes: &[u8]) -> PyResult<PyQueryReport> {
    let module: Module = load_module(dr_bytes)?;
    let result: QueryResult = run_query(&module, &Query::StringDecoders);
    PyQueryReport::from_serialize(&result)
}

#[pyfunction]
#[pyo3(text_signature = "(dr_bytes, threshold)")]
fn query_complexity_over(dr_bytes: &[u8], threshold: u32) -> PyResult<PyQueryReport> {
    let module: Module = load_module(dr_bytes)?;
    let result: QueryResult = run_query(&module, &Query::ComplexityOver { threshold });
    PyQueryReport::from_serialize(&result)
}

#[pyfunction]
#[pyo3(text_signature = "(dr_bytes, capability)")]
fn query_capability_sites(dr_bytes: &[u8], capability: &str) -> PyResult<PyQueryReport> {
    let parsed: Capability = Capability::parse(capability).ok_or_else(|| {
        DisrobeError::new_err(format!(
            "unknown capability `{capability}`; expected network | crypto | filesystem | process"
        ))
    })?;
    let module: Module = load_module(dr_bytes)?;
    let result: QueryResult = run_query(&module, &Query::CapabilitySites { capability: parsed });
    PyQueryReport::from_serialize(&result)
}

#[pyfunction]
#[pyo3(text_signature = "(dr_bytes)")]
fn query_call_graph(dr_bytes: &[u8]) -> PyResult<PyCallGraph> {
    let module: Module = load_module(dr_bytes)?;
    let graph: CallGraph = module.call_graph();
    PyCallGraph::from_serialize(&graph)
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(query_functions, m)?)?;
    m.add_function(wrap_pyfunction!(query_calls_to, m)?)?;
    m.add_function(wrap_pyfunction!(query_xrefs_to, m)?)?;
    m.add_function(wrap_pyfunction!(query_string_decoders, m)?)?;
    m.add_function(wrap_pyfunction!(query_complexity_over, m)?)?;
    m.add_function(wrap_pyfunction!(query_capability_sites, m)?)?;
    m.add_function(wrap_pyfunction!(query_call_graph, m)?)?;
    Ok(())
}
