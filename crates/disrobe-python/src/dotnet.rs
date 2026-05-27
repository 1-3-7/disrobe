use disrobe_pass_dotnet::{
    Backend, ClrHeader, DetectionReport, MetadataRoot, PeImage, analyze as analyze_pass,
    detect_all, parse, parse_clr_header, parse_metadata_root,
};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde::Serialize;

use crate::convert::to_py;
use crate::err::map;
use crate::llm::report_with_null_bundle;

/// Parse a .NET PE image (managed DLL/EXE) and return the PE layout
/// summary (sections, data directories, bitness).
#[pyfunction]
#[pyo3(text_signature = "(pe_bytes)")]
fn dotnet_parse_pe<'py>(py: Python<'py>, pe_bytes: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let pe: PeImage = parse(pe_bytes).map_err(map("dotnet parse pe"))?;
    report_with_null_bundle(py, &pe)
}

/// Parse the CLR header and metadata root of a .NET assembly. Returns
/// the metadata streams (`#~`, `#Strings`, `#US`, `#GUID`, `#Blob`) and
/// runtime label.
#[pyfunction]
#[pyo3(text_signature = "(pe_bytes)")]
fn dotnet_parse_metadata<'py>(py: Python<'py>, pe_bytes: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let pe: PeImage = parse(pe_bytes).map_err(map("dotnet parse pe"))?;
    let clr: ClrHeader = parse_clr_header(pe_bytes, &pe).map_err(map("dotnet parse clr"))?;
    let meta: MetadataRoot =
        parse_metadata_root(pe_bytes, &pe, &clr).map_err(map("dotnet parse metadata"))?;
    let report: DotnetMetadataReport = DotnetMetadataReport {
        clr,
        metadata: meta,
    };
    report_with_null_bundle(py, &report)
}

#[derive(Debug, Clone, Serialize)]
struct DotnetMetadataReport {
    clr: ClrHeader,
    metadata: MetadataRoot,
}

/// Run all .NET protector detectors (Eazfuscator, ConfuserEx, Themida.NET,
/// SmartAssembly, Dotfuscator, AgileNet, ArmDot, BabelNet, CryptoObfuscator,
/// DeepSea, .NET Reactor, Goliath, ILProtector, MaxtoCode, ObfuscatorNet,
/// Skater, Spices.Net) against `pe_bytes`.
#[pyfunction]
#[pyo3(text_signature = "(pe_bytes)")]
fn dotnet_detect<'py>(py: Python<'py>, pe_bytes: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let report: DetectionReport = detect_all(pe_bytes);
    report_with_null_bundle(py, &report)
}

/// Run the full dotnet pass summary (parse + classify protectors + plan
/// execution) against `pe_bytes`.
#[pyfunction]
#[pyo3(text_signature = "(pe_bytes)")]
fn dotnet_analyze<'py>(py: Python<'py>, pe_bytes: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let summary: disrobe_pass_dotnet::PassSummary =
        analyze_pass(pe_bytes).map_err(map("dotnet analyze"))?;
    report_with_null_bundle(py, &summary)
}

/// Probe the host for installed .NET decompiler backends (ilspycmd, dnSpy,
/// dnSpyEx, de4dot). Returns the list of backends found on PATH.
#[pyfunction]
#[pyo3(text_signature = "()")]
fn dotnet_backends<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
    let backends: [Backend; 4] = [
        Backend::Ilspy,
        Backend::Dnspy,
        Backend::DnspyEx,
        Backend::De4dot,
    ];
    let rows: Vec<BackendProbe> = backends
        .into_iter()
        .map(|b: Backend| BackendProbe {
            backend: format!("{b:?}"),
            binary_name: b.binary_name().to_owned(),
            available: disrobe_pass_dotnet::backends::probe(b),
        })
        .collect();
    to_py(py, &rows)
}

#[derive(Debug, Clone, Serialize)]
struct BackendProbe {
    backend: String,
    binary_name: String,
    available: bool,
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(dotnet_parse_pe, m)?)?;
    m.add_function(wrap_pyfunction!(dotnet_parse_metadata, m)?)?;
    m.add_function(wrap_pyfunction!(dotnet_detect, m)?)?;
    m.add_function(wrap_pyfunction!(dotnet_analyze, m)?)?;
    m.add_function(wrap_pyfunction!(dotnet_backends, m)?)?;
    Ok(())
}
