use disrobe_pass_dotnet::aot::detect as detect_native_aot;
use disrobe_pass_dotnet::{
    AotReport, Backend, ClrHeader, DecompiledAssembly, DetectionReport, MetadataRoot, PeImage,
    StaticDecryptReport, analyze as analyze_pass, decompile_assembly, detect_all, parse,
    parse_clr_header, parse_metadata_root, recover_static_decoders,
};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde::Serialize;

use crate::convert::to_value;
use crate::err::map;
use crate::llm::null_bundled_value;
use crate::typed::{
    BackendList, DotnetAnalysis, DotnetDecoders, DotnetDecompilation, DotnetDetection,
    DotnetMetadata, DotnetNativeAot, DotnetPe,
};

#[pyfunction]
#[pyo3(text_signature = "(pe_bytes)")]
fn dotnet_parse_pe(pe_bytes: &[u8]) -> PyResult<DotnetPe> {
    let pe: PeImage = parse(pe_bytes).map_err(map("dotnet parse pe"))?;
    Ok(DotnetPe::from_value(null_bundled_value(&pe)?))
}

#[pyfunction]
#[pyo3(text_signature = "(pe_bytes)")]
fn dotnet_parse_metadata(pe_bytes: &[u8]) -> PyResult<DotnetMetadata> {
    let pe: PeImage = parse(pe_bytes).map_err(map("dotnet parse pe"))?;
    let clr: ClrHeader = parse_clr_header(pe_bytes, &pe).map_err(map("dotnet parse clr"))?;
    let meta: MetadataRoot =
        parse_metadata_root(pe_bytes, &pe, &clr).map_err(map("dotnet parse metadata"))?;
    let report: DotnetMetadataReport = DotnetMetadataReport {
        clr,
        metadata: meta,
    };
    Ok(DotnetMetadata::from_value(null_bundled_value(&report)?))
}

#[derive(Debug, Clone, Serialize)]
struct DotnetMetadataReport {
    clr: ClrHeader,
    metadata: MetadataRoot,
}

#[pyfunction]
#[pyo3(text_signature = "(pe_bytes)")]
fn dotnet_detect(pe_bytes: &[u8]) -> PyResult<DotnetDetection> {
    let report: DetectionReport = detect_all(pe_bytes);
    Ok(DotnetDetection::from_value(null_bundled_value(&report)?))
}

#[pyfunction]
#[pyo3(text_signature = "(pe_bytes)")]
fn dotnet_analyze(pe_bytes: &[u8]) -> PyResult<DotnetAnalysis> {
    let summary: disrobe_pass_dotnet::PassSummary =
        analyze_pass(pe_bytes).map_err(map("dotnet analyze"))?;
    Ok(DotnetAnalysis::from_value(null_bundled_value(&summary)?))
}

#[pyfunction]
#[pyo3(text_signature = "(pe_bytes)")]
fn dotnet_decompile(pe_bytes: &[u8]) -> PyResult<DotnetDecompilation> {
    let asm: DecompiledAssembly = decompile_assembly(pe_bytes).map_err(map("dotnet decompile"))?;
    Ok(DotnetDecompilation::from_value(null_bundled_value(&asm)?))
}

#[pyfunction]
#[pyo3(text_signature = "(pe_bytes)")]
fn dotnet_recover_decoders(pe_bytes: &[u8]) -> PyResult<DotnetDecoders> {
    let report: StaticDecryptReport =
        recover_static_decoders(pe_bytes).map_err(map("dotnet recover decoders"))?;
    Ok(DotnetDecoders::from_value(null_bundled_value(&report)?))
}

#[pyfunction]
#[pyo3(text_signature = "(image_bytes)")]
fn dotnet_native_aot(image_bytes: &[u8]) -> PyResult<DotnetNativeAot> {
    let report: AotReport = detect_native_aot(image_bytes);
    Ok(DotnetNativeAot::from_value(null_bundled_value(&report)?))
}

#[pyfunction]
#[pyo3(text_signature = "()")]
fn dotnet_backends() -> PyResult<BackendList> {
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
    Ok(BackendList::from_value(to_value(&rows)?))
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
    m.add_function(wrap_pyfunction!(dotnet_decompile, m)?)?;
    m.add_function(wrap_pyfunction!(dotnet_recover_decoders, m)?)?;
    m.add_function(wrap_pyfunction!(dotnet_native_aot, m)?)?;
    m.add_function(wrap_pyfunction!(dotnet_backends, m)?)?;
    Ok(())
}
