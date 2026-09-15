use disrobe_pass_go::{GarbleReport, GoAnalysis, GoSymbols, analyze, analyze_garble};
use disrobe_pass_go::{GoImage, LocatedPclntab, locate_pclntab, parse_symbols};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde::Serialize;

use crate::err::map;
use crate::llm::null_bundled_value;
use crate::typed::{
    GarbleReport as PyGarbleReport, GoAnalysis as PyGoAnalysis, GoPclntab, GoSymbols as PyGoSymbols,
};

#[pyfunction]
#[pyo3(text_signature = "(binary_bytes)")]
fn go_analyze(binary_bytes: &[u8]) -> PyResult<PyGoAnalysis> {
    let analysis: GoAnalysis = analyze(binary_bytes).map_err(map("go analyze"))?;
    Ok(PyGoAnalysis::from_value(null_bundled_value(&analysis)?))
}

#[pyfunction]
#[pyo3(text_signature = "(binary_bytes)")]
fn go_symbols(binary_bytes: &[u8]) -> PyResult<PyGoSymbols> {
    let image: GoImage<'_> = GoImage::parse(binary_bytes).map_err(map("go parse image"))?;
    let located: LocatedPclntab<'_> = locate_pclntab(&image).map_err(map("go locate pclntab"))?;
    let symbols: GoSymbols = parse_symbols(&image, &located).map_err(map("go parse symbols"))?;
    Ok(PyGoSymbols::from_value(null_bundled_value(&symbols)?))
}

#[derive(Debug, Clone, Serialize)]
struct GoPclntabReport {
    version: String,
    ptr_size: u8,
    func_count: u64,
    image_kind: String,
}

#[pyfunction]
#[pyo3(text_signature = "(binary_bytes)")]
fn go_pclntab(binary_bytes: &[u8]) -> PyResult<GoPclntab> {
    let image: GoImage<'_> = GoImage::parse(binary_bytes).map_err(map("go parse image"))?;
    let located: LocatedPclntab<'_> = locate_pclntab(&image).map_err(map("go locate pclntab"))?;
    let report: GoPclntabReport = GoPclntabReport {
        version: located.header.version.label().to_owned(),
        ptr_size: located.header.ptr_size,
        func_count: located.header.n_funcs,
        image_kind: image_kind_label(image.kind()),
    };
    Ok(GoPclntab::from_value(null_bundled_value(&report)?))
}

#[pyfunction]
#[pyo3(text_signature = "(binary_bytes)")]
fn go_garble(binary_bytes: &[u8]) -> PyResult<PyGarbleReport> {
    let image: GoImage<'_> = GoImage::parse(binary_bytes).map_err(map("go parse image"))?;
    let located: LocatedPclntab<'_> = locate_pclntab(&image).map_err(map("go locate pclntab"))?;
    let symbols: GoSymbols = parse_symbols(&image, &located).map_err(map("go parse symbols"))?;
    let garble: GarbleReport = analyze_garble(&image, &symbols);
    Ok(PyGarbleReport::from_value(null_bundled_value(&garble)?))
}

fn image_kind_label(kind: disrobe_pass_go::ImageKind) -> String {
    match kind {
        disrobe_pass_go::ImageKind::Pe => "pe".to_owned(),
        disrobe_pass_go::ImageKind::Elf => "elf".to_owned(),
        disrobe_pass_go::ImageKind::MachO => "macho".to_owned(),
    }
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(go_analyze, m)?)?;
    m.add_function(wrap_pyfunction!(go_symbols, m)?)?;
    m.add_function(wrap_pyfunction!(go_pclntab, m)?)?;
    m.add_function(wrap_pyfunction!(go_garble, m)?)?;
    Ok(())
}
