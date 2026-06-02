use disrobe_pass_nuitka::{Detection, VariantExtraction, detect_in_bytes, extract_variant};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde::Serialize;

use crate::err::map;
use crate::llm::report_with_null_bundle;

#[derive(Debug, Clone, Serialize)]
struct NuitkaDetectionReport {
    flavor: String,
    version: String,
    wheel_marker: String,
    onefile_payload_offset: Option<usize>,
    onefile_payload_compressed: bool,
    hits: Vec<String>,
}

impl From<&Detection> for NuitkaDetectionReport {
    fn from(d: &Detection) -> Self {
        Self {
            flavor: format!("{:?}", d.flavor),
            version: format!("{:?}", d.version),
            wheel_marker: format!("{:?}", d.wheel_marker),
            onefile_payload_offset: d.onefile_payload_offset,
            onefile_payload_compressed: d.onefile_payload_compressed,
            hits: d.hits.clone(),
        }
    }
}

/// Detect whether `image_bytes` is a Nuitka-compiled binary & classify
/// the variant (onefile / standalone / module / wheel / signed-pe).
///
/// Returns a dict including `llm: None` (LLM metadata for the Nuitka pass
/// lands in v0.10).
#[pyfunction]
#[pyo3(text_signature = "(image_bytes)")]
fn nuitka_detect<'py>(py: Python<'py>, image_bytes: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let det: Detection = detect_in_bytes(image_bytes).map_err(map("nuitka detect"))?;
    let report: NuitkaDetectionReport = NuitkaDetectionReport::from(&det);
    report_with_null_bundle(py, &report)
}

/// Classify & extract a Nuitka-compiled image. For onefile variants
/// returns the payload offset, entry count, & compression flag; for
/// signed PEs strips Authenticode & recurses on the inner image.
///
/// Returns a dict including `llm: None` (LLM metadata for the Nuitka pass
/// lands in v0.10).
#[pyfunction]
#[pyo3(text_signature = "(image_bytes)")]
fn nuitka_extract<'py>(py: Python<'py>, image_bytes: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let v: VariantExtraction = extract_variant(image_bytes).map_err(map("nuitka extract"))?;
    report_with_null_bundle(py, &v)
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(nuitka_detect, m)?)?;
    m.add_function(wrap_pyfunction!(nuitka_extract, m)?)?;
    Ok(())
}
