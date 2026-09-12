use disrobe_pass_nuitka::{Detection, VariantExtraction, detect_in_bytes, extract_variant};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde::Serialize;

use crate::err::map;
use crate::llm::null_bundled_value;
use crate::typed::{NuitkaDetection as PyNuitkaDetection, NuitkaExtraction};

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

#[pyfunction]
#[pyo3(text_signature = "(image_bytes)")]
fn nuitka_detect(image_bytes: &[u8]) -> PyResult<PyNuitkaDetection> {
    let det: Detection = detect_in_bytes(image_bytes).map_err(map("nuitka detect"))?;
    let report: NuitkaDetectionReport = NuitkaDetectionReport::from(&det);
    Ok(PyNuitkaDetection::from_value(null_bundled_value(&report)?))
}

#[pyfunction]
#[pyo3(text_signature = "(image_bytes)")]
fn nuitka_extract(image_bytes: &[u8]) -> PyResult<NuitkaExtraction> {
    let v: VariantExtraction = extract_variant(image_bytes).map_err(map("nuitka extract"))?;
    Ok(NuitkaExtraction::from_value(null_bundled_value(&v)?))
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(nuitka_detect, m)?)?;
    m.add_function(wrap_pyfunction!(nuitka_extract, m)?)?;
    Ok(())
}
