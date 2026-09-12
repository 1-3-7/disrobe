use disrobe_pass_ruby::{Flavor, RubyAnalysis, analyze_bytes};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde::Serialize;

use crate::err::map;
use crate::llm::null_bundled_value;
use crate::typed::{RubyAnalysis as PyRubyAnalysis, RubyDetection};

const DEFAULT_SOURCE_PATH: &str = "<ruby>";

#[derive(Debug, Clone, Serialize)]
struct RubyDetectReport {
    flavor: Flavor,
}

#[pyfunction]
#[pyo3(signature = (ruby_bytes, *, source_path = None))]
#[pyo3(text_signature = "(ruby_bytes, *, source_path=None)")]
fn ruby_detect(ruby_bytes: &[u8], source_path: Option<&str>) -> PyResult<RubyDetection> {
    let path: &str = source_path.map_or(DEFAULT_SOURCE_PATH, |value: &str| value);
    let analysis: RubyAnalysis = analyze_bytes(ruby_bytes, path).map_err(map("ruby detect"))?;
    let report: RubyDetectReport = RubyDetectReport {
        flavor: analysis.flavor,
    };
    Ok(RubyDetection::from_value(null_bundled_value(&report)?))
}

#[pyfunction]
#[pyo3(signature = (ruby_bytes, *, source_path = None))]
#[pyo3(text_signature = "(ruby_bytes, *, source_path=None)")]
fn ruby_decompile(ruby_bytes: &[u8], source_path: Option<&str>) -> PyResult<PyRubyAnalysis> {
    let path: &str = source_path.map_or(DEFAULT_SOURCE_PATH, |value: &str| value);
    let analysis: RubyAnalysis = analyze_bytes(ruby_bytes, path).map_err(map("ruby decompile"))?;
    Ok(PyRubyAnalysis::from_value(null_bundled_value(&analysis)?))
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(ruby_detect, m)?)?;
    m.add_function(wrap_pyfunction!(ruby_decompile, m)?)?;
    Ok(())
}
