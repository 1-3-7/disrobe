use disrobe_pass_php::{
    PeelOptions, PeelReport, PhpDetection, detect_php, peel_eval_chain, signature_scan,
};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde::Serialize;

use crate::err::map;
use crate::llm::null_bundled_value;
use crate::typed::{PhpDecode, PhpDetection as PyPhpDetection, PhpScan};

#[pyfunction]
#[pyo3(text_signature = "(php_bytes)")]
fn php_detect(php_bytes: &[u8]) -> PyResult<PyPhpDetection> {
    let detection: PhpDetection = detect_php(php_bytes);
    Ok(PyPhpDetection::from_value(null_bundled_value(&detection)?))
}

#[pyfunction]
#[pyo3(text_signature = "(php_bytes)")]
fn php_scan(php_bytes: &[u8]) -> PyResult<PhpScan> {
    let report: disrobe_pass_php::ScanReport = signature_scan(php_bytes);
    Ok(PhpScan::from_value(null_bundled_value(&report)?))
}

#[derive(Debug, Clone, Serialize)]
struct PhpPeelReport {
    source: String,
    layers: Vec<disrobe_pass_php::PeelTrace>,
    residual_eval: bool,
}

#[pyfunction]
#[pyo3(signature = (php_bytes, *, max_depth = None))]
#[pyo3(text_signature = "(php_bytes, *, max_depth=None)")]
fn php_decode(php_bytes: &[u8], max_depth: Option<u32>) -> PyResult<PhpDecode> {
    let options: PeelOptions =
        max_depth.map_or_else(PeelOptions::default, |depth: u32| PeelOptions {
            max_depth: depth,
            stop_when_clean: true,
        });
    let peeled: PeelReport = peel_eval_chain(php_bytes, options).map_err(map("php decode"))?;
    let report: PhpPeelReport = PhpPeelReport {
        source: String::from_utf8_lossy(&peeled.final_source).into_owned(),
        layers: peeled.layers,
        residual_eval: peeled.residual_eval,
    };
    Ok(PhpDecode::from_value(null_bundled_value(&report)?))
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(php_detect, m)?)?;
    m.add_function(wrap_pyfunction!(php_scan, m)?)?;
    m.add_function(wrap_pyfunction!(php_decode, m)?)?;
    Ok(())
}
