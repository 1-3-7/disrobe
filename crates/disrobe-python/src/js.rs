use disrobe_pass_js_deob::{
    BundlerKind, Detection, UnbundleResult, UnminifyStats, auto_unbundle, detect, unbundle,
    unminify,
};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde::Serialize;

use crate::err::{DisrobeError, map};
use crate::llm::null_bundled_value;
use crate::typed::{JsDetection, JsUnbundle, JsUnminify};

#[pyfunction]
#[pyo3(text_signature = "(js_source)")]
fn js_detect(js_source: &str) -> PyResult<JsDetection> {
    let det: Detection = detect(js_source.as_bytes());
    Ok(JsDetection::from_value(null_bundled_value(&det)?))
}

#[pyfunction]
#[pyo3(text_signature = "(js_source)")]
fn js_unminify(js_source: &str) -> PyResult<JsUnminify> {
    let (out, stats): (String, UnminifyStats) = unminify(js_source);
    let report: UnminifyReport = UnminifyReport { source: out, stats };
    Ok(JsUnminify::from_value(null_bundled_value(&report)?))
}

#[derive(Debug, Clone, Serialize)]
struct UnminifyReport {
    source: String,
    stats: UnminifyStats,
}

#[pyfunction]
#[pyo3(signature = (js_source, *, bundler = None))]
#[pyo3(text_signature = "(js_source, *, bundler=None)")]
fn js_unbundle(js_source: &str, bundler: Option<&str>) -> PyResult<JsUnbundle> {
    let result: UnbundleResult = match bundler {
        None => auto_unbundle(js_source).map_err(map("js unbundle"))?,
        Some(b) => {
            let kind: BundlerKind = parse_bundler(b)?;
            unbundle(kind, js_source).map_err(map("js unbundle"))?
        }
    };
    Ok(JsUnbundle::from_value(null_bundled_value(&result)?))
}

fn parse_bundler(label: &str) -> PyResult<BundlerKind> {
    let normalized: String = label.to_ascii_lowercase();
    let kind: BundlerKind = match normalized.as_str() {
        "webpack4" => BundlerKind::Webpack4,
        "webpack5" | "webpack" => BundlerKind::Webpack5,
        "vite" => BundlerKind::Vite,
        "rollup" => BundlerKind::Rollup,
        "rolldown" => BundlerKind::Rolldown,
        "esbuild" => BundlerKind::Esbuild,
        "turbopack" => BundlerKind::Turbopack,
        "bun" => BundlerKind::Bun,
        "browserify" => BundlerKind::Browserify,
        "parcel" => BundlerKind::Parcel,
        "systemjs" => BundlerKind::SystemJs,
        "amd" => BundlerKind::Amd,
        other => {
            return Err(DisrobeError::new_err(format!(
                "unknown bundler hint: {other}"
            )));
        }
    };
    Ok(kind)
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(js_detect, m)?)?;
    m.add_function(wrap_pyfunction!(js_unminify, m)?)?;
    m.add_function(wrap_pyfunction!(js_unbundle, m)?)?;
    Ok(())
}
