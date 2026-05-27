use disrobe_pass_js_deob::{
    BundlerKind, Detection, UnbundleResult, UnminifyStats, auto_unbundle, detect, unbundle,
    unminify,
};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde::Serialize;

use crate::err::{DisrobeError, map};
use crate::llm::report_with_null_bundle;

/// Run the JS obfuscator detector (jsobfuscator.io, JScrambler, jsobfu,
/// aaencode, jjencode, jsfuck, packer, JSDefender, PACE, Arxan-JS,
/// JsConfuser, Closure-advanced, Terser-mangled). Returns the matched
/// family, confidence, and markers.
#[pyfunction]
#[pyo3(text_signature = "(js_source)")]
fn js_detect<'py>(py: Python<'py>, js_source: &str) -> PyResult<Bound<'py, PyAny>> {
    let det: Detection = detect(js_source.as_bytes());
    report_with_null_bundle(py, &det)
}

/// Unminify a JS source string. Reformats compressed code, renames
/// trivial single-letter identifiers when safe, expands chained
/// expressions back to statements. Returns the unminified source plus
/// stats (`statements_added`, `identifiers_renamed`, `chains_split`).
#[pyfunction]
#[pyo3(text_signature = "(js_source)")]
fn js_unminify<'py>(py: Python<'py>, js_source: &str) -> PyResult<Bound<'py, PyAny>> {
    let (out, stats): (String, UnminifyStats) = unminify(js_source);
    let report: UnminifyReport = UnminifyReport { source: out, stats };
    report_with_null_bundle(py, &report)
}

#[derive(Debug, Clone, Serialize)]
struct UnminifyReport {
    source: String,
    stats: UnminifyStats,
}

/// Unbundle a JS bundle. Either auto-detects the bundler (webpack4/5,
/// vite, rollup, rolldown, esbuild, turbopack, bun, browserify, parcel,
/// systemjs) or uses the provided `bundler` hint. Returns the extracted
/// module list with chunk and module identifiers preserved.
#[pyfunction]
#[pyo3(signature = (js_source, *, bundler = None))]
#[pyo3(text_signature = "(js_source, *, bundler=None)")]
fn js_unbundle<'py>(
    py: Python<'py>,
    js_source: &str,
    bundler: Option<&str>,
) -> PyResult<Bound<'py, PyAny>> {
    let result: UnbundleResult = match bundler {
        None => auto_unbundle(js_source).map_err(map("js unbundle"))?,
        Some(b) => {
            let kind: BundlerKind = parse_bundler(b)?;
            unbundle(kind, js_source).map_err(map("js unbundle"))?
        }
    };
    report_with_null_bundle(py, &result)
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
