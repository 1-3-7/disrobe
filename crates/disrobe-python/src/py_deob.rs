use std::time::Instant;

use disrobe_pass_py_deob::llm::PyDeobLlmInput;
use disrobe_pass_py_deob::{
    CleanupStats, Detection, Obfuscator, ObfuscatorDetectReport, ObfuscatorPass, PeelResult,
    cleanup_source, detect, iter_passes, peel,
};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde::Serialize;

use crate::convert::to_py;
use crate::err::map;
use crate::llm::{
    make_input_descriptor, make_step, parse_pack, report_with_bundle, report_with_null_bundle,
};

const PASS_DEOB: &str = "disrobe-pass-py-deob";
const PASS_DEOB_VERSION: &str = disrobe_pass_py_deob::VERSION;

#[derive(Debug, Clone, Serialize)]
struct PyDeobReport {
    detection: Detection,
    peel: Option<PeelResult>,
    cleanup: Option<CleanupReport>,
}

#[derive(Debug, Clone, Serialize)]
struct CleanupReport {
    source: String,
    stats: CleanupStats,
}

/// Deobfuscate a Python source string.
///
/// Runs the family-aware peel pipeline (Pyfuscator, Hyperion v2/v3, generic
/// droppers, Kramer-successor, etc.) until convergence, then optionally
/// applies AST-level cleanup (constant folding, dead-branch pruning,
/// f-string recovery, junk-fn removal, unrename).
///
/// Returns a dict with `detection`, `peel`, `cleanup`, & `llm` sub-reports.
/// `pack` selects the LLM metadata pack (`pack-1`..`pack-4`); defaults to `pack-1`.
#[pyfunction]
#[pyo3(signature = (source, *, cleanup = true, pack = None))]
#[pyo3(text_signature = "(source, *, cleanup=True, pack='pack-1')")]
fn py_deob<'py>(
    py: Python<'py>,
    source: &str,
    cleanup: bool,
    pack: Option<&str>,
) -> PyResult<Bound<'py, PyAny>> {
    let pack_kind: disrobe_llm_metadata::Pack = parse_pack(pack)?;
    let started: Instant = Instant::now();
    let detection: Detection = detect(source.as_bytes());
    let peel_result: Option<PeelResult> = peel(source.as_bytes()).ok();
    let final_source: String = peel_result.as_ref().map_or_else(
        || source.to_owned(),
        |p: &PeelResult| p.final_source.clone(),
    );
    let cleanup_report: Option<CleanupReport> = if cleanup {
        let (cleaned, stats): (String, CleanupStats) =
            cleanup_source(&final_source).map_err(map("py.deob cleanup"))?;
        Some(CleanupReport {
            source: cleaned,
            stats,
        })
    } else {
        None
    };
    let report: PyDeobReport = PyDeobReport {
        detection,
        peel: peel_result.clone(),
        cleanup: cleanup_report,
    };
    let duration_ms: f64 = started.elapsed().as_secs_f64() * 1000.0_f64;
    peel_result.map_or_else(
        || report_with_null_bundle(py, &report),
        |peel: PeelResult| {
            let llm_input: PyDeobLlmInput = PyDeobLlmInput { peel, duration_ms };
            let step: disrobe_llm_metadata::PipelineStep = make_step(
                PASS_DEOB,
                PASS_DEOB_VERSION,
                "surface",
                "surface",
                duration_ms,
            );
            let input: disrobe_llm_metadata::InputDescriptor =
                make_input_descriptor("<source>", source.as_bytes());
            report_with_bundle(py, &report, &llm_input, pack_kind, step, input)
        },
    )
}

/// Run only the family detector for Python obfuscators (no peel, no cleanup).
/// Returns the `Detection` record with an `llm: null` placeholder.
#[pyfunction]
#[pyo3(text_signature = "(source)")]
fn py_deob_detect<'py>(py: Python<'py>, source: &str) -> PyResult<Bound<'py, PyAny>> {
    let detection: Detection = detect(source.as_bytes());
    report_with_null_bundle(py, &detection)
}

/// Enumerate registered Python-source obfuscator passes (named by family).
#[pyfunction]
#[pyo3(text_signature = "()")]
fn py_deob_list_passes<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
    let rows: Vec<ObfPassRow> = iter_passes()
        .into_iter()
        .map(|p: &dyn ObfuscatorPass| ObfPassRow {
            id: obfuscator_id(p.id()),
        })
        .collect();
    to_py(py, &rows)
}

#[derive(Debug, Clone, Serialize)]
struct ObfPassRow {
    id: String,
}

fn obfuscator_id(o: Obfuscator) -> String {
    format!("{o:?}")
}

/// Run a single named obfuscator-detection pass against `source`.
/// `pass_id` must match an id from `py_deob_list_passes()`.
#[pyfunction]
#[pyo3(text_signature = "(source, pass_id)")]
fn py_deob_detect_pass<'py>(
    py: Python<'py>,
    source: &str,
    pass_id: &str,
) -> PyResult<Bound<'py, PyAny>> {
    let report: ObfuscatorDetectReport = iter_passes()
        .into_iter()
        .find(|p: &&dyn ObfuscatorPass| obfuscator_id(p.id()) == pass_id)
        .ok_or_else(|| crate::err::DisrobeError::new_err(format!("unknown pass_id: {pass_id}")))?
        .detect(source.as_bytes());
    report_with_null_bundle(py, &report)
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_deob, m)?)?;
    m.add_function(wrap_pyfunction!(py_deob_detect, m)?)?;
    m.add_function(wrap_pyfunction!(py_deob_list_passes, m)?)?;
    m.add_function(wrap_pyfunction!(py_deob_detect_pass, m)?)?;
    Ok(())
}
