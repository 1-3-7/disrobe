use std::time::Instant;

use disrobe_pass_py_deob::llm::PyDeobLlmInput;
use disrobe_pass_py_deob::{
    CleanupStats, Detection, Error as PyDeobError, Obfuscator, ObfuscatorDetectReport,
    ObfuscatorPass, PeelResult, cleanup_source, detect, iter_passes, peel,
};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde::Serialize;

use crate::convert::to_value;
use crate::err::map;
use crate::llm::{bundled_value, make_input_descriptor, make_step, null_bundled_value, parse_pack};
use crate::typed::{
    ObfuscatorPass as PyObfuscatorPass, PyDeobDetection, PyDeobReport as PyDeobReportObj,
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

#[pyfunction]
#[pyo3(signature = (source, *, cleanup = true, pack = None))]
#[pyo3(text_signature = "(source, *, cleanup=True, pack='pack-1')")]
fn py_deob(source: &str, cleanup: bool, pack: Option<&str>) -> PyResult<PyDeobReportObj> {
    let pack_kind: disrobe_llm_metadata::Pack = parse_pack(pack)?;
    let started: Instant = Instant::now();
    let detection: Detection = detect(source.as_bytes());
    let peel_result: Option<PeelResult> = peel_result_from_result(peel(source.as_bytes()))?;
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
    let value: serde_json::Value = peel_result.map_or_else(
        || null_bundled_value(&report),
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
            bundled_value(&report, &llm_input, pack_kind, step, input)
        },
    )?;
    Ok(PyDeobReportObj::from_value(value))
}

#[pyfunction]
#[pyo3(text_signature = "(source)")]
fn py_deob_detect(source: &str) -> PyResult<PyDeobDetection> {
    let detection: Detection = detect(source.as_bytes());
    Ok(PyDeobDetection::from_value(null_bundled_value(&detection)?))
}

#[pyfunction]
#[pyo3(text_signature = "()")]
fn py_deob_list_passes() -> PyResult<Vec<PyObfuscatorPass>> {
    iter_passes()
        .into_iter()
        .map(|p: &dyn ObfuscatorPass| {
            let row: ObfPassRow = ObfPassRow {
                id: obfuscator_id(p.id()),
            };
            Ok(PyObfuscatorPass::from_value(to_value(&row)?))
        })
        .collect()
}

#[derive(Debug, Clone, Serialize)]
struct ObfPassRow {
    id: String,
}

fn obfuscator_id(o: Obfuscator) -> String {
    format!("{o:?}")
}

#[pyfunction]
#[pyo3(text_signature = "(source, pass_id)")]
fn py_deob_detect_pass(source: &str, pass_id: &str) -> PyResult<PyDeobDetection> {
    let report: ObfuscatorDetectReport = iter_passes()
        .into_iter()
        .find(|p: &&dyn ObfuscatorPass| obfuscator_id(p.id()) == pass_id)
        .ok_or_else(|| crate::err::DisrobeError::new_err(format!("unknown pass_id: {pass_id}")))?
        .detect(source.as_bytes());
    Ok(PyDeobDetection::from_value(null_bundled_value(&report)?))
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_deob, m)?)?;
    m.add_function(wrap_pyfunction!(py_deob_detect, m)?)?;
    m.add_function(wrap_pyfunction!(py_deob_list_passes, m)?)?;
    m.add_function(wrap_pyfunction!(py_deob_detect_pass, m)?)?;
    Ok(())
}

fn peel_result_from_result(
    result: core::result::Result<PeelResult, PyDeobError>,
) -> PyResult<Option<PeelResult>> {
    match result {
        Ok(peel_result) => Ok(Some(peel_result)),
        Err(PyDeobError::NoFamilyMatched) => Ok(None),
        Err(err) => Err(map("py.deob peel")(err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peel_result_suppresses_explicit_no_family() {
        let result: PyResult<Option<PeelResult>> =
            peel_result_from_result(Err(PyDeobError::NoFamilyMatched));
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn peel_result_does_not_suppress_real_errors() {
        let result: PyResult<Option<PeelResult>> =
            peel_result_from_result(Err(PyDeobError::DepthLimit(3)));
        assert!(result.is_err());
    }
}
