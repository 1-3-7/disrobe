use disrobe_pass_wasm_deob::{
    Error as WasmError, LiftTarget, ModuleSourceLift, ModuleSummary, WasmDetection, analyze_module,
    detect, lift_module_source,
};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde_json::{Value as Json, json};

use crate::err::{DisrobeError, map};
use crate::llm::null_bundled_value;
use crate::typed::{WasmAnalysis, WasmDetection as PyWasmDetection, WasmLift};

#[pyfunction]
#[pyo3(text_signature = "(wasm_bytes)")]
fn wasm_analyze(wasm_bytes: &[u8]) -> PyResult<WasmAnalysis> {
    let summary: ModuleSummary = analyze_module(wasm_bytes).map_err(map("wasm analyze"))?;
    Ok(WasmAnalysis::from_value(null_bundled_value(&summary)?))
}

#[pyfunction]
#[pyo3(text_signature = "(wasm_bytes)")]
fn wasm_detect(wasm_bytes: &[u8]) -> PyResult<PyWasmDetection> {
    let det: WasmDetection = detect(wasm_bytes).map_err(map("wasm detect"))?;
    Ok(PyWasmDetection::from_value(null_bundled_value(&det)?))
}

#[pyfunction]
#[pyo3(signature = (wasm_bytes, *, target), text_signature = "(wasm_bytes, *, target)")]
fn wasm_lift(wasm_bytes: &[u8], target: &str) -> PyResult<WasmLift> {
    let lift_target: LiftTarget = match target {
        "rust" => LiftTarget::Rust,
        "typescript" => LiftTarget::TypeScript,
        "c" => LiftTarget::C,
        "wat" => LiftTarget::Wat,
        _ => {
            return Err(json_error(
                "DR-PY-0420",
                json!({
                    "operation": "wasm lift",
                    "message": format!("unsupported WebAssembly lift target `{target}`"),
                    "target": target,
                    "accepted_targets": ["rust", "typescript", "c", "wat"],
                }),
            ));
        }
    };
    let report: ModuleSourceLift = lift_module_source(wasm_bytes, lift_target)
        .map_err(|error: WasmError| wasm_lift_error(&error))?;
    WasmLift::from_serialize(&report)
}

fn wasm_lift_error(error: &WasmError) -> PyErr {
    let message: String = error.to_string();
    let code: &str = match error {
        WasmError::Parse(_) => "DR-WASMDEOB-0001",
        WasmError::Io(_) => "DR-WASMDEOB-0002",
        WasmError::AtomicMemoryModel(_) => "DR-WASMDEOB-0003",
        WasmError::ModuleSourceLimit { .. } => "DR-WASMDEOB-0004",
        WasmError::ModuleInputLimit { .. } => "DR-WASMDEOB-0005",
    };
    json_error(
        code,
        json!({
            "operation": "wasm lift",
            "message": message,
        }),
    )
}

fn json_error(code: &str, mut payload: Json) -> PyErr {
    if let Json::Object(fields) = &mut payload {
        fields.insert("code".to_owned(), Json::String(code.to_owned()));
    }
    let message: String = serde_json::to_string(&payload).unwrap_or_else(|error| {
        json!({
            "code": "DR-PY-0421",
            "message": error.to_string(),
        })
        .to_string()
    });
    DisrobeError::new_err(message)
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(wasm_analyze, m)?)?;
    m.add_function(wrap_pyfunction!(wasm_detect, m)?)?;
    m.add_function(wrap_pyfunction!(wasm_lift, m)?)?;
    Ok(())
}
