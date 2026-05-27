use std::time::Instant;

use disrobe_pass_py_decompile::engine::{NativeDecompile, decompile_pyc};
use disrobe_pass_py_decompile::llm::{DisasmIns, PyDecompileLlmInput};
use disrobe_pass_py_decompile::recompile::{RoundtripOutcome, RoundtripStatus, roundtrip_native};
use disrobe_pass_py_disasm::Instruction as PyDisasmInstruction;
use disrobe_py_marshal::{Object, PyVersion as MarshalVersion};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde::Serialize;

use crate::err::map;
use crate::llm::{make_input_descriptor, make_step, parse_pack, report_with_bundle};

const PASS_DECOMPILE: &str = "disrobe-pass-py-decompile";
const PASS_DECOMPILE_VERSION: &str = disrobe_pass_py_decompile::VERSION;

#[derive(Debug, Clone, Serialize)]
struct DecompileReport {
    source: String,
    marshal_version: VersionLabel,
    decompile_version: VersionLabel,
    recovered_directly: bool,
    fallback_reason: Option<String>,
    roundtrip: Option<RoundtripReport>,
}

#[derive(Debug, Clone, Copy, Serialize)]
struct VersionLabel {
    major: u8,
    minor: u8,
}

#[derive(Debug, Clone, Serialize)]
struct RoundtripReport {
    status: String,
    detail: Option<String>,
    interpreter_path: Option<String>,
    interpreter_version: Option<String>,
}

impl From<RoundtripStatus> for RoundtripReport {
    fn from(s: RoundtripStatus) -> Self {
        let (status, detail): (String, Option<String>) = match s {
            RoundtripStatus::Perfect => ("perfect".to_owned(), None),
            RoundtripStatus::Semantic => ("semantic".to_owned(), None),
            RoundtripStatus::CodeDiff { detail } => ("code-diff".to_owned(), Some(detail)),
            RoundtripStatus::NoInterpreter { hint } => ("no-interpreter".to_owned(), Some(hint)),
            RoundtripStatus::RecompileFailed { stderr } => {
                ("recompile-failed".to_owned(), Some(stderr))
            }
        };
        Self {
            status,
            detail,
            interpreter_path: None,
            interpreter_version: None,
        }
    }
}

/// Decompile a `.pyc` (with header) into Python source.
///
/// Supports CPython 1.0 through 3.15 and PyPy. When the decompiler cannot
/// reconstruct source it falls back to a typed disassembly listing.
///
/// Pass `roundtrip=True` to recompile the recovered source with a matching
/// `python<major>.<minor>` on PATH and report a roundtrip verdict
/// (`perfect`, `semantic`, `code-diff`, `no-interpreter`, `recompile-failed`).
///
/// `pack` selects the LLM metadata pack attached as `result["llm"]`:
/// `pack-1` (lean), `pack-2` (standard), `pack-3` (full), `pack-4` (exhaustive).
/// Defaults to `pack-1`.
#[pyfunction]
#[pyo3(signature = (pyc_bytes, *, roundtrip = false, pack = None))]
#[pyo3(text_signature = "(pyc_bytes, *, roundtrip=False, pack='pack-1')")]
fn py_decompile<'py>(
    py: Python<'py>,
    pyc_bytes: &[u8],
    roundtrip: bool,
    pack: Option<&str>,
) -> PyResult<Bound<'py, PyAny>> {
    let pack_kind: disrobe_llm_metadata::Pack = parse_pack(pack)?;
    let started: Instant = Instant::now();
    let result: NativeDecompile = decompile_pyc(pyc_bytes).map_err(map("py.decompile"))?;
    let marshal: MarshalVersion = result.marshal_version;
    let decompile_v: (u8, u8) = (
        result.decompile_version.major(),
        result.decompile_version.minor(),
    );
    let roundtrip_report: Option<RoundtripReport> = if roundtrip {
        let outcome: RoundtripOutcome = roundtrip_native(
            &result.source,
            &result.code,
            &result.decompile_version,
            marshal,
        );
        let mut rep: RoundtripReport = RoundtripReport::from(outcome.status);
        rep.interpreter_path = outcome
            .interpreter_path
            .map(|p: std::path::PathBuf| p.display().to_string());
        rep.interpreter_version = outcome.interpreter_version;
        Some(rep)
    } else {
        None
    };
    let report: DecompileReport = DecompileReport {
        source: result.source.clone(),
        marshal_version: VersionLabel {
            major: marshal.major,
            minor: marshal.minor,
        },
        decompile_version: VersionLabel {
            major: decompile_v.0,
            minor: decompile_v.1,
        },
        recovered_directly: result.recovered_directly,
        fallback_reason: result.fallback_reason.clone(),
        roundtrip: roundtrip_report.clone(),
    };
    let duration_ms: f64 = started.elapsed().as_secs_f64() * 1000.0_f64;
    let disasm_ins: Vec<PyDisasmInstruction> =
        disrobe_pass_py_disasm::disassemble(&result.code, marshal);
    let llm_input: PyDecompileLlmInput = PyDecompileLlmInput {
        module_path: format!("python.{}.{}", marshal.major, marshal.minor),
        python_version: format!("{}.{}", marshal.major, marshal.minor),
        final_source: result.source.clone(),
        backend: "native".to_owned(),
        disasm: disasm_ins
            .iter()
            .map(|i: &PyDisasmInstruction| DisasmIns {
                offset: i.offset as u64,
                opname: i.opname.clone(),
                arg: i.arg,
                argrepr: i.argrepr.clone(),
                line: i.line,
            })
            .collect(),
        names: result.code.names.iter().map(object_label).collect(),
        varnames: result.code.varnames.iter().map(object_label).collect(),
        consts: result.code.consts.iter().map(object_label).collect(),
        input_size_bytes: u64::try_from(pyc_bytes.len()).unwrap_or(u64::MAX),
        input_hash_blake3: crate::llm::blake3_hex(pyc_bytes),
        roundtrip_status: roundtrip_report
            .as_ref()
            .map(|r: &RoundtripReport| r.status.clone()),
        duration_ms,
    };
    let step: disrobe_llm_metadata::PipelineStep = make_step(
        PASS_DECOMPILE,
        PASS_DECOMPILE_VERSION,
        "disasm",
        "surface",
        duration_ms,
    );
    let input: disrobe_llm_metadata::InputDescriptor = make_input_descriptor("<pyc>", pyc_bytes);
    report_with_bundle(py, &report, &llm_input, pack_kind, step, input)
}

/// Disassemble a `.pyc` to a typed instruction listing without attempting
/// source reconstruction. Returns a dict with `marshal_version`,
/// `instruction_count`, `text`, and an `llm` bundle.
#[pyfunction]
#[pyo3(signature = (pyc_bytes, *, pack = None))]
#[pyo3(text_signature = "(pyc_bytes, *, pack='pack-1')")]
fn py_disasm<'py>(
    py: Python<'py>,
    pyc_bytes: &[u8],
    pack: Option<&str>,
) -> PyResult<Bound<'py, PyAny>> {
    let pack_kind: disrobe_llm_metadata::Pack = parse_pack(pack)?;
    let started: Instant = Instant::now();
    let result: NativeDecompile = decompile_pyc(pyc_bytes).map_err(map("py.disasm"))?;
    let marshal: MarshalVersion = result.marshal_version;
    let ins: Vec<PyDisasmInstruction> = disrobe_pass_py_disasm::disassemble(&result.code, marshal);
    let text: String = disrobe_pass_py_disasm::render_dis(&ins);
    let duration_ms: f64 = started.elapsed().as_secs_f64() * 1000.0_f64;
    let report: DisasmReport = DisasmReport {
        marshal_version: format!("{}.{}", marshal.major, marshal.minor),
        instruction_count: ins.len(),
        text,
    };
    let llm_input: PyDecompileLlmInput = PyDecompileLlmInput {
        module_path: format!("python.{}.{}", marshal.major, marshal.minor),
        python_version: format!("{}.{}", marshal.major, marshal.minor),
        final_source: result.source.clone(),
        backend: "disasm".to_owned(),
        disasm: ins
            .iter()
            .map(|i: &PyDisasmInstruction| DisasmIns {
                offset: i.offset as u64,
                opname: i.opname.clone(),
                arg: i.arg,
                argrepr: i.argrepr.clone(),
                line: i.line,
            })
            .collect(),
        names: result.code.names.iter().map(object_label).collect(),
        varnames: result.code.varnames.iter().map(object_label).collect(),
        consts: result.code.consts.iter().map(object_label).collect(),
        input_size_bytes: u64::try_from(pyc_bytes.len()).unwrap_or(u64::MAX),
        input_hash_blake3: crate::llm::blake3_hex(pyc_bytes),
        roundtrip_status: None,
        duration_ms,
    };
    let step: disrobe_llm_metadata::PipelineStep = make_step(
        PASS_DECOMPILE,
        PASS_DECOMPILE_VERSION,
        "raw",
        "disasm",
        duration_ms,
    );
    let input: disrobe_llm_metadata::InputDescriptor = make_input_descriptor("<pyc>", pyc_bytes);
    report_with_bundle(py, &report, &llm_input, pack_kind, step, input)
}

#[derive(Debug, Clone, Serialize)]
struct DisasmReport {
    marshal_version: String,
    instruction_count: usize,
    text: String,
}

fn object_label(obj: &Object) -> String {
    match obj {
        Object::String { value, .. } | Object::ShortAscii { value, .. } => value.clone(),
        other => format!("{other:?}"),
    }
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_decompile, m)?)?;
    m.add_function(wrap_pyfunction!(py_disasm, m)?)?;
    Ok(())
}
