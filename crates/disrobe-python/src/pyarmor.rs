use std::time::Instant;

use disrobe_pass_pyarmor::{
    Detection as PyarmorDetection, PyarmorLlmInput, StaticDecryptStatus, StaticUnpackOutput,
    detect_from_wrapper, unpack_static,
};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde::Serialize;

use crate::err::map;
use crate::llm::{make_input_descriptor, make_step, parse_pack, report_with_bundle};

const PASS_PYARMOR: &str = "disrobe-pass-pyarmor";
const PASS_PYARMOR_VERSION: &str = disrobe_pass_pyarmor::VERSION;

#[derive(Debug, Clone, Serialize)]
struct PyarmorDetectionReport {
    version: String,
    protection: String,
    confidence: String,
    serial: Option<String>,
    python_major: Option<u8>,
    python_minor: Option<u8>,
    pyc_magic: Option<u16>,
    payload_offset: usize,
    payload_size: usize,
    diagnostics: Vec<String>,
}

impl From<&PyarmorDetection> for PyarmorDetectionReport {
    fn from(d: &PyarmorDetection) -> Self {
        Self {
            version: format!("{:?}", d.version),
            protection: format!("{:?}", d.protection),
            confidence: format!("{:?}", d.confidence),
            serial: d.serial.clone(),
            python_major: d.python_major,
            python_minor: d.python_minor,
            pyc_magic: d.pyc_magic,
            payload_offset: d.payload_offset_in_payload,
            payload_size: d.payload_size_in_payload,
            diagnostics: d.diagnostics.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct PyarmorUnpackReport {
    detection: PyarmorDetectionReport,
    status: String,
    pyarmor_version: String,
    protection_kind: String,
    python_version: Option<(u8, u8)>,
    pyc_magic: Option<u16>,
    serial: Option<String>,
    plaintext_len: usize,
    plaintext_blake3_hex: String,
    bcc_blob_count: usize,
    inner_cipher_recovered_co: usize,
    inner_cipher_recovered_bytes: usize,
    diagnostics: Vec<String>,
}

/// Detect PyArmor wrappers in a Python source string.
#[pyfunction]
#[pyo3(signature = (source, *, pack = None))]
#[pyo3(text_signature = "(source, *, pack='pack-1')")]
fn pyarmor_detect<'py>(
    py: Python<'py>,
    source: &str,
    pack: Option<&str>,
) -> PyResult<Bound<'py, PyAny>> {
    let pack_kind: disrobe_llm_metadata::Pack = parse_pack(pack)?;
    let started: Instant = Instant::now();
    let (det, _payload): (PyarmorDetection, Vec<u8>) =
        detect_from_wrapper(source).map_err(map("pyarmor detect"))?;
    let report: PyarmorDetectionReport = PyarmorDetectionReport::from(&det);
    let duration_ms: f64 = started.elapsed().as_secs_f64() * 1000.0_f64;
    let llm_input: PyarmorLlmInput = PyarmorLlmInput {
        detection: Some(det),
        recovered_keys: Vec::new(),
        authorized_keys: false,
        input_path: "<source>".to_owned(),
        input_size_bytes: u64::try_from(source.len()).unwrap_or(u64::MAX),
        input_hash_blake3: crate::llm::blake3_hex(source.as_bytes()),
        duration_ms,
    };
    let step: disrobe_llm_metadata::PipelineStep = make_step(
        PASS_PYARMOR,
        PASS_PYARMOR_VERSION,
        "raw",
        "disasm",
        duration_ms,
    );
    let input: disrobe_llm_metadata::InputDescriptor =
        make_input_descriptor("<source>", source.as_bytes());
    report_with_bundle(py, &report, &llm_input, pack_kind, step, input)
}

/// Statically unpack a PyArmor-protected wrapper image (bytes).
#[pyfunction]
#[pyo3(signature = (wrapper_bytes, *, pack = None))]
#[pyo3(text_signature = "(wrapper_bytes, *, pack='pack-1')")]
fn pyarmor_unpack<'py>(
    py: Python<'py>,
    wrapper_bytes: &[u8],
    pack: Option<&str>,
) -> PyResult<Bound<'py, PyAny>> {
    let pack_kind: disrobe_llm_metadata::Pack = parse_pack(pack)?;
    let started: Instant = Instant::now();
    let out: StaticUnpackOutput = unpack_static(wrapper_bytes).map_err(map("pyarmor unpack"))?;
    let detection: PyarmorDetection = PyarmorDetection {
        version: out.pyarmor_version,
        protection: out.protection_kind,
        serial: out.serial.clone(),
        python_major: out.python_version.map(|(maj, _)| maj),
        python_minor: out.python_version.map(|(_, min)| min),
        pyc_magic: out.pyc_magic,
        payload_offset_in_payload: 0,
        payload_size_in_payload: out.plaintext.len(),
        iv: None,
        raw_header: Vec::new(),
        confidence: out.confidence,
        diagnostics: out.diagnostics.clone(),
    };
    let plaintext_blake3: String = blake3::hash(&out.plaintext).to_hex().to_string();
    let report: PyarmorUnpackReport = PyarmorUnpackReport {
        detection: PyarmorDetectionReport::from(&detection),
        status: status_label(out.status),
        pyarmor_version: format!("{:?}", out.pyarmor_version),
        protection_kind: format!("{:?}", out.protection_kind),
        python_version: out.python_version,
        pyc_magic: out.pyc_magic,
        serial: out.serial.clone(),
        plaintext_len: out.plaintext.len(),
        plaintext_blake3_hex: plaintext_blake3,
        bcc_blob_count: out.bcc_blobs.len(),
        inner_cipher_recovered_co: out.inner_cipher_stats.recovered_co_count,
        inner_cipher_recovered_bytes: out.inner_cipher_stats.recovered_co_code_bytes,
        diagnostics: out.diagnostics,
    };
    let duration_ms: f64 = started.elapsed().as_secs_f64() * 1000.0_f64;
    let llm_input: PyarmorLlmInput = PyarmorLlmInput {
        detection: Some(detection),
        recovered_keys: Vec::new(),
        authorized_keys: false,
        input_path: "<wrapper>".to_owned(),
        input_size_bytes: u64::try_from(wrapper_bytes.len()).unwrap_or(u64::MAX),
        input_hash_blake3: crate::llm::blake3_hex(wrapper_bytes),
        duration_ms,
    };
    let step: disrobe_llm_metadata::PipelineStep = make_step(
        PASS_PYARMOR,
        PASS_PYARMOR_VERSION,
        "raw",
        "surface",
        duration_ms,
    );
    let input: disrobe_llm_metadata::InputDescriptor =
        make_input_descriptor("<wrapper>", wrapper_bytes);
    report_with_bundle(py, &report, &llm_input, pack_kind, step, input)
}

fn status_label(s: StaticDecryptStatus) -> String {
    match s {
        StaticDecryptStatus::Functional => "functional",
        StaticDecryptStatus::BccPartial => "bcc-partial",
        StaticDecryptStatus::DetectOnly => "detect-only",
        StaticDecryptStatus::Skeleton => "skeleton",
    }
    .to_owned()
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(pyarmor_detect, m)?)?;
    m.add_function(wrap_pyfunction!(pyarmor_unpack, m)?)?;
    Ok(())
}
