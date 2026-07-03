use std::collections::BTreeMap;

use disrobe_pass_native::{
    BogusBranch, CffUnflattenReport, DecompilerBackend, DeobfBits, DetectedFormat, ObfuscatorHit,
    Probe, SubstitutionResult, detect_format, detect_obfuscators, probe_all, strip_ollvm_bcf,
    undo_ollvm_substitution, unflatten_ollvm,
};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde::Serialize;

use crate::convert::to_value;
use crate::err::{DisrobeError, map};
use crate::llm::null_bundled_value;
use crate::typed::{
    BackendList, DetectionList, NativeDeobfuscation, NativeFormat as PyNativeFormat,
};

#[pyfunction]
#[pyo3(text_signature = "(binary_bytes)")]
fn native_format(binary_bytes: &[u8]) -> PyResult<PyNativeFormat> {
    let f: DetectedFormat = detect_format(binary_bytes).map_err(map("native detect_format"))?;
    Ok(PyNativeFormat::from_value(null_bundled_value(&f)?))
}

#[pyfunction]
#[pyo3(text_signature = "(binary_bytes)")]
fn native_detect(binary_bytes: &[u8]) -> PyResult<DetectionList> {
    let hits: Vec<ObfuscatorHit> = detect_obfuscators(binary_bytes);
    Ok(DetectionList::from_value(to_value(&hits)?))
}

#[pyfunction]
#[pyo3(text_signature = "()")]
fn native_probe_backends() -> PyResult<BackendList> {
    let probes: BTreeMap<DecompilerBackend, Probe> = probe_all();
    let rows: Vec<ProbeRow> = probes
        .into_iter()
        .map(|(b, p): (DecompilerBackend, Probe)| ProbeRow {
            backend: b.label().to_owned(),
            binary_name: b.binary_name().to_owned(),
            license_required: b.license_required(),
            override_env: b.override_env().to_owned(),
            found: p.found,
            path: p.path.map(|p: std::path::PathBuf| p.display().to_string()),
            note: p.note,
        })
        .collect();
    Ok(BackendList::from_value(to_value(&rows)?))
}

#[derive(Debug, Clone, Serialize)]
struct ProbeRow {
    backend: String,
    binary_name: String,
    license_required: bool,
    override_env: String,
    found: bool,
    path: Option<String>,
    note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct NativeDeobfReport {
    bits: u32,
    base: u64,
    entry: u64,
    cff: CffUnflattenReport,
    bogus_branch: Option<BogusBranch>,
    substitution: Option<SubstitutionResult>,
}

fn parse_bits(bits: u32) -> PyResult<DeobfBits> {
    match bits {
        32 => Ok(DeobfBits::Bits32),
        64 => Ok(DeobfBits::Bits64),
        other => Err(DisrobeError::new_err(format!(
            "unsupported bitness {other}; expected 32 or 64"
        ))),
    }
}

#[pyfunction]
#[pyo3(signature = (code, *, bits = 64, base = 0, entry = 0))]
#[pyo3(text_signature = "(code, *, bits=64, base=0, entry=0)")]
fn native_deobfuscate(
    code: &[u8],
    bits: u32,
    base: u64,
    entry: u64,
) -> PyResult<NativeDeobfuscation> {
    let deobf_bits: DeobfBits = parse_bits(bits)?;
    let cff: CffUnflattenReport = unflatten_ollvm(deobf_bits, base, code, entry);
    let bogus_branch: Option<BogusBranch> = strip_ollvm_bcf(deobf_bits, base, code);
    let substitution: Option<SubstitutionResult> = undo_ollvm_substitution(deobf_bits, base, code);
    let report: NativeDeobfReport = NativeDeobfReport {
        bits,
        base,
        entry,
        cff,
        bogus_branch,
        substitution,
    };
    Ok(NativeDeobfuscation::from_value(to_value(&report)?))
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(native_format, m)?)?;
    m.add_function(wrap_pyfunction!(native_detect, m)?)?;
    m.add_function(wrap_pyfunction!(native_probe_backends, m)?)?;
    m.add_function(wrap_pyfunction!(native_deobfuscate, m)?)?;
    Ok(())
}
