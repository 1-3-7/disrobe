use std::collections::BTreeMap;

use disrobe_core::Capability;
use disrobe_ir::{Envelope, RawPayload, Rung, Sidecar, encode_raw};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};
use serde::Serialize;

use crate::err::map;
use crate::typed::EnvelopeReport as PyEnvelopeReport;

const PRODUCED_BY_DEFAULT: &str = "disrobe-python";

#[pyfunction]
#[pyo3(signature = (payload, *, source_label = "inline", produced_by = None, detected_format = None))]
#[pyo3(
    text_signature = "(payload, *, source_label='inline', produced_by=None, detected_format=None)"
)]
fn envelope_create<'py>(
    py: Python<'py>,
    payload: &[u8],
    source_label: &str,
    produced_by: Option<&str>,
    detected_format: Option<&str>,
) -> PyResult<Bound<'py, PyBytes>> {
    let source_hash: [u8; 32] = *blake3::hash(payload).as_bytes();
    let raw: RawPayload = RawPayload {
        source_path: source_label.to_owned(),
        source_bytes: payload.to_vec(),
        source_hash,
        detected_format: detected_format.map(str::to_owned),
    };
    let hot: Vec<u8> = encode_raw(&raw).map_err(map("envelope encode_raw"))?;
    let sidecar: Sidecar = Sidecar {
        produced_by: produced_by
            .map_or(PRODUCED_BY_DEFAULT, |value: &str| value)
            .to_owned(),
        produced_by_version: env!("CARGO_PKG_VERSION").to_owned(),
        capabilities: vec![Capability::produces("raw", 1)],
        provenance: BTreeMap::default(),
    };
    let cold: Vec<u8> = sidecar.encode().map_err(map("envelope sidecar encode"))?;
    let env: Envelope = Envelope::new(Rung::Raw, hot, cold);
    let bytes: Vec<u8> = env.encode().map_err(map("envelope encode"))?;
    Ok(PyBytes::new(py, &bytes))
}

#[derive(Debug, Clone, Serialize)]
struct EnvelopeVerifyReport {
    verified: bool,
    version: u16,
    rung: String,
    hot_bytes: usize,
    cold_bytes: usize,
    root_hash_blake3_hex: String,
}

#[pyfunction]
#[pyo3(text_signature = "(envelope_bytes)")]
fn envelope_verify(envelope_bytes: &[u8]) -> PyResult<PyEnvelopeReport> {
    let env: Envelope = Envelope::decode(envelope_bytes).map_err(map("envelope verify"))?;
    let report: EnvelopeVerifyReport = EnvelopeVerifyReport {
        verified: true,
        version: env.version,
        rung: format!("{:?}", env.rung),
        hot_bytes: env.hot.len(),
        cold_bytes: env.cold.len(),
        root_hash_blake3_hex: hex32(&env.root_hash),
    };
    PyEnvelopeReport::from_serialize(&report)
}

fn hex32(bytes: &[u8; 32]) -> String {
    crate::llm::hex_lower(bytes)
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(envelope_create, m)?)?;
    m.add_function(wrap_pyfunction!(envelope_verify, m)?)?;
    Ok(())
}
