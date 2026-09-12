use std::time::SystemTime;

use disrobe_llm_metadata::{
    BundleBuilder, InputDescriptor, LlmMetadataEmitter, MetadataFormat, MetadataSelection, Pack,
    PipelineStep, SelectionBuilder, ToolDescriptor,
};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde::Serialize;
use serde_json::Value as Json;

use crate::convert::from_py;
use crate::err::DisrobeError;

pub(crate) const DEFAULT_PACK_LABEL: &str = "pack-1";
const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

#[inline]
pub(crate) fn parse_pack(label: Option<&str>) -> PyResult<Pack> {
    let raw: &str = label.map_or(DEFAULT_PACK_LABEL, |value: &str| value).trim();
    match raw {
        "pack-1" | "1" => Ok(Pack::Pack1),
        "pack-2" | "2" => Ok(Pack::Pack2),
        "pack-3" | "3" => Ok(Pack::Pack3),
        "pack-4" | "4" => Ok(Pack::Pack4),
        other => Err(DisrobeError::new_err(format!(
            "unknown pack `{other}`; expected pack-1 | pack-2 | pack-3 | pack-4"
        ))),
    }
}

#[inline]
pub(crate) fn selection_for(pack: Pack) -> MetadataSelection {
    SelectionBuilder::new()
        .pack(pack)
        .format(MetadataFormat::Json)
        .build()
}

#[inline]
pub(crate) fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

pub(crate) fn build_bundle<E: LlmMetadataEmitter>(
    emitter: &E,
    pack: Pack,
    step: PipelineStep,
    input: InputDescriptor,
) -> PyResult<Json> {
    let selection: MetadataSelection = selection_for(pack);
    let envelope_map: Json = emitter.emit_metadata(&selection);
    let mut builder: BundleBuilder = BundleBuilder::new();
    builder.record_pass(step, envelope_map);
    builder
        .finalize(iso8601_now(), ToolDescriptor::default(), &selection, input)
        .map_err(|e: disrobe_llm_metadata::LlmMetadataError| {
            DisrobeError::new_err(format!("serialize llm bundle: {e}"))
        })
}

pub(crate) fn make_input_descriptor(path: &str, bytes: &[u8]) -> InputDescriptor {
    let size_bytes: u64 = usize_to_u64_saturating(bytes.len());
    InputDescriptor {
        path: path.to_owned(),
        size_bytes,
        hash_blake3: blake3_hex(bytes),
        magic_bytes_hex: bytes.first_chunk::<8>().map(|c: &[u8; 8]| hex_lower(c)),
        detected_formats: Vec::new(),
    }
}

pub(crate) fn usize_to_u64_saturating(value: usize) -> u64 {
    u64::try_from(value).map_or(u64::MAX, |converted: u64| converted)
}

pub(crate) fn make_step(
    pass: &str,
    version: &str,
    rung_in: &str,
    rung_out: &str,
    duration_ms: f64,
) -> PipelineStep {
    PipelineStep {
        pass: pass.to_owned(),
        version: version.to_owned(),
        rung_in: rung_in.to_owned(),
        rung_out: rung_out.to_owned(),
        duration_ms,
        input_hash_blake3: None,
        output_hash_blake3: None,
        capabilities_required: Vec::new(),
        capabilities_produced: Vec::new(),
        config: None,
    }
}

pub(crate) fn bundled_value<T: Serialize, E: LlmMetadataEmitter>(
    report: &T,
    emitter: &E,
    pack: Pack,
    step: PipelineStep,
    input: InputDescriptor,
) -> PyResult<Json> {
    let bundle: Json = build_bundle(emitter, pack, step, input)?;
    let mut value: Json = serde_json::to_value(report)
        .map_err(|e: serde_json::Error| DisrobeError::new_err(format!("serialize: {e}")))?;
    if let Some(obj) = value.as_object_mut() {
        obj.insert("llm".to_owned(), bundle);
    }
    Ok(value)
}

pub(crate) fn null_bundled_value<T: Serialize>(report: &T) -> PyResult<Json> {
    let mut value: Json = serde_json::to_value(report)
        .map_err(|e: serde_json::Error| DisrobeError::new_err(format!("serialize: {e}")))?;
    if let Some(obj) = value.as_object_mut() {
        obj.insert("llm".to_owned(), Json::Null);
    }
    Ok(value)
}

fn bundle_from_value(value: Json) -> PyResult<Json> {
    if value.get("categories").is_some() {
        return Ok(value);
    }
    match value.get("llm") {
        Some(Json::Null) | None => Err(DisrobeError::new_err(
            "result has no `llm` bundle; call with an LLM-enabled pass result \
             or pass a bundle dict directly",
        )),
        Some(bundle) => Ok(bundle.clone()),
    }
}

fn depythonize_value(obj: &Bound<'_, PyAny>) -> PyResult<Json> {
    from_py(obj)
}

#[pyfunction]
#[pyo3(name = "agents_md")]
fn agents_md(result: &Bound<'_, PyAny>) -> PyResult<String> {
    let value: Json = depythonize_value(result)?;
    let bundle: Json = bundle_from_value(value)?;
    Ok(disrobe_llm_metadata::render_agents_md(&bundle))
}

#[pyfunction]
#[pyo3(name = "skill_md")]
fn skill_md(result: &Bound<'_, PyAny>) -> PyResult<String> {
    let value: Json = depythonize_value(result)?;
    let bundle: Json = bundle_from_value(value)?;
    Ok(disrobe_llm_metadata::render_skill_md(&bundle))
}

#[pyfunction]
#[pyo3(name = "provenance")]
fn provenance(result: &Bound<'_, PyAny>) -> PyResult<crate::typed::Provenance> {
    let value: Json = depythonize_value(result)?;
    let bundle: Json = bundle_from_value(value)?;
    crate::typed::Provenance::from_serialize(&bundle)
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(agents_md, m)?)?;
    m.add_function(wrap_pyfunction!(skill_md, m)?)?;
    m.add_function(wrap_pyfunction!(provenance, m)?)?;
    Ok(())
}

#[inline]
pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    let mut out: String = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(LOWER_HEX[(byte >> 4) as usize] as char);
        out.push(LOWER_HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[allow(clippy::disallowed_methods)]
fn iso8601_now() -> String {
    let now: SystemTime = SystemTime::now();
    let dur: std::time::Duration = now
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(std::time::Duration::ZERO, |duration| duration);
    let secs: u64 = dur.as_secs();
    let nanos: u32 = dur.subsec_nanos();
    let seconds_per_day: u64 = 86_400;
    let days_since_epoch: u64 = secs / seconds_per_day;
    let time_in_day: u64 = secs % seconds_per_day;
    let hh: u64 = time_in_day / 3600;
    let mm: u64 = (time_in_day % 3600) / 60;
    let ss: u64 = time_in_day % 60;
    let (year, month, day): (i32, u32, u32) = civil_from_days(i64_from_u64(days_since_epoch));
    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}.{nanos:09}Z")
}

#[inline]
const fn i64_from_u64(value: u64) -> i64 {
    if value > (i64::MAX as u64) {
        i64::MAX
    } else {
        value as i64
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z: i64 = z + 719_468;
    let era: i64 = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe: u64 = (z - era * 146_097) as u64;
    let yoe: u64 = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y: i64 = (yoe as i64) + era * 400;
    let doy: u64 = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp: u64 = (5 * doy + 2) / 153;
    let d: u64 = doy - (153 * mp + 2) / 5 + 1;
    let m: u64 = if mp < 10 { mp + 3 } else { mp - 9 };
    let year_out: i32 = (y + i64::from(m <= 2)) as i32;
    (year_out, m as u32, d as u32)
}
