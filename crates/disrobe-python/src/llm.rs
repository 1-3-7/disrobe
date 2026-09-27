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
        .finalize(None, ToolDescriptor::default(), &selection, input)
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

pub(crate) fn make_step(pass: &str, version: &str, rung_in: &str, rung_out: &str) -> PipelineStep {
    PipelineStep {
        pass: pass.to_owned(),
        version: version.to_owned(),
        rung_in: rung_in.to_owned(),
        rung_out: rung_out.to_owned(),
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
