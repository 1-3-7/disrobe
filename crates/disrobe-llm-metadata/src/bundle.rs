#![allow(clippy::needless_pass_by_value, clippy::too_long_first_doc_paragraph)]
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json};

use crate::category::Category;
use crate::envelope::PerPassEnvelope;
use crate::error::LlmMetadataError;
use crate::selection::{MetadataFormat, MetadataSelection};
use crate::{SCHEMA, SCHEMA_VERSION, VERSION};

pub const MAX_PIPELINE_STEPS: usize = 1024;
const MAX_PROVENANCE_CHAIN_ENTRIES: usize = 16_384;
const MAX_DECRYPTION_KEY_ENTRIES: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDescriptor {
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_profile: Option<String>,
}

impl Default for ToolDescriptor {
    fn default() -> Self {
        Self {
            name: "disrobe".to_owned(),
            version: VERSION.to_owned(),
            git_commit: None,
            build_profile: Some(if cfg!(debug_assertions) {
                "debug".to_owned()
            } else {
                "release".to_owned()
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputDescriptor {
    pub path: String,
    pub size_bytes: u64,
    pub hash_blake3: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub magic_bytes_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detected_formats: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStep {
    pub pass: String,
    pub version: String,
    pub rung_in: String,
    pub rung_out: String,
    pub duration_ms: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_hash_blake3: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_hash_blake3: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities_required: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities_produced: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<Json>,
}

#[derive(Debug, Default)]
pub struct BundleBuilder {
    pub steps: Vec<PipelineStep>,
    pub per_pass: Vec<Json>,
}

impl BundleBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_pass(&mut self, step: PipelineStep, pass_envelope_map: Json) -> &mut Self {
        self.per_pass.push(pass_envelope_map);
        self.steps.push(step);
        self
    }

    pub fn finalize(
        self,
        generated_at: String,
        tool: ToolDescriptor,
        selection: &MetadataSelection,
        input: InputDescriptor,
    ) -> Result<Json, LlmMetadataError> {
        validate_builder_state(self.steps.len(), self.per_pass.len())?;
        let categories: Map<String, Json> = build_categories(&self.per_pass)?;
        let pipeline: Vec<Json> = self
            .steps
            .iter()
            .map(pipeline_step_json)
            .collect::<Result<Vec<Json>, LlmMetadataError>>()?;

        let mut top: Map<String, Json> = Map::new();
        top.insert("schema".to_owned(), Json::String(SCHEMA.to_owned()));
        top.insert(
            "schema_version".to_owned(),
            Json::String(SCHEMA_VERSION.to_owned()),
        );
        top.insert("generated_at".to_owned(), Json::String(generated_at));
        top.insert("tool".to_owned(), tool_descriptor_json(&tool));
        top.insert("selection".to_owned(), selection_json(selection));
        top.insert("input".to_owned(), input_descriptor_json(&input));
        top.insert("pipeline".to_owned(), Json::Array(pipeline));
        top.insert("categories".to_owned(), Json::Object(categories));
        Ok(Json::Object(top))
    }
}

fn validate_builder_state(
    step_count: usize,
    envelope_count: usize,
) -> Result<(), LlmMetadataError> {
    if step_count != envelope_count {
        return Err(LlmMetadataError::Serialization(format!(
            "bundle builder has {step_count} pipeline steps but {envelope_count} per-pass envelope maps"
        )));
    }
    if step_count > MAX_PIPELINE_STEPS {
        return Err(LlmMetadataError::Serialization(format!(
            "bundle builder has {step_count} pipeline steps, max {MAX_PIPELINE_STEPS}"
        )));
    }
    Ok(())
}

fn build_categories(per_pass: &[Json]) -> Result<Map<String, Json>, LlmMetadataError> {
    let mut grouped: BTreeMap<String, Vec<Json>> = BTreeMap::new();
    for (index, envelope_map) in per_pass.iter().enumerate() {
        let Some(obj): Option<&Map<String, Json>> = envelope_map.as_object() else {
            return Err(LlmMetadataError::Serialization(format!(
                "per-pass envelope map at index {index} is not a JSON object"
            )));
        };
        for (cat_label, envelope) in obj {
            let category: Category = Category::parse(cat_label)?;
            grouped
                .entry(category.label().to_owned())
                .or_default()
                .push(envelope.clone());
        }
    }
    let mut out: Map<String, Json> = Map::new();
    for (label, entries) in grouped {
        let mut category_obj: Map<String, Json> = Map::new();
        if label == Category::Provenance.label() {
            let mut chain: Vec<Json> = Vec::new();
            for envelope in &entries {
                if let Some(arr) = envelope
                    .get("value")
                    .and_then(|v: &Json| v.get("chain"))
                    .and_then(Json::as_array)
                {
                    if chain.len().saturating_add(arr.len()) > MAX_PROVENANCE_CHAIN_ENTRIES {
                        return Err(LlmMetadataError::Serialization(format!(
                            "`{label}` chain exceeds max {MAX_PROVENANCE_CHAIN_ENTRIES} entries"
                        )));
                    }
                    chain.extend(arr.iter().cloned());
                }
            }
            category_obj.insert("chain".to_owned(), Json::Array(chain));
        } else if label == Category::Manifest.label() {
            if let Some(Json::Object(manifest)) =
                entries.first().and_then(|e: &Json| e.get("value"))
            {
                for (k, v) in manifest {
                    category_obj.insert(k.clone(), v.clone());
                }
            }
        } else if label == Category::DecryptionKeys.label() {
            let mut authorized: bool = false;
            let mut inner_entries: Vec<Json> = Vec::new();
            for envelope in &entries {
                if let Some(v) = envelope.get("value")
                    && let Some(a) = v.get("authorized").and_then(Json::as_bool)
                {
                    authorized = authorized || a;
                    if !a {
                        continue;
                    }
                    if let Some(arr) = v.get("entries").and_then(Json::as_array) {
                        if inner_entries.len().saturating_add(arr.len())
                            > MAX_DECRYPTION_KEY_ENTRIES
                        {
                            return Err(LlmMetadataError::Serialization(format!(
                                "`{label}` entries exceed max {MAX_DECRYPTION_KEY_ENTRIES}"
                            )));
                        }
                        for item in arr {
                            let mut wrapped: Map<String, Json> = Map::new();
                            wrapped.insert(
                                "pass".to_owned(),
                                required_envelope_field(envelope, "pass", &label)?,
                            );
                            wrapped.insert(
                                "pass_version".to_owned(),
                                required_envelope_field(envelope, "pass_version", &label)?,
                            );
                            wrapped.insert("applicable".to_owned(), Json::Bool(true));
                            wrapped.insert("reason".to_owned(), Json::Null);
                            wrapped.insert("value".to_owned(), item.clone());
                            inner_entries.push(Json::Object(wrapped));
                        }
                    }
                }
            }
            category_obj.insert("authorized".to_owned(), Json::Bool(authorized));
            category_obj.insert("entries".to_owned(), Json::Array(inner_entries));
        } else {
            category_obj.insert("entries".to_owned(), Json::Array(entries));
        }
        out.insert(label, Json::Object(category_obj));
    }
    Ok(out)
}

fn tool_descriptor_json(tool: &ToolDescriptor) -> Json {
    let mut obj: Map<String, Json> = Map::new();
    obj.insert("name".to_owned(), Json::String(tool.name.clone()));
    obj.insert("version".to_owned(), Json::String(tool.version.clone()));
    insert_optional_string(&mut obj, "git_commit", tool.git_commit.as_deref());
    insert_optional_string(&mut obj, "build_profile", tool.build_profile.as_deref());
    Json::Object(obj)
}

fn input_descriptor_json(input: &InputDescriptor) -> Json {
    let mut obj: Map<String, Json> = Map::new();
    obj.insert("path".to_owned(), Json::String(input.path.clone()));
    obj.insert(
        "size_bytes".to_owned(),
        Json::Number(serde_json::Number::from(input.size_bytes)),
    );
    obj.insert(
        "hash_blake3".to_owned(),
        Json::String(input.hash_blake3.clone()),
    );
    insert_optional_string(
        &mut obj,
        "magic_bytes_hex",
        input.magic_bytes_hex.as_deref(),
    );
    if !input.detected_formats.is_empty() {
        let detected_formats: Vec<Json> = input
            .detected_formats
            .iter()
            .map(|format: &String| Json::String(format.to_owned()))
            .collect();
        obj.insert("detected_formats".to_owned(), Json::Array(detected_formats));
    }
    Json::Object(obj)
}

fn selection_json(selection: &MetadataSelection) -> Json {
    let mut obj: Map<String, Json> = Map::new();
    let pack: Json = selection
        .pack
        .map_or(Json::Null, |pack| Json::String(pack.label().to_owned()));
    obj.insert("pack".to_owned(), pack);
    obj.insert(
        "categories".to_owned(),
        category_set_json(&selection.categories),
    );
    obj.insert(
        "excluded".to_owned(),
        category_set_json(&selection.excluded),
    );
    obj.insert(
        "format".to_owned(),
        Json::String(selection.format.label().to_owned()),
    );
    obj.insert(
        "authorized_decryption_keys".to_owned(),
        Json::Bool(selection.authorized_decryption_keys),
    );
    Json::Object(obj)
}

fn category_set_json(categories: &BTreeSet<Category>) -> Json {
    let values: Vec<Json> = categories
        .iter()
        .map(|category: &Category| Json::String(category.label().to_owned()))
        .collect();
    Json::Array(values)
}

fn pipeline_step_json(step: &PipelineStep) -> Result<Json, LlmMetadataError> {
    let mut obj: Map<String, Json> = Map::new();
    obj.insert("pass".to_owned(), Json::String(step.pass.clone()));
    obj.insert("version".to_owned(), Json::String(step.version.clone()));
    obj.insert("rung_in".to_owned(), Json::String(step.rung_in.clone()));
    obj.insert("rung_out".to_owned(), Json::String(step.rung_out.clone()));
    obj.insert(
        "duration_ms".to_owned(),
        duration_json(step.duration_ms, &step.pass)?,
    );
    insert_optional_string(
        &mut obj,
        "input_hash_blake3",
        step.input_hash_blake3.as_deref(),
    );
    insert_optional_string(
        &mut obj,
        "output_hash_blake3",
        step.output_hash_blake3.as_deref(),
    );
    insert_string_vec(
        &mut obj,
        "capabilities_required",
        &step.capabilities_required,
    );
    insert_string_vec(
        &mut obj,
        "capabilities_produced",
        &step.capabilities_produced,
    );
    if let Some(config) = &step.config {
        let Json::Object(config_obj) = config else {
            return Err(LlmMetadataError::Serialization(format!(
                "pipeline step `{}` has non-object config",
                step.pass
            )));
        };
        obj.insert("config".to_owned(), Json::Object(config_obj.clone()));
    }
    Ok(Json::Object(obj))
}

fn duration_json(duration_ms: f64, pass: &str) -> Result<Json, LlmMetadataError> {
    if !duration_ms.is_finite() || duration_ms.is_sign_negative() {
        return Err(LlmMetadataError::Serialization(format!(
            "pipeline step `{pass}` has invalid duration_ms"
        )));
    }
    let Some(number): Option<serde_json::Number> = serde_json::Number::from_f64(duration_ms) else {
        return Err(LlmMetadataError::Serialization(format!(
            "pipeline step `{pass}` has invalid duration_ms"
        )));
    };
    Ok(Json::Number(number))
}

fn required_envelope_field(
    envelope: &Json,
    field: &str,
    category: &str,
) -> Result<Json, LlmMetadataError> {
    envelope.get(field).cloned().ok_or_else(|| {
        LlmMetadataError::Serialization(format!(
            "`{category}` decryption key envelope missing `{field}`"
        ))
    })
}

fn insert_optional_string(obj: &mut Map<String, Json>, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        obj.insert(key.to_owned(), Json::String(value.to_owned()));
    }
}

fn insert_string_vec(obj: &mut Map<String, Json>, key: &str, values: &[String]) {
    if !values.is_empty() {
        let json_values: Vec<Json> = values
            .iter()
            .map(|value: &String| Json::String(value.to_owned()))
            .collect();
        obj.insert(key.to_owned(), Json::Array(json_values));
    }
}

fn envelope_json(envelope: &PerPassEnvelope) -> Json {
    let mut obj: Map<String, Json> = Map::new();
    let reason: Json = envelope
        .reason
        .as_ref()
        .map_or(Json::Null, |reason: &String| Json::String(reason.clone()));
    let value: Json = envelope.value.as_ref().map_or(Json::Null, Clone::clone);
    obj.insert("pass".to_owned(), Json::String(envelope.pass.clone()));
    obj.insert(
        "pass_version".to_owned(),
        Json::String(envelope.pass_version.clone()),
    );
    obj.insert("applicable".to_owned(), Json::Bool(envelope.applicable));
    obj.insert("reason".to_owned(), reason);
    obj.insert("value".to_owned(), value);
    Json::Object(obj)
}

pub fn serialize(bundle: &Json, fmt: MetadataFormat) -> Result<Vec<u8>, LlmMetadataError> {
    match fmt {
        MetadataFormat::Json => serde_json::to_vec_pretty(bundle)
            .map_err(|e: serde_json::Error| LlmMetadataError::Serialization(e.to_string())),
        MetadataFormat::Jsonl => serialize_jsonl(bundle),
        MetadataFormat::Cbor => {
            let mut buf: Vec<u8> = Vec::new();
            ciborium::into_writer(bundle, &mut buf).map_err(
                |e: ciborium::ser::Error<std::io::Error>| {
                    LlmMetadataError::Serialization(e.to_string())
                },
            )?;
            Ok(buf)
        }
        MetadataFormat::Msgpack => rmp_serde::to_vec_named(bundle)
            .map_err(|e: rmp_serde::encode::Error| LlmMetadataError::Serialization(e.to_string())),
    }
}

fn serialize_jsonl(bundle: &Json) -> Result<Vec<u8>, LlmMetadataError> {
    let mut out: Vec<u8> = Vec::new();
    let Some(obj): Option<&Map<String, Json>> = bundle.as_object() else {
        return serde_json::to_vec(bundle)
            .map_err(|e: serde_json::Error| LlmMetadataError::Serialization(e.to_string()));
    };
    for (k, v) in obj {
        if k == "categories" {
            let Some(cats): Option<&Map<String, Json>> = v.as_object() else {
                return Err(LlmMetadataError::Serialization(
                    "jsonl bundle `categories` field is not an object".to_owned(),
                ));
            };
            for (cat_label, cat_value) in cats {
                let line: Json = serde_json::json!({
                    "record": "category",
                    "category": cat_label,
                    "value": cat_value,
                });
                push_line(&mut out, &line)?;
            }
        } else if k == "pipeline" {
            let Some(arr): Option<&Vec<Json>> = v.as_array() else {
                return Err(LlmMetadataError::Serialization(
                    "jsonl bundle `pipeline` field is not an array".to_owned(),
                ));
            };
            for step in arr {
                let line: Json = serde_json::json!({
                    "record": "pipeline_step",
                    "value": step,
                });
                push_line(&mut out, &line)?;
            }
        } else {
            let line: Json = serde_json::json!({
                "record": k,
                "value": v,
            });
            push_line(&mut out, &line)?;
        }
    }
    Ok(out)
}

fn push_line(out: &mut Vec<u8>, value: &Json) -> Result<(), LlmMetadataError> {
    let bytes: Vec<u8> = serde_json::to_vec(value)
        .map_err(|e: serde_json::Error| LlmMetadataError::Serialization(e.to_string()))?;
    out.extend_from_slice(&bytes);
    out.push(b'\n');
    Ok(())
}

pub fn write_bundle_to_path(path: &Path, bytes: &[u8]) -> Result<(), LlmMetadataError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|e: std::io::Error| LlmMetadataError::Serialization(e.to_string()))?;
    }
    std::fs::write(path, bytes)
        .map_err(|e: std::io::Error| LlmMetadataError::Serialization(e.to_string()))?;
    Ok(())
}

pub fn write_briefs_to_dir(
    dir: &Path,
    bundle: &Json,
) -> Result<(std::path::PathBuf, std::path::PathBuf), LlmMetadataError> {
    std::fs::create_dir_all(dir)
        .map_err(|e: std::io::Error| LlmMetadataError::Serialization(e.to_string()))?;
    let agents_md: String = crate::markdown::render_agents_md(bundle);
    let skill_md: String = crate::markdown::render_skill_md(bundle);
    let agents_path: std::path::PathBuf = dir.join("AGENTS.md");
    let skill_path: std::path::PathBuf = dir.join("SKILL.md");
    std::fs::write(&agents_path, agents_md.as_bytes())
        .map_err(|e: std::io::Error| LlmMetadataError::Serialization(e.to_string()))?;
    std::fs::write(&skill_path, skill_md.as_bytes())
        .map_err(|e: std::io::Error| LlmMetadataError::Serialization(e.to_string()))?;
    Ok((agents_path, skill_path))
}

#[must_use]
pub fn envelope_map(entries: BTreeMap<&'static str, PerPassEnvelope>) -> Json {
    let mut obj: Map<String, Json> = Map::new();
    for (label, envelope) in entries {
        obj.insert(label.to_owned(), envelope_json(&envelope));
    }
    Json::Object(obj)
}
