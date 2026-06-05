//! Top-level `LlmBundle` writer.
#![allow(clippy::needless_pass_by_value, clippy::too_long_first_doc_paragraph)]

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json};

use crate::category::Category;
use crate::envelope::PerPassEnvelope;
use crate::error::LlmMetadataError;
use crate::selection::{MetadataFormat, MetadataSelection};
use crate::{SCHEMA, SCHEMA_VERSION, VERSION};

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

/// Aggregator over per-pass `emit_metadata` outputs.
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

    /// Build the final bundle JSON value, aligned with `disrobe.metadata.llm.v1`.
    #[must_use]
    pub fn finalize(
        self,
        generated_at: String,
        tool: ToolDescriptor,
        selection: &MetadataSelection,
        input: InputDescriptor,
    ) -> Json {
        let categories: Map<String, Json> = build_categories(&self.per_pass);
        let pipeline: Vec<Json> = self
            .steps
            .iter()
            .map(|s: &PipelineStep| serde_json::to_value(s).unwrap_or(Json::Null))
            .collect();

        let mut top: Map<String, Json> = Map::new();
        top.insert("schema".to_owned(), Json::String(SCHEMA.to_owned()));
        top.insert(
            "schema_version".to_owned(),
            Json::String(SCHEMA_VERSION.to_owned()),
        );
        top.insert("generated_at".to_owned(), Json::String(generated_at));
        top.insert(
            "tool".to_owned(),
            serde_json::to_value(&tool).unwrap_or(Json::Null),
        );
        top.insert(
            "selection".to_owned(),
            serde_json::to_value(selection).unwrap_or(Json::Null),
        );
        top.insert(
            "input".to_owned(),
            serde_json::to_value(&input).unwrap_or(Json::Null),
        );
        top.insert("pipeline".to_owned(), Json::Array(pipeline));
        top.insert("categories".to_owned(), Json::Object(categories));
        Json::Object(top)
    }
}

fn build_categories(per_pass: &[Json]) -> Map<String, Json> {
    let mut grouped: BTreeMap<String, Vec<Json>> = BTreeMap::new();
    for envelope_map in per_pass {
        let Some(obj): Option<&Map<String, Json>> = envelope_map.as_object() else {
            continue;
        };
        for (cat_label, envelope) in obj {
            grouped
                .entry(cat_label.clone())
                .or_default()
                .push(envelope.clone());
        }
    }
    let mut out: Map<String, Json> = Map::new();
    for (label, entries) in grouped {
        let mut category_obj: Map<String, Json> = Map::new();
        if label == Category::Provenance.label() {
            let chain: Vec<Json> = entries
                .iter()
                .filter_map(|envelope: &Json| {
                    envelope
                        .get("value")
                        .and_then(|v: &Json| v.get("chain"))
                        .and_then(Json::as_array)
                        .cloned()
                })
                .flatten()
                .collect();
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
                    if let Some(arr) = v.get("entries").and_then(Json::as_array) {
                        for item in arr {
                            let mut wrapped: Map<String, Json> = Map::new();
                            wrapped.insert(
                                "pass".to_owned(),
                                envelope.get("pass").cloned().unwrap_or(Json::Null),
                            );
                            wrapped.insert(
                                "pass_version".to_owned(),
                                envelope.get("pass_version").cloned().unwrap_or(Json::Null),
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
    out
}

/// Serialize a bundle JSON value into the requested wire format.
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
            if let Some(cats) = v.as_object() {
                for (cat_label, cat_value) in cats {
                    let line: Json = serde_json::json!({
                        "record": "category",
                        "category": cat_label,
                        "value": cat_value,
                    });
                    push_line(&mut out, &line)?;
                }
            }
        } else if k == "pipeline" {
            if let Some(arr) = v.as_array() {
                for step in arr {
                    let line: Json = serde_json::json!({
                        "record": "pipeline_step",
                        "value": step,
                    });
                    push_line(&mut out, &line)?;
                }
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

/// Write the serialized bundle to `path`. Creates parent dirs as needed.
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

/// Render and write `AGENTS.md` + `SKILL.md` into `dir`, returning their paths.
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

/// Convert a single envelope map to a JSON value for `record_pass`.
#[must_use]
pub fn envelope_map(entries: BTreeMap<&'static str, PerPassEnvelope>) -> Json {
    let mut obj: Map<String, Json> = Map::new();
    for (label, envelope) in entries {
        obj.insert(
            label.to_owned(),
            serde_json::to_value(&envelope).unwrap_or(Json::Null),
        );
    }
    Json::Object(obj)
}
