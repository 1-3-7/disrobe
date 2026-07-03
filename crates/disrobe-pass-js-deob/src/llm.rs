#![cfg(feature = "llm-metadata")]
#![allow(
    clippy::doc_markdown,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::needless_pass_by_value
)]

use std::collections::BTreeMap;

use disrobe_llm_metadata::{Category, LlmMetadataEmitter, MetadataCapability, shape};
use serde_json::Value as Json;

use crate::VERSION;

const PASS: &str = "disrobe-pass-js-deob";

pub const METADATA_CAPABILITY: MetadataCapability = MetadataCapability::new(
    PASS,
    VERSION,
    &[
        Category::Ast,
        Category::Symbols,
        Category::Strings,
        Category::Provenance,
        Category::Confidence,
        Category::Manifest,
    ],
);

#[derive(Debug, Clone, Default)]
pub struct JsLlmInput {
    pub final_source: String,
    pub dialect: String,
    pub obfuscator: String,
    pub confidence: f64,
    pub symbols: Vec<String>,
    pub strings: Vec<String>,
    pub input_path: String,
    pub input_size_bytes: u64,
    pub input_hash_blake3: String,
    pub duration_ms: f64,
}

impl LlmMetadataEmitter for JsLlmInput {
    fn metadata_capability(&self) -> MetadataCapability {
        METADATA_CAPABILITY
    }

    fn emit_ast(&self) -> Option<Json> {
        let mut attrs: BTreeMap<String, Json> = BTreeMap::new();
        attrs.insert("source".to_owned(), Json::String(self.final_source.clone()));
        let root: Json = shape::make_ast_node("Program", None, Vec::new(), attrs);
        Some(shape::make_ast_value(&self.dialect, root))
    }

    fn emit_symbols(&self) -> Option<Json> {
        let entries: Vec<Json> = self
            .symbols
            .iter()
            .map(|s: &String| shape::make_symbol_entry(s, None, "variable", None, None, "unknown"))
            .collect();
        Some(shape::make_symbols_value(entries))
    }

    fn emit_strings(&self) -> Option<Json> {
        let entries: Vec<Json> = self
            .strings
            .iter()
            .map(|s: &String| shape::make_string_entry(s, "utf-8", None, Vec::new()))
            .collect();
        Some(shape::make_strings_value(entries))
    }

    fn emit_provenance(&self) -> Option<Json> {
        let mut kv: BTreeMap<String, String> = BTreeMap::new();
        kv.insert("dialect".to_owned(), self.dialect.clone());
        kv.insert("obfuscator".to_owned(), self.obfuscator.clone());
        let step: Json = shape::make_pipeline_step(
            PASS,
            VERSION,
            "surface",
            "surface",
            self.duration_ms,
            BTreeMap::new(),
        );
        Some(shape::make_provenance_value(vec![step], kv))
    }

    fn emit_confidence(&self) -> Option<Json> {
        let entry: Json = shape::make_confidence_entry(
            format!("js.{}", self.obfuscator),
            self.confidence,
            Vec::new(),
        );
        Some(shape::make_confidence_value(vec![entry]))
    }

    fn emit_manifest(&self) -> Option<Json> {
        Some(shape::make_manifest_value(
            &self.input_path,
            self.input_size_bytes,
            &self.input_hash_blake3,
            None,
            Some("application/javascript".to_owned()),
            Vec::new(),
            Vec::new(),
        ))
    }
}
