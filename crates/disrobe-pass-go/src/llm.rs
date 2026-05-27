//! `LlmMetadataEmitter` impl for the Go pass.

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

const PASS: &str = "disrobe-pass-go";

pub const METADATA_CAPABILITY: MetadataCapability = MetadataCapability::new(
    PASS,
    VERSION,
    &[
        Category::Symbols,
        Category::Strings,
        Category::Imports,
        Category::Provenance,
        Category::Manifest,
        Category::Confidence,
    ],
);

#[derive(Debug, Clone, Default)]
pub struct GoLlmInput {
    pub image_kind: String,
    pub buildversion: Option<String>,
    pub pclntab_version: String,
    pub packages: Vec<String>,
    pub functions: Vec<GoLlmFn>,
    pub strings: Vec<String>,
    pub garble_confidence: f64,
    pub input_path: String,
    pub input_size_bytes: u64,
    pub input_hash_blake3: String,
    pub duration_ms: f64,
}

#[derive(Debug, Clone)]
pub struct GoLlmFn {
    pub name: String,
    pub address: u64,
    pub package: String,
}

impl LlmMetadataEmitter for GoLlmInput {
    fn metadata_capability(&self) -> MetadataCapability {
        METADATA_CAPABILITY
    }

    fn emit_symbols(&self) -> Option<Json> {
        let entries: Vec<Json> = self
            .functions
            .iter()
            .map(|f: &GoLlmFn| {
                shape::make_symbol_entry(
                    &f.name,
                    None,
                    "function",
                    Some(f.address),
                    Some(f.package.clone()),
                    "public",
                )
            })
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

    fn emit_imports(&self) -> Option<Json> {
        let entries: Vec<Json> = self
            .packages
            .iter()
            .map(|p: &String| shape::make_import_entry(p, Vec::new(), None, "module", None))
            .collect();
        Some(shape::make_imports_value(entries))
    }

    fn emit_provenance(&self) -> Option<Json> {
        let mut kv: BTreeMap<String, String> = BTreeMap::new();
        kv.insert("image_kind".to_owned(), self.image_kind.clone());
        kv.insert(
            "buildversion".to_owned(),
            self.buildversion
                .clone()
                .unwrap_or_else(|| "unknown".to_owned()),
        );
        kv.insert("pclntab_version".to_owned(), self.pclntab_version.clone());
        let step: Json = shape::make_pipeline_step(
            PASS,
            VERSION,
            "raw",
            "surface",
            self.duration_ms,
            BTreeMap::new(),
        );
        Some(shape::make_provenance_value(vec![step], kv))
    }

    fn emit_manifest(&self) -> Option<Json> {
        Some(shape::make_manifest_value(
            &self.input_path,
            self.input_size_bytes,
            &self.input_hash_blake3,
            None,
            Some("application/octet-stream".to_owned()),
            Vec::new(),
            Vec::new(),
        ))
    }

    fn emit_confidence(&self) -> Option<Json> {
        let entry: Json = shape::make_confidence_entry(
            "garble.obfuscated",
            self.garble_confidence,
            vec![format!("pclntab={}", self.pclntab_version)],
        );
        Some(shape::make_confidence_value(vec![entry]))
    }
}
