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

const PASS: &str = "disrobe-pass-wasm-deob";

pub const METADATA_CAPABILITY: MetadataCapability = MetadataCapability::new(
    PASS,
    VERSION,
    &[
        Category::Disasm,
        Category::Symbols,
        Category::Strings,
        Category::Imports,
        Category::Signatures,
        Category::Provenance,
        Category::Manifest,
        Category::Types,
    ],
);

#[derive(Debug, Clone, Default)]
pub struct WasmLlmInput {
    pub functions: Vec<WasmFn>,
    pub imports: Vec<WasmImport>,
    pub strings: Vec<String>,
    pub types: Vec<String>,
    pub input_path: String,
    pub input_size_bytes: u64,
    pub input_hash_blake3: String,
    pub duration_ms: f64,
}

#[derive(Debug, Clone)]
pub struct WasmFn {
    pub name: String,
    pub signature: String,
    pub pc: u64,
}

#[derive(Debug, Clone)]
pub struct WasmImport {
    pub module: String,
    pub name: String,
}

impl LlmMetadataEmitter for WasmLlmInput {
    fn metadata_capability(&self) -> MetadataCapability {
        METADATA_CAPABILITY
    }

    fn emit_disasm(&self) -> Option<Json> {
        let instructions: Vec<Json> = self
            .functions
            .iter()
            .map(|f: &WasmFn| {
                shape::make_disasm_instr(f.pc, None, "call", vec![f.name.clone()], None)
            })
            .collect();
        Some(shape::make_disasm_value(
            "wasm.mvp",
            instructions,
            Vec::new(),
        ))
    }

    fn emit_symbols(&self) -> Option<Json> {
        let entries: Vec<Json> = self
            .functions
            .iter()
            .map(|f: &WasmFn| {
                shape::make_symbol_entry(&f.name, None, "function", Some(f.pc), None, "public")
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
        let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for i in &self.imports {
            grouped
                .entry(i.module.clone())
                .or_default()
                .push(i.name.clone());
        }
        let entries: Vec<Json> = grouped
            .into_iter()
            .map(|(module, symbols): (String, Vec<String>)| {
                shape::make_import_entry(module, symbols, None, "module", None)
            })
            .collect();
        Some(shape::make_imports_value(entries))
    }

    fn emit_signatures(&self) -> Option<Json> {
        let entries: Vec<Json> = self
            .functions
            .iter()
            .map(|f: &WasmFn| {
                shape::make_signature_entry(
                    &f.name,
                    Some(f.signature.clone()),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                )
            })
            .collect();
        Some(shape::make_signatures_value(entries))
    }

    fn emit_types(&self) -> Option<Json> {
        let named_types: Vec<Json> = self
            .types
            .iter()
            .map(|t: &String| {
                serde_json::json!({
                    "name": t,
                    "shape": "wasm.functype",
                })
            })
            .collect();
        Some(serde_json::json!({
            "named_types": named_types,
        }))
    }

    fn emit_provenance(&self) -> Option<Json> {
        let step: Json = shape::make_pipeline_step(
            PASS,
            VERSION,
            "raw",
            "surface",
            self.duration_ms,
            BTreeMap::new(),
        );
        Some(shape::make_provenance_value(vec![step], BTreeMap::new()))
    }

    fn emit_manifest(&self) -> Option<Json> {
        Some(shape::make_manifest_value(
            &self.input_path,
            self.input_size_bytes,
            &self.input_hash_blake3,
            Some("0061736d".to_owned()),
            Some("application/wasm".to_owned()),
            Vec::new(),
            Vec::new(),
        ))
    }
}
