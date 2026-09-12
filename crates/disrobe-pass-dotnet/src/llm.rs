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

const PASS: &str = "disrobe-pass-dotnet";

pub const METADATA_CAPABILITY: MetadataCapability = MetadataCapability::new(
    PASS,
    VERSION,
    &[
        Category::Ast,
        Category::Disasm,
        Category::Symbols,
        Category::Strings,
        Category::Imports,
        Category::Types,
        Category::Signatures,
        Category::Provenance,
        Category::Manifest,
    ],
);

#[derive(Debug, Clone, Default)]
pub struct DotnetLlmInput {
    pub dialect: String,
    pub source: String,
    pub assembly_name: String,
    pub types: Vec<String>,
    pub methods: Vec<String>,
    pub strings: Vec<String>,
    pub imports: Vec<String>,
    pub instructions: Vec<DotnetInstr>,
    pub input_path: String,
    pub input_size_bytes: u64,
    pub input_hash_blake3: String,
    pub duration_ms: f64,
}

#[derive(Debug, Clone)]
pub struct DotnetInstr {
    pub pc: u64,
    pub mnemonic: String,
    pub operands: Vec<String>,
}

impl LlmMetadataEmitter for DotnetLlmInput {
    fn metadata_capability(&self) -> MetadataCapability {
        METADATA_CAPABILITY
    }

    fn emit_ast(&self) -> Option<Json> {
        let mut attrs: BTreeMap<String, Json> = BTreeMap::new();
        attrs.insert("source".to_owned(), Json::String(self.source.clone()));
        let root: Json = shape::make_ast_node(
            "Assembly",
            Some(self.assembly_name.clone()),
            Vec::new(),
            attrs,
        );
        Some(shape::make_ast_value(&self.dialect, root))
    }

    fn emit_disasm(&self) -> Option<Json> {
        let instructions: Vec<Json> = self
            .instructions
            .iter()
            .map(|i: &DotnetInstr| {
                shape::make_disasm_instr(i.pc, None, &i.mnemonic, i.operands.clone(), None)
            })
            .collect();
        Some(shape::make_disasm_value(
            "cil.ecma-335",
            instructions,
            Vec::new(),
        ))
    }

    fn emit_symbols(&self) -> Option<Json> {
        let mut entries: Vec<Json> = Vec::new();
        for m in &self.methods {
            entries.push(shape::make_symbol_entry(
                m,
                None,
                "method",
                None,
                Some(self.assembly_name.clone()),
                "public",
            ));
        }
        for t in &self.types {
            entries.push(shape::make_symbol_entry(
                t,
                None,
                "type",
                None,
                Some(self.assembly_name.clone()),
                "public",
            ));
        }
        Some(shape::make_symbols_value(entries))
    }

    fn emit_strings(&self) -> Option<Json> {
        let entries: Vec<Json> = self
            .strings
            .iter()
            .map(|s: &String| shape::make_string_entry(s, "utf-16-le", None, Vec::new()))
            .collect();
        Some(shape::make_strings_value(entries))
    }

    fn emit_imports(&self) -> Option<Json> {
        let entries: Vec<Json> = self
            .imports
            .iter()
            .map(|i: &String| shape::make_import_entry(i, Vec::new(), None, "library", None))
            .collect();
        Some(shape::make_imports_value(entries))
    }

    fn emit_types(&self) -> Option<Json> {
        let named_types: Vec<Json> = self
            .types
            .iter()
            .map(|t: &String| {
                serde_json::json!({
                    "name": t,
                    "shape": "ecma335.type",
                })
            })
            .collect();
        Some(serde_json::json!({
            "named_types": named_types,
        }))
    }

    fn emit_signatures(&self) -> Option<Json> {
        let entries: Vec<Json> = self
            .methods
            .iter()
            .map(|m: &String| {
                shape::make_signature_entry(m, None, Vec::new(), Vec::new(), Vec::new())
            })
            .collect();
        Some(shape::make_signatures_value(entries))
    }

    fn emit_provenance(&self) -> Option<Json> {
        let mut kv: BTreeMap<String, String> = BTreeMap::new();
        kv.insert("dialect".to_owned(), self.dialect.clone());
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
            Some("application/x-msdownload".to_owned()),
            Vec::new(),
            Vec::new(),
        ))
    }
}
