//! `LlmMetadataEmitter` impl for the JVM/Android pass.

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
use serde_json::{Value as Json, json};

use crate::VERSION;

const PASS: &str = "disrobe-pass-jvm";

pub const METADATA_CAPABILITY: MetadataCapability = MetadataCapability::new(
    PASS,
    VERSION,
    &[
        Category::Ast,
        Category::Disasm,
        Category::Symbols,
        Category::Strings,
        Category::Imports,
        Category::Signatures,
        Category::Provenance,
        Category::Manifest,
    ],
);

#[derive(Debug, Clone, Default)]
pub struct JvmLlmInput {
    pub dialect: String,
    pub source: String,
    pub class_name: String,
    pub methods: Vec<String>,
    pub fields: Vec<String>,
    pub strings: Vec<String>,
    pub imports: Vec<String>,
    pub instructions: Vec<JvmInstr>,
    pub input_path: String,
    pub input_size_bytes: u64,
    pub input_hash_blake3: String,
    pub duration_ms: f64,
}

#[derive(Debug, Clone)]
pub struct JvmInstr {
    pub pc: u64,
    pub mnemonic: String,
    pub operands: Vec<String>,
}

impl LlmMetadataEmitter for JvmLlmInput {
    fn metadata_capability(&self) -> MetadataCapability {
        METADATA_CAPABILITY
    }

    fn emit_ast(&self) -> Option<Json> {
        let mut attrs: BTreeMap<String, Json> = BTreeMap::new();
        attrs.insert("source".to_owned(), Json::String(self.source.clone()));
        let root: Json = shape::make_ast_node(
            "ClassFile",
            Some(self.class_name.clone()),
            Vec::new(),
            attrs,
        );
        Some(shape::make_ast_value(&self.dialect, root))
    }

    fn emit_disasm(&self) -> Option<Json> {
        let instructions: Vec<Json> = self
            .instructions
            .iter()
            .map(|i: &JvmInstr| {
                shape::make_disasm_instr(i.pc, None, &i.mnemonic, i.operands.clone(), None)
            })
            .collect();
        Some(shape::make_disasm_value(
            "jvm.bytecode",
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
                Some(self.class_name.clone()),
                "public",
            ));
        }
        for f in &self.fields {
            entries.push(shape::make_symbol_entry(
                f,
                None,
                "variable",
                None,
                Some(self.class_name.clone()),
                "public",
            ));
        }
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
            .imports
            .iter()
            .map(|i: &String| shape::make_import_entry(i, Vec::new(), None, "module", None))
            .collect();
        Some(shape::make_imports_value(entries))
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
            Some("application/java-archive".to_owned()),
            vec![shape::make_format_detection(
                &self.dialect,
                1.0_f64,
                Some("jvm-pass".to_owned()),
            )],
            Vec::new(),
        ))
    }
}

#[allow(dead_code)]
fn _unused_keep_json_import() -> Json {
    json!({})
}
