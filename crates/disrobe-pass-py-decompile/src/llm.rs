#![cfg(feature = "llm-metadata")]
#![allow(
    clippy::doc_markdown,
    clippy::too_long_first_doc_paragraph,
    clippy::vec_init_then_push,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::needless_pass_by_value
)]

use std::collections::BTreeMap;

use disrobe_llm_metadata::{Category, LlmMetadataEmitter, MetadataCapability, shape};
use serde_json::{Map, Value as Json, json};

use crate::VERSION;

const PASS: &str = "disrobe-pass-py-decompile";

fn published_roundtrip_status(label: &str) -> &'static str {
    match label {
        "perfect" | "semantic" | "pass" => "pass",
        "code-diff" | "partial" => "partial",
        "recompile-failed" | "fail" => "fail",
        _ => "skipped",
    }
}

pub const METADATA_CAPABILITY: MetadataCapability = MetadataCapability::new(
    PASS,
    VERSION,
    &[
        Category::Ast,
        Category::Disasm,
        Category::Symbols,
        Category::Strings,
        Category::Imports,
        Category::Constants,
        Category::Signatures,
        Category::Provenance,
        Category::RoundtripVerdict,
        Category::SourceMap,
        Category::Manifest,
    ],
);

#[derive(Debug, Clone)]
pub struct PyDecompileLlmInput {
    pub module_path: String,
    pub python_version: String,
    pub final_source: String,
    pub backend: String,
    pub disasm: Vec<DisasmIns>,
    pub names: Vec<String>,
    pub varnames: Vec<String>,
    pub consts: Vec<String>,
    pub input_size_bytes: u64,
    pub input_hash_blake3: String,
    pub roundtrip_status: Option<String>,
    pub duration_ms: f64,
}

#[derive(Debug, Clone)]
pub struct DisasmIns {
    pub offset: u64,
    pub opname: String,
    pub arg: Option<u32>,
    pub argrepr: Option<String>,
    pub line: Option<u32>,
}

impl PyDecompileLlmInput {
    fn provenance_chain(&self) -> Json {
        let step: Json = shape::make_pipeline_step(
            PASS,
            VERSION,
            "disasm",
            "surface",
            self.duration_ms,
            BTreeMap::new(),
        );
        shape::make_provenance_value(vec![step], BTreeMap::new())
    }
}

impl LlmMetadataEmitter for PyDecompileLlmInput {
    fn metadata_capability(&self) -> MetadataCapability {
        METADATA_CAPABILITY
    }

    fn emit_ast(&self) -> Option<Json> {
        let mut attrs: BTreeMap<String, Json> = BTreeMap::new();
        attrs.insert("source".to_owned(), Json::String(self.final_source.clone()));
        attrs.insert("backend".to_owned(), Json::String(self.backend.clone()));
        let root: Json = shape::make_ast_node("Module", None, Vec::new(), attrs);
        Some(shape::make_ast_value(
            format!("python.{}", self.python_version),
            root,
        ))
    }

    fn emit_disasm(&self) -> Option<Json> {
        let instructions: Vec<Json> = self
            .disasm
            .iter()
            .map(|i: &DisasmIns| {
                let mut operands: Vec<String> = Vec::new();
                if let Some(a) = i.arg {
                    operands.push(a.to_string());
                }
                shape::make_disasm_instr(i.offset, None, &i.opname, operands, i.argrepr.clone())
            })
            .collect();
        Some(shape::make_disasm_value(
            format!("python.{}", self.python_version),
            instructions,
            Vec::new(),
        ))
    }

    fn emit_symbols(&self) -> Option<Json> {
        let mut entries: Vec<Json> = Vec::new();
        for n in &self.names {
            entries.push(shape::make_symbol_entry(
                n, None, "label", None, None, "unknown",
            ));
        }
        for v in &self.varnames {
            entries.push(shape::make_symbol_entry(
                v, None, "variable", None, None, "unknown",
            ));
        }
        Some(shape::make_symbols_value(entries))
    }

    fn emit_strings(&self) -> Option<Json> {
        let mut entries: Vec<Json> = Vec::new();
        for (idx, c) in self.consts.iter().enumerate() {
            if c.starts_with('"') || c.starts_with('\'') {
                entries.push(shape::make_string_entry(
                    c.trim_matches(|ch: char| ch == '"' || ch == '\''),
                    "utf-8",
                    Some(idx as u64),
                    Vec::new(),
                ));
            }
        }
        Some(shape::make_strings_value(entries))
    }

    fn emit_imports(&self) -> Option<Json> {
        let mut entries: Vec<Json> = Vec::new();
        for line in self.final_source.lines() {
            let trimmed: &str = line.trim_start();
            if let Some(rest) = trimmed.strip_prefix("import ") {
                let module_name: &str = rest.split_whitespace().next().unwrap_or("");
                if !module_name.is_empty() {
                    entries.push(shape::make_import_entry(
                        module_name,
                        Vec::new(),
                        None,
                        "module",
                        None,
                    ));
                }
            } else if let Some(rest) = trimmed.strip_prefix("from ") {
                let mut parts: std::str::SplitWhitespace<'_> = rest.split_whitespace();
                let module_name: &str = parts.next().unwrap_or("");
                let _: Option<&str> = parts.next();
                let symbols: Vec<String> = parts
                    .map(|p: &str| p.trim_matches(',').to_owned())
                    .filter(|s: &String| !s.is_empty())
                    .collect();
                if !module_name.is_empty() {
                    entries.push(shape::make_import_entry(
                        module_name,
                        symbols,
                        None,
                        "module",
                        None,
                    ));
                }
            }
        }
        Some(shape::make_imports_value(entries))
    }

    fn emit_constants(&self) -> Option<Json> {
        let entries: Vec<Json> = self
            .consts
            .iter()
            .enumerate()
            .map(|(idx, c): (usize, &String)| {
                shape::make_constant_entry(idx as u64, "pyc_const", json!(c), Vec::new())
            })
            .collect();
        Some(shape::make_constants_value(entries))
    }

    fn emit_signatures(&self) -> Option<Json> {
        let mut entries: Vec<Json> = Vec::new();
        for line in self.final_source.lines() {
            let trimmed: &str = line.trim_start();
            if let Some(rest) = trimmed.strip_prefix("def ") {
                let name_end: usize = rest.find('(').unwrap_or(rest.len());
                let name: &str = &rest[..name_end];
                entries.push(shape::make_signature_entry(
                    name,
                    None,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ));
            } else if let Some(rest) = trimmed.strip_prefix("async def ") {
                let name_end: usize = rest.find('(').unwrap_or(rest.len());
                let name: &str = &rest[..name_end];
                let attrs: Vec<String> = vec!["async".to_owned()];
                entries.push(shape::make_signature_entry(
                    name,
                    None,
                    Vec::new(),
                    Vec::new(),
                    attrs,
                ));
            }
        }
        Some(shape::make_signatures_value(entries))
    }

    fn emit_provenance(&self) -> Option<Json> {
        Some(self.provenance_chain())
    }

    fn emit_roundtrip_verdict(&self) -> Option<Json> {
        let label: &str = self.roundtrip_status.as_deref().unwrap_or("skipped");
        let status: &str = published_roundtrip_status(label);
        let stage: Json = shape::make_roundtrip_stage(
            "py-decompile",
            status == "pass",
            Some(format!("backend={}, roundtrip={label}", self.backend)),
        );
        Some(shape::make_roundtrip_value(status, vec![stage], None))
    }

    fn emit_source_map(&self) -> Option<Json> {
        let mut obj: Map<String, Json> = Map::new();
        obj.insert(
            "format".to_owned(),
            Json::String("disrobe-linemap-v1".to_owned()),
        );
        obj.insert("mappings".to_owned(), Json::Array(Vec::new()));
        Some(Json::Object(obj))
    }

    fn emit_manifest(&self) -> Option<Json> {
        Some(shape::make_manifest_value(
            &self.module_path,
            self.input_size_bytes,
            &self.input_hash_blake3,
            None,
            Some("application/x-python-bytecode".to_owned()),
            Vec::new(),
            Vec::new(),
        ))
    }
}
