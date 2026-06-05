//! `LlmMetadataEmitter` impl for the native (PE/ELF/Mach-O) pass.

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

const PASS: &str = "disrobe-pass-native";

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
    ],
);

#[derive(Debug, Clone, Default)]
pub struct NativeLlmInput {
    pub format_label: String,
    pub arch_label: String,
    pub symbols: Vec<NativeSymbol>,
    pub strings: Vec<String>,
    pub imports: Vec<NativeImport>,
    pub instructions: Vec<NativeInstr>,
    pub input_path: String,
    pub input_size_bytes: u64,
    pub input_hash_blake3: String,
    pub duration_ms: f64,
}

#[derive(Debug, Clone)]
pub struct NativeSymbol {
    pub mangled: String,
    pub demangled: Option<String>,
    pub kind: String,
    pub address: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct NativeImport {
    pub module: String,
    pub symbol: String,
}

#[derive(Debug, Clone)]
pub struct NativeInstr {
    pub pc: u64,
    pub bytes_hex: String,
    pub mnemonic: String,
    pub operands: Vec<String>,
}

impl LlmMetadataEmitter for NativeLlmInput {
    fn metadata_capability(&self) -> MetadataCapability {
        METADATA_CAPABILITY
    }

    fn emit_disasm(&self) -> Option<Json> {
        let instructions: Vec<Json> = self
            .instructions
            .iter()
            .map(|i: &NativeInstr| {
                shape::make_disasm_instr(
                    i.pc,
                    Some(i.bytes_hex.clone()),
                    &i.mnemonic,
                    i.operands.clone(),
                    None,
                )
            })
            .collect();
        Some(shape::make_disasm_value(
            format!("{}.{}", self.format_label, self.arch_label),
            instructions,
            Vec::new(),
        ))
    }

    fn emit_symbols(&self) -> Option<Json> {
        let entries: Vec<Json> = self
            .symbols
            .iter()
            .map(|s: &NativeSymbol| {
                shape::make_symbol_entry(
                    &s.mangled,
                    s.demangled.clone(),
                    &s.kind,
                    s.address,
                    None,
                    "unknown",
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
        let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for i in &self.imports {
            grouped
                .entry(i.module.clone())
                .or_default()
                .push(i.symbol.clone());
        }
        let entries: Vec<Json> = grouped
            .into_iter()
            .map(|(module, symbols): (String, Vec<String>)| {
                shape::make_import_entry(module, symbols, None, "library", None)
            })
            .collect();
        Some(shape::make_imports_value(entries))
    }

    fn emit_signatures(&self) -> Option<Json> {
        let entries: Vec<Json> = self
            .symbols
            .iter()
            .filter(|s: &&NativeSymbol| s.kind == "function")
            .map(|s: &NativeSymbol| {
                shape::make_signature_entry(
                    s.demangled.as_deref().unwrap_or(&s.mangled),
                    None,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                )
            })
            .collect();
        Some(shape::make_signatures_value(entries))
    }

    fn emit_provenance(&self) -> Option<Json> {
        let mut kv: BTreeMap<String, String> = BTreeMap::new();
        kv.insert("format".to_owned(), self.format_label.clone());
        kv.insert("arch".to_owned(), self.arch_label.clone());
        let step: Json = shape::make_pipeline_step(
            PASS,
            VERSION,
            "raw",
            "disasm",
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
            Some(format!("application/x-{}", self.format_label)),
            Vec::new(),
            Vec::new(),
        ))
    }
}
