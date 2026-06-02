//! `LlmMetadataEmitter` impl for the Python source-level deobfuscator pass.

#![cfg(feature = "llm-metadata")]
#![allow(
    clippy::doc_markdown,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::option_if_let_else,
    clippy::needless_pass_by_value
)]

use std::collections::BTreeMap;

use disrobe_llm_metadata::{Category, LlmMetadataEmitter, MetadataCapability, shape};
use serde_json::Value as Json;

use crate::{PeelResult, VERSION};

const PASS: &str = "disrobe-pass-py-deob";

pub const METADATA_CAPABILITY: MetadataCapability = MetadataCapability::new(
    PASS,
    VERSION,
    &[
        Category::Symbols,
        Category::Strings,
        Category::Provenance,
        Category::Confidence,
        Category::SourceMap,
    ],
);

#[derive(Debug, Clone)]
pub struct PyDeobLlmInput {
    pub peel: PeelResult,
    pub duration_ms: f64,
}

impl LlmMetadataEmitter for PyDeobLlmInput {
    fn metadata_capability(&self) -> MetadataCapability {
        METADATA_CAPABILITY
    }

    fn emit_symbols(&self) -> Option<Json> {
        let entries: Vec<Json> = self
            .peel
            .final_source
            .lines()
            .filter_map(|line: &str| {
                let trimmed: &str = line.trim_start();
                if let Some(rest) = trimmed.strip_prefix("def ") {
                    let name_end: usize = rest.find('(').unwrap_or(rest.len());
                    Some(shape::make_symbol_entry(
                        &rest[..name_end],
                        None,
                        "function",
                        None,
                        None,
                        "public",
                    ))
                } else if let Some(rest) = trimmed.strip_prefix("class ") {
                    let name_end: usize = rest
                        .find('(')
                        .or_else(|| rest.find(':'))
                        .unwrap_or(rest.len());
                    Some(shape::make_symbol_entry(
                        &rest[..name_end],
                        None,
                        "class",
                        None,
                        None,
                        "public",
                    ))
                } else {
                    None
                }
            })
            .collect();
        Some(shape::make_symbols_value(entries))
    }

    fn emit_strings(&self) -> Option<Json> {
        let mut entries: Vec<Json> = Vec::new();
        let mut cursor: usize = 0;
        for (line_no, line) in self.peel.final_source.lines().enumerate() {
            if let Some(start) = line.find('"')
                && let Some(end_rel) = line[start + 1..].find('"')
            {
                let s: &str = &line[start + 1..start + 1 + end_rel];
                if !s.is_empty() {
                    entries.push(shape::make_string_entry(
                        s,
                        "utf-8",
                        Some((cursor + start) as u64),
                        vec![(line_no as u64, None)],
                    ));
                }
            }
            cursor += line.len() + 1;
        }
        Some(shape::make_strings_value(entries))
    }

    fn emit_provenance(&self) -> Option<Json> {
        let mut kv: BTreeMap<String, String> = BTreeMap::new();
        kv.insert(
            "family".to_owned(),
            format!("{:?}", self.peel.initial.family),
        );
        kv.insert("converged".to_owned(), self.peel.converged.to_string());
        kv.insert("steps".to_owned(), self.peel.steps.len().to_string());
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
        let mut evidence: Vec<String> = self.peel.initial.markers.clone();
        for s in &self.peel.steps {
            evidence.push(format!("decoder={}", s.decoder));
        }
        let entry: Json = shape::make_confidence_entry(
            format!("{:?}", self.peel.initial.family),
            f64::from(self.peel.initial.confidence),
            evidence,
        );
        Some(shape::make_confidence_value(vec![entry]))
    }

    fn emit_source_map(&self) -> Option<Json> {
        Some(serde_json::json!({
            "format": "disrobe-linemap-v1",
            "mappings": []
        }))
    }
}
