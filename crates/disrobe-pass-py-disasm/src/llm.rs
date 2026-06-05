//! `LlmMetadataEmitter` impl for the Python disasm pass.

#![cfg(feature = "llm-metadata")]
#![allow(
    clippy::doc_markdown,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::needless_pass_by_value
)]

use std::collections::{BTreeMap, BTreeSet};

use disrobe_llm_metadata::{Category, LlmMetadataEmitter, MetadataCapability, shape};
use serde_json::{Value as Json, json};

use crate::{Instruction, VERSION};

const PASS: &str = "disrobe-pass-py-disasm";

pub const METADATA_CAPABILITY: MetadataCapability = MetadataCapability::new(
    PASS,
    VERSION,
    &[
        Category::Disasm,
        Category::Symbols,
        Category::Strings,
        Category::Constants,
        Category::OpcodeCoverage,
        Category::Provenance,
    ],
);

#[derive(Debug, Clone)]
pub struct PyDisasmLlmInput {
    pub bytecode_version: String,
    pub instructions: Vec<Instruction>,
    pub names: Vec<String>,
    pub varnames: Vec<String>,
    pub consts: Vec<String>,
    pub duration_ms: f64,
}

impl LlmMetadataEmitter for PyDisasmLlmInput {
    fn metadata_capability(&self) -> MetadataCapability {
        METADATA_CAPABILITY
    }

    fn emit_disasm(&self) -> Option<Json> {
        let instructions: Vec<Json> = self
            .instructions
            .iter()
            .map(|i: &Instruction| {
                let mut operands: Vec<String> = Vec::new();
                if let Some(a) = i.arg {
                    operands.push(a.to_string());
                }
                shape::make_disasm_instr(
                    i.offset as u64,
                    Some(format!("{:02x}", i.opcode)),
                    &i.opname,
                    operands,
                    i.argrepr.clone(),
                )
            })
            .collect();
        Some(shape::make_disasm_value(
            &self.bytecode_version,
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
        let entries: Vec<Json> = self
            .consts
            .iter()
            .enumerate()
            .filter_map(|(idx, c): (usize, &String)| {
                if c.starts_with('"') || c.starts_with('\'') {
                    Some(shape::make_string_entry(
                        c.trim_matches(|ch: char| ch == '"' || ch == '\''),
                        "utf-8",
                        Some(idx as u64),
                        Vec::new(),
                    ))
                } else {
                    None
                }
            })
            .collect();
        Some(shape::make_strings_value(entries))
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

    fn emit_opcode_coverage(&self) -> Option<Json> {
        let mut seen_set: BTreeSet<String> = BTreeSet::new();
        let mut unknown_set: BTreeSet<String> = BTreeSet::new();
        for i in &self.instructions {
            if i.opname == crate::opcodes::UNKNOWN_OPCODE || i.opname.is_empty() {
                unknown_set.insert(format!("op_0x{:02x}", i.opcode));
            } else {
                seen_set.insert(i.opname.clone());
            }
        }
        let mut totals: BTreeMap<String, u64> = BTreeMap::new();
        totals.insert("instructions".to_owned(), self.instructions.len() as u64);
        totals.insert("distinct_known".to_owned(), seen_set.len() as u64);
        totals.insert("distinct_unknown".to_owned(), unknown_set.len() as u64);
        Some(shape::make_opcode_coverage_value(
            &self.bytecode_version,
            seen_set.into_iter().collect(),
            unknown_set.into_iter().collect(),
            Some(totals),
        ))
    }

    fn emit_provenance(&self) -> Option<Json> {
        let step: Json = shape::make_pipeline_step(
            PASS,
            VERSION,
            "raw",
            "disasm",
            self.duration_ms,
            BTreeMap::new(),
        );
        Some(shape::make_provenance_value(vec![step], BTreeMap::new()))
    }
}
