//! `LlmMetadataEmitter` impl for the `PyArmor` unpacking pass.

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
use crate::detect::Detection;

const PASS: &str = "disrobe-pass-pyarmor";

pub const METADATA_CAPABILITY: MetadataCapability = MetadataCapability::new(
    PASS,
    VERSION,
    &[
        Category::Provenance,
        Category::Confidence,
        Category::DecryptionKeys,
        Category::Manifest,
    ],
);

/// Compact bag of facts the CLI passes to the emitter after running an unpack.
#[derive(Debug, Clone, Default)]
pub struct PyarmorLlmInput {
    pub detection: Option<Detection>,
    pub recovered_keys: Vec<RecoveredKey>,
    pub authorized_keys: bool,
    pub input_path: String,
    pub input_size_bytes: u64,
    pub input_hash_blake3: String,
    pub duration_ms: f64,
}

#[derive(Debug, Clone)]
pub struct RecoveredKey {
    pub label: String,
    pub algorithm: Option<String>,
    pub key_hex: String,
    pub iv_hex: Option<String>,
    pub salt_hex: Option<String>,
    pub derivation: Option<String>,
}

impl LlmMetadataEmitter for PyarmorLlmInput {
    fn metadata_capability(&self) -> MetadataCapability {
        METADATA_CAPABILITY
    }

    fn emit_provenance(&self) -> Option<Json> {
        let mut kv: BTreeMap<String, String> = BTreeMap::new();
        if let Some(d) = &self.detection {
            kv.insert("pyarmor_version".to_owned(), format!("{:?}", d.version));
            kv.insert("protection".to_owned(), format!("{:?}", d.protection));
            kv.insert("confidence".to_owned(), format!("{:?}", d.confidence));
        }
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

    fn emit_confidence(&self) -> Option<Json> {
        let Some(d) = &self.detection else {
            return Some(shape::make_confidence_value(Vec::new()));
        };
        let score: f64 = match d.confidence {
            crate::detect::DetectionConfidence::High => 0.95,
            crate::detect::DetectionConfidence::Medium => 0.7,
            crate::detect::DetectionConfidence::Low => 0.4,
        };
        let entry: Json = shape::make_confidence_entry(
            format!("pyarmor.{:?}", d.version),
            score,
            d.diagnostics.clone(),
        );
        Some(shape::make_confidence_value(vec![entry]))
    }

    fn emit_decryption_keys(&self) -> Option<Json> {
        if !self.authorized_keys {
            return None;
        }
        let entries: Vec<Json> = self
            .recovered_keys
            .iter()
            .map(|k: &RecoveredKey| {
                shape::make_decryption_key_entry(
                    &k.label,
                    k.algorithm.clone(),
                    &k.key_hex,
                    k.iv_hex.clone(),
                    k.salt_hex.clone(),
                    k.derivation.clone(),
                )
            })
            .collect();
        Some(shape::make_decryption_keys_value(true, entries))
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
}
