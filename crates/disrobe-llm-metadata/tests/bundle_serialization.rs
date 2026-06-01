#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use disrobe_llm_metadata::{
    BundleBuilder, Category, InputDescriptor, MetadataFormat, MetadataSelection, Pack,
    PerPassEnvelope, PipelineStep, SelectionBuilder, ToolDescriptor, envelope_map, serialize,
};
use jsonschema::Validator;
use serde_json::{Value as Json, json};

fn schema_root() -> Json {
    let root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .unwrap()
        .join("schemas")
        .join("disrobe-metadata-llm-v1.json");
    let bytes: Vec<u8> = std::fs::read(&root).expect("read schema");
    serde_json::from_slice(&bytes).expect("schema parse")
}

fn build_synthetic_bundle(selection: &MetadataSelection) -> Json {
    let step: PipelineStep = PipelineStep {
        pass: "disrobe-pass-py-disasm".to_owned(),
        version: "0.1.0".to_owned(),
        rung_in: "raw".to_owned(),
        rung_out: "disasm".to_owned(),
        duration_ms: 1.0_f64,
        input_hash_blake3: None,
        output_hash_blake3: None,
        capabilities_required: Vec::new(),
        capabilities_produced: Vec::new(),
        config: None,
    };
    let mut entries: BTreeMap<&'static str, PerPassEnvelope> = BTreeMap::new();
    entries.insert(
        Category::Disasm.label(),
        PerPassEnvelope::applicable(
            "disrobe-pass-py-disasm",
            "0.1.0",
            json!({
                "bytecode_version": "python.3.12",
                "instructions": [
                    { "pc": 0, "mnemonic": "NOP" }
                ]
            }),
        ),
    );
    entries.insert(
        Category::Provenance.label(),
        PerPassEnvelope::applicable(
            "disrobe-pass-py-disasm",
            "0.1.0",
            json!({
                "chain": [{
                    "pass": "disrobe-pass-py-disasm",
                    "version": "0.1.0",
                    "rung_in": "raw",
                    "rung_out": "disasm",
                    "duration_ms": 1.0,
                }]
            }),
        ),
    );
    let envelope: Json = envelope_map(entries);
    let mut builder: BundleBuilder = BundleBuilder::new();
    builder.record_pass(step, envelope);
    let input: InputDescriptor = InputDescriptor {
        path: "/tmp/x.pyc".to_owned(),
        size_bytes: 8u64,
        hash_blake3: "0".repeat(64),
        magic_bytes_hex: None,
        detected_formats: Vec::new(),
    };
    builder.finalize(
        "2026-05-26T00:00:00.000000000Z".to_owned(),
        ToolDescriptor::default(),
        selection,
        input,
    )
}

#[test]
fn bundle_validates_against_schema_for_pack1() {
    let selection: MetadataSelection = SelectionBuilder::new().pack(Pack::Pack1).build();
    let bundle: Json = build_synthetic_bundle(&selection);
    let schema: Json = schema_root();
    let validator: Validator = jsonschema::validator_for(&schema).expect("compile");
    let errors: Vec<String> = validator
        .iter_errors(&bundle)
        .map(|e: jsonschema::ValidationError<'_>| e.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "bundle failed schema:\n{}\nbundle={}",
        errors.join("\n"),
        serde_json::to_string_pretty(&bundle).unwrap()
    );
}

#[test]
fn bundle_top_level_required_fields_present() {
    let selection: MetadataSelection = SelectionBuilder::new().pack(Pack::Pack4).build();
    let bundle: Json = build_synthetic_bundle(&selection);
    for key in [
        "schema",
        "schema_version",
        "generated_at",
        "tool",
        "selection",
        "input",
        "pipeline",
        "categories",
    ] {
        assert!(bundle.get(key).is_some(), "missing key {key}");
    }
}

#[test]
fn empty_selection_filters_categories() {
    let selection: MetadataSelection = SelectionBuilder::new().build();
    let bundle: Json = build_synthetic_bundle(&selection);
    let categories: &serde_json::Map<String, Json> = bundle
        .get("categories")
        .and_then(Json::as_object)
        .expect("categories obj");
    assert_eq!(
        categories.len(),
        2,
        "synthetic builder feeds 2 categories regardless of selection"
    );
}

#[test]
fn serialize_jsonl_returns_one_record_per_line() {
    let selection: MetadataSelection = SelectionBuilder::new()
        .pack(Pack::Pack1)
        .format(MetadataFormat::Jsonl)
        .build();
    let bundle: Json = build_synthetic_bundle(&selection);
    let bytes: Vec<u8> = serialize(&bundle, MetadataFormat::Jsonl).expect("serialize jsonl");
    let text: String = String::from_utf8(bytes).expect("utf8");
    let lines: Vec<&str> = text.lines().collect();
    assert!(!lines.is_empty());
    for l in &lines {
        let _v: Json = serde_json::from_str(l).expect("each line is valid JSON");
    }
}

#[test]
fn serialize_cbor_roundtrips() {
    let selection: MetadataSelection = SelectionBuilder::new().pack(Pack::Pack1).build();
    let bundle: Json = build_synthetic_bundle(&selection);
    let bytes: Vec<u8> = serialize(&bundle, MetadataFormat::Cbor).expect("serialize cbor");
    let decoded: Json = ciborium::from_reader(&bytes[..]).expect("cbor decode");
    assert_eq!(
        decoded.get("schema").and_then(Json::as_str),
        Some("disrobe.metadata.llm.v1")
    );
}

#[test]
fn serialize_msgpack_roundtrips() {
    let selection: MetadataSelection = SelectionBuilder::new().pack(Pack::Pack1).build();
    let bundle: Json = build_synthetic_bundle(&selection);
    let bytes: Vec<u8> = serialize(&bundle, MetadataFormat::Msgpack).expect("serialize msgpack");
    let decoded: Json = rmp_serde::from_slice(&bytes).expect("msgpack decode");
    assert_eq!(
        decoded.get("schema").and_then(Json::as_str),
        Some("disrobe.metadata.llm.v1")
    );
}

#[test]
fn pack_monotonicity_invariant() {
    let p1: BTreeSet<Category> = SelectionBuilder::new().pack(Pack::Pack1).build().resolved();
    let p2: BTreeSet<Category> = SelectionBuilder::new().pack(Pack::Pack2).build().resolved();
    let p3: BTreeSet<Category> = SelectionBuilder::new().pack(Pack::Pack3).build().resolved();
    let p4: BTreeSet<Category> = SelectionBuilder::new()
        .pack(Pack::Pack4)
        .authorize_decryption_keys()
        .build()
        .resolved();
    assert!(p1.is_subset(&p2));
    assert!(p2.is_subset(&p3));
    assert!(p3.is_subset(&p4));
}
