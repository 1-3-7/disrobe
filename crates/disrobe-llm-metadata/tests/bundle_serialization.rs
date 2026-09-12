#![allow(clippy::expect_used, clippy::unwrap_used)]
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use disrobe_llm_metadata::{
    BundleBuilder, Category, InputDescriptor, MetadataFormat, MetadataSelection, Pack,
    PerPassEnvelope, PipelineStep, SelectionBuilder, ToolDescriptor, bundle::MAX_PIPELINE_STEPS,
    envelope_map, serialize,
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

fn synthetic_step() -> PipelineStep {
    PipelineStep {
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
    }
}

fn synthetic_input() -> InputDescriptor {
    InputDescriptor {
        path: "/tmp/x.pyc".to_owned(),
        size_bytes: 8u64,
        hash_blake3: "0".repeat(64),
        magic_bytes_hex: None,
        detected_formats: Vec::new(),
    }
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
    builder
        .finalize(
            "2026-05-26T00:00:00.000000000Z".to_owned(),
            ToolDescriptor::default(),
            selection,
            input,
        )
        .expect("synthetic bundle must finalize")
}

#[test]
fn finalize_rejects_mismatched_pipeline_and_envelopes() {
    let selection: MetadataSelection = SelectionBuilder::new().pack(Pack::Pack1).build();
    let mut builder: BundleBuilder = BundleBuilder::new();
    builder.steps.push(synthetic_step());
    let err: disrobe_llm_metadata::LlmMetadataError = builder
        .finalize(
            "2026-05-26T00:00:00.000000000Z".to_owned(),
            ToolDescriptor::default(),
            &selection,
            synthetic_input(),
        )
        .expect_err("mismatched builder state must reject");
    assert!(
        err.to_string()
            .contains("1 pipeline steps but 0 per-pass envelope maps"),
        "unexpected error: {err}"
    );
}

#[test]
fn finalize_rejects_too_many_pipeline_steps() {
    let selection: MetadataSelection = SelectionBuilder::new().pack(Pack::Pack1).build();
    let count: usize = MAX_PIPELINE_STEPS + 1;
    let mut builder: BundleBuilder = BundleBuilder::new();
    builder.steps = vec![synthetic_step(); count];
    builder.per_pass = (0..count).map(|_: usize| json!({})).collect();
    let err: disrobe_llm_metadata::LlmMetadataError = builder
        .finalize(
            "2026-05-26T00:00:00.000000000Z".to_owned(),
            ToolDescriptor::default(),
            &selection,
            synthetic_input(),
        )
        .expect_err("overlarge builder state must reject");
    assert!(
        err.to_string().contains("1025 pipeline steps, max 1024"),
        "unexpected error: {err}"
    );
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

    assert_eq!(
        bundle.get("schema").and_then(Json::as_str),
        Some("disrobe.metadata.llm.v1"),
        "schema must be the exact v1 tag"
    );
    assert_eq!(
        bundle.get("schema_version").and_then(Json::as_str),
        Some("1.0.0"),
        "schema_version must be the pinned 1.0.0"
    );
    assert_eq!(
        bundle.get("generated_at").and_then(Json::as_str),
        Some("2026-05-26T00:00:00.000000000Z"),
        "generated_at must round-trip the timestamp we passed to finalize"
    );
    for key in ["tool", "selection", "input"] {
        assert!(
            bundle.get(key).and_then(Json::as_object).is_some(),
            "{key} must serialize as a JSON object"
        );
    }
    let pipeline: &Vec<Json> = bundle
        .get("pipeline")
        .and_then(Json::as_array)
        .expect("pipeline array");
    assert_eq!(pipeline.len(), 1, "the synthetic builder records one pass");
    assert_eq!(
        pipeline[0].get("pass").and_then(Json::as_str),
        Some("disrobe-pass-py-disasm"),
        "the single pipeline step must name the recorded pass"
    );
    let categories: &serde_json::Map<String, Json> = bundle
        .get("categories")
        .and_then(Json::as_object)
        .expect("categories object");
    assert!(
        categories.contains_key("disasm") && categories.contains_key("provenance"),
        "the two fed categories must both appear: {:?}",
        categories.keys().collect::<Vec<&String>>()
    );
    assert_eq!(
        bundle
            .get("input")
            .and_then(|i: &Json| i.get("path"))
            .and_then(Json::as_str),
        Some("/tmp/x.pyc"),
        "the input descriptor path must survive serialization"
    );
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
    let records: Vec<Json> = lines
        .iter()
        .map(|l: &&str| serde_json::from_str(l).expect("each line is valid JSON"))
        .collect();
    assert_eq!(
        records.len(),
        9,
        "six scalar/object top-level fields + one pipeline step + two categories = nine records"
    );
    for record in &records {
        let kind: &str = record
            .get("record")
            .and_then(Json::as_str)
            .expect("every jsonl record names its kind");
        assert!(!kind.is_empty(), "record kind must be non-empty");
        assert!(
            record.get("value").is_some(),
            "every record carries a value"
        );
    }
    let kinds: BTreeSet<&str> = records
        .iter()
        .filter_map(|r: &Json| r.get("record").and_then(Json::as_str))
        .collect();
    assert!(
        kinds.contains("schema") && kinds.contains("pipeline_step") && kinds.contains("category"),
        "the record kinds must include the schema field, the pipeline step, and category rows: {kinds:?}"
    );
    let category_rows: usize = records
        .iter()
        .filter(|r: &&Json| r.get("record").and_then(Json::as_str) == Some("category"))
        .count();
    assert_eq!(category_rows, 2, "exactly two category rows are emitted");
}

#[test]
fn serialize_cbor_roundtrips() {
    let selection: MetadataSelection = SelectionBuilder::new().pack(Pack::Pack1).build();
    let bundle: Json = build_synthetic_bundle(&selection);
    let bytes: Vec<u8> = serialize(&bundle, MetadataFormat::Cbor).expect("serialize cbor");
    let decoded: Json = ciborium::from_reader(&bytes[..]).expect("cbor decode");
    assert_eq!(
        decoded, bundle,
        "the CBOR round-trip must reconstruct the bundle field-for-field"
    );
    assert_eq!(
        decoded.get("schema").and_then(Json::as_str),
        Some("disrobe.metadata.llm.v1")
    );
    assert_eq!(
        decoded.get("schema_version").and_then(Json::as_str),
        Some("1.0.0")
    );
    assert_eq!(
        decoded
            .get("pipeline")
            .and_then(Json::as_array)
            .map(Vec::len),
        Some(1),
        "the single pipeline step must survive the CBOR round-trip"
    );
    assert!(
        decoded
            .get("categories")
            .and_then(Json::as_object)
            .is_some(),
        "categories must decode back to an object"
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
fn finalize_rejects_non_finite_pipeline_duration() {
    let selection: MetadataSelection = SelectionBuilder::new().pack(Pack::Pack1).build();
    let step: PipelineStep = PipelineStep {
        pass: "disrobe-pass-py-disasm".to_owned(),
        version: "0.1.0".to_owned(),
        rung_in: "raw".to_owned(),
        rung_out: "disasm".to_owned(),
        duration_ms: f64::NAN,
        input_hash_blake3: None,
        output_hash_blake3: None,
        capabilities_required: Vec::new(),
        capabilities_produced: Vec::new(),
        config: None,
    };
    let mut entries: BTreeMap<&'static str, PerPassEnvelope> = BTreeMap::new();
    entries.insert(
        Category::Disasm.label(),
        PerPassEnvelope::applicable("disrobe-pass-py-disasm", "0.1.0", json!({})),
    );
    let mut builder: BundleBuilder = BundleBuilder::new();
    builder.record_pass(step, envelope_map(entries));
    let input: InputDescriptor = InputDescriptor {
        path: "/tmp/x.pyc".to_owned(),
        size_bytes: 8u64,
        hash_blake3: "0".repeat(64),
        magic_bytes_hex: None,
        detected_formats: Vec::new(),
    };
    let err: disrobe_llm_metadata::LlmMetadataError = builder
        .finalize(
            "2026-05-26T00:00:00.000000000Z".to_owned(),
            ToolDescriptor::default(),
            &selection,
            input,
        )
        .expect_err("non-finite duration must reject");
    assert!(
        err.to_string().contains("invalid duration_ms"),
        "unexpected error: {err}"
    );
}

#[test]
fn finalize_rejects_unknown_per_pass_category_label() {
    let selection: MetadataSelection = SelectionBuilder::new().pack(Pack::Pack1).build();
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
    let mut builder: BundleBuilder = BundleBuilder::new();
    builder.record_pass(
        step,
        json!({
            "not_a_category": {
                "pass": "disrobe-pass-py-disasm",
                "pass_version": "0.1.0",
                "applicable": true,
                "reason": null,
                "value": {}
            }
        }),
    );
    let input: InputDescriptor = InputDescriptor {
        path: "/tmp/x.pyc".to_owned(),
        size_bytes: 8u64,
        hash_blake3: "0".repeat(64),
        magic_bytes_hex: None,
        detected_formats: Vec::new(),
    };
    let err: disrobe_llm_metadata::LlmMetadataError = builder
        .finalize(
            "2026-05-26T00:00:00.000000000Z".to_owned(),
            ToolDescriptor::default(),
            &selection,
            input,
        )
        .expect_err("unknown category must reject");
    assert!(
        err.to_string().contains("unknown LLM metadata category"),
        "unexpected error: {err}"
    );
}

#[test]
fn unauthorized_decryption_key_envelope_does_not_aggregate_entries() {
    let selection: MetadataSelection = SelectionBuilder::new()
        .category(Category::DecryptionKeys)
        .authorize_decryption_keys()
        .build();
    let mut entries: BTreeMap<&'static str, PerPassEnvelope> = BTreeMap::new();
    entries.insert(
        Category::DecryptionKeys.label(),
        PerPassEnvelope::applicable(
            "disrobe-pass-example",
            "0.1.0",
            json!({
                "authorized": false,
                "entries": [{ "id": "must-not-appear" }]
            }),
        ),
    );
    let mut builder: BundleBuilder = BundleBuilder::new();
    builder.record_pass(synthetic_step(), envelope_map(entries));
    let bundle: Json = builder
        .finalize(
            "2026-05-26T00:00:00.000000000Z".to_owned(),
            ToolDescriptor::default(),
            &selection,
            synthetic_input(),
        )
        .expect("bundle finalizes");
    let category: &Json = bundle
        .get("categories")
        .and_then(|v: &Json| v.get(Category::DecryptionKeys.label()))
        .expect("decryption-key category present");
    assert_eq!(
        category.get("authorized").and_then(Json::as_bool),
        Some(false)
    );
    assert_eq!(
        category
            .get("entries")
            .and_then(Json::as_array)
            .map(Vec::len),
        Some(0)
    );
    assert!(
        !serde_json::to_string(category)
            .unwrap()
            .contains("must-not-appear")
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
