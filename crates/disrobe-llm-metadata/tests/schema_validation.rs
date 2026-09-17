#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_llm_metadata::{
    Category, MetadataFormat, MetadataSelection, Pack, PerPassEnvelope, SelectionBuilder,
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
    let bytes: Vec<u8> =
        std::fs::read(&root).unwrap_or_else(|e| panic!("read schema {}: {e}", root.display()));
    serde_json::from_slice(&bytes).expect("schema must parse as JSON")
}

fn subschema_for(def: &str) -> Json {
    let root: Json = schema_root();
    let defs: &Json = root.get("$defs").expect("schema must have $defs");
    let mut subschema: Json = defs.get(def).cloned().unwrap_or_else(|| {
        panic!("missing $defs/{def}");
    });
    if let Some(obj) = subschema.as_object_mut() {
        obj.insert("$defs".to_owned(), defs.clone());
    }
    subschema
}

#[test]
fn per_pass_envelope_validates_when_applicable() {
    let sub: Json = subschema_for("PerPassEnvelope");
    let validator: Validator = jsonschema::validator_for(&sub).expect("compile schema");
    let env: PerPassEnvelope =
        PerPassEnvelope::applicable("disrobe-pass-py-disasm", "0.1.0", json!({"k": 1}));
    let v: Json = serde_json::to_value(&env).unwrap();
    assert!(
        validator.is_valid(&v),
        "applicable envelope failed schema: {:?}",
        validator
            .iter_errors(&v)
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
    );
}

#[test]
fn per_pass_envelope_validates_when_not_applicable() {
    let sub: Json = subschema_for("PerPassEnvelope");
    let validator: Validator = jsonschema::validator_for(&sub).expect("compile schema");
    let env: PerPassEnvelope =
        PerPassEnvelope::not_applicable("disrobe-pass-shell", "0.1.0", "no disasm in shell");
    let v: Json = serde_json::to_value(&env).unwrap();
    assert!(
        validator.is_valid(&v),
        "not-applicable envelope failed schema: {:?}",
        validator
            .iter_errors(&v)
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
    );
}

#[test]
fn metadata_selection_serializes_compatible_with_schema() {
    let sub: Json = subschema_for("MetadataSelection");
    let validator: Validator = jsonschema::validator_for(&sub).expect("compile schema");

    let sel: MetadataSelection = SelectionBuilder::new()
        .pack(Pack::Pack3)
        .category(Category::Signatures)
        .exclude(Category::Ast)
        .format(MetadataFormat::Json)
        .authorize_decryption_keys()
        .build();
    let v: Json = serde_json::to_value(&sel).unwrap();
    assert!(
        validator.is_valid(&v),
        "selection failed schema: {:?}\n{}",
        validator
            .iter_errors(&v)
            .map(|e| e.to_string())
            .collect::<Vec<_>>(),
        serde_json::to_string_pretty(&v).unwrap(),
    );
}

#[test]
fn empty_selection_serializes_compatible_with_schema() {
    let sub: Json = subschema_for("MetadataSelection");
    let validator: Validator = jsonschema::validator_for(&sub).expect("compile schema");
    let sel: MetadataSelection = SelectionBuilder::new().build();
    let v: Json = serde_json::to_value(&sel).unwrap();
    assert!(
        validator.is_valid(&v),
        "empty selection failed schema: {:?}",
        validator
            .iter_errors(&v)
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
    );
}

#[test]
fn all_category_labels_appear_in_schema_enum() {
    let root: Json = schema_root();
    let names: BTreeSet<String> = root
        .get("$defs")
        .and_then(|d| d.get("CategoryName"))
        .and_then(|c| c.get("enum"))
        .and_then(Json::as_array)
        .map_or_else(BTreeSet::new, |arr: &Vec<Json>| {
            arr.iter()
                .filter_map(|v: &Json| v.as_str().map(str::to_owned))
                .collect()
        });
    for c in Category::ALL {
        assert!(
            names.contains(c.label()),
            "schema CategoryName enum missing `{}`",
            c.label()
        );
    }
}
