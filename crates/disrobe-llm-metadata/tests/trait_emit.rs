#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_llm_metadata::{
    Category, LlmMetadataEmitter, MetadataCapability, Pack, SelectionBuilder,
};
use serde_json::{Value as Json, json};

struct FakePyDisasm;

const FAKE_CAP: MetadataCapability = MetadataCapability::new(
    "disrobe-pass-py-disasm",
    "0.1.0",
    &[
        Category::Disasm,
        Category::Symbols,
        Category::Strings,
        Category::Constants,
        Category::OpcodeCoverage,
        Category::Provenance,
    ],
);

impl LlmMetadataEmitter for FakePyDisasm {
    fn metadata_capability(&self) -> MetadataCapability {
        FAKE_CAP
    }

    fn emit_disasm(&self) -> Option<Json> {
        Some(json!({"bytecode_version": "python.3.12", "instructions": []}))
    }

    fn emit_symbols(&self) -> Option<Json> {
        Some(json!([{"mangled": "main"}]))
    }
}

#[test]
fn supported_category_yields_applicable_envelope() {
    let sel = SelectionBuilder::new().category(Category::Disasm).build();
    let v: Json = FakePyDisasm.emit_metadata(&sel);
    let envelope: &Json = v.get("disasm").expect("disasm must be present");
    assert_eq!(envelope.get("applicable").unwrap().as_bool(), Some(true));
    assert_eq!(
        envelope.get("pass").unwrap().as_str(),
        Some("disrobe-pass-py-disasm")
    );
    assert!(envelope.get("value").unwrap().is_object());
}

#[test]
fn unsupported_category_yields_not_applicable_with_reason() {
    let sel = SelectionBuilder::new().category(Category::Ast).build();
    let v: Json = FakePyDisasm.emit_metadata(&sel);
    let envelope: &Json = v.get("ast").expect("ast must be present");
    assert_eq!(envelope.get("applicable").unwrap().as_bool(), Some(false));
    assert!(envelope.get("reason").unwrap().is_string());
    assert!(envelope.get("value").unwrap().is_null());
}

#[test]
fn pack_request_returns_envelope_per_resolved_category() {
    let sel = SelectionBuilder::new().pack(Pack::Pack1).build();
    let v: Json = FakePyDisasm.emit_metadata(&sel);
    let obj: &serde_json::Map<String, Json> = v.as_object().unwrap();
    assert_eq!(obj.len(), 4);
    for k in ["ast", "disasm", "symbols", "strings"] {
        assert!(obj.contains_key(k), "missing key {k}");
    }
}

#[test]
fn empty_selection_yields_empty_map() {
    let sel = SelectionBuilder::new().build();
    let v: Json = FakePyDisasm.emit_metadata(&sel);
    assert_eq!(v.as_object().unwrap().len(), 0);
}
