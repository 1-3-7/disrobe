#![cfg(feature = "llm-metadata")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_irsummary::IrSummaryEmitter;
use disrobe_llm_metadata::{Category, LlmMetadataEmitter, MetadataSelection, SelectionBuilder};
use disrobe_nir::NirModule;
use disrobe_nir_lift::lift_wasm_module;
use serde_json::Value as Json;

const BRANCH_WAT: &str = r#"
(module
  (import "env" "recv" (func $recv (result i32)))
  (memory (export "memory") 1)
  (func (export "handle") (param i32) (result i32)
    (i32.store (i32.const 0) (call $recv))
    (if (result i32) (local.get 0)
      (then (i32.load (i32.const 0)))
      (else (i32.const 0)))))
"#;

fn lift(wat: &str) -> NirModule {
    let bytes: Vec<u8> = wat::parse_str(wat.replace('\n', " ")).expect("assemble wat");
    lift_wasm_module(&bytes).expect("lift wasm module")
}

#[test]
fn cfg_flows_through_the_emit_metadata_envelope() {
    let module: NirModule = lift(BRANCH_WAT);
    let emitter: IrSummaryEmitter = IrSummaryEmitter::new(&module);
    let sel: MetadataSelection = SelectionBuilder::new().category(Category::Cfg).build();
    let bundle: Json = emitter.emit_metadata(&sel);

    let envelope: &Json = bundle.get("cfg").expect("cfg envelope present");
    assert_eq!(
        envelope.get("applicable").and_then(Json::as_bool),
        Some(true),
        "cfg is a supported category for this emitter"
    );
    assert_eq!(
        envelope.get("pass").and_then(Json::as_str),
        Some("disrobe-irsummary")
    );
    let value: &Json = envelope.get("value").expect("cfg value present");
    let functions: &Vec<Json> = value
        .get("functions")
        .and_then(Json::as_array)
        .expect("functions array");
    assert!(!functions.is_empty(), "the lifted module has a function");
    let has_block: bool = functions
        .iter()
        .filter_map(|f: &Json| f.get("blocks").and_then(Json::as_array))
        .any(|b: &Vec<Json>| !b.is_empty());
    assert!(has_block, "each function carries its basic blocks");
}

#[test]
fn dfg_flows_through_the_emit_metadata_envelope() {
    let module: NirModule = lift(BRANCH_WAT);
    let emitter: IrSummaryEmitter = IrSummaryEmitter::new(&module);
    let sel: MetadataSelection = SelectionBuilder::new().category(Category::Dfg).build();
    let bundle: Json = emitter.emit_metadata(&sel);

    let envelope: &Json = bundle.get("dfg").expect("dfg envelope present");
    assert_eq!(
        envelope.get("applicable").and_then(Json::as_bool),
        Some(true)
    );
    let value: &Json = envelope.get("value").expect("dfg value present");
    assert!(
        value.get("functions").and_then(Json::as_array).is_some(),
        "dfg value is the serialized summary"
    );
}

#[test]
fn an_unsupported_category_is_marked_not_applicable() {
    let module: NirModule = lift(BRANCH_WAT);
    let emitter: IrSummaryEmitter = IrSummaryEmitter::new(&module);
    let sel: MetadataSelection = SelectionBuilder::new().category(Category::Ast).build();
    let bundle: Json = emitter.emit_metadata(&sel);

    let envelope: &Json = bundle.get("ast").expect("ast envelope present");
    assert_eq!(
        envelope.get("applicable").and_then(Json::as_bool),
        Some(false),
        "this emitter does not produce an ast"
    );
}

#[test]
fn the_emitter_surfaces_the_capability_roll_up() {
    let module: NirModule = lift(BRANCH_WAT);
    let emitter: IrSummaryEmitter = IrSummaryEmitter::new(&module);
    let caps = emitter.capabilities();
    assert!(
        caps.labels().contains(&"network"),
        "the recv import is a network capability: {caps:?}"
    );
}
