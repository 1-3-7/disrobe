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
    assert!(
        value.get("function").and_then(Json::as_str).is_some(),
        "the bundle renderer keys every control-flow row on `function`, so a value without it \
         renders as no control flow at all: {value}"
    );
    let blocks: &Vec<Json> = value
        .get("blocks")
        .and_then(Json::as_array)
        .expect("blocks array");
    assert!(!blocks.is_empty(), "the lifted module has basic blocks");
    let edges: &Vec<Json> = value
        .get("edges")
        .and_then(Json::as_array)
        .expect("edges array");
    assert!(
        !edges.is_empty(),
        "the branch in this module produces control-flow edges: {value}"
    );
    for edge in edges {
        let from: u64 = edge.get("from").and_then(Json::as_u64).expect("edge from");
        let to: u64 = edge.get("to").and_then(Json::as_u64).expect("edge to");
        assert!(
            from < blocks.len() as u64 && to < blocks.len() as u64,
            "every edge endpoint indexes a block that is present: {edge}"
        );
    }
    let functions: &Vec<Json> = value
        .get("functions")
        .and_then(Json::as_array)
        .expect("functions array");
    assert!(!functions.is_empty(), "the lifted module has a function");
    let labelled: usize = blocks
        .iter()
        .filter_map(|b: &Json| b.get("label").and_then(Json::as_str))
        .count();
    assert_eq!(
        labelled,
        blocks.len(),
        "every block names the function it belongs to, which is how a consumer regroups the \
         module graph per function"
    );
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
    assert!(value.get("function").and_then(Json::as_str).is_some());
    let defs: &Vec<Json> = value
        .get("defs")
        .and_then(Json::as_array)
        .expect("defs array");
    let uses: &Vec<Json> = value
        .get("uses")
        .and_then(Json::as_array)
        .expect("uses array");
    assert!(
        !defs.is_empty(),
        "the i32.store in this module is a memory write: {value}"
    );
    let def_sites: Vec<u64> = defs
        .iter()
        .filter_map(|d: &Json| d.get("pc").and_then(Json::as_u64))
        .collect();
    for entry in uses {
        let def_pc: u64 = entry
            .get("def_pc")
            .and_then(Json::as_u64)
            .expect("every use names the def that reaches it");
        assert!(
            def_sites.contains(&def_pc),
            "a use points at a def that the same value reports: {entry}"
        );
    }
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
