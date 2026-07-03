#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_irsummary::{capability_summary, cfg_summary};
use disrobe_nir::{BlockKind, NirModule};
use disrobe_nir_lift::lift_wasm_module;
use disrobe_query::Capability;

const NETWORK_PROCESS_WAT: &str = r#"
(module
  (import "env" "recv" (func $recv (result i32)))
  (import "env" "system" (func $system (param i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "handle") (result i32)
    (call $system (call $recv))))
"#;

const BRANCHY_WAT: &str = r#"
(module
  (import "env" "recv" (func $recv (result i32)))
  (memory (export "memory") 1)
  (func (export "handle") (param i32) (result i32)
    (if (result i32) (local.get 0)
      (then (call $recv))
      (else (i32.const 0)))))
"#;

fn lift(wat: &str) -> NirModule {
    let bytes: Vec<u8> = wat::parse_str(wat.replace('\n', " ")).expect("assemble wat");
    lift_wasm_module(&bytes).expect("lift wasm module")
}

#[test]
fn lifted_wasm_imports_classify_into_network_and_process() {
    let module: NirModule = lift(NETWORK_PROCESS_WAT);
    let summary = capability_summary(&module);

    assert!(summary.has(Capability::Network), "recv import -> network");
    assert!(summary.has(Capability::Process), "system import -> process");
    assert!(!summary.has(Capability::Crypto));
    assert!(!summary.has(Capability::Filesystem));

    let net = summary.tag(Capability::Network).expect("network tag");
    assert!(net.symbols.iter().any(|s: &String| s.contains("recv")));
}

#[test]
fn a_clean_wasm_module_reports_no_capabilities() {
    let clean_wat: &str = r#"
(module
  (func (export "add") (param i32 i32) (result i32)
    (i32.add (local.get 0) (local.get 1))))
"#;
    let module: NirModule = lift(clean_wat);
    let summary = capability_summary(&module);
    assert!(
        summary.tags.is_empty(),
        "pure arithmetic touches no external behaviour: {summary:?}"
    );
}

#[test]
fn lifted_wasm_branch_appears_as_a_conditional_block() {
    let module: NirModule = lift(BRANCHY_WAT);
    let summary = cfg_summary(&module);
    let handle = summary.functions.first().expect("a lifted function");
    assert!(
        handle.blocks.len() >= 2,
        "the if-body splits the listing into blocks: {:?}",
        summary.functions
    );
    assert!(
        handle
            .blocks
            .iter()
            .any(|b: &_| b.kind == BlockKind::Conditional),
        "the lifted if produces a conditional decision block: {:?}",
        summary.functions
    );
}
