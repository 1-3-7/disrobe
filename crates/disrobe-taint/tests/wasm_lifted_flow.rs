#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_nir::NirModule;
use disrobe_nir_lift::lift_wasm_module;
use disrobe_taint::{TaintConfig, TaintReport, analyze};

const TAINTED_WAT: &str = r#"
(module
  (import "env" "recv" (func $recv (result i32)))
  (import "env" "system" (func $system (param i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "handle") (result i32)
    (call $system (call $recv))))
"#;

const SEVERED_WAT: &str = r#"
(module
  (import "env" "recv" (func $recv (result i32)))
  (import "env" "system" (func $system (param i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "handle") (param i32) (result i32)
    (if (result i32) (local.get 0)
      (then (drop (call $recv)) (i32.const 0))
      (else (call $system (i32.const 7))))))
"#;

fn lift(wat: &str) -> NirModule {
    let bytes: Vec<u8> = wat::parse_str(wat).expect("assemble wat");
    lift_wasm_module(&bytes).expect("lift wasm module")
}

fn config() -> TaintConfig {
    TaintConfig::from_lists(["recv"], ["system"])
}

#[test]
fn recv_feeding_system_in_lifted_wasm_is_a_reached_flow() {
    let module: NirModule = lift(&TAINTED_WAT.replace('\n', " "));
    let report: TaintReport = analyze(&module, &config());
    assert!(
        report.reaches("recv", "system"),
        "the recv result flows straight into the system call: {report:?}"
    );
}

#[test]
fn recv_and_system_on_opposite_arms_in_lifted_wasm_do_not_join() {
    let module: NirModule = lift(&SEVERED_WAT.replace('\n', " "));
    let report: TaintReport = analyze(&module, &config());
    assert!(
        report.is_empty(),
        "recv on the then-arm, system on the else-arm: no tainted path reaches the sink: {report:?}"
    );
}

#[test]
fn an_empty_config_finds_nothing_even_with_both_imports_present() {
    let module: NirModule = lift(&TAINTED_WAT.replace('\n', " "));
    let report: TaintReport = analyze(&module, &TaintConfig::new().with_source("recv"));
    assert!(
        report.is_empty(),
        "no sink declared, so there is nothing to reach"
    );
}
