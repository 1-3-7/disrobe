#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
//! End-to-end lift over real WAT-compiled bodies, asserting real signatures, operator semantics, and WAT round-trip.

use disrobe_pass_wasm_deob::{
    CalleeNames, FunctionSig, LiftResult, LiftTarget, lift_function_body,
};
use wasmparser::{FunctionBody, Parser, Payload, ValType};

fn sig(name: &str, params: Vec<ValType>, results: Vec<ValType>) -> FunctionSig {
    FunctionSig {
        name: name.to_owned(),
        params,
        results,
        exported: true,
        imported: false,
        local_names: Vec::new(),
    }
}

fn lift_first(wat: &str, s: &FunctionSig, target: LiftTarget) -> LiftResult {
    let bytes: Vec<u8> = wat::parse_str(wat).expect("wat parse");
    let callees: CalleeNames = CalleeNames::new(Vec::new());
    for payload in Parser::new(0).parse_all(&bytes) {
        if let Ok(Payload::CodeSectionEntry(body)) = payload {
            let body: FunctionBody<'_> = body;
            return lift_function_body(&body, s, &callees, target);
        }
    }
    panic!("no code section");
}

const ARITH: &str = r"
(module
  (global $g (mut i32) (i32.const 7))
  (memory 1)
  (func $main (param i32) (result i32)
    global.get $g
    local.get 0
    i32.add
    global.set $g
    local.get 0
    i32.eqz
    i32.const 3
    i32.div_s))
";

const FLOAT: &str = r"
(module
  (func $main (result f64)
    f64.const 3.5
    f64.const 2.0
    f64.mul
    f64.sqrt))
";

const WIDE: &str = r"
(module
  (func $main (param i32) (result i64)
    local.get 0
    i64.extend_i32_s
    i64.const 100
    i64.mul))
";

#[test]
fn wide_module_lifts_to_wat_that_reparses() {
    let s: FunctionSig = sig("wide", vec![ValType::I32], vec![ValType::I64]);
    let out: LiftResult = lift_first(WIDE, &s, LiftTarget::Wat);
    assert!(out.pseudo_source.contains("i64.extend_i32_s"));
    assert!(out.pseudo_source.contains("i64.mul"));
    let reparsed: Result<Vec<u8>, _> = wat::parse_str(&out.pseudo_source);
    assert!(
        reparsed.is_ok(),
        "wide WAT must reparse:\n{}",
        out.pseudo_source
    );
}

#[test]
fn arith_module_lifts_to_real_rust() {
    let s: FunctionSig = sig("arith", vec![ValType::I32], vec![ValType::I32]);
    let out: LiftResult = lift_first(ARITH, &s, LiftTarget::Rust);
    assert!(
        out.pseudo_source.contains("pub fn arith(p0: i32) -> i32"),
        "real signature, got:\n{}",
        out.pseudo_source
    );
    assert!(out.pseudo_source.contains("wasm_i32_div_s("));
    assert!(out.pseudo_source.contains("wasm_global_set(0"));
    assert!(!out.pseudo_source.contains("fn lifted"));
    assert!(!out.pseudo_source.contains("unsupported"));
    assert!(!out.pseudo_source.contains("arity_not_two"));
    assert!(
        !out.pseudo_source.contains('\u{2014}'),
        "no em-dash prose in code"
    );
}

#[test]
fn float_module_lifts_to_typescript_and_c() {
    let s: FunctionSig = sig("flt", Vec::new(), vec![ValType::F64]);
    let ts: LiftResult = lift_first(FLOAT, &s, LiftTarget::TypeScript);
    assert!(ts.pseudo_source.contains("export function flt(): number"));
    assert!(
        ts.pseudo_source.contains("wasm_f64_sqrt(") || ts.pseudo_source.contains("wasmF64Sqrt(")
    );
    let c: LiftResult = lift_first(FLOAT, &s, LiftTarget::C);
    assert!(c.pseudo_source.contains("double flt(void)"));
    assert!(c.pseudo_source.contains("wasm_f64_sqrt("));
}
