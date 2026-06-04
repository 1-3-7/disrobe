#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
//! Per-target lift assertions over real (WAT-compiled) function bodies. Every target is
//! exercised through the production `lift_function_body` entry; WAT output is validated by
//! re-parsing, and the Rust/TS/C signatures are checked for real param/return types
//! (no hardcoded `fn lifted()`).

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

const RET_CONST: &str = r"(module (func (result i32) i32.const 42))";
const ADD2: &str =
    r"(module (func (param i32) (param i32) (result i32) local.get 0 local.get 1 i32.add))";
const LOAD: &str =
    r"(module (memory 1) (func (param i32) (result i32) local.get 0 i32.load offset=16 align=4))";
const BRANCHY: &str = r"
  (module (func (param i32) (result i32)
    local.get 0 i32.const 0 i32.lt_s
    if (result i32) i32.const -1 else i32.const 1 end))";

#[test]
fn rust_const_returns_typed_value() {
    let out: LiftResult = lift_first(
        RET_CONST,
        &sig("k", Vec::new(), vec![ValType::I32]),
        LiftTarget::Rust,
    );
    assert!(out.pseudo_source.contains("pub fn k() -> i32"));
    assert!(out.pseudo_source.contains("return 42i32;"));
    assert!(!out.pseudo_source.contains("fn lifted"));
}

#[test]
fn rust_add_emits_two_real_params_and_wrapping_add() {
    let out: LiftResult = lift_first(
        ADD2,
        &sig("add", vec![ValType::I32, ValType::I32], vec![ValType::I32]),
        LiftTarget::Rust,
    );
    assert!(
        out.pseudo_source
            .contains("pub fn add(p0: i32, p1: i32) -> i32")
    );
    assert!(out.pseudo_source.contains("wasm_i32_add(p0, p1)"));
}

#[test]
fn rust_load_uses_memory_helper_with_offset() {
    let out: LiftResult = lift_first(
        LOAD,
        &sig("ld", vec![ValType::I32], vec![ValType::I32]),
        LiftTarget::Rust,
    );
    assert!(out.pseudo_source.contains("wasm_load_i32(p0, 16)"));
}

#[test]
fn typescript_add_emits_number_params() {
    let out: LiftResult = lift_first(
        ADD2,
        &sig("add", vec![ValType::I32, ValType::I32], vec![ValType::I32]),
        LiftTarget::TypeScript,
    );
    assert!(
        out.pseudo_source
            .contains("export function add(p0: number, p1: number): number")
    );
}

#[test]
fn c_add_emits_int32_signature() {
    let out: LiftResult = lift_first(
        ADD2,
        &sig("add", vec![ValType::I32, ValType::I32], vec![ValType::I32]),
        LiftTarget::C,
    );
    assert!(
        out.pseudo_source
            .contains("int32_t add(int32_t p0, int32_t p1)")
    );
    assert!(out.pseudo_source.contains("wasm_i32_add(p0, p1)"));
}

#[test]
fn wat_single_function_reparses() {
    let out: LiftResult = lift_first(
        ADD2,
        &sig("add", vec![ValType::I32, ValType::I32], vec![ValType::I32]),
        LiftTarget::Wat,
    );
    assert!(out.pseudo_source.starts_with("(module"));
    assert!(
        out.pseudo_source
            .contains("(func $f0 (param $p0 i32) (param $p1 i32) (result i32)")
    );
    assert!(out.pseudo_source.contains("(export \"add\" (func $f0))"));
    let reparsed: Result<Vec<u8>, wat::Error> = wat::parse_str(&out.pseudo_source);
    assert!(
        reparsed.is_ok(),
        "WAT must reparse: {:?}\n{}",
        reparsed.err(),
        out.pseudo_source
    );
}

#[test]
fn wat_if_else_reparses() {
    let out: LiftResult = lift_first(
        BRANCHY,
        &sig("b", vec![ValType::I32], vec![ValType::I32]),
        LiftTarget::Wat,
    );
    assert!(out.pseudo_source.contains("if (result i32)"));
    let reparsed: Result<Vec<u8>, wat::Error> = wat::parse_str(&out.pseudo_source);
    assert!(
        reparsed.is_ok(),
        "branchy WAT must reparse: {:?}\n{}",
        reparsed.err(),
        out.pseudo_source
    );
}

#[test]
fn rust_branchy_emits_if_else_no_pseudo_text() {
    let out: LiftResult = lift_first(
        BRANCHY,
        &sig("b", vec![ValType::I32], vec![ValType::I32]),
        LiftTarget::Rust,
    );
    assert!(out.pseudo_source.contains("if (t0 != 0)") || out.pseudo_source.contains("if t0 != 0"));
    assert!(out.pseudo_source.contains("else"));
    assert!(!out.pseudo_source.contains("br_if then=block"));
    assert!(!out.pseudo_source.contains("fallthrough"));
}
