#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_wasm_deob::{OpKind, WobfuscatorTable, extract_optable, lift_op_to_rust_fn};
use walrus::{FunctionBuilder, FunctionId, InstrSeqBuilder, LocalId, Module, ValType};

fn build_eval_module(evals: &[(&str, EvalOp)]) -> Vec<u8> {
    let mut module: Module = Module::default();
    for (name, op) in evals {
        let mut b: FunctionBuilder = FunctionBuilder::new(
            &mut module.types,
            &[ValType::I32, ValType::I32],
            &[ValType::I32],
        );
        let a: LocalId = module.locals.add(ValType::I32);
        let c: LocalId = module.locals.add(ValType::I32);
        let mut body: InstrSeqBuilder<'_> = b.func_body();
        body.local_get(a).local_get(c);
        match op {
            EvalOp::Add => body.binop(walrus::ir::BinaryOp::I32Add),
            EvalOp::Sub => body.binop(walrus::ir::BinaryOp::I32Sub),
            EvalOp::Mul => body.binop(walrus::ir::BinaryOp::I32Mul),
        };
        let fid: FunctionId = b.finish(vec![a, c], &mut module.funcs);
        module.exports.add(name, fid);
    }
    module.emit_wasm()
}

enum EvalOp {
    Add,
    Sub,
    Mul,
}

#[test]
fn extract_optable_finds_eval0_eval1_eval2() {
    let bytes: Vec<u8> = build_eval_module(&[
        ("eval0", EvalOp::Add),
        ("eval1", EvalOp::Sub),
        ("eval2", EvalOp::Mul),
    ]);
    let table: WobfuscatorTable = extract_optable(&bytes).expect("extract");
    assert_eq!(table.entries.len(), 3);
    assert_eq!(table.entries.get("eval0"), Some(&OpKind::I32Add));
    assert_eq!(table.entries.get("eval1"), Some(&OpKind::I32Sub));
    assert_eq!(table.entries.get("eval2"), Some(&OpKind::I32Mul));
    assert!(table.sidecar_json.contains("\"eval0\""));
    assert!(table.sidecar_json.contains("\"I32Add\""));
}

#[test]
fn lift_op_to_rust_fn_emits_signature_and_body() {
    let out: String = lift_op_to_rust_fn("eval0", OpKind::I32Add);
    assert_eq!(out, "pub fn eval0(a: i32, b: i32) -> i32 { a + b }\n");
}

#[test]
fn extract_optable_skips_non_eval_exports() {
    let mut module: Module = Module::default();
    let mut b: FunctionBuilder = FunctionBuilder::new(
        &mut module.types,
        &[ValType::I32, ValType::I32],
        &[ValType::I32],
    );
    let a: LocalId = module.locals.add(ValType::I32);
    let c: LocalId = module.locals.add(ValType::I32);
    b.func_body()
        .local_get(a)
        .local_get(c)
        .binop(walrus::ir::BinaryOp::I32Xor);
    let fid: FunctionId = b.finish(vec![a, c], &mut module.funcs);
    module.exports.add("eval0", fid);

    let mut b2: FunctionBuilder = FunctionBuilder::new(
        &mut module.types,
        &[ValType::I32, ValType::I32],
        &[ValType::I32],
    );
    let a2: LocalId = module.locals.add(ValType::I32);
    let c2: LocalId = module.locals.add(ValType::I32);
    b2.func_body()
        .local_get(a2)
        .local_get(c2)
        .binop(walrus::ir::BinaryOp::I32Add);
    let fid2: FunctionId = b2.finish(vec![a2, c2], &mut module.funcs);
    module.exports.add("other", fid2);

    let bytes: Vec<u8> = module.emit_wasm();
    let table: WobfuscatorTable = extract_optable(&bytes).expect("extract");
    assert_eq!(table.entries.len(), 1, "only eval0 must be captured");
    assert_eq!(table.entries.get("eval0"), Some(&OpKind::I32Xor));
    assert!(!table.entries.contains_key("other"));
}
