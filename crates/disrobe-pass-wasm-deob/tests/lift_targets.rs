#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_wasm_deob::{
    BlockId, ConstVal, FunctionCfg, LiftResult, LiftTarget, LoadKind, OpKind, SsaBlock,
    SsaFunction, SsaMemArg, SsaTerm, StructuredFunction, TerminatorKind, ValueDef, ValueId, lift,
    lift_with_ssa, reloop_inverse,
};
use smallvec::{SmallVec, smallvec};
use wasmparser::ValType;

fn cfg_with_return() -> FunctionCfg {
    FunctionCfg {
        blocks: vec![disrobe_pass_wasm_deob::CfgBlock {
            id: BlockId(0),
            terminator: Some(TerminatorKind::Return),
            ..Default::default()
        }],
        edges: Vec::new(),
        entry: BlockId(0),
    }
}

fn ssa_one_block(values: Vec<ValueDef>, instrs: Vec<ValueId>, term: SsaTerm) -> SsaFunction {
    SsaFunction {
        values,
        blocks: vec![SsaBlock {
            id: BlockId(0),
            params: SmallVec::new(),
            instrs,
            stores: Vec::new(),
            terminator: term,
            preds: Vec::new(),
        }],
        entry: BlockId(0),
    }
}

#[test]
fn wat_empty_module_is_self_contained() {
    let func: StructuredFunction = reloop_inverse(&cfg_with_return());
    let empty_ssa: SsaFunction = SsaFunction {
        values: Vec::new(),
        blocks: Vec::new(),
        entry: BlockId(0),
    };
    let out: LiftResult = lift_with_ssa(&func, &empty_ssa, LiftTarget::Wat);
    assert_eq!(out.target, LiftTarget::Wat);
    assert!(
        out.pseudo_source.starts_with("(module\n"),
        "wat must start with (module:\n{}",
        out.pseudo_source
    );
    assert!(out.pseudo_source.contains("(func $lifted"));
    assert!(out.pseudo_source.contains("(export \"lifted\""));
    assert!(out.pseudo_source.trim_end().ends_with(')'));
}

#[test]
fn wat_emits_i32_const_and_result_type_for_returning_function() {
    let func: StructuredFunction = reloop_inverse(&cfg_with_return());
    let ssa: SsaFunction = ssa_one_block(
        vec![ValueDef::Const(ConstVal::I32(42))],
        vec![ValueId(0)],
        SsaTerm::Return(smallvec![ValueId(0)]),
    );
    let out: LiftResult = lift_with_ssa(&func, &ssa, LiftTarget::Wat);
    assert!(
        out.pseudo_source.contains("i32.const 42"),
        "wat must emit i32.const 42:\n{}",
        out.pseudo_source
    );
    assert!(
        out.pseudo_source.contains("(result i32)"),
        "non-empty return must surface (result i32):\n{}",
        out.pseudo_source
    );
}

#[test]
fn wat_emits_load_with_offset_and_alignment_attributes() {
    let func: StructuredFunction = reloop_inverse(&cfg_with_return());
    let ssa: SsaFunction = ssa_one_block(
        vec![
            ValueDef::Const(ConstVal::I32(0)),
            ValueDef::Load {
                addr: ValueId(0),
                memarg: SsaMemArg {
                    align: 2,
                    offset: 16,
                    memory: 0,
                },
                kind: LoadKind::I32,
                ty: ValType::I32,
            },
        ],
        vec![ValueId(0), ValueId(1)],
        SsaTerm::Return(smallvec![ValueId(1)]),
    );
    let out: LiftResult = lift_with_ssa(&func, &ssa, LiftTarget::Wat);
    assert!(out.pseudo_source.contains("i32.load"));
    assert!(out.pseudo_source.contains("offset=16"));
    assert!(out.pseudo_source.contains("align=4"));
}

#[test]
fn wat_emits_binop_mnemonic_and_return_terminator() {
    let func: StructuredFunction = reloop_inverse(&cfg_with_return());
    let ssa: SsaFunction = ssa_one_block(
        vec![
            ValueDef::Const(ConstVal::I32(3)),
            ValueDef::Const(ConstVal::I32(5)),
            ValueDef::Op {
                kind: OpKind::I32Xor,
                args: smallvec![ValueId(0), ValueId(1)],
                ty: ValType::I32,
            },
        ],
        vec![ValueId(0), ValueId(1), ValueId(2)],
        SsaTerm::Return(smallvec![ValueId(2)]),
    );
    let out: LiftResult = lift_with_ssa(&func, &ssa, LiftTarget::Wat);
    assert!(out.pseudo_source.contains("i32.xor"));
    assert!(out.pseudo_source.contains("return"));
}

#[test]
fn lift_empty_yields_empty() {
    let func: StructuredFunction = reloop_inverse(&FunctionCfg::default());
    let out: LiftResult = lift(&func, LiftTarget::Rust);
    assert_eq!(out.pseudo_source, "");
    assert_eq!(out.blocks_emitted, 0);
}

#[test]
fn lift_return_block_emits_return_keyword_rust() {
    let func: StructuredFunction = reloop_inverse(&cfg_with_return());
    let out: LiftResult = lift(&func, LiftTarget::Rust);
    assert!(out.pseudo_source.contains("return"));
    assert_eq!(out.blocks_emitted, 1);
}

#[test]
fn lift_return_block_emits_return_keyword_typescript() {
    let func: StructuredFunction = reloop_inverse(&cfg_with_return());
    let out: LiftResult = lift(&func, LiftTarget::TypeScript);
    assert!(out.pseudo_source.contains("return"));
    assert_eq!(out.blocks_emitted, 1);
}

#[test]
fn lift_with_ssa_rust_wraps_in_fn_lifted() {
    let func: StructuredFunction = reloop_inverse(&cfg_with_return());
    let empty: SsaFunction = SsaFunction {
        values: Vec::new(),
        blocks: Vec::new(),
        entry: BlockId(0),
    };
    let out: LiftResult = lift_with_ssa(&func, &empty, LiftTarget::Rust);
    assert!(out.pseudo_source.contains("lifted from wasm"));
    assert!(out.pseudo_source.contains("fn lifted()"));
    assert!(out.pseudo_source.contains("ssa values=0"));
}

#[test]
fn lift_with_ssa_typescript_wraps_in_function() {
    let func: StructuredFunction = reloop_inverse(&cfg_with_return());
    let empty: SsaFunction = SsaFunction {
        values: Vec::new(),
        blocks: Vec::new(),
        entry: BlockId(0),
    };
    let out: LiftResult = lift_with_ssa(&func, &empty, LiftTarget::TypeScript);
    assert!(out.pseudo_source.contains("function lifted(): void"));
}

#[test]
fn lift_with_ssa_rust_emits_const_let_binding() {
    let func: StructuredFunction = reloop_inverse(&cfg_with_return());
    let ssa: SsaFunction = ssa_one_block(
        vec![ValueDef::Const(ConstVal::I32(42))],
        vec![ValueId(0)],
        SsaTerm::Return(SmallVec::new()),
    );
    let out: LiftResult = lift_with_ssa(&func, &ssa, LiftTarget::Rust);
    assert!(out.pseudo_source.contains("let v0 = 42"));
}

#[test]
fn lift_with_ssa_rust_emits_binary_op_expr() {
    let func: StructuredFunction = reloop_inverse(&cfg_with_return());
    let ssa: SsaFunction = ssa_one_block(
        vec![
            ValueDef::Const(ConstVal::I32(1)),
            ValueDef::Const(ConstVal::I32(2)),
            ValueDef::Op {
                kind: OpKind::I32Add,
                args: smallvec![ValueId(0), ValueId(1)],
                ty: ValType::I32,
            },
        ],
        vec![ValueId(0), ValueId(1), ValueId(2)],
        SsaTerm::Return(smallvec![ValueId(2)]),
    );
    let out: LiftResult = lift_with_ssa(&func, &ssa, LiftTarget::Rust);
    assert!(out.pseudo_source.contains("v0 + v1"));
    assert!(out.pseudo_source.contains("let v2 = v0 + v1"));
    assert!(out.pseudo_source.contains("return v2;"));
}

#[test]
fn lift_with_ssa_rust_emits_mem_load_helper() {
    let func: StructuredFunction = reloop_inverse(&cfg_with_return());
    let ssa: SsaFunction = ssa_one_block(
        vec![
            ValueDef::Const(ConstVal::I32(0)),
            ValueDef::Load {
                addr: ValueId(0),
                memarg: SsaMemArg {
                    align: 2,
                    offset: 8,
                    memory: 0,
                },
                kind: LoadKind::I32,
                ty: ValType::I32,
            },
        ],
        vec![ValueId(0), ValueId(1)],
        SsaTerm::Return(smallvec![ValueId(1)]),
    );
    let out: LiftResult = lift_with_ssa(&func, &ssa, LiftTarget::Rust);
    assert!(out.pseudo_source.contains("mem_load_I32"));
    assert!(out.pseudo_source.contains("offset=8"));
}

#[test]
fn rust_typescript_and_wat_targets_remain_distinguishable() {
    let func: StructuredFunction = reloop_inverse(&cfg_with_return());
    let empty: SsaFunction = SsaFunction {
        values: Vec::new(),
        blocks: Vec::new(),
        entry: BlockId(0),
    };
    let rust: LiftResult = lift_with_ssa(&func, &empty, LiftTarget::Rust);
    let ts: LiftResult = lift_with_ssa(&func, &empty, LiftTarget::TypeScript);
    let wat: LiftResult = lift_with_ssa(&func, &empty, LiftTarget::Wat);
    assert!(rust.pseudo_source.contains("fn lifted()"));
    assert!(ts.pseudo_source.contains("function lifted(): void"));
    assert!(wat.pseudo_source.starts_with("(module"));
    assert_eq!(rust.target, LiftTarget::Rust);
    assert_eq!(ts.target, LiftTarget::TypeScript);
    assert_eq!(wat.target, LiftTarget::Wat);
}
