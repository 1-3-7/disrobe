#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::cast_possible_truncation
)]

use disrobe_mba::{BinOp, Expr, Width, equivalent_exhaustive};
use disrobe_pass_wasm_deob::{
    ConstVal, MbaSsaStats, OpKind, SsaFunction, SsaTerm, ValueDef, ValueId, build_function_cfg,
    build_ssa, simplify_mba,
};
use wasmparser::{FunctionBody, Parser, Payload, ValType};

fn ssa_from_wat(wat: &str, params: &[ValType]) -> SsaFunction {
    let bytes: Vec<u8> = wat::parse_str(wat).expect("wat parse");
    for payload in Parser::new(0).parse_all(&bytes) {
        if let Ok(Payload::CodeSectionEntry(body)) = payload {
            let body: FunctionBody<'_> = body;
            let cfg: disrobe_pass_wasm_deob::FunctionCfg = build_function_cfg(&body).expect("cfg");
            return build_ssa(&cfg, &body, params).expect("ssa");
        }
    }
    panic!("no code section");
}

fn return_value(ssa: &SsaFunction) -> ValueId {
    for block in &ssa.blocks {
        if let SsaTerm::Return(vals) = &block.terminator
            && let Some(first) = vals.first()
        {
            return *first;
        }
    }
    panic!("no returned value found");
}

fn lower_to_mba(ssa: &SsaFunction, root: ValueId, leaves: &mut Vec<ValueId>) -> Option<Expr> {
    match ssa.value_def(root)? {
        ValueDef::Const(ConstVal::I32(n)) => Some(Expr::konst(u64::from(n.cast_unsigned()))),
        ValueDef::Const(ConstVal::I64(n)) => Some(Expr::konst(n.cast_unsigned())),
        ValueDef::Op { kind, args, .. } => {
            let op: BinOp = match kind {
                OpKind::I32Add | OpKind::I64Add => BinOp::Add,
                OpKind::I32Sub | OpKind::I64Sub => BinOp::Sub,
                OpKind::I32Mul | OpKind::I64Mul => BinOp::Mul,
                OpKind::I32And | OpKind::I64And => BinOp::And,
                OpKind::I32Or | OpKind::I64Or => BinOp::Or,
                OpKind::I32Xor | OpKind::I64Xor => BinOp::Xor,
                _ => return Some(leaf(root, leaves)),
            };
            let left: Expr = lower_to_mba(ssa, *args.first()?, leaves)?;
            let right: Expr = lower_to_mba(ssa, *args.get(1)?, leaves)?;
            Some(Expr::Binary(op, Box::new(left), Box::new(right)))
        }
        _ => Some(leaf(root, leaves)),
    }
}

fn leaf(v: ValueId, leaves: &mut Vec<ValueId>) -> Expr {
    if let Some(existing) = leaves.iter().position(|id: &ValueId| *id == v) {
        return Expr::var(existing as u32);
    }
    let index: u32 = leaves.len() as u32;
    leaves.push(v);
    Expr::var(index)
}

fn op_node_count(ssa: &SsaFunction, root: ValueId) -> usize {
    match ssa.value_def(root) {
        Some(ValueDef::Op { args, .. }) => {
            1 + args
                .iter()
                .map(|a: &ValueId| op_node_count(ssa, *a))
                .sum::<usize>()
        }
        _ => 0,
    }
}

const ADD_VIA_XOR_CARRY_I32: &str = r"
(module
  (func $mix (param i32) (param i32) (result i32)
    local.get 0
    local.get 1
    i32.xor
    i32.const 2
    local.get 0
    local.get 1
    i32.and
    i32.mul
    i32.add))
";

#[test]
fn i32_xor_carry_collapses_to_add_proven_by_mba_oracle() {
    let mut ssa: SsaFunction = ssa_from_wat(ADD_VIA_XOR_CARRY_I32, &[ValType::I32, ValType::I32]);
    let root: ValueId = return_value(&ssa);

    let mut before_leaves: Vec<ValueId> = Vec::new();
    let before: Expr =
        lower_to_mba(&ssa, root, &mut before_leaves).expect("lower original mba tree");
    assert!(before.is_linear_mba(), "lifted form must be linear MBA");
    assert_eq!(before_leaves.len(), 2, "two parameter leaves x and y");
    let before_ops: usize = op_node_count(&ssa, root);

    let stats: MbaSsaStats = simplify_mba(&mut ssa);
    assert!(stats.candidates >= 1, "the MBA root must be a candidate");
    assert!(stats.simplified >= 1, "the MBA root must be simplified");

    let after_ops: usize = op_node_count(&ssa, root);
    assert!(
        after_ops < before_ops,
        "rewritten subtree must have fewer ops: {after_ops} >= {before_ops}"
    );

    let mut after_leaves: Vec<ValueId> = Vec::new();
    let after: Expr =
        lower_to_mba(&ssa, root, &mut after_leaves).expect("lower rewritten mba tree");

    assert!(
        equivalent_exhaustive(&before, &after, Width::W8, 2),
        "disrobe-mba oracle: rewritten root `{after}` must equal original `{before}`"
    );
    let pure_add: Expr = Expr::add(Expr::var(0), Expr::var(1));
    assert!(
        equivalent_exhaustive(&after, &pure_add, Width::W8, 2),
        "rewritten root `{after}` must equal x + y"
    );
}

const OR_MINUS_AND_I32: &str = r"
(module
  (func $f (param i32) (param i32) (result i32)
    local.get 0
    local.get 1
    i32.or
    local.get 0
    local.get 1
    i32.and
    i32.sub))
";

#[test]
fn i32_or_minus_and_collapses_to_xor_proven_by_mba_oracle() {
    let mut ssa: SsaFunction = ssa_from_wat(OR_MINUS_AND_I32, &[ValType::I32, ValType::I32]);
    let root: ValueId = return_value(&ssa);
    let before_ops: usize = op_node_count(&ssa, root);

    let stats: MbaSsaStats = simplify_mba(&mut ssa);
    assert!(stats.simplified >= 1, "(x|y)-(x&y) must collapse");
    assert!(
        op_node_count(&ssa, root) < before_ops,
        "must be structurally simpler"
    );

    let mut leaves: Vec<ValueId> = Vec::new();
    let after: Expr = lower_to_mba(&ssa, root, &mut leaves).expect("lower rewritten");
    let pure_xor: Expr = Expr::xor(Expr::var(0), Expr::var(1));
    assert!(
        equivalent_exhaustive(&after, &pure_xor, Width::W8, 2),
        "rewritten root `{after}` must equal x ^ y"
    );
}

const OR_PLUS_AND_I64: &str = r"
(module
  (func $g (param i64) (param i64) (result i64)
    local.get 0
    local.get 1
    i64.or
    local.get 0
    local.get 1
    i64.and
    i64.add))
";

#[test]
fn i64_or_plus_and_collapses_to_add_proven_by_mba_oracle() {
    let mut ssa: SsaFunction = ssa_from_wat(OR_PLUS_AND_I64, &[ValType::I64, ValType::I64]);
    let root: ValueId = return_value(&ssa);
    let before_ops: usize = op_node_count(&ssa, root);

    let stats: MbaSsaStats = simplify_mba(&mut ssa);
    assert!(stats.simplified >= 1, "(x|y)+(x&y) must collapse at i64");
    assert!(
        op_node_count(&ssa, root) < before_ops,
        "must be structurally simpler"
    );

    let mut leaves: Vec<ValueId> = Vec::new();
    let after: Expr = lower_to_mba(&ssa, root, &mut leaves).expect("lower rewritten");
    let pure_add: Expr = Expr::add(Expr::var(0), Expr::var(1));
    assert!(
        equivalent_exhaustive(&after, &pure_add, Width::W8, 2),
        "rewritten i64 root `{after}` must equal x + y"
    );
}

const NON_MBA_NONLINEAR: &str = r"
(module
  (func $h (param i32) (param i32) (result i32)
    local.get 0
    local.get 1
    i32.mul))
";

#[test]
fn nonlinear_multiply_is_left_untouched() {
    let mut ssa: SsaFunction = ssa_from_wat(NON_MBA_NONLINEAR, &[ValType::I32, ValType::I32]);
    let root: ValueId = return_value(&ssa);
    let before: String = format!("{:?}", ssa.value_def(root));

    let stats: MbaSsaStats = simplify_mba(&mut ssa);
    assert_eq!(
        stats.simplified, 0,
        "x * y is nonlinear; nothing to simplify"
    );
    let after: String = format!("{:?}", ssa.value_def(root));
    assert_eq!(before, after, "the multiply root must survive unchanged");
}
