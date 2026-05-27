#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::cast_possible_truncation
)]

use disrobe_pass_wasm_deob::{
    BlockTarget, ConstVal, OpKind, OpaquePredStats, SsaBlock, SsaFunction, SsaTerm, ValueDef,
    ValueId, kill_opaque_predicates,
};
use smallvec::{SmallVec, smallvec};
use wasmparser::ValType;

use disrobe_pass_wasm_deob::BlockId;

fn make_eq_const_brif(a: i32, b: i32) -> SsaFunction {
    let values: Vec<ValueDef> = vec![
        ValueDef::Const(ConstVal::I32(a)),
        ValueDef::Const(ConstVal::I32(b)),
        ValueDef::Op {
            kind: OpKind::I32Eq,
            args: smallvec![ValueId(0), ValueId(1)],
            ty: ValType::I32,
        },
    ];
    let blocks: Vec<SsaBlock> = vec![
        SsaBlock {
            id: BlockId(0),
            params: SmallVec::new(),
            instrs: vec![ValueId(0), ValueId(1), ValueId(2)],
            stores: Vec::new(),
            terminator: SsaTerm::BrIf {
                cond: ValueId(2),
                then_t: BlockTarget {
                    block: BlockId(1),
                    args: SmallVec::new(),
                },
                else_t: BlockTarget {
                    block: BlockId(2),
                    args: SmallVec::new(),
                },
            },
            preds: Vec::new(),
        },
        SsaBlock {
            id: BlockId(1),
            params: SmallVec::new(),
            instrs: Vec::new(),
            stores: Vec::new(),
            terminator: SsaTerm::Return(SmallVec::new()),
            preds: vec![BlockId(0)],
        },
        SsaBlock {
            id: BlockId(2),
            params: SmallVec::new(),
            instrs: Vec::new(),
            stores: Vec::new(),
            terminator: SsaTerm::Return(SmallVec::new()),
            preds: vec![BlockId(0)],
        },
    ];
    SsaFunction {
        values,
        blocks,
        entry: BlockId(0),
    }
}

#[test]
fn opaque_pred_const_eq_true_folds_to_br_then() {
    let mut ssa: SsaFunction = make_eq_const_brif(7, 7);
    let stats: OpaquePredStats = kill_opaque_predicates(&mut ssa);
    assert_eq!(stats.found, 1, "must classify the lone BrIf as opaque");
    assert_eq!(stats.folded_true, 1);
    assert_eq!(stats.folded_false, 0);
    match &ssa.blocks[0].terminator {
        SsaTerm::Br(target) => assert_eq!(
            target.block,
            BlockId(1),
            "always-true must rewrite to br(then_t)"
        ),
        other => panic!("expected Br(then_t), got {other:?}"),
    }
}

#[test]
fn opaque_pred_const_eq_false_folds_to_br_else() {
    let mut ssa: SsaFunction = make_eq_const_brif(7, 9);
    let stats: OpaquePredStats = kill_opaque_predicates(&mut ssa);
    assert_eq!(stats.found, 1);
    assert_eq!(stats.folded_true, 0);
    assert_eq!(stats.folded_false, 1);
    match &ssa.blocks[0].terminator {
        SsaTerm::Br(target) => assert_eq!(
            target.block,
            BlockId(2),
            "always-false must rewrite to br(else_t)"
        ),
        other => panic!("expected Br(else_t), got {other:?}"),
    }
}

#[test]
fn opaque_pred_with_non_const_cond_left_alone() {
    let mut ssa: SsaFunction = make_eq_const_brif(7, 7);
    ssa.values[0] = ValueDef::Param(BlockId(0), 0);
    let before: String = format!("{:?}", ssa.blocks[0].terminator);
    let stats: OpaquePredStats = kill_opaque_predicates(&mut ssa);
    assert_eq!(stats.found, 0, "non-const cond must not be classified");
    assert_eq!(stats.folded_true, 0);
    assert_eq!(stats.folded_false, 0);
    let after: String = format!("{:?}", ssa.blocks[0].terminator);
    assert_eq!(before, after, "terminator must survive unchanged");
}

#[test]
fn opaque_pred_arith_zero_result_takes_else_branch() {
    let mut ssa: SsaFunction = make_eq_const_brif(5, 5);
    ssa.values[2] = ValueDef::Op {
        kind: OpKind::I32Sub,
        args: smallvec![ValueId(0), ValueId(1)],
        ty: ValType::I32,
    };
    let stats: OpaquePredStats = kill_opaque_predicates(&mut ssa);
    assert_eq!(stats.folded_false, 1);
    match &ssa.blocks[0].terminator {
        SsaTerm::Br(target) => assert_eq!(target.block, BlockId(2)),
        other => panic!("expected Br(else_t), got {other:?}"),
    }
}

#[test]
fn opaque_pred_three_predicates_fold_three_terminators() {
    let mut ssa: SsaFunction = make_eq_const_brif(1, 1);
    for _ in 0..2 {
        ssa.blocks.push(SsaBlock {
            id: BlockId(ssa.blocks.len() as u32),
            params: SmallVec::new(),
            instrs: vec![ValueId(0), ValueId(1), ValueId(2)],
            stores: Vec::new(),
            terminator: SsaTerm::BrIf {
                cond: ValueId(2),
                then_t: BlockTarget {
                    block: BlockId(1),
                    args: SmallVec::new(),
                },
                else_t: BlockTarget {
                    block: BlockId(2),
                    args: SmallVec::new(),
                },
            },
            preds: Vec::new(),
        });
    }
    let stats: OpaquePredStats = kill_opaque_predicates(&mut ssa);
    assert_eq!(stats.found, 3);
    assert_eq!(stats.folded_true, 3);
    for block in &ssa.blocks {
        assert!(
            !matches!(block.terminator, SsaTerm::BrIf { .. }),
            "no BrIf terminators may remain post-pass"
        );
    }
}
