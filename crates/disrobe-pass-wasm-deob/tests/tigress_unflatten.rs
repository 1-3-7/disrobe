#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;

use disrobe_pass_wasm_deob::{
    BlockId, BlockTarget, ConstVal, DispatcherInfo, OpKind, SsaBlock, SsaFunction, SsaMemArg,
    SsaTerm, StoreKind, UnflattenStats, ValueDef, ValueId, detect_dispatcher, unflatten,
};
use smallvec::{SmallVec, smallvec};
use wasmparser::ValType;

fn target(b: u32) -> BlockTarget {
    BlockTarget {
        block: BlockId(b),
        args: SmallVec::new(),
    }
}

const fn memarg() -> SsaMemArg {
    SsaMemArg {
        align: 2,
        offset: 0,
        memory: 0,
    }
}

fn build_three_state_dispatcher() -> SsaFunction {
    let values: Vec<ValueDef> = vec![
        ValueDef::Param(BlockId(0), 0),
        ValueDef::Load {
            addr: ValueId(0),
            memarg: memarg(),
            kind: disrobe_pass_wasm_deob::LoadKind::I32,
            ty: ValType::I32,
        },
        ValueDef::Const(ConstVal::I32(0)),
        ValueDef::Const(ConstVal::I32(1)),
        ValueDef::Const(ConstVal::I32(2)),
    ];
    let dispatcher: SsaBlock = SsaBlock {
        id: BlockId(0),
        params: SmallVec::new(),
        instrs: vec![ValueId(0), ValueId(1)],
        stores: Vec::new(),
        terminator: SsaTerm::BrTable {
            idx: ValueId(1),
            targets: vec![target(1), target(2), target(3)],
            default: target(4),
        },
        preds: vec![BlockId(1), BlockId(2), BlockId(3)],
    };
    let case0: SsaBlock = SsaBlock {
        id: BlockId(1),
        params: SmallVec::new(),
        instrs: vec![ValueId(3)],
        stores: vec![disrobe_pass_wasm_deob::SideEffect {
            addr: ValueId(0),
            val: ValueId(3),
            memarg: memarg(),
            kind: StoreKind::I32,
        }],
        terminator: SsaTerm::Br(target(0)),
        preds: vec![BlockId(0)],
    };
    let case1: SsaBlock = SsaBlock {
        id: BlockId(2),
        params: SmallVec::new(),
        instrs: vec![ValueId(4)],
        stores: vec![disrobe_pass_wasm_deob::SideEffect {
            addr: ValueId(0),
            val: ValueId(4),
            memarg: memarg(),
            kind: StoreKind::I32,
        }],
        terminator: SsaTerm::Br(target(0)),
        preds: vec![BlockId(0)],
    };
    let case2_exit: SsaBlock = SsaBlock {
        id: BlockId(3),
        params: SmallVec::new(),
        instrs: Vec::new(),
        stores: Vec::new(),
        terminator: SsaTerm::Return(SmallVec::new()),
        preds: vec![BlockId(0)],
    };
    let default_exit: SsaBlock = SsaBlock {
        id: BlockId(4),
        params: SmallVec::new(),
        instrs: Vec::new(),
        stores: Vec::new(),
        terminator: SsaTerm::Unreachable,
        preds: vec![BlockId(0)],
    };
    SsaFunction {
        values,
        blocks: vec![dispatcher, case0, case1, case2_exit, default_exit],
        entry: BlockId(0),
    }
}

#[test]
fn detect_dispatcher_finds_brtable_with_backedge() {
    let ssa: SsaFunction = build_three_state_dispatcher();
    let info: DispatcherInfo = detect_dispatcher(&ssa).expect("must detect three-state dispatcher");
    assert_eq!(info.header, BlockId(0));
    assert_eq!(info.state_value, ValueId(1));
    assert_eq!(info.cases.len(), 3);
    assert_eq!(info.cases.get(&0).copied(), Some(BlockId(1)));
    assert_eq!(info.cases.get(&1).copied(), Some(BlockId(2)));
    assert_eq!(info.cases.get(&2).copied(), Some(BlockId(3)));
}

#[test]
fn detect_dispatcher_skips_brtable_without_backedge() {
    let values: Vec<ValueDef> = vec![
        ValueDef::Param(BlockId(0), 0),
        ValueDef::Load {
            addr: ValueId(0),
            memarg: memarg(),
            kind: disrobe_pass_wasm_deob::LoadKind::I32,
            ty: ValType::I32,
        },
    ];
    let blocks: Vec<SsaBlock> = vec![
        SsaBlock {
            id: BlockId(0),
            params: SmallVec::new(),
            instrs: vec![ValueId(0), ValueId(1)],
            stores: Vec::new(),
            terminator: SsaTerm::BrTable {
                idx: ValueId(1),
                targets: vec![target(1), target(2)],
                default: target(3),
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
        SsaBlock {
            id: BlockId(3),
            params: SmallVec::new(),
            instrs: Vec::new(),
            stores: Vec::new(),
            terminator: SsaTerm::Unreachable,
            preds: vec![BlockId(0)],
        },
    ];
    let ssa: SsaFunction = SsaFunction {
        values,
        blocks,
        entry: BlockId(0),
    };
    assert!(
        detect_dispatcher(&ssa).is_none(),
        "no back-edge predecessor must reject as not-a-dispatcher"
    );
}

#[test]
fn unflatten_chains_3_states_into_linear_blocks() {
    let mut ssa: SsaFunction = build_three_state_dispatcher();
    let info: DispatcherInfo = detect_dispatcher(&ssa).expect("detect");
    let stats: UnflattenStats = unflatten(&mut ssa, &info);
    assert_eq!(
        stats.cases_inlined, 2,
        "case0 and case1 both end with Br(dispatcher) + state write; case2 returns and is left alone"
    );
    assert_eq!(
        stats.blocks_removed, 1,
        "dispatcher header marked unreachable"
    );

    match &ssa.blocks[1].terminator {
        SsaTerm::Br(t) => assert_eq!(
            t.block,
            BlockId(2),
            "case0 writes state=1 -> next target must be cases[1] = block 2"
        ),
        other => panic!("expected Br after unflatten, got {other:?}"),
    }
    match &ssa.blocks[2].terminator {
        SsaTerm::Br(t) => assert_eq!(
            t.block,
            BlockId(3),
            "case1 writes state=2 -> next target must be cases[2] = block 3"
        ),
        other => panic!("expected Br after unflatten, got {other:?}"),
    }
    assert!(
        matches!(ssa.blocks[0].terminator, SsaTerm::Unreachable),
        "dispatcher's BrTable must be replaced by Unreachable for downstream DCE"
    );
}

#[test]
fn unflatten_leaves_non_dispatcher_terminators_alone() {
    let values: Vec<ValueDef> = vec![
        ValueDef::Param(BlockId(0), 0),
        ValueDef::Const(ConstVal::I32(99)),
        ValueDef::Op {
            kind: OpKind::I32Add,
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
            terminator: SsaTerm::Br(target(99)),
            preds: Vec::new(),
        },
        SsaBlock {
            id: BlockId(1),
            params: SmallVec::new(),
            instrs: Vec::new(),
            stores: Vec::new(),
            terminator: SsaTerm::Return(SmallVec::new()),
            preds: Vec::new(),
        },
    ];
    let mut ssa: SsaFunction = SsaFunction {
        values,
        blocks,
        entry: BlockId(0),
    };

    let mut cases: BTreeMap<i32, BlockId> = BTreeMap::new();
    cases.insert(0, BlockId(0));
    cases.insert(1, BlockId(1));
    let phony_info: DispatcherInfo = DispatcherInfo {
        header: BlockId(7),
        state_value: ValueId(0),
        cases,
    };

    let before_b0: String = format!("{:?}", ssa.blocks[0].terminator);
    let before_b1: String = format!("{:?}", ssa.blocks[1].terminator);
    let stats: UnflattenStats = unflatten(&mut ssa, &phony_info);
    let after_b0: String = format!("{:?}", ssa.blocks[0].terminator);
    let after_b1: String = format!("{:?}", ssa.blocks[1].terminator);

    assert_eq!(
        stats.cases_inlined, 0,
        "neither block branches to the phony dispatcher"
    );
    assert_eq!(stats.blocks_removed, 0);
    assert_eq!(before_b0, after_b0, "pure Br terminator unchanged");
    assert_eq!(before_b1, after_b1, "Return terminator unchanged");
}
