use smallvec::SmallVec;

use crate::cfg::BlockId;
use crate::ssa::{BlockTarget, ConstVal, SsaFunction, SsaTerm, ValueDef};

use super::dispatcher_detect::{DispatcherInfo, detect_dispatcher};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UnflattenStats {
    pub cases_inlined: usize,
    pub blocks_removed: usize,
    pub iterations: usize,
}

const MAX_ITERATIONS: usize = 64;

/// Flattens a single detected dispatcher to a fixed point.
pub fn unflatten(ssa: &mut SsaFunction, info: &DispatcherInfo) -> UnflattenStats {
    let mut stats: UnflattenStats = UnflattenStats::default();
    let case_blocks: Vec<BlockId> = info.cases.values().copied().collect();
    loop {
        if stats.iterations >= MAX_ITERATIONS {
            break;
        }
        let mut inlined_this_round: usize = 0;
        for &case_id in &case_blocks {
            if case_id == info.header {
                continue;
            }
            if rewrite_case_terminator(ssa, case_id, info) {
                inlined_this_round += 1;
            }
        }
        stats.iterations += 1;
        stats.cases_inlined += inlined_this_round;
        if inlined_this_round == 0 {
            break;
        }
    }
    if stats.cases_inlined > 0 {
        if let Some(header) = ssa.blocks.get_mut(info.header.0 as usize) {
            header.terminator = SsaTerm::Unreachable;
            stats.blocks_removed = 1;
        }
    }
    stats
}

/// Detects and flattens every (including nested) dispatcher to a fixed point.
pub fn unflatten_to_fixed_point(ssa: &mut SsaFunction) -> UnflattenStats {
    let mut total: UnflattenStats = UnflattenStats::default();
    for _ in 0..MAX_ITERATIONS {
        let Some(info): Option<DispatcherInfo> = detect_dispatcher(ssa) else {
            break;
        };
        let round: UnflattenStats = unflatten(ssa, &info);
        total.cases_inlined += round.cases_inlined;
        total.blocks_removed += round.blocks_removed;
        total.iterations += round.iterations;
        if round.cases_inlined == 0 {
            break;
        }
    }
    total
}

fn rewrite_case_terminator(ssa: &mut SsaFunction, case_id: BlockId, info: &DispatcherInfo) -> bool {
    let Some(case_block): Option<&crate::ssa::SsaBlock> = ssa.blocks.get(case_id.0 as usize) else {
        return false;
    };
    if !terminator_branches_to(&case_block.terminator, info.header) {
        return false;
    }
    let Some(next_state): Option<i32> = last_state_write(ssa, case_id) else {
        return false;
    };
    let Some(&next_target): Option<&BlockId> = info.cases.get(&next_state) else {
        return false;
    };
    if next_target == case_id {
        return false;
    }
    if let Some(case_block) = ssa.blocks.get_mut(case_id.0 as usize) {
        case_block.terminator = SsaTerm::Br(BlockTarget {
            block: next_target,
            args: SmallVec::new(),
        });
        return true;
    }
    false
}

fn terminator_branches_to(term: &SsaTerm, target: BlockId) -> bool {
    match term {
        SsaTerm::Br(t) | SsaTerm::Fallthrough(t) => t.block == target,
        _ => false,
    }
}

/// Most recent constant write to the state variable in `block_id`.
fn last_state_write(ssa: &SsaFunction, block_id: BlockId) -> Option<i32> {
    let block: &crate::ssa::SsaBlock = ssa.blocks.get(block_id.0 as usize)?;
    for global_set in block.global_sets.iter().rev() {
        if let Some(n) = resolve_const_i32(ssa, global_set.val) {
            return Some(n);
        }
    }
    for store in block.stores.iter().rev() {
        if let Some(n) = resolve_const_i32(ssa, store.val) {
            return Some(n);
        }
    }
    None
}

fn resolve_const_i32(ssa: &SsaFunction, value: crate::ssa::ValueId) -> Option<i32> {
    resolve_const_i32_depth(ssa, value, 0)
}

fn resolve_const_i32_depth(
    ssa: &SsaFunction,
    value: crate::ssa::ValueId,
    depth: u32,
) -> Option<i32> {
    const MAX_DEPTH: u32 = 64;
    if depth >= MAX_DEPTH {
        return None;
    }
    match ssa.value_def(value)? {
        ValueDef::Const(ConstVal::I32(n)) => Some(*n),
        ValueDef::Unary { arg, .. } => resolve_const_i32_depth(ssa, *arg, depth + 1),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::ssa::{ConstVal, SideEffect, SsaBlock, SsaMemArg, ValueDef, ValueId};
    use crate::types::StoreKind;
    use smallvec::SmallVec;
    use std::collections::BTreeMap;
    use wasmparser::ValType;

    fn memarg() -> SsaMemArg {
        SsaMemArg {
            align: 2,
            offset: 0,
            memory: 0,
        }
    }

    #[test]
    fn last_state_write_returns_most_recent_i32_const_store() {
        let values: Vec<ValueDef> = vec![
            ValueDef::Const(ConstVal::I32(99)),
            ValueDef::Const(ConstVal::I32(7)),
            ValueDef::Const(ConstVal::I32(42)),
            ValueDef::Param(BlockId(0), 0),
        ];
        let blocks: Vec<SsaBlock> = vec![SsaBlock {
            id: BlockId(0),
            params: SmallVec::new(),
            instrs: Vec::new(),
            stores: vec![
                SideEffect {
                    addr: ValueId(3),
                    val: ValueId(0),
                    memarg: memarg(),
                    kind: StoreKind::I32,
                },
                SideEffect {
                    addr: ValueId(3),
                    val: ValueId(1),
                    memarg: memarg(),
                    kind: StoreKind::I32,
                },
                SideEffect {
                    addr: ValueId(3),
                    val: ValueId(2),
                    memarg: memarg(),
                    kind: StoreKind::I32,
                },
            ],
            global_sets: Vec::new(),
            terminator: SsaTerm::Unreachable,
            preds: Vec::new(),
        }];
        let ssa: SsaFunction = SsaFunction {
            values,
            blocks,
            entry: BlockId(0),
        };
        assert_eq!(last_state_write(&ssa, BlockId(0)), Some(42));
    }

    #[test]
    fn unflatten_skips_when_no_cases_inlined() {
        let mut ssa: SsaFunction = SsaFunction {
            values: Vec::new(),
            blocks: vec![SsaBlock {
                id: BlockId(0),
                params: SmallVec::new(),
                instrs: Vec::new(),
                stores: Vec::new(),
                global_sets: Vec::new(),
                terminator: SsaTerm::Return(SmallVec::new()),
                preds: Vec::new(),
            }],
            entry: BlockId(0),
        };
        let info: DispatcherInfo = DispatcherInfo {
            header: BlockId(0),
            state_value: ValueId(0),
            cases: BTreeMap::new(),
        };
        let stats: UnflattenStats = unflatten(&mut ssa, &info);
        assert_eq!(stats.cases_inlined, 0);
        assert_eq!(stats.blocks_removed, 0);
    }

    #[test]
    fn last_state_write_reads_global_set() {
        let values: Vec<ValueDef> = vec![ValueDef::Const(ConstVal::I32(5))];
        let blocks: Vec<SsaBlock> = vec![SsaBlock {
            id: BlockId(0),
            params: SmallVec::new(),
            instrs: Vec::new(),
            stores: Vec::new(),
            global_sets: vec![crate::ssa::GlobalSet {
                global: 0,
                val: ValueId(0),
            }],
            terminator: SsaTerm::Unreachable,
            preds: Vec::new(),
        }];
        let ssa: SsaFunction = SsaFunction {
            values,
            blocks,
            entry: BlockId(0),
        };
        assert_eq!(last_state_write(&ssa, BlockId(0)), Some(5));
    }

    fn case_block(id: u32, state_const: ValueId, target: u32) -> SsaBlock {
        SsaBlock {
            id: BlockId(id),
            params: SmallVec::new(),
            instrs: vec![state_const],
            stores: vec![SideEffect {
                addr: ValueId(0),
                val: state_const,
                memarg: memarg(),
                kind: StoreKind::I32,
            }],
            global_sets: Vec::new(),
            terminator: SsaTerm::Br(BlockTarget {
                block: BlockId(target),
                args: SmallVec::new(),
            }),
            preds: vec![BlockId(0)],
        }
    }

    #[test]
    fn fixed_point_chains_four_states_in_one_call() {
        let values: Vec<ValueDef> = vec![
            ValueDef::Load {
                addr: ValueId(4),
                memarg: memarg(),
                kind: crate::types::LoadKind::I32,
                ty: ValType::I32,
            },
            ValueDef::Const(ConstVal::I32(1)),
            ValueDef::Const(ConstVal::I32(2)),
            ValueDef::Const(ConstVal::I32(3)),
            ValueDef::Param(BlockId(0), 0),
        ];
        let dispatcher: SsaBlock = SsaBlock {
            id: BlockId(0),
            params: SmallVec::new(),
            instrs: vec![ValueId(0)],
            stores: Vec::new(),
            global_sets: Vec::new(),
            terminator: SsaTerm::BrTable {
                idx: ValueId(0),
                targets: vec![
                    BlockTarget {
                        block: BlockId(1),
                        args: SmallVec::new(),
                    },
                    BlockTarget {
                        block: BlockId(2),
                        args: SmallVec::new(),
                    },
                    BlockTarget {
                        block: BlockId(3),
                        args: SmallVec::new(),
                    },
                    BlockTarget {
                        block: BlockId(4),
                        args: SmallVec::new(),
                    },
                ],
                default: BlockTarget {
                    block: BlockId(5),
                    args: SmallVec::new(),
                },
            },
            preds: vec![BlockId(1), BlockId(2), BlockId(3)],
        };
        let blocks: Vec<SsaBlock> = vec![
            dispatcher,
            case_block(1, ValueId(1), 0),
            case_block(2, ValueId(2), 0),
            case_block(3, ValueId(3), 0),
            SsaBlock {
                id: BlockId(4),
                params: SmallVec::new(),
                instrs: Vec::new(),
                stores: Vec::new(),
                global_sets: Vec::new(),
                terminator: SsaTerm::Return(SmallVec::new()),
                preds: vec![BlockId(0)],
            },
            SsaBlock {
                id: BlockId(5),
                params: SmallVec::new(),
                instrs: Vec::new(),
                stores: Vec::new(),
                global_sets: Vec::new(),
                terminator: SsaTerm::Unreachable,
                preds: vec![BlockId(0)],
            },
        ];
        let mut ssa: SsaFunction = SsaFunction {
            values,
            blocks,
            entry: BlockId(0),
        };
        let stats: UnflattenStats = unflatten_to_fixed_point(&mut ssa);
        assert_eq!(stats.cases_inlined, 3, "case0->1->2->3 all chained");
        assert!(stats.blocks_removed >= 1, "dispatcher removed");
        match &ssa.blocks[1].terminator {
            SsaTerm::Br(t) => assert_eq!(t.block, BlockId(2)),
            other => panic!("expected Br, got {other:?}"),
        }
        match &ssa.blocks[3].terminator {
            SsaTerm::Br(t) => assert_eq!(t.block, BlockId(4)),
            other => panic!("expected Br to exit, got {other:?}"),
        }
        assert!(matches!(ssa.blocks[0].terminator, SsaTerm::Unreachable));
    }
}
