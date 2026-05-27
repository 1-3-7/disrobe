use smallvec::SmallVec;

use crate::cfg::BlockId;
use crate::ssa::{BlockTarget, ConstVal, SsaFunction, SsaTerm, ValueDef};

use super::dispatcher_detect::DispatcherInfo;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UnflattenStats {
    pub cases_inlined: usize,
    pub blocks_removed: usize,
}

pub fn unflatten(ssa: &mut SsaFunction, info: &DispatcherInfo) -> UnflattenStats {
    let mut stats: UnflattenStats = UnflattenStats::default();
    let case_blocks: Vec<BlockId> = info.cases.values().copied().collect();
    for case_id in case_blocks {
        if case_id == info.header {
            continue;
        }
        if rewrite_case_terminator(ssa, case_id, info) {
            stats.cases_inlined += 1;
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

fn last_state_write(ssa: &SsaFunction, block_id: BlockId) -> Option<i32> {
    let block: &crate::ssa::SsaBlock = ssa.blocks.get(block_id.0 as usize)?;
    for store in block.stores.iter().rev() {
        if let Some(ValueDef::Const(ConstVal::I32(n))) = ssa.value_def(store.val) {
            return Some(*n);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssa::{ConstVal, SideEffect, SsaBlock, SsaMemArg, ValueDef, ValueId};
    use crate::types::StoreKind;
    use smallvec::SmallVec;
    use std::collections::BTreeMap;

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
}
