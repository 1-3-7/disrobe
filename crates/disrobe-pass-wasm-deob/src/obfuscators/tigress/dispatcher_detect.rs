use std::collections::BTreeMap;

use crate::cfg::BlockId;
use crate::ssa::{SsaFunction, SsaTerm, ValueDef, ValueId};

#[derive(Debug, Clone)]
pub struct DispatcherInfo {
    pub header: BlockId,
    pub state_value: ValueId,
    pub cases: BTreeMap<i32, BlockId>,
}

pub fn detect_dispatcher(ssa: &SsaFunction) -> Option<DispatcherInfo> {
    for block in &ssa.blocks {
        let SsaTerm::BrTable { idx, targets, .. }: &SsaTerm = &block.terminator else {
            continue;
        };
        if !has_back_edge(ssa, block.id) {
            continue;
        }
        if !is_state_variable(ssa, *idx) {
            continue;
        }
        let cases: BTreeMap<i32, BlockId> = build_case_map(targets);
        return Some(DispatcherInfo {
            header: block.id,
            state_value: *idx,
            cases,
        });
    }
    None
}

fn has_back_edge(ssa: &SsaFunction, header: BlockId) -> bool {
    let Some(header_block): Option<&crate::ssa::SsaBlock> = ssa.blocks.get(header.0 as usize)
    else {
        return false;
    };
    header_block
        .preds
        .iter()
        .any(|pred| branches_to(ssa, *pred, header))
}

fn branches_to(ssa: &SsaFunction, from: BlockId, target: BlockId) -> bool {
    let Some(block): Option<&crate::ssa::SsaBlock> = ssa.blocks.get(from.0 as usize) else {
        return false;
    };
    match &block.terminator {
        SsaTerm::Br(t) | SsaTerm::Fallthrough(t) => t.block == target,
        SsaTerm::BrIf { then_t, else_t, .. } => then_t.block == target || else_t.block == target,
        SsaTerm::BrTable {
            targets, default, ..
        } => default.block == target || targets.iter().any(|t| t.block == target),
        SsaTerm::Return(_) | SsaTerm::Unreachable => false,
    }
}

fn is_state_variable(ssa: &SsaFunction, v: ValueId) -> bool {
    let Some(def): Option<&ValueDef> = ssa.value_def(v) else {
        return false;
    };
    match def {
        ValueDef::Phi { .. } => true,
        ValueDef::Load { addr, .. } => load_addr_roots_in_param(ssa, *addr),
        _ => false,
    }
}

fn load_addr_roots_in_param(ssa: &SsaFunction, v: ValueId) -> bool {
    load_addr_roots_in_param_depth(ssa, v, 0)
}

fn load_addr_roots_in_param_depth(ssa: &SsaFunction, v: ValueId, depth: u32) -> bool {
    const MAX_DEPTH: u32 = 1024;
    if depth >= MAX_DEPTH {
        return false;
    }
    let Some(def): Option<&ValueDef> = ssa.value_def(v) else {
        return false;
    };
    match def {
        ValueDef::Param(_, _) => true,
        ValueDef::Op { args, .. } => args
            .iter()
            .any(|a| load_addr_roots_in_param_depth(ssa, *a, depth + 1)),
        ValueDef::Unary { arg, .. } => load_addr_roots_in_param_depth(ssa, *arg, depth + 1),
        ValueDef::Load { addr, .. } => load_addr_roots_in_param_depth(ssa, *addr, depth + 1),
        _ => false,
    }
}

fn build_case_map(targets: &[crate::ssa::BlockTarget]) -> BTreeMap<i32, BlockId> {
    let mut out: BTreeMap<i32, BlockId> = BTreeMap::new();
    for (i, t) in targets.iter().enumerate() {
        let state_value: i32 = i32::try_from(i).unwrap_or(i32::MAX);
        out.insert(state_value, t.block);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssa::{BlockTarget, ConstVal, SsaBlock, SsaFunction};
    use smallvec::SmallVec;
    use wasmparser::ValType;

    fn empty_br_target(b: u32) -> BlockTarget {
        BlockTarget {
            block: BlockId(b),
            args: SmallVec::new(),
        }
    }

    #[test]
    fn build_case_map_indexes_by_table_position() {
        let targets: Vec<BlockTarget> = vec![
            empty_br_target(10),
            empty_br_target(11),
            empty_br_target(12),
        ];
        let cases: BTreeMap<i32, BlockId> = build_case_map(&targets);
        assert_eq!(cases.get(&0).copied(), Some(BlockId(10)));
        assert_eq!(cases.get(&1).copied(), Some(BlockId(11)));
        assert_eq!(cases.get(&2).copied(), Some(BlockId(12)));
    }

    #[test]
    fn load_addr_rooted_in_param_returns_true_through_op_chain() {
        let values: Vec<ValueDef> = vec![
            ValueDef::Param(BlockId(0), 0),
            ValueDef::Const(ConstVal::I32(4)),
            ValueDef::Op {
                kind: crate::ssa::OpKind::I32Add,
                args: smallvec::smallvec![ValueId(0), ValueId(1)],
                ty: ValType::I32,
            },
        ];
        let ssa: SsaFunction = SsaFunction {
            values,
            blocks: vec![SsaBlock {
                id: BlockId(0),
                params: SmallVec::new(),
                instrs: Vec::new(),
                stores: Vec::new(),
                global_sets: Vec::new(),
                terminator: SsaTerm::Unreachable,
                preds: Vec::new(),
            }],
            entry: BlockId(0),
        };
        assert!(load_addr_roots_in_param(&ssa, ValueId(2)));
    }

    #[test]
    fn const_alone_is_not_a_state_variable() {
        let values: Vec<ValueDef> = vec![ValueDef::Const(ConstVal::I32(7))];
        let ssa: SsaFunction = SsaFunction {
            values,
            blocks: vec![SsaBlock {
                id: BlockId(0),
                params: SmallVec::new(),
                instrs: Vec::new(),
                stores: Vec::new(),
                global_sets: Vec::new(),
                terminator: SsaTerm::Unreachable,
                preds: Vec::new(),
            }],
            entry: BlockId(0),
        };
        assert!(!is_state_variable(&ssa, ValueId(0)));
    }
}
