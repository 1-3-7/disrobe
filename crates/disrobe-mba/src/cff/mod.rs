#![allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is the right visibility for these crate-internal control-flow-flattening helpers; redundant_pub_crate (nursery) and the workspace unreachable_pub lint cannot both hold for a private submodule, matching the crate-level allow already shipped across the workspace"
)]

use std::collections::{BTreeMap, BTreeSet};

use disrobe_nir::{NirBlock, NirFunction, basic_blocks};

mod cheap;
mod detect;
mod types;

#[cfg(feature = "smt-solver")]
mod solver;

use cheap::{CheapResolution, cheap_initial, cheap_resolve_block};
use detect::{MAX_CFF_BLOCKS, Plan, detect};

pub use types::{
    BlockRole, CanaryViolation, CffAbstain, CffOutcome, DegradeReason, DevirtEdge, DevirtNote,
    EdgeGuard, RecoveredCfg,
};

#[cfg(feature = "smt-solver")]
pub use solver::{
    CffTrace, devirtualize, devirtualize_table_dispatch, devirtualize_traced, devirtualize_with,
};

const CHEAP_LOOP_CAP: u32 = 8;

#[must_use]
pub fn devirtualize_cheap(function: &NirFunction) -> CffOutcome {
    let blocks_list: Vec<NirBlock> = basic_blocks(function);
    if blocks_list.is_empty() {
        return CffOutcome::Abstain(CffAbstain::NotFlattened);
    }
    if blocks_list.len() > MAX_CFF_BLOCKS {
        return CffOutcome::Abstain(CffAbstain::TooManyBlocks);
    }
    let blocks: BTreeMap<u64, NirBlock> = blocks_list
        .into_iter()
        .map(|block: NirBlock| (block.start, block))
        .collect();
    let entry_block: u64 = if blocks.contains_key(&function.address) {
        function.address
    } else {
        match blocks.keys().next() {
            Some(first) => *first,
            None => return CffOutcome::Abstain(CffAbstain::NotFlattened),
        }
    };
    let plan: Plan = match detect(&blocks, entry_block) {
        Ok(plan) => plan,
        Err(reason) => return CffOutcome::Abstain(reason),
    };
    let case_heads: BTreeSet<u64> = plan.casemap.values().copied().collect();
    let Some(entry_real): Option<u64> = cheap_initial(&blocks, &plan, &case_heads, CHEAP_LOOP_CAP)
    else {
        return CffOutcome::Abstain(CffAbstain::InitialStateUnknown);
    };
    let mut edges: Vec<DevirtEdge> = Vec::new();
    let mut roles: BTreeMap<u64, BlockRole> = BTreeMap::new();
    let mut notes: Vec<DevirtNote> = Vec::new();
    for (&case_value, &block) in &plan.casemap {
        match cheap_resolve_block(
            &blocks,
            &plan,
            &case_heads,
            case_value,
            block,
            CHEAP_LOOP_CAP,
        ) {
            CheapResolution::Resolved { targets } => {
                let guard: EdgeGuard = if targets.len() > 1 {
                    EdgeGuard::Branch
                } else {
                    EdgeGuard::Direct
                };
                roles.insert(block, BlockRole::Resolved);
                for to in targets {
                    edges.push(DevirtEdge {
                        from: block,
                        to,
                        guard,
                    });
                }
            }
            CheapResolution::Terminal => {
                roles.insert(block, BlockRole::Terminal);
            }
            CheapResolution::Degrade(reason) => {
                roles.insert(block, BlockRole::Unresolved);
                notes.push(DevirtNote { block, reason });
            }
            CheapResolution::NeedsSolver => {
                roles.insert(block, BlockRole::Unresolved);
                notes.push(DevirtNote {
                    block,
                    reason: DegradeReason::RequiresSolver,
                });
            }
        }
    }
    edges.sort_by_key(|edge: &DevirtEdge| (edge.from, edge.to));
    edges.dedup_by(|a: &mut DevirtEdge, b: &mut DevirtEdge| a.from == b.from && a.to == b.to);
    let mut cases: Vec<u64> = plan.casemap.values().copied().collect();
    cases.sort_unstable();
    cases.dedup();
    let mut scaffolding: Vec<u64> = plan.scaffolding.iter().copied().collect();
    scaffolding.sort_unstable();
    CffOutcome::Recovered(RecoveredCfg {
        entry: entry_real,
        state_var: plan.state_var,
        cases,
        edges,
        scaffolding,
        roles,
        notes,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use disrobe_nir::{NirInstr, NirOp, SourceLang, SourceRef, ValueOp};

    use super::*;

    fn raw(address: u64, op: NirOp, operands: &[&str]) -> NirInstr {
        NirInstr {
            address,
            op,
            mnemonic: String::new(),
            operands: operands
                .iter()
                .map(|item: &&str| (*item).to_owned())
                .collect(),
            reads_memory: false,
            writes_memory: false,
            byte_width: false,
            source: SourceRef::new(SourceLang::NativeX86, address),
        }
    }

    fn cmp_eq(address: u64, dest: &str, var: &str, constant: &str) -> NirInstr {
        raw(
            address,
            NirOp::Value {
                op: ValueOp::IntEqual,
                inputs: vec![var.to_owned(), constant.to_owned()],
                input_sizes: vec![4, 4],
                size: 1,
            },
            &[dest],
        )
    }

    fn cmp_data(address: u64, dest: &str, lhs: &str, rhs: &str) -> NirInstr {
        raw(
            address,
            NirOp::Value {
                op: ValueOp::IntEqual,
                inputs: vec![lhs.to_owned(), rhs.to_owned()],
                input_sizes: vec![4, 4],
                size: 1,
            },
            &[dest],
        )
    }

    fn cmp_less(address: u64, dest: &str, lhs: &str, rhs: &str) -> NirInstr {
        raw(
            address,
            NirOp::Value {
                op: ValueOp::IntLess,
                inputs: vec![lhs.to_owned(), rhs.to_owned()],
                input_sizes: vec![4, 4],
                size: 1,
            },
            &[dest],
        )
    }

    fn set_state(address: u64, sv: &str, value: &str) -> NirInstr {
        raw(
            address,
            NirOp::Copy {
                src: value.to_owned(),
                size: 4,
            },
            &[sv],
        )
    }

    fn function(instructions: Vec<NirInstr>, end: u64) -> NirFunction {
        NirFunction {
            name: "flat".to_owned(),
            address: 0x0,
            end,
            is_export: false,
            instructions,
            source: SourceRef::new(SourceLang::NativeX86, 0x0),
        }
    }

    fn dispatch_head() -> Vec<NirInstr> {
        vec![
            cmp_eq(0x10, "e0", "sv", "0"),
            raw(0x14, NirOp::CondBranch { target: Some(0x40) }, &["e0"]),
            cmp_eq(0x18, "e1", "sv", "1"),
            raw(0x1c, NirOp::CondBranch { target: Some(0x50) }, &["e1"]),
            cmp_eq(0x20, "e2", "sv", "2"),
            raw(0x24, NirOp::CondBranch { target: Some(0x60) }, &["e2"]),
            raw(0x28, NirOp::Return, &[]),
        ]
    }

    fn straight_flattened() -> NirFunction {
        function(
            vec![
                set_state(0x00, "sv", "0"),
                raw(0x04, NirOp::Branch { target: Some(0x10) }, &[]),
                cmp_eq(0x10, "e0", "sv", "0"),
                raw(0x14, NirOp::CondBranch { target: Some(0x40) }, &["e0"]),
                cmp_eq(0x18, "e1", "sv", "1"),
                raw(0x1c, NirOp::CondBranch { target: Some(0x50) }, &["e1"]),
                cmp_eq(0x20, "e2", "sv", "2"),
                raw(0x24, NirOp::CondBranch { target: Some(0x60) }, &["e2"]),
                raw(0x28, NirOp::Return, &[]),
                set_state(0x40, "sv", "1"),
                raw(0x44, NirOp::Branch { target: Some(0x10) }, &[]),
                set_state(0x50, "sv", "2"),
                raw(0x54, NirOp::Branch { target: Some(0x10) }, &[]),
                raw(0x60, NirOp::Return, &[]),
            ],
            0x64,
        )
    }

    #[test]
    fn cheap_only_recovers_the_constant_state_chain() {
        let CffOutcome::Recovered(cfg) = devirtualize_cheap(&straight_flattened()) else {
            panic!("the constant state-chain must devirtualize with no solver");
        };
        assert_eq!(cfg.entry, 0x40);
        assert_eq!(cfg.edge_set(), BTreeSet::from([(0x40, 0x50), (0x50, 0x60)]));
        assert_eq!(cfg.roles.get(&0x60), Some(&BlockRole::Terminal));
        assert!(cfg.notes.is_empty());
        assert!(cfg.canary().is_ok());
    }

    #[test]
    fn cheap_only_recovers_the_conditional_diamond() {
        let mut instrs: Vec<NirInstr> = vec![
            set_state(0x00, "sv", "0"),
            raw(0x04, NirOp::Branch { target: Some(0x10) }, &[]),
        ];
        instrs.extend(dispatch_head());
        instrs.extend(vec![
            cmp_data(0x40, "c", "a", "b"),
            raw(0x44, NirOp::CondBranch { target: Some(0x4c) }, &["c"]),
            set_state(0x48, "sv", "1"),
            raw(0x4a, NirOp::Branch { target: Some(0x10) }, &[]),
            set_state(0x4c, "sv", "2"),
            raw(0x4e, NirOp::Branch { target: Some(0x10) }, &[]),
            set_state(0x50, "sv", "2"),
            raw(0x54, NirOp::Branch { target: Some(0x10) }, &[]),
            raw(0x60, NirOp::Return, &[]),
        ]);
        let CffOutcome::Recovered(cfg) = devirtualize_cheap(&function(instrs, 0x64)) else {
            panic!("a free-input diamond must devirtualize with no solver");
        };
        assert_eq!(cfg.entry, 0x40);
        assert_eq!(
            cfg.edge_set(),
            BTreeSet::from([(0x40, 0x50), (0x40, 0x60), (0x50, 0x60)])
        );
        assert!(
            cfg.edges
                .iter()
                .filter(|edge: &&DevirtEdge| edge.from == 0x40)
                .all(|edge: &DevirtEdge| edge.guard == EdgeGuard::Branch)
        );
        assert!(cfg.notes.is_empty());
        assert!(cfg.canary().is_ok());
    }

    #[test]
    fn cheap_only_defers_an_ordering_branch_without_dropping_the_backbone() {
        let mut instrs: Vec<NirInstr> = vec![
            set_state(0x00, "sv", "0"),
            raw(0x04, NirOp::Branch { target: Some(0x10) }, &[]),
        ];
        instrs.extend(dispatch_head());
        instrs.extend(vec![
            cmp_less(0x40, "c", "a", "5"),
            raw(0x44, NirOp::CondBranch { target: Some(0x4c) }, &["c"]),
            set_state(0x48, "sv", "1"),
            raw(0x4a, NirOp::Branch { target: Some(0x10) }, &[]),
            set_state(0x4c, "sv", "2"),
            raw(0x4e, NirOp::Branch { target: Some(0x10) }, &[]),
            set_state(0x50, "sv", "2"),
            raw(0x54, NirOp::Branch { target: Some(0x10) }, &[]),
            raw(0x60, NirOp::Return, &[]),
        ]);
        let CffOutcome::Recovered(cfg) = devirtualize_cheap(&function(instrs, 0x64)) else {
            panic!("the backbone must survive even when one block defers");
        };
        assert_eq!(cfg.roles.get(&0x40), Some(&BlockRole::Unresolved));
        assert!(cfg.notes.contains(&DevirtNote {
            block: 0x40,
            reason: DegradeReason::RequiresSolver,
        }));
        assert!(
            !cfg.edge_set()
                .iter()
                .any(|(from, _): &(u64, u64)| *from == 0x40),
            "no edge may be invented for the deferred block"
        );
        assert_eq!(cfg.roles.get(&0x50), Some(&BlockRole::Resolved));
        assert_eq!(cfg.roles.get(&0x60), Some(&BlockRole::Terminal));
        assert!(cfg.canary().is_ok());
    }

    #[test]
    fn cheap_only_abstains_on_a_plain_switch() {
        let switch: NirFunction = function(
            vec![
                cmp_eq(0x00, "e0", "x", "0"),
                raw(0x04, NirOp::CondBranch { target: Some(0x40) }, &["e0"]),
                cmp_eq(0x08, "e1", "x", "1"),
                raw(0x0c, NirOp::CondBranch { target: Some(0x50) }, &["e1"]),
                cmp_eq(0x10, "e2", "x", "2"),
                raw(0x14, NirOp::CondBranch { target: Some(0x60) }, &["e2"]),
                raw(0x18, NirOp::Return, &[]),
                raw(0x40, NirOp::Return, &[]),
                raw(0x50, NirOp::Return, &[]),
                raw(0x60, NirOp::Return, &[]),
            ],
            0x64,
        );
        assert!(devirtualize_cheap(&switch).is_abstain());
    }
}
