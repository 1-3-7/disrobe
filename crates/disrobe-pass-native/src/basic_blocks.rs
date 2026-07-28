use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

pub(crate) const MAX_BLOCKS: usize = 256;

pub(crate) const MAX_BLOCK_INSNS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transfer {
    FallsThrough,
    Terminal { returns: bool },
    ConditionalBranch { taken: u64 },
    UnconditionalBranch { taken: u64 },
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BasicBlock {
    pub(crate) insns: Range<usize>,
    pub(crate) successors: Vec<usize>,
    pub(crate) returns: bool,
}

pub(crate) fn build_cfg(
    transfers: &[Transfer],
    positions: &BTreeMap<u64, usize>,
    entry: usize,
) -> Option<Vec<BasicBlock>> {
    let leaders: BTreeSet<usize> = collect_leaders(transfers, positions, entry)?;
    let ordered: Vec<usize> = leaders.into_iter().collect();
    if ordered.len() > MAX_BLOCKS {
        return None;
    }
    let block_of: BTreeMap<usize, usize> = ordered
        .iter()
        .enumerate()
        .map(|(block, leader): (usize, &usize)| (*leader, block))
        .collect();

    let mut blocks: Vec<BasicBlock> = Vec::with_capacity(ordered.len());
    for (position, leader) in ordered.iter().copied().enumerate() {
        let next_leader: usize = ordered
            .get(position.saturating_add(1))
            .copied()
            .unwrap_or(transfers.len());
        blocks.push(build_block(
            transfers,
            positions,
            leader,
            next_leader,
            &block_of,
        )?);
    }

    let entry_block: usize = *block_of.get(&entry)?;
    if entry_block != 0 {
        blocks.swap(0, entry_block);
        for block in &mut blocks {
            for successor in &mut block.successors {
                *successor = swap_ends(*successor, entry_block);
            }
        }
    }
    Some(blocks)
}

const fn swap_ends(block: usize, entry_block: usize) -> usize {
    if block == 0 {
        entry_block
    } else if block == entry_block {
        0
    } else {
        block
    }
}

fn collect_leaders(
    transfers: &[Transfer],
    positions: &BTreeMap<u64, usize>,
    entry: usize,
) -> Option<BTreeSet<usize>> {
    let mut leaders: BTreeSet<usize> = BTreeSet::from([entry]);
    let mut worklist: Vec<usize> = vec![entry];
    let mut visited: BTreeSet<usize> = BTreeSet::new();

    while let Some(leader) = worklist.pop() {
        if !visited.insert(leader) {
            continue;
        }
        if visited.len() > MAX_BLOCKS {
            return None;
        }
        let mut cursor: usize = leader;
        let limit: usize = leader.saturating_add(MAX_BLOCK_INSNS);
        loop {
            if cursor > limit {
                return None;
            }
            match *transfers.get(cursor)? {
                Transfer::FallsThrough => cursor = cursor.checked_add(1)?,
                Transfer::Terminal { .. } => break,
                Transfer::ConditionalBranch { taken } => {
                    let taken: usize = *positions.get(&taken)?;
                    let fallthrough: usize = cursor.checked_add(1)?;
                    if fallthrough >= transfers.len() {
                        return None;
                    }
                    leaders.insert(taken);
                    leaders.insert(fallthrough);
                    worklist.push(taken);
                    worklist.push(fallthrough);
                    break;
                }
                Transfer::UnconditionalBranch { taken } => {
                    let target: usize = *positions.get(&taken)?;
                    leaders.insert(target);
                    worklist.push(target);
                    break;
                }
                Transfer::Unresolved => return None,
            }
        }
    }
    Some(leaders)
}

fn build_block(
    transfers: &[Transfer],
    positions: &BTreeMap<u64, usize>,
    leader: usize,
    next_leader: usize,
    block_of: &BTreeMap<usize, usize>,
) -> Option<BasicBlock> {
    let mut cursor: usize = leader;
    let limit: usize = leader.saturating_add(MAX_BLOCK_INSNS);
    loop {
        if cursor > limit {
            return None;
        }
        let transfer: Transfer = *transfers.get(cursor)?;
        let end: usize = cursor.checked_add(1)?;
        match transfer {
            Transfer::FallsThrough => {
                if end == next_leader {
                    return Some(BasicBlock {
                        insns: leader..end,
                        successors: vec![*block_of.get(&next_leader)?],
                        returns: false,
                    });
                }
                cursor = end;
            }
            Transfer::Terminal { returns } => {
                return Some(BasicBlock {
                    insns: leader..end,
                    successors: Vec::new(),
                    returns,
                });
            }
            Transfer::ConditionalBranch { taken } => {
                let taken: usize = *block_of.get(positions.get(&taken)?)?;
                let fallthrough: usize = *block_of.get(&end)?;
                return Some(BasicBlock {
                    insns: leader..end,
                    successors: vec![taken, fallthrough],
                    returns: false,
                });
            }
            Transfer::UnconditionalBranch { taken } => {
                let target: usize = *block_of.get(positions.get(&taken)?)?;
                return Some(BasicBlock {
                    insns: leader..end,
                    successors: vec![target],
                    returns: false,
                });
            }
            Transfer::Unresolved => return None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn positions(count: usize) -> BTreeMap<u64, usize> {
        (0..count)
            .map(|index: usize| (index as u64 * 4, index))
            .collect()
    }

    #[test]
    fn a_straight_line_body_is_one_block() {
        let transfers: [Transfer; 3] = [
            Transfer::FallsThrough,
            Transfer::FallsThrough,
            Transfer::Terminal { returns: true },
        ];
        let blocks: Vec<BasicBlock> =
            build_cfg(&transfers, &positions(3), 0).expect("a returning body partitions");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].insns, 0..3);
        assert!(blocks[0].successors.is_empty());
        assert!(blocks[0].returns);
    }

    #[test]
    fn a_forward_conditional_branch_yields_a_diamond() {
        let transfers: [Transfer; 4] = [
            Transfer::ConditionalBranch { taken: 8 },
            Transfer::FallsThrough,
            Transfer::FallsThrough,
            Transfer::Terminal { returns: true },
        ];
        let blocks: Vec<BasicBlock> =
            build_cfg(&transfers, &positions(4), 0).expect("a diamond partitions");
        assert_eq!(blocks.len(), 3, "entry, fallthrough, join: {blocks:?}");
        assert_eq!(blocks[0].successors, vec![2, 1]);
        assert_eq!(blocks[1].successors, vec![2]);
        assert!(blocks[2].successors.is_empty());
    }

    #[test]
    fn instructions_behind_a_return_never_become_a_block() {
        let transfers: [Transfer; 4] = [
            Transfer::FallsThrough,
            Transfer::Terminal { returns: true },
            Transfer::FallsThrough,
            Transfer::FallsThrough,
        ];
        let blocks: Vec<BasicBlock> =
            build_cfg(&transfers, &positions(4), 0).expect("trailing padding is dropped");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].insns, 0..2, "the padding stays outside the body");
    }

    #[test]
    fn a_backward_branch_closes_a_loop() {
        let transfers: [Transfer; 3] = [
            Transfer::FallsThrough,
            Transfer::ConditionalBranch { taken: 0 },
            Transfer::Terminal { returns: true },
        ];
        let blocks: Vec<BasicBlock> =
            build_cfg(&transfers, &positions(3), 0).expect("a loop partitions");
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].successors, vec![0, 1]);
        assert_eq!(blocks[1].insns, 2..3);
    }

    #[test]
    fn an_unresolved_transfer_refuses_the_whole_body() {
        let transfers: [Transfer; 2] = [Transfer::Unresolved, Transfer::Terminal { returns: true }];
        assert!(build_cfg(&transfers, &positions(2), 0).is_none());
    }

    #[test]
    fn a_branch_leaving_the_body_refuses_the_whole_body() {
        let transfers: [Transfer; 2] = [
            Transfer::UnconditionalBranch { taken: 0x4000 },
            Transfer::Terminal { returns: true },
        ];
        assert!(build_cfg(&transfers, &positions(2), 0).is_none());
    }

    #[test]
    fn a_body_that_runs_off_its_end_refuses() {
        let transfers: [Transfer; 2] = [Transfer::FallsThrough, Transfer::FallsThrough];
        assert!(build_cfg(&transfers, &positions(2), 0).is_none());
    }

    #[test]
    fn an_entry_that_is_not_the_lowest_leader_becomes_block_zero() {
        let transfers: [Transfer; 3] = [
            Transfer::Terminal { returns: true },
            Transfer::UnconditionalBranch { taken: 0 },
            Transfer::Terminal { returns: true },
        ];
        let blocks: Vec<BasicBlock> =
            build_cfg(&transfers, &positions(3), 1).expect("entry at index one partitions");
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].insns, 1..2, "the entry leader owns block zero");
        assert_eq!(blocks[0].successors, vec![1]);
        assert_eq!(blocks[1].insns, 0..1);
    }
}
