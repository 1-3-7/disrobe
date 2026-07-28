use std::collections::{BTreeMap, BTreeSet};

use super::cfg::{VmBlock, VmCfg};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StructuredNode {
    Linear {
        block_offset: u32,
    },
    Loop {
        header_offset: u32,
        body: Vec<Self>,
    },
    IfElse {
        head_offset: u32,
        then_branch: Vec<Self>,
        else_branch: Vec<Self>,
    },
}

#[must_use]
pub fn structure_program(cfg: &VmCfg) -> Vec<StructuredNode> {
    let order: Vec<u32> = reverse_postorder(cfg);
    let back_edges: BTreeSet<(u32, u32)> = find_back_edges(cfg, &order);
    let block_index: BTreeMap<u32, &VmBlock> = cfg
        .blocks
        .iter()
        .map(|b: &VmBlock| (b.start_offset, b))
        .collect();

    let mut nodes: Vec<StructuredNode> = Vec::new();
    let mut loop_headers: BTreeMap<u32, u32> = BTreeMap::new();
    for (tail, header) in &back_edges {
        loop_headers
            .entry(*header)
            .and_modify(|t: &mut u32| *t = (*t).max(*tail))
            .or_insert(*tail);
    }

    let mut handled: BTreeSet<u32> = BTreeSet::new();
    for offset in &order {
        if handled.contains(offset) {
            continue;
        }
        if let Some(tail) = loop_headers.get(offset) {
            let body_set: BTreeSet<u32> = disrobe_core::dominators::natural_loop_body(
                *offset,
                &[*tail],
                |node: u32, emit: &mut dyn FnMut(u32)| {
                    for block in &cfg.blocks {
                        if block.successors.contains(&node) {
                            emit(block.start_offset);
                        }
                    }
                },
            );
            let mut body: Vec<StructuredNode> = Vec::new();
            for body_off in &order {
                if body_set.contains(body_off) && !handled.contains(body_off) {
                    body.push(StructuredNode::Linear {
                        block_offset: *body_off,
                    });
                    handled.insert(*body_off);
                }
            }
            nodes.push(StructuredNode::Loop {
                header_offset: *offset,
                body,
            });
            continue;
        }
        if let Some(block) = block_index.get(offset)
            && let Some(if_node) = try_if_else(cfg, block, &back_edges, &handled)
        {
            mark_handled(&if_node, &mut handled);
            handled.insert(*offset);
            nodes.push(if_node);
            continue;
        }
        nodes.push(StructuredNode::Linear {
            block_offset: *offset,
        });
        handled.insert(*offset);
    }
    nodes
}

fn try_if_else(
    cfg: &VmCfg,
    block: &VmBlock,
    back_edges: &BTreeSet<(u32, u32)>,
    handled: &BTreeSet<u32>,
) -> Option<StructuredNode> {
    let branch: u32 = block.branch?;
    let fallthrough: u32 = block.fallthrough?;
    if branch == fallthrough {
        return None;
    }
    if back_edges.contains(&(block.start_offset, branch))
        || back_edges.contains(&(block.start_offset, fallthrough))
    {
        return None;
    }
    let join: Option<u32> = find_join(cfg, branch, fallthrough);
    let then_blocks: Vec<u32> = linear_run(cfg, fallthrough, join, handled);
    let else_blocks: Vec<u32> = linear_run(cfg, branch, join, handled);
    if then_blocks.is_empty() && else_blocks.is_empty() {
        return None;
    }
    Some(StructuredNode::IfElse {
        head_offset: block.start_offset,
        then_branch: then_blocks
            .into_iter()
            .map(|o: u32| StructuredNode::Linear { block_offset: o })
            .collect(),
        else_branch: else_blocks
            .into_iter()
            .map(|o: u32| StructuredNode::Linear { block_offset: o })
            .collect(),
    })
}

fn linear_run(cfg: &VmCfg, start: u32, stop: Option<u32>, handled: &BTreeSet<u32>) -> Vec<u32> {
    let mut out: Vec<u32> = Vec::new();
    let mut cursor: Option<u32> = Some(start);
    let mut guard: usize = 0;
    while let Some(off) = cursor {
        guard += 1;
        if guard > cfg.blocks.len() + 1 {
            break;
        }
        if Some(off) == stop || handled.contains(&off) {
            break;
        }
        let block: &VmBlock = match cfg.block_at(off) {
            Some(b) => b,
            None => break,
        };
        out.push(off);
        if block.branch.is_some() {
            break;
        }
        cursor = block.fallthrough;
    }
    out
}

fn find_join(cfg: &VmCfg, a: u32, b: u32) -> Option<u32> {
    let reach_a: BTreeSet<u32> = reachable(cfg, a);
    let reach_b: BTreeSet<u32> = reachable(cfg, b);
    cfg.blocks
        .iter()
        .map(|blk: &VmBlock| blk.start_offset)
        .filter(|o: &u32| reach_a.contains(o) && reach_b.contains(o))
        .min()
}

fn reachable(cfg: &VmCfg, start: u32) -> BTreeSet<u32> {
    let mut seen: BTreeSet<u32> = BTreeSet::new();
    let mut stack: Vec<u32> = vec![start];
    while let Some(off) = stack.pop() {
        if !seen.insert(off) {
            continue;
        }
        if let Some(block) = cfg.block_at(off) {
            for s in &block.successors {
                if !seen.contains(s) {
                    stack.push(*s);
                }
            }
        }
    }
    seen
}

fn mark_handled(node: &StructuredNode, handled: &mut BTreeSet<u32>) {
    match node {
        StructuredNode::Linear { block_offset } => {
            handled.insert(*block_offset);
        }
        StructuredNode::Loop {
            header_offset,
            body,
        } => {
            handled.insert(*header_offset);
            for child in body {
                mark_handled(child, handled);
            }
        }
        StructuredNode::IfElse {
            head_offset,
            then_branch,
            else_branch,
        } => {
            handled.insert(*head_offset);
            for child in then_branch {
                mark_handled(child, handled);
            }
            for child in else_branch {
                mark_handled(child, handled);
            }
        }
    }
}

fn reverse_postorder(cfg: &VmCfg) -> Vec<u32> {
    let mut visited: BTreeSet<u32> = BTreeSet::new();
    let mut post: Vec<u32> = Vec::new();
    let mut stack: Vec<(u32, usize)> = vec![(cfg.entry, 0)];
    if cfg.block_at(cfg.entry).is_none()
        && let Some(first) = cfg.blocks.first()
    {
        stack = vec![(first.start_offset, 0)];
    }
    while let Some((off, child_idx)) = stack.pop() {
        visited.insert(off);
        let block: Option<&VmBlock> = cfg.block_at(off);
        let succ: Vec<u32> = block.map_or_else(Vec::new, |b: &VmBlock| b.successors.clone());
        if child_idx < succ.len() {
            stack.push((off, child_idx + 1));
            let next: u32 = succ[child_idx];
            if !visited.contains(&next) {
                stack.push((next, 0));
            }
        } else {
            post.push(off);
        }
    }
    post.reverse();
    for block in &cfg.blocks {
        if !post.contains(&block.start_offset) {
            post.push(block.start_offset);
        }
    }
    post
}

fn find_back_edges(cfg: &VmCfg, order: &[u32]) -> BTreeSet<(u32, u32)> {
    let position: BTreeMap<u32, usize> = order
        .iter()
        .enumerate()
        .map(|(i, o): (usize, &u32)| (*o, i))
        .collect();
    let mut edges: BTreeSet<(u32, u32)> = BTreeSet::new();
    for block in &cfg.blocks {
        let from: usize = match position.get(&block.start_offset).copied() {
            Some(value) => value,
            None => continue,
        };
        for succ in &block.successors {
            let to: usize = match position.get(succ).copied() {
                Some(value) => value,
                None => continue,
            };
            if to <= from {
                edges.insert((block.start_offset, *succ));
            }
        }
    }
    edges
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::vm_devirt::cfg::build_cfg;
    use crate::vm_devirt::lift::{LiftedProgram, VmInsn};
    use crate::vm_devirt::microop::MicroOp;

    fn insn(offset: u32, op: MicroOp, bt: Option<u32>) -> VmInsn {
        VmInsn {
            offset,
            opcode: 0,
            micro_op: op,
            imm: None,
            reg: None,
            branch_target: bt,
        }
    }

    #[test]
    fn loop_is_detected() {
        let prog: LiftedProgram = LiftedProgram {
            insns: vec![
                insn(0, MicroOp::PushImm, None),
                insn(
                    9,
                    MicroOp::Compare {
                        op: super::super::microop::CmpKind::Lt,
                    },
                    None,
                ),
                insn(10, MicroOp::BranchFalse, Some(30)),
                insn(15, MicroOp::PushImm, None),
                insn(24, MicroOp::Jump, Some(0)),
                insn(30, MicroOp::Return, None),
            ],
            entry_offset: 0,
            max_reg: 0,
            unresolved_opcodes: vec![],
        };
        let cfg: VmCfg = build_cfg(&prog);
        let nodes: Vec<StructuredNode> = structure_program(&cfg);
        assert!(
            nodes
                .iter()
                .any(|n: &StructuredNode| matches!(n, StructuredNode::Loop { .. })),
            "expected a loop node; got {nodes:?}"
        );
    }

    #[test]
    fn missing_successor_position_is_not_a_back_edge() {
        let cfg: VmCfg = VmCfg {
            entry: 0,
            blocks: vec![VmBlock {
                start_offset: 0,
                insns: vec![],
                successors: vec![100],
                fallthrough: None,
                branch: Some(100),
            }],
        };
        let order: [u32; 1] = [0];
        let edges: BTreeSet<(u32, u32)> = find_back_edges(&cfg, &order);
        assert!(edges.is_empty());
    }
}
