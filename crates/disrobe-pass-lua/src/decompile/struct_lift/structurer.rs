use crate::decompile::luau_lift::{LStmt, LiftedStmt};
use crate::decompile::luau_structure::StructuredBlock;

const MAX_STRUCTURE_DEPTH: usize = 256;

#[derive(Debug, Clone)]
enum Node {
    Raw(String),
    Cond {
        cond: String,
        target: usize,
    },
    Jump {
        target: usize,
    },
    ForNum {
        var: String,
        init: String,
        limit: String,
        step: String,
        exit: usize,
    },
    ForGen {
        vars: Vec<String>,
        iter: String,
        exit: usize,
    },
    BlockEnd,
}

#[derive(Debug, Clone)]
struct PcNode {
    pc: usize,
    node: Node,
}

struct Ctx<'a> {
    nodes: &'a [PcNode],
    end_pc: usize,
    depth: usize,
    repeats: Vec<RepeatEdge>,
    active_repeats: Vec<usize>,
    label_candidates: std::collections::BTreeSet<usize>,
    placed_labels: std::collections::BTreeSet<usize>,
    total_jumps: usize,
    placed_jumps: std::collections::BTreeSet<usize>,
    truncated_regions: usize,
}

#[derive(Debug)]
pub(super) struct StructureResult {
    pub blocks: Vec<StructuredBlock>,
    pub unresolved_jumps: usize,
    pub truncated_regions: usize,
}

#[derive(Debug, Clone)]
struct RepeatEdge {
    head: usize,
    cond_pc: usize,
    cond: String,
}

#[must_use]
pub(super) fn structure_standard(stmts: &[LiftedStmt], code_len: usize) -> StructureResult {
    let nodes: Vec<PcNode> = build_nodes(stmts);
    let repeats: Vec<RepeatEdge> = detect_repeats(&nodes);
    let label_candidates: std::collections::BTreeSet<usize> = nodes
        .iter()
        .filter_map(|n: &PcNode| match n.node {
            Node::Jump { target } if target != usize::MAX => Some(target),
            _ => None,
        })
        .collect();
    let total_jumps: usize = nodes
        .iter()
        .filter(|n: &&PcNode| matches!(n.node, Node::Jump { .. }))
        .count();
    let mut ctx: Ctx<'_> = Ctx {
        nodes: &nodes,
        end_pc: code_len + 1,
        depth: 0,
        repeats,
        active_repeats: Vec::new(),
        label_candidates,
        placed_labels: std::collections::BTreeSet::new(),
        total_jumps,
        placed_jumps: std::collections::BTreeSet::new(),
        truncated_regions: 0,
    };
    let mut pos: usize = 0;
    let mut blocks: Vec<StructuredBlock> = structure_seq(&mut ctx, &mut pos, code_len + 1, None);
    let surviving_jumps: usize = finalize_gotos(&mut blocks, &ctx.placed_labels);
    let unplaced_jumps: usize = ctx.total_jumps.saturating_sub(ctx.placed_jumps.len());
    StructureResult {
        blocks,
        unresolved_jumps: surviving_jumps.saturating_add(unplaced_jumps),
        truncated_regions: ctx.truncated_regions,
    }
}

fn finalize_gotos(
    blocks: &mut Vec<StructuredBlock>,
    placed: &std::collections::BTreeSet<usize>,
) -> usize {
    let mut surviving: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    let carried: usize = convert_dangling_gotos(blocks, placed, &mut surviving);
    prune_unreferenced_labels(blocks, &surviving);
    carried
}

fn convert_dangling_gotos(
    blocks: &mut [StructuredBlock],
    placed: &std::collections::BTreeSet<usize>,
    surviving: &mut std::collections::BTreeSet<usize>,
) -> usize {
    let mut carried: usize = 0;
    for b in blocks.iter_mut() {
        match b {
            StructuredBlock::Goto { pc } => {
                carried += 1;
                if placed.contains(pc) {
                    surviving.insert(*pc);
                } else {
                    let target: usize = *pc;
                    *b = StructuredBlock::Raw(format!("-- unresolved jump to pc {target}"));
                }
            }
            StructuredBlock::If {
                then_body,
                else_body,
                ..
            } => {
                carried += convert_dangling_gotos(then_body, placed, surviving);
                carried += convert_dangling_gotos(else_body, placed, surviving);
            }
            StructuredBlock::While { body, .. }
            | StructuredBlock::Repeat { body, .. }
            | StructuredBlock::NumericFor { body, .. }
            | StructuredBlock::GenericFor { body, .. } => {
                carried += convert_dangling_gotos(body, placed, surviving);
            }
            _ => {}
        }
    }
    carried
}

fn prune_unreferenced_labels(
    blocks: &mut Vec<StructuredBlock>,
    surviving: &std::collections::BTreeSet<usize>,
) {
    blocks.retain(|b: &StructuredBlock| {
        !matches!(b, StructuredBlock::Label { pc } if !surviving.contains(pc))
    });
    for b in blocks.iter_mut() {
        match b {
            StructuredBlock::If {
                then_body,
                else_body,
                ..
            } => {
                prune_unreferenced_labels(then_body, surviving);
                prune_unreferenced_labels(else_body, surviving);
            }
            StructuredBlock::While { body, .. }
            | StructuredBlock::Repeat { body, .. }
            | StructuredBlock::NumericFor { body, .. }
            | StructuredBlock::GenericFor { body, .. } => {
                prune_unreferenced_labels(body, surviving);
            }
            _ => {}
        }
    }
}

#[must_use]
fn detect_repeats(nodes: &[PcNode]) -> Vec<RepeatEdge> {
    let mut out: Vec<RepeatEdge> = Vec::new();
    for n in nodes {
        if let Node::Cond { cond, target } = &n.node
            && *target <= n.pc
        {
            out.push(RepeatEdge {
                head: *target,
                cond_pc: n.pc,
                cond: cond.clone(),
            });
        }
    }
    out
}

#[must_use]
fn repeat_at(repeats: &[RepeatEdge], pc: usize) -> Option<RepeatEdge> {
    repeats
        .iter()
        .filter(|e: &&RepeatEdge| e.head == pc)
        .max_by_key(|e: &&RepeatEdge| e.cond_pc)
        .cloned()
}

fn build_nodes(stmts: &[LiftedStmt]) -> Vec<PcNode> {
    let mut nodes: Vec<PcNode> = Vec::with_capacity(stmts.len());
    let mut forgen_pending: Vec<usize> = Vec::new();
    for item in stmts {
        match &item.stmt {
            LStmt::Raw(s) => {
                if let Some(rest) = s.strip_prefix("--FORGLOOP_VARS ") {
                    let vars: Vec<String> = if rest.is_empty() {
                        Vec::new()
                    } else {
                        rest.split(',').map(str::to_owned).collect()
                    };
                    if let Some(idx) = forgen_pending.pop()
                        && let Node::ForGen { vars: v, .. } = &mut nodes[idx].node
                    {
                        *v = vars;
                    }
                } else {
                    nodes.push(PcNode {
                        pc: item.pc,
                        node: Node::Raw(s.clone()),
                    });
                }
            }
            LStmt::Cond { cond, target } => nodes.push(PcNode {
                pc: item.pc,
                node: Node::Cond {
                    cond: cond.clone(),
                    target: *target,
                },
            }),
            LStmt::Jump { target } => nodes.push(PcNode {
                pc: item.pc,
                node: Node::Jump { target: *target },
            }),
            LStmt::ForNum {
                var,
                init,
                limit,
                step,
                end,
            } => nodes.push(PcNode {
                pc: item.pc,
                node: Node::ForNum {
                    var: var.clone(),
                    init: init.clone(),
                    limit: limit.clone(),
                    step: step.clone(),
                    exit: *end,
                },
            }),
            LStmt::ForGen { iter, end } => {
                forgen_pending.push(nodes.len());
                nodes.push(PcNode {
                    pc: item.pc,
                    node: Node::ForGen {
                        vars: Vec::new(),
                        iter: iter.clone(),
                        exit: *end,
                    },
                });
            }
            LStmt::BlockEnd => nodes.push(PcNode {
                pc: item.pc,
                node: Node::BlockEnd,
            }),
        }
    }
    nodes
}

#[derive(Debug, Clone, Copy)]
struct LoopCtx {
    exit: usize,
}

fn structure_seq(
    ctx: &mut Ctx<'_>,
    pos: &mut usize,
    stop_pc: usize,
    cur_loop: Option<LoopCtx>,
) -> Vec<StructuredBlock> {
    let mut out: Vec<StructuredBlock> = Vec::new();
    if ctx.depth >= MAX_STRUCTURE_DEPTH {
        ctx.truncated_regions = ctx.truncated_regions.saturating_add(1);
        out.push(StructuredBlock::Raw(format!(
            "-- nesting deeper than {MAX_STRUCTURE_DEPTH} left this region unstructured"
        )));
        return out;
    }
    ctx.depth += 1;
    while *pos < ctx.nodes.len() {
        let cur: PcNode = ctx.nodes[*pos].clone();
        let cur_index: usize = *pos;
        if cur.pc >= stop_pc {
            break;
        }
        if ctx.label_candidates.contains(&cur.pc) && !ctx.placed_labels.contains(&cur.pc) {
            ctx.placed_labels.insert(cur.pc);
            out.push(StructuredBlock::Label { pc: cur.pc });
        }
        if let Some(edge) = repeat_at(&ctx.repeats, cur.pc)
            && !ctx.active_repeats.contains(&cur.pc)
            && !matches!(cur.node, Node::ForNum { .. } | Node::ForGen { .. })
        {
            ctx.active_repeats.push(edge.head);
            let body: Vec<StructuredBlock> = structure_seq(
                ctx,
                pos,
                edge.cond_pc,
                Some(LoopCtx {
                    exit: edge.cond_pc + 2,
                }),
            );
            ctx.active_repeats.pop();
            consume_cond(ctx.nodes, pos);
            out.push(StructuredBlock::Repeat {
                cond: edge.cond.clone(),
                body,
            });
            continue;
        }
        match cur.node {
            Node::Raw(s) => {
                out.push(StructuredBlock::Raw(s));
                *pos += 1;
            }
            Node::BlockEnd => {
                *pos += 1;
            }
            Node::ForNum {
                var,
                init,
                limit,
                step,
                exit,
            } => {
                *pos += 1;
                let body: Vec<StructuredBlock> =
                    structure_seq(ctx, pos, exit, Some(LoopCtx { exit }));
                skip_block_end(ctx.nodes, pos);
                out.push(StructuredBlock::NumericFor {
                    var,
                    init,
                    limit,
                    step,
                    body,
                });
            }
            Node::ForGen { vars, iter, exit } => {
                *pos += 1;
                let body: Vec<StructuredBlock> =
                    structure_seq(ctx, pos, exit, Some(LoopCtx { exit }));
                skip_block_end(ctx.nodes, pos);
                out.push(StructuredBlock::GenericFor { vars, iter, body });
            }
            Node::Jump { target } => {
                *pos += 1;
                ctx.placed_jumps.insert(cur_index);
                let is_break: bool =
                    target == usize::MAX || cur_loop.is_some_and(|l: LoopCtx| target == l.exit);
                if is_break {
                    out.push(StructuredBlock::Break);
                } else {
                    out.push(StructuredBlock::Goto { pc: target });
                }
            }
            Node::Cond { cond, target } => {
                if target <= cur.pc {
                    *pos += 1;
                    continue;
                }
                if cur_loop.is_some_and(|l: LoopCtx| l.exit == target) {
                    *pos += 1;
                    out.push(StructuredBlock::If {
                        cond: crate::decompile::luau_structure::negate_cond(&cond),
                        then_body: vec![StructuredBlock::Break],
                        else_body: Vec::new(),
                    });
                    continue;
                }
                emit_branch(ctx, pos, &mut out, &cond, target, stop_pc, cur.pc, cur_loop);
            }
        }
    }
    ctx.depth -= 1;
    out
}

#[allow(clippy::too_many_arguments)]
fn emit_branch(
    ctx: &mut Ctx<'_>,
    pos: &mut usize,
    out: &mut Vec<StructuredBlock>,
    cond: &str,
    target: usize,
    stop_pc: usize,
    cur_pc: usize,
    cur_loop: Option<LoopCtx>,
) {
    let back_jump: Option<usize> = jump_before(ctx.nodes, target, cur_pc);
    if let Some(head) = back_jump
        && head <= cur_pc
    {
        let exit: usize = target;
        *pos += 1;
        let mut body: Vec<StructuredBlock> =
            structure_seq(ctx, pos, target, Some(LoopCtx { exit }));
        pop_trailing_goto(&mut body, head);
        consume_back_jump(ctx, pos, head);
        out.push(StructuredBlock::While {
            cond: cond.to_owned(),
            body,
        });
        return;
    }

    *pos += 1;
    let effective_then_stop: usize = target.min(stop_pc);
    let then_body: Vec<StructuredBlock> = structure_seq(ctx, pos, effective_then_stop, cur_loop);
    let else_jump: Option<usize> =
        preceding_forward_jump(ctx.nodes, *pos, target, cur_loop, ctx.end_pc);
    match else_jump {
        Some(else_end) if else_end > target && else_end <= ctx.end_pc => {
            let mut then_trim: Vec<StructuredBlock> = then_body;
            if !pop_trailing_goto(&mut then_trim, else_end)
                && matches!(then_trim.last(), Some(StructuredBlock::Break))
            {
                then_trim.pop();
            }
            let else_stop: usize = else_end.min(stop_pc);
            let else_body: Vec<StructuredBlock> = structure_seq(ctx, pos, else_stop, cur_loop);
            out.push(StructuredBlock::If {
                cond: cond.to_owned(),
                then_body: then_trim,
                else_body,
            });
        }
        _ => out.push(StructuredBlock::If {
            cond: cond.to_owned(),
            then_body,
            else_body: Vec::new(),
        }),
    }
}

#[must_use]
fn jump_before(nodes: &[PcNode], target: usize, cond_pc: usize) -> Option<usize> {
    for n in nodes {
        if n.pc + 1 == target
            && let Node::Jump { target: jt } = n.node
            && jt != usize::MAX
            && jt <= cond_pc
        {
            return Some(jt);
        }
    }
    None
}

#[must_use]
fn preceding_forward_jump(
    nodes: &[PcNode],
    pos: usize,
    target: usize,
    cur_loop: Option<LoopCtx>,
    end_pc: usize,
) -> Option<usize> {
    if pos == 0 {
        return None;
    }
    let prev: &PcNode = &nodes[pos - 1];
    if let Node::Jump { target: j } = prev.node
        && j != usize::MAX
        && j > target
        && j <= end_pc
        && cur_loop.is_none_or(|l: LoopCtx| l.exit != j)
    {
        return Some(j);
    }
    None
}

fn pop_trailing_goto(body: &mut Vec<StructuredBlock>, absorbed_target: usize) -> bool {
    let Some(StructuredBlock::Goto { pc }) = body.last() else {
        return false;
    };
    if *pc != absorbed_target {
        return false;
    }
    body.pop();
    true
}

fn consume_cond(nodes: &[PcNode], pos: &mut usize) {
    if *pos < nodes.len() && matches!(nodes[*pos].node, Node::Cond { .. }) {
        *pos += 1;
    }
}

fn consume_back_jump(ctx: &mut Ctx<'_>, pos: &mut usize, head: usize) {
    if *pos < ctx.nodes.len()
        && let Node::Jump { target } = ctx.nodes[*pos].node
        && target == head
        && target <= ctx.nodes[*pos].pc
    {
        ctx.placed_jumps.insert(*pos);
        *pos += 1;
    }
}

fn skip_block_end(nodes: &[PcNode], pos: &mut usize) {
    if *pos < nodes.len() && matches!(nodes[*pos].node, Node::BlockEnd) {
        *pos += 1;
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn lifted(pc: usize, stmt: LStmt) -> LiftedStmt {
        LiftedStmt { pc, stmt }
    }

    fn branch_ladder(branches: usize) -> Vec<LiftedStmt> {
        let mut stmts: Vec<LiftedStmt> = Vec::with_capacity(branches * 2);
        let mut pc: usize = 0;
        for i in 0..branches {
            stmts.push(lifted(
                pc,
                LStmt::Cond {
                    cond: format!("a < {i}"),
                    target: pc + 2,
                },
            ));
            stmts.push(lifted(pc + 1, LStmt::Raw(format!("b = b + {i}"))));
            pc += 2;
        }
        stmts
    }

    fn count_conditionals(blocks: &[StructuredBlock]) -> usize {
        blocks
            .iter()
            .map(|b: &StructuredBlock| match b {
                StructuredBlock::If {
                    then_body,
                    else_body,
                    ..
                } => 1 + count_conditionals(then_body) + count_conditionals(else_body),
                StructuredBlock::While { body, .. }
                | StructuredBlock::Repeat { body, .. }
                | StructuredBlock::NumericFor { body, .. }
                | StructuredBlock::GenericFor { body, .. } => count_conditionals(body),
                _ => 0,
            })
            .sum()
    }

    fn empty_conditionals(blocks: &[StructuredBlock]) -> usize {
        blocks
            .iter()
            .map(|b: &StructuredBlock| match b {
                StructuredBlock::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    let here: usize = usize::from(then_body.is_empty() && else_body.is_empty());
                    here + empty_conditionals(then_body) + empty_conditionals(else_body)
                }
                StructuredBlock::While { body, .. }
                | StructuredBlock::Repeat { body, .. }
                | StructuredBlock::NumericFor { body, .. }
                | StructuredBlock::GenericFor { body, .. } => empty_conditionals(body),
                _ => 0,
            })
            .sum()
    }

    fn nested_conditionals(depth: usize) -> Vec<LiftedStmt> {
        let span: usize = depth * 2;
        let mut stmts: Vec<LiftedStmt> = Vec::with_capacity(span);
        for i in 0..depth {
            stmts.push(lifted(
                i,
                LStmt::Cond {
                    cond: format!("r0 == {i}"),
                    target: span - i,
                },
            ));
        }
        stmts.push(lifted(depth, LStmt::Raw("r1 = 1".to_owned())));
        stmts
    }

    fn nesting_of(blocks: &[StructuredBlock]) -> usize {
        blocks
            .iter()
            .map(|b: &StructuredBlock| match b {
                StructuredBlock::If {
                    then_body,
                    else_body,
                    ..
                } => 1 + nesting_of(then_body).max(nesting_of(else_body)),
                StructuredBlock::While { body, .. }
                | StructuredBlock::Repeat { body, .. }
                | StructuredBlock::NumericFor { body, .. }
                | StructuredBlock::GenericFor { body, .. } => 1 + nesting_of(body),
                _ => 0,
            })
            .max()
            .unwrap_or(0)
    }

    fn carries_depth_marker(blocks: &[StructuredBlock]) -> bool {
        blocks.iter().any(|b: &StructuredBlock| match b {
            StructuredBlock::Raw(text) => text.contains("nesting deeper than"),
            StructuredBlock::If {
                then_body,
                else_body,
                ..
            } => carries_depth_marker(then_body) || carries_depth_marker(else_body),
            StructuredBlock::While { body, .. }
            | StructuredBlock::Repeat { body, .. }
            | StructuredBlock::NumericFor { body, .. }
            | StructuredBlock::GenericFor { body, .. } => carries_depth_marker(body),
            _ => false,
        })
    }

    #[test]
    fn nesting_far_past_the_limit_returns_instead_of_exhausting_the_stack() {
        let depth: usize = MAX_STRUCTURE_DEPTH * 8;
        let stmts: Vec<LiftedStmt> = nested_conditionals(depth);

        let worker: std::thread::JoinHandle<StructureResult> = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || structure_standard(&stmts, depth * 2))
            .expect("spawn a thread whose stack this walk overflowed before the limit existed");
        let result: StructureResult = worker.join().expect("the walk must return, never overflow");

        assert!(
            result.truncated_regions > 0,
            "nesting {depth} deep is past the limit, so the walk must refuse and count it"
        );
        assert!(
            nesting_of(&result.blocks) <= MAX_STRUCTURE_DEPTH,
            "the recovered tree must not nest past the limit that bounds the walk building it, \
             because every consumer of that tree walks it to the same depth; got {}",
            nesting_of(&result.blocks)
        );
        assert!(
            carries_depth_marker(&result.blocks),
            "a reader of the recovered source has to see where structure stopped"
        );
    }

    #[test]
    fn a_forward_jump_that_reaches_a_statement_is_placed_and_counted_unresolved() {
        let stmts: Vec<LiftedStmt> = vec![
            lifted(0, LStmt::Raw("r0 = 1".to_owned())),
            lifted(1, LStmt::Jump { target: 4 }),
            lifted(2, LStmt::Raw("r0 = 2".to_owned())),
        ];

        let result: StructureResult = structure_standard(&stmts, 4);

        assert_eq!(result.truncated_regions, 0);
        assert_eq!(
            result.unresolved_jumps, 1,
            "a jump the structure does not absorb survives as a goto and is reported once, not \
             once per accounting pass"
        );
    }

    #[test]
    fn a_sentinel_jump_target_is_placed_and_leaves_the_report_clean() {
        let stmts: Vec<LiftedStmt> = vec![
            lifted(0, LStmt::Raw("r0 = 1".to_owned())),
            lifted(1, LStmt::Jump { target: usize::MAX }),
        ];

        let result: StructureResult = structure_standard(&stmts, 2);

        assert_eq!(
            result.unresolved_jumps, 0,
            "the sentinel target means the jump has no successor, so discarding it is correct and \
             must not read as a lost edge"
        );
        assert_eq!(result.truncated_regions, 0);
    }

    fn carries_goto_to(blocks: &[StructuredBlock], target: usize) -> bool {
        blocks.iter().any(|b: &StructuredBlock| match b {
            StructuredBlock::Goto { pc } => *pc == target,
            StructuredBlock::Raw(text) => text == &format!("-- unresolved jump to pc {target}"),
            StructuredBlock::If {
                then_body,
                else_body,
                ..
            } => carries_goto_to(then_body, target) || carries_goto_to(else_body, target),
            StructuredBlock::While { body, .. }
            | StructuredBlock::Repeat { body, .. }
            | StructuredBlock::NumericFor { body, .. }
            | StructuredBlock::GenericFor { body, .. } => carries_goto_to(body, target),
            _ => false,
        })
    }

    #[test]
    fn a_loop_absorbs_only_the_back_edge_that_closes_it() {
        let stmts: Vec<LiftedStmt> = vec![
            lifted(
                0,
                LStmt::Cond {
                    cond: "r0 < 10".to_owned(),
                    target: 4,
                },
            ),
            lifted(1, LStmt::Raw("r0 = r0 + 1".to_owned())),
            lifted(2, LStmt::Raw("r2 = r0".to_owned())),
            lifted(3, LStmt::Jump { target: 0 }),
            lifted(3, LStmt::Jump { target: 9 }),
            lifted(4, LStmt::Raw("r1 = r0".to_owned())),
        ];

        let result: StructureResult = structure_standard(&stmts, 9);

        assert!(
            carries_goto_to(&result.blocks, 9),
            "the loop closes on the back edge to pc 0, so the jump to pc 9 is a separate edge and \
             must survive rather than be deleted for sitting last; blocks: {:?}",
            result.blocks
        );
        assert!(
            result.unresolved_jumps > 0,
            "an edge the structure does not carry has to be reported; blocks: {:?}",
            result.blocks
        );
    }

    #[test]
    fn a_backward_jump_that_is_not_the_loop_head_is_not_swallowed_after_the_loop() {
        let stmts: Vec<LiftedStmt> = vec![
            lifted(
                0,
                LStmt::Cond {
                    cond: "r0 < 10".to_owned(),
                    target: 4,
                },
            ),
            lifted(1, LStmt::Raw("r0 = r0 + 1".to_owned())),
            lifted(2, LStmt::Raw("r2 = r0".to_owned())),
            lifted(3, LStmt::Jump { target: 0 }),
            lifted(4, LStmt::Jump { target: 1 }),
            lifted(5, LStmt::Raw("r1 = r0".to_owned())),
        ];

        let result: StructureResult = structure_standard(&stmts, 6);

        assert!(
            carries_goto_to(&result.blocks, 1),
            "the jump at pc 4 goes back to pc 1, which is not the head the loop closed on, so it \
             is a live edge and must survive rather than be consumed as that loop's back edge; \
             blocks: {:?}",
            result.blocks
        );
    }

    #[test]
    fn a_ladder_inside_the_budget_nests_every_statement_in_its_own_branch() {
        let branches: usize = 8;
        let stmts: Vec<LiftedStmt> = branch_ladder(branches);

        let result: StructureResult = structure_standard(&stmts, branches * 2);

        assert_eq!(result.truncated_regions, 0);
        assert_eq!(count_conditionals(&result.blocks), branches);
        assert_eq!(
            empty_conditionals(&result.blocks),
            0,
            "inside the budget every branch keeps its own statement"
        );
    }

    #[test]
    fn a_ladder_of_siblings_costs_nothing_against_a_limit_that_counts_nesting() {
        let branches: usize = 5000;
        let stmts: Vec<LiftedStmt> = branch_ladder(branches);

        let result: StructureResult = structure_standard(&stmts, branches * 2);

        assert_eq!(
            result.truncated_regions, 0,
            "{branches} sibling branches nest one deep, so a limit on nesting must refuse none of \
             them; a counter that never released would refuse every branch past its value"
        );
        assert_eq!(
            count_conditionals(&result.blocks),
            branches,
            "every branch is recovered"
        );
        assert_eq!(
            empty_conditionals(&result.blocks),
            0,
            "and every one of them keeps the statement it guards, which is the defect this limit \
             shape removes"
        );
        assert_eq!(nesting_of(&result.blocks), 1, "the ladder is flat");
    }

    #[test]
    fn a_chain_deeper_than_the_limit_is_still_refused_and_counted() {
        let depth: usize = MAX_STRUCTURE_DEPTH + 40;
        let stmts: Vec<LiftedStmt> = nested_conditionals(depth);

        let result: StructureResult = structure_standard(&stmts, depth * 2);

        assert!(
            result.truncated_regions > 0,
            "trading a total budget for a nesting limit moves where the refusal happens; it must \
             not remove it"
        );
        assert!(carries_depth_marker(&result.blocks));
    }

    #[test]
    fn nesting_inside_the_limit_is_recovered_at_its_real_depth() {
        let depth: usize = MAX_STRUCTURE_DEPTH - 8;
        let stmts: Vec<LiftedStmt> = nested_conditionals(depth);

        let result: StructureResult = structure_standard(&stmts, depth * 2);

        assert_eq!(result.truncated_regions, 0);
        assert_eq!(
            nesting_of(&result.blocks),
            depth,
            "a body that fits the limit keeps its real shape rather than being flattened"
        );
    }
}
