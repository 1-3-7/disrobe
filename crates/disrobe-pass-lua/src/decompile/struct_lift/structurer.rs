use crate::decompile::luau_lift::{LStmt, LiftedStmt};
use crate::decompile::luau_structure::StructuredBlock;

const MAX_STRUCT_RECURSION: usize = 4096;

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
    guard: usize,
    repeats: Vec<RepeatEdge>,
    active_repeats: Vec<usize>,
    unresolved: usize,
    label_candidates: std::collections::BTreeSet<usize>,
    placed_labels: std::collections::BTreeSet<usize>,
}

#[derive(Debug)]
pub(super) struct StructureResult {
    pub blocks: Vec<StructuredBlock>,
    pub unresolved_jumps: usize,
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
    let mut ctx: Ctx<'_> = Ctx {
        nodes: &nodes,
        end_pc: code_len + 1,
        guard: 0,
        repeats,
        active_repeats: Vec::new(),
        unresolved: 0,
        label_candidates,
        placed_labels: std::collections::BTreeSet::new(),
    };
    let mut pos: usize = 0;
    let mut blocks: Vec<StructuredBlock> = structure_seq(&mut ctx, &mut pos, code_len + 1, None);
    let dangling: usize = finalize_gotos(&mut blocks, &ctx.placed_labels);
    StructureResult {
        blocks,
        unresolved_jumps: ctx.unresolved.saturating_add(dangling),
    }
}

fn finalize_gotos(
    blocks: &mut Vec<StructuredBlock>,
    placed: &std::collections::BTreeSet<usize>,
) -> usize {
    let mut surviving: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    let dangling: usize = convert_dangling_gotos(blocks, placed, &mut surviving);
    prune_unreferenced_labels(blocks, &surviving);
    dangling
}

fn convert_dangling_gotos(
    blocks: &mut [StructuredBlock],
    placed: &std::collections::BTreeSet<usize>,
    surviving: &mut std::collections::BTreeSet<usize>,
) -> usize {
    let mut dangling: usize = 0;
    for b in blocks.iter_mut() {
        match b {
            StructuredBlock::Goto { pc } => {
                if placed.contains(pc) {
                    surviving.insert(*pc);
                } else {
                    let target: usize = *pc;
                    dangling += 1;
                    *b = StructuredBlock::Raw(format!("-- unresolved jump to pc {target}"));
                }
            }
            StructuredBlock::If {
                then_body,
                else_body,
                ..
            } => {
                dangling += convert_dangling_gotos(then_body, placed, surviving);
                dangling += convert_dangling_gotos(else_body, placed, surviving);
            }
            StructuredBlock::While { body, .. }
            | StructuredBlock::Repeat { body, .. }
            | StructuredBlock::NumericFor { body, .. }
            | StructuredBlock::GenericFor { body, .. } => {
                dangling += convert_dangling_gotos(body, placed, surviving);
            }
            _ => {}
        }
    }
    dangling
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
    ctx.guard += 1;
    if ctx.guard > MAX_STRUCT_RECURSION {
        return out;
    }
    while *pos < ctx.nodes.len() {
        let cur: PcNode = ctx.nodes[*pos].clone();
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
                let is_break: bool =
                    target == usize::MAX || cur_loop.is_some_and(|l: LoopCtx| target == l.exit);
                if is_break {
                    out.push(StructuredBlock::Break);
                } else {
                    ctx.unresolved += 1;
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
        pop_trailing_goto(ctx, &mut body);
        consume_back_jump(ctx.nodes, pos);
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
            if !pop_trailing_goto(ctx, &mut then_trim)
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

fn pop_trailing_goto(ctx: &mut Ctx<'_>, body: &mut Vec<StructuredBlock>) -> bool {
    if !matches!(body.last(), Some(StructuredBlock::Goto { .. })) {
        return false;
    }
    body.pop();
    ctx.unresolved = ctx.unresolved.saturating_sub(1);
    true
}

fn consume_cond(nodes: &[PcNode], pos: &mut usize) {
    if *pos < nodes.len() && matches!(nodes[*pos].node, Node::Cond { .. }) {
        *pos += 1;
    }
}

fn consume_back_jump(nodes: &[PcNode], pos: &mut usize) {
    if *pos < nodes.len()
        && let Node::Jump { target } = nodes[*pos].node
        && target != usize::MAX
        && target <= nodes[*pos].pc
    {
        *pos += 1;
    }
}

fn skip_block_end(nodes: &[PcNode], pos: &mut usize) {
    if *pos < nodes.len() && matches!(nodes[*pos].node, Node::BlockEnd) {
        *pos += 1;
    }
}
