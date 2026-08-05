use crate::decompile::luau_lift::{LStmt, LiftedStmt};

const MAX_STRUCTURE_DEPTH: usize = 256;

#[derive(Debug, Clone)]
pub(crate) enum StructuredBlock {
    Raw(String),
    Break,
    Goto {
        pc: usize,
    },
    Label {
        pc: usize,
    },
    If {
        cond: String,
        then_body: Vec<StructuredBlock>,
        else_body: Vec<StructuredBlock>,
    },
    While {
        cond: String,
        body: Vec<StructuredBlock>,
    },
    Repeat {
        cond: String,
        body: Vec<StructuredBlock>,
    },
    NumericFor {
        var: String,
        init: String,
        limit: String,
        step: String,
        body: Vec<StructuredBlock>,
    },
    GenericFor {
        vars: Vec<String>,
        iter: String,
        body: Vec<StructuredBlock>,
    },
}

#[derive(Debug)]
pub(crate) struct StructureResult {
    pub blocks: Vec<StructuredBlock>,
    pub unresolved_jumps: usize,
    pub refused_regions: usize,
}

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

#[must_use]
pub(crate) fn structure_blocks(stmts: &[LiftedStmt], code_len: usize) -> StructureResult {
    let nodes: Vec<PcNode> = build_nodes(stmts);
    let loops: Vec<BackEdge> = detect_back_edges(&nodes);
    let mut pos: usize = 0;
    let mut ctx: SeqCtx<'_> = SeqCtx {
        nodes: &nodes,
        loops: &loops,
        active: Vec::new(),
        depth: 0,
        refused_regions: 0,
    };
    let mut blocks: Vec<StructuredBlock> = structure_seq(&mut ctx, &mut pos, code_len + 1, None);
    let unresolved_jumps: usize = finalize_unresolved_jumps(&mut blocks);
    StructureResult {
        blocks,
        unresolved_jumps,
        refused_regions: ctx.refused_regions,
    }
}

#[derive(Debug, Clone, Copy)]
struct BackEdge {
    head: usize,
    tail_pc: usize,
}

struct SeqCtx<'a> {
    nodes: &'a [PcNode],
    loops: &'a [BackEdge],
    active: Vec<usize>,
    depth: usize,
    refused_regions: usize,
}

#[must_use]
fn detect_back_edges(nodes: &[PcNode]) -> Vec<BackEdge> {
    let mut edges: Vec<BackEdge> = Vec::new();
    for n in nodes {
        if let Node::Jump { target } = n.node
            && target <= n.pc
        {
            edges.push(BackEdge {
                head: target,
                tail_pc: n.pc,
            });
        }
    }
    edges
}

#[must_use]
fn loop_starting_at(loops: &[BackEdge], pc: usize) -> Option<BackEdge> {
    loops
        .iter()
        .copied()
        .filter(|e: &BackEdge| e.head == pc)
        .max_by_key(|e: &BackEdge| e.tail_pc)
}

fn build_nodes(stmts: &[LiftedStmt]) -> Vec<PcNode> {
    let mut nodes: Vec<PcNode> = Vec::new();
    let mut forgen_stack: Vec<usize> = Vec::new();
    let mut loop_stack: Vec<bool> = Vec::new();
    for item in stmts {
        match &item.stmt {
            LStmt::Raw(s) => {
                if let Some(rest) = s.strip_prefix("--FORGLOOP_VARS ") {
                    let vars: Vec<String> = if rest.is_empty() {
                        Vec::new()
                    } else {
                        rest.split(',').map(str::to_owned).collect()
                    };
                    if let Some(node_pos) = forgen_stack.last()
                        && let Node::ForGen { vars: v, .. } = &mut nodes[*node_pos].node
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
            } => {
                loop_stack.push(false);
                nodes.push(PcNode {
                    pc: item.pc,
                    node: Node::ForNum {
                        var: var.clone(),
                        init: init.clone(),
                        limit: limit.clone(),
                        step: step.clone(),
                        exit: *end,
                    },
                });
            }
            LStmt::ForGen { iter, end } => {
                loop_stack.push(true);
                forgen_stack.push(nodes.len());
                nodes.push(PcNode {
                    pc: item.pc,
                    node: Node::ForGen {
                        vars: Vec::new(),
                        iter: iter.clone(),
                        exit: *end,
                    },
                });
            }
            LStmt::BlockEnd => {
                if loop_stack.pop() == Some(true) {
                    forgen_stack.pop();
                }
                nodes.push(PcNode {
                    pc: item.pc,
                    node: Node::BlockEnd,
                });
            }
        }
    }
    nodes
}

#[derive(Debug, Clone, Copy)]
struct LoopRef {
    exit: usize,
    is_while: bool,
}

fn structure_seq(
    ctx: &mut SeqCtx<'_>,
    pos: &mut usize,
    stop_pc: usize,
    cur_loop: Option<LoopRef>,
) -> Vec<StructuredBlock> {
    let mut out: Vec<StructuredBlock> = Vec::new();
    if ctx.depth >= MAX_STRUCTURE_DEPTH {
        ctx.refused_regions = ctx.refused_regions.saturating_add(1);
        out.push(StructuredBlock::Raw(format!(
            "error(\"disrobe: nesting deeper than {MAX_STRUCTURE_DEPTH} left this region unstructured\")"
        )));
        return out;
    }
    ctx.depth += 1;
    while *pos < ctx.nodes.len() {
        let cur: PcNode = ctx.nodes[*pos].clone();
        if cur.pc >= stop_pc {
            break;
        }
        if let Some(edge) = loop_starting_at(ctx.loops, cur.pc)
            && !ctx.active.contains(&cur.pc)
        {
            let block: StructuredBlock = structure_loop(ctx, pos, edge);
            out.push(block);
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
                let inner: LoopRef = LoopRef {
                    exit,
                    is_while: false,
                };
                let body: Vec<StructuredBlock> = structure_seq(ctx, pos, exit, Some(inner));
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
                let inner: LoopRef = LoopRef {
                    exit,
                    is_while: false,
                };
                let body: Vec<StructuredBlock> = structure_seq(ctx, pos, exit, Some(inner));
                skip_block_end(ctx.nodes, pos);
                out.push(StructuredBlock::GenericFor { vars, iter, body });
            }
            Node::Jump { target } => {
                *pos += 1;
                if cur_loop.is_some_and(|l: LoopRef| l.exit == target) {
                    out.push(StructuredBlock::Break);
                } else {
                    out.push(StructuredBlock::Goto { pc: target });
                }
            }
            Node::Cond { cond, target } => {
                *pos += 1;
                if target <= cur.pc {
                    continue;
                }
                let is_loop_exit: bool = cur_loop.is_some_and(|l: LoopRef| l.exit == target);
                if is_loop_exit && cur_loop.is_some_and(|l: LoopRef| l.is_while) {
                    out.push(StructuredBlock::If {
                        cond: negate_cond(&cond),
                        then_body: vec![StructuredBlock::Break],
                        else_body: Vec::new(),
                    });
                    continue;
                }
                if is_loop_exit {
                    let then_body: Vec<StructuredBlock> =
                        structure_seq(ctx, pos, stop_pc, cur_loop);
                    out.push(StructuredBlock::If {
                        cond,
                        then_body,
                        else_body: Vec::new(),
                    });
                    continue;
                }
                let effective_target: usize = target.min(stop_pc);
                let then_body: Vec<StructuredBlock> =
                    structure_seq(ctx, pos, effective_target, cur_loop);
                let else_jump: Option<usize> = pre_target_else(ctx.nodes, *pos, target, cur_loop);
                match else_jump {
                    Some(else_end) if else_end > target => {
                        let mut then_trim: Vec<StructuredBlock> = then_body;
                        pop_trailing_goto(&mut then_trim, else_end);
                        let else_body: Vec<StructuredBlock> =
                            structure_seq(ctx, pos, else_end, cur_loop);
                        out.push(StructuredBlock::If {
                            cond,
                            then_body: then_trim,
                            else_body,
                        });
                    }
                    _ => out.push(StructuredBlock::If {
                        cond,
                        then_body,
                        else_body: Vec::new(),
                    }),
                }
            }
        }
    }
    ctx.depth -= 1;
    out
}

fn pop_trailing_goto(body: &mut Vec<StructuredBlock>, target: usize) {
    let matches_target: bool =
        matches!(body.last(), Some(StructuredBlock::Goto { pc }) if *pc == target);
    if matches_target {
        body.pop();
    }
}

#[must_use]
fn finalize_unresolved_jumps(blocks: &mut [StructuredBlock]) -> usize {
    let mut unresolved: usize = 0;
    for block in blocks {
        let nested: usize = match block {
            StructuredBlock::Goto { pc } => {
                let target: usize = *pc;
                *block = StructuredBlock::Raw(format!(
                    "error(\"disrobe: unresolved luau jump to pc {target}\")"
                ));
                1
            }
            StructuredBlock::If {
                then_body,
                else_body,
                ..
            } => finalize_unresolved_jumps(then_body)
                .saturating_add(finalize_unresolved_jumps(else_body)),
            StructuredBlock::While { body, .. }
            | StructuredBlock::Repeat { body, .. }
            | StructuredBlock::NumericFor { body, .. }
            | StructuredBlock::GenericFor { body, .. } => finalize_unresolved_jumps(body),
            StructuredBlock::Raw(_) | StructuredBlock::Break | StructuredBlock::Label { .. } => 0,
        };
        unresolved = unresolved.saturating_add(nested);
    }
    unresolved
}

fn structure_loop(ctx: &mut SeqCtx<'_>, pos: &mut usize, edge: BackEdge) -> StructuredBlock {
    let loop_exit: usize = edge.tail_pc + 1;
    let body_stop: usize = edge.tail_pc;
    ctx.active.push(edge.head);
    let inner: LoopRef = LoopRef {
        exit: loop_exit,
        is_while: true,
    };
    let body: Vec<StructuredBlock> = structure_seq(ctx, pos, body_stop, Some(inner));
    ctx.active.pop();
    consume_back_edge(ctx.nodes, pos, edge.head);
    simplify_loop(body)
}

#[must_use]
fn simplify_loop(mut body: Vec<StructuredBlock>) -> StructuredBlock {
    if let Some(StructuredBlock::If {
        cond,
        then_body,
        else_body,
    }) = body.first()
        && else_body.is_empty()
        && then_body.len() == 1
        && matches!(then_body.first(), Some(StructuredBlock::Break))
    {
        let while_cond: String = negate_cond(cond);
        body.remove(0);
        return StructuredBlock::While {
            cond: while_cond,
            body,
        };
    }
    StructuredBlock::While {
        cond: "true".to_owned(),
        body,
    }
}

#[must_use]
pub(crate) fn negate_cond(cond: &str) -> String {
    if let Some(rest) = cond.strip_prefix("not (")
        && let Some(inner) = rest.strip_suffix(')')
    {
        return inner.to_owned();
    }
    for (op, inv) in [
        (" == ", " ~= "),
        (" ~= ", " == "),
        (" <= ", " > "),
        (" >= ", " < "),
        (" < ", " >= "),
        (" > ", " <= "),
    ] {
        if let Some(idx) = cond.find(op) {
            let (lhs, rhs): (&str, &str) = cond.split_at(idx);
            let rhs: &str = &rhs[op.len()..];
            return format!("{lhs}{inv}{rhs}");
        }
    }
    format!("not ({cond})")
}

fn consume_back_edge(nodes: &[PcNode], pos: &mut usize, head: usize) {
    if *pos < nodes.len()
        && let Node::Jump { target } = nodes[*pos].node
        && target == head
    {
        *pos += 1;
    }
}

fn skip_block_end(nodes: &[PcNode], pos: &mut usize) {
    if *pos < nodes.len() && matches!(nodes[*pos].node, Node::BlockEnd) {
        *pos += 1;
    }
}

#[must_use]
fn pre_target_else(
    nodes: &[PcNode],
    pos: usize,
    target: usize,
    cur_loop: Option<LoopRef>,
) -> Option<usize> {
    if pos == 0 {
        return None;
    }
    let prev: &PcNode = &nodes[pos - 1];
    if let Node::Jump { target: j } = prev.node
        && j > target
        && cur_loop.is_none_or(|l: LoopRef| l.exit != j)
    {
        return Some(j);
    }
    None
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn lifted(pc: usize, stmt: LStmt) -> LiftedStmt {
        LiftedStmt { pc, stmt }
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

    fn sibling_conditionals(count: usize) -> Vec<LiftedStmt> {
        let mut stmts: Vec<LiftedStmt> = Vec::with_capacity(count * 2);
        let mut pc: usize = 0;
        for i in 0..count {
            stmts.push(lifted(
                pc,
                LStmt::Cond {
                    cond: format!("r0 == {i}"),
                    target: pc + 2,
                },
            ));
            stmts.push(lifted(pc + 1, LStmt::Raw(format!("r1 = {i}"))));
            pc += 2;
        }
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
        let depth: usize = MAX_STRUCTURE_DEPTH * 24;
        let stmts: Vec<LiftedStmt> = nested_conditionals(depth);

        let worker: std::thread::JoinHandle<StructureResult> = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || structure_blocks(&stmts, depth * 2))
            .expect("spawn a thread whose stack this walk overflowed before the limit existed");
        let result: StructureResult = worker.join().expect("the walk must return, never overflow");

        assert!(
            result.refused_regions > 0,
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
            "a reader of the recovered source has to see where structure stopped, not only a \
             counter the caller may never print"
        );
    }

    #[test]
    fn the_limit_counts_nesting_and_not_total_work() {
        let count: usize = MAX_STRUCTURE_DEPTH * 20;
        let stmts: Vec<LiftedStmt> = sibling_conditionals(count);

        let result: StructureResult = structure_blocks(&stmts, count * 2);

        assert_eq!(
            result.refused_regions, 0,
            "{count} sibling regions nest one deep, so a limit on nesting must not refuse any of \
             them; a counter that never decrements would refuse everything past its value"
        );
        assert_eq!(
            nesting_of(&result.blocks),
            1,
            "the shape under test is flat by construction"
        );
        assert_eq!(
            result.blocks.len(),
            count,
            "every sibling region is recovered"
        );
    }

    #[test]
    fn nesting_inside_the_limit_is_recovered_whole() {
        let depth: usize = MAX_STRUCTURE_DEPTH - 8;
        let stmts: Vec<LiftedStmt> = nested_conditionals(depth);

        let result: StructureResult = structure_blocks(&stmts, depth * 2);

        assert_eq!(
            result.refused_regions, 0,
            "a body that fits the limit must not be refused"
        );
        assert_eq!(
            nesting_of(&result.blocks),
            depth,
            "and it must be recovered at its real depth rather than flattened"
        );
    }

    #[test]
    fn forward_branch_jump_preserves_then_tail() {
        let stmts: Vec<LiftedStmt> = vec![
            lifted(
                0,
                LStmt::Cond {
                    cond: "r0 == 3".to_owned(),
                    target: 3,
                },
            ),
            lifted(1, LStmt::Raw("r1 = r1 + 100".to_owned())),
            lifted(2, LStmt::Jump { target: 5 }),
            lifted(3, LStmt::Raw("r1 = r1 + r0".to_owned())),
            lifted(4, LStmt::Raw("r1 = r1 + 10".to_owned())),
        ];

        let result: StructureResult = structure_blocks(&stmts, 5);

        assert_eq!(result.unresolved_jumps, 0);
        assert!(matches!(
            result.blocks.as_slice(),
            [StructuredBlock::If { then_body, .. }]
                if matches!(
                    then_body.as_slice(),
                    [StructuredBlock::Raw(statement)] if statement == "r1 = r1 + 100"
                )
        ));
        assert!(matches!(
            result.blocks.as_slice(),
            [StructuredBlock::If { else_body, .. }]
                if matches!(
                    else_body.as_slice(),
                    [StructuredBlock::Raw(first), StructuredBlock::Raw(second)]
                        if first == "r1 = r1 + r0" && second == "r1 = r1 + 10"
                )
        ));
    }

    #[test]
    fn surviving_jump_hard_stops_and_counts_unresolved() {
        let stmts: Vec<LiftedStmt> = vec![
            lifted(0, LStmt::Raw("r0 = 1".to_owned())),
            lifted(1, LStmt::Jump { target: 4 }),
            lifted(2, LStmt::Raw("r0 = 2".to_owned())),
        ];

        let result: StructureResult = structure_blocks(&stmts, 4);

        assert_eq!(result.unresolved_jumps, 1);
        assert!(matches!(
            result.blocks.as_slice(),
            [
                StructuredBlock::Raw(first),
                StructuredBlock::Raw(marker),
                StructuredBlock::Raw(last)
            ] if first == "r0 = 1"
                && marker == "error(\"disrobe: unresolved luau jump to pc 4\")"
                && last == "r0 = 2"
        ));
    }
}
