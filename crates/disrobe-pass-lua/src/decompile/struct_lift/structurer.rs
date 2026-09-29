use crate::decompile::luau_lift::{LStmt, LiftedStmt};
use crate::decompile::luau_structure::{StructureWorkBudget, StructuredBlock};

const GENERIC_FOR_CONTROL_WIDTH: usize = 2;

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
    repeats: std::collections::BTreeMap<usize, RepeatEdge>,
    active_repeats: std::collections::BTreeSet<usize>,
    endless: std::collections::BTreeMap<usize, usize>,
    active_endless: std::collections::BTreeSet<usize>,
    label_candidates: LabelSites,
    placed_labels: std::collections::BTreeSet<usize>,
    edges: EdgeLedger,
    non_block_prefix: Vec<usize>,
    truncated_regions: usize,
    work: StructureWorkBudget,
}

#[derive(Debug)]
pub(super) struct StructureResult {
    pub blocks: Vec<StructuredBlock>,
    pub unresolved_jumps: usize,
    pub truncated_regions: usize,
}

#[derive(Debug)]
struct EdgeLedger {
    required: Vec<Option<usize>>,
    carried: Vec<bool>,
}

impl EdgeLedger {
    #[must_use]
    fn build(nodes: &[PcNode]) -> Self {
        let required: Vec<Option<usize>> = nodes
            .iter()
            .map(|n: &PcNode| match n.node {
                Node::Jump { target } if target == usize::MAX => None,
                Node::Jump { target } | Node::Cond { target, .. } => Some(target),
                Node::ForNum { exit, .. } | Node::ForGen { exit, .. } => Some(exit),
                Node::Raw(_) | Node::BlockEnd => None,
            })
            .collect();
        let carried: Vec<bool> = vec![false; required.len()];
        Self { required, carried }
    }

    fn carry(&mut self, index: usize) {
        if let Some(slot) = self.carried.get_mut(index) {
            *slot = true;
        }
    }

    #[must_use]
    fn dropped(&self) -> usize {
        self.required
            .iter()
            .zip(self.carried.iter())
            .filter(|(edge, carried): &(&Option<usize>, &bool)| edge.is_some() && !**carried)
            .count()
    }
}

#[derive(Debug, Clone)]
struct RepeatEdge {
    head: usize,
    cond_pc: usize,
    cond: String,
}

type LabelSites = std::collections::BTreeMap<usize, std::collections::BTreeSet<usize>>;

fn label_sites(nodes: &[PcNode]) -> LabelSites {
    let node_pcs: std::collections::BTreeSet<usize> = nodes.iter().map(|n: &PcNode| n.pc).collect();
    let mut sites: LabelSites = LabelSites::new();
    for n in nodes {
        if let Node::Jump { target } = n.node
            && target != usize::MAX
            && let Some(&site) = node_pcs.range(target..).next()
        {
            sites.entry(site).or_default().insert(target);
        }
    }
    sites
}

#[must_use]
pub(super) fn structure_standard(stmts: &[LiftedStmt], code_len: usize) -> StructureResult {
    let mut nodes: Vec<PcNode> = recover_short_circuit_chains(build_nodes(stmts));
    retarget_back_edges_through_closing_jumps(&mut nodes);
    let repeats: std::collections::BTreeMap<usize, RepeatEdge> = detect_repeats(&nodes);
    let label_candidates: LabelSites = label_sites(&nodes);
    let endless: std::collections::BTreeMap<usize, usize> = detect_endless_loops(&nodes, &repeats);
    let mut ctx: Ctx<'_> = Ctx {
        nodes: &nodes,
        end_pc: code_len + 1,
        repeats,
        active_repeats: std::collections::BTreeSet::new(),
        endless,
        active_endless: std::collections::BTreeSet::new(),
        label_candidates,
        placed_labels: std::collections::BTreeSet::new(),
        edges: EdgeLedger::build(&nodes),
        non_block_prefix: non_block_prefix(&nodes),
        truncated_regions: 0,
        work: StructureWorkBudget::for_nodes(nodes.len()),
    };
    let mut pos: usize = 0;
    let mut blocks: Vec<StructuredBlock> = structure_seq(&mut ctx, &mut pos, code_len + 1, None);
    let surviving_jumps: usize = finalize_gotos(&mut blocks, &ctx.placed_labels);
    StructureResult {
        blocks,
        unresolved_jumps: surviving_jumps.saturating_add(ctx.edges.dropped()),
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
    let mut pending: Vec<&mut [StructuredBlock]> = vec![blocks];
    while let Some(current) = pending.pop() {
        for block in current {
            match block {
                StructuredBlock::Goto { pc } => {
                    carried += 1;
                    if placed.contains(pc) {
                        surviving.insert(*pc);
                    } else {
                        let target: usize = *pc;
                        *block = StructuredBlock::Raw(format!("-- unresolved jump to pc {target}"));
                    }
                }
                StructuredBlock::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    pending.push(then_body.as_mut_slice());
                    pending.push(else_body.as_mut_slice());
                }
                StructuredBlock::While { body, .. }
                | StructuredBlock::Repeat { body, .. }
                | StructuredBlock::NumericFor { body, .. }
                | StructuredBlock::GenericFor { body, .. } => {
                    pending.push(body.as_mut_slice());
                }
                _ => {}
            }
        }
    }
    carried
}

fn prune_unreferenced_labels(
    blocks: &mut Vec<StructuredBlock>,
    surviving: &std::collections::BTreeSet<usize>,
) {
    let mut pending: Vec<&mut Vec<StructuredBlock>> = vec![blocks];
    while let Some(current) = pending.pop() {
        current.retain(|block: &StructuredBlock| {
            !matches!(block, StructuredBlock::Label { pc } if !surviving.contains(pc))
        });
        for block in current.iter_mut() {
            match block {
                StructuredBlock::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    pending.push(then_body);
                    pending.push(else_body);
                }
                StructuredBlock::While { body, .. }
                | StructuredBlock::Repeat { body, .. }
                | StructuredBlock::NumericFor { body, .. }
                | StructuredBlock::GenericFor { body, .. } => {
                    pending.push(body);
                }
                _ => {}
            }
        }
    }
}

fn recover_short_circuit_chains(nodes: Vec<PcNode>) -> Vec<PcNode> {
    let entered: std::collections::BTreeSet<usize> = nodes
        .iter()
        .filter_map(|n: &PcNode| match n.node {
            Node::Cond { target, .. } | Node::Jump { target } => Some(target),
            _ => None,
        })
        .collect();
    let mut out: Vec<PcNode> = Vec::with_capacity(nodes.len());
    let mut start: usize = 0;
    while start < nodes.len() {
        let mut end: usize = start;
        while end < nodes.len()
            && matches!(nodes[end].node, Node::Cond { .. })
            && (end == start || !entered.contains(&nodes[end].pc))
        {
            end += 1;
        }
        if end - start >= 2
            && let Some(next) = nodes.get(end)
            && let Some(folded) = fold_condition_chain(&nodes[start..end], next.pc)
        {
            out.push(folded);
            start = end;
            continue;
        }
        out.push(nodes[start].clone());
        start += 1;
    }
    out
}

fn fold_condition_chain(chain: &[PcNode], body_pc: usize) -> Option<PcNode> {
    let (last, init): (&PcNode, &[PcNode]) = chain.split_last()?;
    let Node::Cond {
        cond: last_cond,
        target: exit,
    } = &last.node
    else {
        return None;
    };
    let enters_body = |target: usize| -> bool { target > last.pc && target <= body_pc };
    if *exit == usize::MAX || enters_body(*exit) {
        return None;
    }
    let mut folded: String = last_cond.clone();
    for node in init.iter().rev() {
        let Node::Cond { cond, target } = &node.node else {
            return None;
        };
        folded = if *target == *exit {
            format!("({cond}) and ({folded})")
        } else if enters_body(*target) {
            format!(
                "({}) or ({folded})",
                crate::decompile::luau_structure::negate_cond(cond)
            )
        } else {
            return None;
        };
    }
    Some(PcNode {
        pc: chain.first()?.pc,
        node: Node::Cond {
            cond: folded,
            target: *exit,
        },
    })
}

fn retarget_back_edges_through_closing_jumps(nodes: &mut [PcNode]) {
    for i in 0..nodes.len() {
        let Node::Cond { target: head, .. } = nodes[i].node else {
            continue;
        };
        if head > nodes[i].pc || head == usize::MAX {
            continue;
        }
        let mut closing: Option<usize> = None;
        for later in &nodes[i + 1..] {
            match later.node {
                Node::Jump { target } if target == head => {
                    closing = Some(later.pc);
                    break;
                }
                Node::Jump { target } | Node::Cond { target, .. } if target <= later.pc => break,
                Node::ForNum { .. } | Node::ForGen { .. } | Node::BlockEnd => break,
                _ => {}
            }
        }
        if let Some(closing_pc) = closing
            && let Node::Cond { target, .. } = &mut nodes[i].node
        {
            *target = closing_pc;
        }
    }
}

#[must_use]
fn detect_repeats(nodes: &[PcNode]) -> std::collections::BTreeMap<usize, RepeatEdge> {
    let mut out: std::collections::BTreeMap<usize, RepeatEdge> = std::collections::BTreeMap::new();
    for n in nodes {
        if let Node::Cond { cond, target } = &n.node
            && *target <= n.pc
        {
            let head: usize = nodes
                .get(nodes.partition_point(|node: &PcNode| node.pc < *target))
                .map_or(*target, |node: &PcNode| node.pc.min(n.pc));
            let candidate: RepeatEdge = RepeatEdge {
                head,
                cond_pc: n.pc,
                cond: cond.clone(),
            };
            out.entry(head)
                .and_modify(|edge: &mut RepeatEdge| {
                    if candidate.cond_pc > edge.cond_pc {
                        *edge = candidate.clone();
                    }
                })
                .or_insert(candidate);
        }
    }
    out
}

#[must_use]
fn detect_endless_loops(
    nodes: &[PcNode],
    repeats: &std::collections::BTreeMap<usize, RepeatEdge>,
) -> std::collections::BTreeMap<usize, usize> {
    let mut out: std::collections::BTreeMap<usize, usize> = std::collections::BTreeMap::new();
    for n in nodes {
        let Node::Jump { target } = n.node else {
            continue;
        };
        if target == usize::MAX || target > n.pc {
            continue;
        }
        let Some(head) = nodes.get(nodes.partition_point(|node: &PcNode| node.pc < target)) else {
            continue;
        };
        let is_while_test: bool =
            matches!(head.node, Node::Cond { target: exit, .. } if exit == n.pc + 1);
        let is_counted: bool = matches!(head.node, Node::ForNum { .. } | Node::ForGen { .. });
        if is_while_test || is_counted || repeats.contains_key(&head.pc) {
            continue;
        }
        out.entry(head.pc)
            .and_modify(|jump_pc: &mut usize| *jump_pc = (*jump_pc).max(n.pc))
            .or_insert(n.pc);
    }
    out
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

#[derive(Debug)]
enum SequenceState {
    Scan,
    AfterRepeat {
        edge: RepeatEdge,
    },
    AfterNumericFor {
        var: String,
        init: String,
        limit: String,
        step: String,
    },
    AfterGenericFor {
        vars: Vec<String>,
        iter: String,
    },
    AfterWhile {
        cond: String,
        head: usize,
    },
    AfterEndless {
        head: usize,
        jump_pc: usize,
    },
    AfterThen {
        cond: String,
        target: usize,
        cur_loop: Option<LoopCtx>,
    },
    AfterElse {
        cond: String,
        then_body: Vec<StructuredBlock>,
    },
}

enum Budgeted<T> {
    Complete(T),
    Exhausted,
}

#[derive(Debug)]
struct SequenceFrame {
    stop_pc: usize,
    cur_loop: Option<LoopCtx>,
    state: SequenceState,
    out: Vec<StructuredBlock>,
}

impl SequenceFrame {
    fn new(stop_pc: usize, cur_loop: Option<LoopCtx>) -> Self {
        Self {
            stop_pc,
            cur_loop,
            state: SequenceState::Scan,
            out: Vec::new(),
        }
    }
}

fn structure_seq(
    ctx: &mut Ctx<'_>,
    pos: &mut usize,
    stop_pc: usize,
    cur_loop: Option<LoopCtx>,
) -> Vec<StructuredBlock> {
    let mut frames: Vec<SequenceFrame> = vec![SequenceFrame::new(stop_pc, cur_loop)];
    let mut completed: Option<Vec<StructuredBlock>> = None;
    loop {
        if let Some(body) = completed.take() {
            let Some(frame) = frames.last_mut() else {
                return body;
            };
            let state: SequenceState = std::mem::replace(&mut frame.state, SequenceState::Scan);
            match state {
                SequenceState::AfterRepeat { edge } => {
                    ctx.active_repeats.remove(&edge.head);
                    consume_cond(ctx, pos);
                    frame.out.push(StructuredBlock::Repeat {
                        cond: edge.cond,
                        body,
                    });
                }
                SequenceState::AfterNumericFor {
                    var,
                    init,
                    limit,
                    step,
                } => {
                    skip_block_end(ctx.nodes, pos);
                    frame.out.push(StructuredBlock::NumericFor {
                        var,
                        init,
                        limit,
                        step,
                        body,
                    });
                }
                SequenceState::AfterGenericFor { vars, iter } => {
                    skip_block_end(ctx.nodes, pos);
                    frame
                        .out
                        .push(StructuredBlock::GenericFor { vars, iter, body });
                }
                SequenceState::AfterWhile { cond, head } => {
                    let mut while_body: Vec<StructuredBlock> = body;
                    pop_trailing_goto(&mut while_body, head);
                    frame.out.push(StructuredBlock::While {
                        cond,
                        body: while_body,
                    });
                }
                SequenceState::AfterEndless { head, jump_pc } => {
                    ctx.active_endless.remove(&head);
                    if let Some(node) = ctx.nodes.get(*pos)
                        && node.pc == jump_pc
                        && matches!(node.node, Node::Jump { .. })
                    {
                        ctx.edges.carry(*pos);
                        *pos += 1;
                    }
                    frame.out.push(StructuredBlock::While {
                        cond: "true".to_owned(),
                        body,
                    });
                }
                SequenceState::AfterThen {
                    cond,
                    target,
                    cur_loop,
                } => {
                    let else_jump: Option<usize> =
                        preceding_forward_jump(ctx.nodes, *pos, target, cur_loop, ctx.end_pc);
                    match else_jump {
                        Some(else_end)
                            if else_end > target && else_end <= frame.stop_pc.min(ctx.end_pc) =>
                        {
                            let mut then_body: Vec<StructuredBlock> = body;
                            pop_trailing_goto(&mut then_body, else_end);
                            frame.state = SequenceState::AfterElse { cond, then_body };
                            frames.push(SequenceFrame::new(else_end, cur_loop));
                        }
                        _ => frame.out.push(StructuredBlock::If {
                            cond,
                            then_body: body,
                            else_body: Vec::new(),
                        }),
                    }
                }
                SequenceState::AfterElse { cond, then_body } => {
                    frame.out.push(StructuredBlock::If {
                        cond,
                        then_body,
                        else_body: body,
                    });
                }
                SequenceState::Scan => frame.out.extend(body),
            }
            continue;
        }

        let Some(frame) = frames.last_mut() else {
            return Vec::new();
        };
        if *pos >= ctx.nodes.len()
            || ctx
                .nodes
                .get(*pos)
                .is_some_and(|node: &PcNode| node.pc >= frame.stop_pc)
        {
            if let Some(finished) = frames.pop() {
                completed = Some(finished.out);
            } else {
                return Vec::new();
            }
            continue;
        }
        if !ctx.work.take() {
            skip_to_stop(ctx.nodes, pos, frame.stop_pc);
            ctx.truncated_regions = ctx.truncated_regions.saturating_add(1);
            frame.out.push(StructuredBlock::Raw(
                "-- structure work budget exhausted".to_owned(),
            ));
            if let Some(finished) = frames.pop() {
                completed = Some(finished.out);
            } else {
                return Vec::new();
            }
            continue;
        }

        let cur: PcNode = ctx.nodes[*pos].clone();
        let cur_index: usize = *pos;
        if let Some(targets) = ctx.label_candidates.get(&cur.pc) {
            for &target in targets {
                if ctx.placed_labels.insert(target) {
                    frame.out.push(StructuredBlock::Label { pc: target });
                }
            }
        }
        if let Some(edge) = ctx.repeats.get(&cur.pc).cloned()
            && !ctx.active_repeats.contains(&cur.pc)
            && !matches!(cur.node, Node::ForNum { .. } | Node::ForGen { .. })
        {
            ctx.active_repeats.insert(edge.head);
            frame.state = SequenceState::AfterRepeat { edge: edge.clone() };
            frames.push(SequenceFrame::new(
                edge.cond_pc,
                Some(LoopCtx {
                    exit: edge.cond_pc + 2,
                }),
            ));
            continue;
        }
        if let Some(&jump_pc) = ctx.endless.get(&cur.pc)
            && jump_pc < frame.stop_pc
            && ctx.active_endless.insert(cur.pc)
        {
            frame.state = SequenceState::AfterEndless {
                head: cur.pc,
                jump_pc,
            };
            frames.push(SequenceFrame::new(
                jump_pc,
                Some(LoopCtx { exit: jump_pc + 1 }),
            ));
            continue;
        }
        match cur.node {
            Node::Raw(s) => {
                frame.out.push(StructuredBlock::Raw(s));
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
                if exit <= frame.stop_pc {
                    ctx.edges.carry(cur_index);
                }
                frame.state = SequenceState::AfterNumericFor {
                    var,
                    init,
                    limit,
                    step,
                };
                frames.push(SequenceFrame::new(exit, Some(LoopCtx { exit })));
            }
            Node::ForGen { vars, iter, exit } => {
                *pos += 1;
                if exit <= frame.stop_pc {
                    ctx.edges.carry(cur_index);
                }
                frame.state = SequenceState::AfterGenericFor { vars, iter };
                let break_target: usize = exit.saturating_add(GENERIC_FOR_CONTROL_WIDTH);
                frames.push(SequenceFrame::new(
                    exit,
                    Some(LoopCtx { exit: break_target }),
                ));
            }
            Node::Jump { target } => {
                *pos += 1;
                ctx.edges.carry(cur_index);
                let is_break: bool = target == usize::MAX
                    || frame.cur_loop.is_some_and(|l: LoopCtx| target == l.exit);
                if is_break {
                    frame.out.push(StructuredBlock::Break);
                } else {
                    frame.out.push(StructuredBlock::Goto { pc: target });
                }
            }
            Node::Cond { cond, target } => {
                if target <= cur.pc {
                    *pos += 1;
                    continue;
                }
                if frame.cur_loop.is_some_and(|l: LoopCtx| l.exit == target) {
                    *pos += 1;
                    ctx.edges.carry(cur_index);
                    frame.out.push(StructuredBlock::If {
                        cond: crate::decompile::luau_structure::negate_cond(&cond),
                        then_body: vec![StructuredBlock::Break],
                        else_body: Vec::new(),
                    });
                    continue;
                }
                let back_jump: Option<usize> =
                    match jump_before(ctx.nodes, target, cur.pc, &mut ctx.work) {
                        Budgeted::Complete(back_jump) => back_jump,
                        Budgeted::Exhausted => continue,
                    };
                let while_head: Option<usize> = if let Some(head) = back_jump
                    && head <= cur.pc
                    && target <= frame.stop_pc
                {
                    while_test_covers_back_edge(ctx.nodes, &ctx.non_block_prefix, head, cur.pc)
                        .then_some(head)
                } else {
                    None
                };
                if let Some(head) = while_head {
                    let child_loop: LoopCtx = LoopCtx { exit: target };
                    *pos += 1;
                    ctx.edges.carry(cur_index);
                    frame.state = SequenceState::AfterWhile { cond, head };
                    frames.push(SequenceFrame::new(target, Some(child_loop)));
                    continue;
                }
                *pos += 1;
                if target <= frame.stop_pc {
                    ctx.edges.carry(cur_index);
                }
                let effective_then_stop: usize = target.min(frame.stop_pc);
                let child_loop: Option<LoopCtx> = frame.cur_loop;
                frame.state = SequenceState::AfterThen {
                    cond,
                    target,
                    cur_loop: child_loop,
                };
                frames.push(SequenceFrame::new(effective_then_stop, child_loop));
            }
        }
    }
}

fn skip_to_stop(nodes: &[PcNode], pos: &mut usize, stop_pc: usize) {
    while *pos < nodes.len() && nodes[*pos].pc < stop_pc {
        *pos += 1;
    }
}

#[must_use]
fn while_test_covers_back_edge(
    nodes: &[PcNode],
    non_block_prefix: &[usize],
    head: usize,
    test_pc: usize,
) -> bool {
    let start: usize = nodes.partition_point(|node: &PcNode| node.pc < head);
    let end: usize = nodes.partition_point(|node: &PcNode| node.pc < test_pc);
    non_block_prefix[end].saturating_sub(non_block_prefix[start]) == 0
}

#[must_use]
fn jump_before(
    nodes: &[PcNode],
    target: usize,
    cond_pc: usize,
    work: &mut StructureWorkBudget,
) -> Budgeted<Option<usize>> {
    let Some(preceding_pc): Option<usize> = target.checked_sub(1) else {
        return Budgeted::Complete(None);
    };
    let mut index: usize = nodes.partition_point(|node: &PcNode| node.pc < preceding_pc);
    while let Some(n) = nodes.get(index)
        && n.pc == preceding_pc
    {
        if !work.take() {
            return Budgeted::Exhausted;
        }
        if let Node::Jump { target: jt } = n.node
            && jt != usize::MAX
            && jt <= cond_pc
        {
            return Budgeted::Complete(Some(jt));
        }
        index += 1;
    }
    Budgeted::Complete(None)
}

fn non_block_prefix(nodes: &[PcNode]) -> Vec<usize> {
    let mut prefix: Vec<usize> = Vec::with_capacity(nodes.len().saturating_add(1));
    prefix.push(0);
    for node in nodes {
        let previous: usize = prefix.last().copied().unwrap_or(0);
        prefix.push(previous + usize::from(!matches!(node.node, Node::BlockEnd)));
    }
    prefix
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

fn pop_trailing_goto(body: &mut Vec<StructuredBlock>, absorbed_target: usize) {
    let Some(StructuredBlock::Goto { pc }) = body.last() else {
        return;
    };
    if *pc != absorbed_target {
        return;
    }
    body.pop();
}

fn consume_cond(ctx: &mut Ctx<'_>, pos: &mut usize) {
    if *pos < ctx.nodes.len() && matches!(ctx.nodes[*pos].node, Node::Cond { .. }) {
        ctx.edges.carry(*pos);
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
    use std::io::Write;
    use std::process::{Command, Stdio};

    const PREVIOUS_STRUCTURE_DEPTH_LIMIT: usize = 256;

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

    fn nested_guarded_conditionals(depth: usize) -> Vec<LiftedStmt> {
        let span: usize = depth * 2;
        let mut stmts: Vec<LiftedStmt> = Vec::with_capacity(depth + 1);
        for level in 0..depth {
            stmts.push(lifted(
                level,
                LStmt::Cond {
                    cond: "enabled".to_owned(),
                    target: span - level,
                },
            ));
        }
        stmts.push(lifted(depth, LStmt::Raw("result = result + 1".to_owned())));
        stmts
    }

    fn execute_source(interpreter: &str, source: &str) -> Option<std::process::Output> {
        let mut child: std::process::Child = Command::new(interpreter)
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .ok()?;
        let mut stdin: std::process::ChildStdin = child.stdin.take()?;
        let write_result: std::io::Result<()> = stdin.write_all(source.as_bytes());
        drop(stdin);
        let output: std::process::Output = child.wait_with_output().ok()?;
        if write_result.is_err() && output.status.success() {
            return None;
        }
        Some(output)
    }

    fn nested_else_conditionals(depth: usize) -> (Vec<LiftedStmt>, usize) {
        let end_pc: usize = depth * 3 + 1;
        let mut stmts: Vec<LiftedStmt> = Vec::with_capacity(depth * 3 + 1);
        for level in 0..depth {
            let pc: usize = level * 3;
            stmts.push(lifted(
                pc,
                LStmt::Cond {
                    cond: "enabled".to_owned(),
                    target: pc + 3,
                },
            ));
            stmts.push(lifted(pc + 1, LStmt::Raw(format!("then_{level} = true"))));
            stmts.push(lifted(pc + 2, LStmt::Jump { target: end_pc }));
        }
        stmts.push(lifted(depth * 3, LStmt::Raw("guarded_leaf()".to_owned())));
        (stmts, end_pc)
    }

    fn nested_numeric_fors(depth: usize) -> (Vec<LiftedStmt>, usize) {
        let mut stmts: Vec<LiftedStmt> = Vec::with_capacity(depth * 2 + 1);
        for level in 0..depth {
            stmts.push(lifted(
                level,
                LStmt::ForNum {
                    var: format!("i{level}"),
                    init: "1".to_owned(),
                    limit: "1".to_owned(),
                    step: "1".to_owned(),
                    end: depth * 2 - level,
                },
            ));
        }
        stmts.push(lifted(depth, LStmt::Raw("guarded_leaf()".to_owned())));
        for pc in depth + 1..=depth * 2 {
            stmts.push(lifted(pc, LStmt::BlockEnd));
        }
        (stmts, depth * 2 + 1)
    }

    fn nested_generic_fors(depth: usize) -> (Vec<LiftedStmt>, usize) {
        let mut stmts: Vec<LiftedStmt> = Vec::with_capacity(depth * 3 + 1);
        for level in 0..depth {
            stmts.push(lifted(
                level,
                LStmt::ForGen {
                    iter: "pairs(values)".to_owned(),
                    end: depth * 2 - level,
                },
            ));
            stmts.push(lifted(
                level,
                LStmt::Raw(format!("--FORGLOOP_VARS k{level},v{level}")),
            ));
        }
        stmts.push(lifted(depth, LStmt::Raw("guarded_leaf()".to_owned())));
        for pc in depth + 1..=depth * 2 {
            stmts.push(lifted(pc, LStmt::BlockEnd));
        }
        (stmts, depth * 2 + 1)
    }

    fn nested_whiles(depth: usize) -> (Vec<LiftedStmt>, usize) {
        let mut stmts: Vec<LiftedStmt> = Vec::with_capacity(depth * 2 + 1);
        for level in 0..depth {
            stmts.push(lifted(
                level,
                LStmt::Cond {
                    cond: "enabled".to_owned(),
                    target: depth * 2 + 1 - level,
                },
            ));
        }
        stmts.push(lifted(depth, LStmt::Raw("guarded_leaf()".to_owned())));
        for offset in 0..depth {
            stmts.push(lifted(
                depth + 1 + offset,
                LStmt::Jump {
                    target: depth - 1 - offset,
                },
            ));
        }
        (stmts, depth * 2 + 1)
    }

    fn nested_repeats(depth: usize) -> (Vec<LiftedStmt>, usize) {
        let mut stmts: Vec<LiftedStmt> = Vec::with_capacity(depth * 2 + 1);
        for level in 0..depth {
            stmts.push(lifted(level, LStmt::Raw(format!("enter_{level}()"))));
        }
        stmts.push(lifted(depth, LStmt::Raw("guarded_leaf()".to_owned())));
        for offset in 0..depth {
            stmts.push(lifted(
                depth + 1 + offset,
                LStmt::Cond {
                    cond: "finished".to_owned(),
                    target: depth - 1 - offset,
                },
            ));
        }
        (stmts, depth * 2 + 1)
    }

    fn nesting_of(blocks: &[StructuredBlock]) -> usize {
        let mut maximum: usize = 0;
        let mut pending: Vec<(&[StructuredBlock], usize)> = vec![(blocks, 0)];
        while let Some((current, depth)) = pending.pop() {
            maximum = maximum.max(depth);
            for block in current {
                match block {
                    StructuredBlock::If {
                        then_body,
                        else_body,
                        ..
                    } => {
                        pending.push((then_body, depth + 1));
                        pending.push((else_body, depth + 1));
                    }
                    StructuredBlock::While { body, .. }
                    | StructuredBlock::Repeat { body, .. }
                    | StructuredBlock::NumericFor { body, .. }
                    | StructuredBlock::GenericFor { body, .. } => {
                        pending.push((body, depth + 1));
                    }
                    StructuredBlock::Raw(_)
                    | StructuredBlock::Break
                    | StructuredBlock::Goto { .. }
                    | StructuredBlock::Label { .. } => {}
                }
            }
        }
        maximum
    }

    fn carries_depth_marker(blocks: &[StructuredBlock]) -> bool {
        let mut pending: Vec<&[StructuredBlock]> = vec![blocks];
        while let Some(current) = pending.pop() {
            for block in current {
                match block {
                    StructuredBlock::Raw(text) if text.contains("nesting deeper than") => {
                        return true;
                    }
                    StructuredBlock::If {
                        then_body,
                        else_body,
                        ..
                    } => {
                        pending.push(then_body);
                        pending.push(else_body);
                    }
                    StructuredBlock::While { body, .. }
                    | StructuredBlock::Repeat { body, .. }
                    | StructuredBlock::NumericFor { body, .. }
                    | StructuredBlock::GenericFor { body, .. } => pending.push(body),
                    StructuredBlock::Raw(_)
                    | StructuredBlock::Break
                    | StructuredBlock::Goto { .. }
                    | StructuredBlock::Label { .. } => {}
                }
            }
        }
        false
    }

    fn leaf_depth(blocks: &[StructuredBlock], statement: &str) -> Option<usize> {
        let mut pending: Vec<(&[StructuredBlock], usize)> = vec![(blocks, 0)];
        while let Some((current, depth)) = pending.pop() {
            for block in current {
                match block {
                    StructuredBlock::Raw(text) if text == statement => return Some(depth),
                    StructuredBlock::If {
                        then_body,
                        else_body,
                        ..
                    } => {
                        pending.push((then_body, depth + 1));
                        pending.push((else_body, depth + 1));
                    }
                    StructuredBlock::While { body, .. }
                    | StructuredBlock::Repeat { body, .. }
                    | StructuredBlock::NumericFor { body, .. }
                    | StructuredBlock::GenericFor { body, .. } => {
                        pending.push((body, depth + 1));
                    }
                    StructuredBlock::Raw(_)
                    | StructuredBlock::Break
                    | StructuredBlock::Goto { .. }
                    | StructuredBlock::Label { .. } => {}
                }
            }
        }
        None
    }

    #[test]
    fn nesting_far_past_the_previous_limit_returns_without_exhausting_the_stack() {
        let depth: usize = PREVIOUS_STRUCTURE_DEPTH_LIMIT * 8;
        let stmts: Vec<LiftedStmt> = nested_conditionals(depth);

        let worker: std::thread::JoinHandle<StructureResult> = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || structure_standard(&stmts, depth * 2))
            .expect("spawn a thread whose stack this walk overflowed before the limit existed");
        let result: StructureResult = worker.join().expect("the walk must return, never overflow");

        assert_eq!(result.truncated_regions, 0);
        assert_eq!(nesting_of(&result.blocks), depth);
        assert_eq!(leaf_depth(&result.blocks, "r1 = 1"), Some(depth));
        assert!(!carries_depth_marker(&result.blocks));
    }

    #[test]
    fn every_standard_region_kind_structures_renders_and_drops_on_a_small_stack() {
        let depth: usize = PREVIOUS_STRUCTURE_DEPTH_LIMIT * 2;
        let then_case: (Vec<LiftedStmt>, usize) = (nested_conditionals(depth), depth * 2);
        let else_case: (Vec<LiftedStmt>, usize) = nested_else_conditionals(depth);
        let numeric_case: (Vec<LiftedStmt>, usize) = nested_numeric_fors(depth);
        let generic_case: (Vec<LiftedStmt>, usize) = nested_generic_fors(depth);
        let while_case: (Vec<LiftedStmt>, usize) = nested_whiles(depth);
        let repeat_case: (Vec<LiftedStmt>, usize) = nested_repeats(depth);
        let cases: Vec<(&str, Vec<LiftedStmt>, usize, &str)> = vec![
            ("conditional then", then_case.0, then_case.1, "r1 = 1"),
            (
                "conditional else",
                else_case.0,
                else_case.1,
                "guarded_leaf()",
            ),
            (
                "numeric for",
                numeric_case.0,
                numeric_case.1,
                "guarded_leaf()",
            ),
            (
                "generic for",
                generic_case.0,
                generic_case.1,
                "guarded_leaf()",
            ),
            ("while", while_case.0, while_case.1, "guarded_leaf()"),
            ("repeat", repeat_case.0, repeat_case.1, "guarded_leaf()"),
        ];
        for (name, stmts, code_len, leaf) in cases {
            let worker: std::thread::JoinHandle<(usize, Option<usize>, usize, usize, usize)> =
                std::thread::Builder::new()
                    .stack_size(256 * 1024)
                    .spawn(move || {
                        let result: StructureResult = structure_standard(&stmts, code_len);
                        let tree_depth: usize = nesting_of(&result.blocks);
                        let guarded_depth: Option<usize> = leaf_depth(&result.blocks, leaf);
                        let rendered: crate::decompile::luau_lift::RenderedBlocks =
                            crate::decompile::luau_lift::render_blocks(&result.blocks, 0);
                        let outcome: (usize, Option<usize>, usize, usize, usize) = (
                            tree_depth,
                            guarded_depth,
                            result.unresolved_jumps,
                            result.truncated_regions,
                            rendered.source.len(),
                        );
                        drop(result);
                        outcome
                    })
                    .unwrap_or_else(|error: std::io::Error| {
                        panic!("{name}: cannot create the small-stack worker: {error}")
                    });
            let (tree_depth, guarded_depth, unresolved, truncated, rendered_len): (
                usize,
                Option<usize>,
                usize,
                usize,
                usize,
            ) = worker
                .join()
                .unwrap_or_else(|_| panic!("{name}: the iterative pipeline exhausted its stack"));
            assert_eq!(tree_depth, depth, "{name}");
            assert_eq!(guarded_depth, Some(depth), "{name}");
            assert_eq!(unresolved, 0, "{name}");
            assert_eq!(truncated, 0, "{name}");
            assert!(rendered_len > 0, "{name}");
        }
    }

    #[test]
    fn guarded_body_past_the_previous_limit_reexecutes_after_both_structurers() {
        let depth: usize = PREVIOUS_STRUCTURE_DEPTH_LIMIT + 1;
        let stmts: Vec<LiftedStmt> = nested_guarded_conditionals(depth);
        let standard: StructureResult = structure_standard(&stmts, depth * 2);
        let luau: crate::decompile::luau_structure::StructureResult =
            crate::decompile::luau_structure::structure_blocks(&stmts, depth * 2);
        assert_eq!(standard.truncated_regions, 0);
        assert_eq!(standard.unresolved_jumps, 0);
        assert_eq!(luau.refused_regions, 0);
        assert_eq!(luau.unresolved_jumps, 0);
        assert_eq!(
            leaf_depth(&standard.blocks, "result = result + 1"),
            Some(depth)
        );
        assert_eq!(leaf_depth(&luau.blocks, "result = result + 1"), Some(depth));
        let recovered_bodies: [String; 2] = [
            crate::decompile::luau_lift::render_blocks(&standard.blocks, 0).source,
            crate::decompile::luau_lift::render_blocks(&luau.blocks, 0).source,
        ];
        let original: &str =
            "local result = 0\nif enabled then result = result + 1 end\nprint(result)\n";
        let mut exercised: Vec<&str> = Vec::new();
        for interpreter in ["lua5.1", "lua5.3", "lua5.4"] {
            let executable: String = format!("{interpreter}{}", std::env::consts::EXE_SUFFIX);
            let program: &str = executable.as_str();
            let Some(version): Option<std::process::Output> =
                Command::new(program).arg("-v").output().ok()
            else {
                continue;
            };
            if !version.status.success() {
                continue;
            }
            exercised.push(interpreter);
            for enabled in [true, false] {
                let expected_source: String = format!("local enabled = {enabled}\n{original}");
                let expected: std::process::Output = execute_source(program, &expected_source)
                    .unwrap_or_else(|| panic!("{interpreter} must execute the original source"));
                assert!(
                    expected.status.success(),
                    "{interpreter} rejected the original source with enabled={enabled}: {}",
                    String::from_utf8_lossy(&expected.stderr)
                );
                for (index, body) in recovered_bodies.iter().enumerate() {
                    let source: String = format!(
                        "local enabled = {enabled}\nlocal result = 0\n{body}print(result)\n"
                    );
                    let actual: std::process::Output = execute_source(program, &source)
                        .unwrap_or_else(|| {
                            panic!(
                                "{interpreter} must execute recovered body {index} with enabled={enabled}"
                            )
                        });
                    assert!(
                        actual.status.success(),
                        "{interpreter} rejected recovered body {index} with enabled={enabled}: {}\n{source}",
                        String::from_utf8_lossy(&actual.stderr)
                    );
                    assert_eq!(
                        actual.stdout, expected.stdout,
                        "{interpreter} with enabled={enabled}: {source}"
                    );
                }
            }
        }
        if std::env::var_os("DISROBE_REQUIRE_LUA_TOOLCHAIN").is_some() {
            assert!(
                exercised.contains(&"lua5.1") && exercised.contains(&"lua5.4"),
                "lua5.1 and lua5.4 must be on PATH; ran {exercised:?}"
            );
        }
    }

    #[test]
    fn exhausted_work_budget_refuses_inside_the_guarded_region() {
        let stmts: Vec<LiftedStmt> = vec![
            lifted(
                0,
                LStmt::Cond {
                    cond: "enabled".to_owned(),
                    target: 3,
                },
            ),
            lifted(1, LStmt::Raw("guarded_leaf()".to_owned())),
            lifted(2, LStmt::Raw("guarded_tail()".to_owned())),
        ];
        let nodes: Vec<PcNode> = build_nodes(&stmts);
        let repeats: std::collections::BTreeMap<usize, RepeatEdge> = detect_repeats(&nodes);
        let mut ctx: Ctx<'_> = Ctx {
            nodes: &nodes,
            end_pc: 4,
            repeats,
            active_repeats: std::collections::BTreeSet::new(),
            endless: std::collections::BTreeMap::new(),
            active_endless: std::collections::BTreeSet::new(),
            label_candidates: LabelSites::new(),
            placed_labels: std::collections::BTreeSet::new(),
            edges: EdgeLedger::build(&nodes),
            non_block_prefix: non_block_prefix(&nodes),
            truncated_regions: 0,
            work: StructureWorkBudget::for_nodes(0),
        };
        let mut pos: usize = 0;

        let blocks: Vec<StructuredBlock> = structure_seq(&mut ctx, &mut pos, 4, None);

        assert_eq!(ctx.truncated_regions, 1);
        assert_eq!(
            leaf_depth(&blocks, "-- structure work budget exhausted"),
            Some(0)
        );
        assert_eq!(leaf_depth(&blocks, "guarded_leaf()"), None);
        assert_eq!(leaf_depth(&blocks, "guarded_tail()"), None);
    }

    #[test]
    fn public_structurers_refuse_inputs_past_the_total_work_ceiling() {
        let statement_count: usize = 70_000;
        let stmts: Vec<LiftedStmt> = (0..statement_count)
            .map(|pc: usize| lifted(pc, LStmt::Raw("statement()".to_owned())))
            .collect();

        let standard: StructureResult = structure_standard(&stmts, statement_count);
        let luau: crate::decompile::luau_structure::StructureResult =
            crate::decompile::luau_structure::structure_blocks(&stmts, statement_count);

        assert_eq!(standard.truncated_regions, 1);
        assert_eq!(
            leaf_depth(&standard.blocks, "-- structure work budget exhausted"),
            Some(0)
        );
        assert_eq!(luau.refused_regions, 1);
        assert_eq!(
            leaf_depth(
                &luau.blocks,
                "error(\"disrobe: structure work budget exhausted\")"
            ),
            Some(0)
        );
    }

    #[test]
    fn dense_nested_back_edges_complete_without_hidden_scan_work() {
        let depth: usize = 8_192;
        let (stmts, code_len): (Vec<LiftedStmt>, usize) = nested_whiles(depth);

        let standard: StructureResult = structure_standard(&stmts, code_len);
        let luau: crate::decompile::luau_structure::StructureResult =
            crate::decompile::luau_structure::structure_blocks(&stmts, code_len);

        assert_eq!(standard.truncated_regions, 0);
        assert_eq!(luau.refused_regions, 0);
        assert_eq!(nesting_of(&standard.blocks), depth);
        assert_eq!(nesting_of(&luau.blocks), depth);
    }

    #[test]
    fn dense_overlapping_malformed_back_edges_remain_within_the_work_ceiling() {
        let edge_count: usize = 4_096;
        let mut stmts: Vec<LiftedStmt> = Vec::with_capacity(edge_count * 2);
        for index in 0..edge_count {
            let pc: usize = index * 2;
            stmts.push(lifted(
                pc,
                LStmt::Cond {
                    cond: format!("repeat_{index}"),
                    target: 0,
                },
            ));
            stmts.push(lifted(pc + 1, LStmt::Jump { target: 0 }));
        }

        let standard: StructureResult = structure_standard(&stmts, edge_count * 2);
        let luau: crate::decompile::luau_structure::StructureResult =
            crate::decompile::luau_structure::structure_blocks(&stmts, edge_count * 2);

        assert_eq!(standard.truncated_regions, 0);
        assert_eq!(luau.refused_regions, 0);
        assert!(standard.unresolved_jumps > 0);
        assert!(luau.unresolved_jumps > 0);
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
    fn a_conditional_branch_past_the_region_is_dropped_without_a_surviving_goto() {
        let stmts: Vec<LiftedStmt> = vec![
            lifted(
                0,
                LStmt::Cond {
                    cond: "x > 0".to_owned(),
                    target: 100,
                },
            ),
            lifted(1, LStmt::Raw("y = 1".to_owned())),
        ];

        let result: StructureResult = structure_standard(&stmts, 3);

        assert!(
            !carries_goto_to(&result.blocks, 100),
            "the target lies past the region this walk ever visits, so the tree never places a \
             goto to it; blocks: {:?}",
            result.blocks
        );
        assert!(
            result.unresolved_jumps > 0,
            "a conditional branch to a target the walk never places is a dropped edge even when \
             it never survives as a goto in the tree; the edge ledger, not a walk over the \
             finished tree, is what has to catch it; blocks: {:?}",
            result.blocks
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

    fn carries_while(blocks: &[StructuredBlock]) -> bool {
        blocks.iter().any(|b: &StructuredBlock| match b {
            StructuredBlock::While { .. } => true,
            StructuredBlock::If {
                then_body,
                else_body,
                ..
            } => carries_while(then_body) || carries_while(else_body),
            StructuredBlock::Repeat { body, .. }
            | StructuredBlock::NumericFor { body, .. }
            | StructuredBlock::GenericFor { body, .. } => carries_while(body),
            _ => false,
        })
    }

    #[test]
    fn a_back_edge_that_re_enters_a_statement_before_the_test_loops_over_that_statement() {
        let stmts: Vec<LiftedStmt> = vec![
            lifted(0, LStmt::Raw("local acc = 0".to_owned())),
            lifted(2, LStmt::Raw("acc = acc + 1".to_owned())),
            lifted(
                3,
                LStmt::Cond {
                    cond: "i < 5".to_owned(),
                    target: 6,
                },
            ),
            lifted(4, LStmt::Raw("i = i + 1".to_owned())),
            lifted(5, LStmt::Jump { target: 2 }),
            lifted(6, LStmt::Raw("print(i, acc)".to_owned())),
        ];

        let result: StructureResult = structure_standard(&stmts, 7);

        let exit_test: String = crate::decompile::luau_structure::negate_cond("i < 5");
        let shape_holds: bool = match result.blocks.as_slice() {
            [
                StructuredBlock::Raw(before),
                StructuredBlock::While { cond, body },
                StructuredBlock::Raw(after),
            ] => {
                before == "local acc = 0"
                    && cond == "true"
                    && after == "print(i, acc)"
                    && matches!(
                        body.as_slice(),
                        [
                            StructuredBlock::Raw(head),
                            StructuredBlock::If { cond: test, then_body, else_body },
                            StructuredBlock::Raw(step),
                        ] if head == "acc = acc + 1"
                            && *test == exit_test
                            && matches!(then_body.as_slice(), [StructuredBlock::Break])
                            && else_body.is_empty()
                            && step == "i = i + 1"
                    )
            }
            _ => false,
        };
        assert!(
            shape_holds,
            "the back edge re-enters the statement at pc 2, so that statement must stay inside \
             an endless loop that tests after it and breaks, never run once before a while; \
             blocks: {:?}",
            result.blocks
        );
        assert_eq!(
            result.unresolved_jumps, 0,
            "every edge is carried by the loop; blocks: {:?}",
            result.blocks
        );
    }

    #[test]
    fn a_back_edge_that_re_enters_only_the_test_becomes_a_while_and_reports_clean() {
        let stmts: Vec<LiftedStmt> = vec![
            lifted(
                0,
                LStmt::Cond {
                    cond: "i < 5".to_owned(),
                    target: 4,
                },
            ),
            lifted(1, LStmt::Raw("acc = acc + i".to_owned())),
            lifted(2, LStmt::Raw("i = i + 1".to_owned())),
            lifted(3, LStmt::Jump { target: 0 }),
            lifted(4, LStmt::Raw("print(acc)".to_owned())),
        ];

        let result: StructureResult = structure_standard(&stmts, 5);

        assert!(
            carries_while(&result.blocks),
            "the back edge re-enters the test itself, so the while carries it exactly; blocks: {:?}",
            result.blocks
        );
        assert_eq!(
            result.unresolved_jumps, 0,
            "every edge is carried, so nothing is outstanding; blocks: {:?}",
            result.blocks
        );
    }

    #[test]
    fn a_numeric_for_reports_its_exit_edge_as_carried() {
        let stmts: Vec<LiftedStmt> = vec![
            lifted(
                0,
                LStmt::ForNum {
                    var: "i".to_owned(),
                    init: "1".to_owned(),
                    limit: "10".to_owned(),
                    step: "1".to_owned(),
                    end: 3,
                },
            ),
            lifted(1, LStmt::Raw("acc = acc + i".to_owned())),
            lifted(2, LStmt::BlockEnd),
            lifted(3, LStmt::Raw("print(acc)".to_owned())),
        ];

        let result: StructureResult = structure_standard(&stmts, 4);

        assert_eq!(result.unresolved_jumps, 0, "blocks: {:?}", result.blocks);
    }

    #[test]
    fn a_generic_for_reports_its_exit_edge_as_carried() {
        let stmts: Vec<LiftedStmt> = vec![
            lifted(
                0,
                LStmt::ForGen {
                    iter: "ipairs(t)".to_owned(),
                    end: 3,
                },
            ),
            lifted(1, LStmt::Raw("acc = acc + v".to_owned())),
            lifted(2, LStmt::BlockEnd),
            lifted(3, LStmt::Raw("print(acc)".to_owned())),
        ];

        let result: StructureResult = structure_standard(&stmts, 4);

        assert_eq!(result.unresolved_jumps, 0, "blocks: {:?}", result.blocks);
    }

    #[test]
    fn a_jump_to_the_loop_exit_becomes_a_break_that_carries_its_edge() {
        let stmts: Vec<LiftedStmt> = vec![
            lifted(
                0,
                LStmt::ForNum {
                    var: "i".to_owned(),
                    init: "1".to_owned(),
                    limit: "10".to_owned(),
                    step: "1".to_owned(),
                    end: 4,
                },
            ),
            lifted(1, LStmt::Raw("first = i".to_owned())),
            lifted(2, LStmt::Jump { target: 4 }),
            lifted(3, LStmt::BlockEnd),
            lifted(4, LStmt::Raw("print(first)".to_owned())),
        ];

        let result: StructureResult = structure_standard(&stmts, 5);

        assert_eq!(
            result.unresolved_jumps, 0,
            "a break lands on the loop exit, which is the edge the jump asked for; blocks: {:?}",
            result.blocks
        );
    }

    #[test]
    fn a_condition_on_the_loop_exit_becomes_a_break_that_carries_its_edge() {
        let stmts: Vec<LiftedStmt> = vec![
            lifted(
                0,
                LStmt::ForNum {
                    var: "i".to_owned(),
                    init: "1".to_owned(),
                    limit: "10".to_owned(),
                    step: "1".to_owned(),
                    end: 5,
                },
            ),
            lifted(
                1,
                LStmt::Cond {
                    cond: "i > 3".to_owned(),
                    target: 5,
                },
            ),
            lifted(2, LStmt::Raw("acc = acc + i".to_owned())),
            lifted(3, LStmt::BlockEnd),
            lifted(5, LStmt::Raw("print(acc)".to_owned())),
        ];

        let result: StructureResult = structure_standard(&stmts, 6);

        assert_eq!(result.unresolved_jumps, 0, "blocks: {:?}", result.blocks);
    }

    #[test]
    fn a_repeat_carries_the_back_condition_that_closes_it() {
        let stmts: Vec<LiftedStmt> = vec![
            lifted(0, LStmt::Raw("i = i + 1".to_owned())),
            lifted(1, LStmt::Raw("s = s .. i".to_owned())),
            lifted(
                2,
                LStmt::Cond {
                    cond: "i >= 5".to_owned(),
                    target: 0,
                },
            ),
            lifted(3, LStmt::Raw("print(s)".to_owned())),
        ];

        let result: StructureResult = structure_standard(&stmts, 4);

        assert!(
            matches!(result.blocks.first(), Some(StructuredBlock::Repeat { .. })),
            "blocks: {:?}",
            result.blocks
        );
        assert_eq!(result.unresolved_jumps, 0, "blocks: {:?}", result.blocks);
    }

    #[test]
    fn a_repeat_whose_head_instruction_emits_no_statement_still_loops() {
        let stmts: Vec<LiftedStmt> = vec![
            lifted(1, LStmt::Raw("n = n + 1".to_owned())),
            lifted(
                2,
                LStmt::Cond {
                    cond: "(n * 2) >= 6".to_owned(),
                    target: 0,
                },
            ),
            lifted(3, LStmt::Raw("print(n)".to_owned())),
        ];

        let result: StructureResult = structure_standard(&stmts, 4);

        assert!(
            matches!(
                result.blocks.first(),
                Some(StructuredBlock::Repeat { body, .. }) if body.len() == 1
            ),
            "the back condition targets pc 0, which only folded into the condition; blocks: {:?}",
            result.blocks
        );
        assert_eq!(result.unresolved_jumps, 0, "blocks: {:?}", result.blocks);
    }

    #[test]
    fn two_back_conditions_on_the_same_head_close_the_repeat_together() {
        let stmts: Vec<LiftedStmt> = vec![
            lifted(0, LStmt::Raw("i = i + 1".to_owned())),
            lifted(
                1,
                LStmt::Cond {
                    cond: "i >= 5".to_owned(),
                    target: 0,
                },
            ),
            lifted(
                2,
                LStmt::Cond {
                    cond: "s > 100".to_owned(),
                    target: 0,
                },
            ),
            lifted(3, LStmt::Raw("print(s)".to_owned())),
        ];

        let result: StructureResult = structure_standard(&stmts, 4);

        assert_eq!(result.unresolved_jumps, 0, "blocks: {:?}", result.blocks);
        assert!(
            matches!(
                result.blocks.first(),
                Some(StructuredBlock::Repeat { cond, .. }) if cond == "(i >= 5) and (s > 100)"
            ),
            "each condition branches back when false, so the loop ends only when both hold; \
             blocks: {:?}",
            result.blocks
        );
    }

    #[test]
    fn a_plain_forward_branch_carries_its_own_edge() {
        let stmts: Vec<LiftedStmt> = vec![
            lifted(
                0,
                LStmt::Cond {
                    cond: "x > 0".to_owned(),
                    target: 3,
                },
            ),
            lifted(1, LStmt::Raw("r = x".to_owned())),
            lifted(3, LStmt::Raw("print(r)".to_owned())),
        ];

        let result: StructureResult = structure_standard(&stmts, 4);

        assert_eq!(result.unresolved_jumps, 0, "blocks: {:?}", result.blocks);
    }

    fn fold(stmts: &[LiftedStmt]) -> Vec<PcNode> {
        recover_short_circuit_chains(build_nodes(stmts))
    }

    fn cond(pc: usize, text: &str, target: usize) -> LiftedStmt {
        lifted(
            pc,
            LStmt::Cond {
                cond: text.to_owned(),
                target,
            },
        )
    }

    #[test]
    fn conditions_sharing_the_false_exit_fold_into_a_conjunction() {
        let nodes: Vec<PcNode> = fold(&[
            cond(0, "x < 10", 5),
            cond(2, "(x % 2) == 0", 5),
            lifted(4, LStmt::Raw("return 1".to_owned())),
            lifted(5, LStmt::Raw("return 2".to_owned())),
        ]);
        assert!(
            matches!(&nodes[0].node, Node::Cond { cond, target: 5 } if cond == "(x < 10) and ((x % 2) == 0)"),
            "{nodes:?}"
        );
        assert_eq!(nodes.len(), 3);
    }

    #[test]
    fn a_condition_that_enters_the_body_folds_into_a_negated_disjunct() {
        let nodes: Vec<PcNode> = fold(&[
            cond(0, "n < 20", 9),
            cond(2, "(n % 7) == 6", 6),
            cond(4, "#acc < 2", 9),
            lifted(6, LStmt::Raw("n = n + 1".to_owned())),
            lifted(9, LStmt::Raw("print(n)".to_owned())),
        ]);
        assert!(
            matches!(&nodes[0].node, Node::Cond { cond, target: 9 } if cond == "(n < 20) and (((n % 7) ~= 6) or (#acc < 2))"),
            "{nodes:?}"
        );
    }

    #[test]
    fn a_chain_stops_before_a_condition_entered_from_elsewhere() {
        let nodes: Vec<PcNode> = fold(&[
            cond(0, "a", 4),
            cond(2, "b", 9),
            cond(4, "c", 9),
            lifted(6, LStmt::Raw("x = 1".to_owned())),
            lifted(9, LStmt::Raw("x = 2".to_owned())),
        ]);
        assert_eq!(nodes.len(), 4, "{nodes:?}");
        assert!(
            matches!(&nodes[0].node, Node::Cond { cond, target: 9 } if cond == "(not (a)) or (b)"),
            "{nodes:?}"
        );
        assert!(matches!(&nodes[1].node, Node::Cond { cond, target: 9 } if cond == "c"));
    }

    #[test]
    fn a_condition_that_jumps_past_the_body_start_is_left_unfolded() {
        let nodes: Vec<PcNode> = fold(&[
            cond(0, "a", 7),
            cond(2, "b", 9),
            lifted(4, LStmt::Raw("x = 1".to_owned())),
            lifted(7, LStmt::Raw("x = 3".to_owned())),
            lifted(9, LStmt::Raw("x = 2".to_owned())),
        ]);
        assert_eq!(nodes.len(), 5, "{nodes:?}");
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
    fn the_work_budget_accepts_many_shallow_sibling_regions() {
        let branches: usize = 5000;
        let stmts: Vec<LiftedStmt> = branch_ladder(branches);

        let result: StructureResult = structure_standard(&stmts, branches * 2);

        assert_eq!(
            result.truncated_regions, 0,
            "{branches} sibling branches require linear work, so the node-derived budget must \
             accept all of them"
        );
        assert_eq!(
            count_conditionals(&result.blocks),
            branches,
            "every branch is recovered"
        );
        assert_eq!(
            empty_conditionals(&result.blocks),
            0,
            "every branch must keep the statement it guards"
        );
        assert_eq!(nesting_of(&result.blocks), 1, "the ladder is flat");
    }

    #[test]
    fn a_chain_deeper_than_the_previous_limit_keeps_its_guarded_body() {
        let depth: usize = PREVIOUS_STRUCTURE_DEPTH_LIMIT + 40;
        let stmts: Vec<LiftedStmt> = nested_conditionals(depth);

        let result: StructureResult = structure_standard(&stmts, depth * 2);

        assert_eq!(result.truncated_regions, 0);
        assert_eq!(result.unresolved_jumps, 0);
        assert_eq!(nesting_of(&result.blocks), depth);
        assert_eq!(leaf_depth(&result.blocks, "r1 = 1"), Some(depth));
        assert!(!carries_depth_marker(&result.blocks));
    }

    #[test]
    fn nesting_inside_the_previous_limit_is_recovered_at_its_real_depth() {
        let depth: usize = PREVIOUS_STRUCTURE_DEPTH_LIMIT - 8;
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
