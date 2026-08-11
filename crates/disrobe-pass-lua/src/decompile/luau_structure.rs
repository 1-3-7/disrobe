use crate::decompile::luau_lift::{LStmt, LiftedStmt};

const MAX_STRUCTURE_VISITS_PER_NODE: usize = 2;
pub(crate) const MAX_STRUCTURE_WORK: usize = 1 << 16;

#[derive(Debug)]
pub(crate) struct StructureWorkBudget {
    remaining: usize,
}

impl StructureWorkBudget {
    pub(crate) fn for_nodes(node_count: usize) -> Self {
        Self {
            remaining: node_count
                .saturating_mul(MAX_STRUCTURE_VISITS_PER_NODE)
                .saturating_add(1)
                .min(MAX_STRUCTURE_WORK),
        }
    }

    pub(crate) fn take(&mut self) -> bool {
        if self.remaining == 0 {
            return false;
        }
        self.remaining -= 1;
        true
    }
}

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

impl Drop for StructuredBlock {
    fn drop(&mut self) {
        let mut pending: Vec<Vec<StructuredBlock>> = Vec::new();
        take_nested_bodies(self, &mut pending);
        while let Some(mut body) = pending.pop() {
            while let Some(mut child) = body.pop() {
                take_nested_bodies(&mut child, &mut pending);
            }
        }
    }
}

fn take_nested_bodies(block: &mut StructuredBlock, pending: &mut Vec<Vec<StructuredBlock>>) {
    match block {
        StructuredBlock::If {
            then_body,
            else_body,
            ..
        } => {
            pending.push(std::mem::take(then_body));
            pending.push(std::mem::take(else_body));
        }
        StructuredBlock::While { body, .. }
        | StructuredBlock::Repeat { body, .. }
        | StructuredBlock::NumericFor { body, .. }
        | StructuredBlock::GenericFor { body, .. } => {
            pending.push(std::mem::take(body));
        }
        StructuredBlock::Raw(_)
        | StructuredBlock::Break
        | StructuredBlock::Goto { .. }
        | StructuredBlock::Label { .. } => {}
    }
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
    let loops: std::collections::BTreeMap<usize, BackEdge> = detect_back_edges(&nodes);
    let mut pos: usize = 0;
    let mut ctx: SeqCtx<'_> = SeqCtx {
        nodes: &nodes,
        loops: &loops,
        active: std::collections::BTreeSet::new(),
        refused_regions: 0,
        edges: EdgeLedger::build(&nodes),
        work: StructureWorkBudget::for_nodes(nodes.len()),
    };
    let mut blocks: Vec<StructuredBlock> = structure_seq(&mut ctx, &mut pos, code_len + 1, None);
    let surviving_jumps: usize = finalize_unresolved_jumps(&mut blocks);
    StructureResult {
        blocks,
        unresolved_jumps: surviving_jumps.saturating_add(ctx.edges.dropped()),
        refused_regions: ctx.refused_regions,
    }
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

#[derive(Debug, Clone, Copy)]
struct BackEdge {
    head: usize,
    tail_pc: usize,
}

struct SeqCtx<'a> {
    nodes: &'a [PcNode],
    loops: &'a std::collections::BTreeMap<usize, BackEdge>,
    active: std::collections::BTreeSet<usize>,
    refused_regions: usize,
    edges: EdgeLedger,
    work: StructureWorkBudget,
}

#[must_use]
fn detect_back_edges(nodes: &[PcNode]) -> std::collections::BTreeMap<usize, BackEdge> {
    let mut edges: std::collections::BTreeMap<usize, BackEdge> = std::collections::BTreeMap::new();
    for n in nodes {
        if let Node::Jump { target } = n.node
            && target <= n.pc
        {
            let candidate: BackEdge = BackEdge {
                head: target,
                tail_pc: n.pc,
            };
            edges
                .entry(target)
                .and_modify(|edge: &mut BackEdge| {
                    if candidate.tail_pc > edge.tail_pc {
                        *edge = candidate;
                    }
                })
                .or_insert(candidate);
        }
    }
    edges
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

#[derive(Debug)]
enum SequenceState {
    Scan,
    AfterLoop {
        edge: BackEdge,
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
    AfterLoopExitIf {
        cond: String,
    },
    AfterThen {
        cond: String,
        target: usize,
        cur_loop: Option<LoopRef>,
    },
    AfterElse {
        cond: String,
        then_body: Vec<StructuredBlock>,
    },
}

#[derive(Debug)]
struct SequenceFrame {
    stop_pc: usize,
    cur_loop: Option<LoopRef>,
    state: SequenceState,
    out: Vec<StructuredBlock>,
}

impl SequenceFrame {
    fn new(stop_pc: usize, cur_loop: Option<LoopRef>) -> Self {
        Self {
            stop_pc,
            cur_loop,
            state: SequenceState::Scan,
            out: Vec::new(),
        }
    }
}

fn structure_seq(
    ctx: &mut SeqCtx<'_>,
    pos: &mut usize,
    stop_pc: usize,
    cur_loop: Option<LoopRef>,
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
                SequenceState::AfterLoop { edge } => {
                    ctx.active.remove(&edge.head);
                    consume_back_edge(ctx, pos, edge.head);
                    frame.out.push(simplify_loop(body));
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
                SequenceState::AfterLoopExitIf { cond } => {
                    frame.out.push(StructuredBlock::If {
                        cond,
                        then_body: body,
                        else_body: Vec::new(),
                    });
                }
                SequenceState::AfterThen {
                    cond,
                    target,
                    cur_loop,
                } => {
                    let else_jump: Option<usize> =
                        pre_target_else(ctx.nodes, *pos, target, cur_loop);
                    match else_jump {
                        Some(else_end) if else_end > target => {
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
            ctx.refused_regions = ctx.refused_regions.saturating_add(1);
            frame.out.push(StructuredBlock::Raw(
                "error(\"disrobe: structure work budget exhausted\")".to_owned(),
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
        if let Some(edge) = ctx.loops.get(&cur.pc).copied()
            && !ctx.active.contains(&cur.pc)
        {
            ctx.active.insert(edge.head);
            frame.state = SequenceState::AfterLoop { edge };
            frames.push(SequenceFrame::new(
                edge.tail_pc,
                Some(LoopRef {
                    exit: edge.tail_pc + 1,
                    is_while: true,
                }),
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
                frames.push(SequenceFrame::new(
                    exit,
                    Some(LoopRef {
                        exit,
                        is_while: false,
                    }),
                ));
            }
            Node::ForGen { vars, iter, exit } => {
                *pos += 1;
                if exit <= frame.stop_pc {
                    ctx.edges.carry(cur_index);
                }
                frame.state = SequenceState::AfterGenericFor { vars, iter };
                frames.push(SequenceFrame::new(
                    exit,
                    Some(LoopRef {
                        exit,
                        is_while: false,
                    }),
                ));
            }
            Node::Jump { target } => {
                *pos += 1;
                ctx.edges.carry(cur_index);
                let is_break: bool = target == usize::MAX
                    || frame.cur_loop.is_some_and(|l: LoopRef| l.exit == target);
                if is_break {
                    frame.out.push(StructuredBlock::Break);
                } else {
                    frame.out.push(StructuredBlock::Goto { pc: target });
                }
            }
            Node::Cond { cond, target } => {
                *pos += 1;
                if target <= cur.pc {
                    continue;
                }
                let is_loop_exit: bool = frame.cur_loop.is_some_and(|l: LoopRef| l.exit == target);
                if is_loop_exit && frame.cur_loop.is_some_and(|l: LoopRef| l.is_while) {
                    ctx.edges.carry(cur_index);
                    frame.out.push(StructuredBlock::If {
                        cond: negate_cond(&cond),
                        then_body: vec![StructuredBlock::Break],
                        else_body: Vec::new(),
                    });
                    continue;
                }
                if is_loop_exit {
                    ctx.edges.carry(cur_index);
                    let child_stop: usize = frame.stop_pc;
                    let child_loop: Option<LoopRef> = frame.cur_loop;
                    frame.state = SequenceState::AfterLoopExitIf { cond };
                    frames.push(SequenceFrame::new(child_stop, child_loop));
                    continue;
                }
                if target <= frame.stop_pc {
                    ctx.edges.carry(cur_index);
                }
                let effective_target: usize = target.min(frame.stop_pc);
                let child_loop: Option<LoopRef> = frame.cur_loop;
                frame.state = SequenceState::AfterThen {
                    cond,
                    target,
                    cur_loop: child_loop,
                };
                frames.push(SequenceFrame::new(effective_target, child_loop));
            }
        }
    }
}

fn skip_to_stop(nodes: &[PcNode], pos: &mut usize, stop_pc: usize) {
    while *pos < nodes.len() && nodes[*pos].pc < stop_pc {
        *pos += 1;
    }
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
    let mut pending: Vec<&mut [StructuredBlock]> = vec![blocks];
    while let Some(current) = pending.pop() {
        for block in current {
            match block {
                StructuredBlock::Goto { pc } => {
                    let target: usize = *pc;
                    *block = StructuredBlock::Raw(format!(
                        "error(\"disrobe: unresolved luau jump to pc {target}\")"
                    ));
                    unresolved = unresolved.saturating_add(1);
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
                StructuredBlock::Raw(_)
                | StructuredBlock::Break
                | StructuredBlock::Label { .. } => {}
            }
        }
    }
    unresolved
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

fn consume_back_edge(ctx: &mut SeqCtx<'_>, pos: &mut usize, head: usize) {
    if *pos < ctx.nodes.len()
        && let Node::Jump { target } = ctx.nodes[*pos].node
        && target == head
    {
        ctx.edges.carry(*pos);
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

    const PREVIOUS_STRUCTURE_DEPTH_LIMIT: usize = 256;

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
        let depth: usize = PREVIOUS_STRUCTURE_DEPTH_LIMIT * 24;
        let stmts: Vec<LiftedStmt> = nested_conditionals(depth);

        let worker: std::thread::JoinHandle<StructureResult> = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || structure_blocks(&stmts, depth * 2))
            .expect("spawn a thread whose stack this walk overflowed before the limit existed");
        let result: StructureResult = worker.join().expect("the walk must return, never overflow");

        assert_eq!(result.refused_regions, 0);
        assert_eq!(nesting_of(&result.blocks), depth);
        assert_eq!(leaf_depth(&result.blocks, "r1 = 1"), Some(depth));
        assert!(!carries_depth_marker(&result.blocks));
    }

    #[test]
    fn every_luau_region_kind_structures_renders_and_drops_on_a_small_stack() {
        let depth: usize = PREVIOUS_STRUCTURE_DEPTH_LIMIT * 2;
        let then_case: (Vec<LiftedStmt>, usize) = (nested_conditionals(depth), depth * 2);
        let else_case: (Vec<LiftedStmt>, usize) = nested_else_conditionals(depth);
        let numeric_case: (Vec<LiftedStmt>, usize) = nested_numeric_fors(depth);
        let generic_case: (Vec<LiftedStmt>, usize) = nested_generic_fors(depth);
        let while_case: (Vec<LiftedStmt>, usize) = nested_whiles(depth);
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
        ];
        for (name, stmts, code_len, leaf) in cases {
            let worker: std::thread::JoinHandle<(usize, Option<usize>, usize, usize, usize)> =
                std::thread::Builder::new()
                    .stack_size(256 * 1024)
                    .spawn(move || {
                        let result: StructureResult = structure_blocks(&stmts, code_len);
                        let tree_depth: usize = nesting_of(&result.blocks);
                        let guarded_depth: Option<usize> = leaf_depth(&result.blocks, leaf);
                        let rendered: crate::decompile::luau_lift::RenderedBlocks =
                            crate::decompile::luau_lift::render_blocks(&result.blocks, 0);
                        let outcome: (usize, Option<usize>, usize, usize, usize) = (
                            tree_depth,
                            guarded_depth,
                            result.unresolved_jumps,
                            result.refused_regions,
                            rendered.source.len(),
                        );
                        drop(result);
                        outcome
                    })
                    .unwrap_or_else(|error: std::io::Error| {
                        panic!("{name}: cannot create the small-stack worker: {error}")
                    });
            let (tree_depth, guarded_depth, unresolved, refused, rendered_len): (
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
            assert_eq!(refused, 0, "{name}");
            assert!(rendered_len > 0, "{name}");
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
        let loops: std::collections::BTreeMap<usize, BackEdge> = detect_back_edges(&nodes);
        let mut ctx: SeqCtx<'_> = SeqCtx {
            nodes: &nodes,
            loops: &loops,
            active: std::collections::BTreeSet::new(),
            refused_regions: 0,
            edges: EdgeLedger::build(&nodes),
            work: StructureWorkBudget::for_nodes(0),
        };
        let mut pos: usize = 0;

        let blocks: Vec<StructuredBlock> = structure_seq(&mut ctx, &mut pos, 4, None);

        assert_eq!(ctx.refused_regions, 1);
        assert_eq!(
            leaf_depth(
                &blocks,
                "error(\"disrobe: structure work budget exhausted\")"
            ),
            Some(1)
        );
        assert_eq!(leaf_depth(&blocks, "guarded_leaf()"), None);
        assert_eq!(leaf_depth(&blocks, "guarded_tail()"), None);
    }

    #[test]
    fn every_structured_block_variant_drops_iteratively() {
        let depth: usize = PREVIOUS_STRUCTURE_DEPTH_LIMIT * 64;
        let worker: std::thread::JoinHandle<()> = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(move || {
                let mut body: Vec<StructuredBlock> =
                    vec![StructuredBlock::Raw("guarded_leaf()".to_owned())];
                for level in 0..depth {
                    body = vec![match level % 6 {
                        0 => StructuredBlock::If {
                            cond: "enabled".to_owned(),
                            then_body: body,
                            else_body: Vec::new(),
                        },
                        1 => StructuredBlock::While {
                            cond: "enabled".to_owned(),
                            body,
                        },
                        2 => StructuredBlock::Repeat {
                            cond: "finished".to_owned(),
                            body,
                        },
                        3 => StructuredBlock::NumericFor {
                            var: "i".to_owned(),
                            init: "1".to_owned(),
                            limit: "1".to_owned(),
                            step: "1".to_owned(),
                            body,
                        },
                        4 => StructuredBlock::GenericFor {
                            vars: vec!["k".to_owned(), "v".to_owned()],
                            iter: "pairs(values)".to_owned(),
                            body,
                        },
                        _ => StructuredBlock::If {
                            cond: "enabled".to_owned(),
                            then_body: Vec::new(),
                            else_body: body,
                        },
                    }];
                }
                drop(body);
            })
            .expect("create the small-stack drop worker");

        worker
            .join()
            .expect("dropping a deeply nested block tree must not recurse");
    }

    #[test]
    fn the_work_budget_accepts_many_shallow_sibling_regions() {
        let count: usize = PREVIOUS_STRUCTURE_DEPTH_LIMIT * 20;
        let stmts: Vec<LiftedStmt> = sibling_conditionals(count);

        let result: StructureResult = structure_blocks(&stmts, count * 2);

        assert_eq!(
            result.refused_regions, 0,
            "{count} sibling regions require linear work, so the node-derived budget must accept \
             all of them"
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
    fn nesting_inside_the_previous_limit_is_recovered_whole() {
        let depth: usize = PREVIOUS_STRUCTURE_DEPTH_LIMIT - 8;
        let stmts: Vec<LiftedStmt> = nested_conditionals(depth);

        let result: StructureResult = structure_blocks(&stmts, depth * 2);

        assert_eq!(
            result.refused_regions, 0,
            "a body inside the previous depth limit must not be refused"
        );
        assert_eq!(
            nesting_of(&result.blocks),
            depth,
            "and it must be recovered at its real depth rather than flattened"
        );
    }

    #[test]
    fn nesting_past_the_previous_limit_keeps_the_guarded_body() {
        let depth: usize = PREVIOUS_STRUCTURE_DEPTH_LIMIT + 40;
        let stmts: Vec<LiftedStmt> = nested_conditionals(depth);

        let result: StructureResult = structure_blocks(&stmts, depth * 2);
        assert_eq!(result.refused_regions, 0);
        assert_eq!(result.unresolved_jumps, 0);
        assert_eq!(nesting_of(&result.blocks), depth);
        assert_eq!(leaf_depth(&result.blocks, "r1 = 1"), Some(depth));
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
    fn a_back_edge_jump_that_closes_a_loop_carries_its_edge() {
        let stmts: Vec<LiftedStmt> = vec![
            lifted(0, LStmt::Raw("acc = acc + i".to_owned())),
            lifted(1, LStmt::Raw("i = i + 1".to_owned())),
            lifted(2, LStmt::Jump { target: 0 }),
            lifted(3, LStmt::Raw("print(acc)".to_owned())),
        ];

        let result: StructureResult = structure_blocks(&stmts, 4);

        assert!(
            matches!(result.blocks.first(), Some(StructuredBlock::While { .. })),
            "blocks: {:?}",
            result.blocks
        );
        assert_eq!(
            result.unresolved_jumps, 0,
            "the loop re-enters at the head the jump names, so the edge is carried; blocks: {:?}",
            result.blocks
        );
    }

    #[test]
    fn a_backward_condition_that_closes_no_loop_is_reported_rather_than_discarded() {
        let stmts: Vec<LiftedStmt> = vec![
            lifted(0, LStmt::Raw("i = i + 1".to_owned())),
            lifted(1, LStmt::Raw("s = s + i".to_owned())),
            lifted(
                2,
                LStmt::Cond {
                    cond: "i < 5".to_owned(),
                    target: 0,
                },
            ),
            lifted(3, LStmt::Raw("print(s)".to_owned())),
        ];

        let result: StructureResult = structure_blocks(&stmts, 4);

        assert!(
            result.unresolved_jumps > 0,
            "loop detection here reads jumps only, so a backward condition closes nothing and its \
             edge reaches no structure; dropping it in silence would report a repeat loop that was \
             never recovered; blocks: {:?}",
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

        let result: StructureResult = structure_blocks(&stmts, 4);

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

        let result: StructureResult = structure_blocks(&stmts, 4);

        assert_eq!(result.unresolved_jumps, 0, "blocks: {:?}", result.blocks);
    }

    #[test]
    fn a_loop_exit_test_that_becomes_the_while_condition_carries_its_edge() {
        let stmts: Vec<LiftedStmt> = vec![
            lifted(
                0,
                LStmt::Cond {
                    cond: "i >= 5".to_owned(),
                    target: 4,
                },
            ),
            lifted(1, LStmt::Raw("acc = acc + i".to_owned())),
            lifted(2, LStmt::Raw("i = i + 1".to_owned())),
            lifted(3, LStmt::Jump { target: 0 }),
            lifted(4, LStmt::Raw("print(acc)".to_owned())),
        ];

        let result: StructureResult = structure_blocks(&stmts, 5);

        assert!(
            matches!(result.blocks.first(), Some(StructuredBlock::While { .. })),
            "blocks: {:?}",
            result.blocks
        );
        assert_eq!(result.unresolved_jumps, 0, "blocks: {:?}", result.blocks);
    }

    #[test]
    fn a_test_on_a_numeric_for_exit_carries_its_edge() {
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
                    cond: "i % 2 == 0".to_owned(),
                    target: 5,
                },
            ),
            lifted(2, LStmt::Raw("acc = acc + i".to_owned())),
            lifted(3, LStmt::BlockEnd),
            lifted(5, LStmt::Raw("print(acc)".to_owned())),
        ];

        let result: StructureResult = structure_blocks(&stmts, 6);

        assert_eq!(
            result.unresolved_jumps, 0,
            "a counted loop ends at its own exit, so a test that jumps there reaches the statement \
             after the loop and its edge is carried; blocks: {:?}",
            result.blocks
        );
    }

    #[test]
    fn a_break_to_the_loop_exit_carries_its_edge() {
        let stmts: Vec<LiftedStmt> = vec![
            lifted(0, LStmt::Raw("acc = acc + i".to_owned())),
            lifted(1, LStmt::Jump { target: 4 }),
            lifted(2, LStmt::Raw("i = i + 1".to_owned())),
            lifted(3, LStmt::Jump { target: 0 }),
            lifted(4, LStmt::Raw("print(acc)".to_owned())),
        ];

        let result: StructureResult = structure_blocks(&stmts, 5);

        assert_eq!(
            result.unresolved_jumps, 0,
            "the jump at pc 1 lands on the loop exit, so break carries it; blocks: {:?}",
            result.blocks
        );
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

        let result: StructureResult = structure_blocks(&stmts, 3);

        assert!(
            matches!(
                result.blocks.as_slice(),
                [StructuredBlock::If { then_body, else_body, .. }]
                    if else_body.is_empty()
                        && matches!(
                            then_body.as_slice(),
                            [StructuredBlock::Raw(s)] if s == "y = 1"
                        )
            ),
            "the tree never places a goto to the out-of-region target, so nothing in it names \
             pc 100; blocks: {:?}",
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

        let result: StructureResult = structure_blocks(&stmts, 2);

        assert_eq!(
            result.unresolved_jumps, 0,
            "the sentinel target means the jump has no successor, so discarding it is correct \
             and must not read as a lost edge; blocks: {:?}",
            result.blocks
        );
    }

    #[test]
    fn a_plain_jump_past_the_region_is_reported_as_a_lost_edge() {
        let stmts: Vec<LiftedStmt> = vec![
            lifted(0, LStmt::Raw("r0 = 1".to_owned())),
            lifted(1, LStmt::Jump { target: 100 }),
        ];

        let result: StructureResult = structure_blocks(&stmts, 2);

        assert!(
            result.unresolved_jumps > 0,
            "this jump names a real target no structure here carries, and it is not the sentinel, \
             so it must read as a lost edge; blocks: {:?}",
            result.blocks
        );
    }
}
