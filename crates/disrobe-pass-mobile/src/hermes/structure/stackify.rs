use std::collections::{BTreeMap, BTreeSet};

use super::{
    JsStmt, Labels, SBlock, Sink, StructureDecline, SwitchArm, Term, references_label,
    successors_of,
};
use crate::hermes::decompile::negate_cond;

const MAX_STACKIFY_DEPTH: usize = 256;
const CAUGHT_BINDING: &str = "$caught";
pub(super) const HANDLER_TEST: &str = "$test";

pub(super) fn stackify(
    blocks: &[SBlock],
    sinks: &BTreeMap<usize, Sink>,
    labels: &mut Labels,
) -> Result<Vec<JsStmt>, StructureDecline> {
    lay_out(blocks, sinks, &[], labels).map(|(body, _): (Vec<JsStmt>, bool)| body)
}

pub(super) fn stackify_with_handlers(
    blocks: &[SBlock],
    handlers: &[Option<usize>],
    labels: &mut Labels,
) -> Result<(Vec<JsStmt>, bool), StructureDecline> {
    lay_out(blocks, &BTreeMap::new(), handlers, labels)
}

fn lay_out(
    blocks: &[SBlock],
    sinks: &BTreeMap<usize, Sink>,
    handlers: &[Option<usize>],
    labels: &mut Labels,
) -> Result<(Vec<JsStmt>, bool), StructureDecline> {
    if blocks.is_empty() {
        return Ok((Vec::new(), false));
    }
    let graph: Graph = Graph::new(blocks, sinks, handlers)?;
    let exit_label: usize = labels.fresh()?;
    let mut emitter: Emitter<'_> = Emitter {
        blocks,
        sinks,
        handlers,
        graph: &graph,
        labels,
        exit_label,
        emitted: BTreeSet::new(),
        follow_label: BTreeMap::new(),
        loop_label: BTreeMap::new(),
        depth: 0,
        uses_test: false,
    };
    let mut body: Vec<JsStmt> = Vec::new();
    emitter.tree(0, &mut body)?;
    if emitter.emitted != graph.reachable {
        return Err(StructureDecline::IncompleteCover);
    }
    let uses_test: bool = emitter.uses_test;
    Ok((finish_exit(simplify(body), exit_label), uses_test))
}

fn handler_of(handlers: &[Option<usize>], node: usize) -> Option<usize> {
    handlers.get(node).copied().flatten()
}

fn can_throw(block: &SBlock) -> bool {
    !block.prelude.is_empty()
        || !block.body.is_empty()
        || matches!(
            block.term,
            Term::Return(_) | Term::Throw(_) | Term::Branch { .. } | Term::Switch { .. }
        )
}

fn exception_edge(blocks: &[SBlock], handlers: &[Option<usize>], node: usize) -> Option<usize> {
    handler_of(handlers, node).filter(|_| blocks.get(node).is_some_and(can_throw))
}

pub(super) fn finish_exit(mut body: Vec<JsStmt>, label: usize) -> Vec<JsStmt> {
    drop_tail_break(&mut body, label);
    if references_label(&body, label) {
        vec![labeled_block(label, body)]
    } else {
        body
    }
}

fn labeled_block(label: usize, body: Vec<JsStmt>) -> JsStmt {
    JsStmt::Labeled {
        label,
        body: Box::new(JsStmt::Block(body)),
    }
}

fn switch_targets(cases: &[(i64, usize)], default: usize) -> Vec<usize> {
    let mut targets: Vec<usize> = Vec::with_capacity(cases.len() + 1);
    for (_, target) in cases {
        if !targets.contains(target) {
            targets.push(*target);
        }
    }
    if !targets.contains(&default) {
        targets.push(default);
    }
    targets
}

fn arm_targets(term: &Term) -> Vec<usize> {
    match term {
        Term::Exit | Term::Return(_) | Term::Throw(_) => Vec::new(),
        Term::Goto(target) => vec![*target],
        Term::Branch {
            taken, not_taken, ..
        } => vec![*taken, *not_taken],
        Term::Switch { cases, default, .. } => switch_targets(cases, *default),
    }
}

fn sink_jump(blocks: &[SBlock], sinks: &BTreeMap<usize, Sink>, node: usize) -> Option<Sink> {
    let block: &SBlock = blocks.get(node)?;
    if !block.prelude.is_empty() || !block.body.is_empty() || !matches!(block.term, Term::Exit) {
        return None;
    }
    Some(sinks.get(&node).copied().unwrap_or(Sink::Exit))
}

struct Graph {
    reachable: BTreeSet<usize>,
    rpo: Vec<usize>,
    idom: Vec<usize>,
    loop_header: Vec<bool>,
    loop_body: BTreeMap<usize, BTreeSet<usize>>,
    merge: Vec<bool>,
    merge_children: Vec<Vec<usize>>,
}

impl Graph {
    fn new(
        blocks: &[SBlock],
        sinks: &BTreeMap<usize, Sink>,
        handlers: &[Option<usize>],
    ) -> Result<Self, StructureDecline> {
        let count: usize = blocks.len();
        let successors: Vec<Vec<usize>> = blocks
            .iter()
            .enumerate()
            .map(|(node, block): (usize, &SBlock)| {
                let mut targets: Vec<usize> = successors_of(block);
                if let Some(handler) = exception_edge(blocks, handlers, node)
                    && !targets.contains(&handler)
                {
                    targets.push(handler);
                }
                targets
            })
            .collect();
        if successors
            .iter()
            .flatten()
            .any(|target: &usize| *target >= count)
        {
            return Err(StructureDecline::UnresolvedEdge);
        }
        let mut postorder: Vec<usize> = Vec::with_capacity(count);
        let mut seen: Vec<bool> = vec![false; count];
        let mut stack: Vec<(usize, usize)> = vec![(0, 0)];
        seen[0] = true;
        while let Some((node, next)) = stack.last().copied() {
            if let Some(successor) = successors[node].get(next).copied() {
                if let Some(top) = stack.last_mut() {
                    top.1 += 1;
                }
                if !seen[successor] {
                    seen[successor] = true;
                    stack.push((successor, 0));
                }
            } else {
                postorder.push(node);
                stack.pop();
            }
        }
        let order: Vec<usize> = postorder.iter().rev().copied().collect();
        let mut rpo: Vec<usize> = vec![usize::MAX; count];
        for (position, node) in order.iter().enumerate() {
            rpo[*node] = position;
        }
        let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); count];
        for node in &order {
            for successor in &successors[*node] {
                if !predecessors[*successor].contains(node) {
                    predecessors[*successor].push(*node);
                }
            }
        }
        let idom: Vec<usize> = dominators(&order, &rpo, &predecessors);
        let mut loop_header: Vec<bool> = vec![false; count];
        let mut loop_body: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
        let mut references: Vec<usize> = vec![0; count];
        for node in &order {
            let mut targets: Vec<usize> = arm_targets(&blocks[*node].term);
            targets.extend(exception_edge(blocks, handlers, *node));
            for target in targets {
                if rpo[target] <= rpo[*node] {
                    if !dominates(&idom, &rpo, target, *node) {
                        return Err(StructureDecline::Irreducible);
                    }
                    loop_header[target] = true;
                    let body: &mut BTreeSet<usize> = loop_body.entry(target).or_default();
                    body.insert(target);
                    let mut pending: Vec<usize> = vec![*node];
                    while let Some(member) = pending.pop() {
                        if body.insert(member) {
                            pending.extend(predecessors[member].iter().copied());
                        }
                    }
                } else {
                    references[target] += 1;
                }
            }
        }
        let merge: Vec<bool> = (0..count)
            .map(|node: usize| references[node] >= 2 && sink_jump(blocks, sinks, node).is_none())
            .collect();
        let mut merge_children: Vec<Vec<usize>> = vec![Vec::new(); count];
        for node in order.iter().skip(1) {
            if merge[*node] {
                merge_children[idom[*node]].push(*node);
            }
        }
        for children in &mut merge_children {
            children.sort_by_key(|child: &usize| rpo[*child]);
        }
        Ok(Self {
            reachable: order.iter().copied().collect(),
            rpo,
            idom,
            loop_header,
            loop_body,
            merge,
            merge_children,
        })
    }
}

fn dominators(order: &[usize], rpo: &[usize], predecessors: &[Vec<usize>]) -> Vec<usize> {
    let mut idom: Vec<usize> = vec![usize::MAX; rpo.len()];
    let Some(entry): Option<usize> = order.first().copied() else {
        return idom;
    };
    idom[entry] = entry;
    let mut changed: bool = true;
    while changed {
        changed = false;
        for node in order.iter().skip(1) {
            let mut candidate: Option<usize> = None;
            for predecessor in &predecessors[*node] {
                if idom[*predecessor] == usize::MAX {
                    continue;
                }
                candidate = Some(match candidate {
                    None => *predecessor,
                    Some(current) => intersect(&idom, rpo, current, *predecessor),
                });
            }
            if let Some(candidate) = candidate
                && idom[*node] != candidate
            {
                idom[*node] = candidate;
                changed = true;
            }
        }
    }
    idom
}

fn intersect(idom: &[usize], rpo: &[usize], mut left: usize, mut right: usize) -> usize {
    while left != right {
        while rpo[left] > rpo[right] {
            left = idom[left];
        }
        while rpo[right] > rpo[left] {
            right = idom[right];
        }
    }
    left
}

fn dominates(idom: &[usize], rpo: &[usize], dominator: usize, mut node: usize) -> bool {
    loop {
        if node == dominator {
            return true;
        }
        let parent: usize = idom[node];
        if parent == node || parent == usize::MAX || rpo[parent] >= rpo[node] {
            return false;
        }
        node = parent;
    }
}

struct Emitter<'a> {
    blocks: &'a [SBlock],
    sinks: &'a BTreeMap<usize, Sink>,
    handlers: &'a [Option<usize>],
    graph: &'a Graph,
    labels: &'a mut Labels,
    exit_label: usize,
    emitted: BTreeSet<usize>,
    follow_label: BTreeMap<usize, usize>,
    loop_label: BTreeMap<usize, usize>,
    depth: usize,
    uses_test: bool,
}

impl Emitter<'_> {
    fn descend(&mut self, levels: usize) -> Result<(), StructureDecline> {
        self.depth += levels;
        if self.depth > MAX_STACKIFY_DEPTH {
            return Err(StructureDecline::DepthExceeded);
        }
        Ok(())
    }

    fn tree(&mut self, node: usize, out: &mut Vec<JsStmt>) -> Result<(), StructureDecline> {
        self.descend(1)?;
        let merges: Vec<usize> = self.graph.merge_children[node].clone();
        if let Some(body) = self.graph.loop_body.get(&node) {
            let (inside, outside): (Vec<usize>, Vec<usize>) = merges
                .iter()
                .partition(|merge: &&usize| body.contains(*merge));
            let after: Vec<(usize, usize)> = self.open_blocks(&outside)?;
            let label: usize = self.labels.fresh()?;
            self.loop_label.insert(node, label);
            let mut looped: Vec<JsStmt> = Vec::new();
            self.within(node, &inside, &mut looped)?;
            let lowered: Vec<JsStmt> = vec![JsStmt::Labeled {
                label,
                body: Box::new(JsStmt::Forever(looped)),
            }];
            out.extend(self.close_blocks(lowered, after)?);
        } else {
            self.within(node, &merges, out)?;
        }
        self.depth -= 1;
        Ok(())
    }

    fn within(
        &mut self,
        node: usize,
        merges: &[usize],
        out: &mut Vec<JsStmt>,
    ) -> Result<(), StructureDecline> {
        let opened: Vec<(usize, usize)> = self.open_blocks(merges)?;
        let mut inner: Vec<JsStmt> = Vec::new();
        self.code(node, &mut inner)?;
        out.extend(self.close_blocks(inner, opened)?);
        Ok(())
    }

    fn open_blocks(&mut self, merges: &[usize]) -> Result<Vec<(usize, usize)>, StructureDecline> {
        self.descend(merges.len())?;
        let mut opened: Vec<(usize, usize)> = Vec::with_capacity(merges.len());
        for merge in merges {
            let label: usize = self.labels.fresh()?;
            self.follow_label.insert(*merge, label);
            opened.push((*merge, label));
        }
        Ok(opened)
    }

    fn close_blocks(
        &mut self,
        mut inner: Vec<JsStmt>,
        opened: Vec<(usize, usize)>,
    ) -> Result<Vec<JsStmt>, StructureDecline> {
        let levels: usize = opened.len();
        for (merge, label) in opened {
            let mut outer: Vec<JsStmt> = vec![labeled_block(label, inner)];
            self.tree(merge, &mut outer)?;
            inner = outer;
        }
        self.depth -= levels;
        Ok(inner)
    }

    fn jump(&self, sink: Sink) -> JsStmt {
        match sink {
            Sink::Break(label) => JsStmt::Break(Some(label)),
            Sink::Continue(label) => JsStmt::Continue(Some(label)),
            Sink::Exit => JsStmt::Break(Some(self.exit_label)),
        }
    }

    fn code(&mut self, start: usize, out: &mut Vec<JsStmt>) -> Result<(), StructureDecline> {
        let mut node: usize = start;
        loop {
            if !self.emitted.insert(node) {
                return Err(StructureDecline::IncompleteCover);
            }
            let block: &SBlock = &self.blocks[node];
            if let Some(handler) = exception_edge(self.blocks, self.handlers, node) {
                self.protected(node, handler, out)?;
                return Ok(());
            }
            out.extend(block.prelude.iter().cloned());
            out.extend(block.body.iter().cloned().map(JsStmt::Raw));
            match &block.term {
                Term::Return(value) => out.push(JsStmt::Return(value.clone())),
                Term::Throw(value) => out.push(JsStmt::Throw(value.clone())),
                Term::Exit => {
                    let sink: Sink = self.sinks.get(&node).copied().unwrap_or(Sink::Exit);
                    out.push(self.jump(sink));
                }
                Term::Goto(target) => {
                    let target: usize = *target;
                    if self.inlines_plainly(node, target) {
                        node = target;
                        continue;
                    }
                    self.branch(node, target, out)?;
                }
                Term::Branch {
                    cond,
                    taken,
                    not_taken,
                } => {
                    let (cond, taken, not_taken): (String, usize, usize) =
                        (cond.clone(), *taken, *not_taken);
                    let mut then: Vec<JsStmt> = Vec::new();
                    self.branch(node, taken, &mut then)?;
                    let mut els: Vec<JsStmt> = Vec::new();
                    self.branch(node, not_taken, &mut els)?;
                    out.push(JsStmt::If { cond, then, els });
                }
                Term::Switch {
                    scrutinee,
                    cases,
                    default,
                } => {
                    let (scrutinee, cases, default): (String, Vec<(i64, usize)>, usize) =
                        (scrutinee.clone(), cases.clone(), *default);
                    let mut arms: Vec<SwitchArm> = Vec::new();
                    for target in switch_targets(&cases, default) {
                        let mut body: Vec<JsStmt> = Vec::new();
                        self.branch(node, target, &mut body)?;
                        arms.push(SwitchArm {
                            labels: cases
                                .iter()
                                .filter(|(_, to): &&(i64, usize)| *to == target)
                                .map(|(value, _): &(i64, usize)| *value)
                                .collect(),
                            is_default: target == default,
                            body,
                        });
                    }
                    out.push(JsStmt::Switch { scrutinee, arms });
                }
            }
            return Ok(());
        }
    }

    fn protected(
        &mut self,
        node: usize,
        handler: usize,
        out: &mut Vec<JsStmt>,
    ) -> Result<(), StructureDecline> {
        let block: &SBlock = &self.blocks[node];
        let mut body: Vec<JsStmt> = block.prelude.clone();
        body.extend(block.body.iter().cloned().map(JsStmt::Raw));
        let term: Term = match &block.term {
            Term::Return(value) => {
                body.push(JsStmt::Return(value.clone()));
                Term::Exit
            }
            Term::Throw(value) => {
                body.push(JsStmt::Throw(value.clone()));
                Term::Exit
            }
            Term::Branch {
                cond,
                taken,
                not_taken,
            } => {
                self.uses_test = true;
                body.push(JsStmt::Raw(format!("{HANDLER_TEST} = {cond};")));
                Term::Branch {
                    cond: HANDLER_TEST.to_owned(),
                    taken: *taken,
                    not_taken: *not_taken,
                }
            }
            Term::Switch {
                scrutinee,
                cases,
                default,
            } => {
                self.uses_test = true;
                body.push(JsStmt::Raw(format!("{HANDLER_TEST} = {scrutinee};")));
                Term::Switch {
                    scrutinee: HANDLER_TEST.to_owned(),
                    cases: cases.clone(),
                    default: *default,
                }
            }
            other => other.clone(),
        };
        let ends_inside: bool = matches!(block.term, Term::Return(_) | Term::Throw(_));
        if can_throw(block) {
            let mut catch_body: Vec<JsStmt> = vec![JsStmt::Raw(format!(
                "{} = {CAUGHT_BINDING};",
                super::CAUGHT_EXCEPTION_BINDING
            ))];
            self.branch(node, handler, &mut catch_body)?;
            out.push(JsStmt::Try {
                body,
                catch_var: CAUGHT_BINDING.to_owned(),
                catch_body,
            });
        }
        if ends_inside {
            return Ok(());
        }
        match term {
            Term::Exit => {
                let sink: Sink = self.sinks.get(&node).copied().unwrap_or(Sink::Exit);
                out.push(self.jump(sink));
            }
            Term::Goto(target) => self.branch(node, target, out)?,
            Term::Branch {
                cond,
                taken,
                not_taken,
            } => {
                let mut then: Vec<JsStmt> = Vec::new();
                self.branch(node, taken, &mut then)?;
                let mut els: Vec<JsStmt> = Vec::new();
                self.branch(node, not_taken, &mut els)?;
                out.push(JsStmt::If { cond, then, els });
            }
            Term::Switch {
                scrutinee,
                cases,
                default,
            } => {
                let mut arms: Vec<SwitchArm> = Vec::new();
                for target in switch_targets(&cases, default) {
                    let mut body: Vec<JsStmt> = Vec::new();
                    self.branch(node, target, &mut body)?;
                    arms.push(SwitchArm {
                        labels: cases
                            .iter()
                            .filter(|(_, to): &&(i64, usize)| *to == target)
                            .map(|(value, _): &(i64, usize)| *value)
                            .collect(),
                        is_default: target == default,
                        body,
                    });
                }
                out.push(JsStmt::Switch { scrutinee, arms });
            }
            Term::Return(_) | Term::Throw(_) => {}
        }
        Ok(())
    }

    fn inlines_plainly(&self, source: usize, target: usize) -> bool {
        self.graph.rpo[target] > self.graph.rpo[source]
            && !self.graph.merge[target]
            && !self.graph.loop_header[target]
            && self.graph.merge_children[target].is_empty()
            && sink_jump(self.blocks, self.sinks, target).is_none()
    }

    fn branch(
        &mut self,
        source: usize,
        target: usize,
        out: &mut Vec<JsStmt>,
    ) -> Result<(), StructureDecline> {
        if self.graph.rpo[target] <= self.graph.rpo[source] {
            let label: usize = *self
                .loop_label
                .get(&target)
                .ok_or(StructureDecline::Irreducible)?;
            out.push(JsStmt::Continue(Some(label)));
            return Ok(());
        }
        if let Some(sink) = sink_jump(self.blocks, self.sinks, target) {
            self.emitted.insert(target);
            out.push(self.jump(sink));
            return Ok(());
        }
        if self.graph.merge[target] {
            let label: usize = *self
                .follow_label
                .get(&target)
                .ok_or(StructureDecline::IncompleteCover)?;
            out.push(JsStmt::Break(Some(label)));
            return Ok(());
        }
        if self.graph.idom[target] != source {
            return Err(StructureDecline::IncompleteCover);
        }
        self.tree(target, out)
    }
}

fn simplify(stmts: Vec<JsStmt>) -> Vec<JsStmt> {
    let mut out: Vec<JsStmt> = Vec::with_capacity(stmts.len());
    for stmt in stmts {
        match stmt {
            JsStmt::Labeled { label, body } => match *body {
                JsStmt::Block(inner) => {
                    let mut inner: Vec<JsStmt> = simplify(inner);
                    drop_tail_break(&mut inner, label);
                    if references_label(&inner, label) {
                        out.push(labeled_block(label, inner));
                    } else {
                        out.extend(inner);
                    }
                }
                JsStmt::Forever(inner) => {
                    let mut inner: Vec<JsStmt> = simplify(inner);
                    while matches!(
                        inner.last(),
                        Some(JsStmt::Continue(Some(target))) if *target == label
                    ) {
                        inner.pop();
                    }
                    let lowered: JsStmt = JsStmt::Forever(inner);
                    if references_label(std::slice::from_ref(&lowered), label) {
                        out.push(JsStmt::Labeled {
                            label,
                            body: Box::new(lowered),
                        });
                    } else {
                        out.push(lowered);
                    }
                }
                other => out.push(JsStmt::Labeled {
                    label,
                    body: Box::new(other),
                }),
            },
            JsStmt::If { cond, then, els } => {
                push_if(&mut out, cond, simplify(then), simplify(els));
            }
            JsStmt::Switch { scrutinee, arms } => out.push(JsStmt::Switch {
                scrutinee,
                arms: arms
                    .into_iter()
                    .map(|arm: SwitchArm| SwitchArm {
                        body: simplify(arm.body),
                        ..arm
                    })
                    .collect(),
            }),
            JsStmt::Block(inner) => out.extend(simplify(inner)),
            other => out.push(other),
        }
    }
    out
}

fn push_if(out: &mut Vec<JsStmt>, cond: String, then: Vec<JsStmt>, els: Vec<JsStmt>) {
    match (then.is_empty(), els.is_empty()) {
        (true, true) => out.push(JsStmt::Raw(format!("{cond};"))),
        (true, false) => push_if(out, negate_cond(&cond), els, then),
        (false, false) if jumps_away(&then) => {
            out.push(JsStmt::If {
                cond,
                then,
                els: Vec::new(),
            });
            out.extend(els);
        }
        _ => out.push(JsStmt::If { cond, then, els }),
    }
}

fn jumps_away(stmts: &[JsStmt]) -> bool {
    matches!(
        stmts.last(),
        Some(
            JsStmt::Return(_)
                | JsStmt::Throw(_)
                | JsStmt::Break(Some(_))
                | JsStmt::Continue(Some(_))
        )
    )
}

fn drop_tail_break(stmts: &mut Vec<JsStmt>, label: usize) {
    match stmts.last_mut() {
        Some(JsStmt::Break(Some(target))) if *target == label => {
            stmts.pop();
            drop_tail_break(stmts, label);
        }
        Some(JsStmt::If { then, els, .. }) => {
            let (then_len, els_len): (usize, usize) = (then.len(), els.len());
            drop_tail_break(then, label);
            drop_tail_break(els, label);
            if (then.len() != then_len || els.len() != els_len)
                && let Some(JsStmt::If { cond, then, els }) = stmts.pop()
            {
                match (then.is_empty(), els.is_empty()) {
                    (true, true) => stmts.push(JsStmt::Raw(format!("{cond};"))),
                    (true, false) => stmts.push(JsStmt::If {
                        cond: negate_cond(&cond),
                        then: els,
                        els: Vec::new(),
                    }),
                    _ => stmts.push(JsStmt::If { cond, then, els }),
                }
            }
        }
        Some(JsStmt::Labeled { body, .. }) => {
            if let JsStmt::Block(inner) = body.as_mut() {
                drop_tail_break(inner, label);
            }
        }
        Some(JsStmt::Switch { arms, .. }) => {
            for arm in arms {
                drop_tail_break(&mut arm.body, label);
            }
        }
        Some(JsStmt::Try {
            body, catch_body, ..
        }) => {
            drop_tail_break(body, label);
            drop_tail_break(catch_body, label);
        }
        _ => {}
    }
}
