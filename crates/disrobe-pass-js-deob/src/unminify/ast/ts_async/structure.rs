use std::collections::{BTreeMap, BTreeSet};

use oxc_ast::ast::{Expression, Statement, UnaryOperator};
use oxc_span::{GetSpan, Span};

use super::Refusal;
use super::emit::{CondTransfer, Finalizer, Handler, LabelKind, Labels, LoopHead, Out, Transfer};
use super::machine::{Block, Machine, NestedKind, Part, PartKind, Terminator, terminator_targets};
use super::order::FoldPlan;
use super::raw_statement;
use super::render::{Code, LabelId, Renderer, Replacement};

const MAX_TREE_DEPTH: usize = 128;

#[derive(Debug, Clone, Copy)]
struct Scope {
    part: Option<Part>,
    entry: u32,
    reentry: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Unit {
    Block(u32),
    Region(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Internal(usize),
    Exit(u32),
}

#[derive(Debug, Clone, Copy)]
struct Edge {
    label: u32,
    target: Target,
    nested: bool,
}

#[derive(Debug)]
struct Graph {
    units: Vec<Unit>,
    edges: Vec<Vec<Edge>>,
    children: Vec<Vec<usize>>,
    loop_header: Vec<bool>,
    merge: Vec<bool>,
    loop_body: BTreeMap<usize, BTreeSet<usize>>,
}

#[derive(Debug, Clone, Copy)]
enum Frame {
    Loop { key: u32, label: LabelId },
    Follow { key: u32, label: LabelId },
    TryExit { end: u32, label: LabelId },
    Finally { label: LabelId },
}

pub(super) fn emit(
    machine: &Machine<'_>,
    plan: &FoldPlan,
    renderer: &mut Renderer<'_>,
    labels: &mut Labels,
) -> Result<Vec<Out>, Refusal> {
    let mut emitter: Emitter<'_, '_, '_, '_> = Emitter {
        machine,
        plan,
        renderer,
        labels,
        frames: Vec::new(),
        depth: 0,
    };
    emitter.scope(Scope {
        part: None,
        entry: 0,
        reentry: None,
    })
}

struct Emitter<'m, 'a, 'r, 's> {
    machine: &'m Machine<'a>,
    plan: &'m FoldPlan,
    renderer: &'r mut Renderer<'s>,
    labels: &'m mut Labels,
    frames: Vec<Frame>,
    depth: usize,
}

impl<'a> Emitter<'_, 'a, '_, '_> {
    fn scope(&mut self, scope: Scope) -> Result<Vec<Out>, Refusal> {
        self.depth += 1;
        if self.depth > MAX_TREE_DEPTH {
            return Err(Refusal::TooDeep);
        }
        let graph: Graph = self.build_graph(scope)?;
        let result: Result<Vec<Out>, Refusal> = self.do_tree(&graph, 0);
        self.depth -= 1;
        result
    }

    fn unit_of(&self, label: u32, scope: Scope) -> Option<Unit> {
        let mut cursor: Option<Part> = self.machine.block_part.get(label as usize).copied()?;
        if cursor == scope.part {
            return Some(Unit::Block(label));
        }
        while let Some(part) = cursor {
            let parent: Option<Part> = self.machine.region_parent[part.region];
            if parent == scope.part {
                return Some(Unit::Region(part.region));
            }
            cursor = parent;
        }
        None
    }

    fn unit_key(&self, unit: Unit) -> u32 {
        match unit {
            Unit::Block(label) => label,
            Unit::Region(region) => self.machine.regions[region].try_start,
        }
    }

    fn block_edges(block: &Block<'_>) -> Vec<(u32, bool)> {
        let mut edges: Vec<(u32, bool)> = block
            .nested
            .iter()
            .filter_map(|nested| match nested.kind {
                NestedKind::Jump(target) => Some((target, true)),
                NestedKind::Return(_) => None,
            })
            .collect();
        edges.extend(
            terminator_targets(&block.terminator, block.label)
                .into_iter()
                .map(|target: u32| (target, false)),
        );
        edges
    }

    fn raw_edges(&self, unit: Unit) -> Vec<(u32, bool)> {
        match unit {
            Unit::Block(label) => Self::block_edges(&self.machine.blocks[label as usize]),
            Unit::Region(region) => {
                let bounds = self.machine.regions[region];
                let mut edges: Vec<(u32, bool)> = Vec::new();
                for block in &self.machine.blocks[bounds.try_start as usize..bounds.end as usize] {
                    for (target, _) in Self::block_edges(block) {
                        if target == bounds.end {
                            edges.push((target, false));
                        } else if target <= bounds.try_start || target > bounds.end {
                            edges.push((target, true));
                        }
                    }
                }
                edges.sort_unstable();
                edges.dedup();
                edges
            }
        }
    }

    fn check_exit(
        &self,
        scope: Scope,
        source: Unit,
        target: u32,
        nested: bool,
    ) -> Result<(), Refusal> {
        let Some(part) = scope.part else {
            return Err(Refusal::UnresolvedTransfer);
        };
        let region = self.machine.regions[part.region];
        let tail_kind_ok: bool = match source {
            Unit::Block(label) => {
                nested
                    || matches!(
                        self.machine.blocks[label as usize].terminator,
                        Terminator::Jump(_)
                    )
            }
            Unit::Region(_) => true,
        };
        if !tail_kind_ok {
            return Err(Refusal::RegionShape);
        }
        let outside: bool = target <= region.try_start || target >= region.end;
        if outside {
            Ok(())
        } else {
            Err(Refusal::RegionShape)
        }
    }

    fn resolve(&self, scope: Scope, target: u32) -> Result<Option<Unit>, Refusal> {
        if scope.reentry == Some(target) {
            return Ok(None);
        }
        match self.unit_of(target, scope) {
            Some(Unit::Region(region)) if self.machine.regions[region].try_start != target => {
                Err(Refusal::RegionShape)
            }
            Some(unit) => Ok(Some(unit)),
            None => Ok(None),
        }
    }

    fn build_graph(&self, scope: Scope) -> Result<Graph, Refusal> {
        let entry: Unit = self
            .unit_of(scope.entry, scope)
            .ok_or(Refusal::RegionShape)?;
        let mut order: Vec<Unit> = Vec::new();
        let mut visited: BTreeSet<Unit> = BTreeSet::new();
        let mut stack: Vec<(Unit, Vec<Unit>)> = Vec::new();
        visited.insert(entry);
        stack.push((entry, self.successor_units(scope, entry)?));
        while let Some((unit, pending)) = stack.last_mut() {
            if let Some(next) = pending.pop() {
                if visited.insert(next) {
                    let successors: Vec<Unit> = self.successor_units(scope, next)?;
                    stack.push((next, successors));
                }
            } else {
                order.push(*unit);
                stack.pop();
            }
        }
        order.reverse();
        let index: BTreeMap<Unit, usize> = order
            .iter()
            .enumerate()
            .map(|(position, unit): (usize, &Unit)| (*unit, position))
            .collect();
        let mut edges: Vec<Vec<Edge>> = Vec::with_capacity(order.len());
        for unit in &order {
            let mut unit_edges: Vec<Edge> = Vec::new();
            for (label, nested) in self.raw_edges(*unit) {
                let target: Target = if let Some(target_unit) = self.resolve(scope, label)? {
                    Target::Internal(*index.get(&target_unit).ok_or(Refusal::UnresolvedTransfer)?)
                } else {
                    self.check_exit(scope, *unit, label, nested)?;
                    Target::Exit(label)
                };
                unit_edges.push(Edge {
                    label,
                    target,
                    nested,
                });
            }
            edges.push(unit_edges);
        }
        for (position, unit) in order.iter().enumerate() {
            let entry_like: bool = match (scope.part, unit) {
                (Some(part), Unit::Block(label)) => {
                    part.kind != PartKind::Try && *label == scope.entry
                }
                _ => false,
            };
            if entry_like
                && edges
                    .iter()
                    .flatten()
                    .any(|edge: &Edge| edge.target == Target::Internal(position))
            {
                return Err(Refusal::RegionShape);
            }
        }
        let idom: Vec<usize> = dominators(&edges);
        let count: usize = order.len();
        let mut loop_header: Vec<bool> = vec![false; count];
        let mut forward: Vec<usize> = vec![0; count];
        let mut merge: Vec<bool> = vec![false; count];
        let mut back_sources: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for (source, unit_edges) in edges.iter().enumerate() {
            for edge in unit_edges {
                let Target::Internal(target) = edge.target else {
                    continue;
                };
                if target <= source {
                    if !dominates(&idom, target, source) {
                        return Err(Refusal::IrreducibleFlow);
                    }
                    loop_header[target] = true;
                    back_sources.entry(target).or_default().push(source);
                } else {
                    forward[target] += 1;
                    if edge.nested {
                        merge[target] = true;
                    }
                }
            }
        }
        for (target, count_in) in forward.iter().enumerate() {
            if *count_in >= 2 {
                merge[target] = true;
            }
        }
        let mut children: Vec<Vec<usize>> = vec![Vec::new(); count];
        for (node, parent) in idom.iter().enumerate().skip(1) {
            children[*parent].push(node);
        }
        let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); count];
        for (source, unit_edges) in edges.iter().enumerate() {
            for edge in unit_edges {
                if let Target::Internal(target) = edge.target {
                    predecessors[target].push(source);
                }
            }
        }
        let mut loop_body: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
        for (header, sources) in &back_sources {
            let mut body: BTreeSet<usize> = BTreeSet::new();
            body.insert(*header);
            let mut work: Vec<usize> = sources.clone();
            while let Some(node) = work.pop() {
                if body.insert(node) {
                    work.extend(predecessors[node].iter().copied());
                }
            }
            loop_body.insert(*header, body);
        }
        Ok(Graph {
            units: order,
            edges,
            children,
            loop_header,
            merge,
            loop_body,
        })
    }

    fn successor_units(&self, scope: Scope, unit: Unit) -> Result<Vec<Unit>, Refusal> {
        let mut units: Vec<Unit> = Vec::new();
        for (label, _) in self.raw_edges(unit).into_iter().rev() {
            if let Some(target) = self.resolve(scope, label)? {
                units.push(target);
            }
        }
        units.sort_by_key(|unit: &Unit| std::cmp::Reverse(self.unit_key(*unit)));
        units.dedup();
        units.reverse();
        Ok(units)
    }

    fn do_tree(&mut self, graph: &Graph, node: usize) -> Result<Vec<Out>, Refusal> {
        self.depth += 1;
        if self.depth > MAX_TREE_DEPTH {
            return Err(Refusal::TooDeep);
        }
        let mut merges: Vec<usize> = graph.children[node]
            .iter()
            .copied()
            .filter(|child: &usize| graph.merge[*child])
            .collect();
        merges.sort_by(|left: &usize, right: &usize| right.cmp(left));
        let result: Result<Vec<Out>, Refusal> = if graph.loop_header[node] {
            let body: BTreeSet<usize> = graph.loop_body.get(&node).cloned().unwrap_or_default();
            let (inside, outside): (Vec<usize>, Vec<usize>) = merges
                .into_iter()
                .partition(|child: &usize| body.contains(child));
            self.within(graph, node, &outside, Some(inside.as_slice()))
        } else {
            self.within(graph, node, &merges, None)
        };
        self.depth -= 1;
        result
    }

    fn within(
        &mut self,
        graph: &Graph,
        node: usize,
        follows: &[usize],
        loop_children: Option<&[usize]>,
    ) -> Result<Vec<Out>, Refusal> {
        if let Some((first, rest)) = follows.split_first() {
            let label: LabelId = self.labels.fresh(LabelKind::Block);
            let key: u32 = self.unit_key(graph.units[*first]);
            self.frames.push(Frame::Follow { key, label });
            let body: Result<Vec<Out>, Refusal> = self.within(graph, node, rest, loop_children);
            self.frames.pop();
            let mut outs: Vec<Out> = vec![Out::Block { label, body: body? }];
            outs.extend(self.do_tree(graph, *first)?);
            return Ok(outs);
        }
        if let Some(inside) = loop_children {
            let label: LabelId = self.labels.fresh(LabelKind::Loop);
            let key: u32 = self.unit_key(graph.units[node]);
            self.frames.push(Frame::Loop { key, label });
            let body: Result<Vec<Out>, Refusal> = self.within(graph, node, inside, None);
            self.frames.pop();
            return Ok(vec![Out::Loop {
                label,
                head: LoopHead::Infinite,
                body: body?,
            }]);
        }
        self.code_for(graph, node)
    }

    fn code_for(&mut self, graph: &Graph, node: usize) -> Result<Vec<Out>, Refusal> {
        let mut outs: Vec<Out> = Vec::new();
        let mut current: usize = node;
        loop {
            let (mut code, next): (Vec<Out>, Option<usize>) = self.node_code(graph, current)?;
            outs.append(&mut code);
            let Some(next) = next else {
                break;
            };
            let plain: bool = !graph.loop_header[next]
                && graph.children[next]
                    .iter()
                    .all(|child: &usize| !graph.merge[*child]);
            if plain {
                current = next;
            } else {
                outs.extend(self.do_tree(graph, next)?);
                break;
            }
        }
        Ok(outs)
    }

    fn node_code(
        &mut self,
        graph: &Graph,
        node: usize,
    ) -> Result<(Vec<Out>, Option<usize>), Refusal> {
        match graph.units[node] {
            Unit::Block(label) => self.block_code(graph, node, label),
            Unit::Region(region) => self.region_code(graph, node, region),
        }
    }

    fn tail(&self, graph: &Graph, node: usize, label: u32) -> Result<Tail, Refusal> {
        let edge: Edge = graph.edges[node]
            .iter()
            .copied()
            .find(|edge: &Edge| edge.label == label && !edge.nested)
            .ok_or(Refusal::UnresolvedTransfer)?;
        match edge.target {
            Target::Internal(target) if target <= node => Ok(Tail::Transfer(
                self.frame_transfer(self.unit_key(graph.units[target]))?,
            )),
            Target::Internal(target) if graph.merge[target] => Ok(Tail::Transfer(
                self.frame_transfer(self.unit_key(graph.units[target]))?,
            )),
            Target::Internal(target) => Ok(Tail::Inline(target)),
            Target::Exit(exit) => Ok(Tail::Transfer(self.frame_transfer(exit)?)),
        }
    }

    fn nested_transfer(&self, graph: &Graph, node: usize, label: u32) -> Result<Transfer, Refusal> {
        let edge: Edge = graph.edges[node]
            .iter()
            .copied()
            .find(|edge: &Edge| edge.label == label && edge.nested)
            .ok_or(Refusal::UnresolvedTransfer)?;
        let key: u32 = match edge.target {
            Target::Internal(target) => self.unit_key(graph.units[target]),
            Target::Exit(exit) => exit,
        };
        self.frame_transfer(key)
    }

    fn frame_transfer(&self, key: u32) -> Result<Transfer, Refusal> {
        for frame in self.frames.iter().rev() {
            match *frame {
                Frame::Loop {
                    key: loop_key,
                    label,
                } if loop_key == key => {
                    return Ok(Transfer::Continue(label));
                }
                Frame::Follow {
                    key: follow_key,
                    label,
                } if follow_key == key => return Ok(Transfer::Break(label)),
                Frame::TryExit { end, label } if end == key => return Ok(Transfer::Break(label)),
                _ => {}
            }
        }
        Err(Refusal::UnresolvedTransfer)
    }

    fn block_code(
        &mut self,
        graph: &Graph,
        node: usize,
        label: u32,
    ) -> Result<(Vec<Out>, Option<usize>), Refusal> {
        let machine: &Machine<'a> = self.machine;
        let block: &Block<'a> = &machine.blocks[label as usize];
        let mut transfers: BTreeMap<(u32, u32), Transfer> = BTreeMap::new();
        for nested in &block.nested {
            let transfer: Transfer = match nested.kind {
                NestedKind::Jump(target) => self.nested_transfer(graph, node, target)?,
                NestedKind::Return(argument) => Transfer::Return(
                    argument
                        .map(|span: Span| self.renderer.render(span))
                        .transpose()?,
                ),
            };
            transfers.insert((nested.statement.start, nested.statement.end), transfer);
        }
        let mut outs: Vec<Out> = Vec::with_capacity(block.statements.len() + 1);
        for statement in &block.statements {
            let span: Span = statement.span();
            if self.plan.deleted.contains(&(span.start, span.end)) {
                continue;
            }
            if let Some((test, jump)) = conditional_jump(statement)
                && let Some(transfer) = transfers.get(&(jump.start, jump.end))
            {
                outs.push(Out::CondTransfer(CondTransfer {
                    test: self.renderer.render(test.span())?,
                    negated: negated(test, self.renderer)?,
                    transfer: transfer.clone(),
                }));
                continue;
            }
            for nested in &block.nested {
                if !contains_span(span, nested.statement) {
                    continue;
                }
                let key: (u32, u32) = (nested.statement.start, nested.statement.end);
                let replacement: Replacement = match (&nested.kind, transfers.get(&key)) {
                    (NestedKind::Return(argument), _) => Replacement::Return {
                        argument: *argument,
                    },
                    (NestedKind::Jump(_), Some(transfer)) => {
                        Replacement::Code(transfer_code(transfer))
                    }
                    (NestedKind::Jump(_), None) => return Err(Refusal::UnresolvedTransfer),
                };
                self.renderer.insert(nested.statement, replacement)?;
            }
            outs.push(raw_statement(statement, self.renderer)?);
        }
        let next: Option<usize> = match block.terminator {
            Terminator::Return(value) => {
                outs.push(Out::Transfer(Transfer::Return(
                    value
                        .map(|expression: &Expression<'_>| self.renderer.render(expression.span()))
                        .transpose()?,
                )));
                None
            }
            Terminator::Stop => None,
            Terminator::EndFinally => {
                let innermost: Option<Part> = machine.block_part[label as usize];
                if innermost.map(|part: Part| part.kind) != Some(PartKind::Finally) {
                    return Err(Refusal::MisplacedInstruction);
                }
                let finally_label: LabelId = self
                    .frames
                    .iter()
                    .rev()
                    .find_map(|frame: &Frame| match frame {
                        Frame::Finally { label } => Some(*label),
                        _ => None,
                    })
                    .ok_or(Refusal::MisplacedInstruction)?;
                outs.push(Out::Transfer(Transfer::Break(finally_label)));
                None
            }
            Terminator::Jump(target) | Terminator::FallThrough(target) => {
                self.apply_tail(graph, node, target, &mut outs)?
            }
            Terminator::Await(_) => self.apply_tail(graph, node, label + 1, &mut outs)?,
        };
        Ok((outs, next))
    }

    fn apply_tail(
        &self,
        graph: &Graph,
        node: usize,
        label: u32,
        outs: &mut Vec<Out>,
    ) -> Result<Option<usize>, Refusal> {
        match self.tail(graph, node, label)? {
            Tail::Inline(target) => Ok(Some(target)),
            Tail::Transfer(transfer) => {
                outs.push(Out::Transfer(transfer));
                Ok(None)
            }
        }
    }

    fn region_code(
        &mut self,
        graph: &Graph,
        node: usize,
        region: usize,
    ) -> Result<(Vec<Out>, Option<usize>), Refusal> {
        let bounds = self.machine.regions[region];
        let try_label: LabelId = self.labels.fresh(LabelKind::Try);
        self.frames.push(Frame::TryExit {
            end: bounds.end,
            label: try_label,
        });
        let result: Result<Out, Refusal> = self.region_parts(region, try_label);
        self.frames.pop();
        let statement: Out = result?;
        let mut outs: Vec<Out> = vec![statement];
        let completes: bool = graph.edges[node]
            .iter()
            .any(|edge: &Edge| edge.label == bounds.end && !edge.nested);
        let next: Option<usize> = if completes {
            self.apply_tail(graph, node, bounds.end, &mut outs)?
        } else {
            None
        };
        Ok((outs, next))
    }

    fn region_parts(&mut self, region: usize, try_label: LabelId) -> Result<Out, Refusal> {
        let bounds = self.machine.regions[region];
        let block: Vec<Out> = self.scope(Scope {
            part: Some(Part {
                region,
                kind: PartKind::Try,
            }),
            entry: bounds.try_start,
            reentry: Some(bounds.try_start),
        })?;
        let handler: Option<Handler> = match bounds.catch_start {
            Some(start) => {
                let entry = self.machine.blocks[start as usize]
                    .catch_entry
                    .ok_or(Refusal::CatchBinding)?;
                let param: Option<Code> = entry
                    .name
                    .map(|span: Span| self.renderer.render(span))
                    .transpose()?;
                let body: Vec<Out> = self.scope(Scope {
                    part: Some(Part {
                        region,
                        kind: PartKind::Catch,
                    }),
                    entry: start,
                    reentry: Some(bounds.try_start),
                })?;
                Some(Handler { param, body })
            }
            None => None,
        };
        let finalizer: Option<Finalizer> = match bounds.finally_start {
            Some(start) => {
                let label: LabelId = self.labels.fresh(LabelKind::Finally);
                self.frames.push(Frame::Finally { label });
                let body: Result<Vec<Out>, Refusal> = self.scope(Scope {
                    part: Some(Part {
                        region,
                        kind: PartKind::Finally,
                    }),
                    entry: start,
                    reentry: Some(bounds.try_start),
                });
                self.frames.pop();
                Some(Finalizer { label, body: body? })
            }
            None => None,
        };
        Ok(Out::Try {
            label: try_label,
            block,
            handler,
            finalizer,
        })
    }
}

enum Tail {
    Inline(usize),
    Transfer(Transfer),
}

fn dominators(edges: &[Vec<Edge>]) -> Vec<usize> {
    let count: usize = edges.len();
    let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); count];
    for (source, unit_edges) in edges.iter().enumerate() {
        for edge in unit_edges {
            if let Target::Internal(target) = edge.target {
                predecessors[target].push(source);
            }
        }
    }
    let mut idom: Vec<Option<usize>> = vec![None; count];
    if count == 0 {
        return Vec::new();
    }
    idom[0] = Some(0);
    let mut changed: bool = true;
    while changed {
        changed = false;
        for node in 1..count {
            let mut candidate: Option<usize> = None;
            for predecessor in &predecessors[node] {
                if idom[*predecessor].is_none() {
                    continue;
                }
                candidate = Some(candidate.map_or(*predecessor, |current: usize| {
                    intersect(&idom, current, *predecessor)
                }));
            }
            if candidate.is_some() && idom[node] != candidate {
                idom[node] = candidate;
                changed = true;
            }
        }
    }
    idom.into_iter()
        .map(|dominator: Option<usize>| dominator.unwrap_or(0))
        .collect()
}

fn intersect(idom: &[Option<usize>], left: usize, right: usize) -> usize {
    let mut first: usize = left;
    let mut second: usize = right;
    while first != second {
        while first > second {
            first = idom[first].unwrap_or(0);
        }
        while second > first {
            second = idom[second].unwrap_or(0);
        }
    }
    first
}

fn dominates(idom: &[usize], dominator: usize, node: usize) -> bool {
    let mut cursor: usize = node;
    loop {
        if cursor == dominator {
            return true;
        }
        if cursor == 0 {
            return false;
        }
        cursor = idom[cursor];
    }
}

const fn contains_span(outer: Span, inner: Span) -> bool {
    outer.start <= inner.start && inner.end <= outer.end
}

fn conditional_jump<'b, 'a>(statement: &'b Statement<'a>) -> Option<(&'b Expression<'a>, Span)> {
    let Statement::IfStatement(branch) = statement else {
        return None;
    };
    if branch.alternate.is_some() {
        return None;
    }
    let jump: &Statement<'a> = match &branch.consequent {
        Statement::BlockStatement(block) => match block.body.as_slice() {
            [single] => single,
            _ => return None,
        },
        other => other,
    };
    let Statement::ReturnStatement(ret) = jump else {
        return None;
    };
    Some((&branch.test, ret.span))
}

fn negated(test: &Expression<'_>, renderer: &Renderer<'_>) -> Result<Code, Refusal> {
    if let Expression::UnaryExpression(unary) = test
        && unary.operator == UnaryOperator::LogicalNot
    {
        let operand: &Expression<'_> = match &unary.argument {
            Expression::ParenthesizedExpression(inner) => &inner.expression,
            other => other,
        };
        return renderer.render(operand.span());
    }
    Ok(Code::wrapped(renderer.render(test.span())?, "!(", ")"))
}

fn transfer_code(transfer: &Transfer) -> Code {
    let mut code: Code = Code::default();
    match transfer {
        Transfer::Break(label) => {
            code.push_str("break ");
            code.push_label(*label);
            code.push_str(";");
        }
        Transfer::Continue(label) => {
            code.push_str("continue ");
            code.push_label(*label);
            code.push_str(";");
        }
        Transfer::Return(None) => code.push_str("return;"),
        Transfer::Return(Some(value)) => {
            code.push_str("return ");
            code.append(value.clone());
            code.push_str(";");
        }
    }
    code
}
