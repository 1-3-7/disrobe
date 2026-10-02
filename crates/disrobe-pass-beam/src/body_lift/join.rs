use std::collections::{BTreeMap, BTreeSet};

use crate::chunks::Chunks;
use crate::disasm::{Instruction, Operand};

use super::expr::{AfterClause, CaseArm, CatchArm, Expr, IfArm, Stmt};
use super::{Block, Env, Flags, Lifter, Reg, TEST_OPS, as_reg, catch_value, resolve_import};

const MAX_JOIN_INSTRUCTIONS: usize = 200_000;
const MAX_JOIN_PASSES: u32 = 64;
const UNDEFINED: usize = usize::MAX;
const JOIN_TAG: &str = "\u{0}join";
const TRY_END_TAG: &str = "\u{0}try_end";

#[derive(Debug, Default)]
pub(super) struct JoinIndex {
    joins: BTreeMap<usize, u32>,
}

#[derive(Debug)]
pub(super) struct JoinFrame {
    target: Target,
    marks_try: Option<Reg>,
    arrivals: Vec<Arrival>,
    broken: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Label(u32),
    TryEnd(Reg),
}

#[derive(Debug)]
struct Arrival {
    tag: String,
    env: Env,
    at: usize,
}

impl JoinIndex {
    pub(super) fn build(
        instrs: &[Instruction],
        blocks: &BTreeMap<u32, Block>,
        chunks: &Chunks,
    ) -> Self {
        let exit: usize = instrs.len();
        if exit == 0 || exit > MAX_JOIN_INSTRUCTIONS {
            return Self::default();
        }
        let label_at: BTreeMap<u32, usize> = blocks
            .iter()
            .filter_map(|(label, block): (&u32, &Block)| {
                block.start.checked_sub(1).map(|at: usize| (*label, at))
            })
            .collect();
        let successors: Vec<Vec<usize>> = (0..exit)
            .map(|idx: usize| successors(instrs, idx, &label_at, chunks))
            .collect();
        let Some(ipdom): Option<Vec<usize>> = post_dominators(&successors, exit) else {
            return Self::default();
        };
        let mut joins: BTreeMap<usize, u32> = BTreeMap::new();
        for (idx, ins) in instrs.iter().enumerate() {
            if !is_branch_site(ins.name) {
                continue;
            }
            let target: usize = ipdom[idx];
            if target == UNDEFINED || target >= exit || instrs[target].name != "label" {
                continue;
            }
            if let Some(Operand::Literal(value)) = instrs[target].operands.first()
                && let Ok(label) = u32::try_from(*value)
            {
                joins.insert(idx, label);
            }
        }
        Self { joins }
    }

    fn at(&self, idx: usize) -> Option<u32> {
        self.joins.get(&idx).copied()
    }
}

fn is_branch_site(name: &str) -> bool {
    TEST_OPS.contains(&name)
        || matches!(
            name,
            "select_val" | "select_tuple_arity" | "bs_match" | "get_map_elements" | "try"
        )
}

pub(super) fn is_raising_import(module: &str, name: &str, arity: u32) -> bool {
    module == "erlang"
        && matches!(
            (name, arity),
            ("error", 1..=3) | ("exit" | "throw", 1) | ("raise", 2 | 3) | ("nif_error", 1 | 2)
        )
}

fn raises(ins: &Instruction, chunks: &Chunks) -> bool {
    let import: Option<&Operand> = match ins.name {
        "badmatch" | "case_end" | "if_end" | "try_case_end" | "badrecord" | "raise"
        | "raw_raise" | "func_info" | "int_code_end" => return true,
        "call_ext" | "call_ext_only" | "call_ext_last" | "bif1" | "bif2" => ins.operands.get(1),
        _ => None,
    };
    import
        .and_then(|op: &Operand| resolve_import(chunks, op))
        .is_some_and(|(module, name, arity): (String, String, u32)| {
            is_raising_import(&module, &name, arity)
        })
}

fn unconditional(name: &str) -> bool {
    matches!(
        name,
        "jump" | "select_val" | "select_tuple_arity" | "loop_rec_end" | "wait"
    )
}

fn successors(
    instrs: &[Instruction],
    idx: usize,
    label_at: &BTreeMap<u32, usize>,
    chunks: &Chunks,
) -> Vec<usize> {
    let ins: &Instruction = &instrs[idx];
    let exit: usize = instrs.len();
    if raises(ins, chunks) {
        return Vec::new();
    }
    if matches!(
        ins.name,
        "return" | "call_last" | "call_only" | "call_ext_last" | "call_ext_only" | "apply_last"
    ) {
        return vec![exit];
    }
    let mut out: Vec<usize> = Vec::new();
    if ins.name != "call" {
        let mut labels: Vec<u32> = Vec::new();
        collect_labels(&ins.operands, &mut labels);
        out.extend(
            labels
                .into_iter()
                .filter_map(|label: u32| label_at.get(&label).copied()),
        );
    }
    if !unconditional(ins.name) && idx + 1 < exit {
        out.push(idx + 1);
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn collect_labels(operands: &[Operand], out: &mut Vec<u32>) {
    for op in operands {
        match op {
            Operand::Label(label) if *label != 0 => out.push(*label),
            Operand::List(items) | Operand::AllocList(items) => {
                for item in items {
                    if let Operand::Label(label) = item
                        && *label != 0
                    {
                        out.push(*label);
                    }
                }
            }
            _ => {}
        }
    }
}

fn post_dominators(successors: &[Vec<usize>], exit: usize) -> Option<Vec<usize>> {
    let nodes: usize = exit + 1;
    let mut reverse: Vec<Vec<usize>> = vec![Vec::new(); nodes];
    for (node, targets) in successors.iter().enumerate() {
        for &target in targets {
            reverse[target].push(node);
        }
    }
    let mut order_of: Vec<usize> = vec![UNDEFINED; nodes];
    let mut order: Vec<usize> = Vec::with_capacity(nodes);
    let mut visited: Vec<bool> = vec![false; nodes];
    let mut stack: Vec<(usize, usize)> = vec![(exit, 0)];
    visited[exit] = true;
    while let Some(top) = stack.last_mut() {
        let (node, cursor): (usize, usize) = *top;
        if let Some(&pred) = reverse[node].get(cursor) {
            top.1 = cursor + 1;
            if !visited[pred] {
                visited[pred] = true;
                stack.push((pred, 0));
            }
        } else {
            order_of[node] = order.len();
            order.push(node);
            stack.pop();
        }
    }
    let mut ipdom: Vec<usize> = vec![UNDEFINED; nodes];
    ipdom[exit] = exit;
    let step_budget: usize = nodes.saturating_mul(64);
    for _ in 0..MAX_JOIN_PASSES {
        let mut changed: bool = false;
        for &node in order.iter().rev() {
            if node == exit {
                continue;
            }
            let mut candidate: usize = UNDEFINED;
            for &target in &successors[node] {
                if ipdom[target] == UNDEFINED {
                    continue;
                }
                candidate = if candidate == UNDEFINED {
                    target
                } else {
                    intersect(&ipdom, &order_of, target, candidate, step_budget)?
                };
            }
            if candidate != ipdom[node] {
                ipdom[node] = candidate;
                changed = true;
            }
        }
        if !changed {
            return Some(ipdom);
        }
    }
    None
}

fn intersect(
    ipdom: &[usize],
    order_of: &[usize],
    mut a: usize,
    mut b: usize,
    budget: usize,
) -> Option<usize> {
    let mut steps: usize = 0;
    while a != b {
        while order_of[a] < order_of[b] {
            a = ipdom[a];
            steps += 1;
            if a == UNDEFINED || steps > budget {
                return None;
            }
        }
        while order_of[b] < order_of[a] {
            b = ipdom[b];
            steps += 1;
            if b == UNDEFINED || steps > budget {
                return None;
            }
        }
    }
    Some(a)
}

impl Flags {
    pub(super) fn arrival(&mut self, label: u32, env: &Env) -> Option<Vec<Stmt>> {
        let position: usize = self
            .joins
            .iter()
            .rposition(|frame: &JoinFrame| frame.target == Target::Label(label))?;
        Some(self.arrive(position, env, 0))
    }

    pub(super) fn try_end(&mut self, reg: Reg, env: &Env, at: usize) -> TryEnd {
        if let Some(position) = self
            .joins
            .iter()
            .rposition(|frame: &JoinFrame| frame.target == Target::TryEnd(reg))
        {
            return TryEnd::Arrive(self.arrive(position, env, at));
        }
        if self
            .joins
            .iter()
            .any(|frame: &JoinFrame| frame.marks_try == Some(reg))
        {
            return TryEnd::Mark(Stmt::Comment(TRY_END_TAG.to_owned()));
        }
        TryEnd::Pass
    }

    fn arrive(&mut self, position: usize, env: &Env, at: usize) -> Vec<Stmt> {
        let top: usize = self.joins.len() - 1;
        if position != top {
            self.joins[top].broken = true;
        }
        let tag: String = format!("{JOIN_TAG}{}", self.join_serial);
        self.join_serial = self.join_serial.saturating_add(1);
        self.joins[position].arrivals.push(Arrival {
            tag: tag.clone(),
            env: env.clone(),
            at,
        });
        vec![Stmt::Return(Expr::Raw(tag))]
    }

    pub(super) fn is_join_label(&self, label: u32) -> bool {
        self.joins
            .iter()
            .any(|frame: &JoinFrame| frame.target == Target::Label(label))
    }

    fn marks_try(&self, reg: Reg) -> bool {
        self.joins
            .iter()
            .any(|frame: &JoinFrame| frame.marks_try == Some(reg))
    }

    fn fresh_join_var(&mut self) -> String {
        let n: u32 = self.join_vars;
        self.join_vars = self.join_vars.saturating_add(1);
        format!("J{n}")
    }

    fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            degraded: self.degraded,
            arrivals: self
                .joins
                .iter()
                .map(|frame: &JoinFrame| frame.arrivals.len())
                .collect(),
        }
    }

    fn rewind(&mut self, checkpoint: Checkpoint) {
        self.degraded = checkpoint.degraded;
        for (frame, len) in self.joins.iter_mut().zip(checkpoint.arrivals) {
            frame.arrivals.truncate(len);
        }
    }
}

#[derive(Debug)]
struct Checkpoint {
    degraded: bool,
    arrivals: Vec<usize>,
}

#[derive(Debug)]
pub(super) enum TryEnd {
    Arrive(Vec<Stmt>),
    Mark(Stmt),
    Pass,
}

struct Merge {
    env: Env,
    phis: Vec<(Reg, String)>,
}

impl Lifter<'_> {
    pub(super) fn lift_branch<F>(
        &self,
        idx: usize,
        marks_try: Option<Reg>,
        env: &Env,
        flags: &mut Flags,
        depth: u32,
        build: F,
    ) -> Option<Vec<Stmt>>
    where
        F: Fn(&Self, &mut Flags) -> Option<Expr>,
    {
        let join: Option<u32> = self.joins.at(idx).filter(|label: &u32| {
            !flags.refused_joins.contains(&idx) && !flags.is_join_label(*label)
        });
        let Some(label) = join else {
            return build(self, flags).map(|expr: Expr| vec![Stmt::Return(expr)]);
        };
        let checkpoint: Checkpoint = flags.checkpoint();
        flags.joins.push(JoinFrame {
            target: Target::Label(label),
            marks_try,
            arrivals: Vec::new(),
            broken: false,
        });
        let built: Option<Expr> = build(self, flags);
        let frame: Option<JoinFrame> = flags.joins.pop();
        let closed: Option<Vec<Stmt>> = match (built, frame) {
            (Some(expr), Some(frame)) => self.close_join(label, frame, expr, env, flags, depth),
            _ => None,
        };
        if closed.is_some() {
            return closed;
        }
        flags.rewind(checkpoint);
        flags.refused_joins.insert(idx);
        build(self, flags).map(|expr: Expr| vec![Stmt::Return(expr)])
    }

    pub(super) fn lift_try_body(
        &self,
        idx: usize,
        region: Block,
        env: &Env,
        flags: &mut Flags,
        depth: u32,
    ) -> (Vec<Stmt>, Vec<CaseArm>) {
        let tag: Option<Reg> = self
            .instrs
            .get(idx)
            .and_then(|ins: &Instruction| ins.operands.first().and_then(as_reg));
        let split: Option<Reg> =
            tag.filter(|reg: &Reg| !flags.marks_try(*reg) && !flags.refused_splits.contains(&idx));
        if let Some(reg) = split {
            let checkpoint: Checkpoint = flags.checkpoint();
            flags.joins.push(JoinFrame {
                target: Target::TryEnd(reg),
                marks_try: None,
                arrivals: Vec::new(),
                broken: false,
            });
            let mut body_env: Env = env.clone();
            let mut body: Vec<Stmt> = self.walk_synth(region, &mut body_env, flags, depth + 1);
            let frame: Option<JoinFrame> = flags.joins.pop();
            if let Some(frame) = frame
                && let Some(of_arms) = self.close_try_split(frame, &mut body, env, flags, depth)
            {
                return (body, of_arms);
            }
            flags.rewind(checkpoint);
            flags.refused_splits.insert(idx);
        }
        let mut body_env: Env = env.clone();
        (
            self.walk_synth(region, &mut body_env, flags, depth + 1),
            Vec::new(),
        )
    }

    pub(super) fn lift_catch_body(
        &self,
        idx: usize,
        tag: Option<Reg>,
        region: Block,
        env: &Env,
        flags: &mut Flags,
        depth: u32,
    ) -> Option<(Expr, usize)> {
        let reg: Reg = tag.filter(|_| !flags.refused_splits.contains(&idx))?;
        let checkpoint: Checkpoint = flags.checkpoint();
        flags.joins.push(JoinFrame {
            target: Target::TryEnd(reg),
            marks_try: None,
            arrivals: Vec::new(),
            broken: false,
        });
        let mut body_env: Env = env.clone();
        let mut body: Vec<Stmt> = self.walk_synth(region, &mut body_env, flags, depth + 1);
        let frame: Option<JoinFrame> = flags.joins.pop();
        if let Some(frame) = frame
            && let Some(resume) = close_catch(&frame, &mut body, region.end.saturating_sub(1))
        {
            return Some((catch_value(body, &body_env), resume));
        }
        flags.rewind(checkpoint);
        flags.refused_splits.insert(idx);
        None
    }

    fn close_try_split(
        &self,
        frame: JoinFrame,
        body: &mut Vec<Stmt>,
        before: &Env,
        flags: &mut Flags,
        depth: u32,
    ) -> Option<Vec<CaseArm>> {
        if frame.broken {
            return None;
        }
        let tags: BTreeSet<String> = frame
            .arrivals
            .iter()
            .map(|arrival: &Arrival| arrival.tag.clone())
            .collect();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        if !frame.arrivals.is_empty() && !settle_body(body, &tags, false, &mut seen) {
            return None;
        }
        let mut census: Census = Census::default();
        census.body(body);
        if seen != tags || census.placeholders != tags.len() || census.try_ends != 0 {
            return None;
        }
        let Some(first) = frame.arrivals.first() else {
            return Some(Vec::new());
        };
        let at: usize = first.at;
        if frame
            .arrivals
            .iter()
            .any(|arrival: &Arrival| arrival.at != at)
        {
            return None;
        }
        let Merge {
            env: mut merged,
            mut phis,
        } = merge(&frame.arrivals, before, flags)?;
        let rest_region: Block = Block {
            start: at + 1,
            end: self.next_label_at(at + 1),
        };
        let rest: Vec<Stmt> = self.walk_synth(rest_region, &mut merged, flags, depth + 1);
        retain_used(&mut phis, &rest, flags);
        let values: BTreeMap<String, Expr> = arrival_values(&frame.arrivals, &phis);
        replace_body(body, &values);
        let names: Vec<Expr> = phis
            .into_iter()
            .map(|(_, name): (Reg, String)| Expr::Var(name))
            .collect();
        if !names.is_empty()
            && matches!(rest.as_slice(), [Stmt::Return(value)] if *value == pack(names.clone()))
        {
            return Some(Vec::new());
        }
        let pattern: Expr = if names.is_empty() {
            Expr::Var("_".to_owned())
        } else {
            pack(names)
        };
        Some(vec![CaseArm {
            pattern,
            guard: None,
            body: rest,
        }])
    }

    fn close_join(
        &self,
        label: u32,
        frame: JoinFrame,
        mut expr: Expr,
        before: &Env,
        flags: &mut Flags,
        depth: u32,
    ) -> Option<Vec<Stmt>> {
        if frame.broken {
            return None;
        }
        let tags: BTreeSet<String> = frame
            .arrivals
            .iter()
            .map(|arrival: &Arrival| arrival.tag.clone())
            .collect();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        if !frame.arrivals.is_empty()
            && !settle_construct(&mut expr, &tags, frame.marks_try.is_some(), &mut seen)
        {
            return None;
        }
        let mut census: Census = Census::default();
        census.expr(&expr);
        if seen != tags || census.placeholders != tags.len() || census.try_ends != 0 {
            return None;
        }
        if frame.arrivals.is_empty() {
            return Some(vec![Stmt::Return(expr)]);
        }
        let Merge {
            env: mut merged,
            mut phis,
        } = merge(&frame.arrivals, before, flags)?;
        let rest: Vec<Stmt> = self.walk(label, &mut merged, flags, depth + 1);
        retain_used(&mut phis, &rest, flags);
        let values: BTreeMap<String, Expr> = arrival_values(&frame.arrivals, &phis);
        let mut out: Vec<Stmt> = Vec::with_capacity(rest.len() + 1);
        if !(phis.is_empty() && only_placeholders(&expr)) {
            replace_construct(&mut expr, &values);
            let names: Vec<Expr> = phis
                .into_iter()
                .map(|(_, name): (Reg, String)| Expr::Var(name))
                .collect();
            if !names.is_empty()
                && matches!(rest.as_slice(), [Stmt::Return(value)] if *value == pack(names.clone()))
            {
                return Some(vec![Stmt::Return(expr)]);
            }
            out.push(if names.is_empty() {
                Stmt::Expr(expr)
            } else {
                Stmt::Bind {
                    pattern: pack(names),
                    value: expr,
                }
            });
        }
        out.extend(rest);
        Some(out)
    }
}

fn close_catch(frame: &JoinFrame, body: &mut Vec<Stmt>, catch_end: usize) -> Option<usize> {
    if frame.broken {
        return None;
    }
    let tags: BTreeSet<String> = frame
        .arrivals
        .iter()
        .map(|arrival: &Arrival| arrival.tag.clone())
        .collect();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    if !frame.arrivals.is_empty() && !settle_body(body, &tags, false, &mut seen) {
        return None;
    }
    let mut census: Census = Census::default();
    census.body(body);
    if seen != tags || census.placeholders != tags.len() || census.try_ends != 0 {
        return None;
    }
    let at: usize = frame
        .arrivals
        .first()
        .map_or(catch_end, |first: &Arrival| first.at);
    if frame
        .arrivals
        .iter()
        .any(|arrival: &Arrival| arrival.at != at)
    {
        return None;
    }
    let values: BTreeMap<String, Expr> = frame
        .arrivals
        .iter()
        .map(|arrival: &Arrival| (arrival.tag.clone(), arrival.env.get(Reg::X(0))))
        .collect();
    replace_body(body, &values);
    Some(at + 1)
}

fn merge(arrivals: &[Arrival], before: &Env, flags: &mut Flags) -> Option<Merge> {
    let first: &Env = &arrivals.first()?.env;
    if arrivals
        .iter()
        .any(|arrival: &Arrival| arrival.env.bin_ctx != first.bin_ctx)
    {
        return None;
    }
    let mut env: Env = Env {
        regs: BTreeMap::new(),
        bin_ctx: first.bin_ctx.clone(),
    };
    let outer_vars: BTreeSet<String> = env_vars(before);
    let mut phis: Vec<(Reg, String)> = Vec::new();
    let mut named: Vec<(Vec<Expr>, String)> = Vec::new();
    let regs: BTreeSet<Reg> = arrivals
        .iter()
        .flat_map(|arrival: &Arrival| arrival.env.regs.keys().copied())
        .collect();
    for reg in regs {
        let values: Option<Vec<Expr>> = arrivals
            .iter()
            .map(|arrival: &Arrival| arrival.env.bound(reg))
            .collect();
        let Some(values) = values else {
            continue;
        };
        let shared: bool = values.windows(2).all(|pair: &[Expr]| pair[0] == pair[1]);
        if shared && vars_within(&values[0], &outer_vars) {
            env.set(reg, values[0].clone());
        } else if let Some((_, name)) = named
            .iter()
            .find(|(seen, _): &&(Vec<Expr>, String)| *seen == values)
        {
            env.set(reg, Expr::Var(name.clone()));
        } else {
            let name: String = flags.fresh_join_var();
            env.set(reg, Expr::Var(name.clone()));
            phis.push((reg, name.clone()));
            named.push((values, name));
        }
    }
    Some(Merge { env, phis })
}

fn retain_used(phis: &mut Vec<(Reg, String)>, rest: &[Stmt], flags: &Flags) {
    let mut used: BTreeSet<String> = BTreeSet::new();
    body_vars(rest, &mut used);
    for frame in &flags.joins {
        for arrival in &frame.arrivals {
            for value in arrival.env.regs.values() {
                collect_vars(value, &mut used);
            }
        }
    }
    phis.retain(|(_, name): &(Reg, String)| used.contains(name));
}

fn arrival_values(arrivals: &[Arrival], phis: &[(Reg, String)]) -> BTreeMap<String, Expr> {
    arrivals
        .iter()
        .map(|arrival: &Arrival| {
            let parts: Vec<Expr> = phis
                .iter()
                .map(|(reg, _): &(Reg, String)| arrival.env.get(*reg))
                .collect();
            (arrival.tag.clone(), pack(parts))
        })
        .collect()
}

fn pack(mut parts: Vec<Expr>) -> Expr {
    match parts.len() {
        0 => Expr::Atom("ok".to_owned()),
        1 => parts.remove(0),
        _ => Expr::Tuple(parts),
    }
}

fn env_vars(env: &Env) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for value in env.regs.values() {
        collect_vars(value, &mut out);
    }
    out
}

fn vars_within(expr: &Expr, outer: &BTreeSet<String>) -> bool {
    let mut found: BTreeSet<String> = BTreeSet::new();
    collect_vars(expr, &mut found);
    found.is_subset(outer)
}

fn body_vars(stmts: &[Stmt], out: &mut BTreeSet<String>) {
    for stmt in stmts {
        match stmt {
            Stmt::Return(e) | Stmt::Expr(e) => collect_vars(e, out),
            Stmt::Bind { pattern, value } | Stmt::Match { pattern, value } => {
                collect_vars(pattern, out);
                collect_vars(value, out);
            }
            Stmt::Send { dest, msg } => {
                collect_vars(dest, out);
                collect_vars(msg, out);
            }
            Stmt::Comment(_) => {}
        }
    }
}

fn arm_vars(arm: &CaseArm, out: &mut BTreeSet<String>) {
    collect_vars(&arm.pattern, out);
    if let Some(guard) = arm.guard.as_ref() {
        collect_vars(guard, out);
    }
    body_vars(&arm.body, out);
}

fn collect_vars(expr: &Expr, out: &mut BTreeSet<String>) {
    match expr {
        Expr::Var(name) => {
            out.insert(name.clone());
        }
        Expr::Tuple(items) | Expr::Call { args: items, .. } | Expr::Guard { args: items, .. } => {
            for item in items {
                collect_vars(item, out);
            }
        }
        Expr::MakeFun { env, .. } => {
            for item in env {
                collect_vars(item, out);
            }
        }
        Expr::List { elements, tail } => {
            for item in elements {
                collect_vars(item, out);
            }
            collect_vars(tail, out);
        }
        Expr::Cons { head, tail } => {
            collect_vars(head, out);
            collect_vars(tail, out);
        }
        Expr::Map { pairs } | Expr::MapPattern { pairs } => {
            for (key, value) in pairs {
                collect_vars(key, out);
                collect_vars(value, out);
            }
        }
        Expr::MapUpdate { base, pairs, .. } => {
            collect_vars(base, out);
            for (key, value) in pairs {
                collect_vars(key, out);
                collect_vars(value, out);
            }
        }
        Expr::TupleElement { tuple, .. } => collect_vars(tuple, out),
        Expr::RecordUpdate { base, updates } => {
            collect_vars(base, out);
            for (_, value) in updates {
                collect_vars(value, out);
            }
        }
        Expr::BinOp { lhs, rhs, .. } => {
            collect_vars(lhs, out);
            collect_vars(rhs, out);
        }
        Expr::UnOp { operand, .. } => collect_vars(operand, out),
        Expr::CallFun { fun, args } => {
            collect_vars(fun, out);
            for item in args {
                collect_vars(item, out);
            }
        }
        Expr::BinaryConstruct(segments) => {
            for segment in segments {
                collect_vars(&segment.value, out);
                if let Some(size) = segment.size.as_deref() {
                    collect_vars(size, out);
                }
            }
        }
        Expr::Catch(inner) => collect_vars(inner, out),
        Expr::Case { subject, arms } => {
            collect_vars(subject, out);
            for arm in arms {
                arm_vars(arm, out);
            }
        }
        Expr::If { arms } => {
            for arm in arms {
                collect_vars(&arm.guard, out);
                body_vars(&arm.body, out);
            }
        }
        Expr::Receive { arms, after } => {
            for arm in arms {
                arm_vars(arm, out);
            }
            if let Some(clause) = after.as_deref() {
                collect_vars(&clause.timeout, out);
                body_vars(&clause.body, out);
            }
        }
        Expr::Try {
            body,
            of_arms,
            catch_arms,
            after,
        } => {
            body_vars(body, out);
            for arm in of_arms {
                arm_vars(arm, out);
            }
            for arm in catch_arms {
                out.insert(arm.class.clone());
                collect_vars(&arm.pattern, out);
                if let Some(stack) = arm.stacktrace.as_ref() {
                    out.insert(stack.clone());
                }
                body_vars(&arm.body, out);
            }
            body_vars(after, out);
        }
        Expr::Block(stmts) => body_vars(stmts, out),
        Expr::Atom(_)
        | Expr::Nil
        | Expr::Int(_)
        | Expr::BigInt { .. }
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::CharLit(_)
        | Expr::BinaryLit(_)
        | Expr::Raw(_) => {}
    }
}

fn is_placeholder(stmt: &Stmt) -> bool {
    matches!(stmt, Stmt::Return(Expr::Raw(tag)) if tag.starts_with(JOIN_TAG))
}

fn is_try_end(stmt: &Stmt) -> bool {
    matches!(stmt, Stmt::Comment(text) if text == TRY_END_TAG)
}

fn only_placeholders(expr: &Expr) -> bool {
    let single = |body: &[Stmt]| -> bool { matches!(body, [stmt] if is_placeholder(stmt)) };
    match expr {
        Expr::If { arms } => arms.iter().all(|arm: &IfArm| single(&arm.body)),
        Expr::Case { arms, .. } => arms.iter().all(|arm: &CaseArm| single(&arm.body)),
        _ => false,
    }
}

pub(super) fn is_raising_target(target: &str) -> bool {
    matches!(
        target,
        "error"
            | "exit"
            | "throw"
            | "erlang:error"
            | "erlang:exit"
            | "erlang:throw"
            | "erlang:raise"
            | "erlang:nif_error"
    )
}

fn settle_construct(
    expr: &mut Expr,
    tags: &BTreeSet<String>,
    try_frame: bool,
    seen: &mut BTreeSet<String>,
) -> bool {
    match expr {
        Expr::Try {
            body,
            of_arms,
            catch_arms,
            after,
        } if try_frame => {
            after.is_empty()
                && of_arms.is_empty()
                && settle_body(body, tags, true, seen)
                && catch_arms
                    .iter_mut()
                    .all(|arm: &mut CatchArm| settle_body(&mut arm.body, tags, false, seen))
        }
        _ if try_frame => false,
        _ => settle_expr(expr, tags, false, seen),
    }
}

fn settle_body(
    body: &mut Vec<Stmt>,
    tags: &BTreeSet<String>,
    marked: bool,
    seen: &mut BTreeSet<String>,
) -> bool {
    let Some(last) = body.last_mut() else {
        return false;
    };
    match last {
        Stmt::Return(Expr::Raw(tag)) if tag.starts_with(JOIN_TAG) => {
            if !tags.contains(tag.as_str()) || !seen.insert(tag.clone()) {
                return false;
            }
            if !marked {
                return true;
            }
            let at: Option<usize> = body.len().checked_sub(2);
            match at {
                Some(at) if is_try_end(&body[at]) => {
                    body.remove(at);
                    true
                }
                _ => false,
            }
        }
        Stmt::Return(Expr::Call { target, .. }) if is_raising_target(target) => true,
        Stmt::Return(inner) => settle_expr(inner, tags, marked, seen),
        Stmt::Comment(text) => text != TRY_END_TAG,
        _ => false,
    }
}

fn settle_expr(
    expr: &mut Expr,
    tags: &BTreeSet<String>,
    marked: bool,
    seen: &mut BTreeSet<String>,
) -> bool {
    match expr {
        Expr::If { arms } => arms
            .iter_mut()
            .all(|arm: &mut IfArm| settle_body(&mut arm.body, tags, marked, seen)),
        Expr::Case { arms, .. } => arms
            .iter_mut()
            .all(|arm: &mut CaseArm| settle_body(&mut arm.body, tags, marked, seen)),
        Expr::Receive { arms, after } => {
            arms.iter_mut()
                .all(|arm: &mut CaseArm| settle_body(&mut arm.body, tags, marked, seen))
                && after.as_deref_mut().is_none_or(|clause: &mut AfterClause| {
                    settle_body(&mut clause.body, tags, marked, seen)
                })
        }
        Expr::Try {
            body,
            of_arms,
            catch_arms,
            after,
        } => {
            after.is_empty()
                && (!of_arms.is_empty() || settle_body(body, tags, marked, seen))
                && of_arms
                    .iter_mut()
                    .all(|arm: &mut CaseArm| settle_body(&mut arm.body, tags, marked, seen))
                && catch_arms
                    .iter_mut()
                    .all(|arm: &mut CatchArm| settle_body(&mut arm.body, tags, marked, seen))
        }
        Expr::Block(stmts) => settle_body(stmts, tags, marked, seen),
        _ => false,
    }
}

#[derive(Debug, Default)]
struct Census {
    placeholders: usize,
    try_ends: usize,
}

impl Census {
    fn body(&mut self, stmts: &[Stmt]) {
        for stmt in stmts {
            match stmt {
                Stmt::Return(e) | Stmt::Expr(e) => self.expr(e),
                Stmt::Bind { value, .. } | Stmt::Match { value, .. } => self.expr(value),
                Stmt::Send { dest, msg } => {
                    self.expr(dest);
                    self.expr(msg);
                }
                Stmt::Comment(text) => {
                    if text == TRY_END_TAG {
                        self.try_ends += 1;
                    }
                }
            }
        }
    }

    fn expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Raw(tag) if tag.starts_with(JOIN_TAG) => self.placeholders += 1,
            Expr::Case { subject, arms } => {
                self.expr(subject);
                for arm in arms {
                    self.body(&arm.body);
                }
            }
            Expr::If { arms } => {
                for arm in arms {
                    self.body(&arm.body);
                }
            }
            Expr::Receive { arms, after } => {
                for arm in arms {
                    self.body(&arm.body);
                }
                if let Some(clause) = after.as_deref() {
                    self.body(&clause.body);
                }
            }
            Expr::Try {
                body,
                of_arms,
                catch_arms,
                after,
            } => {
                self.body(body);
                for arm in of_arms {
                    self.body(&arm.body);
                }
                for arm in catch_arms {
                    self.body(&arm.body);
                }
                self.body(after);
            }
            Expr::Catch(inner) => self.expr(inner),
            Expr::Block(stmts) => self.body(stmts),
            _ => {}
        }
    }
}

fn replace_construct(expr: &mut Expr, values: &BTreeMap<String, Expr>) {
    match expr {
        Expr::Case { arms, .. } => {
            for arm in arms {
                replace_body(&mut arm.body, values);
            }
        }
        Expr::Receive { arms, after } => {
            for arm in arms {
                replace_body(&mut arm.body, values);
            }
            if let Some(clause) = after.as_deref_mut() {
                replace_body(&mut clause.body, values);
            }
        }
        Expr::If { arms } => {
            for arm in arms {
                replace_body(&mut arm.body, values);
            }
        }
        Expr::Try {
            body,
            of_arms,
            catch_arms,
            after,
        } => {
            if of_arms.is_empty() {
                replace_body(body, values);
            }
            for arm in of_arms {
                replace_body(&mut arm.body, values);
            }
            for arm in catch_arms {
                replace_body(&mut arm.body, values);
            }
            replace_body(after, values);
        }
        Expr::Block(stmts) => replace_body(stmts, values),
        _ => {}
    }
}

fn replace_body(body: &mut [Stmt], values: &BTreeMap<String, Expr>) {
    if let Some(Stmt::Return(last)) = body.last_mut() {
        if let Expr::Raw(tag) = last
            && let Some(value) = values.get(tag.as_str())
        {
            *last = value.clone();
            return;
        }
        replace_construct(last, values);
    }
}
