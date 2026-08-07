use std::collections::{BTreeMap, BTreeSet};

use disrobe_cfg::{
    Cfg, CfgNode, CnsBudget, CnsOutcome, Region, RegionId, RegionKind, Terminator,
    structure_with_cns,
};

use crate::debug::{dbg_kv, dbg_section};
use crate::error::{Error, Result};
use crate::obfuscator::prometheus_vm_ast::{
    AssignTarget, BinOp, Block, Expr, ExprKind, LocalId, Parser, Span, Stat, StatKind, TableField,
    Var,
};

const MAX_DISPATCH_DEPTH: u32 = 96;
const MAX_FUNCTION_BLOCKS: usize = 1 << 14;
const MAX_FUNCTIONS: usize = 1 << 10;
const MAX_REACHABILITY_STEPS: usize = 1 << 18;
const MAX_RECOVERY_DEPTH: usize = 6;

fn refuse(reason: &str) -> Error {
    Error::PrometheusVmifyRefused(reason.to_owned())
}

fn refuse_owned(reason: String) -> Error {
    Error::PrometheusVmifyRefused(reason)
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ThresholdOp {
    Lt,
    Gt,
}

fn is_bare_local(expr: &Expr, id: LocalId) -> bool {
    matches!(&unwrap_paren(expr).kind, ExprKind::Var(Var::Local(x)) if *x == id)
}

fn number_of(expr: &Expr) -> Option<f64> {
    match expr.kind {
        ExprKind::Number(n) => Some(n),
        _ => None,
    }
}

fn as_pos_threshold(cond: &Expr, pos_local: LocalId) -> Option<(ThresholdOp, f64)> {
    let ExprKind::Binary(op, lhs, rhs) = &cond.kind else {
        return None;
    };
    let lhs_is_pos: bool = is_bare_local(lhs, pos_local);
    let rhs_is_pos: bool = is_bare_local(rhs, pos_local);
    match (op, lhs_is_pos, rhs_is_pos) {
        (BinOp::Lt, true, false) => number_of(rhs).map(|n: f64| (ThresholdOp::Lt, n)),
        (BinOp::Gt, false, true) => number_of(lhs).map(|n: f64| (ThresholdOp::Lt, n)),
        (BinOp::Gt, true, false) => number_of(rhs).map(|n: f64| (ThresholdOp::Gt, n)),
        (BinOp::Lt, false, true) => number_of(lhs).map(|n: f64| (ThresholdOp::Gt, n)),
        _ => None,
    }
}

fn eval_threshold(op: ThresholdOp, bound: f64, candidate: f64) -> bool {
    match op {
        ThresholdOp::Lt => candidate < bound,
        ThresholdOp::Gt => candidate > bound,
    }
}

fn is_dispatch_if(arms: &[(Expr, Block)], else_body: Option<&Block>, pos_local: LocalId) -> bool {
    !arms.is_empty()
        && else_body.is_some()
        && arms
            .iter()
            .all(|(cond, _): &(Expr, Block)| as_pos_threshold(cond, pos_local).is_some())
}

fn leaf_ident(b: &Block) -> u64 {
    std::ptr::from_ref::<Block>(b).addr() as u64
}

fn resolve_leaf(block: &Block, pos_local: LocalId, candidate: f64, depth: u32) -> Option<&Block> {
    if depth > MAX_DISPATCH_DEPTH {
        return None;
    }
    if let [stat] = block.stats.as_slice()
        && let StatKind::If { arms, else_body } = &stat.kind
        && is_dispatch_if(arms, else_body.as_ref(), pos_local)
    {
        for (cond, body) in arms {
            let (op, bound): (ThresholdOp, f64) = as_pos_threshold(cond, pos_local)?;
            if eval_threshold(op, bound, candidate) {
                return resolve_leaf(body, pos_local, candidate, depth + 1);
            }
        }
        let else_body: &Block = else_body.as_ref()?;
        return resolve_leaf(else_body, pos_local, candidate, depth + 1);
    }
    Some(block)
}

fn collect_all_leaves<'a>(
    block: &'a Block,
    pos_local: LocalId,
    out: &mut Vec<&'a Block>,
    depth: u32,
) -> Result<()> {
    if depth > MAX_DISPATCH_DEPTH {
        return Err(refuse("dispatch tree exceeds depth budget"));
    }
    if let [stat] = block.stats.as_slice()
        && let StatKind::If { arms, else_body } = &stat.kind
        && is_dispatch_if(arms, else_body.as_ref(), pos_local)
    {
        for (_, body) in arms {
            collect_all_leaves(body, pos_local, out, depth + 1)?;
        }
        if let Some(else_body) = else_body {
            collect_all_leaves(else_body, pos_local, out, depth + 1)?;
        }
        return Ok(());
    }
    if out.len() >= MAX_FUNCTION_BLOCKS {
        return Err(refuse("dispatch tree exceeds leaf budget"));
    }
    out.push(block);
    Ok(())
}

fn walk_exprs<'a>(block: &'a Block, out: &mut Vec<&'a Expr>) {
    for stat in &block.stats {
        walk_exprs_stat(stat, out);
    }
}

fn walk_exprs_stat<'a>(stat: &'a Stat, out: &mut Vec<&'a Expr>) {
    match &stat.kind {
        StatKind::Local { values, .. } => {
            for v in values {
                walk_exprs_expr(v, out);
            }
        }
        StatKind::Assign { targets, values } => {
            for t in targets {
                if let AssignTarget::Index(base, key, _) = t {
                    walk_exprs_expr(base, out);
                    walk_exprs_expr(key, out);
                }
            }
            for v in values {
                walk_exprs_expr(v, out);
            }
        }
        StatKind::ExprStat(e) => walk_exprs_expr(e, out),
        StatKind::Do(b) | StatKind::While { body: b, .. } | StatKind::Repeat { body: b, .. } => {
            walk_exprs(b, out);
        }
        StatKind::If { arms, else_body } => {
            for (cond, body) in arms {
                walk_exprs_expr(cond, out);
                walk_exprs(body, out);
            }
            if let Some(eb) = else_body {
                walk_exprs(eb, out);
            }
        }
        StatKind::NumericFor {
            start,
            stop,
            step,
            body,
            ..
        } => {
            walk_exprs_expr(start, out);
            walk_exprs_expr(stop, out);
            if let Some(s) = step {
                walk_exprs_expr(s, out);
            }
            walk_exprs(body, out);
        }
        StatKind::GenericFor { exprs, body, .. } => {
            for e in exprs {
                walk_exprs_expr(e, out);
            }
            walk_exprs(body, out);
        }
        StatKind::Return(values) => {
            for v in values {
                walk_exprs_expr(v, out);
            }
        }
        StatKind::Break => {}
    }
}

fn walk_exprs_expr<'a>(expr: &'a Expr, out: &mut Vec<&'a Expr>) {
    out.push(expr);
    match &expr.kind {
        ExprKind::Index(base, key) => {
            walk_exprs_expr(base, out);
            walk_exprs_expr(key, out);
        }
        ExprKind::Call { base, args } => {
            walk_exprs_expr(base, out);
            for a in args {
                walk_exprs_expr(a, out);
            }
        }
        ExprKind::MethodCall { base, args, .. } => {
            walk_exprs_expr(base, out);
            for a in args {
                walk_exprs_expr(a, out);
            }
        }
        ExprKind::Function { body, .. } => walk_exprs(body, out),
        ExprKind::Table(fields) => {
            for field in fields {
                match field {
                    TableField::Positional(v) => walk_exprs_expr(v, out),
                    TableField::Named(_, v) => walk_exprs_expr(v, out),
                    TableField::Indexed(k, v) => {
                        walk_exprs_expr(k, out);
                        walk_exprs_expr(v, out);
                    }
                }
            }
        }
        ExprKind::Binary(_, l, r) => {
            walk_exprs_expr(l, out);
            walk_exprs_expr(r, out);
        }
        ExprKind::Unary(_, e) | ExprKind::Paren(e) => walk_exprs_expr(e, out),
        ExprKind::Nil
        | ExprKind::True
        | ExprKind::False
        | ExprKind::Vararg
        | ExprKind::Number(_)
        | ExprKind::Str
        | ExprKind::Var(_) => {}
    }
}

fn collect_locals_used(block: &Block, out: &mut BTreeSet<LocalId>) {
    let mut exprs: Vec<&Expr> = Vec::new();
    walk_exprs(block, &mut exprs);
    for e in exprs {
        if let ExprKind::Var(Var::Local(id)) = &e.kind {
            out.insert(*id);
        }
    }
    for stat in &block.stats {
        if let StatKind::Assign { targets, .. } = &stat.kind {
            for t in targets {
                if let AssignTarget::Var(Var::Local(id), _) = t {
                    out.insert(*id);
                }
            }
        }
        if let StatKind::Local { targets, .. } = &stat.kind {
            for id in targets {
                out.insert(*id);
            }
        }
    }
}

struct ContainerShape<'a> {
    pos_local: LocalId,
    args_local: LocalId,
    upvals_local: LocalId,
    gcflag_local: LocalId,
    dispatch_root: &'a Block,
    full_body: &'a Block,
    whole_span: Span,
}

fn as_container_shape(func_expr: &Expr) -> Option<ContainerShape<'_>> {
    let ExprKind::Function {
        params,
        is_vararg,
        body,
    } = &func_expr.kind
    else {
        return None;
    };
    if *is_vararg || params.len() != 4 {
        return None;
    }
    let pos_local: LocalId = params[0];
    for stat in &body.stats {
        if let StatKind::While { cond, body: wbody } = &stat.kind
            && is_bare_local(cond, pos_local)
        {
            return Some(ContainerShape {
                pos_local,
                args_local: params[1],
                upvals_local: params[2],
                gcflag_local: params[3],
                dispatch_root: wbody,
                full_body: body,
                whole_span: func_expr.span,
            });
        }
    }
    None
}

fn container_scope_locals(container: &ContainerShape<'_>) -> BTreeSet<LocalId> {
    let mut out: BTreeSet<LocalId> = BTreeSet::from([
        container.pos_local,
        container.args_local,
        container.upvals_local,
        container.gcflag_local,
    ]);
    collect_declared_locals(container.full_body, &mut out);
    out
}

fn collect_declared_locals(block: &Block, out: &mut BTreeSet<LocalId>) {
    for stat in &block.stats {
        match &stat.kind {
            StatKind::Local { targets, .. } => out.extend(targets.iter().copied()),
            StatKind::Do(b)
            | StatKind::While { body: b, .. }
            | StatKind::Repeat { body: b, .. } => {
                collect_declared_locals(b, out);
            }
            StatKind::If { arms, else_body } => {
                for (_, body) in arms {
                    collect_declared_locals(body, out);
                }
                if let Some(eb) = else_body {
                    collect_declared_locals(eb, out);
                }
            }
            StatKind::NumericFor { var, body, .. } => {
                out.insert(*var);
                collect_declared_locals(body, out);
            }
            StatKind::GenericFor { vars, body, .. } => {
                out.extend(vars.iter().copied());
                collect_declared_locals(body, out);
            }
            StatKind::Assign { .. }
            | StatKind::ExprStat(_)
            | StatKind::Return(_)
            | StatKind::Break => {}
        }
    }
}

fn find_enclosing_function_span(chunk: &Block, target_span: Span) -> Option<Span> {
    let mut all_exprs: Vec<&Expr> = Vec::new();
    walk_exprs(chunk, &mut all_exprs);
    let mut matches: Vec<Span> = all_exprs
        .iter()
        .filter_map(|e: &&Expr| {
            let ExprKind::Function { body, .. } = &e.kind else {
                return None;
            };
            find_local_binding_block_direct(body, target_span).then_some(e.span)
        })
        .collect();
    matches.dedup();
    match matches.as_slice() {
        [single] => Some(*single),
        _ => None,
    }
}

fn find_local_binding_block_direct(block: &Block, target_span: Span) -> bool {
    for stat in &block.stats {
        match &stat.kind {
            StatKind::Local { values, .. } | StatKind::Assign { values, .. }
                if values.iter().any(|v: &Expr| v.span == target_span) =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn unwrap_paren(expr: &Expr) -> &Expr {
    let mut current: &Expr = expr;
    while let ExprKind::Paren(inner) = &current.kind {
        current = inner;
    }
    current
}

fn wrapper_internal_bindings(wrapper_body: &Block) -> BTreeMap<LocalId, Span> {
    let mut out: BTreeMap<LocalId, Span> = BTreeMap::new();
    for stat in &wrapper_body.stats {
        match &stat.kind {
            StatKind::Assign { targets, values } => {
                for (i, t) in targets.iter().enumerate() {
                    if let AssignTarget::Var(Var::Local(id), _) = t
                        && let Some(v) = values.get(i)
                    {
                        out.entry(*id).or_insert(v.span);
                    }
                }
            }
            StatKind::Local { targets, values } => {
                for (i, id) in targets.iter().enumerate() {
                    if let Some(v) = values.get(i) {
                        out.entry(*id).or_insert(v.span);
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn wrapper_upvalue_bindings(chunk: &Block, wrapper_span: Span) -> Option<BTreeMap<LocalId, Span>> {
    let mut all_exprs: Vec<&Expr> = Vec::new();
    walk_exprs(chunk, &mut all_exprs);
    let (wrapper_params, wrapper_body): (Vec<LocalId>, &Block) =
        all_exprs.iter().find_map(|e: &&Expr| {
            if e.span == wrapper_span
                && let ExprKind::Function {
                    params,
                    is_vararg,
                    body,
                } = &e.kind
                && !is_vararg
            {
                Some((params.clone(), body))
            } else {
                None
            }
        })?;
    let call_args: &[Expr] = all_exprs.iter().find_map(|e: &&Expr| {
        if let ExprKind::Call { base, args } = &e.kind
            && unwrap_paren(base).span == wrapper_span
        {
            Some(args.as_slice())
        } else {
            None
        }
    })?;
    let mut out: BTreeMap<LocalId, Span> = wrapper_params
        .iter()
        .zip(call_args.iter())
        .map(|(id, arg): (&LocalId, &Expr)| (*id, arg.span))
        .collect();
    for (id, span) in wrapper_internal_bindings(wrapper_body) {
        out.entry(id).or_insert(span);
    }
    Some(out)
}

fn confirms_creator_shape(func_expr: &Expr, container_local: LocalId) -> bool {
    let ExprKind::Function {
        params,
        is_vararg,
        body,
    } = &func_expr.kind
    else {
        return false;
    };
    if *is_vararg || params.len() != 2 {
        return false;
    }
    let outer_pos: LocalId = params[0];
    let outer_upvals: LocalId = params[1];
    let mut inner_local: Option<LocalId> = None;
    for stat in &body.stats {
        if let StatKind::Local { targets, values } = &stat.kind
            && targets.len() == 1
            && values.len() == 1
            && matches!(values[0].kind, ExprKind::Function { .. })
        {
            inner_local = Some(targets[0]);
        }
    }
    let Some(inner_local) = inner_local else {
        return false;
    };
    for stat in &body.stats {
        let StatKind::Local { targets, values } = &stat.kind else {
            continue;
        };
        if targets.len() != 1 || targets[0] != inner_local || values.len() != 1 {
            continue;
        }
        let ExprKind::Function {
            body: inner_body, ..
        } = &values[0].kind
        else {
            continue;
        };
        for istat in &inner_body.stats {
            if let StatKind::Return(rv) = &istat.kind
                && rv.len() == 1
                && call_targets_container(&rv[0], container_local, outer_pos, outer_upvals)
            {
                return true;
            }
        }
    }
    false
}

fn call_targets_container(
    expr: &Expr,
    container_local: LocalId,
    outer_pos: LocalId,
    outer_upvals: LocalId,
) -> bool {
    let ExprKind::Call { base, args } = &expr.kind else {
        return false;
    };
    if !is_bare_local(base, container_local) || args.len() != 4 {
        return false;
    }
    is_bare_local(&args[0], outer_pos) && is_bare_local(&args[2], outer_upvals)
}

fn find_local_binding(chunk: &Block, target_span: Span) -> Option<LocalId> {
    let mut found: Option<LocalId> = None;
    find_local_binding_block(chunk, target_span, &mut found);
    found
}

fn find_local_binding_block(block: &Block, target_span: Span, found: &mut Option<LocalId>) {
    if found.is_some() {
        return;
    }
    for stat in &block.stats {
        find_local_binding_stat(stat, target_span, found);
        if found.is_some() {
            return;
        }
    }
}

fn find_local_binding_stat(stat: &Stat, target_span: Span, found: &mut Option<LocalId>) {
    match &stat.kind {
        StatKind::Local { targets, values } => {
            for (i, v) in values.iter().enumerate() {
                if v.span == target_span
                    && let Some(id) = targets.get(i).copied()
                {
                    *found = Some(id);
                    return;
                }
                find_local_binding_expr(v, target_span, found);
            }
        }
        StatKind::Assign { targets, values } => {
            for (i, v) in values.iter().enumerate() {
                if v.span == target_span
                    && let Some(AssignTarget::Var(Var::Local(id), _)) = targets.get(i)
                {
                    *found = Some(*id);
                    return;
                }
                find_local_binding_expr(v, target_span, found);
            }
        }
        StatKind::ExprStat(e) => find_local_binding_expr(e, target_span, found),
        StatKind::Do(b) | StatKind::While { body: b, .. } | StatKind::Repeat { body: b, .. } => {
            find_local_binding_block(b, target_span, found);
        }
        StatKind::If { arms, else_body } => {
            for (cond, body) in arms {
                find_local_binding_expr(cond, target_span, found);
                find_local_binding_block(body, target_span, found);
            }
            if let Some(eb) = else_body {
                find_local_binding_block(eb, target_span, found);
            }
        }
        StatKind::NumericFor { body, .. } | StatKind::GenericFor { body, .. } => {
            find_local_binding_block(body, target_span, found);
        }
        StatKind::Return(values) => {
            for v in values {
                find_local_binding_expr(v, target_span, found);
            }
        }
        StatKind::Break => {}
    }
}

fn find_local_binding_expr(expr: &Expr, target_span: Span, found: &mut Option<LocalId>) {
    if found.is_some() {
        return;
    }
    let mut nested: Vec<&Expr> = Vec::new();
    walk_exprs_expr(expr, &mut nested);
    for e in nested {
        if found.is_some() {
            return;
        }
        if let ExprKind::Function { body, .. } = &e.kind {
            find_local_binding_block(body, target_span, found);
        }
    }
}

fn nth_last_target_stmt(stats: &[Stat], target: LocalId, skip: usize) -> Option<(Span, &Expr)> {
    let mut remaining: usize = skip;
    for stat in stats.iter().rev() {
        if let StatKind::Assign { targets, values } = &stat.kind {
            for (i, t) in targets.iter().enumerate() {
                if let AssignTarget::Var(Var::Local(id), _) = t
                    && *id == target
                    && let Some(v) = values.get(i)
                {
                    if remaining == 0 {
                        return Some((stat.span, v));
                    }
                    remaining -= 1;
                }
            }
        }
    }
    None
}

fn nth_last_target_value(stats: &[Stat], target: LocalId, skip: usize) -> Option<&Expr> {
    nth_last_target_stmt(stats, target, skip).map(|(_, v): (Span, &Expr)| v)
}

fn last_target_value(stats: &[Stat], target: LocalId) -> Option<&Expr> {
    nth_last_target_value(stats, target, 0)
}

fn is_exit_shape(rhs: &Expr) -> bool {
    matches!(&rhs.kind, ExprKind::Index(_, key) if matches!(key.kind, ExprKind::Str))
}

fn find_return_local(dispatch_root: &Block, pos_local: LocalId) -> Result<LocalId> {
    let mut leaves: Vec<&Block> = Vec::new();
    collect_all_leaves(dispatch_root, pos_local, &mut leaves, 0)?;
    let mut votes: BTreeMap<LocalId, usize> = BTreeMap::new();
    let mut exit_leaves_seen: usize = 0;
    for leaf in &leaves {
        let Some(pos_rhs) = last_target_value(&leaf.stats, pos_local) else {
            continue;
        };
        if !is_exit_shape(pos_rhs) {
            continue;
        }
        exit_leaves_seen += 1;
        let mut seen_in_leaf: BTreeSet<LocalId> = BTreeSet::new();
        for stat in &leaf.stats {
            if let StatKind::Assign { targets, values } = &stat.kind {
                for (i, t) in targets.iter().enumerate() {
                    if let AssignTarget::Var(Var::Local(id), _) = t
                        && matches!(
                            values.get(i).map(|v: &Expr| &v.kind),
                            Some(ExprKind::Table(_))
                        )
                    {
                        seen_in_leaf.insert(*id);
                    }
                }
            }
        }
        for id in seen_in_leaf {
            *votes.entry(id).or_insert(0) += 1;
        }
    }
    dbg_kv("prometheus_vmify.dispatch_leaves", || {
        leaves.len().to_string()
    });
    dbg_kv("prometheus_vmify.exit_leaves", || {
        exit_leaves_seen.to_string()
    });
    let max: usize = votes.values().copied().max().unwrap_or(0);
    if max == 0 {
        return Err(refuse(
            "no exit block carries a recognizable return-value table assignment (a preceding string-pool step may have replaced the exit sentinel literal with a pool lookup)",
        ));
    }
    let winners: Vec<LocalId> = votes
        .iter()
        .filter(|(_, c): &(&LocalId, &usize)| **c == max)
        .map(|(id, _): (&LocalId, &usize)| *id)
        .collect();
    match winners.as_slice() {
        [single] => Ok(*single),
        _ => Err(refuse(
            "the return-value register is ambiguous across the program's exit blocks",
        )),
    }
}

enum Transfer<'a> {
    Return,
    Goto(f64),
    Branch {
        cond: &'a Expr,
        cond_capture_span: Option<Span>,
        taken: f64,
        not_taken: f64,
    },
}

struct LeafPlan {
    pos_terminal_span: Span,
    pos_chain_span: Option<Span>,
    return_span: Option<Span>,
    numeric_chain_spans: Vec<Span>,
}

const MAX_SCRATCH_CHAIN_DEPTH: u32 = 12;

fn resolve_number_via_last_write(
    leaf: &Block,
    expr: &Expr,
    depth: u32,
    chain: &mut Vec<Span>,
) -> Option<f64> {
    if depth > MAX_SCRATCH_CHAIN_DEPTH {
        return None;
    }
    match &expr.kind {
        ExprKind::Number(n) => Some(*n),
        ExprKind::Var(Var::Local(id)) => {
            let (span, prior): (Span, &Expr) = nth_last_target_stmt(&leaf.stats, *id, 0)?;
            chain.push(span);
            resolve_number_via_last_write(leaf, prior, depth + 1, chain)
        }
        _ => None,
    }
}

fn resolve_and_expr<'a>(
    leaf: &'a Block,
    expr: &'a Expr,
    defining_span: Option<Span>,
    depth: u32,
) -> Option<(&'a Expr, Option<Span>)> {
    if depth > MAX_SCRATCH_CHAIN_DEPTH {
        return None;
    }
    match &expr.kind {
        ExprKind::Binary(BinOp::And, ..) => Some((expr, defining_span)),
        ExprKind::Var(Var::Local(id)) => {
            let (span, prior): (Span, &Expr) = nth_last_target_stmt(&leaf.stats, *id, 0)?;
            resolve_and_expr(leaf, prior, Some(span), depth + 1)
        }
        _ => None,
    }
}

fn contains_local_decl_anywhere(block: &Block) -> bool {
    block.stats.iter().any(stat_contains_local_decl)
}

fn stat_contains_local_decl(stat: &Stat) -> bool {
    if matches!(stat.kind, StatKind::Local { .. }) {
        return true;
    }
    match &stat.kind {
        StatKind::Local { values, .. } => values.iter().any(expr_contains_local_decl),
        StatKind::Assign { targets, values } => {
            targets.iter().any(|t: &AssignTarget| match t {
                AssignTarget::Index(base, key, _) => {
                    expr_contains_local_decl(base) || expr_contains_local_decl(key)
                }
                AssignTarget::Var(..) => false,
            }) || values.iter().any(expr_contains_local_decl)
        }
        StatKind::ExprStat(e) => expr_contains_local_decl(e),
        StatKind::Do(b) | StatKind::While { body: b, .. } | StatKind::Repeat { body: b, .. } => {
            contains_local_decl_anywhere(b)
        }
        StatKind::If { arms, else_body } => {
            arms.iter().any(|(cond, body): &(Expr, Block)| {
                expr_contains_local_decl(cond) || contains_local_decl_anywhere(body)
            }) || else_body.as_ref().is_some_and(contains_local_decl_anywhere)
        }
        StatKind::NumericFor {
            start,
            stop,
            step,
            body,
            ..
        } => {
            expr_contains_local_decl(start)
                || expr_contains_local_decl(stop)
                || step.as_ref().is_some_and(expr_contains_local_decl)
                || contains_local_decl_anywhere(body)
        }
        StatKind::GenericFor { exprs, body, .. } => {
            exprs.iter().any(expr_contains_local_decl) || contains_local_decl_anywhere(body)
        }
        StatKind::Return(values) => values.iter().any(expr_contains_local_decl),
        StatKind::Break => false,
    }
}

fn expr_contains_local_decl(expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::Function { body, .. } => contains_local_decl_anywhere(body),
        ExprKind::Index(base, key) => {
            expr_contains_local_decl(base) || expr_contains_local_decl(key)
        }
        ExprKind::Call { base, args } => {
            expr_contains_local_decl(base) || args.iter().any(expr_contains_local_decl)
        }
        ExprKind::MethodCall { base, args, .. } => {
            expr_contains_local_decl(base) || args.iter().any(expr_contains_local_decl)
        }
        ExprKind::Table(fields) => fields.iter().any(|field: &TableField| match field {
            TableField::Positional(v) => expr_contains_local_decl(v),
            TableField::Named(_, v) => expr_contains_local_decl(v),
            TableField::Indexed(k, v) => expr_contains_local_decl(k) || expr_contains_local_decl(v),
        }),
        ExprKind::Binary(_, l, r) => expr_contains_local_decl(l) || expr_contains_local_decl(r),
        ExprKind::Unary(_, e) | ExprKind::Paren(e) => expr_contains_local_decl(e),
        ExprKind::Nil
        | ExprKind::True
        | ExprKind::False
        | ExprKind::Vararg
        | ExprKind::Number(_)
        | ExprKind::Str
        | ExprKind::Var(_) => false,
    }
}

fn terminal_transfer(
    leaf: &Block,
    pos_local: LocalId,
    return_local: LocalId,
) -> Result<(Transfer<'_>, LeafPlan)> {
    if contains_local_decl_anywhere(leaf) {
        return Err(refuse(
            "a reachable leaf carries a real local declaration, directly or inside a nested closure it builds; this is the shape of a nested Vmify layer's own bootstrap code and is not yet peeled through a second recognizer pass",
        ));
    }
    let Some((pos_terminal_span, rhs)) = nth_last_target_stmt(&leaf.stats, pos_local, 0) else {
        return Err(refuse(
            "a reachable leaf block never assigns the instruction-pointer register",
        ));
    };
    match &rhs.kind {
        ExprKind::Number(n) => Ok((
            Transfer::Goto(*n),
            LeafPlan {
                pos_terminal_span,
                pos_chain_span: None,
                return_span: None,
                numeric_chain_spans: Vec::new(),
            },
        )),
        ExprKind::Binary(BinOp::Or, lhs, rhs2) => {
            let (start, pos_chain_span): (Option<&Expr>, Option<Span>) =
                if is_bare_local(lhs, pos_local) {
                    match nth_last_target_stmt(&leaf.stats, pos_local, 1) {
                        Some((span, val)) => (Some(val), Some(span)),
                        None => (None, None),
                    }
                } else {
                    (Some(lhs.as_ref()), None)
                };
            let Some(start) = start else {
                return Err(refuse_owned(format!(
                    "a leaf's instruction-pointer assignment is an or-expression but not the and/or numeric ternary shape, at byte {}",
                    rhs.span.start
                )));
            };
            let Some((and_expr, and_def_span)) = resolve_and_expr(leaf, start, pos_chain_span, 0)
            else {
                return Err(refuse_owned(format!(
                    "a leaf's instruction-pointer assignment is an or-expression but not the and/or numeric ternary shape, at byte {}",
                    rhs.span.start
                )));
            };
            let ExprKind::Binary(BinOp::And, cond, taken) = &and_expr.kind else {
                unreachable!("resolve_and_expr only returns Binary(And, ..) expressions");
            };
            let mut numeric_chain_spans: Vec<Span> = Vec::new();
            let (Some(t), Some(nt)) = (
                resolve_number_via_last_write(leaf, taken, 0, &mut numeric_chain_spans),
                resolve_number_via_last_write(leaf, rhs2, 0, &mut numeric_chain_spans),
            ) else {
                return Err(refuse_owned(format!(
                    "a leaf's ternary jump targets do not resolve to static numeric literals, at byte {}",
                    rhs.span.start
                )));
            };
            numeric_chain_spans.retain(|s: &Span| Some(*s) != and_def_span);
            Ok((
                Transfer::Branch {
                    cond,
                    cond_capture_span: and_def_span,
                    taken: t,
                    not_taken: nt,
                },
                LeafPlan {
                    pos_terminal_span,
                    pos_chain_span,
                    return_span: None,
                    numeric_chain_spans,
                },
            ))
        }
        _ if is_exit_shape(rhs) => {
            let return_span: Option<Span> =
                nth_last_target_stmt(&leaf.stats, return_local, 0).map(|(s, _): (Span, &Expr)| s);
            Ok((
                Transfer::Return,
                LeafPlan {
                    pos_terminal_span,
                    pos_chain_span: None,
                    return_span,
                    numeric_chain_spans: Vec::new(),
                },
            ))
        }
        _ => Err(refuse_owned(format!(
            "a leaf's instruction-pointer assignment has an unrecognized shape at byte {}",
            rhs.span.start
        ))),
    }
}

fn collect_creation_calls<'a>(
    exprs: &[&'a Expr],
    creator_locals: &BTreeSet<LocalId>,
) -> Vec<(&'a Expr, LocalId, &'a Expr, &'a Expr)> {
    let mut out: Vec<(&Expr, LocalId, &Expr, &Expr)> = Vec::new();
    for e in exprs {
        if let ExprKind::Call { base, args } = &e.kind
            && let ExprKind::Var(Var::Local(id)) = &base.kind
            && creator_locals.contains(id)
            && args.len() == 2
        {
            out.push((e, *id, &args[0], &args[1]));
        }
    }
    out
}

fn span_key(s: Span) -> u64 {
    (u64::from(s.start) << 32) | u64::from(s.end)
}

struct RecoveredFunction {
    text: String,
}

#[derive(Debug, Default)]
struct GlobalStats {
    leaves_recovered: usize,
    functions_attempted: usize,
    functions_fully_structured: usize,
    reached: BTreeSet<u64>,
}

#[derive(Debug)]
pub struct VmifyRecovery {
    pub source: String,
    pub handlers_recovered: usize,
    pub handlers_total: usize,
    pub functions_recovered: usize,
    pub functions_total: usize,
    pub unreached_structural_leaves: usize,
    pub fully_recovered: bool,
}

struct Ctx<'a> {
    src: &'a str,
    pos_local: LocalId,
    args_local: LocalId,
    return_local: LocalId,
    dispatch_root: &'a Block,
    container_span: Span,
    container_scope: BTreeSet<LocalId>,
    upvalue_bindings: BTreeMap<LocalId, Span>,
    all_creation_calls: Vec<(&'a Expr, LocalId, &'a Expr, &'a Expr)>,
}

fn find_top_level_entry(ctx: &Ctx<'_>) -> Result<f64> {
    let mut outside: Vec<f64> = Vec::new();
    for (call_expr, _creator, entry_arg, _upvals) in &ctx.all_creation_calls {
        let within: bool = call_expr.span.start >= ctx.container_span.start
            && call_expr.span.end <= ctx.container_span.end;
        if within {
            continue;
        }
        let Some(entry) = number_of(entry_arg) else {
            continue;
        };
        outside.push(entry);
    }
    match outside.as_slice() {
        [single] => Ok(*single),
        [] => Err(refuse(
            "no top-level Vmify entry point found outside the container function",
        )),
        _ => Err(refuse(
            "more than one top-level Vmify entry point found; ambiguous chunk root",
        )),
    }
}

fn recover_function(
    ctx: &Ctx<'_>,
    entry: f64,
    depth: usize,
    subst: &mut BTreeMap<u64, String>,
    stats: &mut GlobalStats,
) -> Result<RecoveredFunction> {
    if depth > MAX_RECOVERY_DEPTH {
        return Err(refuse("closure nesting exceeds recovery depth budget"));
    }
    stats.functions_attempted += 1;
    if stats.functions_attempted > MAX_FUNCTIONS {
        return Err(refuse(
            "program defines more closures than the recovery budget allows",
        ));
    }
    let mut visited: BTreeMap<u64, &Block> = BTreeMap::new();
    let mut order: Vec<u64> = Vec::new();
    let mut pending: Vec<f64> = vec![entry];
    let mut steps: usize = 0;
    while let Some(v) = pending.pop() {
        steps += 1;
        if steps > MAX_REACHABILITY_STEPS {
            return Err(refuse("function reachability walk exceeds step budget"));
        }
        let Some(leaf) = resolve_leaf(ctx.dispatch_root, ctx.pos_local, v, 0) else {
            return Err(refuse_owned(format!(
                "instruction pointer target {v} does not resolve to any dispatch leaf"
            )));
        };
        let key: u64 = leaf_ident(leaf);
        if visited.contains_key(&key) {
            continue;
        }
        if visited.len() >= MAX_FUNCTION_BLOCKS {
            return Err(refuse("function block set exceeds recovery budget"));
        }
        visited.insert(key, leaf);
        order.push(key);
        let (transfer, _plan): (Transfer<'_>, LeafPlan) =
            terminal_transfer(leaf, ctx.pos_local, ctx.return_local)?;
        match transfer {
            Transfer::Return => {}
            Transfer::Goto(n) => pending.push(n),
            Transfer::Branch {
                taken, not_taken, ..
            } => {
                pending.push(taken);
                pending.push(not_taken);
            }
        }
    }

    let entry_leaf: &Block = resolve_leaf(ctx.dispatch_root, ctx.pos_local, entry, 0)
        .ok_or_else(|| refuse("function entry does not resolve to any dispatch leaf"))?;
    let entry_key: u64 = leaf_ident(entry_leaf);
    let mut node_of: BTreeMap<u64, u32> = BTreeMap::new();
    node_of.insert(entry_key, 0);
    let mut next_node: u32 = 1;
    for &key in &order {
        if key != entry_key {
            node_of.insert(key, next_node);
            next_node += 1;
        }
    }

    let mut nodes: Vec<CfgNode> = Vec::with_capacity(order.len());
    let mut cond_of_atom: Vec<String> = Vec::new();
    let mut leaf_of_node: Vec<&Block> = Vec::with_capacity(order.len());
    let mut plan_of_node: Vec<LeafPlan> = Vec::new();
    let mut captures: BTreeMap<u64, String> = BTreeMap::new();
    for _ in 0..order.len() {
        nodes.push(CfgNode {
            term: Terminator::Return,
            pure: true,
        });
        leaf_of_node.push(entry_leaf);
        plan_of_node.push(LeafPlan {
            pos_terminal_span: Span { start: 0, end: 0 },
            pos_chain_span: None,
            return_span: None,
            numeric_chain_spans: Vec::new(),
        });
    }
    for &key in &order {
        let leaf: &Block = visited[&key];
        let node_id: u32 = node_of[&key];
        leaf_of_node[node_id as usize] = leaf;
        let (transfer, plan): (Transfer<'_>, LeafPlan) =
            terminal_transfer(leaf, ctx.pos_local, ctx.return_local)?;
        let term: Terminator = match transfer {
            Transfer::Return => Terminator::Return,
            Transfer::Goto(n) => {
                let target_leaf: &Block = resolve_leaf(ctx.dispatch_root, ctx.pos_local, n, 0)
                    .ok_or_else(|| refuse("goto target does not resolve to any dispatch leaf"))?;
                let target_key: u64 = leaf_ident(target_leaf);
                Terminator::Goto(*node_of.get(&target_key).ok_or_else(|| {
                    refuse("goto target leaf is unreachable from the function entry")
                })?)
            }
            Transfer::Branch {
                cond,
                cond_capture_span,
                taken,
                not_taken,
            } => {
                let taken_leaf: &Block = resolve_leaf(ctx.dispatch_root, ctx.pos_local, taken, 0)
                    .ok_or_else(|| {
                    refuse("branch taken-target does not resolve to any dispatch leaf")
                })?;
                let not_taken_leaf: &Block =
                    resolve_leaf(ctx.dispatch_root, ctx.pos_local, not_taken, 0).ok_or_else(
                        || refuse("branch not-taken-target does not resolve to any dispatch leaf"),
                    )?;
                let taken_node: u32 = *node_of.get(&leaf_ident(taken_leaf)).ok_or_else(|| {
                    refuse("branch taken-target leaf is unreachable from the function entry")
                })?;
                let not_taken_node: u32 =
                    *node_of.get(&leaf_ident(not_taken_leaf)).ok_or_else(|| {
                        refuse(
                            "branch not-taken-target leaf is unreachable from the function entry",
                        )
                    })?;
                let atom: u32 = cond_of_atom.len() as u32;
                match cond_capture_span {
                    Some(def_span) => {
                        let name: String = format!("__vc{}", def_span.start);
                        captures.insert(
                            span_key(def_span),
                            format!(
                                "local {name} = {};",
                                render_expr_span_with_subst(cond.span, ctx.src, subst)
                            ),
                        );
                        cond_of_atom.push(name);
                    }
                    None => {
                        cond_of_atom.push(render_expr_span_with_subst(cond.span, ctx.src, subst));
                    }
                }
                Terminator::Branch {
                    atom,
                    taken: taken_node,
                    not_taken: not_taken_node,
                }
            }
        };
        nodes[node_id as usize].term = term;
        plan_of_node[node_id as usize] = plan;
    }

    for (call_expr, creator, entry_arg, upvals_arg) in &ctx.all_creation_calls {
        let call_key: u64 = span_key(call_expr.span);
        if subst.contains_key(&call_key) {
            continue;
        }
        let within_this_function: bool = order.iter().any(|&leaf_key: &u64| {
            let leaf: &Block = visited[&leaf_key];
            let mut exprs: Vec<&Expr> = Vec::new();
            walk_exprs(leaf, &mut exprs);
            exprs.iter().any(|e: &&Expr| e.span == call_expr.span)
        });
        if !within_this_function {
            continue;
        }
        let _ = creator;
        let non_empty_upvals: bool =
            matches!(&upvals_arg.kind, ExprKind::Table(fields) if !fields.is_empty());
        if non_empty_upvals {
            subst.insert(
                call_key,
                "(function(...) error(\"prometheus-vmify: closures that capture an upvalue are not recovered by this pass\") end)".to_owned(),
            );
            continue;
        }
        let Some(nested_entry) = number_of(entry_arg) else {
            subst.insert(
                call_key,
                "(function(...) error(\"prometheus-vmify: closure entry point is not a static literal\") end)".to_owned(),
            );
            continue;
        };
        let recovered: RecoveredFunction =
            recover_function(ctx, nested_entry, depth + 1, subst, stats)?;
        subst.insert(call_key, recovered.text);
    }

    let terms: Vec<Terminator> = nodes.iter().map(|n: &CfgNode| n.term.clone()).collect();
    let cfg: Cfg = Cfg::new(0, nodes).map_err(|e: disrobe_cfg::CfgError| {
        refuse_owned(format!(
            "recovered control-flow graph rejected by the structurer: {e:?}"
        ))
    })?;
    let budget: CnsBudget = CnsBudget::tight_for(&cfg);
    let outcome: Option<CnsOutcome> = structure_with_cns(&cfg, budget);

    let mut used_locals: BTreeSet<LocalId> = BTreeSet::new();
    for leaf in &leaf_of_node {
        collect_locals_used(leaf, &mut used_locals);
    }
    used_locals.remove(&ctx.args_local);

    let args_text: &str =
        local_display_span(ctx.dispatch_root, ctx.args_local, ctx.src).unwrap_or("__args");
    let mut prelude: String = String::new();
    prelude.push_str("local ");
    prelude.push_str(args_text);
    prelude.push_str(" = { ... };\n");

    let mut register_names: Vec<&str> = Vec::new();
    for id in &used_locals {
        if ctx.container_scope.contains(id) {
            if let Some(name) = local_display_span(ctx.dispatch_root, *id, ctx.src) {
                register_names.push(name);
            }
        } else if let Some(arg_span) = ctx.upvalue_bindings.get(id) {
            let name: &str = local_display_span(ctx.dispatch_root, *id, ctx.src)
                .ok_or_else(|| refuse("an upvalue local has no textual occurrence to name it"))?;
            prelude.push_str(&format!(
                "local {name} = {};\n",
                render_expr_span_with_subst(*arg_span, ctx.src, subst)
            ));
        } else {
            return Err(refuse_owned(format!(
                "local {id} is neither a container-scope register nor a recognized wrapper upvalue"
            )));
        }
    }
    if !register_names.is_empty() {
        prelude.push_str("local ");
        prelude.push_str(&register_names.join(", "));
        prelude.push_str(";\n");
    }

    let (body_text, fully_structured, recovered_leaves): (String, bool, usize) = match outcome {
        Some(outcome) if outcome.result.is_complete() => {
            let mut renderer: RegionRenderer<'_, '_> = RegionRenderer {
                ctx,
                leaf_of_node: &leaf_of_node,
                terms: &terms,
                plan_of_node: &plan_of_node,
                captures: &captures,
                cond_of_atom: &cond_of_atom,
                result: &outcome.result,
                subst,
                ok: true,
            };
            let root: RegionId = outcome
                .result
                .root
                .ok_or_else(|| refuse("structuring produced no root region"))?;
            let text: String = renderer.render(root);
            if renderer.ok {
                (text, true, order.len())
            } else {
                (
                    render_dispatch_fallback(
                        ctx,
                        &leaf_of_node,
                        &terms,
                        &plan_of_node,
                        &captures,
                        &cond_of_atom,
                        subst,
                    ),
                    false,
                    0,
                )
            }
        }
        _ => (
            render_dispatch_fallback(
                ctx,
                &leaf_of_node,
                &terms,
                &plan_of_node,
                &captures,
                &cond_of_atom,
                subst,
            ),
            false,
            0,
        ),
    };

    let mut text: String = String::new();
    text.push_str("function(...)\n");
    text.push_str(&prelude);
    text.push_str(&body_text);
    text.push_str("\nend");

    stats.leaves_recovered += recovered_leaves;
    stats.reached.extend(order.iter().copied());
    if fully_structured {
        stats.functions_fully_structured += 1;
    }

    Ok(RecoveredFunction { text })
}

fn local_display_span<'a>(scope_root: &Block, id: LocalId, src: &'a str) -> Option<&'a str> {
    let mut exprs: Vec<&Expr> = Vec::new();
    walk_exprs(scope_root, &mut exprs);
    for e in exprs {
        if let ExprKind::Var(Var::Local(x)) = &e.kind
            && *x == id
        {
            return Some(e.span.text(src));
        }
    }
    None
}

fn render_expr_span_with_subst(span: Span, src: &str, subst: &BTreeMap<u64, String>) -> String {
    if let Some(replacement) = subst.get(&span_key(span)) {
        return replacement.clone();
    }
    let mut hits: Vec<(u64, u64)> = Vec::new();
    for &key in subst.keys() {
        let start: u32 = (key >> 32) as u32;
        let end: u32 = key as u32;
        if start >= span.start && end <= span.end {
            hits.push((u64::from(start), u64::from(end)));
        }
    }
    if hits.is_empty() {
        return span.text(src).to_owned();
    }
    hits.sort_unstable();
    let mut out: String = String::new();
    let mut cursor: u32 = span.start;
    for (start, end) in hits {
        let start: u32 = start as u32;
        let end: u32 = end as u32;
        if start < cursor {
            continue;
        }
        out.push_str(&src[cursor as usize..start as usize]);
        if let Some(text) = subst.get(&((u64::from(start) << 32) | u64::from(end))) {
            out.push_str(text);
        }
        cursor = end;
    }
    out.push_str(&src[cursor as usize..span.end as usize]);
    out
}

fn render_leaf_body(
    leaf: &Block,
    pos_local: LocalId,
    return_local: LocalId,
    plan: &LeafPlan,
    captures: &BTreeMap<u64, String>,
    src: &str,
    subst: &BTreeMap<u64, String>,
) -> String {
    let mut out: String = String::new();
    for stat in &leaf.stats {
        if let Some(capture_text) = captures.get(&span_key(stat.span)) {
            out.push_str(capture_text);
            out.push('\n');
            continue;
        }
        if plan.numeric_chain_spans.contains(&stat.span) {
            continue;
        }
        let mut strip_here: Vec<LocalId> = Vec::new();
        if stat.span == plan.pos_terminal_span || Some(stat.span) == plan.pos_chain_span {
            strip_here.push(pos_local);
        }
        if Some(stat.span) == plan.return_span {
            strip_here.push(return_local);
        }
        if let StatKind::Assign { targets, values } = &stat.kind {
            let keep: Vec<(&AssignTarget, &Expr)> = targets
                .iter()
                .zip(values.iter())
                .filter(|(t, _): &(&AssignTarget, &Expr)| {
                    !matches!(t, AssignTarget::Var(Var::Local(id), _) if strip_here.contains(id))
                })
                .collect();
            if keep.is_empty() {
                continue;
            }
            if keep.len() == targets.len() {
                out.push_str(&render_expr_span_with_subst(stat.span, src, subst));
                out.push_str(";\n");
                continue;
            }
            let lhs: Vec<String> = keep
                .iter()
                .map(|(t, _): &(&AssignTarget, &Expr)| match t {
                    AssignTarget::Var(_, span) => render_expr_span_with_subst(*span, src, subst),
                    AssignTarget::Index(_, _, span) => {
                        render_expr_span_with_subst(*span, src, subst)
                    }
                })
                .collect();
            let rhs: Vec<String> = keep
                .iter()
                .map(|(_, v): &(&AssignTarget, &Expr)| {
                    render_expr_span_with_subst(v.span, src, subst)
                })
                .collect();
            out.push_str(&lhs.join(", "));
            out.push_str(" = ");
            out.push_str(&rhs.join(", "));
            out.push_str(";\n");
            continue;
        }
        out.push_str(&render_expr_span_with_subst(stat.span, src, subst));
        out.push_str(";\n");
    }
    out
}

fn render_return(ctx: &Ctx<'_>, leaf: &Block, subst: &BTreeMap<u64, String>) -> String {
    match last_target_value(&leaf.stats, ctx.return_local) {
        Some(expr) => format!(
            "return (unpack or table.unpack)({})",
            render_expr_span_with_subst(expr.span, ctx.src, subst)
        ),
        None => "return".to_owned(),
    }
}

fn render_cond(
    cond_of_atom: &[String],
    conds: &disrobe_cfg::CondPool,
    id: disrobe_cfg::CondId,
) -> Option<String> {
    match conds.nodes().get(id as usize)? {
        disrobe_cfg::Cond::Leaf(atom) => cond_of_atom.get(*atom as usize).cloned(),
        disrobe_cfg::Cond::NotLeaf(atom) => {
            let text: &String = cond_of_atom.get(*atom as usize)?;
            Some(format!("not ({text})"))
        }
        disrobe_cfg::Cond::And(l, r) => {
            let lt: String = render_cond(cond_of_atom, conds, *l)?;
            let rt: String = render_cond(cond_of_atom, conds, *r)?;
            Some(format!("({lt}) and ({rt})"))
        }
        disrobe_cfg::Cond::Or(l, r) => {
            let lt: String = render_cond(cond_of_atom, conds, *l)?;
            let rt: String = render_cond(cond_of_atom, conds, *r)?;
            Some(format!("({lt}) or ({rt})"))
        }
    }
}

fn render_leaf_terminal(
    ctx: &Ctx<'_>,
    leaf: &Block,
    term: &Terminator,
    subst: &BTreeMap<u64, String>,
) -> String {
    match term {
        Terminator::Return | Terminator::Unreachable => render_return(ctx, leaf, subst),
        Terminator::Goto(_) => String::new(),
        Terminator::Branch { .. } => String::new(),
        Terminator::Switch { .. } => {
            "error(\"prometheus-vmify: switch terminator not recovered\")".to_owned()
        }
    }
}

struct RegionRenderer<'a, 'b> {
    ctx: &'b Ctx<'a>,
    leaf_of_node: &'b [&'a Block],
    terms: &'b [Terminator],
    plan_of_node: &'b [LeafPlan],
    captures: &'b BTreeMap<u64, String>,
    cond_of_atom: &'b [String],
    result: &'b disrobe_cfg::StructureResult,
    subst: &'b BTreeMap<u64, String>,
    ok: bool,
}

impl RegionRenderer<'_, '_> {
    fn render(&mut self, id: RegionId) -> String {
        if !self.ok {
            return String::new();
        }
        let region: Region = self.result.regions[id as usize].clone();
        match region.kind {
            RegionKind::Block if region.children.is_empty() => {
                let node: usize = region.entry as usize;
                let (Some(leaf), Some(plan)) = (
                    self.leaf_of_node.get(node).copied(),
                    self.plan_of_node.get(node),
                ) else {
                    self.ok = false;
                    return String::new();
                };
                let mut out: String = render_leaf_body(
                    leaf,
                    self.ctx.pos_local,
                    self.ctx.return_local,
                    plan,
                    self.captures,
                    self.ctx.src,
                    self.subst,
                );
                if let Some(term) = self.terms.get(node) {
                    out.push_str(&render_leaf_terminal(self.ctx, leaf, term, self.subst));
                }
                out
            }
            RegionKind::Block => {
                let mut out: String = String::new();
                for child in &region.children {
                    out.push_str(&self.render(*child));
                }
                out
            }
            RegionKind::IfThen => {
                let (Some(head), Some(cond_id), Some(&arm)) =
                    (region.head, region.cond, region.children.first())
                else {
                    self.ok = false;
                    return String::new();
                };
                let mut out: String = self.render(head);
                let Some(guard) = render_cond(self.cond_of_atom, &self.result.conds, cond_id)
                else {
                    self.ok = false;
                    return String::new();
                };
                let body: String = self.render(arm);
                out.push_str(&format!("if {guard} then\n{body}\nend;\n"));
                out
            }
            RegionKind::IfThenElse => {
                let (Some(head), Some(cond_id)) = (region.head, region.cond) else {
                    self.ok = false;
                    return String::new();
                };
                let [taken_id, not_taken_id]: [RegionId; 2] = match region.children.as_slice() {
                    [a, b] => [*a, *b],
                    _ => {
                        self.ok = false;
                        return String::new();
                    }
                };
                let mut out: String = self.render(head);
                let fused: bool = matches!(
                    self.result.conds.nodes().get(cond_id as usize),
                    Some(disrobe_cfg::Cond::And(_, _) | disrobe_cfg::Cond::Or(_, _))
                );
                let (guard, then_id, else_id): (String, RegionId, RegionId) = if fused {
                    let Some(g) = render_cond(self.cond_of_atom, &self.result.conds, cond_id)
                    else {
                        self.ok = false;
                        return String::new();
                    };
                    (g, taken_id, not_taken_id)
                } else {
                    let negated: Option<String> =
                        match self.result.conds.nodes().get(cond_id as usize) {
                            Some(disrobe_cfg::Cond::Leaf(atom)) => self
                                .cond_of_atom
                                .get(*atom as usize)
                                .map(|t: &String| format!("not ({t})")),
                            Some(disrobe_cfg::Cond::NotLeaf(atom)) => {
                                self.cond_of_atom.get(*atom as usize).cloned()
                            }
                            _ => None,
                        };
                    let Some(g) = negated else {
                        self.ok = false;
                        return String::new();
                    };
                    (g, not_taken_id, taken_id)
                };
                let then_body: String = self.render(then_id);
                let else_body: String = self.render(else_id);
                out.push_str(&format!(
                    "if {guard} then\n{then_body}\nelse\n{else_body}\nend;\n"
                ));
                out
            }
            RegionKind::While
            | RegionKind::DoWhile
            | RegionKind::NaturalLoop
            | RegionKind::SelfLoop
            | RegionKind::Switch
            | RegionKind::Proper
            | RegionKind::Irreducible => {
                self.ok = false;
                String::new()
            }
        }
    }
}

fn render_dispatch_fallback(
    ctx: &Ctx<'_>,
    leaf_of_node: &[&Block],
    terms: &[Terminator],
    plan_of_node: &[LeafPlan],
    captures: &BTreeMap<u64, String>,
    cond_of_atom: &[String],
    subst: &BTreeMap<u64, String>,
) -> String {
    let mut out: String = String::new();
    out.push_str("local __pc = 0;\n");
    out.push_str("while true do\n");
    for (node_id, leaf) in leaf_of_node.iter().enumerate() {
        out.push_str(&format!("if __pc == {node_id} then\n"));
        let plan: &LeafPlan = &plan_of_node[node_id];
        out.push_str(&render_leaf_body(
            leaf,
            ctx.pos_local,
            ctx.return_local,
            plan,
            captures,
            ctx.src,
            subst,
        ));
        match terms.get(node_id) {
            Some(Terminator::Return | Terminator::Unreachable) | None => {
                out.push_str(&render_return(ctx, leaf, subst));
                out.push('\n');
            }
            Some(Terminator::Goto(target)) => {
                out.push_str(&format!("__pc = {target};\n"));
            }
            Some(Terminator::Branch {
                atom,
                taken,
                not_taken,
            }) => {
                let cond: String = cond_of_atom
                    .get(*atom as usize)
                    .cloned()
                    .unwrap_or_else(|| "false".to_owned());
                out.push_str(&format!(
                    "if {cond} then __pc = {taken} else __pc = {not_taken} end;\n"
                ));
            }
            Some(Terminator::Switch { .. }) => {
                out.push_str("error(\"prometheus-vmify: switch terminator not recovered\");\n");
            }
        }
        out.push_str("end;\n");
    }
    out.push_str("end;\n");
    out
}

pub fn recover(text: &str) -> Result<Option<VmifyRecovery>> {
    dbg_section("lua.prometheus_vmify.recover");
    if text.len() > crate::obfuscator::prometheus_vm_ast::MAX_SOURCE_BYTES {
        return Err(refuse("source exceeds the Vmify recovery byte budget"));
    }
    let mut parser: Parser<'_> = Parser::new(text)?;
    let chunk: Block = parser.parse_chunk()?;

    let mut all_exprs: Vec<&Expr> = Vec::new();
    walk_exprs(&chunk, &mut all_exprs);
    let function_exprs: Vec<&Expr> = all_exprs
        .iter()
        .copied()
        .filter(|e: &&Expr| matches!(e.kind, ExprKind::Function { .. }))
        .collect();

    let mut containers: Vec<ContainerShape<'_>> = function_exprs
        .iter()
        .filter_map(|e: &&Expr| as_container_shape(e))
        .collect();
    let container: ContainerShape<'_> = match containers.len() {
        0 => return Ok(None),
        1 => containers.remove(0),
        _ => {
            return Err(refuse(
                "more than one Vmify container-function shape found in one chunk",
            ));
        }
    };

    let container_local: LocalId = find_local_binding(&chunk, container.whole_span)
        .ok_or_else(|| refuse("the Vmify container function value is not bound to any local"))?;

    let mut creator_locals: BTreeSet<LocalId> = BTreeSet::new();
    for f in &function_exprs {
        if confirms_creator_shape(f, container_local)
            && let Some(id) = find_local_binding(&chunk, f.span)
        {
            creator_locals.insert(id);
        }
    }
    if creator_locals.is_empty() {
        return Err(refuse(
            "no closure-creator helper functions found alongside the Vmify container",
        ));
    }

    let all_creation_calls: Vec<(&Expr, LocalId, &Expr, &Expr)> =
        collect_creation_calls(&all_exprs, &creator_locals);
    dbg_kv("prometheus_vmify.creator_locals", || {
        format!("{creator_locals:?}")
    });
    dbg_kv("prometheus_vmify.creation_calls", || {
        all_creation_calls.len().to_string()
    });
    let return_local: LocalId = find_return_local(container.dispatch_root, container.pos_local)?;
    dbg_kv("prometheus_vmify.pos_local", || {
        container.pos_local.to_string()
    });
    dbg_kv("prometheus_vmify.args_local", || {
        container.args_local.to_string()
    });
    dbg_kv("prometheus_vmify.return_local", || return_local.to_string());
    let container_scope: BTreeSet<LocalId> = container_scope_locals(&container);
    let wrapper_span: Span = find_enclosing_function_span(&chunk, container.whole_span)
        .ok_or_else(|| {
            refuse("could not locate the wrapper closure that binds the Vmify container")
        })?;
    let upvalue_bindings: BTreeMap<LocalId, Span> = wrapper_upvalue_bindings(&chunk, wrapper_span)
        .ok_or_else(|| refuse("could not resolve the wrapper closure's own call-site arguments"))?;

    let ctx: Ctx<'_> = Ctx {
        src: text,
        pos_local: container.pos_local,
        args_local: container.args_local,
        return_local,
        dispatch_root: container.dispatch_root,
        container_span: container.whole_span,
        container_scope,
        upvalue_bindings,
        all_creation_calls,
    };

    let top_entry: f64 = find_top_level_entry(&ctx)?;
    let mut subst: BTreeMap<u64, String> = BTreeMap::new();
    let mut stats: GlobalStats = GlobalStats::default();
    let recovered: RecoveredFunction =
        recover_function(&ctx, top_entry, 0, &mut subst, &mut stats)?;

    let mut all_leaves: Vec<&Block> = Vec::new();
    collect_all_leaves(
        container.dispatch_root,
        container.pos_local,
        &mut all_leaves,
        0,
    )?;
    let real_leaf_count: usize = all_leaves
        .iter()
        .filter(|leaf: &&&Block| !leaf.stats.is_empty())
        .count();
    let reached_real_leaf_count: usize = all_leaves
        .iter()
        .filter(|leaf: &&&Block| {
            !leaf.stats.is_empty() && stats.reached.contains(&leaf_ident(leaf))
        })
        .count();
    let handlers_total: usize = reached_real_leaf_count;
    let unreached_structural_leaves: usize =
        real_leaf_count.saturating_sub(reached_real_leaf_count);

    let mut targeted: BTreeSet<u64> = BTreeSet::new();
    let mut unclassified_leaves: usize = 0;
    for leaf in &all_leaves {
        let Ok((transfer, _plan)) = terminal_transfer(leaf, ctx.pos_local, ctx.return_local) else {
            if !leaf.stats.is_empty() {
                unclassified_leaves += 1;
            }
            continue;
        };
        let targets: Vec<f64> = match transfer {
            Transfer::Return => Vec::new(),
            Transfer::Goto(n) => vec![n],
            Transfer::Branch {
                taken, not_taken, ..
            } => vec![taken, not_taken],
        };
        for target in targets {
            if let Some(target_leaf) =
                resolve_leaf(container.dispatch_root, container.pos_local, target, 0)
            {
                targeted.insert(leaf_ident(target_leaf));
            }
        }
    }
    dbg_kv("prometheus_vmify.unclassified_leaves", || {
        unclassified_leaves.to_string()
    });
    if let Some(missed) = all_leaves.iter().find(|leaf: &&&Block| {
        !leaf.stats.is_empty()
            && targeted.contains(&leaf_ident(leaf))
            && !stats.reached.contains(&leaf_ident(leaf))
    }) {
        return Err(refuse_owned(format!(
            "a dispatch-tree leaf at byte {} is a real jump target of another leaf in this container but was never reached from any discovered function entry; at least one entry point into this shared dispatch tree was not found, the common signature of a second Vmify layer sharing the outer VM's leaf pool",
            missed.stats.first().map_or(0, |s: &Stat| s.span.start)
        )));
    }
    if unclassified_leaves > 0 && unreached_structural_leaves > 0 {
        return Err(refuse_owned(format!(
            "{unclassified_leaves} dispatch-tree leaf(ves) could not be classified for their jump targets (they carry a nested closure's own local declarations) while {unreached_structural_leaves} leaf(ves) remain unreached; whether any unreached leaf is a real jump target of an unclassified leaf cannot be proven, so full recovery is refused rather than assumed"
        )));
    }
    for (_call_expr, _creator, entry_arg, upvals_arg) in &ctx.all_creation_calls {
        let non_empty_upvals: bool =
            matches!(&upvals_arg.kind, ExprKind::Table(fields) if !fields.is_empty());
        if non_empty_upvals {
            continue;
        }
        let Some(entry) = number_of(entry_arg) else {
            continue;
        };
        let Some(entry_leaf) = resolve_leaf(container.dispatch_root, container.pos_local, entry, 0)
        else {
            continue;
        };
        if !entry_leaf.stats.is_empty() && !stats.reached.contains(&leaf_ident(entry_leaf)) {
            return Err(refuse_owned(format!(
                "a discovered closure-creation call targets instruction pointer {entry}, which resolves to a real dispatch leaf, but that leaf was never visited by any recovery pass despite carrying no captured upvalue and a static entry, the shape this pass would ordinarily recurse into"
            )));
        }
    }

    let body: &str = recovered
        .text
        .strip_prefix("function(...)\n")
        .and_then(|s: &str| s.strip_suffix("\nend"))
        .unwrap_or(&recovered.text);

    let fully_recovered: bool = stats.functions_fully_structured == stats.functions_attempted
        && stats.leaves_recovered >= handlers_total;
    dbg_kv("prometheus_vmify.handlers", || {
        format!(
            "{}/{}",
            stats.leaves_recovered.min(handlers_total),
            handlers_total
        )
    });
    dbg_kv("prometheus_vmify.functions", || {
        format!(
            "{}/{}",
            stats.functions_fully_structured, stats.functions_attempted
        )
    });
    dbg_kv("prometheus_vmify.unreached_structural_leaves", || {
        unreached_structural_leaves.to_string()
    });
    dbg_kv("prometheus_vmify.fully_recovered", || {
        fully_recovered.to_string()
    });

    Ok(Some(VmifyRecovery {
        source: body.to_owned(),
        handlers_recovered: stats.leaves_recovered.min(handlers_total),
        handlers_total,
        functions_recovered: stats.functions_fully_structured,
        functions_total: stats.functions_attempted,
        unreached_structural_leaves,
        fully_recovered,
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn non_vmify_source_yields_no_recovery() {
        let out: Option<VmifyRecovery> = recover("local x = 1\nprint(x)\n").expect("parse");
        assert!(out.is_none());
    }

    #[test]
    fn recovers_real_loop_free_prometheus_vmify_sample_with_full_coverage() {
        let src: &str =
            include_str!("../../../../corpus/lua/prometheus/vmify_simple/obfuscated.lua");
        let out: VmifyRecovery = recover(src)
            .expect("recover")
            .expect("must detect as Vmify");
        assert_eq!(
            out.functions_total, 2,
            "the sample defines exactly two functions"
        );
        assert_eq!(
            out.functions_recovered, 2,
            "both functions must reach clean if/else structuring"
        );
        assert!(out.handlers_recovered > 0 && out.handlers_recovered == out.handlers_total);
        assert!(
            out.source.contains("if"),
            "the recovered source must contain real structured control flow"
        );
        assert!(
            !out.source.contains("__pc"),
            "a fully structured recovery must not fall back to the dispatch loop"
        );
    }

    #[test]
    fn a_real_double_vmify_sample_refuses_rather_than_mis_lift() {
        let src: &str =
            include_str!("../../../../corpus/lua/prometheus/vmify_nested/obfuscated.lua");
        let err: Error = recover(src).expect_err(
            "the second Vmify pass shares its dispatch tree with leaves the first pass's bootstrap \
             calls into, so most of the tree is only reachable through an entry point this single \
             pass never discovers; it must name that reason rather than report full recovery",
        );
        let message: String = err.to_string();
        assert!(
            message.contains("never reached from any discovered function entry"),
            "the refusal must name the real cause, got: {message}"
        );
    }

    #[test]
    fn recovers_real_loop_bearing_prometheus_vmify_sample_via_dispatch_fallback() {
        let src: &str = include_str!("../../../../corpus/lua/prometheus/vmify/obfuscated.lua");
        let out: VmifyRecovery = recover(src)
            .expect("recover")
            .expect("must detect as Vmify");
        assert!(
            out.handlers_recovered > 0,
            "at least the loop-free function must fully structure"
        );
        assert!(
            out.source.contains("__pc"),
            "the loop-bearing function must fall back to the dispatch-loop form, not drop the loop"
        );
    }
}
