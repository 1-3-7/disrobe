use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

use disrobe_cfg::{
    Cfg, CfgNode, CnsBudget, CnsOutcome, Region, RegionId, RegionKind, Terminator,
    structure_with_cns,
};

use crate::debug::{dbg_kv, dbg_section};
use crate::error::{Error, Result};
use crate::obfuscator::prometheus_vm_ast::{
    AssignTarget, BinOp, Block, Expr, ExprKind, LocalId, Parser, Span, Stat, StatKind, TableField,
    UnOp, Var,
};
use crate::obfuscator::string_decode::{decode_base85_variant, discover_base85_alphabets};

const MAX_DISPATCH_DEPTH: u32 = 96;
const MAX_FUNCTION_BLOCKS: usize = 1 << 14;
const MAX_FUNCTIONS: usize = 1 << 10;
const MAX_REACHABILITY_STEPS: usize = 1 << 18;
const MAX_RECOVERY_DEPTH: usize = 6;
const MAX_CONSTANT_POOL_RESOLVERS: usize = 8;
const MAX_LOOP_NESTING: usize = 32;
const MAX_REGION_TREE_STEPS: usize = 1 << 16;
const MAX_STATIC_NUMBER_DEPTH: usize = 32;
const MAX_STATIC_NUMBER_FUEL: usize = 1 << 12;
const MAX_BOX_STATE_BINDINGS: usize = 1 << 18;
const MAX_BOX_STATEMENT_USES: usize = 1 << 12;
const MAX_ANTITAMPER_PROOF_STEPS: usize = 1 << 16;
const MAX_ANTITAMPER_STATE_BINDINGS: usize = 1 << 12;
const MAX_ANTITAMPER_EXPRESSION_DEPTH: usize = 32;
const CAPTURED_VARIABLE_PREFIX: &str = "__vu";

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
    static_number_value(expr)
}

fn as_pos_threshold(
    cond: &Expr,
    pos_local: LocalId,
    numbers: &StaticNumberEvaluator,
) -> Option<(ThresholdOp, f64)> {
    let ExprKind::Binary(op, lhs, rhs) = &cond.kind else {
        return None;
    };
    let lhs_is_pos: bool = is_bare_local(lhs, pos_local);
    let rhs_is_pos: bool = is_bare_local(rhs, pos_local);
    match (op, lhs_is_pos, rhs_is_pos) {
        (BinOp::Lt, true, false) => numbers.evaluate(rhs).map(|n: f64| (ThresholdOp::Lt, n)),
        (BinOp::Gt, false, true) => numbers.evaluate(lhs).map(|n: f64| (ThresholdOp::Lt, n)),
        (BinOp::Gt, true, false) => numbers.evaluate(rhs).map(|n: f64| (ThresholdOp::Gt, n)),
        (BinOp::Lt, false, true) => numbers.evaluate(lhs).map(|n: f64| (ThresholdOp::Gt, n)),
        _ => None,
    }
}

fn eval_threshold(op: ThresholdOp, bound: f64, candidate: f64) -> bool {
    match op {
        ThresholdOp::Lt => candidate < bound,
        ThresholdOp::Gt => candidate > bound,
    }
}

fn is_dispatch_if(
    arms: &[(Expr, Block)],
    else_body: Option<&Block>,
    pos_local: LocalId,
    numbers: &StaticNumberEvaluator,
) -> bool {
    !arms.is_empty()
        && else_body.is_some()
        && arms
            .iter()
            .all(|(cond, _): &(Expr, Block)| as_pos_threshold(cond, pos_local, numbers).is_some())
}

fn leaf_ident(b: &Block) -> u64 {
    std::ptr::from_ref::<Block>(b).addr() as u64
}

fn resolve_leaf<'a>(
    block: &'a Block,
    pos_local: LocalId,
    candidate: f64,
    depth: u32,
    numbers: &StaticNumberEvaluator,
) -> Option<&'a Block> {
    if depth > MAX_DISPATCH_DEPTH {
        return None;
    }
    if let [stat] = block.stats.as_slice()
        && let StatKind::If { arms, else_body } = &stat.kind
        && is_dispatch_if(arms, else_body.as_ref(), pos_local, numbers)
    {
        for (cond, body) in arms {
            let (op, bound): (ThresholdOp, f64) = as_pos_threshold(cond, pos_local, numbers)?;
            if eval_threshold(op, bound, candidate) {
                return resolve_leaf(body, pos_local, candidate, depth + 1, numbers);
            }
        }
        let else_body: &Block = else_body.as_ref()?;
        return resolve_leaf(else_body, pos_local, candidate, depth + 1, numbers);
    }
    Some(block)
}

fn collect_all_leaves<'a>(
    block: &'a Block,
    pos_local: LocalId,
    out: &mut Vec<&'a Block>,
    depth: u32,
    numbers: &StaticNumberEvaluator,
) -> Result<()> {
    if depth > MAX_DISPATCH_DEPTH {
        return Err(refuse("dispatch tree exceeds depth budget"));
    }
    if let [stat] = block.stats.as_slice()
        && let StatKind::If { arms, else_body } = &stat.kind
        && is_dispatch_if(arms, else_body.as_ref(), pos_local, numbers)
    {
        for (_, body) in arms {
            collect_all_leaves(body, pos_local, out, depth + 1, numbers)?;
        }
        if let Some(else_body) = else_body {
            collect_all_leaves(else_body, pos_local, out, depth + 1, numbers)?;
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

fn collect_block_bound_locals(block: &Block, out: &mut BTreeSet<LocalId>) {
    for stat in &block.stats {
        match &stat.kind {
            StatKind::Local { targets, .. } => out.extend(targets.iter().copied()),
            StatKind::Do(body) | StatKind::While { body, .. } | StatKind::Repeat { body, .. } => {
                collect_block_bound_locals(body, out);
            }
            StatKind::If { arms, else_body } => {
                for (_, body) in arms {
                    collect_block_bound_locals(body, out);
                }
                if let Some(body) = else_body {
                    collect_block_bound_locals(body, out);
                }
            }
            StatKind::NumericFor { var, body, .. } => {
                out.insert(*var);
                collect_block_bound_locals(body, out);
            }
            StatKind::GenericFor { vars, body, .. } => {
                out.extend(vars.iter().copied());
                collect_block_bound_locals(body, out);
            }
            StatKind::Assign { .. }
            | StatKind::ExprStat(_)
            | StatKind::Return(_)
            | StatKind::Break => {}
        }
    }
}

fn collect_function_bound_locals(params: &[LocalId], body: &Block, out: &mut BTreeSet<LocalId>) {
    out.extend(params.iter().copied());
    collect_block_bound_locals(body, out);
    let mut nested: Vec<&Expr> = Vec::new();
    walk_exprs(body, &mut nested);
    for expr in nested {
        if let ExprKind::Function { params, body, .. } = &expr.kind {
            out.extend(params.iter().copied());
            collect_block_bound_locals(body, out);
        }
    }
}

fn collect_expr_locals(expr: &Expr, subst: &BTreeMap<u64, String>, out: &mut BTreeSet<LocalId>) {
    if subst.contains_key(&span_key(expr.span)) {
        return;
    }
    match &expr.kind {
        ExprKind::Var(Var::Local(id)) => {
            out.insert(*id);
        }
        ExprKind::Index(base, key) => {
            collect_expr_locals(base, subst, out);
            collect_expr_locals(key, subst, out);
        }
        ExprKind::Call { base, args } => {
            collect_expr_locals(base, subst, out);
            for argument in args {
                collect_expr_locals(argument, subst, out);
            }
        }
        ExprKind::MethodCall { base, args, .. } => {
            collect_expr_locals(base, subst, out);
            for argument in args {
                collect_expr_locals(argument, subst, out);
            }
        }
        ExprKind::Function { params, body, .. } => {
            let mut referenced: BTreeSet<LocalId> = BTreeSet::new();
            collect_block_locals(body, subst, &mut referenced);
            let mut bound: BTreeSet<LocalId> = BTreeSet::new();
            collect_function_bound_locals(params, body, &mut bound);
            referenced.retain(|id: &LocalId| !bound.contains(id));
            out.extend(referenced);
        }
        ExprKind::Table(fields) => {
            for field in fields {
                match field {
                    TableField::Positional(value) | TableField::Named(_, value) => {
                        collect_expr_locals(value, subst, out);
                    }
                    TableField::Indexed(key, value) => {
                        collect_expr_locals(key, subst, out);
                        collect_expr_locals(value, subst, out);
                    }
                }
            }
        }
        ExprKind::Binary(_, left, right) => {
            collect_expr_locals(left, subst, out);
            collect_expr_locals(right, subst, out);
        }
        ExprKind::Unary(_, inner) | ExprKind::Paren(inner) => {
            collect_expr_locals(inner, subst, out);
        }
        ExprKind::Nil
        | ExprKind::True
        | ExprKind::False
        | ExprKind::Vararg
        | ExprKind::Number(_)
        | ExprKind::Str
        | ExprKind::Var(Var::Global(_)) => {}
    }
}

fn collect_target_locals(
    target: &AssignTarget,
    subst: &BTreeMap<u64, String>,
    out: &mut BTreeSet<LocalId>,
) {
    match target {
        AssignTarget::Var(Var::Local(id), _) => {
            out.insert(*id);
        }
        AssignTarget::Var(Var::Global(_), _) => {}
        AssignTarget::Index(base, key, span) => {
            if subst.contains_key(&span_key(*span)) {
                return;
            }
            collect_expr_locals(base, subst, out);
            collect_expr_locals(key, subst, out);
        }
    }
}

fn is_dropped_statement(stat: &Stat, subst: &BTreeMap<u64, String>) -> bool {
    subst
        .get(&span_key(stat.span))
        .is_some_and(|text: &String| text.is_empty())
}

fn collect_stat_locals(stat: &Stat, subst: &BTreeMap<u64, String>, out: &mut BTreeSet<LocalId>) {
    match &stat.kind {
        StatKind::Local { targets, values } => {
            out.extend(targets.iter().copied());
            for value in values {
                collect_expr_locals(value, subst, out);
            }
        }
        StatKind::Assign { targets, values } => {
            for target in targets {
                collect_target_locals(target, subst, out);
            }
            for value in values {
                collect_expr_locals(value, subst, out);
            }
        }
        StatKind::ExprStat(expr) => collect_expr_locals(expr, subst, out),
        StatKind::Do(block) => collect_block_locals(block, subst, out),
        StatKind::While { cond, body } | StatKind::Repeat { body, cond } => {
            collect_expr_locals(cond, subst, out);
            collect_block_locals(body, subst, out);
        }
        StatKind::If { arms, else_body } => {
            for (condition, body) in arms {
                collect_expr_locals(condition, subst, out);
                collect_block_locals(body, subst, out);
            }
            if let Some(body) = else_body {
                collect_block_locals(body, subst, out);
            }
        }
        StatKind::NumericFor {
            var,
            start,
            stop,
            step,
            body,
        } => {
            out.insert(*var);
            collect_expr_locals(start, subst, out);
            collect_expr_locals(stop, subst, out);
            if let Some(step) = step {
                collect_expr_locals(step, subst, out);
            }
            collect_block_locals(body, subst, out);
        }
        StatKind::GenericFor { vars, exprs, body } => {
            out.extend(vars.iter().copied());
            for expr in exprs {
                collect_expr_locals(expr, subst, out);
            }
            collect_block_locals(body, subst, out);
        }
        StatKind::Return(values) => {
            for value in values {
                collect_expr_locals(value, subst, out);
            }
        }
        StatKind::Break => {}
    }
}

fn collect_block_locals(block: &Block, subst: &BTreeMap<u64, String>, out: &mut BTreeSet<LocalId>) {
    for stat in &block.stats {
        collect_stat_locals(stat, subst, out);
    }
}

fn collect_rendered_locals(
    leaf: &Block,
    pos_local: LocalId,
    return_local: LocalId,
    plan: &LeafPlan,
    captures: &BTreeMap<u64, String>,
    subst: &BTreeMap<u64, String>,
    out: &mut BTreeSet<LocalId>,
) {
    for stat in &leaf.stats {
        if subst.contains_key(&span_key(stat.span)) {
            continue;
        }
        if captures.contains_key(&span_key(stat.span)) {
            if let StatKind::Assign { values, .. } = &stat.kind {
                for value in values {
                    collect_expr_locals(value, subst, out);
                }
            } else {
                collect_stat_locals(stat, subst, out);
            }
            continue;
        }
        if plan.numeric_chain_spans.contains(&stat.span) {
            continue;
        }
        let StatKind::Assign { targets, values } = &stat.kind else {
            collect_stat_locals(stat, subst, out);
            continue;
        };
        let aligned: bool = targets.len() == values.len();
        for (index, target) in targets.iter().enumerate() {
            let target_local: Option<LocalId> = match target {
                AssignTarget::Var(Var::Local(id), _) => Some(*id),
                _ => None,
            };
            let strips_pos: bool = aligned
                && (stat.span == plan.pos_terminal_span || Some(stat.span) == plan.pos_chain_span)
                && target_local == Some(pos_local);
            let strips_return: bool = aligned
                && Some(stat.span) == plan.return_span
                && target_local == Some(return_local);
            if strips_pos {
                continue;
            }
            if !strips_return {
                collect_target_locals(target, subst, out);
            }
            if let Some(value) = values.get(index) {
                collect_expr_locals(value, subst, out);
            }
        }
        for value in values.iter().skip(targets.len()) {
            collect_expr_locals(value, subst, out);
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

#[derive(Debug, Clone, Copy)]
struct BoxModel {
    heap: LocalId,
    alloc: LocalId,
    release: Option<LocalId>,
}

fn is_unit_increment(expr: &Expr, id: LocalId) -> bool {
    let ExprKind::Binary(BinOp::Add, left, right) = &unwrap_paren(expr).kind else {
        return false;
    };
    (is_bare_local(left, id) && static_number_value(right) == Some(1.0))
        || (is_bare_local(right, id) && static_number_value(left) == Some(1.0))
}

fn is_indexed_slot(expr: &Expr, table: LocalId, slot: LocalId) -> bool {
    let ExprKind::Index(base, key) = &unwrap_paren(expr).kind else {
        return false;
    };
    is_bare_local(base, table) && is_bare_local(key, slot)
}

fn is_zero_slot_test(cond: &Expr, table: LocalId, slot: LocalId) -> bool {
    let ExprKind::Binary(BinOp::Eq, left, right) = &unwrap_paren(cond).kind else {
        return false;
    };
    (is_indexed_slot(left, table, slot) && static_number_value(right) == Some(0.0))
        || (is_indexed_slot(right, table, slot) && static_number_value(left) == Some(0.0))
}

fn as_box_allocator(func_expr: &Expr) -> Option<(LocalId, LocalId)> {
    let ExprKind::Function {
        params,
        is_vararg,
        body,
    } = &func_expr.kind
    else {
        return None;
    };
    if *is_vararg || !params.is_empty() {
        return None;
    }
    let [bump, mark, tail]: &[Stat] = body.stats.as_slice() else {
        return None;
    };
    let StatKind::Assign {
        targets: bump_targets,
        values: bump_values,
    } = &bump.kind
    else {
        return None;
    };
    let ([AssignTarget::Var(Var::Local(counter), _)], [bump_value]): (&[AssignTarget], &[Expr]) =
        (bump_targets.as_slice(), bump_values.as_slice())
    else {
        return None;
    };
    if !is_unit_increment(bump_value, *counter) {
        return None;
    }
    let StatKind::Assign {
        targets: mark_targets,
        values: mark_values,
    } = &mark.kind
    else {
        return None;
    };
    let ([AssignTarget::Index(refcount_base, refcount_key, _)], [mark_value]): (
        &[AssignTarget],
        &[Expr],
    ) = (mark_targets.as_slice(), mark_values.as_slice()) else {
        return None;
    };
    if static_number_value(mark_value) != Some(1.0) || !is_bare_local(refcount_key, *counter) {
        return None;
    }
    let ExprKind::Var(Var::Local(refcount)) = &unwrap_paren(refcount_base).kind else {
        return None;
    };
    let StatKind::Return(returned) = &tail.kind else {
        return None;
    };
    let [returned]: &[Expr] = returned.as_slice() else {
        return None;
    };
    if !is_bare_local(returned, *counter) {
        return None;
    }
    Some((*counter, *refcount))
}

fn as_box_releaser(func_expr: &Expr) -> Option<(LocalId, LocalId)> {
    let ExprKind::Function {
        params,
        is_vararg,
        body,
    } = &func_expr.kind
    else {
        return None;
    };
    if *is_vararg {
        return None;
    }
    let [slot]: &[LocalId] = params.as_slice() else {
        return None;
    };
    let [drop_stat, clear_stat]: &[Stat] = body.stats.as_slice() else {
        return None;
    };
    let StatKind::Assign {
        targets: drop_targets,
        values: drop_values,
    } = &drop_stat.kind
    else {
        return None;
    };
    let ([AssignTarget::Index(refcount_base, refcount_key, _)], [drop_value]): (
        &[AssignTarget],
        &[Expr],
    ) = (drop_targets.as_slice(), drop_values.as_slice()) else {
        return None;
    };
    let ExprKind::Var(Var::Local(refcount)) = &unwrap_paren(refcount_base).kind else {
        return None;
    };
    if !is_bare_local(refcount_key, *slot) {
        return None;
    }
    let ExprKind::Binary(BinOp::Sub, decrement_base, decrement_step) =
        &unwrap_paren(drop_value).kind
    else {
        return None;
    };
    if !is_indexed_slot(decrement_base, *refcount, *slot)
        || static_number_value(decrement_step) != Some(1.0)
    {
        return None;
    }
    let StatKind::If { arms, else_body } = &clear_stat.kind else {
        return None;
    };
    if else_body.is_some() {
        return None;
    }
    let [(cond, then_body)]: &[(Expr, Block)] = arms.as_slice() else {
        return None;
    };
    if !is_zero_slot_test(cond, *refcount, *slot) {
        return None;
    }
    let [clear]: &[Stat] = then_body.stats.as_slice() else {
        return None;
    };
    let StatKind::Assign {
        targets: clear_targets,
        values: clear_values,
    } = &clear.kind
    else {
        return None;
    };
    let (
        [
            AssignTarget::Index(first_base, first_key, _),
            AssignTarget::Index(second_base, second_key, _),
        ],
        [first_value, second_value],
    ): (&[AssignTarget], &[Expr]) = (clear_targets.as_slice(), clear_values.as_slice())
    else {
        return None;
    };
    if !matches!(first_value.kind, ExprKind::Nil) || !matches!(second_value.kind, ExprKind::Nil) {
        return None;
    }
    if !is_bare_local(first_base, *refcount)
        || !is_bare_local(first_key, *slot)
        || !is_bare_local(second_key, *slot)
    {
        return None;
    }
    let ExprKind::Var(Var::Local(heap)) = &unwrap_paren(second_base).kind else {
        return None;
    };
    Some((*refcount, *heap))
}

fn derive_box_model(chunk: &Block, function_exprs: &[&Expr]) -> Option<BoxModel> {
    let mut allocators: Vec<(LocalId, Span)> = Vec::new();
    let mut releasers: Vec<(LocalId, LocalId, Span)> = Vec::new();
    for candidate in function_exprs {
        if let Some((_, refcount)) = as_box_allocator(candidate) {
            allocators.push((refcount, candidate.span));
        }
        if let Some((refcount, heap)) = as_box_releaser(candidate) {
            releasers.push((refcount, heap, candidate.span));
        }
    }
    let [(refcount, alloc_span)]: &[(LocalId, Span)] = allocators.as_slice() else {
        return None;
    };
    let matching: Vec<&(LocalId, LocalId, Span)> = releasers
        .iter()
        .filter(|(candidate, _, _): &&(LocalId, LocalId, Span)| candidate == refcount)
        .collect();
    let heaps: BTreeSet<LocalId> = matching
        .iter()
        .map(|(_, heap, _): &&(LocalId, LocalId, Span)| *heap)
        .collect();
    let unique_heaps: Vec<LocalId> = heaps.into_iter().collect();
    let [heap]: &[LocalId] = unique_heaps.as_slice() else {
        return None;
    };
    let alloc: LocalId = find_local_binding(chunk, *alloc_span)?;
    let release: Option<LocalId> = match matching.as_slice() {
        [(_, _, span)] => find_local_binding(chunk, *span),
        _ => None,
    };
    Some(BoxModel {
        heap: *heap,
        alloc,
        release,
    })
}

fn walk_assign_targets<'a>(block: &'a Block, out: &mut Vec<&'a AssignTarget>) {
    for stat in &block.stats {
        walk_assign_targets_stat(stat, out);
    }
}

fn walk_assign_targets_stat<'a>(stat: &'a Stat, out: &mut Vec<&'a AssignTarget>) {
    match &stat.kind {
        StatKind::Assign { targets, .. } => out.extend(targets.iter()),
        StatKind::Do(body)
        | StatKind::While { body, .. }
        | StatKind::Repeat { body, .. }
        | StatKind::NumericFor { body, .. }
        | StatKind::GenericFor { body, .. } => walk_assign_targets(body, out),
        StatKind::If { arms, else_body } => {
            for (_, body) in arms {
                walk_assign_targets(body, out);
            }
            if let Some(body) = else_body {
                walk_assign_targets(body, out);
            }
        }
        StatKind::Local { .. } | StatKind::ExprStat(_) | StatKind::Return(_) | StatKind::Break => {}
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

fn is_exit_shape(rhs: &Expr, substitutions: &BTreeMap<u64, String>) -> bool {
    matches!(
        &rhs.kind,
        ExprKind::Index(_, key)
            if matches!(key.kind, ExprKind::Str)
                || substitutions.contains_key(&span_key(key.span))
    )
}

fn static_number_value(expr: &Expr) -> Option<f64> {
    StaticNumberEvaluator::new().evaluate(expr)
}

struct StaticNumberEvaluator {
    cache: RefCell<BTreeMap<u64, Option<f64>>>,
    fuel: Cell<usize>,
}

impl StaticNumberEvaluator {
    fn new() -> Self {
        Self {
            cache: RefCell::new(BTreeMap::new()),
            fuel: Cell::new(MAX_STATIC_NUMBER_FUEL),
        }
    }

    fn evaluate(&self, expr: &Expr) -> Option<f64> {
        self.evaluate_at_depth(expr, 0)
    }

    fn evaluate_at_depth(&self, expr: &Expr, depth: usize) -> Option<f64> {
        if depth > MAX_STATIC_NUMBER_DEPTH {
            return None;
        }
        let key: u64 = span_key(expr.span);
        if let Some(cached) = self.cache.borrow().get(&key).copied() {
            return cached;
        }
        let remaining: usize = self.fuel.get().checked_sub(1)?;
        self.fuel.set(remaining);
        let next_depth: usize = depth + 1;
        let value: Option<f64> = match &expr.kind {
            ExprKind::Number(value) => finite_number(*value),
            ExprKind::Unary(UnOp::Neg, inner) => {
                finite_number(-self.evaluate_at_depth(inner, next_depth)?)
            }
            ExprKind::Paren(inner) => self.evaluate_at_depth(inner, next_depth),
            ExprKind::Binary(op, left, right)
                if matches!(
                    op,
                    BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Mod | BinOp::Pow
                ) =>
            {
                let left: f64 = self.evaluate_at_depth(left, next_depth)?;
                let right: f64 = self.evaluate_at_depth(right, next_depth)?;
                let value: f64 = match op {
                    BinOp::Add => left + right,
                    BinOp::Sub => left - right,
                    BinOp::Mul => left * right,
                    BinOp::Div if right != 0.0 => left / right,
                    BinOp::Mod if right != 0.0 => (left / right).floor().mul_add(-right, left),
                    BinOp::Pow => left.powf(right),
                    BinOp::Div | BinOp::Mod => return None,
                    BinOp::Concat
                    | BinOp::Eq
                    | BinOp::Ne
                    | BinOp::Lt
                    | BinOp::Le
                    | BinOp::Gt
                    | BinOp::Ge
                    | BinOp::And
                    | BinOp::Or => return None,
                };
                finite_number(value)
            }
            _ => None,
        };
        self.cache.borrow_mut().insert(key, value);
        value
    }
}

fn finite_number(value: f64) -> Option<f64> {
    value.is_finite().then_some(value)
}

fn post_dispatch_return(container: &ContainerShape<'_>) -> Result<Option<(LocalId, LocalId)>> {
    let Some(dispatch_index) = container.full_body.stats.iter().position(|stat: &Stat| {
        matches!(&stat.kind, StatKind::While { body, .. } if std::ptr::eq(body, container.dispatch_root))
    }) else {
        return Err(refuse(
            "the Vmify container's dispatch loop is not present in its own function body",
        ));
    };
    let mut candidates: BTreeSet<(LocalId, LocalId)> = BTreeSet::new();
    for stat in container.full_body.stats.iter().skip(dispatch_index + 1) {
        let StatKind::Return(values) = &stat.kind else {
            continue;
        };
        let [value]: &[Expr] = values.as_slice() else {
            return Err(refuse(
                "the Vmify container has a post-dispatch return with an unsupported value count",
            ));
        };
        let ExprKind::Call { base, args } = &unwrap_paren(value).kind else {
            return Err(refuse(
                "the Vmify container's post-dispatch return is not a direct unpack call",
            ));
        };
        let ExprKind::Var(Var::Local(unpack_local)) = &unwrap_paren(base).kind else {
            return Err(refuse(
                "the Vmify container's post-dispatch return does not call a local unpack alias",
            ));
        };
        let [argument]: &[Expr] = args.as_slice() else {
            return Err(refuse(
                "the Vmify container's post-dispatch unpack call does not take exactly one return table",
            ));
        };
        let ExprKind::Var(Var::Local(return_local)) = &unwrap_paren(argument).kind else {
            return Err(refuse(
                "the Vmify container's post-dispatch unpack call does not receive a local return table",
            ));
        };
        candidates.insert((*unpack_local, *return_local));
    }
    match candidates
        .into_iter()
        .collect::<Vec<(LocalId, LocalId)>>()
        .as_slice()
    {
        [] => Ok(None),
        [single] => Ok(Some(*single)),
        _ => Err(refuse(
            "the Vmify container has conflicting post-dispatch unpack return candidates",
        )),
    }
}

fn is_global_named(expr: &Expr, source: &str, expected: &str) -> bool {
    matches!(&unwrap_paren(expr).kind, ExprKind::Var(Var::Global(span)) if span.text(source) == expected)
}

fn is_unpack_key(expr: &Expr, source: &str, substitutions: &BTreeMap<u64, String>) -> bool {
    if substitutions
        .get(&span_key(expr.span))
        .is_some_and(|value: &String| value == "\"unpack\"")
    {
        return true;
    }
    matches!(&unwrap_paren(expr).kind, ExprKind::Str)
        && matches!(expr.span.text(source), "unpack" | "\"unpack\"" | "'unpack'")
}

fn is_exact_unpack_alias(
    expression: &Expr,
    source: &str,
    substitutions: &BTreeMap<u64, String>,
) -> bool {
    let ExprKind::Binary(BinOp::Or, unpack, fallback) = &unwrap_paren(expression).kind else {
        return false;
    };
    let ExprKind::Index(table, key) = &unwrap_paren(fallback).kind else {
        return false;
    };
    is_global_named(unpack, source, "unpack")
        && is_global_named(table, source, "table")
        && is_unpack_key(key, source, substitutions)
}

fn find_return_local(
    dispatch_root: &Block,
    pos_local: LocalId,
    substitutions: &BTreeMap<u64, String>,
    numbers: &StaticNumberEvaluator,
    post_dispatch: Option<LocalId>,
) -> Result<LocalId> {
    let mut leaves: Vec<&Block> = Vec::new();
    collect_all_leaves(dispatch_root, pos_local, &mut leaves, 0, numbers)?;
    let mut votes: BTreeMap<LocalId, usize> = BTreeMap::new();
    let mut exit_leaves_seen: usize = 0;
    for leaf in &leaves {
        let Some(pos_rhs) = last_target_value(&leaf.stats, pos_local) else {
            continue;
        };
        if !is_exit_shape(pos_rhs, substitutions) {
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
        return post_dispatch.ok_or_else(|| {
            refuse(
                "no exit block or exact post-dispatch unpack call identifies the return-value table",
            )
        });
    }
    let winners: Vec<LocalId> = votes
        .iter()
        .filter(|(_, c): &(&LocalId, &usize)| **c == max)
        .map(|(id, _): (&LocalId, &usize)| *id)
        .collect();
    match winners.as_slice() {
        [single] if post_dispatch.is_none_or(|post: LocalId| post == *single) => Ok(*single),
        [single] => Err(refuse_owned(format!(
            "the exit blocks identify return table {single}, but the post-dispatch unpack call identifies a different local"
        ))),
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

#[derive(Clone)]
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
    numbers: &StaticNumberEvaluator,
) -> Option<f64> {
    if depth > MAX_SCRATCH_CHAIN_DEPTH {
        return None;
    }
    if let Some(value) = numbers.evaluate(expr) {
        return Some(value);
    }
    match &expr.kind {
        ExprKind::Var(Var::Local(id)) => {
            let (span, prior): (Span, &Expr) = nth_last_target_stmt(&leaf.stats, *id, 0)?;
            chain.push(span);
            resolve_number_via_last_write(leaf, prior, depth + 1, chain, numbers)
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

fn contains_local_decl_in_current_function(block: &Block) -> bool {
    block
        .stats
        .iter()
        .any(stat_contains_local_decl_in_current_function)
}

fn stat_contains_local_decl_in_current_function(stat: &Stat) -> bool {
    match &stat.kind {
        StatKind::Local { .. } => true,
        StatKind::Assign { targets, values } => {
            targets.iter().any(|t: &AssignTarget| match t {
                AssignTarget::Index(base, key, _) => {
                    expr_contains_local_decl_in_current_function(base)
                        || expr_contains_local_decl_in_current_function(key)
                }
                AssignTarget::Var(..) => false,
            }) || values
                .iter()
                .any(expr_contains_local_decl_in_current_function)
        }
        StatKind::ExprStat(e) => expr_contains_local_decl_in_current_function(e),
        StatKind::Do(b) | StatKind::While { body: b, .. } | StatKind::Repeat { body: b, .. } => {
            contains_local_decl_in_current_function(b)
        }
        StatKind::If { arms, else_body } => {
            arms.iter().any(|(cond, body): &(Expr, Block)| {
                expr_contains_local_decl_in_current_function(cond)
                    || contains_local_decl_in_current_function(body)
            }) || else_body
                .as_ref()
                .is_some_and(contains_local_decl_in_current_function)
        }
        StatKind::NumericFor {
            start,
            stop,
            step,
            body,
            ..
        } => {
            expr_contains_local_decl_in_current_function(start)
                || expr_contains_local_decl_in_current_function(stop)
                || step
                    .as_ref()
                    .is_some_and(expr_contains_local_decl_in_current_function)
                || contains_local_decl_in_current_function(body)
        }
        StatKind::GenericFor { exprs, body, .. } => {
            exprs
                .iter()
                .any(expr_contains_local_decl_in_current_function)
                || contains_local_decl_in_current_function(body)
        }
        StatKind::Return(values) => values
            .iter()
            .any(expr_contains_local_decl_in_current_function),
        StatKind::Break => false,
    }
}

fn expr_contains_local_decl_in_current_function(expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::Function { .. } => false,
        ExprKind::Index(base, key) => {
            expr_contains_local_decl_in_current_function(base)
                || expr_contains_local_decl_in_current_function(key)
        }
        ExprKind::Call { base, args } => {
            expr_contains_local_decl_in_current_function(base)
                || args
                    .iter()
                    .any(expr_contains_local_decl_in_current_function)
        }
        ExprKind::MethodCall { base, args, .. } => {
            expr_contains_local_decl_in_current_function(base)
                || args
                    .iter()
                    .any(expr_contains_local_decl_in_current_function)
        }
        ExprKind::Table(fields) => fields.iter().any(|field: &TableField| match field {
            TableField::Positional(v) => expr_contains_local_decl_in_current_function(v),
            TableField::Named(_, v) => expr_contains_local_decl_in_current_function(v),
            TableField::Indexed(k, v) => {
                expr_contains_local_decl_in_current_function(k)
                    || expr_contains_local_decl_in_current_function(v)
            }
        }),
        ExprKind::Binary(_, l, r) => {
            expr_contains_local_decl_in_current_function(l)
                || expr_contains_local_decl_in_current_function(r)
        }
        ExprKind::Unary(_, e) | ExprKind::Paren(e) => {
            expr_contains_local_decl_in_current_function(e)
        }
        ExprKind::Nil
        | ExprKind::True
        | ExprKind::False
        | ExprKind::Vararg
        | ExprKind::Number(_)
        | ExprKind::Str
        | ExprKind::Var(_) => false,
    }
}

fn terminal_transfer<'a>(
    leaf: &'a Block,
    pos_local: LocalId,
    return_local: LocalId,
    substitutions: &BTreeMap<u64, String>,
    numbers: &StaticNumberEvaluator,
) -> Result<(Transfer<'a>, LeafPlan)> {
    if contains_local_decl_in_current_function(leaf) {
        return Err(refuse(
            "a reachable leaf carries a local declaration in its own function scope and cannot be re-emitted without changing scope",
        ));
    }
    let Some((pos_terminal_span, rhs)) = nth_last_target_stmt(&leaf.stats, pos_local, 0) else {
        return Err(refuse(
            "a reachable leaf block never assigns the instruction-pointer register",
        ));
    };
    if let Some(target) = numbers.evaluate(rhs) {
        return Ok((
            Transfer::Goto(target),
            LeafPlan {
                pos_terminal_span,
                pos_chain_span: None,
                return_span: None,
                numeric_chain_spans: Vec::new(),
            },
        ));
    }
    match &rhs.kind {
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
                resolve_number_via_last_write(leaf, taken, 0, &mut numeric_chain_spans, numbers),
                resolve_number_via_last_write(leaf, rhs2, 0, &mut numeric_chain_spans, numbers),
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
        _ if is_exit_shape(rhs, substitutions) => {
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
    next_box: u32,
    boxes_bound: usize,
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
    upvals_local: LocalId,
    return_local: LocalId,
    dispatch_root: &'a Block,
    container_span: Span,
    container_scope: BTreeSet<LocalId>,
    upvalue_bindings: BTreeMap<LocalId, Span>,
    environment_locals: BTreeSet<LocalId>,
    unpack_local: Option<LocalId>,
    all_creation_calls: Vec<(&'a Expr, LocalId, &'a Expr, &'a Expr)>,
    box_model: Option<BoxModel>,
    numbers: StaticNumberEvaluator,
}

#[derive(Debug, Default)]
struct FunctionBoxes {
    names: BTreeMap<LocalId, String>,
    declarations: Vec<String>,
    allocation_initializers: BTreeMap<u64, String>,
}

fn is_alloc_call(expr: &Expr, alloc: LocalId) -> bool {
    let ExprKind::Call { base, args } = &unwrap_paren(expr).kind else {
        return false;
    };
    args.is_empty() && is_bare_local(base, alloc)
}

fn successors_of(term: &Terminator, out: &mut Vec<u32>) {
    match term {
        Terminator::Return | Terminator::Unreachable => {}
        Terminator::Goto(next) => out.push(*next),
        Terminator::Branch {
            taken, not_taken, ..
        } => {
            out.push(*taken);
            out.push(*not_taken);
        }
        Terminator::Switch { cases, default, .. } => {
            for (_, target) in cases {
                out.push(*target);
            }
            if let Some(target) = default {
                out.push(*target);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoopSink {
    Continue,
    Break,
}

fn predecessors_of(terms: &[Terminator]) -> BTreeMap<u32, Vec<u32>> {
    let mut out: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    let mut succ: Vec<u32> = Vec::new();
    for (index, term) in terms.iter().enumerate() {
        succ.clear();
        successors_of(term, &mut succ);
        for target in &succ {
            out.entry(*target).or_default().push(index as u32);
        }
    }
    out
}

fn loop_member_set(terms: &[Terminator], header: u32, budget: &mut usize) -> Option<BTreeSet<u32>> {
    let mut forward: BTreeSet<u32> = BTreeSet::new();
    let mut stack: Vec<u32> = vec![header];
    let mut succ: Vec<u32> = Vec::new();
    while let Some(node) = stack.pop() {
        *budget = budget.checked_sub(1)?;
        if !forward.insert(node) {
            continue;
        }
        let term: &Terminator = terms.get(node as usize)?;
        succ.clear();
        successors_of(term, &mut succ);
        stack.extend(succ.iter().copied());
    }
    let preds: BTreeMap<u32, Vec<u32>> = predecessors_of(terms);
    let mut backward: BTreeSet<u32> = BTreeSet::new();
    let mut stack: Vec<u32> = vec![header];
    while let Some(node) = stack.pop() {
        *budget = budget.checked_sub(1)?;
        if !backward.insert(node) {
            continue;
        }
        if let Some(incoming) = preds.get(&node) {
            stack.extend(incoming.iter().copied());
        }
    }
    Some(forward.intersection(&backward).copied().collect())
}

fn region_contains_node(
    result: &disrobe_cfg::StructureResult,
    id: RegionId,
    node: u32,
    budget: &mut usize,
) -> Option<bool> {
    *budget = budget.checked_sub(1)?;
    let region: &Region = result.regions.get(id as usize)?;
    if region.children.is_empty() {
        return Some(matches!(region.kind, RegionKind::Block) && region.entry == node);
    }
    if let Some(head) = region.head
        && region_contains_node(result, head, node, budget)?
    {
        return Some(true);
    }
    for child in &region.children {
        if region_contains_node(result, *child, node, budget)? {
            return Some(true);
        }
    }
    Some(false)
}

fn is_sink_leaf(result: &disrobe_cfg::StructureResult, id: RegionId, node: u32) -> bool {
    result.regions.get(id as usize).is_some_and(|r: &Region| {
        r.children.is_empty() && matches!(r.kind, RegionKind::Block) && r.entry == node
    })
}

fn sink_reached_only_at_tail(
    result: &disrobe_cfg::StructureResult,
    id: RegionId,
    node: u32,
    budget: &mut usize,
) -> Option<bool> {
    *budget = budget.checked_sub(1)?;
    let region: &Region = result.regions.get(id as usize)?;
    match region.kind {
        RegionKind::Block if region.children.is_empty() => Some(true),
        RegionKind::Block => {
            let (last, rest): (&RegionId, &[RegionId]) = region.children.split_last()?;
            for child in rest {
                if region_contains_node(result, *child, node, budget)? {
                    return Some(false);
                }
            }
            sink_reached_only_at_tail(result, *last, node, budget)
        }
        RegionKind::IfThen | RegionKind::IfThenElse => {
            if let Some(head) = region.head
                && region_contains_node(result, head, node, budget)?
            {
                return Some(false);
            }
            for child in &region.children {
                if !sink_reached_only_at_tail(result, *child, node, budget)? {
                    return Some(false);
                }
            }
            Some(true)
        }
        _ => Some(!region_contains_node(result, id, node, budget)?),
    }
}

fn negated_cond(
    cond_of_atom: &[String],
    conds: &disrobe_cfg::CondPool,
    id: disrobe_cfg::CondId,
) -> Option<String> {
    match conds.nodes().get(id as usize)? {
        disrobe_cfg::Cond::Leaf(atom) => cond_of_atom
            .get(*atom as usize)
            .map(|text: &String| format!("not ({text})")),
        disrobe_cfg::Cond::NotLeaf(atom) => cond_of_atom.get(*atom as usize).cloned(),
        _ => None,
    }
}

fn insert_box_subst(subst: &mut BTreeMap<u64, String>, span: Span, text: String) -> Result<()> {
    match subst.get(&span_key(span)) {
        Some(existing) if *existing != text => Err(refuse_owned(format!(
            "the expression at byte {} is bound to two different recovered values, so one dispatch leaf is shared by two closures with different captured variables",
            span.start
        ))),
        Some(_) => Ok(()),
        None => {
            subst.insert(span_key(span), text);
            Ok(())
        }
    }
}

fn box_slot_cell(
    ctx: &Ctx<'_>,
    key: &Expr,
    names: &BTreeMap<LocalId, String>,
    upvalue_boxes: &[String],
    substitutions: &BTreeMap<u64, String>,
) -> Result<String> {
    let key: &Expr = unwrap_paren(key);
    if let Some(value) = substitutions.get(&span_key(key.span)) {
        return Ok(value.clone());
    }
    if let ExprKind::Var(Var::Local(id)) = &key.kind {
        return names.get(id).cloned().ok_or_else(|| {
            refuse_owned(format!(
                "the upvalue-box slot read at byte {} is indexed by a register this function never allocated a box into, so the captured variable it names cannot be identified",
                key.span.start
            ))
        });
    }
    if let ExprKind::Index(base, slot) = &key.kind
        && is_bare_local(base, ctx.upvals_local)
        && let Some(position) = static_number_value(slot)
    {
        if !position.is_finite() || position.fract() != 0.0 || position < 1.0 {
            return Err(refuse_owned(format!(
                "the captured-variable index at byte {} is not a positive whole number",
                slot.span.start
            )));
        }
        let index: usize = position as usize;
        return upvalue_boxes.get(index - 1).cloned().ok_or_else(|| {
            refuse_owned(format!(
                "the function body reads captured variable {index} but its closure-creation call supplies only {} captured variable(s)",
                upvalue_boxes.len()
            ))
        });
    }
    Err(refuse_owned(format!(
        "the upvalue-box slot at byte {} is indexed by an expression shape this pass does not recognize",
        key.span.start
    )))
}

fn box_allocation(stat: &Stat, allocator: LocalId) -> Option<(LocalId, Span)> {
    let StatKind::Assign { targets, values } = &stat.kind else {
        return None;
    };
    let ([AssignTarget::Var(Var::Local(id), _)], [value]): (&[AssignTarget], &[Expr]) =
        (targets.as_slice(), values.as_slice())
    else {
        return None;
    };
    is_alloc_call(value, allocator).then_some((*id, value.span))
}

fn exact_box_release(stat: &Stat, release: LocalId) -> Option<(LocalId, bool)> {
    let (call, assignment): (&Expr, Option<LocalId>) = match &stat.kind {
        StatKind::ExprStat(expression) => (expression, None),
        StatKind::Assign { targets, values } => {
            let ([AssignTarget::Var(Var::Local(target), _)], [value]): (&[AssignTarget], &[Expr]) =
                (targets.as_slice(), values.as_slice())
            else {
                return None;
            };
            (value, Some(*target))
        }
        _ => return None,
    };
    let ExprKind::Call { base, args } = &unwrap_paren(call).kind else {
        return None;
    };
    if !is_bare_local(base, release) {
        return None;
    }
    let [argument]: &[Expr] = args.as_slice() else {
        return None;
    };
    let ExprKind::Var(Var::Local(id)) = &unwrap_paren(argument).kind else {
        return None;
    };
    assignment
        .is_none_or(|target: LocalId| target == *id)
        .then_some((*id, assignment.is_some()))
}

fn captured_box_spans(ctx: &Ctx<'_>) -> BTreeSet<u64> {
    let mut spans: BTreeSet<u64> = BTreeSet::new();
    for (_, _, _, upvalues) in &ctx.all_creation_calls {
        let ExprKind::Table(fields) = &unwrap_paren(upvalues).kind else {
            continue;
        };
        for field in fields {
            if let TableField::Positional(value) = field {
                spans.insert(span_key(value.span));
            }
        }
    }
    spans
}

fn leading_box_state_kills(leaf: &Block, tracked: &BTreeSet<LocalId>) -> BTreeSet<LocalId> {
    let mut undecided: BTreeSet<LocalId> = tracked.clone();
    let mut kills: BTreeSet<LocalId> = BTreeSet::new();
    let substitutions: BTreeMap<u64, String> = BTreeMap::new();
    for stat in &leaf.stats {
        let mut expressions: Vec<&Expr> = Vec::new();
        walk_exprs_stat(stat, &mut expressions);
        let mut reads: BTreeSet<LocalId> = BTreeSet::new();
        for expression in expressions {
            collect_expr_locals(expression, &substitutions, &mut reads);
        }
        for id in reads {
            undecided.remove(&id);
        }
        let mut definitions: BTreeSet<LocalId> = BTreeSet::new();
        collect_statement_defs(stat, &mut definitions);
        for id in definitions {
            if undecided.remove(&id) {
                kills.insert(id);
            }
        }
        if undecided.is_empty() {
            break;
        }
    }
    kills
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoxRegisterState {
    Live(u64),
    MaybeLive(u64),
    ReleasedNil,
    ReleasedOrOrdinary,
}

fn generation_name<'a>(
    state: &BTreeMap<LocalId, BoxRegisterState>,
    names: &'a BTreeMap<u64, String>,
    id: LocalId,
) -> Option<&'a String> {
    match state.get(&id) {
        Some(BoxRegisterState::Live(site) | BoxRegisterState::MaybeLive(site)) => names.get(site),
        Some(BoxRegisterState::ReleasedNil | BoxRegisterState::ReleasedOrOrdinary) | None => None,
    }
}

struct BoxRewriteContext<'a> {
    ctx: &'a Ctx<'a>,
    model: BoxModel,
    tracked: &'a BTreeSet<LocalId>,
    names: &'a BTreeMap<u64, String>,
    unique_names: &'a BTreeMap<LocalId, String>,
    capture_spans: &'a BTreeSet<u64>,
    upvalue_boxes: &'a [String],
}

fn rewrite_box_uses(
    rewrite: &BoxRewriteContext<'_>,
    stat: &Stat,
    state: &BTreeMap<LocalId, BoxRegisterState>,
    substitutions: &mut BTreeMap<u64, String>,
) -> Result<()> {
    let mut expressions: Vec<&Expr> = Vec::new();
    walk_exprs_stat(stat, &mut expressions);
    if expressions.len() > MAX_BOX_STATEMENT_USES {
        return Err(refuse(
            "an upvalue-box statement exceeds the expression-use budget",
        ));
    }
    let mut heap_key_spans: BTreeSet<u64> = BTreeSet::new();
    for expression in &expressions {
        let ExprKind::Index(base, key) = &expression.kind else {
            continue;
        };
        if !is_bare_local(base, rewrite.model.heap) {
            continue;
        }
        let replacement: String = match &unwrap_paren(key).kind {
            ExprKind::Var(Var::Local(id)) if rewrite.tracked.contains(id) => {
                heap_key_spans.insert(span_key(key.span));
                match state.get(id) {
                    Some(BoxRegisterState::Live(site)) => rewrite
                        .names
                        .get(site)
                        .map(|name: &String| format!("{name}[1]"))
                        .ok_or_else(|| refuse("a live upvalue-box generation has no name"))?,
                    Some(BoxRegisterState::MaybeLive(site)) => {
                        let name: &String = rewrite.names.get(site).ok_or_else(|| {
                            refuse("an optional upvalue-box generation has no name")
                        })?;
                        format!("({name} and {name}[1])")
                    }
                    Some(BoxRegisterState::ReleasedNil) => "nil".to_owned(),
                    Some(BoxRegisterState::ReleasedOrOrdinary) => {
                        return Err(refuse_owned(format!(
                            "the captured-variable store read at byte {} uses a released or ordinary register value",
                            expression.span.start
                        )));
                    }
                    None => {
                        return Err(refuse_owned(format!(
                            "the captured-variable store read at byte {} uses a register holding an ordinary value rather than a live or released box handle",
                            expression.span.start
                        )));
                    }
                }
            }
            _ => {
                let cell: String = box_slot_cell(
                    rewrite.ctx,
                    key,
                    rewrite.unique_names,
                    rewrite.upvalue_boxes,
                    substitutions,
                )?;
                if matches!(cell.as_str(), "nil" | "(nil)") {
                    "nil".to_owned()
                } else {
                    format!("{cell}[1]")
                }
            }
        };
        insert_box_subst(substitutions, expression.span, replacement)?;
    }
    let mut targets: Vec<&AssignTarget> = Vec::new();
    walk_assign_targets_stat(stat, &mut targets);
    for target in targets {
        let AssignTarget::Index(base, key, span) = target else {
            continue;
        };
        if !is_bare_local(base, rewrite.model.heap) {
            continue;
        }
        let replacement: String = match &unwrap_paren(key).kind {
            ExprKind::Var(Var::Local(id)) if rewrite.tracked.contains(id) => {
                let name: &String = match state.get(id) {
                    Some(BoxRegisterState::Live(site) | BoxRegisterState::MaybeLive(site)) => {
                        rewrite.names.get(site).ok_or_else(|| {
                            refuse("a writable upvalue-box generation has no name")
                        })?
                    }
                    Some(BoxRegisterState::ReleasedNil) => {
                        return Err(refuse_owned(format!(
                            "the captured-variable store at byte {} writes through a released box handle",
                            span.start
                        )));
                    }
                    Some(BoxRegisterState::ReleasedOrOrdinary) => {
                        return Err(refuse_owned(format!(
                            "the captured-variable store at byte {} writes through a released or ordinary register value",
                            span.start
                        )));
                    }
                    None => {
                        return Err(refuse_owned(format!(
                            "the captured-variable store at byte {} writes through a register holding an ordinary value",
                            span.start
                        )));
                    }
                };
                heap_key_spans.insert(span_key(key.span));
                format!("{name}[1]")
            }
            _ => {
                let cell: String = box_slot_cell(
                    rewrite.ctx,
                    key,
                    rewrite.unique_names,
                    rewrite.upvalue_boxes,
                    substitutions,
                )?;
                if matches!(cell.as_str(), "nil" | "(nil)") {
                    return Err(refuse_owned(format!(
                        "the captured-variable store at byte {} writes through a nil or released inherited box handle",
                        span.start
                    )));
                }
                format!("{cell}[1]")
            }
        };
        insert_box_subst(substitutions, *span, replacement)?;
    }
    for expression in expressions {
        let ExprKind::Var(Var::Local(id)) = &expression.kind else {
            continue;
        };
        if !rewrite.tracked.contains(id) {
            continue;
        }
        match state.get(id) {
            Some(BoxRegisterState::Live(_) | BoxRegisterState::MaybeLive(_))
                if rewrite.capture_spans.contains(&span_key(expression.span))
                    || heap_key_spans.contains(&span_key(expression.span)) =>
            {
                let name: &String = generation_name(state, rewrite.names, *id)
                    .ok_or_else(|| refuse("an upvalue-box generation has no name"))?;
                insert_box_subst(substitutions, expression.span, name.clone())?;
            }
            Some(BoxRegisterState::Live(_) | BoxRegisterState::MaybeLive(_)) => {
                return Err(refuse_owned(format!(
                    "the statement at byte {} uses a live upvalue-box handle outside a heap access or closure capture",
                    stat.span.start
                )));
            }
            Some(BoxRegisterState::ReleasedNil) => {
                insert_box_subst(substitutions, expression.span, "(nil)".to_owned())?;
            }
            Some(BoxRegisterState::ReleasedOrOrdinary)
                if rewrite.capture_spans.contains(&span_key(expression.span))
                    || heap_key_spans.contains(&span_key(expression.span)) =>
            {
                return Err(refuse_owned(format!(
                    "the statement at byte {} captures or uses a released or ordinary register value",
                    stat.span.start
                )));
            }
            Some(BoxRegisterState::ReleasedOrOrdinary) => {}
            None => {}
        }
    }
    Ok(())
}

fn merge_box_register_states(
    id: LocalId,
    node: u32,
    left: Option<BoxRegisterState>,
    right: Option<BoxRegisterState>,
) -> Result<Option<BoxRegisterState>> {
    match (left, right) {
        (None, None) => Ok(None),
        (Some(BoxRegisterState::ReleasedNil), Some(BoxRegisterState::ReleasedNil)) => {
            Ok(Some(BoxRegisterState::ReleasedNil))
        }
        (Some(BoxRegisterState::ReleasedNil), None)
        | (None, Some(BoxRegisterState::ReleasedNil)) => {
            Ok(Some(BoxRegisterState::ReleasedOrOrdinary))
        }
        (
            Some(BoxRegisterState::ReleasedOrOrdinary),
            None | Some(BoxRegisterState::ReleasedNil | BoxRegisterState::ReleasedOrOrdinary),
        )
        | (
            None | Some(BoxRegisterState::ReleasedNil),
            Some(BoxRegisterState::ReleasedOrOrdinary),
        ) => Ok(Some(BoxRegisterState::ReleasedOrOrdinary)),
        (
            Some(BoxRegisterState::Live(site) | BoxRegisterState::MaybeLive(site)),
            Some(BoxRegisterState::ReleasedNil),
        )
        | (
            Some(BoxRegisterState::ReleasedNil),
            Some(BoxRegisterState::Live(site) | BoxRegisterState::MaybeLive(site)),
        ) => Ok(Some(BoxRegisterState::MaybeLive(site))),
        (
            Some(BoxRegisterState::Live(left_site) | BoxRegisterState::MaybeLive(left_site)),
            Some(BoxRegisterState::Live(right_site) | BoxRegisterState::MaybeLive(right_site)),
        ) => {
            if left_site != right_site {
                return Err(refuse_owned(format!(
                    "upvalue-box register {id} reaches CFG node {node} from allocation generations {left_site} and {right_site}"
                )));
            }
            let merged: BoxRegisterState = if matches!(
                (left, right),
                (
                    Some(BoxRegisterState::Live(_)),
                    Some(BoxRegisterState::Live(_))
                )
            ) {
                BoxRegisterState::Live(left_site)
            } else {
                BoxRegisterState::MaybeLive(left_site)
            };
            Ok(Some(merged))
        }
        (Some(BoxRegisterState::Live(_) | BoxRegisterState::MaybeLive(_)), None)
        | (None, Some(BoxRegisterState::Live(_) | BoxRegisterState::MaybeLive(_))) => {
            Err(refuse_owned(format!(
                "upvalue-box register {id} reaches CFG node {node} as both an ordinary value and a live allocation generation"
            )))
        }
        (
            Some(BoxRegisterState::Live(_) | BoxRegisterState::MaybeLive(_)),
            Some(BoxRegisterState::ReleasedOrOrdinary),
        )
        | (
            Some(BoxRegisterState::ReleasedOrOrdinary),
            Some(BoxRegisterState::Live(_) | BoxRegisterState::MaybeLive(_)),
        ) => Err(refuse_owned(format!(
            "upvalue-box register {id} reaches CFG node {node} as both a live allocation generation and a released-or-ordinary value"
        ))),
    }
}

fn apply_box_definitions(
    state: &mut BTreeMap<LocalId, BoxRegisterState>,
    tracked: &BTreeSet<LocalId>,
    definitions: &BTreeSet<LocalId>,
) {
    for id in definitions {
        if tracked.contains(id) && state.contains_key(id) {
            state.insert(*id, BoxRegisterState::ReleasedOrOrdinary);
        }
    }
}

fn bind_function_boxes(
    ctx: &Ctx<'_>,
    order: &[u64],
    visited: &BTreeMap<u64, &Block>,
    node_of: &BTreeMap<u64, u32>,
    terms: &[Terminator],
    upvalue_boxes: &[String],
    subst: &mut BTreeMap<u64, String>,
    stats: &mut GlobalStats,
) -> Result<FunctionBoxes> {
    let Some(model): Option<BoxModel> = ctx.box_model else {
        return Ok(FunctionBoxes::default());
    };
    let mut allocations: Vec<(LocalId, Span, Span)> = Vec::new();
    for &key in order {
        let leaf: &Block = visited[&key];
        for stat in &leaf.stats {
            if let Some((id, call_span)) = box_allocation(stat, model.alloc) {
                allocations.push((id, stat.span, call_span));
            }
        }
    }
    if allocations.len() > MAX_FUNCTION_BLOCKS {
        return Err(refuse(
            "upvalue-box allocation sites exceed the function budget",
        ));
    }
    let tracked: BTreeSet<LocalId> = allocations
        .iter()
        .map(|(id, _, _): &(LocalId, Span, Span)| *id)
        .collect();
    let mut counts: BTreeMap<LocalId, usize> = BTreeMap::new();
    let mut names_by_site: BTreeMap<u64, String> = BTreeMap::new();
    let mut declarations: Vec<String> = Vec::new();
    let mut allocation_initializers: BTreeMap<u64, String> = BTreeMap::new();
    for (id, stat_span, _) in &allocations {
        let name: String = format!("{CAPTURED_VARIABLE_PREFIX}{}", stats.next_box);
        stats.next_box = stats.next_box.checked_add(1).ok_or_else(|| {
            refuse("the program allocates more captured variables than this pass can name")
        })?;
        names_by_site.insert(span_key(*stat_span), name.clone());
        let count: &mut usize = counts.entry(*id).or_insert(0);
        *count = count.saturating_add(1);
        allocation_initializers.insert(span_key(*stat_span), format!("{name} = {{}}"));
        declarations.push(name);
    }
    let mut unique_names: BTreeMap<LocalId, String> = BTreeMap::new();
    for (id, stat_span, _) in &allocations {
        if counts.get(id) != Some(&1) {
            continue;
        }
        let name: String = names_by_site
            .get(&span_key(*stat_span))
            .cloned()
            .ok_or_else(|| refuse("an upvalue-box allocation has no generation name"))?;
        unique_names.insert(*id, name);
    }
    stats.boxes_bound = stats.boxes_bound.saturating_add(allocations.len());

    let mut leaf_of_node: Vec<&Block> = vec![ctx.dispatch_root; order.len()];
    for &key in order {
        let node: u32 = node_of[&key];
        leaf_of_node[node as usize] = visited[&key];
    }
    let leading_kills: Vec<BTreeSet<LocalId>> = leaf_of_node
        .iter()
        .map(|leaf: &&Block| leading_box_state_kills(leaf, &tracked))
        .collect();
    let capture_spans: BTreeSet<u64> = captured_box_spans(ctx);
    let rewrite: BoxRewriteContext<'_> = BoxRewriteContext {
        ctx,
        model,
        tracked: &tracked,
        names: &names_by_site,
        unique_names: &unique_names,
        capture_spans: &capture_spans,
        upvalue_boxes,
    };
    let mut entry_states: Vec<Option<BTreeMap<LocalId, BoxRegisterState>>> =
        vec![None; order.len()];
    entry_states[0] = Some(BTreeMap::new());
    let mut pending: Vec<u32> = vec![0];
    let mut steps: usize = 0;
    let mut stored_bindings: usize = 0;
    let mut successors: Vec<u32> = Vec::new();
    while let Some(node) = pending.pop() {
        steps = steps
            .checked_add(1)
            .ok_or_else(|| refuse("upvalue-box generation analysis exceeds the step budget"))?;
        if steps > MAX_REACHABILITY_STEPS {
            return Err(refuse(
                "upvalue-box generation analysis exceeds the step budget",
            ));
        }
        let index: usize = node as usize;
        let Some(mut state) = entry_states.get(index).and_then(Clone::clone) else {
            continue;
        };
        let Some(leaf) = leaf_of_node.get(index).copied() else {
            continue;
        };
        for stat in &leaf.stats {
            if let Some((id, _)) = box_allocation(stat, model.alloc) {
                let site: u64 = span_key(stat.span);
                if !names_by_site.contains_key(&site) {
                    return Err(refuse("an upvalue-box allocation has no generation name"));
                }
                state.insert(id, BoxRegisterState::Live(site));
                insert_box_subst(subst, stat.span, String::new())?;
                continue;
            }
            if let Some(release) = model.release
                && let Some((id, clears_register)) = exact_box_release(stat, release)
            {
                if !tracked.contains(&id) {
                    return Err(refuse_owned(format!(
                        "the upvalue-box release at byte {} targets register {id}, which this function never allocates a box into",
                        stat.span.start
                    )));
                }
                if !clears_register {
                    return Err(refuse_owned(format!(
                        "the upvalue-box release at byte {} does not assign the helper's nil result back to the handle register",
                        stat.span.start
                    )));
                }
                let site: u64 = match state.get(&id) {
                    Some(BoxRegisterState::Live(site)) => *site,
                    Some(BoxRegisterState::MaybeLive(_)) => {
                        return Err(refuse_owned(format!(
                            "the upvalue-box release at byte {} has an optional reaching allocation",
                            stat.span.start
                        )));
                    }
                    Some(BoxRegisterState::ReleasedNil | BoxRegisterState::ReleasedOrOrdinary)
                    | None => {
                        return Err(refuse_owned(format!(
                            "the upvalue-box release at byte {} has no reaching allocation",
                            stat.span.start
                        )));
                    }
                };
                let name: &String = names_by_site
                    .get(&site)
                    .ok_or_else(|| refuse("a released upvalue-box generation has no name"))?;
                state.insert(id, BoxRegisterState::ReleasedNil);
                insert_box_subst(subst, stat.span, format!("{name} = nil"))?;
                continue;
            }
            rewrite_box_uses(&rewrite, stat, &state, subst)?;
            let mut definitions: BTreeSet<LocalId> = BTreeSet::new();
            collect_statement_defs(stat, &mut definitions);
            apply_box_definitions(&mut state, &tracked, &definitions);
        }
        successors.clear();
        if let Some(term) = terms.get(index) {
            successors_of(term, &mut successors);
        }
        for target in &successors {
            let target_index: usize = *target as usize;
            let Some(kills) = leading_kills.get(target_index) else {
                continue;
            };
            let mut incoming: BTreeMap<LocalId, BoxRegisterState> = state.clone();
            apply_box_definitions(&mut incoming, &tracked, kills);
            match entry_states.get_mut(target_index) {
                Some(slot @ None) => {
                    stored_bindings = stored_bindings.saturating_add(incoming.len());
                    if stored_bindings > MAX_BOX_STATE_BINDINGS {
                        return Err(refuse(
                            "upvalue-box generation states exceed the binding budget",
                        ));
                    }
                    *slot = Some(incoming);
                    pending.push(*target);
                }
                Some(Some(existing)) => {
                    let mut changed: bool = false;
                    let ids: BTreeSet<LocalId> =
                        existing.keys().chain(incoming.keys()).copied().collect();
                    for id in ids {
                        let left: Option<BoxRegisterState> = existing.get(&id).copied();
                        let right: Option<BoxRegisterState> = incoming.get(&id).copied();
                        let merged: Option<BoxRegisterState> =
                            merge_box_register_states(id, *target, left, right)?;
                        if merged == left {
                            continue;
                        }
                        match merged {
                            Some(value) => {
                                existing.insert(id, value);
                                stored_bindings = stored_bindings.saturating_add(1);
                                if stored_bindings > MAX_BOX_STATE_BINDINGS {
                                    return Err(refuse(
                                        "upvalue-box generation states exceed the binding budget",
                                    ));
                                }
                            }
                            None => {
                                existing.remove(&id);
                            }
                        }
                        changed = true;
                    }
                    if changed {
                        pending.push(*target);
                    }
                }
                None => {}
            }
        }
    }
    Ok(FunctionBoxes {
        names: unique_names,
        declarations,
        allocation_initializers,
    })
}

fn collect_statement_defs(stat: &Stat, out: &mut BTreeSet<LocalId>) {
    match &stat.kind {
        StatKind::Assign { targets, .. } => {
            for target in targets {
                if let AssignTarget::Var(Var::Local(id), _) = target {
                    out.insert(*id);
                }
            }
        }
        StatKind::Local { targets, .. } => out.extend(targets.iter().copied()),
        _ => {}
    }
}

fn closure_upvalue_names(
    ctx: &Ctx<'_>,
    upvals_arg: &Expr,
    boxes: &FunctionBoxes,
    own_upvalues: &[String],
    substitutions: &BTreeMap<u64, String>,
) -> Result<Vec<String>> {
    let ExprKind::Table(fields) = &unwrap_paren(upvals_arg).kind else {
        return Err(refuse_owned(format!(
            "the closure-creation call at byte {} supplies its captured variables through an expression that is not a table constructor",
            upvals_arg.span.start
        )));
    };
    let mut out: Vec<String> = Vec::with_capacity(fields.len());
    for field in fields {
        let TableField::Positional(value) = field else {
            return Err(refuse_owned(format!(
                "the closure-creation call at byte {} supplies a keyed captured-variable entry, which carries no stable position",
                upvals_arg.span.start
            )));
        };
        out.push(box_slot_cell(
            ctx,
            value,
            &boxes.names,
            own_upvalues,
            substitutions,
        )?);
    }
    Ok(out)
}

fn find_top_level_entry(ctx: &Ctx<'_>) -> Result<f64> {
    let mut outside: Vec<f64> = Vec::new();
    for (call_expr, _creator, entry_arg, _upvals) in &ctx.all_creation_calls {
        let within: bool = call_expr.span.start >= ctx.container_span.start
            && call_expr.span.end <= ctx.container_span.end;
        if within {
            continue;
        }
        let entry: f64 = number_of(entry_arg).ok_or_else(|| {
            refuse_owned(format!(
                "the top-level closure-creation call at byte {} has a dynamic entry point",
                call_expr.span.start
            ))
        })?;
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum StaticOperandKind {
    Number,
    String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AntiTamperValue {
    Environment,
    UnpackFunction,
    Candidate,
    StringKey,
    StringLibrary,
    GmatchKey,
    GmatchFunction,
    TonumberKey,
    TonumberFunction,
    PcallKey,
    TostringKey,
    LinePattern,
    TupleSecondKey,
    PcallFunction,
    TostringFunction,
    PcallCall,
    PcallPacked,
    PcallUnpacked,
    PcallTuple,
    PcallError,
    ErrorString,
    LineIterator,
    LineMatch,
    LineMatchPacked,
    LineMatchUnpacked,
    ParsedLine,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct AntiTamperState {
    locals: BTreeMap<LocalId, AntiTamperValue>,
    cells: BTreeMap<String, AntiTamperValue>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct AntiTamperProof {
    parsed_line: bool,
    candidate_state: Option<AntiTamperState>,
}

fn is_exact_environment_alias(expression: &Expr, source: &str) -> bool {
    let ExprKind::Binary(BinOp::Or, guarded_call, environment) = &unwrap_paren(expression).kind
    else {
        return false;
    };
    let ExprKind::Binary(BinOp::And, guard, call) = &unwrap_paren(guarded_call).kind else {
        return false;
    };
    let ExprKind::Call { base, args } = &unwrap_paren(call).kind else {
        return false;
    };
    is_global_named(guard, source, "getfenv")
        && args.is_empty()
        && is_global_named(base, source, "getfenv")
        && is_global_named(environment, source, "_ENV")
}

fn is_exact_static_string(
    expression: &Expr,
    source: &str,
    substitutions: &BTreeMap<u64, String>,
    expected: &str,
) -> bool {
    let quoted_double: String = format!("\"{expected}\"");
    let quoted_single: String = format!("'{expected}'");
    if substitutions
        .get(&span_key(expression.span))
        .is_some_and(|value: &String| value == &quoted_double || value == &quoted_single)
    {
        return true;
    }
    matches!(unwrap_paren(expression).kind, ExprKind::Str)
        && matches!(
            expression.span.text(source),
            value if value == expected || value == quoted_double || value == quoted_single
        )
}

fn anti_tamper_value(
    expression: &Expr,
    state: &AntiTamperState,
    candidate_span: Span,
    ctx: &Ctx<'_>,
    substitutions: &BTreeMap<u64, String>,
    depth: usize,
    fuel: &mut usize,
) -> Option<AntiTamperValue> {
    *fuel = fuel.checked_sub(1)?;
    if depth > MAX_ANTITAMPER_EXPRESSION_DEPTH {
        return None;
    }
    let expression: &Expr = unwrap_paren(expression);
    if expression.span == candidate_span {
        return Some(AntiTamperValue::Candidate);
    }
    if let Some(cell) = substitutions.get(&span_key(expression.span))
        && cell.ends_with("[1]")
        && let Some(value) = state.cells.get(cell)
    {
        return Some(*value);
    }
    if is_exact_static_string(expression, ctx.src, substitutions, "pcall") {
        return Some(AntiTamperValue::PcallKey);
    }
    if is_exact_static_string(expression, ctx.src, substitutions, "string") {
        return Some(AntiTamperValue::StringKey);
    }
    if is_exact_static_string(expression, ctx.src, substitutions, "gmatch") {
        return Some(AntiTamperValue::GmatchKey);
    }
    if is_exact_static_string(expression, ctx.src, substitutions, "tonumber") {
        return Some(AntiTamperValue::TonumberKey);
    }
    if is_exact_static_string(expression, ctx.src, substitutions, "tostring") {
        return Some(AntiTamperValue::TostringKey);
    }
    if is_exact_static_string(expression, ctx.src, substitutions, ":(%d*):") {
        return Some(AntiTamperValue::LinePattern);
    }
    if ctx.numbers.evaluate(expression) == Some(2.0) {
        return Some(AntiTamperValue::TupleSecondKey);
    }
    match &expression.kind {
        ExprKind::Var(Var::Local(id)) => state.locals.get(id).copied(),
        ExprKind::Index(base, key) => {
            let base_value: AntiTamperValue = anti_tamper_value(
                base,
                state,
                candidate_span,
                ctx,
                substitutions,
                depth + 1,
                fuel,
            )?;
            let key_value: Option<AntiTamperValue> = anti_tamper_value(
                key,
                state,
                candidate_span,
                ctx,
                substitutions,
                depth + 1,
                fuel,
            );
            match (base_value, key_value) {
                (AntiTamperValue::Environment, Some(AntiTamperValue::StringKey)) => {
                    Some(AntiTamperValue::StringLibrary)
                }
                (AntiTamperValue::StringLibrary, Some(AntiTamperValue::GmatchKey)) => {
                    Some(AntiTamperValue::GmatchFunction)
                }
                (AntiTamperValue::Environment, Some(AntiTamperValue::TonumberKey)) => {
                    Some(AntiTamperValue::TonumberFunction)
                }
                (AntiTamperValue::Environment, Some(AntiTamperValue::PcallKey)) => {
                    Some(AntiTamperValue::PcallFunction)
                }
                (AntiTamperValue::Environment, Some(AntiTamperValue::TostringKey)) => {
                    Some(AntiTamperValue::TostringFunction)
                }
                (AntiTamperValue::PcallTuple, Some(AntiTamperValue::TupleSecondKey)) => {
                    Some(AntiTamperValue::PcallError)
                }
                _ => None,
            }
        }
        ExprKind::Call { base, args } => {
            let base_value: Option<AntiTamperValue> = anti_tamper_value(
                base,
                state,
                candidate_span,
                ctx,
                substitutions,
                depth + 1,
                fuel,
            );
            let argument_values: Option<Vec<AntiTamperValue>> = args
                .iter()
                .map(|argument: &Expr| {
                    anti_tamper_value(
                        argument,
                        state,
                        candidate_span,
                        ctx,
                        substitutions,
                        depth + 1,
                        fuel,
                    )
                })
                .collect();
            match (base_value, argument_values.as_deref()) {
                (Some(AntiTamperValue::PcallFunction), Some([AntiTamperValue::Candidate])) => {
                    Some(AntiTamperValue::PcallCall)
                }
                (Some(AntiTamperValue::UnpackFunction), Some([AntiTamperValue::PcallPacked])) => {
                    Some(AntiTamperValue::PcallUnpacked)
                }
                (Some(AntiTamperValue::TostringFunction), Some([AntiTamperValue::PcallError])) => {
                    Some(AntiTamperValue::ErrorString)
                }
                (
                    Some(AntiTamperValue::GmatchFunction),
                    Some([AntiTamperValue::ErrorString, AntiTamperValue::LinePattern]),
                ) => Some(AntiTamperValue::LineIterator),
                (Some(AntiTamperValue::LineIterator), Some([])) => Some(AntiTamperValue::LineMatch),
                (
                    Some(AntiTamperValue::UnpackFunction),
                    Some([AntiTamperValue::LineMatchPacked]),
                ) => Some(AntiTamperValue::LineMatchUnpacked),
                (
                    Some(AntiTamperValue::TonumberFunction),
                    Some([AntiTamperValue::LineMatchUnpacked]),
                ) => Some(AntiTamperValue::ParsedLine),
                _ => None,
            }
        }
        ExprKind::Table(fields) => {
            let [TableField::Positional(value)] = fields.as_slice() else {
                return None;
            };
            match anti_tamper_value(
                value,
                state,
                candidate_span,
                ctx,
                substitutions,
                depth + 1,
                fuel,
            )? {
                AntiTamperValue::PcallCall => Some(AntiTamperValue::PcallPacked),
                AntiTamperValue::PcallUnpacked => Some(AntiTamperValue::PcallTuple),
                AntiTamperValue::LineMatch => Some(AntiTamperValue::LineMatchPacked),
                _ => None,
            }
        }
        _ => None,
    }
}

fn apply_anti_tamper_statement(
    stat: &Stat,
    state: &mut AntiTamperState,
    candidate_span: Span,
    ctx: &Ctx<'_>,
    substitutions: &BTreeMap<u64, String>,
    fuel: &mut usize,
) -> bool {
    let (local_targets, cell_targets, values): (
        Vec<Option<LocalId>>,
        Vec<Option<String>>,
        &[Expr],
    ) = match &stat.kind {
        StatKind::Local { targets, values } => (
            targets.iter().copied().map(Some).collect(),
            vec![None; targets.len()],
            values.as_slice(),
        ),
        StatKind::Assign { targets, values } => (
            targets
                .iter()
                .map(|target: &AssignTarget| match target {
                    AssignTarget::Var(Var::Local(id), _) => Some(*id),
                    AssignTarget::Var(Var::Global(_), _) | AssignTarget::Index(_, _, _) => None,
                })
                .collect(),
            targets
                .iter()
                .map(|target: &AssignTarget| match target {
                    AssignTarget::Index(_, _, span) => substitutions
                        .get(&span_key(*span))
                        .filter(|cell: &&String| cell.ends_with("[1]"))
                        .cloned(),
                    AssignTarget::Var(_, _) => None,
                })
                .collect(),
            values.as_slice(),
        ),
        _ => return false,
    };
    let updates: Vec<Option<AntiTamperValue>> = values
        .iter()
        .map(|value: &Expr| {
            anti_tamper_value(value, state, candidate_span, ctx, substitutions, 0, fuel)
        })
        .collect();
    let proved: bool = updates.contains(&Some(AntiTamperValue::ParsedLine));
    for ((local, cell), update) in local_targets.into_iter().zip(cell_targets).zip(updates) {
        if let Some(id) = local {
            match update {
                Some(value) => {
                    state.locals.insert(id, value);
                }
                None => {
                    state.locals.remove(&id);
                }
            }
        }
        if let Some(identity) = cell {
            match update {
                Some(value) => {
                    state.cells.insert(identity, value);
                }
                None => {
                    state.cells.remove(&identity);
                }
            }
        }
    }
    proved
}

fn merge_anti_tamper_state(
    existing: &AntiTamperState,
    incoming: &AntiTamperState,
) -> AntiTamperState {
    AntiTamperState {
        locals: existing
            .locals
            .iter()
            .filter_map(|(id, value): (&LocalId, &AntiTamperValue)| {
                (incoming.locals.get(id) == Some(value)).then_some((*id, *value))
            })
            .collect(),
        cells: existing
            .cells
            .iter()
            .filter_map(|(identity, value): (&String, &AntiTamperValue)| {
                (incoming.cells.get(identity) == Some(value)).then_some((identity.clone(), *value))
            })
            .collect(),
    }
}

fn proves_pinned_anti_tamper_call(
    candidate_span: Span,
    leaf_of_node: &[&Block],
    terms: &[Terminator],
    ctx: &Ctx<'_>,
    substitutions: &BTreeMap<u64, String>,
    inherited_cells: &BTreeMap<String, AntiTamperValue>,
) -> Result<AntiTamperProof> {
    let mut initial: AntiTamperState = AntiTamperState {
        locals: ctx
            .environment_locals
            .iter()
            .map(|id: &LocalId| (*id, AntiTamperValue::Environment))
            .collect(),
        cells: inherited_cells.clone(),
    };
    if let Some(unpack_local) = ctx.unpack_local {
        initial
            .locals
            .insert(unpack_local, AntiTamperValue::UnpackFunction);
    }
    let mut entries: Vec<Option<AntiTamperState>> = vec![None; leaf_of_node.len()];
    let Some(entry) = entries.first_mut() else {
        return Ok(AntiTamperProof::default());
    };
    *entry = Some(initial);
    let mut pending: Vec<u32> = vec![0];
    let mut steps: usize = 0;
    let mut fuel: usize = MAX_ANTITAMPER_PROOF_STEPS;
    let mut proof: AntiTamperProof = AntiTamperProof::default();
    while let Some(node) = pending.pop() {
        steps = steps.saturating_add(1);
        if steps > MAX_ANTITAMPER_PROOF_STEPS {
            return Err(refuse("the AntiTamper proof exceeds its CFG step budget"));
        }
        let mut state: AntiTamperState = entries[node as usize]
            .clone()
            .ok_or_else(|| refuse("the AntiTamper proof worklist has no entry state"))?;
        for stat in &leaf_of_node[node as usize].stats {
            let values: &[Expr] = match &stat.kind {
                StatKind::Local { values, .. } | StatKind::Assign { values, .. } => values,
                _ => &[],
            };
            if values
                .iter()
                .any(|value: &Expr| unwrap_paren(value).span == candidate_span)
            {
                proof.candidate_state = Some(match &proof.candidate_state {
                    Some(existing) => merge_anti_tamper_state(existing, &state),
                    None => state.clone(),
                });
            }
            if apply_anti_tamper_statement(
                stat,
                &mut state,
                candidate_span,
                ctx,
                substitutions,
                &mut fuel,
            ) {
                proof.parsed_line = true;
                if proof.candidate_state.is_some() {
                    return Ok(proof);
                }
            }
            let binding_count: usize = state
                .locals
                .len()
                .checked_add(state.cells.len())
                .ok_or_else(|| refuse("the AntiTamper proof state size overflowed"))?;
            if binding_count > MAX_ANTITAMPER_STATE_BINDINGS {
                return Err(refuse(
                    "the AntiTamper proof exceeds its state-binding budget",
                ));
            }
        }
        let mut successors: Vec<u32> = Vec::new();
        successors_of(&terms[node as usize], &mut successors);
        for successor in successors {
            let next: &mut Option<AntiTamperState> = &mut entries[successor as usize];
            let merged: AntiTamperState = match next {
                Some(existing) => merge_anti_tamper_state(existing, &state),
                None => state.clone(),
            };
            if next.as_ref() != Some(&merged) {
                *next = Some(merged);
                pending.push(successor);
            }
        }
    }
    Ok(proof)
}

fn static_operand_kind(
    expression: &Expr,
    values: &BTreeMap<LocalId, StaticOperandKind>,
    substitutions: &BTreeMap<u64, String>,
    numbers: &StaticNumberEvaluator,
) -> Option<StaticOperandKind> {
    let expression: &Expr = unwrap_paren(expression);
    if numbers.evaluate(expression).is_some() {
        return Some(StaticOperandKind::Number);
    }
    if matches!(expression.kind, ExprKind::Str)
        || substitutions
            .get(&span_key(expression.span))
            .is_some_and(|value: &String| value.starts_with(['"', '\'']))
    {
        return Some(StaticOperandKind::String);
    }
    match &expression.kind {
        ExprKind::Var(Var::Local(id)) => values.get(id).copied(),
        _ => None,
    }
}

fn deliberate_arithmetic_error_line(
    leaf: &Block,
    source: &str,
    substitutions: &BTreeMap<u64, String>,
    numbers: &StaticNumberEvaluator,
) -> Option<usize> {
    let mut values: BTreeMap<LocalId, StaticOperandKind> = BTreeMap::new();
    for stat in &leaf.stats {
        let StatKind::Assign {
            targets,
            values: rhs,
        } = &stat.kind
        else {
            return None;
        };
        if targets.len() != rhs.len() {
            return None;
        }
        let mut updates: Vec<(LocalId, Option<StaticOperandKind>)> = Vec::with_capacity(rhs.len());
        for (target, expression) in targets.iter().zip(rhs) {
            let AssignTarget::Var(Var::Local(id), _) = target else {
                return None;
            };
            if let ExprKind::Binary(BinOp::Pow, left, right) = &unwrap_paren(expression).kind {
                let left: Option<StaticOperandKind> =
                    static_operand_kind(left, &values, substitutions, numbers);
                let right: Option<StaticOperandKind> =
                    static_operand_kind(right, &values, substitutions, numbers);
                if matches!(
                    (left, right),
                    (
                        Some(StaticOperandKind::String),
                        Some(StaticOperandKind::Number)
                    ) | (
                        Some(StaticOperandKind::Number),
                        Some(StaticOperandKind::String)
                    )
                ) {
                    let prefix: &str = source.get(..expression.span.start as usize)?;
                    return Some(prefix.bytes().filter(|byte: &u8| *byte == b'\n').count() + 1);
                }
            }
            updates.push((
                *id,
                static_operand_kind(expression, &values, substitutions, numbers),
            ));
        }
        for (id, value) in updates {
            match value {
                Some(kind) => {
                    values.insert(id, kind);
                }
                None => {
                    values.remove(&id);
                }
            }
        }
    }
    None
}

fn recover_function(
    ctx: &Ctx<'_>,
    entry: f64,
    depth: usize,
    upvalue_boxes: &[String],
    anti_tamper_cells: &BTreeMap<String, AntiTamperValue>,
    subst: &mut BTreeMap<u64, String>,
    stats: &mut GlobalStats,
    allow_arithmetic_error: bool,
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
    let capture_parameters: Vec<String> = upvalue_boxes
        .iter()
        .enumerate()
        .map(|(index, _): (usize, &String)| format!("__vuc{depth}_{index}"))
        .collect();
    let mut visited: BTreeMap<u64, &Block> = BTreeMap::new();
    let mut order: Vec<u64> = Vec::new();
    let mut pending: Vec<f64> = vec![entry];
    let mut steps: usize = 0;
    while let Some(v) = pending.pop() {
        steps += 1;
        if steps > MAX_REACHABILITY_STEPS {
            return Err(refuse("function reachability walk exceeds step budget"));
        }
        let Some(leaf) = resolve_leaf(ctx.dispatch_root, ctx.pos_local, v, 0, &ctx.numbers) else {
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
            terminal_transfer(leaf, ctx.pos_local, ctx.return_local, subst, &ctx.numbers)?;
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

    if allow_arithmetic_error
        && upvalue_boxes.is_empty()
        && let [key] = order.as_slice()
        && let Some(leaf) = visited.get(key).copied()
        && let Some(line) = deliberate_arithmetic_error_line(leaf, ctx.src, subst, &ctx.numbers)
    {
        stats.leaves_recovered = stats.leaves_recovered.saturating_add(1);
        stats.functions_fully_structured = stats.functions_fully_structured.saturating_add(1);
        stats.reached.insert(*key);
        return Ok(RecoveredFunction {
            text: format!("function() error(\":{line}:\", 0) end"),
        });
    }

    let entry_leaf: &Block = resolve_leaf(ctx.dispatch_root, ctx.pos_local, entry, 0, &ctx.numbers)
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
            terminal_transfer(leaf, ctx.pos_local, ctx.return_local, subst, &ctx.numbers)?;
        let term: Terminator = match transfer {
            Transfer::Return => Terminator::Return,
            Transfer::Goto(n) => {
                let target_leaf: &Block =
                    resolve_leaf(ctx.dispatch_root, ctx.pos_local, n, 0, &ctx.numbers).ok_or_else(
                        || refuse("goto target does not resolve to any dispatch leaf"),
                    )?;
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
                let taken_leaf: &Block =
                    resolve_leaf(ctx.dispatch_root, ctx.pos_local, taken, 0, &ctx.numbers)
                        .ok_or_else(|| {
                            refuse("branch taken-target does not resolve to any dispatch leaf")
                        })?;
                let not_taken_leaf: &Block =
                    resolve_leaf(ctx.dispatch_root, ctx.pos_local, not_taken, 0, &ctx.numbers)
                        .ok_or_else(|| {
                            refuse("branch not-taken-target does not resolve to any dispatch leaf")
                        })?;
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

    let terms: Vec<Terminator> = nodes.iter().map(|n: &CfgNode| n.term.clone()).collect();
    let boxes: FunctionBoxes = bind_function_boxes(
        ctx,
        &order,
        &visited,
        &node_of,
        &terms,
        &capture_parameters,
        subst,
        stats,
    )?;

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
        let Some(nested_entry) = number_of(entry_arg) else {
            return Err(refuse_owned(format!(
                "the closure-creation call at byte {} takes a non-literal entry point, so the closure body cannot be located in the dispatch tree",
                call_expr.span.start
            )));
        };
        let nested_upvalues: Vec<String> =
            closure_upvalue_names(ctx, upvals_arg, &boxes, &capture_parameters, subst)?;
        let proof: AntiTamperProof = proves_pinned_anti_tamper_call(
            call_expr.span,
            &leaf_of_node,
            &terms,
            ctx,
            subst,
            anti_tamper_cells,
        )?;
        let nested_anti_tamper_cells: BTreeMap<String, AntiTamperValue> = proof
            .candidate_state
            .as_ref()
            .into_iter()
            .flat_map(|state: &AntiTamperState| {
                nested_upvalues.iter().enumerate().filter_map(
                    |(index, identity): (usize, &String)| {
                        state
                            .cells
                            .get(&format!("{identity}[1]"))
                            .map(|value: &AntiTamperValue| {
                                (format!("__vuc{}_{index}[1]", depth + 1), *value)
                            })
                    },
                )
            })
            .collect();
        let recovered: RecoveredFunction = recover_function(
            ctx,
            nested_entry,
            depth + 1,
            &nested_upvalues,
            &nested_anti_tamper_cells,
            subst,
            stats,
            proof.parsed_line,
        )?;
        subst.insert(call_key, recovered.text);
    }

    let cfg: Cfg = Cfg::new(0, nodes).map_err(|e: disrobe_cfg::CfgError| {
        refuse_owned(format!(
            "recovered control-flow graph rejected by the structurer: {e:?}"
        ))
    })?;
    let budget: CnsBudget = CnsBudget::tight_for(&cfg);
    let outcome: Option<CnsOutcome> = structure_with_cns(&cfg, budget);

    let mut used_locals: BTreeSet<LocalId> = BTreeSet::new();
    for (leaf, plan) in leaf_of_node.iter().zip(&plan_of_node) {
        collect_rendered_locals(
            leaf,
            ctx.pos_local,
            ctx.return_local,
            plan,
            &captures,
            subst,
            &mut used_locals,
        );
    }
    used_locals.remove(&ctx.args_local);

    let mut leaked: Vec<String> = Vec::new();
    note_machinery_leak(
        ctx,
        &used_locals,
        ctx.upvals_local,
        "captured-variable table",
        &mut leaked,
    );
    if let Some(model) = ctx.box_model {
        note_machinery_leak(
            ctx,
            &used_locals,
            model.heap,
            "captured-variable store",
            &mut leaked,
        );
        note_machinery_leak(
            ctx,
            &used_locals,
            model.alloc,
            "captured-variable allocator",
            &mut leaked,
        );
        if let Some(release) = model.release {
            note_machinery_leak(
                ctx,
                &used_locals,
                release,
                "captured-variable release helper",
                &mut leaked,
            );
        }
    }
    if !leaked.is_empty() {
        return Err(refuse_owned(format!(
            "the recovered body still names the Vmify captured-variable machinery ({}), so at least one captured-variable access was not resolved to a real Lua variable",
            leaked.join(", ")
        )));
    }

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
            let name: &str =
                local_display_span(ctx.dispatch_root, *id, ctx.src).unwrap_or("<unnamed>");
            return Err(refuse_owned(format!(
                "local {id} ('{name}') is neither a container-scope register nor a recognized wrapper upvalue"
            )));
        }
    }
    if !register_names.is_empty() {
        prelude.push_str("local ");
        prelude.push_str(&register_names.join(", "));
        prelude.push_str(";\n");
    }
    if !boxes.declarations.is_empty() {
        prelude.push_str("local ");
        prelude.push_str(&boxes.declarations.join(", "));
        prelude.push_str(";\n");
    }

    let no_sinks: BTreeMap<u32, LoopSink> = BTreeMap::new();
    let (body_text, fully_structured, recovered_leaves): (String, bool, usize) = match outcome {
        Some(outcome) if outcome.result.is_complete() => {
            let mut renderer: RegionRenderer<'_, '_> = RegionRenderer {
                ctx,
                leaf_of_node: &leaf_of_node,
                terms: &terms,
                plan_of_node: &plan_of_node,
                captures: &captures,
                allocation_initializers: &boxes.allocation_initializers,
                cond_of_atom: &cond_of_atom,
                result: &outcome.result,
                subst,
                sinks: &no_sinks,
                loop_depth: 0,
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
                        &boxes.allocation_initializers,
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
                &boxes.allocation_initializers,
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
    if !upvalue_boxes.is_empty() {
        text = format!(
            "(function({})\nreturn {text}\nend)({})",
            capture_parameters.join(", "),
            upvalue_boxes.join(", ")
        );
    }
    if text.len() > crate::obfuscator::prometheus_vm_ast::MAX_SOURCE_BYTES {
        return Err(refuse(
            "a recovered closure exceeds the Vmify output byte budget",
        ));
    }

    stats.leaves_recovered += recovered_leaves;
    stats.reached.extend(order.iter().copied());
    if fully_structured {
        stats.functions_fully_structured += 1;
    }

    Ok(RecoveredFunction { text })
}

fn note_machinery_leak(
    ctx: &Ctx<'_>,
    used_locals: &BTreeSet<LocalId>,
    id: LocalId,
    role: &str,
    leaked: &mut Vec<String>,
) {
    if !used_locals.contains(&id) {
        return;
    }
    let name: &str = local_display_span(ctx.dispatch_root, id, ctx.src).unwrap_or("<unnamed>");
    leaked.push(format!("{role} '{name}'"));
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
    allocation_initializers: &BTreeMap<u64, String>,
    src: &str,
    subst: &BTreeMap<u64, String>,
) -> String {
    let mut out: String = String::new();
    for stat in &leaf.stats {
        if let Some(initializer) = allocation_initializers.get(&span_key(stat.span)) {
            out.push_str(initializer);
            out.push_str(";\n");
            continue;
        }
        if is_dropped_statement(stat, subst) {
            continue;
        }
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
            let aligned: bool = targets.len() == values.len();
            let stripped: usize = if aligned {
                targets
                    .iter()
                    .filter(|t: &&AssignTarget| {
                        matches!(t, AssignTarget::Var(Var::Local(id), _) if strip_here.contains(id))
                    })
                    .count()
            } else {
                0
            };
            if stripped == 0 {
                out.push_str(&render_expr_span_with_subst(stat.span, src, subst));
                out.push_str(";\n");
                continue;
            }
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
    allocation_initializers: &'b BTreeMap<u64, String>,
    cond_of_atom: &'b [String],
    result: &'b disrobe_cfg::StructureResult,
    subst: &'b BTreeMap<u64, String>,
    sinks: &'b BTreeMap<u32, LoopSink>,
    loop_depth: usize,
    ok: bool,
}

impl<'a> RegionRenderer<'a, '_> {
    fn render(&mut self, id: RegionId) -> String {
        if !self.ok {
            return String::new();
        }
        let Some(region): Option<Region> = self.result.regions.get(id as usize).cloned() else {
            self.ok = false;
            return String::new();
        };
        match region.kind {
            RegionKind::Block if region.children.is_empty() => {
                match self.sinks.get(&region.entry).copied() {
                    Some(LoopSink::Continue) => return String::new(),
                    Some(LoopSink::Break) => return "do break end;\n".to_owned(),
                    None => {}
                }
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
                    self.allocation_initializers,
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
            | RegionKind::SelfLoop => self.render_loop(region.entry),
            RegionKind::Switch | RegionKind::Proper | RegionKind::Irreducible => {
                self.ok = false;
                String::new()
            }
        }
    }

    fn decline(&mut self) -> String {
        self.ok = false;
        String::new()
    }

    fn render_loop(&mut self, header: u32) -> String {
        if self.loop_depth >= MAX_LOOP_NESTING {
            return self.decline();
        }
        let mut walk_budget: usize = MAX_REACHABILITY_STEPS;
        let Some(members): Option<BTreeSet<u32>> =
            loop_member_set(self.terms, header, &mut walk_budget)
        else {
            return self.decline();
        };
        if !members.contains(&header) || members.len() > MAX_FUNCTION_BLOCKS {
            return self.decline();
        }
        let mut exits: BTreeSet<u32> = BTreeSet::new();
        let mut succ: Vec<u32> = Vec::new();
        for node in &members {
            let Some(term): Option<&Terminator> = self.terms.get(*node as usize) else {
                return self.decline();
            };
            succ.clear();
            successors_of(term, &mut succ);
            for target in &succ {
                if !members.contains(target) {
                    exits.insert(*target);
                }
            }
        }
        if exits.len() > 1 {
            return self.decline();
        }
        let follow: Option<u32> = exits.iter().copied().next();
        let preds: BTreeMap<u32, Vec<u32>> = predecessors_of(self.terms);
        for node in &members {
            if *node == header {
                continue;
            }
            if preds.get(node).is_some_and(|incoming: &Vec<u32>| {
                incoming.iter().any(|from: &u32| !members.contains(from))
            }) {
                return self.decline();
            }
        }

        let mut order: Vec<u32> = vec![header];
        order.extend(members.iter().copied().filter(|node: &u32| *node != header));
        let index_of: BTreeMap<u32, u32> = order
            .iter()
            .enumerate()
            .map(|(position, node): (usize, &u32)| (*node, position as u32))
            .collect();
        let continue_index: u32 = order.len() as u32;
        let break_index: u32 = continue_index + 1;
        let remap = |target: u32| -> Option<u32> {
            if target == header {
                return Some(continue_index);
            }
            if let Some(position) = index_of.get(&target) {
                return Some(*position);
            }
            if Some(target) == follow {
                return Some(break_index);
            }
            None
        };

        let mut sub_nodes: Vec<CfgNode> = Vec::with_capacity(order.len() + 2);
        let mut sub_terms: Vec<Terminator> = Vec::with_capacity(order.len() + 2);
        let mut sub_leaves: Vec<&'a Block> = Vec::with_capacity(order.len() + 2);
        let mut sub_plans: Vec<LeafPlan> = Vec::with_capacity(order.len() + 2);
        for node in &order {
            let (Some(term), Some(leaf), Some(plan)) = (
                self.terms.get(*node as usize),
                self.leaf_of_node.get(*node as usize).copied(),
                self.plan_of_node.get(*node as usize),
            ) else {
                return self.decline();
            };
            let remapped: Terminator = match term {
                Terminator::Return => Terminator::Return,
                Terminator::Unreachable => Terminator::Unreachable,
                Terminator::Goto(target) => match remap(*target) {
                    Some(next) => Terminator::Goto(next),
                    None => return self.decline(),
                },
                Terminator::Branch {
                    atom,
                    taken,
                    not_taken,
                } => match (remap(*taken), remap(*not_taken)) {
                    (Some(taken), Some(not_taken)) => Terminator::Branch {
                        atom: *atom,
                        taken,
                        not_taken,
                    },
                    _ => return self.decline(),
                },
                Terminator::Switch { .. } => return self.decline(),
            };
            sub_nodes.push(CfgNode {
                term: remapped.clone(),
                pure: true,
            });
            sub_terms.push(remapped);
            sub_leaves.push(leaf);
            sub_plans.push(plan.clone());
        }
        let Some(entry_leaf): Option<&'a Block> = self.leaf_of_node.first().copied() else {
            return self.decline();
        };
        let mut sinks: BTreeMap<u32, LoopSink> = BTreeMap::new();
        sinks.insert(continue_index, LoopSink::Continue);
        sinks.insert(break_index, LoopSink::Break);
        for _ in 0..2 {
            sub_nodes.push(CfgNode {
                term: Terminator::Return,
                pure: true,
            });
            sub_terms.push(Terminator::Return);
            sub_leaves.push(entry_leaf);
            sub_plans.push(LeafPlan {
                pos_terminal_span: Span { start: 0, end: 0 },
                pos_chain_span: None,
                return_span: None,
                numeric_chain_spans: Vec::new(),
            });
        }

        let Ok(sub_cfg): std::result::Result<Cfg, disrobe_cfg::CfgError> = Cfg::new(0, sub_nodes)
        else {
            return self.decline();
        };
        let budget: CnsBudget = CnsBudget::tight_for(&sub_cfg);
        let Some(outcome): Option<CnsOutcome> = structure_with_cns(&sub_cfg, budget) else {
            return self.decline();
        };
        if !outcome.result.is_complete() {
            return self.decline();
        }
        let Some(root): Option<RegionId> = outcome.result.root else {
            return self.decline();
        };
        let mut tree_budget: usize = MAX_REGION_TREE_STEPS;
        let continue_ok: Option<bool> =
            sink_reached_only_at_tail(&outcome.result, root, continue_index, &mut tree_budget);
        if continue_ok != Some(true) {
            return self.decline();
        }
        if follow.is_some() {
            if region_contains_node(&outcome.result, root, break_index, &mut tree_budget)
                != Some(true)
            {
                return self.decline();
            }
        } else if region_contains_node(&outcome.result, root, break_index, &mut tree_budget)
            != Some(false)
        {
            return self.decline();
        }

        let mut sub: RegionRenderer<'a, '_> = RegionRenderer {
            ctx: self.ctx,
            leaf_of_node: &sub_leaves,
            terms: &sub_terms,
            plan_of_node: &sub_plans,
            captures: self.captures,
            allocation_initializers: self.allocation_initializers,
            cond_of_atom: self.cond_of_atom,
            result: &outcome.result,
            subst: self.subst,
            sinks: &sinks,
            loop_depth: self.loop_depth + 1,
            ok: true,
        };
        let rendered: Option<String> =
            sub.render_head_tested_loop(root, continue_index, break_index);
        let text: String = match rendered {
            Some(text) => text,
            None => {
                let body: String = sub.render(root);
                format!("while true do\n{body}\nend;\n")
            }
        };
        if !sub.ok {
            return self.decline();
        }
        text
    }

    fn render_head_tested_loop(
        &mut self,
        root: RegionId,
        continue_index: u32,
        break_index: u32,
    ) -> Option<String> {
        let region: Region = self.result.regions.get(root as usize).cloned()?;
        if !matches!(region.kind, RegionKind::IfThenElse) {
            return None;
        }
        let head: RegionId = region.head?;
        let cond_id: disrobe_cfg::CondId = region.cond?;
        let [taken, not_taken]: [RegionId; 2] = match region.children.as_slice() {
            [taken, not_taken] => [*taken, *not_taken],
            _ => return None,
        };
        let head_text: String = self.render(head);
        if !self.ok || !head_text.trim().is_empty() {
            return None;
        }
        let mut tree_budget: usize = MAX_REGION_TREE_STEPS;
        let (guard, body_id): (String, RegionId) =
            if is_sink_leaf(self.result, not_taken, break_index) {
                (
                    render_cond(self.cond_of_atom, &self.result.conds, cond_id)?,
                    taken,
                )
            } else if is_sink_leaf(self.result, taken, break_index) {
                (
                    negated_cond(self.cond_of_atom, &self.result.conds, cond_id)?,
                    not_taken,
                )
            } else {
                return None;
            };
        if region_contains_node(self.result, body_id, break_index, &mut tree_budget)? {
            return None;
        }
        if !sink_reached_only_at_tail(self.result, body_id, continue_index, &mut tree_budget)? {
            return None;
        }
        let body: String = self.render(body_id);
        if !self.ok {
            return None;
        }
        Some(format!("while {guard} do\n{body}\nend;\n"))
    }
}

fn render_dispatch_fallback(
    ctx: &Ctx<'_>,
    leaf_of_node: &[&Block],
    terms: &[Terminator],
    plan_of_node: &[LeafPlan],
    captures: &BTreeMap<u64, String>,
    allocation_initializers: &BTreeMap<u64, String>,
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
            allocation_initializers,
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

fn pool_resolver_shape(expr: &Expr, pool_locals: &BTreeSet<LocalId>) -> Option<f64> {
    let ExprKind::Function {
        params,
        is_vararg,
        body,
    } = &expr.kind
    else {
        return None;
    };
    if *is_vararg || params.len() != 1 {
        return None;
    }
    let [stat]: &[Stat] = body.stats.as_slice() else {
        return None;
    };
    let StatKind::Return(values) = &stat.kind else {
        return None;
    };
    let [value]: &[Expr] = values.as_slice() else {
        return None;
    };
    let ExprKind::Index(base, key) = &value.kind else {
        return None;
    };
    if !matches!(&base.kind, ExprKind::Var(Var::Local(id)) if pool_locals.contains(id)) {
        return None;
    }
    match &key.kind {
        ExprKind::Binary(BinOp::Add, left, right) if is_bare_local(left, params[0]) => {
            static_number_value(right)
        }
        ExprKind::Binary(BinOp::Add, left, right) if is_bare_local(right, params[0]) => {
            static_number_value(left)
        }
        ExprKind::Binary(BinOp::Sub, left, right) if is_bare_local(left, params[0]) => {
            static_number_value(right).map(|value: f64| -value)
        }
        _ => None,
    }
}

fn constant_pool_substitutions(
    text: &str,
    chunk: &Block,
    all_exprs: &[&Expr],
    function_exprs: &[&Expr],
    strings: &[String],
    resolved_entries: &[bool],
    pool_binding: Option<&str>,
) -> Result<BTreeMap<u64, String>> {
    let mut substitutions: BTreeMap<u64, String> = BTreeMap::new();
    let Some(pool_binding): Option<&str> = pool_binding else {
        return Ok(substitutions);
    };
    if strings.is_empty() {
        return Ok(substitutions);
    }
    if strings.len() != resolved_entries.len() {
        return Err(refuse(
            "the recovered string pool and resolution mask have different lengths",
        ));
    }
    let marker: String = format!("local {pool_binding}={{");
    let Some(table_start): Option<usize> = text
        .find(&marker)
        .and_then(|start: usize| start.checked_add(marker.len() - 1))
    else {
        return Ok(substitutions);
    };
    let pool_locals: BTreeSet<LocalId> = all_exprs
        .iter()
        .filter_map(|expr: &&Expr| {
            let ExprKind::Table(fields) = &expr.kind else {
                return None;
            };
            if expr.span.start as usize == table_start && fields.len() == strings.len() {
                find_local_binding(chunk, expr.span)
            } else {
                None
            }
        })
        .collect();
    let mut resolvers: BTreeMap<LocalId, f64> = BTreeMap::new();
    let mut resolver_shapes: usize = 0;
    for expr in function_exprs {
        let Some(offset): Option<f64> = pool_resolver_shape(expr, &pool_locals) else {
            continue;
        };
        resolver_shapes += 1;
        if resolver_shapes > MAX_CONSTANT_POOL_RESOLVERS {
            return Err(refuse(
                "the ConstantArray resolver count exceeds the recovery budget",
            ));
        }
        let Some(local): Option<LocalId> = find_local_binding(chunk, expr.span) else {
            continue;
        };
        resolvers.insert(local, offset);
    }
    let base85_alphabets: Vec<(char, BTreeMap<char, u8>)> = discover_base85_alphabets(text);
    if base85_alphabets.len() > MAX_CONSTANT_POOL_RESOLVERS {
        return Err(refuse(
            "the ConstantArray Base85 alphabet count exceeds the recovery budget",
        ));
    }
    let mut replacement_bytes: usize = 0;
    for expr in all_exprs {
        let ExprKind::Call { base, args } = &expr.kind else {
            continue;
        };
        let ExprKind::Var(Var::Local(resolver)) = &base.kind else {
            continue;
        };
        let Some(offset): Option<&f64> = resolvers.get(resolver) else {
            continue;
        };
        let [argument]: &[Expr] = args.as_slice() else {
            continue;
        };
        let Some(argument): Option<f64> = static_number_value(argument) else {
            continue;
        };
        let one_based: f64 = argument + offset;
        if !one_based.is_finite() || one_based.fract() != 0.0 || one_based < 1.0 {
            return Err(refuse("a static ConstantArray lookup has an invalid index"));
        }
        let index: usize = one_based as usize;
        let value: &String = strings.get(index - 1).ok_or_else(|| {
            refuse("a static ConstantArray lookup exceeds the recovered string pool")
        })?;
        let replacement: String = if resolved_entries[index - 1] {
            crate::decompile::lift::quote_lua_string(value)
        } else if base85_alphabets.is_empty() {
            continue;
        } else {
            let decoded: Vec<u8> = decode_unresolved_base85(value, &base85_alphabets)?
                .ok_or_else(|| {
                    refuse_owned(format!(
                        "the unresolved ConstantArray entry {index} ('{value}') cannot be decoded by the script's {} exact Base85 alphabet(s)",
                        base85_alphabets.len(),
                    ))
                })?;
            quote_lua_bytes(&decoded)
        };
        replacement_bytes = replacement_bytes
            .checked_add(replacement.len())
            .ok_or_else(|| refuse("ConstantArray substitutions exceed the output byte budget"))?;
        if replacement_bytes > crate::obfuscator::prometheus_vm_ast::MAX_SOURCE_BYTES {
            return Err(refuse(
                "ConstantArray substitutions exceed the output byte budget",
            ));
        }
        substitutions.insert(span_key(expr.span), replacement);
    }
    Ok(substitutions)
}

fn decode_unresolved_base85(
    encoded: &str,
    alphabets: &[(char, BTreeMap<char, u8>)],
) -> Result<Option<Vec<u8>>> {
    let mut chars: core::str::Chars<'_> = encoded.chars();
    let _: char = match chars.next() {
        Some(tag) => tag,
        None => return Ok(None),
    };
    let body: &str = chars.as_str();
    if body.is_empty() {
        return Ok(Some(Vec::new()));
    }
    if body.chars().count() % 5 == 1 {
        return Err(refuse(
            "an unresolved ConstantArray Base85 entry has an invalid one-symbol tail",
        ));
    }
    let mut candidates: BTreeSet<Vec<u8>> = BTreeSet::new();
    for (_, alphabet) in alphabets {
        if let Some(decoded) = decode_base85_variant(body, alphabet) {
            candidates.insert(decoded);
        }
    }
    match candidates.len() {
        0 => Ok(None),
        1 => Ok(candidates.into_iter().next()),
        _ => Err(refuse(
            "an unresolved ConstantArray entry decodes to different bytes under multiple script alphabets",
        )),
    }
}

fn quote_lua_bytes(bytes: &[u8]) -> String {
    let mut output: String = String::with_capacity(bytes.len().saturating_mul(4).saturating_add(2));
    output.push('"');
    for byte in bytes {
        match byte {
            b'"' => output.push_str("\\\""),
            b'\\' => output.push_str("\\\\"),
            0x20..=0x7e => output.push(char::from(*byte)),
            _ => output.push_str(&format!("\\{byte:03}")),
        }
    }
    output.push('"');
    output
}

fn assert_captured_variables_stay_in_scope(recovered: &str) -> Result<()> {
    let wrapped: String = format!("local __vmify_scope_probe = {recovered};");
    if wrapped.len() > crate::obfuscator::prometheus_vm_ast::MAX_SOURCE_BYTES {
        return Err(refuse(
            "the recovered source exceeds the captured-variable scope-check byte budget",
        ));
    }
    let mut parser: Parser<'_> = Parser::new(&wrapped)?;
    let chunk: Block = parser.parse_chunk()?;
    let mut exprs: Vec<&Expr> = Vec::new();
    walk_exprs(&chunk, &mut exprs);
    let mut escaped: Option<&str> = None;
    for expr in &exprs {
        if let ExprKind::Var(Var::Global(span)) = &expr.kind
            && span.text(&wrapped).starts_with(CAPTURED_VARIABLE_PREFIX)
        {
            escaped = Some(span.text(&wrapped));
            break;
        }
    }
    if escaped.is_none() {
        let mut targets: Vec<&AssignTarget> = Vec::new();
        walk_assign_targets(&chunk, &mut targets);
        for target in targets {
            if let AssignTarget::Var(Var::Global(span), _) = target
                && span.text(&wrapped).starts_with(CAPTURED_VARIABLE_PREFIX)
            {
                escaped = Some(span.text(&wrapped));
                break;
            }
        }
    }
    match escaped {
        None => Ok(()),
        Some(name) => Err(refuse_owned(format!(
            "the recovered source names captured variable {name} outside the block that declares it, so it would read as a global instead of the captured local"
        ))),
    }
}

pub fn recover(text: &str) -> Result<Option<VmifyRecovery>> {
    recover_with_string_pool(text, &[], &[], None)
}

pub fn recover_with_string_pool(
    text: &str,
    strings: &[String],
    resolved_entries: &[bool],
    pool_binding: Option<&str>,
) -> Result<Option<VmifyRecovery>> {
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
    let mut subst: BTreeMap<u64, String> = constant_pool_substitutions(
        text,
        &chunk,
        &all_exprs,
        &function_exprs,
        strings,
        resolved_entries,
        pool_binding,
    )?;

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
    let wrapper_span: Span = find_enclosing_function_span(&chunk, container.whole_span)
        .ok_or_else(|| {
            refuse("could not locate the wrapper closure that binds the Vmify container")
        })?;
    let upvalue_bindings: BTreeMap<LocalId, Span> = wrapper_upvalue_bindings(&chunk, wrapper_span)
        .ok_or_else(|| refuse("could not resolve the wrapper closure's own call-site arguments"))?;
    let post_dispatch: Option<(LocalId, LocalId)> = post_dispatch_return(&container)?;
    let post_dispatch_return_local: Option<LocalId> = match post_dispatch {
        Some((unpack_local, return_local)) => {
            let binding_span: Span = *upvalue_bindings.get(&unpack_local).ok_or_else(|| {
                refuse("the post-dispatch unpack helper has no exact binding in the wrapper call")
            })?;
            let binding: &Expr = all_exprs
                .iter()
                .copied()
                .find(|expression: &&Expr| expression.span == binding_span)
                .ok_or_else(|| {
                    refuse("the post-dispatch unpack helper binding cannot be located in the AST")
                })?;
            if !is_exact_unpack_alias(binding, text, &subst) {
                return Err(refuse(
                    "the post-dispatch return helper is not bound to the exact 'unpack or table.unpack' compatibility expression",
                ));
            }
            Some(return_local)
        }
        None => None,
    };
    let unpack_local: Option<LocalId> = post_dispatch.map(|(unpack, _): (LocalId, LocalId)| unpack);
    let environment_locals: BTreeSet<LocalId> = upvalue_bindings
        .iter()
        .filter_map(|(id, binding_span): (&LocalId, &Span)| {
            all_exprs
                .iter()
                .copied()
                .find(|expression: &&Expr| expression.span == *binding_span)
                .filter(|expression: &&Expr| is_exact_environment_alias(expression, text))
                .map(|_: &Expr| *id)
        })
        .collect();
    let numbers: StaticNumberEvaluator = StaticNumberEvaluator::new();
    let return_local: LocalId = find_return_local(
        container.dispatch_root,
        container.pos_local,
        &subst,
        &numbers,
        post_dispatch_return_local,
    )?;
    dbg_kv("prometheus_vmify.pos_local", || {
        container.pos_local.to_string()
    });
    dbg_kv("prometheus_vmify.args_local", || {
        container.args_local.to_string()
    });
    dbg_kv("prometheus_vmify.return_local", || return_local.to_string());
    let container_scope: BTreeSet<LocalId> = container_scope_locals(&container);

    let box_model: Option<BoxModel> = derive_box_model(&chunk, &function_exprs);
    let captures_upvalues: bool = all_creation_calls.iter().any(
        |(_, _, _, upvals_arg): &(&Expr, LocalId, &Expr, &Expr)| {
            matches!(&upvals_arg.kind, ExprKind::Table(fields) if !fields.is_empty())
        },
    );
    if captures_upvalues && box_model.is_none() {
        return Err(refuse(
            "this program creates a closure that captures a variable, but the Vmify reference-counted capture helpers could not be fingerprinted in this chunk, so no captured variable can be resolved to a real Lua variable",
        ));
    }
    dbg_kv("prometheus_vmify.box_model", || format!("{box_model:?}"));

    let ctx: Ctx<'_> = Ctx {
        src: text,
        pos_local: container.pos_local,
        args_local: container.args_local,
        upvals_local: container.upvals_local,
        return_local,
        dispatch_root: container.dispatch_root,
        container_span: container.whole_span,
        container_scope,
        upvalue_bindings,
        environment_locals,
        unpack_local,
        all_creation_calls,
        box_model,
        numbers,
    };

    let top_entry: f64 = find_top_level_entry(&ctx)?;
    let mut stats: GlobalStats = GlobalStats::default();
    let recovered: RecoveredFunction = recover_function(
        &ctx,
        top_entry,
        0,
        &[],
        &BTreeMap::new(),
        &mut subst,
        &mut stats,
        false,
    )?;
    if stats.boxes_bound > 0 {
        assert_captured_variables_stay_in_scope(&recovered.text)?;
    }

    let mut all_leaves: Vec<&Block> = Vec::new();
    collect_all_leaves(
        container.dispatch_root,
        container.pos_local,
        &mut all_leaves,
        0,
        &ctx.numbers,
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
        let Ok((transfer, _plan)) =
            terminal_transfer(leaf, ctx.pos_local, ctx.return_local, &subst, &ctx.numbers)
        else {
            if !leaf.stats.is_empty() {
                unclassified_leaves += 1;
            }
            continue;
        };
        if !stats.reached.contains(&leaf_ident(leaf)) {
            continue;
        }
        let targets: Vec<f64> = match transfer {
            Transfer::Return => Vec::new(),
            Transfer::Goto(n) => vec![n],
            Transfer::Branch {
                taken, not_taken, ..
            } => vec![taken, not_taken],
        };
        for target in targets {
            if let Some(target_leaf) = resolve_leaf(
                container.dispatch_root,
                container.pos_local,
                target,
                0,
                &ctx.numbers,
            ) {
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
            "a reached dispatch-tree leaf targets the leaf at byte {}, but the recovery walk did not visit that target",
            missed.stats.first().map_or(0, |s: &Stat| s.span.start)
        )));
    }
    for (_call_expr, _creator, entry_arg, _upvals_arg) in &ctx.all_creation_calls {
        let Some(entry) = number_of(entry_arg) else {
            continue;
        };
        let Some(entry_leaf) = resolve_leaf(
            container.dispatch_root,
            container.pos_local,
            entry,
            0,
            &ctx.numbers,
        ) else {
            continue;
        };
        if !entry_leaf.stats.is_empty() && !stats.reached.contains(&leaf_ident(entry_leaf)) {
            return Err(refuse_owned(format!(
                "a discovered closure-creation call targets instruction pointer {entry}, which resolves to a real dispatch leaf, but that leaf was never visited by any recovery pass despite carrying a static entry, the shape this pass would ordinarily recurse into"
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
    dbg_kv("prometheus_vmify.captured_variables", || {
        stats.boxes_bound.to_string()
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
    use std::fmt::Write;

    use super::*;

    fn local_value(source: &str) -> Expr {
        let mut parser: Parser<'_> = Parser::new(source).expect("parse source");
        let chunk: Block = parser.parse_chunk().expect("parse chunk");
        let [stat]: &[Stat] = chunk.stats.as_slice() else {
            panic!("expected one statement");
        };
        let StatKind::Local { values, .. } = &stat.kind else {
            panic!("expected a local declaration");
        };
        let [value]: &[Expr] = values.as_slice() else {
            panic!("expected one local value");
        };
        value.clone()
    }

    #[test]
    fn static_number_evaluation_refuses_unbounded_or_non_finite_work() {
        let nested: String = format!(
            "local value = {}1{}",
            "(".repeat(MAX_STATIC_NUMBER_DEPTH + 1),
            ")".repeat(MAX_STATIC_NUMBER_DEPTH + 1)
        );
        assert_eq!(static_number_value(&local_value(&nested)), None);
        assert_eq!(
            static_number_value(&local_value("local value = 1 / 0")),
            None
        );
        assert_eq!(
            static_number_value(&local_value("local value = 1 % 0")),
            None
        );
        assert_eq!(
            static_number_value(&local_value("local value = 1e308 ^ 2")),
            None
        );
        assert_eq!(
            static_number_value(&local_value("local value = 1e999")),
            None
        );
        assert_eq!(
            static_number_value(&local_value("local value = math.huge")),
            None
        );
        assert_eq!(
            static_number_value(&local_value("local value = tonumber('1')")),
            None
        );

        let mut source: String = String::new();
        for index in 0..=MAX_STATIC_NUMBER_FUEL {
            writeln!(&mut source, "local value{index} = {index}")
                .expect("writing to a string must succeed");
        }
        let mut parser: Parser<'_> = Parser::new(&source).expect("parse fuel fixture");
        let chunk: Block = parser.parse_chunk().expect("parse fuel fixture chunk");
        let expressions: Vec<&Expr> = chunk
            .stats
            .iter()
            .filter_map(|stat: &Stat| match &stat.kind {
                StatKind::Local { values, .. } => values.first(),
                _ => None,
            })
            .collect();
        assert_eq!(expressions.len(), MAX_STATIC_NUMBER_FUEL + 1);
        let evaluator: StaticNumberEvaluator = StaticNumberEvaluator::new();
        assert!(
            expressions[..MAX_STATIC_NUMBER_FUEL]
                .iter()
                .all(|expression: &&Expr| evaluator.evaluate(expression).is_some())
        );
        assert_eq!(
            evaluator.evaluate(expressions[MAX_STATIC_NUMBER_FUEL]),
            None
        );
    }

    #[test]
    fn static_number_evaluation_caches_completed_expression_trees() {
        let expression: Expr = local_value("local value = (8 * 7) + (9 % 4)");
        let evaluator: StaticNumberEvaluator = StaticNumberEvaluator::new();
        assert_eq!(evaluator.evaluate(&expression), Some(57.0));
        let remaining: usize = evaluator.fuel.get();
        assert_eq!(evaluator.evaluate(&expression), Some(57.0));
        assert_eq!(evaluator.fuel.get(), remaining);
    }

    #[test]
    fn box_generation_joins_preserve_release_and_refuse_alias_conflicts() {
        assert_eq!(
            merge_box_register_states(
                7,
                3,
                Some(BoxRegisterState::Live(11)),
                Some(BoxRegisterState::ReleasedNil),
            )
            .expect("a release path may join its own live generation"),
            Some(BoxRegisterState::MaybeLive(11))
        );
        assert_eq!(
            merge_box_register_states(7, 3, Some(BoxRegisterState::ReleasedNil), None,)
                .expect("a released nil may join an ordinary register value"),
            Some(BoxRegisterState::ReleasedOrOrdinary)
        );
        let conflicting_generations: Error = merge_box_register_states(
            7,
            3,
            Some(BoxRegisterState::Live(11)),
            Some(BoxRegisterState::Live(12)),
        )
        .expect_err("two live allocation sites must not alias one recovered cell");
        assert!(
            conflicting_generations
                .to_string()
                .contains("allocation generations 11 and 12")
        );
        let ordinary_overlap: Error =
            merge_box_register_states(7, 3, Some(BoxRegisterState::Live(11)), None).expect_err(
                "an ordinary value and a live handle require different representations",
            );
        assert!(ordinary_overlap.to_string().contains("ordinary value"));
    }

    #[test]
    fn refuses_a_capture_after_released_and_ordinary_paths_join() {
        let source: &str = concat!(
            "local heap, handle, creator\n",
            "local closure = creator(1, {handle})\n",
        );
        let mut parser: Parser<'_> = Parser::new(source).expect("parse capture fixture");
        let chunk: Block = parser.parse_chunk().expect("parse capture fixture chunk");
        let [locals, capture]: &[Stat] = chunk.stats.as_slice() else {
            panic!("expected local declarations and one capture statement");
        };
        let StatKind::Local { targets, .. } = &locals.kind else {
            panic!("expected local declarations");
        };
        let [heap, handle, creator]: &[LocalId] = targets.as_slice() else {
            panic!("expected heap, handle and creator locals");
        };
        let mut expressions: Vec<&Expr> = Vec::new();
        walk_exprs_stat(capture, &mut expressions);
        let handle_expression: &Expr = expressions
            .iter()
            .copied()
            .find(|expression: &&Expr| is_bare_local(expression, *handle))
            .expect("capture statement must reference the handle");
        let tracked: BTreeSet<LocalId> = BTreeSet::from([*handle]);
        let names: BTreeMap<u64, String> = BTreeMap::from([(11, "__vu0".to_owned())]);
        let unique_names: BTreeMap<LocalId, String> =
            BTreeMap::from([(*handle, "__vu0".to_owned())]);
        let capture_spans: BTreeSet<u64> = BTreeSet::from([span_key(handle_expression.span)]);
        let context: Ctx<'_> = Ctx {
            src: source,
            pos_local: *creator,
            args_local: *creator,
            upvals_local: *creator,
            return_local: *creator,
            dispatch_root: &chunk,
            container_span: Span {
                start: 0,
                end: u32::try_from(source.len()).expect("fixture length fits u32"),
            },
            container_scope: BTreeSet::new(),
            upvalue_bindings: BTreeMap::new(),
            environment_locals: BTreeSet::new(),
            unpack_local: None,
            all_creation_calls: Vec::new(),
            box_model: None,
            numbers: StaticNumberEvaluator::new(),
        };
        let rewrite: BoxRewriteContext<'_> = BoxRewriteContext {
            ctx: &context,
            model: BoxModel {
                heap: *heap,
                alloc: *creator,
                release: None,
            },
            tracked: &tracked,
            names: &names,
            unique_names: &unique_names,
            capture_spans: &capture_spans,
            upvalue_boxes: &[],
        };
        let joined: Option<BoxRegisterState> =
            merge_box_register_states(*handle, 2, Some(BoxRegisterState::ReleasedNil), None)
                .expect("merge released and ordinary paths");
        let mut state: BTreeMap<LocalId, BoxRegisterState> = BTreeMap::new();
        if let Some(joined) = joined {
            state.insert(*handle, joined);
        }
        let mut substitutions: BTreeMap<u64, String> = BTreeMap::new();
        let error: Error = rewrite_box_uses(&rewrite, capture, &state, &mut substitutions)
            .expect_err("a capture after a released-or-ordinary join must refuse");
        assert!(error.to_string().contains("released or ordinary"));
    }

    #[test]
    fn ordinary_overwrite_keeps_a_released_box_register_poisoned_for_later_capture() {
        let id: LocalId = 7;
        let tracked: BTreeSet<LocalId> = BTreeSet::from([id]);
        let definitions: BTreeSet<LocalId> = BTreeSet::from([id]);
        let mut state: BTreeMap<LocalId, BoxRegisterState> =
            BTreeMap::from([(id, BoxRegisterState::ReleasedOrOrdinary)]);
        apply_box_definitions(&mut state, &tracked, &definitions);
        assert_eq!(
            state.get(&id),
            Some(&BoxRegisterState::ReleasedOrOrdinary),
            "an ordinary overwrite must not erase the poison that makes a later closure capture refuse",
        );
    }

    #[test]
    fn lua_byte_literals_preserve_binary_values_and_digit_boundaries() {
        assert_eq!(
            quote_lua_bytes(&[0, b'1', b'"', b'\\', 31, 32, 126, 127, 255]),
            "\"\\0001\\\"\\\\\\031 ~\\127\\255\""
        );
    }

    #[test]
    fn base85_rejects_one_symbol_partial_groups() {
        let alphabet: BTreeMap<char, u8> = (0_u8..85)
            .map(|value: u8| (char::from(value + 33), value))
            .collect();
        let alphabets: Vec<(char, BTreeMap<char, u8>)> = vec![('=', alphabet)];
        for malformed in ["=!", "=!!!!!!"] {
            let error: Error = decode_unresolved_base85(malformed, &alphabets)
                .expect_err("a Base85 body with a one-symbol tail must refuse");
            assert!(error.to_string().contains("one-symbol tail"));
        }
    }

    #[test]
    fn anti_tamper_candidate_requires_the_full_line_iterator_and_parse_chain() {
        let source: &str = concat!(
            "local candidate, error_text, matcher, parser, unpacker\n",
            "local iterator = matcher(error_text, ':(%d*):')\n",
            "local matched = iterator()\n",
            "local unpacked = unpacker({matched})\n",
            "local parsed = parser(unpacked)\n",
        );
        let mut parser: Parser<'_> = Parser::new(source).expect("parse AntiTamper fixture");
        let chunk: Block = parser.parse_chunk().expect("parse AntiTamper chunk");
        let [locals, chain @ ..]: &[Stat] = chunk.stats.as_slice() else {
            panic!("expected locals and AntiTamper consumer chain");
        };
        let StatKind::Local { targets, .. } = &locals.kind else {
            panic!("expected local declarations");
        };
        let [candidate, error_text, _matcher, _parser, unpacker]: &[LocalId] = targets.as_slice()
        else {
            panic!("expected candidate, error text, matcher, parser and unpacker locals");
        };
        let context: Ctx<'_> = Ctx {
            src: source,
            pos_local: *candidate,
            args_local: *candidate,
            upvals_local: *candidate,
            return_local: *candidate,
            dispatch_root: &chunk,
            container_span: Span {
                start: 0,
                end: u32::try_from(source.len()).expect("fixture length fits u32"),
            },
            container_scope: BTreeSet::new(),
            upvalue_bindings: BTreeMap::new(),
            environment_locals: BTreeSet::new(),
            unpack_local: None,
            all_creation_calls: Vec::new(),
            box_model: None,
            numbers: StaticNumberEvaluator::new(),
        };
        let mut state: AntiTamperState = AntiTamperState {
            locals: BTreeMap::from([
                (*error_text, AntiTamperValue::ErrorString),
                (*unpacker, AntiTamperValue::UnpackFunction),
            ]),
            cells: BTreeMap::new(),
        };
        let candidate_span: Span = Span { start: 0, end: 0 };
        let mut fuel: usize = MAX_ANTITAMPER_PROOF_STEPS;
        let proved: bool = chain.iter().any(|statement: &Stat| {
            apply_anti_tamper_statement(
                statement,
                &mut state,
                candidate_span,
                &context,
                &BTreeMap::new(),
                &mut fuel,
            )
        });
        assert!(
            !proved,
            "an arbitrary function that accepts the error text and line pattern is not the pinned AntiTamper consumer",
        );
    }

    fn constant_pool_substitutions_for(
        source: &str,
        strings: &[String],
        resolved_entries: &[bool],
        binding: Option<&str>,
    ) -> Result<BTreeMap<u64, String>> {
        let mut parser: Parser<'_> = Parser::new(source)?;
        let chunk: Block = parser.parse_chunk()?;
        let mut expressions: Vec<&Expr> = Vec::new();
        walk_exprs(&chunk, &mut expressions);
        let functions: Vec<&Expr> = expressions
            .iter()
            .copied()
            .filter(|expression: &&Expr| matches!(expression.kind, ExprKind::Function { .. }))
            .collect();
        constant_pool_substitutions(
            source,
            &chunk,
            &expressions,
            &functions,
            strings,
            resolved_entries,
            binding,
        )
    }

    #[test]
    fn substitutes_only_exact_static_constant_pool_resolvers() {
        let source: &str = concat!(
            "local pool={\"encoded-a\", \"encoded-b\"}\n",
            "local resolve = function(index) return pool[index + 2] end\n",
            "local value = resolve(-1)\n",
        );
        let strings: Vec<String> = vec!["first".to_owned(), "second".to_owned()];
        let resolved_entries: Vec<bool> = vec![true, true];
        let substitutions: BTreeMap<u64, String> =
            constant_pool_substitutions_for(source, &strings, &resolved_entries, Some("pool"))
                .expect("substitute");
        assert_eq!(
            substitutions
                .values()
                .map(String::as_str)
                .collect::<Vec<&str>>(),
            vec!["\"first\""]
        );

        let wrong_binding: BTreeMap<u64, String> =
            constant_pool_substitutions_for(source, &strings, &resolved_entries, Some("other"))
                .expect("reject unrelated pool");
        assert!(wrong_binding.is_empty());

        let unresolved: Vec<bool> = vec![false, true];
        let unresolved_substitutions: BTreeMap<u64, String> =
            constant_pool_substitutions_for(source, &strings, &unresolved, Some("pool"))
                .expect("skip unresolved entry");
        assert!(unresolved_substitutions.is_empty());

        let mismatched: Error =
            constant_pool_substitutions_for(source, &strings, &[true], Some("pool"))
                .expect_err("mismatched resolution metadata must refuse recovery");
        assert!(mismatched.to_string().contains("different lengths"));
    }

    #[test]
    fn refuses_out_of_range_static_constant_pool_lookups() {
        let source: &str = concat!(
            "local pool={\"encoded-a\", \"encoded-b\"}\n",
            "local resolve = function(index) return pool[index + 2] end\n",
            "local value = resolve(8)\n",
        );
        let strings: Vec<String> = vec!["first".to_owned(), "second".to_owned()];
        let resolved_entries: Vec<bool> = vec![true, true];
        let error: Error =
            constant_pool_substitutions_for(source, &strings, &resolved_entries, Some("pool"))
                .expect_err("out-of-range lookup must refuse recovery");
        assert!(
            error
                .to_string()
                .contains("exceeds the recovered string pool")
        );

        let output_source: &str = concat!(
            "local pool={\"encoded-a\", \"encoded-b\"}\n",
            "local resolve = function(index) return pool[index + 2] end\n",
            "local value = resolve(-1)\n",
        );
        let oversized_strings: Vec<String> = vec![
            "a".repeat(crate::obfuscator::prometheus_vm_ast::MAX_SOURCE_BYTES),
            "second".to_owned(),
        ];
        let oversized: Error = constant_pool_substitutions_for(
            output_source,
            &oversized_strings,
            &resolved_entries,
            Some("pool"),
        )
        .expect_err("oversized substitutions must refuse recovery");
        assert!(oversized.to_string().contains("output byte budget"));
    }

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
    fn refuses_a_post_dispatch_return_helper_that_is_not_the_unpack_alias() {
        let src: &str =
            include_str!("../../../../corpus/lua/prometheus/vmify_simple/obfuscated.lua");
        let mutated: String = src.replacen("unpack or table.unpack", "select or table.unpack", 1);
        assert_ne!(mutated, src);
        let error: Error = recover(&mutated)
            .expect_err("a post-dispatch return through an unrelated helper must refuse");
        assert!(
            error
                .to_string()
                .contains("post-dispatch return helper is not bound to the exact"),
            "the refusal must name the incompatible return helper: {error}"
        );
    }

    #[test]
    fn does_not_rewrite_an_ordinary_one_leaf_function_that_raises_an_arithmetic_error() {
        let source: &str =
            include_str!("../../../../corpus/lua/prometheus/vmify_upvalue/obfuscated.lua");
        let mutated: String = source.replacen("X,k=W[1],f", "X,k=\"ordinary\"^2,f", 1);
        assert_ne!(mutated, source);
        let recovered: VmifyRecovery = recover(&mutated)
            .expect("recover ordinary arithmetic-error fixture")
            .expect("detect ordinary arithmetic-error fixture");
        assert!(recovered.fully_recovered);
        assert_eq!(recovered.handlers_recovered, recovered.handlers_total);
        assert_eq!(recovered.functions_recovered, recovered.functions_total);
        assert!(recovered.source.contains("\"ordinary\"^2"));
        assert!(!recovered.source.contains("function() error("));
    }

    #[test]
    fn recovers_a_real_double_vmify_sample_through_both_layers() {
        let src: &str =
            include_str!("../../../../corpus/lua/prometheus/vmify_nested/obfuscated.lua");
        let out: VmifyRecovery = recover(src)
            .expect("a sample put through Vmify twice must recover")
            .expect("must detect as Vmify");
        assert_eq!(
            (out.handlers_recovered, out.handlers_total),
            (49, 49),
            "every dispatch leaf reached across both layers must be structured: {}",
            out.source
        );
        assert_eq!(
            (out.functions_recovered, out.functions_total),
            (13, 13),
            "both layers together define thirteen closures and each must reach clean structuring"
        );
        assert!(out.fully_recovered);
        assert!(
            !out.source.contains("__pc"),
            "neither layer may be left as an instruction-pointer state machine: {}",
            out.source
        );
        assert!(
            !out.source.contains("prometheus-vmify:"),
            "a fully recovered program must carry none of this pass's own refusal stubs: {}",
            out.source
        );
    }

    #[test]
    fn recovers_a_real_vmify_closure_that_captures_a_local() {
        let src: &str =
            include_str!("../../../../corpus/lua/prometheus/vmify_upvalue/obfuscated.lua");
        let out: VmifyRecovery = recover(src)
            .expect("recover")
            .expect("must detect as Vmify");
        assert_eq!(
            (out.functions_recovered, out.functions_total),
            (3, 3),
            "the sample defines the chunk, the factory and the captured-variable closure, and all three must reach clean structuring"
        );
        assert_eq!(
            (out.handlers_recovered, out.handlers_total),
            (3, 3),
            "the closure's own dispatch leaf must be walked, not left unreached"
        );
        assert_eq!(
            out.unreached_structural_leaves, 0,
            "no dispatch leaf may be written off as dead when it is a closure body"
        );
        assert!(out.fully_recovered);
        assert!(
            !out.source.contains("prometheus-vmify:"),
            "a fully recovered program must carry none of this pass's own refusal stubs: {}",
            out.source
        );
        let declaration: usize = out.source.matches("local __vu0;").count();
        assert_eq!(
            declaration, 1,
            "the captured variable must be declared exactly once, in the scope that allocates it, so the closure captures it by reference: {}",
            out.source
        );
        assert!(out.source.contains("__vu0 = {};"), "{}", out.source);
        assert!(out.source.contains("end)(__vu0)"), "{}", out.source);
        assert!(out.source.contains("__vuc2_0[1]"), "{}", out.source);
    }

    #[test]
    fn declares_a_per_iteration_capture_inside_the_loop_that_allocates_it() {
        let src: &str =
            include_str!("../../../../corpus/lua/prometheus/vmify_loop_capture/obfuscated.lua");
        let out: VmifyRecovery = recover(src)
            .expect("a per-iteration capture must recover")
            .expect("must detect as Vmify");
        assert!(out.fully_recovered);
        let declaration: usize = out.source.matches("local __vu0;").count();
        assert_eq!(
            declaration, 1,
            "the captured variable must be declared exactly once: {}",
            out.source
        );
        let loop_start: usize = out
            .source
            .find("while ")
            .expect("the guest loop must appear as a Lua loop");
        let initialized_at: usize = out
            .source
            .find("__vu0 = {};")
            .expect("the captured cell must be initialized");
        assert!(
            initialized_at > loop_start,
            "each iteration must allocate a fresh cell inside the guest loop: {}",
            out.source
        );
        assert!(out.source.contains("end)(__vu0)"), "{}", out.source);
    }

    #[test]
    fn refuses_a_vmify_capture_whose_reference_counted_helpers_are_absent() {
        let src: &str =
            include_str!("../../../../corpus/lua/prometheus/vmify_upvalue/obfuscated.lua");
        let stripped: String = src.replace("X[K]=X[K]-1 if X[K]==0 then X[K],x[K]=nil,nil end", "");
        assert_ne!(
            stripped, src,
            "the release helper must be present in the fixture for this test to mean anything"
        );
        let err: Error = recover(&stripped)
            .expect_err("a chunk that captures a variable but has no fingerprintable capture helpers must refuse");
        assert!(
            err.to_string()
                .contains("the Vmify reference-counted capture helpers could not be fingerprinted"),
            "the refusal must name the missing helper rather than emit a stub, got: {err}"
        );
    }

    #[test]
    fn recovers_a_real_loop_bearing_prometheus_vmify_sample_as_a_lua_loop() {
        let src: &str = include_str!("../../../../corpus/lua/prometheus/vmify/obfuscated.lua");
        let out: VmifyRecovery = recover(src)
            .expect("recover")
            .expect("must detect as Vmify");
        assert_eq!(
            (out.handlers_recovered, out.handlers_total),
            (8, 8),
            "every reached dispatch leaf must be structured: {}",
            out.source
        );
        assert!(out.fully_recovered);
        assert!(
            out.source.contains("while "),
            "the guest loop must recover as a Lua loop: {}",
            out.source
        );
        assert!(
            !out.source.contains("__pc"),
            "a guest loop must not be left as an instruction-pointer state machine: {}",
            out.source
        );
    }

    #[test]
    fn loop_membership_stops_at_its_step_budget() {
        let terms: Vec<Terminator> = vec![Terminator::Goto(1), Terminator::Goto(0)];
        let mut generous: usize = MAX_REACHABILITY_STEPS;
        assert_eq!(
            loop_member_set(&terms, 0, &mut generous),
            Some(BTreeSet::from([0, 1])),
            "a two-node cycle is one loop body"
        );
        let mut exhausted: usize = 1;
        assert_eq!(
            loop_member_set(&terms, 0, &mut exhausted),
            None,
            "an exhausted step budget must stop the walk rather than run to completion"
        );
    }

    #[test]
    fn region_tree_predicates_stop_at_their_step_budget() {
        let cfg: Cfg = Cfg::new(
            0,
            vec![
                CfgNode {
                    term: Terminator::Branch {
                        atom: 0,
                        taken: 1,
                        not_taken: 2,
                    },
                    pure: true,
                },
                CfgNode {
                    term: Terminator::Goto(2),
                    pure: true,
                },
                CfgNode {
                    term: Terminator::Return,
                    pure: true,
                },
            ],
        )
        .expect("a three-node if-then graph is well formed");
        let outcome: CnsOutcome =
            structure_with_cns(&cfg, CnsBudget::tight_for(&cfg)).expect("structuring must succeed");
        let root: RegionId = outcome.result.root.expect("a complete result has a root");
        let mut exhausted: usize = 0;
        assert_eq!(
            region_contains_node(&outcome.result, root, 2, &mut exhausted),
            None,
            "an exhausted budget must stop the containment walk"
        );
        let mut also_exhausted: usize = 0;
        assert_eq!(
            sink_reached_only_at_tail(&outcome.result, root, 2, &mut also_exhausted),
            None,
            "an exhausted budget must stop the tail-position walk"
        );
        let mut generous: usize = MAX_REGION_TREE_STEPS;
        assert_eq!(
            region_contains_node(&outcome.result, root, 2, &mut generous),
            Some(true),
            "the walk must find a node the region really contains when the budget allows it"
        );
    }
}
