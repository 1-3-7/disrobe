//! Re-sugars BEAM-lowered list comprehensions back to surface `[Expr || Quals]`.
//!
//! The OTP compiler lowers `[Expr || X <- List, Filters]` into a local recursive
//! helper named `'-Parent/Arity-lc$^N/M-K-'` whose body is the canonical
//! cons/nil/`bad_generator` recursion:
//!
//! ```erlang
//! '-f/1-lc$^0/1-0-'(L) ->
//!     if is_list(L) andalso L =/= [] ->
//!            if <Filter1> -> if <Filter2> -> [<Elem> | recurse(tl(L))];
//!                                    true -> recurse(tl(L)) end;
//!                  true -> recurse(tl(L)) end;
//!        L =:= [] -> L;
//!        true -> error({bad_generator, L}) end.
//! ```
//!
//! This pass recognizes the single-generator shape, reconstructs the element
//! expression and filter list with the register source rewritten to a recovered
//! generator variable, and rewrites the helper call site to the surface
//! comprehension while dropping the now-inlined helper. Nested (`lc$^1` chaining)
//! and binary (`lbc$`) comprehensions are left as their faithful, recompilable
//! recursion.

use crate::body_lift::expr::{Expr, IfArm, Stmt};
use crate::body_lift::render::render_expr;
use crate::core_erlang::{CoreClause, CoreFunction, CoreModule};

/// Rewrites recognizable single-generator list-comprehension helper calls into
/// surface `[Expr || X <- Src, Filters]` and removes the inlined helpers.
pub fn resugar_module(core: &mut CoreModule) {
    let resugared: Vec<(String, u32, ComprehensionShape)> = core
        .functions
        .iter()
        .filter(|f: &&CoreFunction| is_lc_helper(&f.name))
        .filter_map(|f: &CoreFunction| {
            analyze(f).map(|s: ComprehensionShape| (f.name.clone(), f.arity, s))
        })
        .collect();
    if resugared.is_empty() {
        return;
    }
    for (name, arity, shape) in &resugared {
        for f in &mut core.functions {
            if is_lc_helper(&f.name) {
                continue;
            }
            for clause in &mut f.clauses {
                rewrite_calls(&mut clause.body.stmts, name, *arity, shape);
            }
        }
    }
    let removed: std::collections::BTreeSet<String> = resugared
        .into_iter()
        .map(|(n, _, _): (String, u32, ComprehensionShape)| n)
        .collect();
    core.functions
        .retain(|f: &CoreFunction| !removed.contains(&f.name));
}

#[derive(Debug, Clone)]
struct ComprehensionShape {
    element: Expr,
    filters: Vec<Expr>,
    source_reg: String,
}

fn is_lc_helper(name: &str) -> bool {
    name.contains("-lc$^") && !name.contains("-lc$^1")
}

/// Analyzes a list-comprehension helper. The helper takes the generator list in
/// its first parameter `X0`; the recovered element is the cons head, the filters
/// are the guards of the nested `if` arms that lead to the cons, and the source
/// register is `X0` (rewritten to the call argument at the call site).
fn analyze(f: &CoreFunction) -> Option<ComprehensionShape> {
    let [clause]: &[CoreClause] = f.clauses.as_slice() else {
        return None;
    };
    let [Stmt::Return(Expr::If { arms })] = clause.body.stmts.as_slice() else {
        return None;
    };
    let cons_arm: &IfArm = arms.first()?;
    if !is_nonempty_list_guard(&cons_arm.guard, "X0") {
        return None;
    }
    let mut filters: Vec<Expr> = Vec::new();
    let element: Expr = descend(&cons_arm.body, &f.name, &mut filters)?;
    let shape: ComprehensionShape = ComprehensionShape {
        element,
        filters,
        source_reg: "X0".to_owned(),
    };
    let genv: String = "G".to_owned();
    let leftover: bool = mentions_hd(&substitute(&shape.element, &shape.source_reg, &genv), "X0")
        || shape
            .filters
            .iter()
            .any(|fl: &Expr| mentions_hd(&substitute(fl, &shape.source_reg, &genv), "X0"));
    if leftover {
        return None;
    }
    Some(shape)
}

/// Whether a `hd(<reg>)` reference survives substitution — a signal that the
/// generator binds a destructuring pattern (e.g. `{K, V} <- Pairs`) the
/// single-variable resugarer cannot faithfully recover; decline rather than
/// emit a subtly-wrong comprehension.
fn mentions_hd(expr: &Expr, reg: &str) -> bool {
    match expr {
        Expr::Guard { name, args } if name == "hd" => {
            matches!(args.first(), Some(Expr::Var(v)) if v == reg)
        }
        Expr::Guard { args, .. } | Expr::Call { args, .. } => {
            args.iter().any(|e: &Expr| mentions_hd(e, reg))
        }
        Expr::Tuple(items) => items.iter().any(|e: &Expr| mentions_hd(e, reg)),
        Expr::List { elements, tail } => {
            elements.iter().any(|e: &Expr| mentions_hd(e, reg)) || mentions_hd(tail, reg)
        }
        Expr::Cons { head, tail } => mentions_hd(head, reg) || mentions_hd(tail, reg),
        Expr::BinOp { lhs, rhs, .. } => mentions_hd(lhs, reg) || mentions_hd(rhs, reg),
        Expr::UnOp { operand, .. } => mentions_hd(operand, reg),
        Expr::TupleElement { tuple, .. } => mentions_hd(tuple, reg),
        _ => false,
    }
}

/// Walks the nested filter `if`s collecting each filter guard, until it reaches
/// the cons `[Elem | recurse(tl(Src))]` that yields the element expression.
fn descend(body: &[Stmt], helper: &str, filters: &mut Vec<Expr>) -> Option<Expr> {
    match body {
        [Stmt::Return(Expr::If { arms })] => {
            let arm: &IfArm = arms.first()?;
            if is_true_guard(&arm.guard) {
                return None;
            }
            filters.push(arm.guard.clone());
            descend(&arm.body, helper, filters)
        }
        [Stmt::Return(Expr::Cons { head, tail })] => {
            is_recurse_on_tail(tail, helper).then(|| (**head).clone())
        }
        [Stmt::Return(Expr::List { elements, tail })] if elements.len() == 1 => {
            is_recurse_on_tail(tail, helper).then(|| elements[0].clone())
        }
        _ => None,
    }
}

fn is_nonempty_list_guard(guard: &Expr, reg: &str) -> bool {
    matches!(guard, Expr::BinOp { op, lhs, .. }
        if op == "andalso"
            && matches!(&**lhs, Expr::Guard { name, args }
                if name == "is_list"
                    && matches!(args.first(), Some(Expr::Var(v)) if v == reg)))
}

fn is_true_guard(guard: &Expr) -> bool {
    matches!(guard, Expr::Atom(a) if a == "true")
}

/// The comprehension recursion tail is `helper(tl(Src), ...captured)`.
fn is_recurse_on_tail(tail: &Expr, helper: &str) -> bool {
    matches!(tail, Expr::Call { target, args }
        if strip_quotes(target) == helper
            && matches!(args.first(), Some(Expr::Guard { name, .. }) if name == "tl"))
}

fn strip_quotes(s: &str) -> &str {
    s.strip_prefix('\'')
        .and_then(|t: &str| t.strip_suffix('\''))
        .unwrap_or(s)
}

/// Rewrites every `helper(Src, ..captured)` call in a statement tree to the
/// surface comprehension `[Elem' || G <- Src, Filters']`, substituting the
/// recovered generator variable for `hd(Src_reg)` and `Src` for the source.
fn rewrite_calls(stmts: &mut [Stmt], helper: &str, _arity: u32, shape: &ComprehensionShape) {
    for stmt in stmts.iter_mut() {
        match stmt {
            Stmt::Return(e) | Stmt::Expr(e) => rewrite_expr(e, helper, shape),
            Stmt::Bind { value, .. } | Stmt::Match { value, .. } => {
                rewrite_expr(value, helper, shape);
            }
            Stmt::Send { dest, msg } => {
                rewrite_expr(dest, helper, shape);
                rewrite_expr(msg, helper, shape);
            }
            Stmt::Comment(_) => {}
        }
    }
}

fn rewrite_expr(expr: &mut Expr, helper: &str, shape: &ComprehensionShape) {
    if let Expr::Call { target, args } = expr
        && strip_quotes(target) == helper
        && let Some(src) = args.first()
    {
        *expr = render_comprehension(shape, src);
        return;
    }
    descend_expr(expr, helper, shape);
}

fn descend_expr(expr: &mut Expr, helper: &str, shape: &ComprehensionShape) {
    match expr {
        Expr::Tuple(items) => {
            for e in items.iter_mut() {
                rewrite_expr(e, helper, shape);
            }
        }
        Expr::List { elements, tail } => {
            for e in elements.iter_mut() {
                rewrite_expr(e, helper, shape);
            }
            rewrite_expr(tail, helper, shape);
        }
        Expr::Cons { head, tail } => {
            rewrite_expr(head, helper, shape);
            rewrite_expr(tail, helper, shape);
        }
        Expr::Call { args, .. } | Expr::Guard { args, .. } => {
            for e in args.iter_mut() {
                rewrite_expr(e, helper, shape);
            }
        }
        Expr::BinOp { lhs, rhs, .. } => {
            rewrite_expr(lhs, helper, shape);
            rewrite_expr(rhs, helper, shape);
        }
        Expr::UnOp { operand, .. } => rewrite_expr(operand, helper, shape),
        _ => {}
    }
}

/// Builds the `[Elem || G <- Src, Filters]` surface string, substituting the
/// fresh generator variable `G` for `hd(X0)` and the call source for `X0`.
fn render_comprehension(shape: &ComprehensionShape, src: &Expr) -> Expr {
    let gen_var: String = "G".to_owned();
    let element: String = render_expr(&substitute(&shape.element, &shape.source_reg, &gen_var));
    let filters: Vec<String> = shape
        .filters
        .iter()
        .map(|f: &Expr| render_expr(&substitute(f, &shape.source_reg, &gen_var)))
        .collect();
    let source: String = render_expr(src);
    let mut quals: Vec<String> = vec![format!("{gen_var} <- {source}")];
    quals.extend(filters);
    Expr::Raw(format!("[{element} || {}]", quals.join(", ")))
}

/// Replaces `hd(<reg>)` with the generator variable `genv` throughout an
/// expression (the lowered comprehension reads the current element as `hd(L)`).
fn substitute(expr: &Expr, reg: &str, genv: &str) -> Expr {
    if let Expr::Guard { name, args } = expr
        && name == "hd"
        && matches!(args.first(), Some(Expr::Var(v)) if v == reg)
    {
        return Expr::Var(genv.to_owned());
    }
    match expr {
        Expr::Tuple(items) => Expr::Tuple(
            items
                .iter()
                .map(|e: &Expr| substitute(e, reg, genv))
                .collect(),
        ),
        Expr::List { elements, tail } => Expr::List {
            elements: elements
                .iter()
                .map(|e: &Expr| substitute(e, reg, genv))
                .collect(),
            tail: Box::new(substitute(tail, reg, genv)),
        },
        Expr::Cons { head, tail } => Expr::Cons {
            head: Box::new(substitute(head, reg, genv)),
            tail: Box::new(substitute(tail, reg, genv)),
        },
        Expr::Call { target, args } => Expr::Call {
            target: target.clone(),
            args: args
                .iter()
                .map(|e: &Expr| substitute(e, reg, genv))
                .collect(),
        },
        Expr::Guard { name, args } => Expr::Guard {
            name: name.clone(),
            args: args
                .iter()
                .map(|e: &Expr| substitute(e, reg, genv))
                .collect(),
        },
        Expr::BinOp { op, lhs, rhs } => Expr::BinOp {
            op: op.clone(),
            lhs: Box::new(substitute(lhs, reg, genv)),
            rhs: Box::new(substitute(rhs, reg, genv)),
        },
        Expr::UnOp { op, operand } => Expr::UnOp {
            op: op.clone(),
            operand: Box::new(substitute(operand, reg, genv)),
        },
        other => other.clone(),
    }
}
