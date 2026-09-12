use crate::body_lift::expr::{AfterClause, BinSegment, CatchArm, Expr, IfArm, Stmt};
use crate::body_lift::render::render_expr;
use crate::core_erlang::{CoreClause, CoreFunction, CoreModule};

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

    tuple_arity: Option<u32>,
}

fn is_lc_helper(name: &str) -> bool {
    name.contains("-lc$^") && !name.contains("-lc$^1")
}

fn analyze(f: &CoreFunction) -> Option<ComprehensionShape> {
    if f.arity != 1 {
        return None;
    }
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

    let tuple_arity: Option<u32> = filters
        .first()
        .and_then(|g: &Expr| tuple_pattern_arity(g, "X0"));
    if tuple_arity.is_some() {
        filters.remove(0);
    }
    let shape: ComprehensionShape = ComprehensionShape {
        element,
        filters,
        source_reg: "X0".to_owned(),
        tuple_arity,
    };
    if remaining_hd(&shape) {
        return None;
    }
    let subst_element: Expr = apply_generator(&shape.element, &shape);
    let references_capture: bool = mentions_foreign_var(&subst_element)
        || shape
            .filters
            .iter()
            .any(|fl: &Expr| mentions_foreign_var(&apply_generator(fl, &shape)));
    if references_capture {
        return None;
    }
    Some(shape)
}

fn mentions_foreign_var(expr: &Expr) -> bool {
    match expr {
        Expr::Var(v) => {
            (v.starts_with('X') || v.starts_with('Y'))
                && v[1..].chars().all(|c: char| c.is_ascii_digit())
                && v.len() > 1
        }
        Expr::Tuple(items) => items.iter().any(mentions_foreign_var),
        Expr::List { elements, tail } => {
            elements.iter().any(mentions_foreign_var) || mentions_foreign_var(tail)
        }
        Expr::Cons { head, tail } => mentions_foreign_var(head) || mentions_foreign_var(tail),
        Expr::Call { args, .. } | Expr::Guard { args, .. } => args.iter().any(mentions_foreign_var),
        Expr::CallFun { fun, args } => {
            mentions_foreign_var(fun) || args.iter().any(mentions_foreign_var)
        }
        Expr::BinOp { lhs, rhs, .. } => mentions_foreign_var(lhs) || mentions_foreign_var(rhs),
        Expr::UnOp { operand, .. } => mentions_foreign_var(operand),
        Expr::TupleElement { tuple, .. } => mentions_foreign_var(tuple),
        _ => false,
    }
}

fn remaining_hd(shape: &ComprehensionShape) -> bool {
    mentions_hd(&apply_generator(&shape.element, shape), "X0")
        || shape
            .filters
            .iter()
            .any(|fl: &Expr| mentions_hd(&apply_generator(fl, shape), "X0"))
}

fn tuple_pattern_arity(guard: &Expr, reg: &str) -> Option<u32> {
    let Expr::BinOp { op, lhs, rhs } = guard else {
        return None;
    };
    if op != "andalso" {
        return None;
    }
    let is_tuple_hd: bool = matches!(&**lhs, Expr::Guard { name, args }
        if name == "is_tuple" && is_hd_of(args.first(), reg));
    if !is_tuple_hd {
        return None;
    }
    match &**rhs {
        Expr::BinOp {
            op: eq,
            lhs: size,
            rhs: n,
        } if eq == "=:=" => {
            let size_ok: bool = matches!(&**size, Expr::Guard { name, args }
                if name == "tuple_size" && is_hd_of(args.first(), reg));
            match (&size_ok, &**n) {
                (true, Expr::Int(v)) => u32::try_from(*v).ok().filter(|a: &u32| *a >= 1),
                _ => None,
            }
        }
        _ => None,
    }
}

fn is_hd_of(arg: Option<&Expr>, reg: &str) -> bool {
    matches!(arg, Some(Expr::Guard { name, args })
        if name == "hd" && matches!(args.first(), Some(Expr::Var(v)) if v == reg))
}

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
        Expr::CallFun { fun, args } => {
            rewrite_expr(fun, helper, shape);
            for e in args.iter_mut() {
                rewrite_expr(e, helper, shape);
            }
        }
        Expr::Catch(inner) => rewrite_expr(inner, helper, shape),
        Expr::TupleElement { tuple, .. } => rewrite_expr(tuple, helper, shape),
        Expr::RecordUpdate { base, updates } => {
            rewrite_expr(base, helper, shape);
            for (_, v) in updates.iter_mut() {
                rewrite_expr(v, helper, shape);
            }
        }
        Expr::Map { pairs } | Expr::MapPattern { pairs } => rewrite_pairs(pairs, helper, shape),
        Expr::MapUpdate { base, pairs, .. } => {
            rewrite_expr(base, helper, shape);
            rewrite_pairs(pairs, helper, shape);
        }
        Expr::BinaryConstruct(segments) => {
            for seg in segments.iter_mut() {
                rewrite_segment(seg, helper, shape);
            }
        }
        Expr::Block(stmts) => rewrite_calls(stmts, helper, 0, shape),
        Expr::Case { subject, arms } => {
            rewrite_expr(subject, helper, shape);
            for arm in arms.iter_mut() {
                rewrite_calls(&mut arm.body, helper, 0, shape);
            }
        }
        Expr::If { arms } => {
            for arm in arms.iter_mut() {
                rewrite_expr(&mut arm.guard, helper, shape);
                rewrite_calls(&mut arm.body, helper, 0, shape);
            }
        }
        Expr::Receive { arms, after } => {
            for arm in arms.iter_mut() {
                rewrite_calls(&mut arm.body, helper, 0, shape);
            }
            if let Some(after) = after.as_deref_mut() {
                rewrite_after(after, helper, shape);
            }
        }
        Expr::Try {
            body,
            of_arms,
            catch_arms,
            after,
        } => {
            rewrite_calls(body, helper, 0, shape);
            for arm in of_arms.iter_mut() {
                rewrite_calls(&mut arm.body, helper, 0, shape);
            }
            for arm in catch_arms.iter_mut() {
                rewrite_catch(arm, helper, shape);
            }
            rewrite_calls(after, helper, 0, shape);
        }
        _ => {}
    }
}

fn rewrite_pairs(pairs: &mut [(Expr, Expr)], helper: &str, shape: &ComprehensionShape) {
    for (k, v) in pairs.iter_mut() {
        rewrite_expr(k, helper, shape);
        rewrite_expr(v, helper, shape);
    }
}

fn rewrite_segment(seg: &mut BinSegment, helper: &str, shape: &ComprehensionShape) {
    rewrite_expr(&mut seg.value, helper, shape);
    if let Some(size) = seg.size.as_deref_mut() {
        rewrite_expr(size, helper, shape);
    }
}

fn rewrite_after(after: &mut AfterClause, helper: &str, shape: &ComprehensionShape) {
    rewrite_expr(&mut after.timeout, helper, shape);
    rewrite_calls(&mut after.body, helper, 0, shape);
}

fn rewrite_catch(arm: &mut CatchArm, helper: &str, shape: &ComprehensionShape) {
    rewrite_calls(&mut arm.body, helper, 0, shape);
}

fn render_comprehension(shape: &ComprehensionShape, src: &Expr) -> Expr {
    let pattern: Expr = generator_pattern(shape);
    let element: String = render_expr(&apply_generator(&shape.element, shape));
    let filters: Vec<String> = shape
        .filters
        .iter()
        .map(|f: &Expr| render_expr(&apply_generator(f, shape)))
        .collect();
    let source: String = render_expr(src);
    let mut quals: Vec<String> = vec![format!("{} <- {source}", render_expr(&pattern))];
    quals.extend(filters);
    Expr::Raw(format!("[{element} || {}]", quals.join(", ")))
}

fn generator_pattern(shape: &ComprehensionShape) -> Expr {
    match shape.tuple_arity {
        None => Expr::Var("G".to_owned()),
        Some(n) => Expr::Tuple((0..n).map(|i: u32| Expr::Var(format!("T{i}"))).collect()),
    }
}

fn apply_generator(expr: &Expr, shape: &ComprehensionShape) -> Expr {
    match shape.tuple_arity {
        None => substitute(expr, &shape.source_reg, "G"),
        Some(n) => substitute_tuple(expr, &shape.source_reg, n),
    }
}

fn substitute_tuple(expr: &Expr, reg: &str, arity: u32) -> Expr {
    if let Expr::TupleElement { tuple, index } = expr
        && is_hd_var(tuple, reg)
        && *index < arity
    {
        return Expr::Var(format!("T{index}"));
    }
    if let Expr::Guard { name, args } = expr
        && name == "hd"
        && matches!(args.first(), Some(Expr::Var(v)) if v == reg)
    {
        return Expr::Tuple(
            (0..arity)
                .map(|i: u32| Expr::Var(format!("T{i}")))
                .collect(),
        );
    }
    map_children(expr, &|e: &Expr| substitute_tuple(e, reg, arity))
}

fn is_hd_var(expr: &Expr, reg: &str) -> bool {
    matches!(expr, Expr::Guard { name, args }
        if name == "hd" && matches!(args.first(), Some(Expr::Var(v)) if v == reg))
}

fn substitute(expr: &Expr, reg: &str, genv: &str) -> Expr {
    if is_hd_var(expr, reg) {
        return Expr::Var(genv.to_owned());
    }
    map_children(expr, &|e: &Expr| substitute(e, reg, genv))
}

fn map_children(expr: &Expr, f: &dyn Fn(&Expr) -> Expr) -> Expr {
    match expr {
        Expr::Tuple(items) => Expr::Tuple(items.iter().map(f).collect()),
        Expr::List { elements, tail } => Expr::List {
            elements: elements.iter().map(f).collect(),
            tail: Box::new(f(tail)),
        },
        Expr::Cons { head, tail } => Expr::Cons {
            head: Box::new(f(head)),
            tail: Box::new(f(tail)),
        },
        Expr::Call { target, args } => Expr::Call {
            target: target.clone(),
            args: args.iter().map(f).collect(),
        },
        Expr::Guard { name, args } => Expr::Guard {
            name: name.clone(),
            args: args.iter().map(f).collect(),
        },
        Expr::BinOp { op, lhs, rhs } => Expr::BinOp {
            op: op.clone(),
            lhs: Box::new(f(lhs)),
            rhs: Box::new(f(rhs)),
        },
        Expr::UnOp { op, operand } => Expr::UnOp {
            op: op.clone(),
            operand: Box::new(f(operand)),
        },
        Expr::TupleElement { tuple, index } => Expr::TupleElement {
            tuple: Box::new(f(tuple)),
            index: *index,
        },
        other => other.clone(),
    }
}
