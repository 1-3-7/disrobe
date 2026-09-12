use crate::ast::node::{
    Arg, Arguments, Comprehension, ExceptHandler, Expr, MatchCase, Pattern, Stmt, TStrItem,
    WithItem,
};

#[must_use]
pub fn demangle_class_body(class_name: &str, body: &[Stmt]) -> Vec<Stmt> {
    let stripped: &str = class_name.trim_start_matches('_');
    if stripped.is_empty() {
        return body.to_vec();
    }
    let prefix: String = format!("_{stripped}");
    let mut cloned: Vec<Stmt> = body.to_vec();
    for stmt in &mut cloned {
        demangle_stmt(&prefix, stmt);
    }
    cloned
}

fn demangle_name(prefix: &str, id: &mut String) {
    let Some(rest): Option<&str> = id.strip_prefix(prefix) else {
        return;
    };
    if rest.starts_with("__") && !rest.ends_with("__") {
        *id = rest.to_owned();
    }
}

fn demangle_stmt(prefix: &str, stmt: &mut Stmt) {
    match stmt {
        Stmt::FunctionDef {
            name,
            args,
            body,
            decorators,
            returns,
            ..
        } => {
            demangle_name(prefix, name);
            for dec in decorators.iter_mut() {
                demangle_expr(prefix, dec);
            }
            demangle_arguments(prefix, args);
            if let Some(r) = returns.as_mut() {
                demangle_expr(prefix, r);
            }
            for s in body.iter_mut() {
                demangle_stmt(prefix, s);
            }
        }
        Stmt::ClassDef {
            name,
            bases,
            keywords,
            decorators,
            ..
        } => {
            demangle_name(prefix, name);
            for dec in decorators.iter_mut() {
                demangle_expr(prefix, dec);
            }
            for b in bases.iter_mut() {
                demangle_expr(prefix, b);
            }
            for kw in keywords.iter_mut() {
                demangle_expr(prefix, &mut kw.value);
            }
        }
        Stmt::Return(maybe) => {
            if let Some(e) = maybe.as_mut() {
                demangle_expr(prefix, e);
            }
        }
        Stmt::Delete(targets) => {
            for t in targets.iter_mut() {
                demangle_expr(prefix, t);
            }
        }
        Stmt::Assign { targets, value, .. } => {
            for t in targets.iter_mut() {
                demangle_expr(prefix, t);
            }
            demangle_expr(prefix, value);
        }
        Stmt::AugAssign { target, value, .. } => {
            demangle_expr(prefix, target);
            demangle_expr(prefix, value);
        }
        Stmt::AnnAssign {
            target,
            annotation,
            value,
            ..
        } => {
            demangle_expr(prefix, target);
            demangle_expr(prefix, annotation);
            if let Some(val) = value.as_mut() {
                demangle_expr(prefix, val);
            }
        }
        Stmt::TypeAlias { value, .. } => demangle_expr(prefix, value),
        Stmt::For {
            target,
            iter,
            body,
            orelse,
            ..
        } => {
            demangle_expr(prefix, target);
            demangle_expr(prefix, iter);
            for s in body.iter_mut().chain(orelse.iter_mut()) {
                demangle_stmt(prefix, s);
            }
        }
        Stmt::While {
            test, body, orelse, ..
        }
        | Stmt::If {
            test, body, orelse, ..
        } => {
            demangle_expr(prefix, test);
            for s in body.iter_mut().chain(orelse.iter_mut()) {
                demangle_stmt(prefix, s);
            }
        }
        Stmt::With { items, body, .. } => {
            for item in items.iter_mut() {
                demangle_with_item(prefix, item);
            }
            for s in body.iter_mut() {
                demangle_stmt(prefix, s);
            }
        }
        Stmt::Match { subject, cases, .. } => {
            demangle_expr(prefix, subject);
            for case in cases.iter_mut() {
                demangle_match_case(prefix, case);
            }
        }
        Stmt::Raise { exc, cause, .. } => {
            if let Some(e) = exc.as_mut() {
                demangle_expr(prefix, e);
            }
            if let Some(c) = cause.as_mut() {
                demangle_expr(prefix, c);
            }
        }
        Stmt::Try {
            body,
            handlers,
            orelse,
            finalbody,
            ..
        }
        | Stmt::TryStar {
            body,
            handlers,
            orelse,
            finalbody,
            ..
        } => {
            for s in body
                .iter_mut()
                .chain(orelse.iter_mut())
                .chain(finalbody.iter_mut())
            {
                demangle_stmt(prefix, s);
            }
            for h in handlers.iter_mut() {
                demangle_handler(prefix, h);
            }
        }
        Stmt::Assert { test, msg, .. } => {
            demangle_expr(prefix, test);
            if let Some(m) = msg.as_mut() {
                demangle_expr(prefix, m);
            }
        }
        Stmt::Expr(e) => demangle_expr(prefix, e),
        Stmt::Import(_)
        | Stmt::ImportFrom { .. }
        | Stmt::Global(_)
        | Stmt::Nonlocal(_)
        | Stmt::Pass
        | Stmt::Break
        | Stmt::Continue => {}
    }
}

fn demangle_expr(prefix: &str, expr: &mut Expr) {
    match expr {
        Expr::Name { id, .. } => demangle_name(prefix, id),
        Expr::Attribute { value, attr, .. } => {
            demangle_expr(prefix, value);
            demangle_name(prefix, attr);
        }
        Expr::Constant { .. } | Expr::EmptyDictUnpack | Expr::EmptyDictKeyUnpack => {}
        Expr::FormattedValue {
            value, format_spec, ..
        } => {
            demangle_expr(prefix, value);
            if let Some(spec) = format_spec.as_mut() {
                demangle_expr(prefix, spec);
            }
        }
        Expr::JoinedStr { values, .. } | Expr::BoolOp { values, .. } => {
            for e in values.iter_mut() {
                demangle_expr(prefix, e);
            }
        }
        Expr::TStr { items, .. } => {
            for item in items.iter_mut() {
                if let TStrItem::Interp {
                    value, format_spec, ..
                } = item
                {
                    demangle_expr(prefix, value);
                    if let Some(spec) = format_spec.as_mut() {
                        demangle_expr(prefix, spec);
                    }
                }
            }
        }
        Expr::NamedExpr { target, value } => {
            demangle_expr(prefix, target);
            demangle_expr(prefix, value);
        }
        Expr::BinOp { left, right, .. } => {
            demangle_expr(prefix, left);
            demangle_expr(prefix, right);
        }
        Expr::UnaryOp { operand, .. } => demangle_expr(prefix, operand),
        Expr::Lambda { args, body } => {
            demangle_arguments(prefix, args);
            demangle_expr(prefix, body);
        }
        Expr::IfExp { test, body, orelse } => {
            demangle_expr(prefix, test);
            demangle_expr(prefix, body);
            demangle_expr(prefix, orelse);
        }
        Expr::Dict { keys, values } => {
            for k in keys.iter_mut().flatten() {
                demangle_expr(prefix, k);
            }
            for val in values.iter_mut() {
                demangle_expr(prefix, val);
            }
        }
        Expr::Set(elts) | Expr::List { elts, .. } | Expr::Tuple { elts, .. } => {
            for e in elts.iter_mut() {
                demangle_expr(prefix, e);
            }
        }
        Expr::ListComp { elt, generators }
        | Expr::SetComp { elt, generators }
        | Expr::GeneratorExp { elt, generators } => {
            demangle_expr(prefix, elt);
            for generator in generators.iter_mut() {
                demangle_comprehension(prefix, generator);
            }
        }
        Expr::DictComp {
            key,
            value,
            generators,
        } => {
            demangle_expr(prefix, key);
            demangle_expr(prefix, value);
            for generator in generators.iter_mut() {
                demangle_comprehension(prefix, generator);
            }
        }
        Expr::Await(inner) | Expr::YieldFrom(inner) => demangle_expr(prefix, inner),
        Expr::Yield(maybe) => {
            if let Some(inner) = maybe.as_mut() {
                demangle_expr(prefix, inner);
            }
        }
        Expr::Compare {
            left, comparators, ..
        } => {
            demangle_expr(prefix, left);
            for c in comparators.iter_mut() {
                demangle_expr(prefix, c);
            }
        }
        Expr::Call {
            func,
            args,
            keywords,
        } => {
            demangle_expr(prefix, func);
            for a in args.iter_mut() {
                demangle_expr(prefix, a);
            }
            for kw in keywords.iter_mut() {
                demangle_expr(prefix, &mut kw.value);
            }
        }
        Expr::Starred { value, .. } => demangle_expr(prefix, value),
        Expr::Subscript { value, slice, .. } => {
            demangle_expr(prefix, value);
            demangle_expr(prefix, slice);
        }
        Expr::Slice { lower, upper, step } => {
            for part in [lower, upper, step].into_iter().flatten() {
                demangle_expr(prefix, part);
            }
        }
    }
}

fn demangle_arguments(prefix: &str, args: &mut Arguments) {
    for arg in args
        .posonly
        .iter_mut()
        .chain(args.args.iter_mut())
        .chain(args.kwonly.iter_mut())
    {
        demangle_arg(prefix, arg);
    }
    if let Some(va) = args.vararg.as_mut() {
        demangle_arg(prefix, va);
    }
    if let Some(kw) = args.kwarg.as_mut() {
        demangle_arg(prefix, kw);
    }
    for default in args.kw_defaults.iter_mut().flatten() {
        demangle_expr(prefix, default);
    }
    for default in &mut args.defaults {
        demangle_expr(prefix, default);
    }
}

fn demangle_arg(prefix: &str, arg: &mut Arg) {
    if let Some(ann) = arg.annotation.as_mut() {
        demangle_expr(prefix, ann);
    }
    if let Some(def) = arg.default.as_mut() {
        demangle_expr(prefix, def);
    }
}

fn demangle_with_item(prefix: &str, item: &mut WithItem) {
    demangle_expr(prefix, &mut item.context_expr);
    if let Some(target) = item.optional_vars.as_mut() {
        demangle_expr(prefix, target);
    }
}

fn demangle_handler(prefix: &str, handler: &mut ExceptHandler) {
    if let Some(t) = handler.typ.as_mut() {
        demangle_expr(prefix, t);
    }
    for s in &mut handler.body {
        demangle_stmt(prefix, s);
    }
}

fn demangle_match_case(prefix: &str, case: &mut MatchCase) {
    demangle_pattern(prefix, &mut case.pattern);
    if let Some(g) = case.guard.as_mut() {
        demangle_expr(prefix, g);
    }
    for s in &mut case.body {
        demangle_stmt(prefix, s);
    }
}

fn demangle_pattern(prefix: &str, pattern: &mut Pattern) {
    match pattern {
        Pattern::MatchValue(e) => demangle_expr(prefix, e),
        Pattern::MatchSingleton(_) | Pattern::MatchStar(_) => {}
        Pattern::MatchSequence(patterns) | Pattern::MatchOr(patterns) => {
            for p in patterns.iter_mut() {
                demangle_pattern(prefix, p);
            }
        }
        Pattern::MatchMapping { keys, patterns, .. } => {
            for k in keys.iter_mut() {
                demangle_expr(prefix, k);
            }
            for p in patterns.iter_mut() {
                demangle_pattern(prefix, p);
            }
        }
        Pattern::MatchClass {
            cls,
            patterns,
            kwd_patterns,
            ..
        } => {
            demangle_expr(prefix, cls);
            for p in patterns.iter_mut().chain(kwd_patterns.iter_mut()) {
                demangle_pattern(prefix, p);
            }
        }
        Pattern::MatchAs { pattern, .. } => {
            if let Some(inner) = pattern.as_mut() {
                demangle_pattern(prefix, inner);
            }
        }
    }
}

fn demangle_comprehension(prefix: &str, comp: &mut Comprehension) {
    demangle_expr(prefix, &mut comp.target);
    demangle_expr(prefix, &mut comp.iter);
    for cond in &mut comp.ifs {
        demangle_expr(prefix, cond);
    }
}
