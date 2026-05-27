use crate::ast::node::{
    AstModule, Comprehension, ExceptHandler, Expr, MatchCase, Pattern, Stmt, TStrItem,
};

pub trait Visitor {
    fn visit_module(&mut self, module: &AstModule) {
        walk_module(self, module);
    }

    fn visit_stmt(&mut self, stmt: &Stmt) {
        walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &Expr) {
        walk_expr(self, expr);
    }

    fn visit_pattern(&mut self, pattern: &Pattern) {
        walk_pattern(self, pattern);
    }

    fn visit_handler(&mut self, handler: &ExceptHandler) {
        walk_handler(self, handler);
    }

    fn visit_match_case(&mut self, case: &MatchCase) {
        walk_match_case(self, case);
    }

    fn visit_comprehension(&mut self, comp: &Comprehension) {
        walk_comprehension(self, comp);
    }
}

pub fn walk_module<V: Visitor + ?Sized>(v: &mut V, module: &AstModule) {
    for stmt in &module.body {
        v.visit_stmt(stmt);
    }
}

#[allow(clippy::too_many_lines)]
pub fn walk_stmt<V: Visitor + ?Sized>(v: &mut V, stmt: &Stmt) {
    match stmt {
        Stmt::FunctionDef {
            args,
            body,
            decorators,
            returns,
            ..
        } => {
            for dec in decorators {
                v.visit_expr(dec);
            }
            walk_arguments(v, args);
            if let Some(r) = returns.as_ref() {
                v.visit_expr(r);
            }
            for s in body {
                v.visit_stmt(s);
            }
        }
        Stmt::ClassDef {
            bases,
            keywords,
            body,
            decorators,
            ..
        } => {
            for dec in decorators {
                v.visit_expr(dec);
            }
            for b in bases {
                v.visit_expr(b);
            }
            for kw in keywords {
                v.visit_expr(&kw.value);
            }
            for s in body {
                v.visit_stmt(s);
            }
        }
        Stmt::Return(maybe) => {
            if let Some(e) = maybe.as_ref() {
                v.visit_expr(e);
            }
        }
        Stmt::Delete(targets) => {
            for t in targets {
                v.visit_expr(t);
            }
        }
        Stmt::Assign { targets, value, .. } => {
            for t in targets {
                v.visit_expr(t);
            }
            v.visit_expr(value);
        }
        Stmt::AugAssign { target, value, .. } => {
            v.visit_expr(target);
            v.visit_expr(value);
        }
        Stmt::AnnAssign {
            target,
            annotation,
            value,
            ..
        } => {
            v.visit_expr(target);
            v.visit_expr(annotation);
            if let Some(val) = value.as_ref() {
                v.visit_expr(val);
            }
        }
        Stmt::TypeAlias { value, .. } => {
            v.visit_expr(value);
        }
        Stmt::For {
            target,
            iter,
            body,
            orelse,
            ..
        } => {
            v.visit_expr(target);
            v.visit_expr(iter);
            for s in body {
                v.visit_stmt(s);
            }
            for s in orelse {
                v.visit_stmt(s);
            }
        }
        Stmt::While {
            test, body, orelse, ..
        }
        | Stmt::If {
            test, body, orelse, ..
        } => {
            v.visit_expr(test);
            for s in body {
                v.visit_stmt(s);
            }
            for s in orelse {
                v.visit_stmt(s);
            }
        }
        Stmt::With { items, body, .. } => {
            for item in items {
                v.visit_expr(&item.context_expr);
                if let Some(target) = item.optional_vars.as_ref() {
                    v.visit_expr(target);
                }
            }
            for s in body {
                v.visit_stmt(s);
            }
        }
        Stmt::Match { subject, cases, .. } => {
            v.visit_expr(subject);
            for case in cases {
                v.visit_match_case(case);
            }
        }
        Stmt::Raise { exc, cause, .. } => {
            if let Some(e) = exc.as_ref() {
                v.visit_expr(e);
            }
            if let Some(c) = cause.as_ref() {
                v.visit_expr(c);
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
            for s in body {
                v.visit_stmt(s);
            }
            for h in handlers {
                v.visit_handler(h);
            }
            for s in orelse {
                v.visit_stmt(s);
            }
            for s in finalbody {
                v.visit_stmt(s);
            }
        }
        Stmt::Assert { test, msg, .. } => {
            v.visit_expr(test);
            if let Some(m) = msg.as_ref() {
                v.visit_expr(m);
            }
        }
        Stmt::Expr(e) => v.visit_expr(e),
        Stmt::Import(_)
        | Stmt::ImportFrom { .. }
        | Stmt::Global(_)
        | Stmt::Nonlocal(_)
        | Stmt::Pass
        | Stmt::Break
        | Stmt::Continue => {}
    }
}

#[allow(clippy::too_many_lines)]
pub fn walk_expr<V: Visitor + ?Sized>(v: &mut V, expr: &Expr) {
    match expr {
        Expr::Constant { .. }
        | Expr::Name { .. }
        | Expr::EmptyDictUnpack
        | Expr::EmptyDictKeyUnpack => {}
        Expr::FormattedValue {
            value, format_spec, ..
        } => {
            v.visit_expr(value);
            if let Some(spec) = format_spec.as_ref() {
                v.visit_expr(spec);
            }
        }
        Expr::JoinedStr { values, .. } | Expr::BoolOp { values, .. } => {
            for e in values {
                v.visit_expr(e);
            }
        }
        Expr::TStr { items, .. } => {
            for item in items {
                if let TStrItem::Interp {
                    value, format_spec, ..
                } = item
                {
                    v.visit_expr(value);
                    if let Some(spec) = format_spec.as_ref() {
                        v.visit_expr(spec);
                    }
                }
            }
        }
        Expr::NamedExpr { target, value } => {
            v.visit_expr(target);
            v.visit_expr(value);
        }
        Expr::BinOp { left, right, .. } => {
            v.visit_expr(left);
            v.visit_expr(right);
        }
        Expr::UnaryOp { operand, .. } => v.visit_expr(operand),
        Expr::Lambda { args, body } => {
            walk_arguments(v, args);
            v.visit_expr(body);
        }
        Expr::IfExp { test, body, orelse } => {
            v.visit_expr(test);
            v.visit_expr(body);
            v.visit_expr(orelse);
        }
        Expr::Dict { keys, values } => {
            for k in keys.iter().flatten() {
                v.visit_expr(k);
            }
            for val in values {
                v.visit_expr(val);
            }
        }
        Expr::Set(elts) | Expr::List { elts, .. } | Expr::Tuple { elts, .. } => {
            for e in elts {
                v.visit_expr(e);
            }
        }
        Expr::ListComp { elt, generators }
        | Expr::SetComp { elt, generators }
        | Expr::GeneratorExp { elt, generators } => {
            v.visit_expr(elt);
            for generator in generators {
                v.visit_comprehension(generator);
            }
        }
        Expr::DictComp {
            key,
            value,
            generators,
        } => {
            v.visit_expr(key);
            v.visit_expr(value);
            for generator in generators {
                v.visit_comprehension(generator);
            }
        }
        Expr::Await(inner) | Expr::YieldFrom(inner) => v.visit_expr(inner),
        Expr::Yield(maybe) => {
            if let Some(inner) = maybe.as_ref() {
                v.visit_expr(inner);
            }
        }
        Expr::Compare {
            left, comparators, ..
        } => {
            v.visit_expr(left);
            for c in comparators {
                v.visit_expr(c);
            }
        }
        Expr::Call {
            func,
            args,
            keywords,
        } => {
            v.visit_expr(func);
            for a in args {
                v.visit_expr(a);
            }
            for kw in keywords {
                v.visit_expr(&kw.value);
            }
        }
        Expr::Attribute { value, .. } | Expr::Starred { value, .. } => v.visit_expr(value),
        Expr::Subscript { value, slice, .. } => {
            v.visit_expr(value);
            v.visit_expr(slice);
        }
        Expr::Slice { lower, upper, step } => {
            if let Some(l) = lower.as_ref() {
                v.visit_expr(l);
            }
            if let Some(u) = upper.as_ref() {
                v.visit_expr(u);
            }
            if let Some(s) = step.as_ref() {
                v.visit_expr(s);
            }
        }
    }
}

pub fn walk_pattern<V: Visitor + ?Sized>(v: &mut V, pattern: &Pattern) {
    match pattern {
        Pattern::MatchValue(e) => v.visit_expr(e),
        Pattern::MatchSingleton(_) | Pattern::MatchStar(_) => {}
        Pattern::MatchSequence(patterns) | Pattern::MatchOr(patterns) => {
            for p in patterns {
                v.visit_pattern(p);
            }
        }
        Pattern::MatchMapping { keys, patterns, .. } => {
            for k in keys {
                v.visit_expr(k);
            }
            for p in patterns {
                v.visit_pattern(p);
            }
        }
        Pattern::MatchClass {
            cls,
            patterns,
            kwd_patterns,
            ..
        } => {
            v.visit_expr(cls);
            for p in patterns {
                v.visit_pattern(p);
            }
            for p in kwd_patterns {
                v.visit_pattern(p);
            }
        }
        Pattern::MatchAs { pattern, .. } => {
            if let Some(inner) = pattern.as_ref() {
                v.visit_pattern(inner);
            }
        }
    }
}

pub fn walk_handler<V: Visitor + ?Sized>(v: &mut V, handler: &ExceptHandler) {
    if let Some(t) = handler.typ.as_ref() {
        v.visit_expr(t);
    }
    for s in &handler.body {
        v.visit_stmt(s);
    }
}

pub fn walk_match_case<V: Visitor + ?Sized>(v: &mut V, case: &MatchCase) {
    v.visit_pattern(&case.pattern);
    if let Some(g) = case.guard.as_ref() {
        v.visit_expr(g);
    }
    for s in &case.body {
        v.visit_stmt(s);
    }
}

pub fn walk_comprehension<V: Visitor + ?Sized>(v: &mut V, comp: &Comprehension) {
    v.visit_expr(&comp.target);
    v.visit_expr(&comp.iter);
    for cond in &comp.ifs {
        v.visit_expr(cond);
    }
}

fn walk_arguments<V: Visitor + ?Sized>(v: &mut V, args: &crate::ast::node::Arguments) {
    for arg in args.posonly.iter().chain(&args.args).chain(&args.kwonly) {
        if let Some(ann) = arg.annotation.as_ref() {
            v.visit_expr(ann);
        }
        if let Some(def) = arg.default.as_ref() {
            v.visit_expr(def);
        }
    }
    if let Some(va) = args.vararg.as_ref()
        && let Some(ann) = va.annotation.as_ref()
    {
        v.visit_expr(ann);
    }
    if let Some(kw) = args.kwarg.as_ref()
        && let Some(ann) = kw.annotation.as_ref()
    {
        v.visit_expr(ann);
    }
    for default in args.kw_defaults.iter().flatten() {
        v.visit_expr(default);
    }
    for default in &args.defaults {
        v.visit_expr(default);
    }
}

pub trait VisitorMut {
    fn visit_module_mut(&mut self, module: &mut AstModule) {
        walk_module_mut(self, module);
    }

    fn visit_stmt_mut(&mut self, stmt: &mut Stmt) {
        walk_stmt_mut(self, stmt);
    }

    fn visit_expr_mut(&mut self, expr: &mut Expr) {
        walk_expr_mut(self, expr);
    }

    fn visit_pattern_mut(&mut self, pattern: &mut Pattern) {
        walk_pattern_mut(self, pattern);
    }

    fn visit_handler_mut(&mut self, handler: &mut ExceptHandler) {
        walk_handler_mut(self, handler);
    }

    fn visit_match_case_mut(&mut self, case: &mut MatchCase) {
        walk_match_case_mut(self, case);
    }

    fn visit_comprehension_mut(&mut self, comp: &mut Comprehension) {
        walk_comprehension_mut(self, comp);
    }
}

pub fn walk_module_mut<V: VisitorMut + ?Sized>(v: &mut V, module: &mut AstModule) {
    for stmt in &mut module.body {
        v.visit_stmt_mut(stmt);
    }
}

#[allow(clippy::too_many_lines)]
pub fn walk_stmt_mut<V: VisitorMut + ?Sized>(v: &mut V, stmt: &mut Stmt) {
    match stmt {
        Stmt::FunctionDef {
            args,
            body,
            decorators,
            returns,
            ..
        } => {
            for dec in decorators.iter_mut() {
                v.visit_expr_mut(dec);
            }
            walk_arguments_mut(v, args);
            if let Some(r) = returns.as_mut() {
                v.visit_expr_mut(r);
            }
            for s in body.iter_mut() {
                v.visit_stmt_mut(s);
            }
        }
        Stmt::ClassDef {
            bases,
            keywords,
            body,
            decorators,
            ..
        } => {
            for dec in decorators.iter_mut() {
                v.visit_expr_mut(dec);
            }
            for b in bases.iter_mut() {
                v.visit_expr_mut(b);
            }
            for kw in keywords.iter_mut() {
                v.visit_expr_mut(&mut kw.value);
            }
            for s in body.iter_mut() {
                v.visit_stmt_mut(s);
            }
        }
        Stmt::Return(maybe) => {
            if let Some(e) = maybe.as_mut() {
                v.visit_expr_mut(e);
            }
        }
        Stmt::Delete(targets) => {
            for t in targets.iter_mut() {
                v.visit_expr_mut(t);
            }
        }
        Stmt::Assign { targets, value, .. } => {
            for t in targets.iter_mut() {
                v.visit_expr_mut(t);
            }
            v.visit_expr_mut(value);
        }
        Stmt::AugAssign { target, value, .. } => {
            v.visit_expr_mut(target);
            v.visit_expr_mut(value);
        }
        Stmt::AnnAssign {
            target,
            annotation,
            value,
            ..
        } => {
            v.visit_expr_mut(target);
            v.visit_expr_mut(annotation);
            if let Some(val) = value.as_mut() {
                v.visit_expr_mut(val);
            }
        }
        Stmt::TypeAlias { value, .. } => v.visit_expr_mut(value),
        Stmt::For {
            target,
            iter,
            body,
            orelse,
            ..
        } => {
            v.visit_expr_mut(target);
            v.visit_expr_mut(iter);
            for s in body.iter_mut() {
                v.visit_stmt_mut(s);
            }
            for s in orelse.iter_mut() {
                v.visit_stmt_mut(s);
            }
        }
        Stmt::While {
            test, body, orelse, ..
        }
        | Stmt::If {
            test, body, orelse, ..
        } => {
            v.visit_expr_mut(test);
            for s in body {
                v.visit_stmt_mut(s);
            }
            for s in orelse {
                v.visit_stmt_mut(s);
            }
        }
        Stmt::With { items, body, .. } => {
            for item in items.iter_mut() {
                v.visit_expr_mut(&mut item.context_expr);
                if let Some(target) = item.optional_vars.as_mut() {
                    v.visit_expr_mut(target);
                }
            }
            for s in body.iter_mut() {
                v.visit_stmt_mut(s);
            }
        }
        Stmt::Match { subject, cases, .. } => {
            v.visit_expr_mut(subject);
            for case in cases.iter_mut() {
                v.visit_match_case_mut(case);
            }
        }
        Stmt::Raise { exc, cause, .. } => {
            if let Some(e) = exc.as_mut() {
                v.visit_expr_mut(e);
            }
            if let Some(c) = cause.as_mut() {
                v.visit_expr_mut(c);
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
            for s in body.iter_mut() {
                v.visit_stmt_mut(s);
            }
            for h in handlers.iter_mut() {
                v.visit_handler_mut(h);
            }
            for s in orelse.iter_mut() {
                v.visit_stmt_mut(s);
            }
            for s in finalbody.iter_mut() {
                v.visit_stmt_mut(s);
            }
        }
        Stmt::Assert { test, msg, .. } => {
            v.visit_expr_mut(test);
            if let Some(m) = msg.as_mut() {
                v.visit_expr_mut(m);
            }
        }
        Stmt::Expr(e) => v.visit_expr_mut(e),
        Stmt::Import(_)
        | Stmt::ImportFrom { .. }
        | Stmt::Global(_)
        | Stmt::Nonlocal(_)
        | Stmt::Pass
        | Stmt::Break
        | Stmt::Continue => {}
    }
}

#[allow(clippy::too_many_lines)]
pub fn walk_expr_mut<V: VisitorMut + ?Sized>(v: &mut V, expr: &mut Expr) {
    match expr {
        Expr::Constant { .. }
        | Expr::Name { .. }
        | Expr::EmptyDictUnpack
        | Expr::EmptyDictKeyUnpack => {}
        Expr::FormattedValue {
            value, format_spec, ..
        } => {
            v.visit_expr_mut(value);
            if let Some(spec) = format_spec.as_mut() {
                v.visit_expr_mut(spec);
            }
        }
        Expr::JoinedStr { values, .. } | Expr::BoolOp { values, .. } => {
            for e in values {
                v.visit_expr_mut(e);
            }
        }
        Expr::TStr { items, .. } => {
            for item in items {
                if let TStrItem::Interp {
                    value, format_spec, ..
                } = item
                {
                    v.visit_expr_mut(value);
                    if let Some(spec) = format_spec.as_mut() {
                        v.visit_expr_mut(spec);
                    }
                }
            }
        }
        Expr::NamedExpr { target, value } => {
            v.visit_expr_mut(target);
            v.visit_expr_mut(value);
        }
        Expr::BinOp { left, right, .. } => {
            v.visit_expr_mut(left);
            v.visit_expr_mut(right);
        }
        Expr::UnaryOp { operand, .. } => v.visit_expr_mut(operand),
        Expr::Lambda { args, body } => {
            walk_arguments_mut(v, args);
            v.visit_expr_mut(body);
        }
        Expr::IfExp { test, body, orelse } => {
            v.visit_expr_mut(test);
            v.visit_expr_mut(body);
            v.visit_expr_mut(orelse);
        }
        Expr::Dict { keys, values } => {
            for k in keys.iter_mut().flatten() {
                v.visit_expr_mut(k);
            }
            for val in values.iter_mut() {
                v.visit_expr_mut(val);
            }
        }
        Expr::Set(elts) | Expr::List { elts, .. } | Expr::Tuple { elts, .. } => {
            for e in elts.iter_mut() {
                v.visit_expr_mut(e);
            }
        }
        Expr::ListComp { elt, generators }
        | Expr::SetComp { elt, generators }
        | Expr::GeneratorExp { elt, generators } => {
            v.visit_expr_mut(elt);
            for generator in generators.iter_mut() {
                v.visit_comprehension_mut(generator);
            }
        }
        Expr::DictComp {
            key,
            value,
            generators,
        } => {
            v.visit_expr_mut(key);
            v.visit_expr_mut(value);
            for generator in generators.iter_mut() {
                v.visit_comprehension_mut(generator);
            }
        }
        Expr::Await(inner) | Expr::YieldFrom(inner) => v.visit_expr_mut(inner),
        Expr::Yield(maybe) => {
            if let Some(inner) = maybe.as_mut() {
                v.visit_expr_mut(inner);
            }
        }
        Expr::Compare {
            left, comparators, ..
        } => {
            v.visit_expr_mut(left);
            for c in comparators.iter_mut() {
                v.visit_expr_mut(c);
            }
        }
        Expr::Call {
            func,
            args,
            keywords,
        } => {
            v.visit_expr_mut(func);
            for a in args.iter_mut() {
                v.visit_expr_mut(a);
            }
            for kw in keywords.iter_mut() {
                v.visit_expr_mut(&mut kw.value);
            }
        }
        Expr::Attribute { value, .. } | Expr::Starred { value, .. } => v.visit_expr_mut(value),
        Expr::Subscript { value, slice, .. } => {
            v.visit_expr_mut(value);
            v.visit_expr_mut(slice);
        }
        Expr::Slice { lower, upper, step } => {
            if let Some(l) = lower.as_mut() {
                v.visit_expr_mut(l);
            }
            if let Some(u) = upper.as_mut() {
                v.visit_expr_mut(u);
            }
            if let Some(s) = step.as_mut() {
                v.visit_expr_mut(s);
            }
        }
    }
}

pub fn walk_pattern_mut<V: VisitorMut + ?Sized>(v: &mut V, pattern: &mut Pattern) {
    match pattern {
        Pattern::MatchValue(e) => v.visit_expr_mut(e),
        Pattern::MatchSingleton(_) | Pattern::MatchStar(_) => {}
        Pattern::MatchSequence(patterns) | Pattern::MatchOr(patterns) => {
            for p in patterns.iter_mut() {
                v.visit_pattern_mut(p);
            }
        }
        Pattern::MatchMapping { keys, patterns, .. } => {
            for k in keys.iter_mut() {
                v.visit_expr_mut(k);
            }
            for p in patterns.iter_mut() {
                v.visit_pattern_mut(p);
            }
        }
        Pattern::MatchClass {
            cls,
            patterns,
            kwd_patterns,
            ..
        } => {
            v.visit_expr_mut(cls);
            for p in patterns.iter_mut() {
                v.visit_pattern_mut(p);
            }
            for p in kwd_patterns.iter_mut() {
                v.visit_pattern_mut(p);
            }
        }
        Pattern::MatchAs { pattern, .. } => {
            if let Some(inner) = pattern.as_mut() {
                v.visit_pattern_mut(inner);
            }
        }
    }
}

pub fn walk_handler_mut<V: VisitorMut + ?Sized>(v: &mut V, handler: &mut ExceptHandler) {
    if let Some(t) = handler.typ.as_mut() {
        v.visit_expr_mut(t);
    }
    for s in &mut handler.body {
        v.visit_stmt_mut(s);
    }
}

pub fn walk_match_case_mut<V: VisitorMut + ?Sized>(v: &mut V, case: &mut MatchCase) {
    v.visit_pattern_mut(&mut case.pattern);
    if let Some(g) = case.guard.as_mut() {
        v.visit_expr_mut(g);
    }
    for s in &mut case.body {
        v.visit_stmt_mut(s);
    }
}

pub fn walk_comprehension_mut<V: VisitorMut + ?Sized>(v: &mut V, comp: &mut Comprehension) {
    v.visit_expr_mut(&mut comp.target);
    v.visit_expr_mut(&mut comp.iter);
    for cond in &mut comp.ifs {
        v.visit_expr_mut(cond);
    }
}

fn walk_arguments_mut<V: VisitorMut + ?Sized>(v: &mut V, args: &mut crate::ast::node::Arguments) {
    for arg in args
        .posonly
        .iter_mut()
        .chain(args.args.iter_mut())
        .chain(args.kwonly.iter_mut())
    {
        if let Some(ann) = arg.annotation.as_mut() {
            v.visit_expr_mut(ann);
        }
        if let Some(def) = arg.default.as_mut() {
            v.visit_expr_mut(def);
        }
    }
    if let Some(va) = args.vararg.as_mut()
        && let Some(ann) = va.annotation.as_mut()
    {
        v.visit_expr_mut(ann);
    }
    if let Some(kw) = args.kwarg.as_mut()
        && let Some(ann) = kw.annotation.as_mut()
    {
        v.visit_expr_mut(ann);
    }
    for default in args.kw_defaults.iter_mut().flatten() {
        v.visit_expr_mut(default);
    }
    for default in &mut args.defaults {
        v.visit_expr_mut(default);
    }
}
