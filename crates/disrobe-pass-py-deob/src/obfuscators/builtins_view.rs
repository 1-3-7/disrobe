use std::cell::Cell;
use std::collections::BTreeSet;

use ruff_python_ast::name::Name;
use ruff_python_ast::token::TokenKind;
use ruff_python_ast::visitor::transformer::{Transformer, walk_expr};
use ruff_python_ast::{
    AtomicNodeIndex, Expr, ExprAttribute, ExprCall, ExprContext, ExprIf, ExprName, ExprSubscript,
    ModModule, Stmt, StmtAssign,
};
use ruff_python_codegen::{Generator, Stylist};
use ruff_python_parser::{Parsed, parse_module};
use ruff_text_size::Ranged;

pub(crate) fn fold_builtins_view(source: &str) -> Option<(String, usize)> {
    let parsed: Parsed<ModModule> = parse_module(source).ok()?;
    let name_tokens: BTreeSet<&str> = parsed
        .tokens()
        .iter()
        .filter(|token| token.kind() == TokenKind::Name)
        .filter_map(|token| {
            let range = token.range();
            source.get(range.start().to_usize()..range.end().to_usize())
        })
        .collect();
    let stylist: Stylist<'_> = Stylist::from_tokens(parsed.tokens(), source);
    let mut module: ModModule = parsed.into_syntax();
    let (holder, view): (String, String) = builtins_prologue(&module.body)?;
    let folder: ViewFolder<'_> = ViewFolder {
        view: &view,
        bound: &name_tokens,
        folded: Cell::new(0),
    };
    for stmt in &mut module.body {
        folder.visit_stmt(stmt);
    }
    let folded: usize = folder.folded.get();
    if folded == 0 {
        return None;
    }
    if !loads_name(&module.body[2..], &view) {
        module.body.remove(1);
        if !loads_name(&module.body[1..], &holder) {
            module.body.remove(0);
        }
    }
    let mut out: String = String::with_capacity(source.len());
    for stmt in &module.body {
        out.push_str(&Generator::from(&stylist).stmt(stmt));
        out.push('\n');
    }
    Some((out, folded))
}

fn assigned_name(stmt: &Stmt) -> Option<(&str, &Expr)> {
    let Stmt::Assign(StmtAssign { targets, value, .. }) = stmt else {
        return None;
    };
    let [Expr::Name(target)] = targets.as_slice() else {
        return None;
    };
    Some((target.id.as_str(), value.as_ref()))
}

fn is_name(expr: &Expr, wanted: &str) -> bool {
    matches!(expr, Expr::Name(ExprName { id, .. }) if id.as_str() == wanted)
}

fn builtins_prologue(body: &[Stmt]) -> Option<(String, String)> {
    let (holder, holder_value): (&str, &Expr) = assigned_name(body.first()?)?;
    let Expr::Subscript(ExprSubscript { value, slice, .. }) = holder_value else {
        return None;
    };
    let Expr::Call(ExprCall {
        func, arguments, ..
    }) = value.as_ref()
    else {
        return None;
    };
    if !is_name(func, "globals") || !arguments.is_empty() {
        return None;
    }
    if !matches!(slice.as_ref(), Expr::StringLiteral(key) if key.value.to_str() == "__builtins__") {
        return None;
    }
    let (view, view_value): (&str, &Expr) = assigned_name(body.get(1)?)?;
    let Expr::If(ExprIf {
        test, body, orelse, ..
    }) = view_value
    else {
        return None;
    };
    let Expr::Call(ExprCall {
        func: check,
        arguments: checked,
        ..
    }) = test.as_ref()
    else {
        return None;
    };
    let [first, second] = checked.args.as_ref() else {
        return None;
    };
    let dict_check: bool = is_name(check, "isinstance")
        && checked.keywords.is_empty()
        && is_name(first, holder)
        && is_name(second, "dict");
    let attribute_fallback: bool = matches!(
        orelse.as_ref(),
        Expr::Attribute(ExprAttribute { value, attr, .. })
            if is_name(value, holder) && attr.as_str() == "__dict__"
    );
    (dict_check && is_name(body, holder) && attribute_fallback)
        .then(|| (holder.to_owned(), view.to_owned()))
}

struct ViewFolder<'a> {
    view: &'a str,
    bound: &'a BTreeSet<&'a str>,
    folded: Cell<usize>,
}

impl Transformer for ViewFolder<'_> {
    fn visit_expr(&self, expr: &mut Expr) {
        walk_expr(self, expr);
        let Expr::Subscript(ExprSubscript {
            value,
            slice,
            ctx: ExprContext::Load,
            range,
            ..
        }) = expr
        else {
            return;
        };
        if !is_name(value, self.view) {
            return;
        }
        let Expr::StringLiteral(key) = slice.as_ref() else {
            return;
        };
        let name: &str = key.value.to_str();
        let identifier: bool = name
            .chars()
            .next()
            .is_some_and(|c: char| c.is_ascii_alphabetic() || c == '_')
            && name
                .chars()
                .all(|c: char| c.is_ascii_alphanumeric() || c == '_');
        if !identifier || self.bound.contains(name) {
            return;
        }
        *expr = Expr::Name(ExprName {
            node_index: AtomicNodeIndex::default(),
            range: *range,
            id: Name::new(name),
            ctx: ExprContext::Load,
        });
        self.folded.set(self.folded.get() + 1);
    }
}

fn loads_name(body: &[Stmt], wanted: &str) -> bool {
    use ruff_python_ast::visitor::{Visitor, walk_expr as walk_ref};

    struct Finder<'a> {
        wanted: &'a str,
        found: bool,
    }

    impl<'b> Visitor<'b> for Finder<'_> {
        fn visit_expr(&mut self, expr: &'b Expr) {
            if is_name(expr, self.wanted) {
                self.found = true;
            }
            walk_ref(self, expr);
        }
    }

    let mut finder: Finder<'_> = Finder {
        wanted,
        found: false,
    };
    for stmt in body {
        finder.visit_stmt(stmt);
    }
    finder.found
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn folds_builtin_lookups_and_drops_the_unused_prologue() {
        let source: &str = "name_0 = globals()['__builtins__']\nname_1 = name_0 if isinstance(name_0, dict) else name_0.__dict__\nname_1['print'](name_1['len']('ab'))\n";
        let (out, folded): (String, usize) = fold_builtins_view(source).expect("folds");
        assert_eq!(folded, 2);
        assert_eq!(out, "print(len('ab'))\n");
    }

    #[test]
    fn keeps_lookups_of_names_the_module_binds() {
        let source: &str = "b = globals()['__builtins__']\nv = b if isinstance(b, dict) else b.__dict__\nprint = 1\nv['print'](v['len']('ab'))\n";
        let (out, folded): (String, usize) = fold_builtins_view(source).expect("folds");
        assert_eq!(folded, 1);
        assert!(out.contains("v['print'](len('ab'))"), "{out}");
        assert!(out.starts_with("b = globals()"), "{out}");
    }

    #[test]
    fn ignores_modules_without_the_prologue() {
        assert!(fold_builtins_view("v = {}\nv['print'](1)\n").is_none());
    }
}
