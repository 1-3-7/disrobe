use std::collections::{BTreeMap, BTreeSet};

use ruff_python_ast::name::Name;
use ruff_python_ast::token::TokenKind;
use ruff_python_ast::visitor::transformer::{Transformer, walk_expr};
use ruff_python_ast::{Expr, ExprCall, ExprContext, ModModule, Stmt, StmtAssign};
use ruff_python_codegen::{Generator, Stylist};
use ruff_python_parser::{Parsed, parse_module};
use ruff_text_size::Ranged;

const DECLARING_CALLS: [&str; 4] = ["TypeVar", "ParamSpec", "TypeVarTuple", "NewType"];
const NAMESPACE_READERS: [&str; 6] = ["globals", "locals", "vars", "eval", "exec", "__dict__"];
const PYTHON_KEYWORDS: [&str; 35] = [
    "False", "None", "True", "and", "as", "assert", "async", "await", "break", "class", "continue",
    "def", "del", "elif", "else", "except", "finally", "for", "from", "global", "if", "import",
    "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try", "while",
    "with", "yield",
];

pub(crate) fn restore_declared_names(
    source: &str,
    generated: fn(&str) -> bool,
) -> Option<(String, BTreeMap<String, String>)> {
    let parsed: Parsed<ModModule> = parse_module(source).ok()?;
    let mut identifiers: BTreeMap<String, usize> = BTreeMap::new();
    let mut strings: BTreeSet<String> = BTreeSet::new();
    for token in parsed.tokens() {
        let text: &str =
            source.get(token.range().start().to_usize()..token.range().end().to_usize())?;
        match token.kind() {
            TokenKind::Name => *identifiers.entry(text.to_owned()).or_default() += 1,
            TokenKind::String => {
                strings.insert(text.trim_matches(['\'', '"']).to_owned());
            }
            _ => {}
        }
    }
    if NAMESPACE_READERS
        .iter()
        .any(|reader: &&str| identifiers.contains_key(*reader))
    {
        return None;
    }
    let stylist: Stylist<'_> = Stylist::from_tokens(parsed.tokens(), source);
    let mut module: ModModule = parsed.into_syntax();
    let declarations: Vec<(&str, &str)> = module.body.iter().filter_map(declaration).collect();
    let mut claims: BTreeMap<&str, usize> = BTreeMap::new();
    for (_, declared) in &declarations {
        *claims.entry(declared).or_default() += 1;
    }
    let mut renames: BTreeMap<String, String> = BTreeMap::new();
    for (variable, declared) in declarations.iter().copied() {
        let identifier: bool = declared
            .chars()
            .next()
            .is_some_and(|c: char| c.is_ascii_alphabetic() || c == '_')
            && declared
                .chars()
                .all(|c: char| c.is_ascii_alphanumeric() || c == '_');
        let free: bool = !identifiers.contains_key(declared) && claims.get(declared) == Some(&1);
        if generated(variable)
            && identifier
            && free
            && !PYTHON_KEYWORDS.contains(&declared)
            && !strings.contains(variable)
            && assigned_once(&module.body, variable)
        {
            renames.insert(variable.to_owned(), declared.to_owned());
        }
    }
    if renames.is_empty() {
        return None;
    }
    let renamer: Renamer<'_> = Renamer { renames: &renames };
    for stmt in &mut module.body {
        renamer.visit_stmt(stmt);
    }
    let mut out: String = String::with_capacity(source.len());
    for stmt in &module.body {
        out.push_str(&Generator::from(&stylist).stmt(stmt));
        out.push('\n');
    }
    Some((out, renames))
}

fn declaration(stmt: &Stmt) -> Option<(&str, &str)> {
    let Stmt::Assign(StmtAssign { targets, value, .. }) = stmt else {
        return None;
    };
    let [Expr::Name(target)] = targets.as_slice() else {
        return None;
    };
    let Expr::Call(ExprCall {
        func, arguments, ..
    }) = value.as_ref()
    else {
        return None;
    };
    let callee: &str = match func.as_ref() {
        Expr::Name(name) => name.id.as_str(),
        Expr::Attribute(attribute) => attribute.attr.as_str(),
        _ => return None,
    };
    if !DECLARING_CALLS.contains(&callee) {
        return None;
    }
    let Some(Expr::StringLiteral(declared)) = arguments.args.first() else {
        return None;
    };
    Some((target.id.as_str(), declared.value.to_str()))
}

fn assigned_once(body: &[Stmt], variable: &str) -> bool {
    use ruff_python_ast::visitor::{Visitor, walk_expr as walk_ref, walk_stmt};

    struct Stores<'a> {
        variable: &'a str,
        count: usize,
    }

    impl<'b> Visitor<'b> for Stores<'_> {
        fn visit_stmt(&mut self, stmt: &'b Stmt) {
            match stmt {
                Stmt::FunctionDef(function) if function.name.as_str() == self.variable => {
                    self.count += 2;
                }
                Stmt::ClassDef(class) if class.name.as_str() == self.variable => self.count += 2,
                Stmt::Global(global)
                    if global
                        .names
                        .iter()
                        .any(|name| name.as_str() == self.variable) =>
                {
                    self.count += 2;
                }
                Stmt::Nonlocal(nonlocal)
                    if nonlocal
                        .names
                        .iter()
                        .any(|name| name.as_str() == self.variable) =>
                {
                    self.count += 2;
                }
                _ => {}
            }
            walk_stmt(self, stmt);
        }

        fn visit_expr(&mut self, expr: &'b Expr) {
            if let Expr::Name(name) = expr
                && name.id.as_str() == self.variable
                && matches!(name.ctx, ExprContext::Store | ExprContext::Del)
            {
                self.count += 1;
            }
            walk_ref(self, expr);
        }

        fn visit_parameter(&mut self, parameter: &'b ruff_python_ast::Parameter) {
            if parameter.name.as_str() == self.variable {
                self.count += 2;
            }
        }
    }

    let mut stores: Stores<'_> = Stores { variable, count: 0 };
    for stmt in body {
        stores.visit_stmt(stmt);
    }
    stores.count == 1
}

struct Renamer<'a> {
    renames: &'a BTreeMap<String, String>,
}

impl Transformer for Renamer<'_> {
    fn visit_expr(&self, expr: &mut Expr) {
        if let Expr::Name(name) = expr
            && let Some(restored) = self.renames.get(name.id.as_str())
        {
            name.id = Name::new(restored);
        }
        walk_expr(self, expr);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn hex_name(name: &str) -> bool {
        name.starts_with("v_")
    }

    #[test]
    fn a_renamed_typevar_takes_back_its_declared_name() {
        let source: &str = "from typing import Generic, TypeVar\nv_9d = TypeVar('T')\nclass Holder(Generic[v_9d]):\n    def get(self, value: v_9d) -> v_9d:\n        return value\n";
        let (restored, renames): (String, BTreeMap<String, String>) =
            restore_declared_names(source, hex_name).expect("restores");
        assert_eq!(renames.get("v_9d").map(String::as_str), Some("T"));
        assert_eq!(
            restored,
            "from typing import Generic, TypeVar\nT = TypeVar('T')\nclass Holder(Generic[T]):\n\n    def get(self, value: T) -> T:\n        return value\n"
        );
    }

    #[test]
    fn a_taken_or_ambiguous_name_is_not_restored() {
        for source in [
            "from typing import TypeVar\nv_1 = TypeVar('T')\nT = 3\n",
            "from typing import TypeVar\nv_1 = TypeVar('T')\nv_2 = TypeVar('T')\n",
            "from typing import TypeVar\nv_1 = TypeVar('T')\nv_1 = 4\n",
            "from typing import TypeVar\nv_1 = TypeVar('T')\nprint(globals()['v_1'])\n",
            "from typing import TypeVar\nv_1 = TypeVar('class')\n",
            "from typing import TypeVar\nkeep = TypeVar('T')\n",
            "from typing import TypeVar\nv_1 = TypeVar('T')\nx: 'v_1' = 0\n",
        ] {
            assert_eq!(restore_declared_names(source, hex_name), None, "{source}");
        }
    }
}
