use std::borrow::Cow;

use oxc_allocator::Allocator;
use oxc_ast::ast::{Expression, Statement};
use oxc_parser::{Parser, ParserReturn};
use oxc_span::SourceType;
use regex::{Captures, Regex};
use serde::Serialize;

use crate::js_string::unescape_string_literal;

#[derive(Debug, Clone, Default, Serialize)]
pub struct EvalIndirectionStats {
    pub eval_calls_seen: usize,
    pub function_calls_seen: usize,
    pub constant_folded: usize,
    pub detect_only_markers: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvalIndirectionResult {
    pub stats: EvalIndirectionStats,
    pub rewritten: String,
}

#[must_use]
pub fn peel_eval_indirection(source: &str) -> EvalIndirectionResult {
    let mut stats: EvalIndirectionStats = EvalIndirectionStats::default();
    count_via_ast(source, &mut stats);
    let folded: String = fold_constant_arguments(source, &mut stats);
    EvalIndirectionResult {
        stats,
        rewritten: folded,
    }
}

fn count_via_ast(source: &str, stats: &mut EvalIndirectionStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("eval-peel.js").unwrap_or_default();
    let parsed: ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return;
    }
    for stmt in &parsed.program.body {
        walk_statement(stmt, stats);
    }
}

fn walk_statement(stmt: &Statement<'_>, stats: &mut EvalIndirectionStats) {
    match stmt {
        Statement::ExpressionStatement(es) => walk_expression(&es.expression, stats),
        Statement::VariableDeclaration(vd) => {
            for declarator in &vd.declarations {
                if let Some(init) = &declarator.init {
                    walk_expression(init, stats);
                }
            }
        }
        Statement::BlockStatement(block) => {
            for inner in &block.body {
                walk_statement(inner, stats);
            }
        }
        Statement::ReturnStatement(ret) => {
            if let Some(expr) = &ret.argument {
                walk_expression(expr, stats);
            }
        }
        _ => {}
    }
}

fn walk_expression(expr: &Expression<'_>, stats: &mut EvalIndirectionStats) {
    match expr {
        Expression::CallExpression(call) => {
            classify_call_callee(&call.callee, stats);
            walk_expression(&call.callee, stats);
            for arg in &call.arguments {
                if let Some(expr) = arg.as_expression() {
                    walk_expression(expr, stats);
                }
            }
        }
        Expression::NewExpression(new_expr) => {
            if let Expression::Identifier(id) = &new_expr.callee
                && id.name == "Function"
            {
                stats.function_calls_seen += 1;
            }
            for arg in &new_expr.arguments {
                if let Some(expr) = arg.as_expression() {
                    walk_expression(expr, stats);
                }
            }
        }
        Expression::ParenthesizedExpression(paren) => walk_expression(&paren.expression, stats),
        Expression::SequenceExpression(seq) => {
            for inner in &seq.expressions {
                walk_expression(inner, stats);
            }
        }
        Expression::BinaryExpression(bin) => {
            walk_expression(&bin.left, stats);
            walk_expression(&bin.right, stats);
        }
        _ => {}
    }
}

fn classify_call_callee(callee: &Expression<'_>, stats: &mut EvalIndirectionStats) {
    match callee {
        Expression::Identifier(ident) => {
            if ident.name == "eval" {
                stats.eval_calls_seen += 1;
            } else if ident.name == "Function" {
                stats.function_calls_seen += 1;
            }
        }
        Expression::ParenthesizedExpression(paren) => {
            classify_call_callee(&paren.expression, stats);
        }
        Expression::CallExpression(inner) => {
            if let Expression::NewExpression(ne) = &inner.callee
                && let Expression::Identifier(id) = &ne.callee
                && id.name == "Function"
            {
                stats.function_calls_seen += 1;
            }
            if let Expression::Identifier(id) = &inner.callee
                && id.name == "Function"
            {
                stats.function_calls_seen += 1;
            }
        }
        _ => {}
    }
}

fn fold_constant_arguments(source: &str, stats: &mut EvalIndirectionStats) -> String {
    let after_eval: String = fold_eval_string_literal(source, stats);
    let after_new_fn: String = fold_new_function_invocation(&after_eval, stats);
    let after_call_fn: String = fold_function_invocation(&after_new_fn, stats);
    add_detect_only_markers(&after_call_fn, stats)
}

fn fold_eval_string_literal(source: &str, stats: &mut EvalIndirectionStats) -> String {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r#"(?s)\beval\s*\(\s*(?:'((?:\\.|[^'\\])*)'|"((?:\\.|[^"\\])*)")\s*\)"#)
    else {
        return source.to_owned();
    };
    let replaced: Cow<'_, str> = re.replace_all(source, |caps: &Captures<'_>| {
        let raw: Option<&str> = caps.get(1).or_else(|| caps.get(2)).map(|m| m.as_str());
        match raw {
            Some(payload) => {
                stats.constant_folded += 1;
                format!("/* dr-eval-folded */ {}", unescape_string_literal(payload))
            }
            None => caps[0].to_owned(),
        }
    });
    replaced.into_owned()
}

fn fold_new_function_invocation(source: &str, stats: &mut EvalIndirectionStats) -> String {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(
        r#"(?s)\(\s*new\s+Function\s*\(\s*(?:'((?:\\.|[^'\\])*)'|"((?:\\.|[^"\\])*)")\s*\)\s*\)\s*\(\s*\)"#,
    ) else {
        return source.to_owned();
    };
    let replaced: Cow<'_, str> = re.replace_all(source, |caps: &Captures<'_>| {
        let raw: Option<&str> = caps.get(1).or_else(|| caps.get(2)).map(|m| m.as_str());
        match raw {
            Some(payload) => {
                stats.constant_folded += 1;
                format!("/* dr-newfn-folded */ {}", unescape_string_literal(payload))
            }
            None => caps[0].to_owned(),
        }
    });
    replaced.into_owned()
}

fn fold_function_invocation(source: &str, stats: &mut EvalIndirectionStats) -> String {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(
        r#"(?s)\bFunction\s*\(\s*(?:'((?:\\.|[^'\\])*)'|"((?:\\.|[^"\\])*)")\s*\)\s*\(\s*\)"#,
    ) else {
        return source.to_owned();
    };
    let replaced: Cow<'_, str> = re.replace_all(source, |caps: &Captures<'_>| {
        let raw: Option<&str> = caps.get(1).or_else(|| caps.get(2)).map(|m| m.as_str());
        match raw {
            Some(payload) => {
                stats.constant_folded += 1;
                format!("/* dr-fn-folded */ {}", unescape_string_literal(payload))
            }
            None => caps[0].to_owned(),
        }
    });
    replaced.into_owned()
}

fn add_detect_only_markers(source: &str, stats: &mut EvalIndirectionStats) -> String {
    let pending_eval: usize = source
        .matches("eval(")
        .filter(|_| true)
        .count()
        .saturating_sub(source.matches("/* dr-eval-folded */").count());
    let pending_fn: usize = source
        .matches("Function(")
        .filter(|_| true)
        .count()
        .saturating_sub(source.matches("/* dr-fn-folded */").count())
        .saturating_sub(source.matches("/* dr-newfn-folded */").count());
    stats.detect_only_markers = pending_eval + pending_fn;
    source.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_eval_string_literal() {
        let src: &str = r#"eval("var x = 1;")"#;
        let res: EvalIndirectionResult = peel_eval_indirection(src);
        assert!(res.stats.constant_folded >= 1);
        assert!(res.rewritten.contains("var x = 1;"));
        assert!(res.rewritten.contains("dr-eval-folded"));
    }

    #[test]
    fn folds_new_function_iife() {
        let src: &str = r#"(new Function("return 42"))()"#;
        let res: EvalIndirectionResult = peel_eval_indirection(src);
        assert!(res.stats.constant_folded >= 1);
        assert!(res.rewritten.contains("return 42"));
    }

    #[test]
    fn leaves_non_constant_eval_alone_and_marks_detect_only() {
        let src: &str = "var x = compute(); eval(x);";
        let res: EvalIndirectionResult = peel_eval_indirection(src);
        assert_eq!(res.stats.constant_folded, 0);
        assert!(res.stats.eval_calls_seen >= 1);
        assert!(res.stats.detect_only_markers >= 1);
    }

    #[test]
    fn ast_walk_sees_function_constructor() {
        let src: &str = r#"var f = new Function("return 1"); f();"#;
        let res: EvalIndirectionResult = peel_eval_indirection(src);
        assert!(res.stats.function_calls_seen >= 1);
    }
}
