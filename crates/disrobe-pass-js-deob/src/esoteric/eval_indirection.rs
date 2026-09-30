use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, BindingPatternKind, Expression, Statement, VariableDeclaration,
    VariableDeclarationKind,
};
use oxc_parser::{Parser, ParserReturn};
use oxc_span::{GetSpan, SourceType};
use serde::Serialize;

use crate::scan_utils::reparses;

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
        Statement::IfStatement(branch) => {
            walk_expression(&branch.test, stats);
            walk_statement(&branch.consequent, stats);
            if let Some(alternate) = &branch.alternate {
                walk_statement(alternate, stats);
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
        Expression::LogicalExpression(logical) => {
            walk_expression(&logical.left, stats);
            walk_expression(&logical.right, stats);
        }
        Expression::ConditionalExpression(conditional) => {
            walk_expression(&conditional.test, stats);
            walk_expression(&conditional.consequent, stats);
            walk_expression(&conditional.alternate, stats);
        }
        Expression::AssignmentExpression(assignment) => walk_expression(&assignment.right, stats),
        Expression::UnaryExpression(unary) => walk_expression(&unary.argument, stats),
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
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("eval-peel.js").unwrap_or_default();
    let parsed: ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    let mut folds: Vec<StatementFold> = Vec::new();
    if parsed.errors.is_empty() && !parsed.panicked {
        collect_statement_folds(&parsed.program.body, &mut folds);
    }
    folds.sort_by_key(|fold: &StatementFold| fold.start);
    let mut out: String = String::with_capacity(source.len());
    let mut cursor: usize = 0;
    for fold in folds {
        if fold.start < cursor {
            continue;
        }
        out.push_str(&source[cursor..fold.start]);
        out.push_str(&fold.replacement);
        cursor = fold.end;
        stats.constant_folded += 1;
    }
    out.push_str(&source[cursor..]);
    stats.detect_only_markers =
        (stats.eval_calls_seen + stats.function_calls_seen).saturating_sub(stats.constant_folded);
    out
}

#[derive(Debug)]
struct StatementFold {
    start: usize,
    end: usize,
    replacement: String,
}

fn collect_statement_folds(statements: &[Statement<'_>], folds: &mut Vec<StatementFold>) {
    for statement in statements {
        match statement {
            Statement::ExpressionStatement(es) => {
                if let Some(replacement) = statement_fold(&es.expression) {
                    folds.push(StatementFold {
                        start: es.span.start as usize,
                        end: es.span.end as usize,
                        replacement,
                    });
                }
            }
            Statement::VariableDeclaration(declaration) => {
                if let Some(replacement) = declaration_fold(declaration) {
                    folds.push(StatementFold {
                        start: declaration.span.start as usize,
                        end: declaration.span.end as usize,
                        replacement,
                    });
                }
            }
            Statement::BlockStatement(block) => collect_statement_folds(&block.body, folds),
            Statement::FunctionDeclaration(function) => {
                if let Some(body) = &function.body {
                    collect_statement_folds(&body.statements, folds);
                }
            }
            _ => {}
        }
    }
}

fn statement_fold(expression: &Expression<'_>) -> Option<String> {
    let Expression::CallExpression(call) = expression.without_parentheses() else {
        return None;
    };
    if let Expression::Identifier(callee) = call.callee.without_parentheses()
        && callee.name == "eval"
    {
        let payload: &str = single_string_argument(&call.arguments)?;
        return reparses(payload).then(|| format!("/* dr-eval-folded */\n{payload}\n"));
    }
    if !call.arguments.is_empty() {
        return None;
    }
    let body: &str = match call.callee.without_parentheses() {
        Expression::CallExpression(constructor) => {
            let Expression::Identifier(callee) = constructor.callee.without_parentheses() else {
                return None;
            };
            if callee.name != "Function" {
                return None;
            }
            single_string_argument(&constructor.arguments)?
        }
        Expression::NewExpression(constructor) => {
            let Expression::Identifier(callee) = constructor.callee.without_parentheses() else {
                return None;
            };
            if callee.name != "Function" {
                return None;
            }
            single_string_argument(&constructor.arguments)?
        }
        _ => return None,
    };
    let wrapped: String = format!("(function () {{\n{body}\n}})();");
    reparses(&wrapped).then(|| format!("/* dr-fn-folded */\n{wrapped}\n"))
}

fn declaration_fold(declaration: &VariableDeclaration<'_>) -> Option<String> {
    if declaration.kind != VariableDeclarationKind::Var {
        return None;
    }
    let [declarator] = declaration.declarations.as_slice() else {
        return None;
    };
    let BindingPatternKind::BindingIdentifier(binding) = &declarator.id.kind else {
        return None;
    };
    let Some(Expression::CallExpression(call)) = declarator
        .init
        .as_ref()
        .map(Expression::without_parentheses)
    else {
        return None;
    };
    let Expression::Identifier(callee) = call.callee.without_parentheses() else {
        return None;
    };
    if callee.name != "eval" {
        return None;
    }
    let payload: &str = single_string_argument(&call.arguments)?;
    let (declarations, completion): (&str, &str) = split_completion(payload)?;
    let name: &str = binding.name.as_str();
    Some(format!(
        "/* dr-eval-folded */\n{declarations}\nvar {name} = ({completion});\n"
    ))
}

fn split_completion(payload: &str) -> Option<(&str, &str)> {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("eval-payload.js").unwrap_or_default();
    let parsed: ParserReturn<'_> = Parser::new(&allocator, payload, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked || !parsed.program.directives.is_empty() {
        return None;
    }
    let body: &[Statement<'_>] = &parsed.program.body;
    let (last, leading): (&Statement<'_>, &[Statement<'_>]) = body.split_last()?;
    let is_var = |statement: &Statement<'_>| matches!(statement, Statement::VariableDeclaration(declaration) if declaration.kind == VariableDeclarationKind::Var);
    if !leading.iter().all(is_var) {
        return None;
    }
    if is_var(last) {
        return Some((payload, "void 0"));
    }
    let Statement::ExpressionStatement(completion) = last else {
        return None;
    };
    let declarations: &str = payload.get(..last.span().start as usize)?;
    let expression: &str = payload.get(
        completion.expression.span().start as usize..completion.expression.span().end as usize,
    )?;
    Some((declarations, expression))
}

fn single_string_argument<'a>(arguments: &'a [Argument<'a>]) -> Option<&'a str> {
    let [argument] = arguments else {
        return None;
    };
    match argument.as_expression()?.without_parentheses() {
        Expression::StringLiteral(literal) => Some(literal.value.as_str()),
        _ => None,
    }
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
    fn calls_inside_expressions_are_left_alone_and_the_output_reparses() {
        for src in [
            "var y = 2*eval(\"1+2\");",
            "var root = freeGlobal || freeSelf || Function('return this')();",
            "if (eval(\"flag\")) { go(); }",
        ] {
            let res: EvalIndirectionResult = peel_eval_indirection(src);
            assert_eq!(res.stats.constant_folded, 0, "{src}");
            assert_eq!(res.rewritten, src);
            assert!(res.stats.detect_only_markers >= 1, "{src}");
        }
    }

    #[test]
    fn a_function_body_keeps_its_function_scope_when_folded() {
        let src: &str = "Function('return this')();\nnext();";
        let res: EvalIndirectionResult = peel_eval_indirection(src);
        assert_eq!(res.stats.constant_folded, 1);
        assert!(
            res.rewritten.contains("(function () {\nreturn this\n})();"),
            "{}",
            res.rewritten
        );
        assert!(reparses(&res.rewritten), "{}", res.rewritten);
    }

    #[test]
    fn a_var_initialized_by_eval_keeps_the_payload_declarations_and_its_completion_value() {
        let src: &str = r#"var z = eval("var a = 20; a + 22"); log(z, a);"#;
        let res: EvalIndirectionResult = peel_eval_indirection(src);
        assert_eq!(res.stats.constant_folded, 1);
        assert!(
            res.rewritten
                .contains("var a = 20; \nvar z = (a + 22);\n log(z, a);"),
            "{}",
            res.rewritten
        );
        assert!(reparses(&res.rewritten), "{}", res.rewritten);
    }

    #[test]
    fn a_var_initialized_by_a_declaration_only_eval_receives_undefined() {
        let src: &str = r#"var z = eval("var a = 1;");"#;
        let res: EvalIndirectionResult = peel_eval_indirection(src);
        assert_eq!(res.stats.constant_folded, 1);
        assert!(
            res.rewritten.contains("var a = 1;\nvar z = (void 0);"),
            "{}",
            res.rewritten
        );
    }

    #[test]
    fn an_eval_initializer_whose_completion_or_scope_would_change_is_left_alone() {
        for src in [
            r#"var z = eval("let a = 1; a");"#,
            r#"var z = eval("if (x) { 1 } else { 2 }");"#,
            r#"var z = eval("f(); var a = 1;");"#,
            r#"let z = eval("var a = 1;");"#,
            r#"var y = 1, z = eval("var a = 1;");"#,
            r#"var z = eval("'use strict'; var a = 1;");"#,
        ] {
            let res: EvalIndirectionResult = peel_eval_indirection(src);
            assert_eq!(res.stats.constant_folded, 0, "{src}");
            assert_eq!(res.rewritten, src);
        }
    }

    #[test]
    fn a_payload_that_does_not_parse_is_not_folded() {
        let src: &str = "eval(\"var = ;\");";
        let res: EvalIndirectionResult = peel_eval_indirection(src);
        assert_eq!(res.stats.constant_folded, 0);
        assert_eq!(res.rewritten, src);
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
