use oxc_allocator::Allocator;
use oxc_ast::ast::{
    CallExpression, Expression, Function, FunctionBody, Program, Statement, UnaryOperator,
};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct IifeUnwrapStats {
    pub(super) iifes_unwrapped: usize,
    pub(super) statements_hoisted: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, IifeUnwrapStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), IifeUnwrapStats::default());
    }
    let program: &Program<'_> = &parsed.program;

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: IifeUnwrapStats = IifeUnwrapStats::default();
    for stmt in &program.body {
        if let Statement::ExpressionStatement(expr_stmt) = stmt
            && let Some((func, body)) = top_level_iife(&expr_stmt.expression)
            && let Some(replacement) = hoist_body(func, body, source)
        {
            edits.push(Edit {
                start: stmt.span().start as usize,
                end: stmt.span().end as usize,
                replacement,
            });
            stats.iifes_unwrapped += 1;
            stats.statements_hoisted += body.statements.len();
        }
    }

    if edits.is_empty() {
        return (RuleOutcome::empty(), stats);
    }
    (RuleOutcome { edits }, stats)
}

fn top_level_iife<'a>(
    expr: &'a Expression<'a>,
) -> Option<(&'a Function<'a>, &'a FunctionBody<'a>)> {
    let call: &CallExpression<'a> = match expr {
        Expression::CallExpression(call) => call.as_ref(),
        Expression::UnaryExpression(unary)
            if matches!(
                unary.operator,
                UnaryOperator::LogicalNot | UnaryOperator::UnaryNegation | UnaryOperator::Void
            ) =>
        {
            match unary.argument.get_inner_expression() {
                Expression::CallExpression(call) => call.as_ref(),
                _ => return None,
            }
        }
        _ => return None,
    };
    if !call.arguments.is_empty() {
        return None;
    }
    let Expression::FunctionExpression(func) = call.callee.get_inner_expression() else {
        return None;
    };
    if func.r#async || func.generator {
        return None;
    }
    if !func.params.items.is_empty() || func.params.rest.is_some() {
        return None;
    }
    let body: &FunctionBody<'a> = func.body.as_ref()?;
    Some((func.as_ref(), body))
}

fn hoist_body(func: &Function<'_>, body: &FunctionBody<'_>, source: &str) -> Option<String> {
    if body.statements.is_empty() {
        return Some(";".to_owned());
    }
    if let Some(name) = func.id.as_ref()
        && statements_reference_name(body.statements.as_slice(), name.name.as_str())
    {
        return None;
    }
    let mut escape: bool = false;
    scan_statements_for_escape(body.statements.as_slice(), &mut escape);
    if escape {
        return None;
    }
    let mut pieces: Vec<String> = Vec::with_capacity(body.statements.len());
    for stmt in &body.statements {
        pieces.push(stmt.span().source_text(source).to_owned());
    }
    Some(pieces.join("\n"))
}

fn statements_reference_name(statements: &[Statement<'_>], target: &str) -> bool {
    let mut found: bool = false;
    for stmt in statements {
        scan_statement_for_name(stmt, target, &mut found, 0);
        if found {
            return true;
        }
    }
    found
}

const MAX_SCAN_DEPTH: usize = 512;

fn scan_statement_for_name(stmt: &Statement<'_>, target: &str, found: &mut bool, depth: usize) {
    if *found || depth > MAX_SCAN_DEPTH {
        return;
    }
    visit_child_statements(stmt, &mut |child: &Statement<'_>| {
        scan_statement_for_name(child, target, found, depth + 1);
    });
    visit_statement_expressions(stmt, &mut |expr: &Expression<'_>| {
        scan_expression_for_name(expr, target, found, depth + 1);
    });
}

fn scan_expression_for_name(expr: &Expression<'_>, target: &str, found: &mut bool, depth: usize) {
    if *found || depth > MAX_SCAN_DEPTH {
        return;
    }
    if let Expression::Identifier(ident) = expr
        && ident.name.as_str() == target
    {
        *found = true;
        return;
    }
    visit_child_expressions(expr, &mut |child: &Expression<'_>| {
        scan_expression_for_name(child, target, found, depth + 1);
    });
}

fn scan_statements_for_escape(statements: &[Statement<'_>], escape: &mut bool) {
    for stmt in statements {
        scan_statement_for_escape(stmt, escape, 0);
        if *escape {
            return;
        }
    }
}

fn scan_statement_for_escape(stmt: &Statement<'_>, escape: &mut bool, depth: usize) {
    if *escape || depth > MAX_SCAN_DEPTH {
        return;
    }
    match stmt {
        Statement::ReturnStatement(_) => {
            *escape = true;
            return;
        }
        Statement::FunctionDeclaration(_) => return,
        _ => {}
    }
    visit_child_statements(stmt, &mut |child: &Statement<'_>| {
        scan_statement_for_escape(child, escape, depth + 1);
    });
    visit_statement_expressions(stmt, &mut |expr: &Expression<'_>| {
        scan_expression_for_escape(expr, escape, depth + 1);
    });
}

fn scan_expression_for_escape(expr: &Expression<'_>, escape: &mut bool, depth: usize) {
    if *escape || depth > MAX_SCAN_DEPTH {
        return;
    }
    match expr {
        Expression::ThisExpression(_) => {
            *escape = true;
            return;
        }
        Expression::Identifier(ident) if ident.name.as_str() == "arguments" => {
            *escape = true;
            return;
        }
        Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_) => return,
        _ => {}
    }
    visit_child_expressions(expr, &mut |child: &Expression<'_>| {
        scan_expression_for_escape(child, escape, depth + 1);
    });
}

fn visit_child_statements(stmt: &Statement<'_>, f: &mut dyn FnMut(&Statement<'_>)) {
    match stmt {
        Statement::BlockStatement(s) => s.body.iter().for_each(f),
        Statement::IfStatement(s) => {
            f(&s.consequent);
            if let Some(alt) = s.alternate.as_ref() {
                f(alt);
            }
        }
        Statement::ForStatement(s) => f(&s.body),
        Statement::ForInStatement(s) => f(&s.body),
        Statement::ForOfStatement(s) => f(&s.body),
        Statement::WhileStatement(s) => f(&s.body),
        Statement::DoWhileStatement(s) => f(&s.body),
        Statement::LabeledStatement(s) => f(&s.body),
        Statement::WithStatement(s) => f(&s.body),
        Statement::SwitchStatement(s) => {
            for case in &s.cases {
                case.consequent.iter().for_each(&mut *f);
            }
        }
        Statement::TryStatement(s) => {
            s.block.body.iter().for_each(&mut *f);
            if let Some(handler) = s.handler.as_ref() {
                handler.body.body.iter().for_each(&mut *f);
            }
            if let Some(finalizer) = s.finalizer.as_ref() {
                finalizer.body.iter().for_each(&mut *f);
            }
        }
        _ => {}
    }
}

fn visit_statement_expressions(stmt: &Statement<'_>, f: &mut dyn FnMut(&Expression<'_>)) {
    match stmt {
        Statement::ExpressionStatement(s) => f(&s.expression),
        Statement::IfStatement(s) => f(&s.test),
        Statement::ForStatement(s) => {
            if let Some(test) = s.test.as_ref() {
                f(test);
            }
            if let Some(update) = s.update.as_ref() {
                f(update);
            }
        }
        Statement::WhileStatement(s) => f(&s.test),
        Statement::DoWhileStatement(s) => f(&s.test),
        Statement::SwitchStatement(s) => f(&s.discriminant),
        Statement::ThrowStatement(s) => f(&s.argument),
        Statement::VariableDeclaration(s) => {
            for declarator in &s.declarations {
                if let Some(init) = declarator.init.as_ref() {
                    f(init);
                }
            }
        }
        Statement::ReturnStatement(s) => {
            if let Some(argument) = s.argument.as_ref() {
                f(argument);
            }
        }
        _ => {}
    }
}

fn visit_child_expressions(expr: &Expression<'_>, f: &mut dyn FnMut(&Expression<'_>)) {
    match expr {
        Expression::ParenthesizedExpression(e) => f(&e.expression),
        Expression::UnaryExpression(e) => f(&e.argument),
        Expression::AwaitExpression(e) => f(&e.argument),
        Expression::BinaryExpression(e) => {
            f(&e.left);
            f(&e.right);
        }
        Expression::LogicalExpression(e) => {
            f(&e.left);
            f(&e.right);
        }
        Expression::AssignmentExpression(e) => f(&e.right),
        Expression::ConditionalExpression(e) => {
            f(&e.test);
            f(&e.consequent);
            f(&e.alternate);
        }
        Expression::SequenceExpression(e) => e.expressions.iter().for_each(f),
        Expression::CallExpression(e) => {
            f(&e.callee);
            for arg in &e.arguments {
                if let Some(arg_expr) = arg.as_expression() {
                    f(arg_expr);
                }
            }
        }
        Expression::NewExpression(e) => {
            f(&e.callee);
            for arg in &e.arguments {
                if let Some(arg_expr) = arg.as_expression() {
                    f(arg_expr);
                }
            }
        }
        Expression::StaticMemberExpression(e) => f(&e.object),
        Expression::ComputedMemberExpression(e) => {
            f(&e.object);
            f(&e.expression);
        }
        Expression::ArrayExpression(e) => {
            for element in &e.elements {
                if let Some(element_expr) = element.as_expression() {
                    f(element_expr);
                }
            }
        }
        Expression::TemplateLiteral(e) => e.expressions.iter().for_each(f),
        _ => {}
    }
}
