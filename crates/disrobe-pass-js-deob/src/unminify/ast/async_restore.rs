use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, Expression, Function, Program, Statement, VariableDeclaration, VariableDeclarator,
};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType, Span};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct AsyncRestoreStats {
    pub(super) async_to_generator: usize,
    pub(super) regenerator: usize,
}

struct YieldScan {
    spans: Vec<Span>,
    has_delegate: bool,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, AsyncRestoreStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), AsyncRestoreStats::default());
    }
    let program: &Program<'_> = &parsed.program;
    let statements: &[Statement<'_>] = program.body.as_slice();

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: AsyncRestoreStats = AsyncRestoreStats::default();

    let mut index: usize = 0;
    while index < statements.len() {
        let consumed: Option<usize> =
            try_wrapper_pair(source, statements, index, &mut edits, &mut stats);
        if let Some(step) = consumed {
            index += step;
            continue;
        }
        index += 1;
    }

    collect_direct_assignments(source, statements, &mut edits, &mut stats);

    (RuleOutcome { edits }, stats)
}

fn try_wrapper_pair(
    source: &str,
    statements: &[Statement<'_>],
    start: usize,
    edits: &mut Vec<Edit>,
    stats: &mut AsyncRestoreStats,
) -> Option<usize> {
    let Statement::FunctionDeclaration(public_fn): &Statement<'_> = &statements[start] else {
        return None;
    };
    let public_name: &str = public_fn.id.as_ref()?.name.as_str();
    if public_fn.r#async || public_fn.generator {
        return None;
    }
    let helper_name: &str = wrapper_returns_apply(public_fn)?;

    let helper_index: usize = start + 1;
    let helper_fn: &Function<'_> = statements
        .get(helper_index)
        .and_then(named_function_declaration)?;
    if helper_fn.id.as_ref()?.name.as_str() != helper_name {
        return None;
    }
    let generator: &Function<'_> = helper_reassigns_async_to_generator(helper_fn, helper_name)?;
    if !generator.generator || generator.r#async {
        return None;
    }

    let scan: YieldScan = scan_top_level_yields(generator);
    if scan.has_delegate {
        return None;
    }
    let body_start: u32 = generator.body.as_ref()?.span.start;
    let (params_src, body_src): (String, String) = generator_params_body(source, generator)?;
    let rendered: String =
        render_async_function(public_name, &params_src, &body_src, &scan, body_start);

    let replace_span: Span = Span::new(
        statements[start].span().start,
        statements[helper_index].span().end,
    );
    edits.push(Edit {
        start: replace_span.start as usize,
        end: replace_span.end as usize,
        replacement: rendered,
    });
    stats.async_to_generator += 1;
    Some(2)
}

fn wrapper_returns_apply<'a>(func: &Function<'a>) -> Option<&'a str> {
    let body: &oxc_allocator::Box<'a, oxc_ast::ast::FunctionBody<'a>> = func.body.as_ref()?;
    if body.statements.len() != 1 {
        return None;
    }
    let Statement::ReturnStatement(ret): &Statement<'a> = &body.statements[0] else {
        return None;
    };
    let arg: &Expression<'a> = ret.argument.as_ref()?;
    apply_target(arg)
}

fn apply_target<'a>(expr: &Expression<'a>) -> Option<&'a str> {
    let Expression::CallExpression(call): &Expression<'a> = expr else {
        return None;
    };
    let member: &oxc_ast::ast::MemberExpression<'a> = call.callee.as_member_expression()?;
    let oxc_ast::ast::MemberExpression::StaticMemberExpression(sm): &oxc_ast::ast::MemberExpression<'a> =
        member
    else {
        return None;
    };
    if sm.property.name.as_str() != "apply" {
        return None;
    }
    let Expression::Identifier(target): &Expression<'a> = &sm.object else {
        return None;
    };
    if call.arguments.len() != 2 {
        return None;
    }
    if !matches!(&call.arguments[0], Argument::ThisExpression(_)) {
        return None;
    }
    let Argument::Identifier(args_ident): &Argument<'a> = &call.arguments[1] else {
        return None;
    };
    if args_ident.name.as_str() != "arguments" {
        return None;
    }
    Some(target.name.as_str())
}

fn named_function_declaration<'a, 'b>(stmt: &'b Statement<'a>) -> Option<&'b Function<'a>> {
    let Statement::FunctionDeclaration(func): &'b Statement<'a> = stmt else {
        return None;
    };
    Some(func)
}

fn helper_reassigns_async_to_generator<'a, 'b>(
    helper: &'b Function<'a>,
    helper_name: &str,
) -> Option<&'b Function<'a>> {
    let body: &'b oxc_allocator::Box<'a, oxc_ast::ast::FunctionBody<'a>> = helper.body.as_ref()?;
    let first: &'b Statement<'a> = body.statements.first()?;
    let Statement::ExpressionStatement(expr_stmt): &'b Statement<'a> = first else {
        return None;
    };
    let Expression::AssignmentExpression(assign): &'b Expression<'a> = &expr_stmt.expression else {
        return None;
    };
    let oxc_ast::ast::AssignmentTarget::AssignmentTargetIdentifier(lhs) = &assign.left else {
        return None;
    };
    if lhs.name.as_str() != helper_name {
        return None;
    }
    async_to_generator_arg(&assign.right)
}

fn async_to_generator_arg<'a, 'b>(expr: &'b Expression<'a>) -> Option<&'b Function<'a>> {
    let Expression::CallExpression(call): &'b Expression<'a> = expr else {
        return None;
    };
    let Expression::Identifier(callee): &'b Expression<'a> = &call.callee else {
        return None;
    };
    if callee.name.as_str() != "_asyncToGenerator" && callee.name.as_str() != "_asyncToGenerator2" {
        return None;
    }
    if call.arguments.len() != 1 {
        return None;
    }
    let Argument::FunctionExpression(func): &'b Argument<'a> = &call.arguments[0] else {
        return None;
    };
    Some(func)
}

fn collect_direct_assignments(
    source: &str,
    statements: &[Statement<'_>],
    edits: &mut Vec<Edit>,
    stats: &mut AsyncRestoreStats,
) {
    for stmt in statements {
        let Statement::VariableDeclaration(decl): &Statement<'_> = stmt else {
            continue;
        };
        handle_var_decl(source, decl, edits, stats);
    }
}

fn handle_var_decl(
    source: &str,
    decl: &VariableDeclaration<'_>,
    edits: &mut Vec<Edit>,
    stats: &mut AsyncRestoreStats,
) {
    for declarator in &decl.declarations {
        let Some(init): Option<&Expression<'_>> = declarator.init.as_ref() else {
            continue;
        };
        let Some(generator): Option<&Function<'_>> = async_to_generator_arg(init) else {
            continue;
        };
        if generator.r#async {
            continue;
        }
        if !declarator_is_simple(declarator) {
            continue;
        }
        let scan: YieldScan = scan_top_level_yields(generator);
        if scan.has_delegate {
            continue;
        }
        let Some(body_box): Option<&oxc_allocator::Box<'_, oxc_ast::ast::FunctionBody<'_>>> =
            generator.body.as_ref()
        else {
            continue;
        };
        let body_start: u32 = body_box.span.start;
        let Some((params_src, body_src)): Option<(String, String)> =
            generator_params_body(source, generator)
        else {
            continue;
        };
        let rendered: String = render_async_expression(&params_src, &body_src, &scan, body_start);
        let init_span: Span = init.span();
        edits.push(Edit {
            start: init_span.start as usize,
            end: init_span.end as usize,
            replacement: rendered,
        });
        stats.async_to_generator += 1;
    }
}

const fn declarator_is_simple(declarator: &VariableDeclarator<'_>) -> bool {
    matches!(
        &declarator.id.kind,
        oxc_ast::ast::BindingPatternKind::BindingIdentifier(_)
    )
}

fn generator_params_body(source: &str, func: &Function<'_>) -> Option<(String, String)> {
    let span: Span = func.params.span;
    let raw: &str = span.source_text(source);
    let params_src: String = raw
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim()
        .to_owned();
    let body: &oxc_allocator::Box<'_, oxc_ast::ast::FunctionBody<'_>> = func.body.as_ref()?;
    let body_src: String = body.span.source_text(source).to_owned();
    Some((params_src, body_src))
}

fn scan_top_level_yields(func: &Function<'_>) -> YieldScan {
    let mut scan: YieldScan = YieldScan {
        spans: Vec::new(),
        has_delegate: false,
    };
    let Some(body): Option<&oxc_allocator::Box<'_, oxc_ast::ast::FunctionBody<'_>>> =
        func.body.as_ref()
    else {
        return scan;
    };
    for stmt in &body.statements {
        walk_statement_yields(stmt, &mut scan);
    }
    scan
}

fn walk_statement_yields(stmt: &Statement<'_>, scan: &mut YieldScan) {
    match stmt {
        Statement::ExpressionStatement(s) => walk_expr_yields(&s.expression, scan),
        Statement::ReturnStatement(s) => {
            if let Some(arg) = s.argument.as_ref() {
                walk_expr_yields(arg, scan);
            }
        }
        Statement::VariableDeclaration(s) => {
            for d in &s.declarations {
                if let Some(init) = d.init.as_ref() {
                    walk_expr_yields(init, scan);
                }
            }
        }
        Statement::IfStatement(s) => {
            walk_expr_yields(&s.test, scan);
            walk_statement_yields(&s.consequent, scan);
            if let Some(alt) = s.alternate.as_ref() {
                walk_statement_yields(alt, scan);
            }
        }
        Statement::BlockStatement(s) => {
            for inner in &s.body {
                walk_statement_yields(inner, scan);
            }
        }
        Statement::ForStatement(s) => {
            if let Some(test) = s.test.as_ref() {
                walk_expr_yields(test, scan);
            }
            walk_statement_yields(&s.body, scan);
        }
        Statement::WhileStatement(s) => {
            walk_expr_yields(&s.test, scan);
            walk_statement_yields(&s.body, scan);
        }
        Statement::TryStatement(s) => {
            for inner in &s.block.body {
                walk_statement_yields(inner, scan);
            }
            if let Some(handler) = s.handler.as_ref() {
                for inner in &handler.body.body {
                    walk_statement_yields(inner, scan);
                }
            }
            if let Some(finalizer) = s.finalizer.as_ref() {
                for inner in &finalizer.body {
                    walk_statement_yields(inner, scan);
                }
            }
        }
        Statement::SwitchStatement(s) => {
            walk_expr_yields(&s.discriminant, scan);
            for case in &s.cases {
                for inner in &case.consequent {
                    walk_statement_yields(inner, scan);
                }
            }
        }
        Statement::ThrowStatement(s) => walk_expr_yields(&s.argument, scan),
        _ => {}
    }
}

fn walk_expr_yields(expr: &Expression<'_>, scan: &mut YieldScan) {
    match expr {
        Expression::YieldExpression(y) => {
            if y.delegate {
                scan.has_delegate = true;
            }
            scan.spans.push(y.span);
            if let Some(arg) = y.argument.as_ref() {
                walk_expr_yields(arg, scan);
            }
        }
        Expression::BinaryExpression(b) => {
            walk_expr_yields(&b.left, scan);
            walk_expr_yields(&b.right, scan);
        }
        Expression::LogicalExpression(b) => {
            walk_expr_yields(&b.left, scan);
            walk_expr_yields(&b.right, scan);
        }
        Expression::AssignmentExpression(a) => walk_expr_yields(&a.right, scan),
        Expression::ConditionalExpression(c) => {
            walk_expr_yields(&c.test, scan);
            walk_expr_yields(&c.consequent, scan);
            walk_expr_yields(&c.alternate, scan);
        }
        Expression::ParenthesizedExpression(p) => walk_expr_yields(&p.expression, scan),
        Expression::AwaitExpression(a) => walk_expr_yields(&a.argument, scan),
        Expression::UnaryExpression(u) => walk_expr_yields(&u.argument, scan),
        Expression::SequenceExpression(s) => {
            for inner in &s.expressions {
                walk_expr_yields(inner, scan);
            }
        }
        Expression::CallExpression(c) => {
            for arg in &c.arguments {
                if let Argument::SpreadElement(spread) = arg {
                    walk_expr_yields(&spread.argument, scan);
                } else if let Some(inner) = arg.as_expression() {
                    walk_expr_yields(inner, scan);
                }
            }
        }
        _ => {}
    }
}

fn render_async_function(
    name: &str,
    params: &str,
    body: &str,
    scan: &YieldScan,
    body_start: u32,
) -> String {
    let body_awaited: String = rewrite_yields_in_body(body, scan, body_start);
    format!("async function {name}({params}) {body_awaited}")
}

fn render_async_expression(params: &str, body: &str, scan: &YieldScan, body_start: u32) -> String {
    let body_awaited: String = rewrite_yields_in_body(body, scan, body_start);
    format!("async function ({params}) {body_awaited}")
}

fn rewrite_yields_in_body(body: &str, scan: &YieldScan, body_start: u32) -> String {
    let mut local_spans: Vec<(usize, usize)> = scan
        .spans
        .iter()
        .filter_map(|span: &Span| {
            let start: u32 = span.start.checked_sub(body_start)?;
            let yk: &str = body.get(start as usize..start as usize + 5)?;
            if yk == "yield" {
                Some((start as usize, start as usize + 5))
            } else {
                None
            }
        })
        .collect();
    local_spans.sort_by_key(|span: &(usize, usize)| core::cmp::Reverse(span.0));
    let mut out: String = body.to_owned();
    for span in &local_spans {
        out.replace_range(span.0..span.1, "await");
    }
    out
}
