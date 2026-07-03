use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, AssignmentOperator, AssignmentTarget, Expression, Function, FunctionBody, Program,
    Statement, SwitchCase,
};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType, Span};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct RegeneratorRestoreStats {
    pub(super) generators_restored: usize,
    pub(super) async_functions_restored: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, RegeneratorRestoreStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), RegeneratorRestoreStats::default());
    }
    let program: &Program<'_> = &parsed.program;

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: RegeneratorRestoreStats = RegeneratorRestoreStats::default();
    let statements: &[Statement<'_>] = program.body.as_slice();

    let mut index: usize = 0;
    while index < statements.len() {
        if let Some(consumed) = try_async_pair(source, statements, index, &mut edits, &mut stats) {
            index += consumed;
            continue;
        }
        if try_plain_generator(source, &statements[index], &mut edits, &mut stats) {
            index += 1;
            continue;
        }
        index += 1;
    }

    if edits.is_empty() {
        return (RuleOutcome::empty(), stats);
    }
    (RuleOutcome { edits }, stats)
}

struct ReconstructedBody {
    params: String,
    body: String,
}

fn try_plain_generator(
    source: &str,
    stmt: &Statement<'_>,
    edits: &mut Vec<Edit>,
    stats: &mut RegeneratorRestoreStats,
) -> bool {
    let Statement::FunctionDeclaration(func) = stmt else {
        return false;
    };
    if func.r#async || func.generator {
        return false;
    }
    let Some(name) = func.id.as_ref().map(|id| id.name.as_str()) else {
        return false;
    };
    let Some(reconstructed): Option<ReconstructedBody> = reconstruct_generator(source, func) else {
        return false;
    };
    let rendered: String = format!(
        "function* {name}({}) {}",
        reconstructed.params, reconstructed.body
    );
    edits.push(Edit {
        start: func.span.start as usize,
        end: func.span.end as usize,
        replacement: rendered,
    });
    stats.generators_restored += 1;
    true
}

fn try_async_pair(
    source: &str,
    statements: &[Statement<'_>],
    start: usize,
    edits: &mut Vec<Edit>,
    stats: &mut RegeneratorRestoreStats,
) -> Option<usize> {
    let Statement::FunctionDeclaration(public_fn) = &statements[start] else {
        return None;
    };
    if public_fn.r#async || public_fn.generator {
        return None;
    }
    let public_name: &str = public_fn.id.as_ref()?.name.as_str();
    let helper_name: &str = wrapper_returns_apply(public_fn)?;

    let helper_index: usize = start + 1;
    let helper_stmt: &Statement<'_> = statements.get(helper_index)?;
    let Statement::FunctionDeclaration(helper_fn) = helper_stmt else {
        return None;
    };
    if helper_fn.id.as_ref()?.name.as_str() != helper_name {
        return None;
    }
    let inner: &Function<'_> = helper_reassigns_async_marked(helper_fn, helper_name)?;
    let reconstructed: ReconstructedBody = reconstruct_generator(source, inner)?;
    let async_body: String = reconstructed.body.replace("yield ", "await ");
    let rendered: String = format!(
        "async function {public_name}({}) {async_body}",
        reconstructed.params
    );
    let replace_span: Span = Span::new(
        statements[start].span().start,
        statements[helper_index].span().end,
    );
    edits.push(Edit {
        start: replace_span.start as usize,
        end: replace_span.end as usize,
        replacement: rendered,
    });
    stats.async_functions_restored += 1;
    Some(2)
}

fn wrapper_returns_apply<'a>(func: &Function<'a>) -> Option<&'a str> {
    let body: &FunctionBody<'a> = func.body.as_ref()?;
    if body.statements.len() != 1 {
        return None;
    }
    let Statement::ReturnStatement(ret) = &body.statements[0] else {
        return None;
    };
    apply_target(ret.argument.as_ref()?)
}

fn apply_target<'a>(expr: &Expression<'a>) -> Option<&'a str> {
    let Expression::CallExpression(call) = expr else {
        return None;
    };
    let member = call.callee.as_member_expression()?;
    let oxc_ast::ast::MemberExpression::StaticMemberExpression(sm) = member else {
        return None;
    };
    if sm.property.name.as_str() != "apply" {
        return None;
    }
    let Expression::Identifier(target) = &sm.object else {
        return None;
    };
    if call.arguments.len() != 2 {
        return None;
    }
    if !matches!(&call.arguments[0], Argument::ThisExpression(_)) {
        return None;
    }
    let Argument::Identifier(args_ident) = &call.arguments[1] else {
        return None;
    };
    if args_ident.name.as_str() != "arguments" {
        return None;
    }
    Some(target.name.as_str())
}

fn helper_reassigns_async_marked<'a, 'b>(
    helper: &'b Function<'a>,
    helper_name: &str,
) -> Option<&'b Function<'a>> {
    let body: &'b FunctionBody<'a> = helper.body.as_ref()?;
    let first: &'b Statement<'a> = body.statements.first()?;
    let Statement::ExpressionStatement(expr_stmt) = first else {
        return None;
    };
    let Expression::AssignmentExpression(assign) = &expr_stmt.expression else {
        return None;
    };
    let AssignmentTarget::AssignmentTargetIdentifier(lhs) = &assign.left else {
        return None;
    };
    if lhs.name.as_str() != helper_name {
        return None;
    }
    async_to_generator_marked_arg(&assign.right)
}

fn async_to_generator_marked_arg<'a, 'b>(expr: &'b Expression<'a>) -> Option<&'b Function<'a>> {
    let Expression::CallExpression(call) = expr else {
        return None;
    };
    let Expression::Identifier(callee) = &call.callee else {
        return None;
    };
    if !callee.name.as_str().contains("asyncToGenerator") {
        return None;
    }
    if call.arguments.len() != 1 {
        return None;
    }
    marked_generator_arg(call.arguments[0].as_expression()?)
}

fn marked_generator_arg<'a, 'b>(expr: &'b Expression<'a>) -> Option<&'b Function<'a>> {
    if let Expression::FunctionExpression(func) = expr {
        return Some(func);
    }
    let Expression::CallExpression(call) = expr else {
        return None;
    };
    if !callee_is_mark(&call.callee) {
        return None;
    }
    let Argument::FunctionExpression(func) = call.arguments.first()? else {
        return None;
    };
    Some(func)
}

fn callee_is_mark(callee: &Expression<'_>) -> bool {
    let Some(member) = callee.as_member_expression() else {
        return false;
    };
    let oxc_ast::ast::MemberExpression::StaticMemberExpression(sm) = member else {
        return false;
    };
    matches!(sm.property.name.as_str(), "mark" | "m")
}

fn reconstruct_generator(source: &str, marked: &Function<'_>) -> Option<ReconstructedBody> {
    let body: &FunctionBody<'_> = marked.body.as_ref()?;
    let mut hoisted: Vec<&str> = Vec::new();
    let mut wrap_callback: Option<&Function<'_>> = None;
    for stmt in &body.statements {
        match stmt {
            Statement::VariableDeclaration(decl) => {
                for declarator in &decl.declarations {
                    if declarator.init.is_some() {
                        return None;
                    }
                    let oxc_ast::ast::BindingPatternKind::BindingIdentifier(ident) =
                        &declarator.id.kind
                    else {
                        return None;
                    };
                    hoisted.push(ident.name.as_str());
                }
            }
            Statement::ReturnStatement(ret) => {
                wrap_callback = Some(wrap_callback_function(ret.argument.as_ref()?)?);
            }
            _ => return None,
        }
    }
    let wrap_callback: &Function<'_> = wrap_callback?;
    let context_name: &str = single_param_name(wrap_callback)?;
    let all_cases: Vec<&SwitchCase<'_>> = state_machine_cases(wrap_callback, context_name)?;
    let cases: Vec<&SwitchCase<'_>> = strip_terminal_cases(&all_cases, context_name)?;
    let body_src: String = lower_linear_cases(source, &cases, context_name, &hoisted)?;
    let params: String = function_params_src(source, marked);
    Some(ReconstructedBody {
        params,
        body: body_src,
    })
}

fn wrap_callback_function<'a, 'b>(expr: &'b Expression<'a>) -> Option<&'b Function<'a>> {
    let Expression::CallExpression(call) = expr else {
        return None;
    };
    if !callee_is_wrap(&call.callee) {
        return None;
    }
    let Argument::FunctionExpression(func) = call.arguments.first()? else {
        return None;
    };
    Some(func)
}

fn callee_is_wrap(callee: &Expression<'_>) -> bool {
    if let Expression::Identifier(ident) = callee {
        return ident.name.as_str().ends_with("wrap");
    }
    let Some(member) = callee.as_member_expression() else {
        return false;
    };
    let oxc_ast::ast::MemberExpression::StaticMemberExpression(sm) = member else {
        return false;
    };
    matches!(sm.property.name.as_str(), "wrap" | "w")
}

fn single_param_name<'a>(func: &Function<'a>) -> Option<&'a str> {
    if func.params.items.len() != 1 || func.params.rest.is_some() {
        return None;
    }
    let oxc_ast::ast::BindingPatternKind::BindingIdentifier(ident) =
        &func.params.items[0].pattern.kind
    else {
        return None;
    };
    Some(ident.name.as_str())
}

fn state_machine_cases<'a, 'b>(
    func: &'b Function<'a>,
    context_name: &str,
) -> Option<Vec<&'b SwitchCase<'a>>> {
    let body: &'b FunctionBody<'a> = func.body.as_ref()?;
    if body.statements.len() != 1 {
        return None;
    }
    let switch_stmt: &'b oxc_ast::ast::SwitchStatement<'a> = match &body.statements[0] {
        Statement::WhileStatement(while_stmt) => unwrap_while_switch(&while_stmt.body)?,
        Statement::ForStatement(for_stmt) => unwrap_while_switch(&for_stmt.body)?,
        Statement::SwitchStatement(switch_stmt) => switch_stmt,
        _ => return None,
    };
    if !discriminant_is_context_next(&switch_stmt.discriminant, context_name) {
        return None;
    }
    Some(switch_stmt.cases.iter().collect())
}

fn unwrap_while_switch<'a, 'b>(
    body: &'b Statement<'a>,
) -> Option<&'b oxc_ast::ast::SwitchStatement<'a>> {
    match body {
        Statement::SwitchStatement(switch_stmt) => Some(switch_stmt),
        Statement::BlockStatement(block) => {
            if block.body.len() != 1 {
                return None;
            }
            let Statement::SwitchStatement(switch_stmt) = &block.body[0] else {
                return None;
            };
            Some(switch_stmt)
        }
        _ => None,
    }
}

fn discriminant_is_context_next(expr: &Expression<'_>, context_name: &str) -> bool {
    let inner: &Expression<'_> = match expr {
        Expression::AssignmentExpression(assign) => &assign.right,
        other => other,
    };
    let Some(member) = inner.as_member_expression() else {
        return false;
    };
    let oxc_ast::ast::MemberExpression::StaticMemberExpression(sm) = member else {
        return false;
    };
    let Expression::Identifier(object) = &sm.object else {
        return false;
    };
    object.name.as_str() == context_name && matches!(sm.property.name.as_str(), "next" | "n")
}

struct PendingYield {
    expr: String,
    target_case: i64,
}

fn strip_terminal_cases<'a, 'b>(
    cases: &[&'b SwitchCase<'a>],
    context_name: &str,
) -> Option<Vec<&'b SwitchCase<'a>>> {
    let mut kept: Vec<&'b SwitchCase<'a>> = Vec::with_capacity(cases.len());
    for case in cases {
        if case_label(case).is_some() {
            kept.push(case);
            continue;
        }
        if !case_is_terminal(case, context_name) {
            return None;
        }
    }
    if kept.is_empty() {
        return None;
    }
    Some(kept)
}

fn case_is_terminal(case: &SwitchCase<'_>, context_name: &str) -> bool {
    case.consequent
        .iter()
        .all(|stmt: &Statement<'_>| is_stop_or_end(stmt, context_name))
}

fn lower_linear_cases(
    source: &str,
    cases: &[&SwitchCase<'_>],
    context_name: &str,
    hoisted: &[&str],
) -> Option<String> {
    let mut labels: Vec<i64> = Vec::with_capacity(cases.len());
    for case in cases {
        labels.push(case_label(case)?);
    }
    for window in labels.windows(2) {
        if window[1] <= window[0] {
            return None;
        }
    }

    let mut out: String = String::new();
    out.push_str("{\n");
    if !hoisted.is_empty() {
        out.push_str("  var ");
        out.push_str(&hoisted.join(", "));
        out.push_str(";\n");
    }

    let mut pending: Option<PendingYield> = None;
    for (case_index, case) in cases.iter().enumerate() {
        let label: i64 = labels[case_index];
        if let Some(ref carried) = pending
            && carried.target_case != label
        {
            return None;
        }
        let emitted: CaseEmission = lower_case(source, case, context_name, pending.take())?;
        out.push_str(&emitted.text);
        pending = emitted.pending;
    }
    if pending.is_some() {
        return None;
    }
    out.push_str("}\n");
    Some(out)
}

struct CaseEmission {
    text: String,
    pending: Option<PendingYield>,
}

fn push_format(out: &mut String, args: std::fmt::Arguments<'_>) {
    let result: std::result::Result<(), std::fmt::Error> = std::fmt::write(out, args);
    if let Err(error) = result {
        unreachable!("string formatting failed: {error}");
    }
}

fn lower_case(
    source: &str,
    case: &SwitchCase<'_>,
    context_name: &str,
    incoming_yield: Option<PendingYield>,
) -> Option<CaseEmission> {
    let mut text: String = String::new();
    let statements: &[Statement<'_>] = case.consequent.as_slice();
    let mut idx: usize = 0;
    let mut carried: Option<PendingYield> = incoming_yield;

    while idx < statements.len() {
        let stmt: &Statement<'_> = &statements[idx];

        if let Some(target) = take_sent_assignment(stmt, context_name) {
            let pending_yield: PendingYield = carried.take()?;
            push_format(
                &mut text,
                format_args!("  {target} = yield {};\n", pending_yield.expr),
            );
            idx += 1;
            continue;
        }

        if let Some(pending_yield) = carried.take() {
            push_format(&mut text, format_args!("  yield {};\n", pending_yield.expr));
        }

        if let Some(next_value) = take_next_assignment(stmt, context_name) {
            let following: &Statement<'_> = statements.get(idx + 1)?;
            let Statement::ReturnStatement(ret) = following else {
                return None;
            };
            let yielded: &Expression<'_> = ret.argument.as_ref()?;
            if is_abrupt_call(yielded, context_name) {
                return None;
            }
            let yield_src: String = yielded.span().source_text(source).to_owned();
            return Some(CaseEmission {
                text,
                pending: Some(PendingYield {
                    expr: yield_src,
                    target_case: next_value,
                }),
            });
        }

        if let Some(returned) = take_abrupt_return(stmt, context_name, source) {
            push_format(&mut text, format_args!("  return {returned};\n"));
            return Some(CaseEmission {
                text,
                pending: None,
            });
        }

        if is_stop_or_end(stmt, context_name) {
            return Some(CaseEmission {
                text,
                pending: None,
            });
        }

        let stmt_src: &str = stmt.span().source_text(source);
        if references_context(stmt_src, context_name) {
            return None;
        }
        push_format(&mut text, format_args!("  {stmt_src}\n"));
        idx += 1;
    }

    Some(CaseEmission {
        text,
        pending: carried,
    })
}

fn case_label(case: &SwitchCase<'_>) -> Option<i64> {
    let test: &Expression<'_> = case.test.as_ref()?;
    match test {
        Expression::NumericLiteral(num) => {
            let value: f64 = num.value;
            if value.fract() != 0.0 {
                return None;
            }
            Some(value as i64)
        }
        _ => None,
    }
}

fn take_sent_assignment<'a>(stmt: &'a Statement<'a>, context_name: &str) -> Option<&'a str> {
    let Statement::ExpressionStatement(expr_stmt) = stmt else {
        return None;
    };
    let Expression::AssignmentExpression(assign) = &expr_stmt.expression else {
        return None;
    };
    if !matches!(assign.operator, AssignmentOperator::Assign) {
        return None;
    }
    if !is_context_member(&assign.right, context_name, &["sent", "v"]) {
        return None;
    }
    let AssignmentTarget::AssignmentTargetIdentifier(target) = &assign.left else {
        return None;
    };
    Some(target.name.as_str())
}

fn take_next_assignment(stmt: &Statement<'_>, context_name: &str) -> Option<i64> {
    let Statement::ExpressionStatement(expr_stmt) = stmt else {
        return None;
    };
    let Expression::AssignmentExpression(assign) = &expr_stmt.expression else {
        return None;
    };
    if !matches!(assign.operator, AssignmentOperator::Assign) {
        return None;
    }
    let member = assign.left.as_member_expression()?;
    let oxc_ast::ast::MemberExpression::StaticMemberExpression(sm) = member else {
        return None;
    };
    let Expression::Identifier(object) = &sm.object else {
        return None;
    };
    if object.name.as_str() != context_name || !matches!(sm.property.name.as_str(), "next" | "n") {
        return None;
    }
    let Expression::NumericLiteral(num) = &assign.right else {
        return None;
    };
    if num.value.fract() != 0.0 {
        return None;
    }
    Some(num.value as i64)
}

fn take_abrupt_return(stmt: &Statement<'_>, context_name: &str, source: &str) -> Option<String> {
    let Statement::ReturnStatement(ret) = stmt else {
        return None;
    };
    let argument: &Expression<'_> = ret.argument.as_ref()?;
    abrupt_return_value(argument, context_name, source)
}

fn abrupt_return_value(expr: &Expression<'_>, context_name: &str, source: &str) -> Option<String> {
    let Expression::CallExpression(call) = expr else {
        return None;
    };
    let member = call.callee.as_member_expression()?;
    let oxc_ast::ast::MemberExpression::StaticMemberExpression(sm) = member else {
        return None;
    };
    let Expression::Identifier(object) = &sm.object else {
        return None;
    };
    if object.name.as_str() != context_name {
        return None;
    }
    match sm.property.name.as_str() {
        "abrupt" => {
            if call.arguments.len() != 2 {
                return None;
            }
            let Argument::StringLiteral(kind) = &call.arguments[0] else {
                return None;
            };
            if kind.value.as_str() != "return" {
                return None;
            }
            let value: &Expression<'_> = call.arguments[1].as_expression()?;
            Some(value.span().source_text(source).to_owned())
        }
        "a" => {
            if call.arguments.len() != 2 {
                return None;
            }
            let Expression::NumericLiteral(kind) = call.arguments[0].as_expression()? else {
                return None;
            };
            if (kind.value - 2.0).abs() > f64::EPSILON {
                return None;
            }
            let value: &Expression<'_> = call.arguments[1].as_expression()?;
            Some(value.span().source_text(source).to_owned())
        }
        _ => None,
    }
}

fn is_abrupt_call(expr: &Expression<'_>, context_name: &str) -> bool {
    let Expression::CallExpression(call) = expr else {
        return false;
    };
    let Some(member) = call.callee.as_member_expression() else {
        return false;
    };
    let oxc_ast::ast::MemberExpression::StaticMemberExpression(sm) = member else {
        return false;
    };
    let Expression::Identifier(object) = &sm.object else {
        return false;
    };
    object.name.as_str() == context_name && matches!(sm.property.name.as_str(), "abrupt" | "a")
}

fn is_stop_or_end(stmt: &Statement<'_>, context_name: &str) -> bool {
    match stmt {
        Statement::ReturnStatement(ret) => ret
            .argument
            .as_ref()
            .is_some_and(|arg| is_stop_call(arg, context_name)),
        Statement::ExpressionStatement(expr_stmt) => {
            is_stop_call(&expr_stmt.expression, context_name)
        }
        Statement::BreakStatement(_) => true,
        _ => false,
    }
}

fn is_stop_call(expr: &Expression<'_>, context_name: &str) -> bool {
    let Expression::CallExpression(call) = expr else {
        return false;
    };
    let Some(member) = call.callee.as_member_expression() else {
        return false;
    };
    let oxc_ast::ast::MemberExpression::StaticMemberExpression(sm) = member else {
        return false;
    };
    let Expression::Identifier(object) = &sm.object else {
        return false;
    };
    object.name.as_str() == context_name && matches!(sm.property.name.as_str(), "stop" | "s")
}

fn is_context_member(expr: &Expression<'_>, context_name: &str, props: &[&str]) -> bool {
    let Some(member) = expr.as_member_expression() else {
        return false;
    };
    let oxc_ast::ast::MemberExpression::StaticMemberExpression(sm) = member else {
        return false;
    };
    let Expression::Identifier(object) = &sm.object else {
        return false;
    };
    object.name.as_str() == context_name && props.contains(&sm.property.name.as_str())
}

fn references_context(stmt_src: &str, context_name: &str) -> bool {
    let bytes: &[u8] = stmt_src.as_bytes();
    let needle: &[u8] = context_name.as_bytes();
    if needle.is_empty() {
        return false;
    }
    let mut i: usize = 0;
    while let Some(found) = find_subslice(&bytes[i..], needle) {
        let start: usize = i + found;
        let end: usize = start + needle.len();
        let before_ok: bool = start == 0 || !is_word_byte(bytes[start - 1]);
        let after_ok: bool = end >= bytes.len() || !is_word_byte(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        i = start + 1;
    }
    false
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window: &[u8]| window == needle)
}

const fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

fn function_params_src(source: &str, func: &Function<'_>) -> String {
    let raw: &str = func.params.span.source_text(source);
    raw.trim_start_matches('(')
        .trim_end_matches(')')
        .trim()
        .to_owned()
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::recover;
    use crate::unminify::ast::RuleOutcome;

    fn apply(source: &str) -> (String, super::RegeneratorRestoreStats) {
        let (outcome, stats): (RuleOutcome, super::RegeneratorRestoreStats) = recover(source);
        let mut sorted: Vec<&crate::unminify::ast::Edit> = outcome.edits.iter().collect();
        sorted.sort_by_key(|edit| core::cmp::Reverse(edit.start));
        let mut out: String = source.to_owned();
        for edit in sorted {
            out.replace_range(edit.start..edit.end, &edit.replacement);
        }
        (out, stats)
    }

    const ASYNC_PAIR: &str = r"
function load(_x) {
  return _load.apply(this, arguments);
}
function _load() {
  _load = _asyncToGenerator(_regenerator().m(function _callee(n) {
    var a, b;
    return _regenerator().w(function (_context2) {
      while (1) switch (_context2.n) {
        case 0:
          _context2.n = 1;
          return Promise.resolve(n);
        case 1:
          a = _context2.v;
          _context2.n = 2;
          return Promise.resolve(a + 1);
        case 2:
          b = _context2.v;
          return _context2.a(2, a + b);
      }
    }, _callee);
  }));
  return _load.apply(this, arguments);
}
";

    #[test]
    fn restores_async_pair_with_await() {
        let (out, stats): (String, super::RegeneratorRestoreStats) = apply(ASYNC_PAIR);
        assert_eq!(stats.async_functions_restored, 1);
        assert!(out.contains("async function load(n)"), "got: {out}");
        assert!(out.contains("a = await Promise.resolve(n)"), "got: {out}");
        assert!(out.contains("return a + b"), "got: {out}");
        assert!(!out.contains("_context2"), "got: {out}");
    }

    const CLASSIC_GENERATOR: &str = r#"
function simple() {
  var x, y;
  return regeneratorRuntime.wrap(function simple$(_context) {
    while (1) switch (_context.prev = _context.next) {
      case 0:
        _context.next = 2;
        return 1;
      case 2:
        x = _context.sent;
        _context.next = 5;
        return x + 1;
      case 5:
        y = _context.sent;
        return _context.abrupt("return", x + y);
      case 7:
      case "end":
        return _context.stop();
    }
  }, _marked);
}
"#;

    #[test]
    fn restores_classic_generator_with_yield() {
        let (out, stats): (String, super::RegeneratorRestoreStats) = apply(CLASSIC_GENERATOR);
        assert_eq!(stats.generators_restored, 1);
        assert!(out.contains("function* simple"), "got: {out}");
        assert!(out.contains("x = yield 1"), "got: {out}");
        assert!(out.contains("y = yield x + 1"), "got: {out}");
        assert!(out.contains("return x + y"), "got: {out}");
        assert!(
            !out.contains("_context") && !out.contains("regeneratorRuntime"),
            "got: {out}"
        );
    }

    const NON_LINEAR: &str = r"
function tricky() {
  var x;
  return _regenerator().w(function (_context) {
    while (1) switch (_context.n) {
      case 0:
        if (x) {
          _context.n = 2;
          break;
        }
        _context.n = 3;
        break;
      case 2:
        return _context.a(2, 1);
      case 3:
        return _context.a(2, 2);
    }
  }, _marked);
}
";

    #[test]
    fn refuses_non_linear_state_machine() {
        let (out, stats): (String, super::RegeneratorRestoreStats) = apply(NON_LINEAR);
        assert_eq!(
            stats.generators_restored, 0,
            "branching jumps cannot be linearly reconstructed"
        );
        assert_eq!(out, NON_LINEAR, "non-linear machine must be left untouched");
    }

    #[test]
    fn ignores_plain_function() {
        let src: &str = "function add(a, b) { return a + b; }";
        let (out, stats): (String, super::RegeneratorRestoreStats) = apply(src);
        assert_eq!(stats.generators_restored, 0);
        assert_eq!(stats.async_functions_restored, 0);
        assert_eq!(out, src);
    }
}
