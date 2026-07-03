use oxc_allocator::Allocator;
use oxc_ast::Visit;
use oxc_ast::ast::{
    BinaryExpression, BinaryOperator, BindingPatternKind, ConditionalExpression, Expression,
    ForStatement, ForStatementInit, Function, MemberExpression, Statement, UpdateOperator,
    VariableDeclaration,
};
use oxc_parser::Parser;
use oxc_span::SourceType;

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct ArgRestStats {
    pub(super) copy_loops_to_rest: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, ArgRestStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), ArgRestStats::default());
    }

    let mut collector: Collector = Collector { edits: Vec::new() };
    collector.visit_program(&parsed.program);

    if collector.edits.is_empty() {
        return (RuleOutcome::empty(), ArgRestStats::default());
    }
    let copy_loops_to_rest: usize = collector.edits.len() / 2;
    (
        RuleOutcome {
            edits: collector.edits,
        },
        ArgRestStats { copy_loops_to_rest },
    )
}

struct Collector {
    edits: Vec<Edit>,
}

impl<'a> Visit<'a> for Collector {
    fn visit_function(&mut self, func: &Function<'a>, flags: oxc::syntax::scope::ScopeFlags) {
        self.process(func);
        oxc_ast::visit::walk::walk_function(self, func, flags);
    }
}

struct CopyLoop<'a> {
    copy_var: &'a str,
    shift: u32,
}

impl Collector {
    fn process(&mut self, func: &Function<'_>) {
        if func.params.rest.is_some() {
            return;
        }
        let leading: u32 = leading_plain_param_count(func);
        let Some(body) = func.body.as_ref() else {
            return;
        };
        let Some((loop_stmt, copy)) = find_copy_loop(&body.statements) else {
            return;
        };
        if copy.shift != leading {
            return;
        }
        if !only_safe_arguments_use(body, loop_stmt) {
            return;
        }
        let params_span_start: u32 = func.params.span.start;
        let params_span_end: u32 = func.params.span.end;
        if params_span_end <= params_span_start {
            return;
        }
        if leading == 0 {
            self.edits.push(Edit {
                start: params_span_start as usize + 1,
                end: params_span_end as usize - 1,
                replacement: format!("...{}", copy.copy_var),
            });
        } else {
            let close_paren: usize = params_span_end as usize - 1;
            self.edits.push(Edit {
                start: close_paren,
                end: close_paren,
                replacement: format!(", ...{}", copy.copy_var),
            });
        }
        self.edits.push(Edit {
            start: loop_stmt.span.start as usize,
            end: loop_stmt.span.end as usize,
            replacement: String::new(),
        });
    }
}

fn leading_plain_param_count(func: &Function<'_>) -> u32 {
    let mut count: u32 = 0;
    for item in &func.params.items {
        if !matches!(item.pattern.kind, BindingPatternKind::BindingIdentifier(_)) {
            return u32::MAX;
        }
        count += 1;
    }
    count
}

fn find_copy_loop<'a>(
    statements: &'a oxc_allocator::Vec<'a, Statement<'a>>,
) -> Option<(&'a ForStatement<'a>, CopyLoop<'a>)> {
    statements.iter().find_map(|stmt| {
        let Statement::ForStatement(for_stmt) = stmt else {
            return None;
        };
        match_babel_copy_loop(for_stmt).map(|copy| (for_stmt.as_ref(), copy))
    })
}

fn match_babel_copy_loop<'a>(for_stmt: &'a ForStatement<'a>) -> Option<CopyLoop<'a>> {
    let Some(ForStatementInit::VariableDeclaration(init)) = &for_stmt.init else {
        return None;
    };
    if init.declarations.len() != 3 {
        return None;
    }

    let len_name: &str = declarator_name(init, 0)?;
    if !is_arguments_length(init.declarations[0].init.as_ref()?) {
        return None;
    }

    let copy_name: &str = declarator_name(init, 1)?;
    let shift: u32 = array_sizing_shift(init.declarations[1].init.as_ref()?, len_name)?;

    let idx_name: &str = declarator_name(init, 2)?;
    if !is_literal_u32(init.declarations[2].init.as_ref()?, shift) {
        return None;
    }

    if !matches_test(for_stmt.test.as_ref()?, idx_name, len_name) {
        return None;
    }
    if !matches_update(for_stmt.update.as_ref()?, idx_name) {
        return None;
    }
    if !matches_copy_body(&for_stmt.body, copy_name, idx_name, shift) {
        return None;
    }
    Some(CopyLoop {
        copy_var: copy_name,
        shift,
    })
}

fn declarator_name<'a>(decl: &'a VariableDeclaration<'a>, index: usize) -> Option<&'a str> {
    let declarator = decl.declarations.get(index)?;
    match &declarator.id.kind {
        BindingPatternKind::BindingIdentifier(ident) => Some(ident.name.as_str()),
        _ => None,
    }
}

fn is_arguments_length(expr: &Expression<'_>) -> bool {
    let Expression::StaticMemberExpression(member) = expr else {
        return false;
    };
    member.property.name == "length"
        && matches!(&member.object, Expression::Identifier(id) if id.name == "arguments")
}

fn array_sizing_shift(expr: &Expression<'_>, len_name: &str) -> Option<u32> {
    let argument = first_array_argument(expr)?;
    if let Expression::Identifier(id) = argument {
        return (id.name == len_name).then_some(0);
    }
    let Expression::ConditionalExpression(cond) = argument else {
        return None;
    };
    conditional_shift(cond, len_name)
}

fn first_array_argument<'a>(expr: &'a Expression<'a>) -> Option<&'a Expression<'a>> {
    let arguments = match expr {
        Expression::CallExpression(call) => {
            if !is_array_callee(&call.callee) {
                return None;
            }
            &call.arguments
        }
        Expression::NewExpression(new_expr) => {
            if !matches!(&new_expr.callee, Expression::Identifier(id) if id.name == "Array") {
                return None;
            }
            &new_expr.arguments
        }
        _ => return None,
    };
    if arguments.len() != 1 {
        return None;
    }
    arguments[0].as_expression()
}

fn conditional_shift(cond: &ConditionalExpression<'_>, len_name: &str) -> Option<u32> {
    let Expression::BinaryExpression(test) = &cond.test else {
        return None;
    };
    if test.operator != BinaryOperator::GreaterThan {
        return None;
    }
    if !matches!(&test.left, Expression::Identifier(id) if id.name == len_name) {
        return None;
    }
    let threshold: u32 = numeric_literal_u32(&test.right)?;
    if threshold == 0 {
        return None;
    }

    let Expression::BinaryExpression(consequent) = &cond.consequent else {
        return None;
    };
    if !is_len_minus(consequent, len_name, threshold) {
        return None;
    }
    if !is_literal_u32(&cond.alternate, 0) {
        return None;
    }
    Some(threshold)
}

fn is_len_minus(expr: &BinaryExpression<'_>, len_name: &str, amount: u32) -> bool {
    expr.operator == BinaryOperator::Subtraction
        && matches!(&expr.left, Expression::Identifier(id) if id.name == len_name)
        && numeric_literal_u32(&expr.right) == Some(amount)
}

fn is_array_callee(callee: &Expression<'_>) -> bool {
    matches!(callee, Expression::Identifier(id) if id.name == "Array")
}

fn is_literal_u32(expr: &Expression<'_>, value: u32) -> bool {
    numeric_literal_u32(expr) == Some(value)
}

fn numeric_literal_u32(expr: &Expression<'_>) -> Option<u32> {
    let Expression::NumericLiteral(num) = expr else {
        return None;
    };
    if num.value < 0.0 || num.value.fract() != 0.0 || num.value > f64::from(u32::MAX) {
        return None;
    }
    Some(num.value as u32)
}

fn matches_test(test: &Expression<'_>, idx_name: &str, len_name: &str) -> bool {
    let Expression::BinaryExpression(bin) = test else {
        return false;
    };
    bin.operator == BinaryOperator::LessThan
        && matches!(&bin.left, Expression::Identifier(id) if id.name == idx_name)
        && matches!(&bin.right, Expression::Identifier(id) if id.name == len_name)
}

fn matches_update(update: &Expression<'_>, idx_name: &str) -> bool {
    let Expression::UpdateExpression(upd) = update else {
        return false;
    };
    upd.operator == UpdateOperator::Increment
        && upd
            .argument
            .get_identifier()
            .is_some_and(|name: &str| name == idx_name)
}

fn matches_copy_body(body: &Statement<'_>, copy_name: &str, idx_name: &str, shift: u32) -> bool {
    let expr_stmt = match body {
        Statement::ExpressionStatement(stmt) => stmt,
        Statement::BlockStatement(block) if block.body.len() == 1 => match &block.body[0] {
            Statement::ExpressionStatement(stmt) => stmt,
            _ => return false,
        },
        _ => return false,
    };
    let Expression::AssignmentExpression(assign) = &expr_stmt.expression else {
        return false;
    };
    let Some(target) = assign.left.as_member_expression() else {
        return false;
    };
    if !is_shifted_target(target, copy_name, idx_name, shift) {
        return false;
    }
    let Expression::ComputedMemberExpression(source) = &assign.right else {
        return false;
    };
    matches!(&source.object, Expression::Identifier(id) if id.name == "arguments")
        && matches!(&source.expression, Expression::Identifier(id) if id.name == idx_name)
}

fn is_shifted_target(
    member: &MemberExpression<'_>,
    object_name: &str,
    index_name: &str,
    shift: u32,
) -> bool {
    let MemberExpression::ComputedMemberExpression(computed) = member else {
        return false;
    };
    if !matches!(&computed.object, Expression::Identifier(id) if id.name == object_name) {
        return false;
    }
    if shift == 0 {
        return matches!(&computed.expression, Expression::Identifier(id) if id.name == index_name);
    }
    let Expression::BinaryExpression(bin) = &computed.expression else {
        return false;
    };
    bin.operator == BinaryOperator::Subtraction
        && matches!(&bin.left, Expression::Identifier(id) if id.name == index_name)
        && numeric_literal_u32(&bin.right) == Some(shift)
}

fn only_safe_arguments_use(
    body: &oxc_ast::ast::FunctionBody<'_>,
    loop_stmt: &ForStatement<'_>,
) -> bool {
    let mut probe: ArgumentsProbe = ArgumentsProbe {
        skip_span: (loop_stmt.span.start, loop_stmt.span.end),
        unsafe_use: false,
    };
    for stmt in &body.statements {
        probe.visit_statement(stmt);
    }
    !probe.unsafe_use
}

struct ArgumentsProbe {
    skip_span: (u32, u32),
    unsafe_use: bool,
}

impl<'a> Visit<'a> for ArgumentsProbe {
    fn visit_for_statement(&mut self, for_stmt: &ForStatement<'a>) {
        if for_stmt.span.start == self.skip_span.0 && for_stmt.span.end == self.skip_span.1 {
            return;
        }
        oxc_ast::visit::walk::walk_for_statement(self, for_stmt);
    }

    fn visit_identifier_reference(&mut self, ident: &oxc_ast::ast::IdentifierReference<'a>) {
        if ident.name == "arguments" {
            self.unsafe_use = true;
        }
    }

    fn visit_function(&mut self, _func: &Function<'a>, _flags: oxc::syntax::scope::ScopeFlags) {}

    fn visit_arrow_function_expression(
        &mut self,
        _arrow: &oxc_ast::ast::ArrowFunctionExpression<'a>,
    ) {
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::recover;
    use crate::unminify::ast::{Edit, RuleOutcome};

    fn apply(source: &str) -> String {
        let (outcome, _stats): (RuleOutcome, super::ArgRestStats) = recover(source);
        let mut sorted: Vec<&Edit> = outcome.edits.iter().collect();
        sorted.sort_by_key(|edit| core::cmp::Reverse((edit.start, edit.end)));
        let mut out: String = source.to_owned();
        for edit in sorted {
            out.replace_range(edit.start..edit.end, &edit.replacement);
        }
        out
    }

    const BABEL: &str = "function sum() { for (var _len = arguments.length, nums = new Array(_len), _i = 0; _i < _len; _i++) { nums[_i] = arguments[_i]; } return nums.reduce(function (a, b) { return a + b; }, 0); }";

    #[test]
    fn babel_copy_loop_becomes_rest_param() {
        let out: String = apply(BABEL);
        assert!(out.contains("function sum(...nums)"), "got: {out}");
        assert!(!out.contains("arguments.length"), "got: {out}");
        assert!(!out.contains("new Array(_len)"), "got: {out}");
    }

    #[test]
    fn array_ctor_call_form_also_matches() {
        let source: &str = "function f() { for (var _len = arguments.length, a = Array(_len), _i = 0; _i < _len; _i++) a[_i] = arguments[_i]; return a; }";
        let out: String = apply(source);
        assert!(out.contains("function f(...a)"), "got: {out}");
    }

    #[test]
    fn one_leading_param_shifts_into_rest() {
        let source: &str = "function f(a) { for (var _len = arguments.length, rest = new Array(_len > 1 ? _len - 1 : 0), _key = 1; _key < _len; _key++) { rest[_key - 1] = arguments[_key]; } return rest; }";
        let out: String = apply(source);
        assert!(out.contains("function f(a, ...rest)"), "got: {out}");
        assert!(!out.contains("arguments.length"), "got: {out}");
    }

    #[test]
    fn two_leading_params_shift_into_rest() {
        let source: &str = "function g(a, b) { for (var _len = arguments.length, rest = Array(_len > 2 ? _len - 2 : 0), _key = 2; _key < _len; _key++) rest[_key - 2] = arguments[_key]; return rest; }";
        let out: String = apply(source);
        assert!(out.contains("function g(a, b, ...rest)"), "got: {out}");
    }

    #[test]
    fn shift_mismatch_with_param_count_is_rejected() {
        let source: &str = "function f(a) { for (var _len = arguments.length, rest = new Array(_len > 2 ? _len - 2 : 0), _key = 2; _key < _len; _key++) rest[_key - 2] = arguments[_key]; return rest; }";
        let (outcome, _stats): (RuleOutcome, super::ArgRestStats) = recover(source);
        assert!(
            outcome.edits.is_empty(),
            "a shift that does not equal the leading param count is not a faithful rest param"
        );
    }

    #[test]
    fn destructured_leading_param_is_left_alone() {
        let source: &str = "function f({x}) { for (var _len = arguments.length, rest = new Array(_len > 1 ? _len - 1 : 0), _key = 1; _key < _len; _key++) rest[_key - 1] = arguments[_key]; return rest; }";
        let (outcome, _stats): (RuleOutcome, super::ArgRestStats) = recover(source);
        assert!(
            outcome.edits.is_empty(),
            "non-identifier leading params are not handled"
        );
    }

    #[test]
    fn residual_bare_arguments_use_blocks_the_rewrite() {
        let source: &str = "function f() { for (var _len = arguments.length, a = new Array(_len), _i = 0; _i < _len; _i++) a[_i] = arguments[_i]; return arguments.callee; }";
        let (outcome, _stats): (RuleOutcome, super::ArgRestStats) = recover(source);
        assert!(
            outcome.edits.is_empty(),
            "a leftover arguments.callee use means the rest param is not a faithful replacement"
        );
    }

    #[test]
    fn unrelated_for_loop_is_not_matched() {
        let source: &str = "function f() { for (var i = 0; i < 3; i++) { print(i); } }";
        let (outcome, _stats): (RuleOutcome, super::ArgRestStats) = recover(source);
        assert!(outcome.edits.is_empty());
    }
}
