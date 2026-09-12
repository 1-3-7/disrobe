use oxc_allocator::Allocator;
use oxc_ast::Visit;
use oxc_ast::ast::{
    BinaryOperator, BindingPatternKind, Expression, Function, IfStatement, LogicalOperator,
    Statement, UnaryOperator,
};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct DefaultParamStats {
    pub(super) defaults_recovered: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, DefaultParamStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), DefaultParamStats::default());
    }

    let mut collector: Collector = Collector {
        source,
        edits: Vec::new(),
        recovered: 0,
    };
    collector.visit_program(&parsed.program);

    if collector.edits.is_empty() {
        return (RuleOutcome::empty(), DefaultParamStats::default());
    }
    let defaults_recovered: usize = collector.recovered;
    (
        RuleOutcome {
            edits: collector.edits,
        },
        DefaultParamStats { defaults_recovered },
    )
}

struct Collector<'s> {
    source: &'s str,
    edits: Vec<Edit>,
    recovered: usize,
}

impl<'a> Visit<'a> for Collector<'_> {
    fn visit_function(&mut self, func: &Function<'a>, flags: oxc::syntax::scope::ScopeFlags) {
        self.process(func);
        oxc_ast::visit::walk::walk_function(self, func, flags);
    }
}

impl Collector<'_> {
    fn process(&mut self, func: &Function<'_>) {
        let Some(body) = func.body.as_ref() else {
            return;
        };
        let param_names: Vec<&str> = func
            .params
            .items
            .iter()
            .filter_map(|item| plain_param_name(&item.pattern.kind))
            .collect();
        let scan_limit: usize = body.statements.len().min(15);
        for stmt in body.statements.iter().take(scan_limit) {
            let Statement::IfStatement(if_stmt) = stmt else {
                continue;
            };
            let Some((checked, default_expr)) = extract_default(if_stmt.as_ref()) else {
                continue;
            };
            let Some(param_position) = param_names.iter().position(|name| *name == checked) else {
                continue;
            };
            if default_references_later_param(default_expr, &param_names[param_position + 1..]) {
                continue;
            }
            let Some(param_item) = func.params.items.get(param_position) else {
                continue;
            };
            let default_src: &str = default_expr.span().source_text(self.source);
            let param_end: usize = param_item.span.end as usize;
            self.edits.push(Edit {
                start: param_end,
                end: param_end,
                replacement: format!(" = {default_src}"),
            });
            self.edits.push(Edit {
                start: if_stmt.span.start as usize,
                end: if_stmt.span.end as usize,
                replacement: String::new(),
            });
            self.recovered += 1;
        }
        self.process_object_default(func, &param_names);
        self.process_arguments_default(func, param_names.len());
    }

    fn process_arguments_default(&mut self, func: &Function<'_>, param_count: usize) {
        let Some(body) = func.body.as_ref() else {
            return;
        };
        let scan_limit: usize = body.statements.len().min(15);
        for stmt in body.statements.iter().take(scan_limit) {
            let Some((var_name, default_expr, decl_span)) =
                extract_arguments_default(stmt, param_count)
            else {
                continue;
            };
            let default_src: &str = default_expr.span().source_text(self.source);
            let insert_at: usize = func.params.span.end as usize - 1;
            let param_text: String = if param_count == 0 {
                format!("{var_name} = {default_src}")
            } else {
                format!(", {var_name} = {default_src}")
            };
            self.edits.push(Edit {
                start: insert_at,
                end: insert_at,
                replacement: param_text,
            });
            self.edits.push(Edit {
                start: decl_span.0,
                end: decl_span.1,
                replacement: String::new(),
            });
            self.recovered += 1;
            return;
        }
    }

    fn process_object_default(&mut self, func: &Function<'_>, param_names: &[&str]) {
        let Some(body) = func.body.as_ref() else {
            return;
        };
        let scan_limit: usize = body.statements.len().min(15);
        for stmt in body.statements.iter().take(scan_limit) {
            let Some((checked, default_expr, init_span)) = extract_object_default(stmt) else {
                continue;
            };
            let Some(param_position) = param_names.iter().position(|name| *name == checked) else {
                continue;
            };
            if default_references_later_param(default_expr, &param_names[param_position..]) {
                continue;
            }
            let Some(param_item) = func.params.items.get(param_position) else {
                continue;
            };
            let default_src: &str = default_expr.span().source_text(self.source);
            let param_end: usize = param_item.span.end as usize;
            self.edits.push(Edit {
                start: param_end,
                end: param_end,
                replacement: format!(" = {default_src}"),
            });
            self.edits.push(Edit {
                start: init_span.0,
                end: init_span.1,
                replacement: checked.to_owned(),
            });
            self.recovered += 1;
        }
    }
}

fn extract_object_default<'a>(
    stmt: &'a Statement<'a>,
) -> Option<(&'a str, &'a Expression<'a>, (usize, usize))> {
    let Statement::VariableDeclaration(decl) = stmt else {
        return None;
    };
    if decl.declarations.len() != 1 {
        return None;
    }
    let init: &Expression<'_> = decl.declarations[0].init.as_ref()?;
    let Expression::ConditionalExpression(cond) = init else {
        return None;
    };
    let checked: &str = void_check_target(&cond.test)?;
    if !is_empty_object(&cond.consequent) {
        return None;
    }
    let Expression::Identifier(alt_ident) = &cond.alternate else {
        return None;
    };
    if alt_ident.name != checked {
        return None;
    }
    let span: (usize, usize) = (init.span().start as usize, init.span().end as usize);
    Some((checked, &cond.consequent, span))
}

fn is_empty_object(expr: &Expression<'_>) -> bool {
    matches!(expr, Expression::ObjectExpression(obj) if obj.properties.is_empty())
}

fn extract_arguments_default<'a>(
    stmt: &'a Statement<'a>,
    expected_index: usize,
) -> Option<(&'a str, &'a Expression<'a>, (usize, usize))> {
    let Statement::VariableDeclaration(decl) = stmt else {
        return None;
    };
    if decl.declarations.len() != 1 {
        return None;
    }
    let declarator = &decl.declarations[0];
    let BindingPatternKind::BindingIdentifier(binding) = &declarator.id.kind else {
        return None;
    };
    let init: &Expression<'_> = declarator.init.as_ref()?;
    let Expression::ConditionalExpression(cond) = init else {
        return None;
    };
    if !matches_arguments_guard(&cond.test, expected_index) {
        return None;
    }
    if !is_arguments_index(&cond.consequent, expected_index) {
        return None;
    }
    if is_undefined_value(&cond.alternate) {
        return None;
    }
    let span: (usize, usize) = (decl.span.start as usize, decl.span.end as usize);
    Some((binding.name.as_str(), &cond.alternate, span))
}

fn matches_arguments_guard(test: &Expression<'_>, index: usize) -> bool {
    let Expression::LogicalExpression(logical) = test else {
        return false;
    };
    if logical.operator != LogicalOperator::And {
        return false;
    }
    matches_length_threshold(&logical.left, index) && matches_index_defined(&logical.right, index)
}

fn matches_length_threshold(expr: &Expression<'_>, index: usize) -> bool {
    let Expression::BinaryExpression(bin) = expr else {
        return false;
    };
    match bin.operator {
        BinaryOperator::GreaterThan => {
            is_arguments_length(&bin.left) && is_numeric(&bin.right, index)
        }
        BinaryOperator::LessThan => is_arguments_length(&bin.right) && is_numeric(&bin.left, index),
        _ => false,
    }
}

fn matches_index_defined(expr: &Expression<'_>, index: usize) -> bool {
    let Expression::BinaryExpression(bin) = expr else {
        return false;
    };
    if bin.operator != BinaryOperator::StrictInequality {
        return false;
    }
    if is_undefined_value(&bin.right) {
        return is_arguments_index(&bin.left, index);
    }
    if is_undefined_value(&bin.left) {
        return is_arguments_index(&bin.right, index);
    }
    false
}

fn is_arguments_length(expr: &Expression<'_>) -> bool {
    let Expression::StaticMemberExpression(member) = expr else {
        return false;
    };
    member.property.name == "length"
        && matches!(&member.object, Expression::Identifier(id) if id.name == "arguments")
}

fn is_arguments_index(expr: &Expression<'_>, index: usize) -> bool {
    let Expression::ComputedMemberExpression(member) = expr else {
        return false;
    };
    matches!(&member.object, Expression::Identifier(id) if id.name == "arguments")
        && is_numeric(&member.expression, index)
}

fn is_numeric(expr: &Expression<'_>, value: usize) -> bool {
    let Expression::NumericLiteral(num) = expr else {
        return false;
    };
    num.value.fract() == 0.0
        && num.value >= 0.0
        && num.value <= usize::MAX as f64
        && num.value as usize == value
}

fn plain_param_name<'a>(kind: &'a BindingPatternKind<'a>) -> Option<&'a str> {
    match kind {
        BindingPatternKind::BindingIdentifier(ident) => Some(ident.name.as_str()),
        _ => None,
    }
}

fn extract_default<'a>(if_stmt: &'a IfStatement<'a>) -> Option<(&'a str, &'a Expression<'a>)> {
    if if_stmt.alternate.is_some() {
        return None;
    }
    let checked: &str = void_check_target(&if_stmt.test)?;
    let default_expr: &Expression<'_> = assign_default(&if_stmt.consequent, checked)?;
    Some((checked, default_expr))
}

fn void_check_target<'a>(expr: &'a Expression<'a>) -> Option<&'a str> {
    let Expression::BinaryExpression(bin) = expr else {
        return None;
    };
    if bin.operator != oxc_ast::ast::BinaryOperator::StrictEquality {
        return None;
    }
    if is_undefined_value(&bin.right)
        && let Expression::Identifier(ident) = &bin.left
    {
        return Some(ident.name.as_str());
    }
    if is_undefined_value(&bin.left)
        && let Expression::Identifier(ident) = &bin.right
    {
        return Some(ident.name.as_str());
    }
    None
}

fn is_undefined_value(expr: &Expression<'_>) -> bool {
    match expr {
        Expression::Identifier(ident) => ident.name == "undefined",
        Expression::UnaryExpression(unary) => {
            unary.operator == UnaryOperator::Void && is_side_effect_free(&unary.argument)
        }
        _ => false,
    }
}

const fn is_side_effect_free(expr: &Expression<'_>) -> bool {
    matches!(
        expr,
        Expression::NumericLiteral(_)
            | Expression::StringLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_)
    )
}

fn assign_default<'a>(cons: &'a Statement<'a>, param_name: &str) -> Option<&'a Expression<'a>> {
    let expr_stmt = match cons {
        Statement::ExpressionStatement(stmt) => stmt,
        Statement::BlockStatement(block) if block.body.len() == 1 => match &block.body[0] {
            Statement::ExpressionStatement(stmt) => stmt,
            _ => return None,
        },
        _ => return None,
    };
    let Expression::AssignmentExpression(assign) = &expr_stmt.expression else {
        return None;
    };
    if assign.operator != oxc_ast::ast::AssignmentOperator::Assign {
        return None;
    }
    let target_name: &str = assign.left.get_identifier()?;
    if target_name != param_name {
        return None;
    }
    Some(&assign.right)
}

fn default_references_later_param(default_expr: &Expression<'_>, later_params: &[&str]) -> bool {
    if later_params.is_empty() {
        return false;
    }
    let mut probe: IdentProbe = IdentProbe {
        later_params,
        found: false,
    };
    probe.visit_expression(default_expr);
    probe.found
}

struct IdentProbe<'a> {
    later_params: &'a [&'a str],
    found: bool,
}

impl<'a> Visit<'a> for IdentProbe<'_> {
    fn visit_identifier_reference(&mut self, ident: &oxc_ast::ast::IdentifierReference<'a>) {
        if self.later_params.contains(&ident.name.as_str()) {
            self.found = true;
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::recover;
    use crate::unminify::ast::{Edit, RuleOutcome};

    fn apply(source: &str) -> String {
        let (outcome, _stats): (RuleOutcome, super::DefaultParamStats) = recover(source);
        let mut sorted: Vec<&Edit> = outcome.edits.iter().collect();
        sorted.sort_by_key(|edit| core::cmp::Reverse((edit.start, edit.end)));
        let mut out: String = source.to_owned();
        for edit in sorted {
            out.replace_range(edit.start..edit.end, &edit.replacement);
        }
        out
    }

    #[test]
    fn recovers_void0_default() {
        assert_eq!(
            apply("function f(a) { if (a === void 0) { a = 1; } return a; }"),
            "function f(a = 1) {  return a; }"
        );
    }

    #[test]
    fn recovers_undefined_default_without_block() {
        assert_eq!(
            apply("function f(a) { if (a === undefined) a = 'x'; return a; }"),
            "function f(a = 'x') {  return a; }"
        );
    }

    #[test]
    fn recovers_yoda_check() {
        assert_eq!(
            apply("function f(a) { if (void 0 === a) { a = 0; } return a; }"),
            "function f(a = 0) {  return a; }"
        );
    }

    #[test]
    fn ignores_if_with_else() {
        let source: &str =
            "function f(a) { if (a === void 0) { a = 1; } else { a = 2; } return a; }";
        let (outcome, stats): (RuleOutcome, super::DefaultParamStats) = recover(source);
        assert!(outcome.edits.is_empty());
        assert_eq!(stats.defaults_recovered, 0);
    }

    #[test]
    fn ignores_check_on_non_parameter() {
        let source: &str = "function f(a) { var b; if (b === void 0) { b = 1; } return b; }";
        let (outcome, _stats): (RuleOutcome, super::DefaultParamStats) = recover(source);
        assert!(outcome.edits.is_empty());
    }

    #[test]
    fn refuses_default_referencing_a_later_parameter() {
        let source: &str = "function f(a, b) { if (a === void 0) { a = b; } return a; }";
        let (outcome, stats): (RuleOutcome, super::DefaultParamStats) = recover(source);
        assert!(
            outcome.edits.is_empty(),
            "a default that reads a later param `b` is not yet bound at a's default-eval time"
        );
        assert_eq!(stats.defaults_recovered, 0);
    }

    #[test]
    fn allows_default_referencing_an_earlier_parameter() {
        assert_eq!(
            apply("function f(a, b) { if (b === void 0) { b = a; } return b; }"),
            "function f(a, b = a) {  return b; }"
        );
    }

    #[test]
    fn recovers_object_default_ternary() {
        assert_eq!(
            apply("function f(opts) { var o = opts === void 0 ? {} : opts; return o; }"),
            "function f(opts = {}) { var o = opts; return o; }"
        );
    }

    #[test]
    fn object_default_with_undefined_check() {
        assert_eq!(
            apply("function f(cfg) { var c = cfg === undefined ? {} : cfg; return c; }"),
            "function f(cfg = {}) { var c = cfg; return c; }"
        );
    }

    #[test]
    fn ignores_object_default_with_non_empty_object() {
        let source: &str =
            "function f(opts) { var o = opts === void 0 ? {a: 1} : opts; return o; }";
        let (outcome, stats): (RuleOutcome, super::DefaultParamStats) = recover(source);
        assert!(outcome.edits.is_empty());
        assert_eq!(stats.defaults_recovered, 0);
    }

    #[test]
    fn recovers_arguments_positional_default_into_param() {
        assert_eq!(
            apply(
                "function f() { var a = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : 5; return a; }"
            ),
            "function f(a = 5) {  return a; }"
        );
    }

    #[test]
    fn appends_arguments_default_after_an_existing_param() {
        assert_eq!(
            apply(
                "function f(x) { var y = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 9; return x + y; }"
            ),
            "function f(x, y = 9) {  return x + y; }"
        );
    }

    #[test]
    fn ignores_arguments_default_at_wrong_index() {
        let source: &str = "function f() { var a = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 5; return a; }";
        let (outcome, stats): (RuleOutcome, super::DefaultParamStats) = recover(source);
        assert!(outcome.edits.is_empty());
        assert_eq!(stats.defaults_recovered, 0);
    }
}
