use oxc_allocator::Allocator;
use oxc_ast::Visit;
use oxc_ast::ast::{
    AssignmentExpression, AssignmentOperator, BinaryOperator, ConditionalExpression, Expression,
    LogicalExpression, LogicalOperator, Program, UnaryOperator,
};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct LogicalAssignStats {
    pub(super) logical_and: usize,
    pub(super) logical_or: usize,
    pub(super) coalesce: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, LogicalAssignStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), LogicalAssignStats::default());
    }
    let program: &Program<'_> = &parsed.program;

    let mut collector: Collector<'_> = Collector {
        source,
        program,
        edits: Vec::new(),
        stats: LogicalAssignStats::default(),
    };
    collector.visit_program(program);

    if collector.edits.is_empty() {
        return (RuleOutcome::empty(), LogicalAssignStats::default());
    }
    (
        RuleOutcome {
            edits: collector.edits,
        },
        collector.stats,
    )
}

struct Collector<'s> {
    source: &'s str,
    program: &'s Program<'s>,
    edits: Vec<Edit>,
    stats: LogicalAssignStats,
}

impl<'a> Visit<'a> for Collector<'_> {
    fn visit_expression(&mut self, expr: &Expression<'a>) {
        if let Expression::LogicalExpression(logical) = expr
            && let Some((edit, op)) = self.try_short_circuit(logical)
        {
            self.edits.push(edit);
            match op {
                LogicalOperator::And => self.stats.logical_and += 1,
                LogicalOperator::Or => self.stats.logical_or += 1,
                LogicalOperator::Coalesce => {}
            }
            return;
        }
        if let Expression::ConditionalExpression(cond) = expr
            && let Some(edit) = self.try_nullish(cond)
        {
            self.edits.push(edit);
            self.stats.coalesce += 1;
            return;
        }
        oxc_ast::visit::walk::walk_expression(self, expr);
    }
}

impl Collector<'_> {
    fn try_short_circuit(
        &self,
        logical: &LogicalExpression<'_>,
    ) -> Option<(Edit, LogicalOperator)> {
        if logical.operator == LogicalOperator::Coalesce {
            return None;
        }
        let target_name: &str = identifier_of(&logical.left)?;

        let assign: &AssignmentExpression<'_> = assignment_in(&logical.right)?;
        if assign.operator != AssignmentOperator::Assign {
            return None;
        }
        if assign.left.get_identifier()? != target_name {
            return None;
        }

        let symbol: &str = match logical.operator {
            LogicalOperator::And => "&&=",
            LogicalOperator::Or => "||=",
            LogicalOperator::Coalesce => return None,
        };
        let rhs_src: &str = assign.right.span().source_text(self.source);
        Some((
            Edit {
                start: logical.span.start as usize,
                end: logical.span.end as usize,
                replacement: format!("{target_name} {symbol} {rhs_src}"),
            },
            logical.operator,
        ))
    }

    fn try_nullish(&self, cond: &ConditionalExpression<'_>) -> Option<Edit> {
        let temp_name: &str = nullish_test_temp(&cond.test)?;
        if identifier_of(&cond.consequent)? != temp_name {
            return None;
        }

        let assign: &AssignmentExpression<'_> = assignment_in(&cond.alternate)?;
        if assign.operator != AssignmentOperator::Assign {
            return None;
        }
        let target_name: &str = assign.left.get_identifier()?;

        let init: &Expression<'_> = temp_init(&cond.test, temp_name)?;
        if identifier_of(init)? != target_name {
            return None;
        }

        if self.temp_used_outside(temp_name, cond.span.start, cond.span.end) {
            return None;
        }

        let rhs_src: &str = assign.right.span().source_text(self.source);
        Some(Edit {
            start: cond.span.start as usize,
            end: cond.span.end as usize,
            replacement: format!("{target_name} ??= {rhs_src}"),
        })
    }

    fn temp_used_outside(&self, temp_name: &str, region_start: u32, region_end: u32) -> bool {
        let mut probe: OutsideUseProbe<'_> = OutsideUseProbe {
            name: temp_name,
            region_start,
            region_end,
            found: false,
        };
        probe.visit_program(self.program);
        probe.found
    }
}

fn identifier_of<'a>(expr: &'a Expression<'a>) -> Option<&'a str> {
    match unwrap_paren(expr) {
        Expression::Identifier(id) => Some(id.name.as_str()),
        _ => None,
    }
}

fn assignment_in<'a>(expr: &'a Expression<'a>) -> Option<&'a AssignmentExpression<'a>> {
    match unwrap_paren(expr) {
        Expression::AssignmentExpression(assign) => Some(assign),
        _ => None,
    }
}

fn nullish_test_temp<'a>(test: &'a Expression<'a>) -> Option<&'a str> {
    let Expression::LogicalExpression(logical) = unwrap_paren(test) else {
        return None;
    };
    if logical.operator != LogicalOperator::And {
        return None;
    }
    let left_name: &str = strict_compare_temp(&logical.left, BinaryOperator::StrictInequality)?;
    let right_name: &str = strict_compare_temp(&logical.right, BinaryOperator::StrictInequality)?;
    if left_name == right_name {
        Some(left_name)
    } else {
        None
    }
}

fn strict_compare_temp<'a>(expr: &'a Expression<'a>, op: BinaryOperator) -> Option<&'a str> {
    let Expression::BinaryExpression(bin) = unwrap_paren(expr) else {
        return None;
    };
    if bin.operator != op {
        return None;
    }
    if is_null_or_undefined(&bin.right) {
        return temp_name_of(&bin.left);
    }
    if is_null_or_undefined(&bin.left) {
        return temp_name_of(&bin.right);
    }
    None
}

fn temp_name_of<'a>(expr: &'a Expression<'a>) -> Option<&'a str> {
    match unwrap_paren(expr) {
        Expression::Identifier(id) => Some(id.name.as_str()),
        Expression::AssignmentExpression(assign) => assign.left.get_identifier(),
        _ => None,
    }
}

fn temp_init<'a>(test: &'a Expression<'a>, temp_name: &str) -> Option<&'a Expression<'a>> {
    let Expression::LogicalExpression(logical) = unwrap_paren(test) else {
        return None;
    };
    assign_init_in(&logical.left, temp_name).or_else(|| assign_init_in(&logical.right, temp_name))
}

fn assign_init_in<'a>(expr: &'a Expression<'a>, temp_name: &str) -> Option<&'a Expression<'a>> {
    let Expression::BinaryExpression(bin) = unwrap_paren(expr) else {
        return None;
    };
    assign_init_of(&bin.left, temp_name).or_else(|| assign_init_of(&bin.right, temp_name))
}

fn assign_init_of<'a>(expr: &'a Expression<'a>, temp_name: &str) -> Option<&'a Expression<'a>> {
    let Expression::AssignmentExpression(assign) = unwrap_paren(expr) else {
        return None;
    };
    if assign.operator != AssignmentOperator::Assign {
        return None;
    }
    if assign.left.get_identifier()? != temp_name {
        return None;
    }
    Some(&assign.right)
}

fn is_null_or_undefined(expr: &Expression<'_>) -> bool {
    match unwrap_paren(expr) {
        Expression::NullLiteral(_) => true,
        Expression::Identifier(id) => id.name.as_str() == "undefined",
        Expression::UnaryExpression(unary) => {
            unary.operator == UnaryOperator::Void
                && matches!(
                    unwrap_paren(&unary.argument),
                    Expression::NumericLiteral(_) | Expression::StringLiteral(_)
                )
        }
        _ => false,
    }
}

fn unwrap_paren<'a>(expr: &'a Expression<'a>) -> &'a Expression<'a> {
    match expr {
        Expression::ParenthesizedExpression(paren) => unwrap_paren(&paren.expression),
        other => other,
    }
}

struct OutsideUseProbe<'a> {
    name: &'a str,
    region_start: u32,
    region_end: u32,
    found: bool,
}

impl<'a> Visit<'a> for OutsideUseProbe<'_> {
    fn visit_identifier_reference(&mut self, ident: &oxc_ast::ast::IdentifierReference<'a>) {
        if ident.name != self.name {
            return;
        }
        let span_start: u32 = ident.span.start;
        if span_start < self.region_start || span_start >= self.region_end {
            self.found = true;
        }
    }

    fn visit_binding_identifier(&mut self, ident: &oxc_ast::ast::BindingIdentifier<'a>) {
        if ident.name != self.name {
            return;
        }
        let span_start: u32 = ident.span.start;
        if span_start < self.region_start || span_start >= self.region_end {
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
        let (outcome, _stats): (RuleOutcome, super::LogicalAssignStats) = recover(source);
        let mut sorted: Vec<&Edit> = outcome.edits.iter().collect();
        sorted.sort_by_key(|edit| core::cmp::Reverse(edit.start));
        let mut out: String = source.to_owned();
        for edit in sorted {
            out.replace_range(edit.start..edit.end, &edit.replacement);
        }
        out
    }

    #[test]
    fn and_assign_identifier() {
        let out: String = apply("a && (a = b);");
        assert_eq!(out, "a &&= b;");
    }

    #[test]
    fn or_assign_identifier() {
        let out: String = apply("a || (a = b);");
        assert_eq!(out, "a ||= b;");
    }

    #[test]
    fn nullish_assign_identifier() {
        let source: &str = "(_a = a) !== null && _a !== void 0 ? _a : a = b;";
        let out: String = apply(source);
        assert_eq!(out, "a ??= b;");
    }

    #[test]
    fn and_assign_preserves_call_rhs() {
        let out: String = apply("a && (a = getValue());");
        assert_eq!(out, "a &&= getValue();");
    }

    #[test]
    fn mismatched_targets_not_matched() {
        let (outcome, _stats): (RuleOutcome, super::LogicalAssignStats) = recover("a && (b = c);");
        assert!(outcome.edits.is_empty(), "different targets must not match");
    }

    #[test]
    fn plain_logical_not_matched() {
        let (outcome, _stats): (RuleOutcome, super::LogicalAssignStats) = recover("a && b;");
        assert!(outcome.edits.is_empty());
    }

    #[test]
    fn compound_assign_rhs_not_matched() {
        let (outcome, _stats): (RuleOutcome, super::LogicalAssignStats) = recover("a && (a += b);");
        assert!(outcome.edits.is_empty(), "+= is not =, must not match");
    }

    #[test]
    fn nullish_temp_reused_blocks_recovery() {
        let source: &str = "(_a = a) !== null && _a !== void 0 ? _a : a = b; sink(_a);";
        let (outcome, _stats): (RuleOutcome, super::LogicalAssignStats) = recover(source);
        assert!(
            outcome.edits.is_empty(),
            "temp used after the conditional must block recovery"
        );
    }

    #[test]
    fn nullish_undefined_identifier_form() {
        let source: &str = "(_a = a) !== null && _a !== undefined ? _a : a = b;";
        let out: String = apply(source);
        assert_eq!(out, "a ??= b;");
    }

    #[test]
    fn stats_count_each_operator() {
        let source: &str = "a && (a = b); c || (c = d);";
        let (_outcome, stats): (RuleOutcome, super::LogicalAssignStats) = recover(source);
        assert_eq!(stats.logical_and, 1);
        assert_eq!(stats.logical_or, 1);
    }

    #[test]
    fn full_pipeline_recovers_verbatim_babel_output() {
        use crate::unminify::ast::{AstPipeline, AstUnminifyStats};
        let babel: &str = concat!(
            "a && (a = b);\n",
            "a || (a = b);\n",
            "(_a = a) !== null && _a !== void 0 ? _a : a = b;\n"
        );
        let pipeline: AstPipeline = AstPipeline::default();
        let (out, stats): (String, AstUnminifyStats) = pipeline.run(babel);
        assert!(out.contains("a &&= b"), "got: {out}");
        assert!(out.contains("a ||= b"), "got: {out}");
        assert!(out.contains("a ??= b"), "got: {out}");
        assert_eq!(stats.and_assignments_recovered, 1);
        assert_eq!(stats.or_assignments_recovered, 1);
        assert_eq!(stats.nullish_assignments_recovered, 1);
    }
}
