use oxc_allocator::Allocator;
use oxc_ast::Visit;
use oxc_ast::ast::{Argument, CallExpression, Expression};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct ExponentStats {
    pub(super) powers_rewritten: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, ExponentStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), ExponentStats::default());
    }

    let mut collector: Collector = Collector {
        source,
        edits: Vec::new(),
        rewritten: 0,
    };
    collector.visit_program(&parsed.program);

    if collector.edits.is_empty() {
        return (RuleOutcome::empty(), ExponentStats::default());
    }
    let powers_rewritten: usize = collector.rewritten;
    (
        RuleOutcome {
            edits: collector.edits,
        },
        ExponentStats { powers_rewritten },
    )
}

struct Collector<'s> {
    source: &'s str,
    edits: Vec<Edit>,
    rewritten: usize,
}

impl<'a> Visit<'a> for Collector<'_> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if let Some((replacement, count)) = rewrite_pow(call, self.source) {
            self.edits.push(Edit {
                start: call.span.start as usize,
                end: call.span.end as usize,
                replacement,
            });
            self.rewritten += count;
            return;
        }
        for arg in &call.arguments {
            if let Some(expr) = arg.as_expression() {
                self.visit_expression(expr);
            }
        }
        self.visit_expression(&call.callee);
    }
}

fn rewrite_pow(call: &CallExpression<'_>, source: &str) -> Option<(String, usize)> {
    if !is_math_pow(&call.callee) {
        return None;
    }
    if call.arguments.len() != 2 {
        return None;
    }
    let base: &Argument<'_> = &call.arguments[0];
    let exponent: &Argument<'_> = &call.arguments[1];
    let base_expr: &Expression<'_> = base.as_expression()?;
    let exponent_expr: &Expression<'_> = exponent.as_expression()?;

    let (base_src, base_count): (String, usize) = render_operand(base_expr, source, true);
    let (exponent_src, exponent_count): (String, usize) =
        render_operand(exponent_expr, source, false);
    Some((
        format!("{base_src} ** {exponent_src}"),
        1 + base_count + exponent_count,
    ))
}

fn render_operand(expr: &Expression<'_>, source: &str, is_base: bool) -> (String, usize) {
    if let Expression::CallExpression(call) = expr
        && let Some((rewritten, count)) = rewrite_pow(call, source)
    {
        let wrapped: String = if is_base {
            format!("({rewritten})")
        } else {
            rewritten
        };
        return (wrapped, count);
    }
    (parenthesize(expr, source), 0)
}

fn is_math_pow(callee: &Expression<'_>) -> bool {
    let Expression::StaticMemberExpression(member) = callee else {
        return false;
    };
    if member.property.name != "pow" {
        return false;
    }
    matches!(&member.object, Expression::Identifier(ident) if ident.name == "Math")
}

fn parenthesize(expr: &Expression<'_>, source: &str) -> String {
    let text: &str = expr.span().source_text(source);
    if is_primary(expr) {
        text.to_owned()
    } else {
        format!("({text})")
    }
}

const fn is_primary(expr: &Expression<'_>) -> bool {
    matches!(
        expr,
        Expression::Identifier(_)
            | Expression::NumericLiteral(_)
            | Expression::StringLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_)
            | Expression::BigIntLiteral(_)
            | Expression::ThisExpression(_)
            | Expression::ParenthesizedExpression(_)
            | Expression::CallExpression(_)
            | Expression::StaticMemberExpression(_)
            | Expression::ComputedMemberExpression(_)
            | Expression::ArrayExpression(_)
            | Expression::ObjectExpression(_)
    )
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::recover;
    use crate::unminify::ast::{Edit, RuleOutcome};

    fn apply(source: &str) -> String {
        let (outcome, _stats): (RuleOutcome, super::ExponentStats) = recover(source);
        let mut sorted: Vec<&Edit> = outcome.edits.iter().collect();
        sorted.sort_by_key(|edit| core::cmp::Reverse(edit.start));
        let mut out: String = source.to_owned();
        for edit in sorted {
            out.replace_range(edit.start..edit.end, &edit.replacement);
        }
        out
    }

    #[test]
    fn rewrites_simple_math_pow() {
        assert_eq!(apply("var r = Math.pow(a, b);"), "var r = a ** b;");
    }

    #[test]
    fn rewrites_literal_operands() {
        assert_eq!(apply("Math.pow(2, 10);"), "2 ** 10;");
    }

    #[test]
    fn parenthesizes_binary_operands() {
        assert_eq!(apply("Math.pow(a + 1, b - 2);"), "(a + 1) ** (b - 2);");
    }

    #[test]
    fn keeps_member_and_call_operands_unparenthesized() {
        assert_eq!(apply("Math.pow(obj.x, f(y));"), "obj.x ** f(y);");
    }

    #[test]
    fn ignores_other_math_methods() {
        let source: &str = "Math.sqrt(x); Math.max(a, b);";
        let (outcome, stats): (RuleOutcome, super::ExponentStats) = recover(source);
        assert!(outcome.edits.is_empty());
        assert_eq!(stats.powers_rewritten, 0);
    }

    #[test]
    fn ignores_pow_with_wrong_arity() {
        let source: &str = "Math.pow(a); Math.pow(a, b, c);";
        let (outcome, _stats): (RuleOutcome, super::ExponentStats) = recover(source);
        assert!(outcome.edits.is_empty());
    }

    #[test]
    fn ignores_spread_arguments() {
        let source: &str = "Math.pow(...args);";
        let (outcome, _stats): (RuleOutcome, super::ExponentStats) = recover(source);
        assert!(outcome.edits.is_empty());
    }

    #[test]
    fn rewrites_nested_pow_to_fixpoint() {
        assert_eq!(apply("Math.pow(Math.pow(a, b), c);"), "(a ** b) ** c;");
    }
}
