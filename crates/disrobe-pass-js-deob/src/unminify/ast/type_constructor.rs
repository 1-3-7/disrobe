use oxc_allocator::Allocator;
use oxc_ast::Visit;
use oxc_ast::ast::{
    ArrayExpression, ArrayExpressionElement, BinaryExpression, BinaryOperator, Expression,
    UnaryExpression, UnaryOperator,
};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct TypeConstructorStats {
    pub(super) number_coercions: usize,
    pub(super) string_coercions: usize,
    pub(super) array_holes_named: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, TypeConstructorStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), TypeConstructorStats::default());
    }

    let mut probe: ShadowProbe = ShadowProbe {
        number: false,
        string: false,
        array: false,
    };
    probe.visit_program(&parsed.program);

    let mut collector: Collector = Collector {
        source,
        edits: Vec::new(),
        stats: TypeConstructorStats::default(),
        allow_number: !probe.number,
        allow_string: !probe.string,
        allow_array: !probe.array,
    };
    collector.visit_program(&parsed.program);

    if collector.edits.is_empty() {
        return (RuleOutcome::empty(), TypeConstructorStats::default());
    }
    (
        RuleOutcome {
            edits: collector.edits,
        },
        collector.stats,
    )
}

struct ShadowProbe {
    number: bool,
    string: bool,
    array: bool,
}

impl<'a> Visit<'a> for ShadowProbe {
    fn visit_binding_identifier(&mut self, ident: &oxc_ast::ast::BindingIdentifier<'a>) {
        match ident.name.as_str() {
            "Number" => self.number = true,
            "String" => self.string = true,
            "Array" => self.array = true,
            _ => {}
        }
    }
}

struct Collector<'s> {
    source: &'s str,
    edits: Vec<Edit>,
    stats: TypeConstructorStats,
    allow_number: bool,
    allow_string: bool,
    allow_array: bool,
}

impl<'a> Visit<'a> for Collector<'_> {
    fn visit_expression(&mut self, expr: &Expression<'a>) {
        if let Some(edit) = self.try_match(expr) {
            self.edits.push(edit);
            return;
        }
        oxc_ast::visit::walk::walk_expression(self, expr);
    }
}

impl Collector<'_> {
    fn try_match(&mut self, expr: &Expression<'_>) -> Option<Edit> {
        match expr {
            Expression::UnaryExpression(unary) if self.allow_number => self.try_number(unary),
            Expression::BinaryExpression(bin) if self.allow_string => self.try_string(bin),
            Expression::ArrayExpression(arr) if self.allow_array => self.try_array(arr),
            _ => None,
        }
    }

    fn try_number(&mut self, unary: &UnaryExpression<'_>) -> Option<Edit> {
        if unary.operator != UnaryOperator::UnaryPlus {
            return None;
        }
        let Expression::Identifier(ident) = &unary.argument else {
            return None;
        };
        self.stats.number_coercions += 1;
        Some(Edit {
            start: unary.span.start as usize,
            end: unary.span.end as usize,
            replacement: format!("Number({})", ident.name),
        })
    }

    fn try_string(&mut self, bin: &BinaryExpression<'_>) -> Option<Edit> {
        if bin.operator != BinaryOperator::Addition {
            return None;
        }
        if !is_empty_string(&bin.right) {
            return None;
        }
        if is_string_literal(&bin.left) {
            return None;
        }
        let left_src: &str = bin.left.span().source_text(self.source);
        self.stats.string_coercions += 1;
        Some(Edit {
            start: bin.span.start as usize,
            end: bin.span.end as usize,
            replacement: format!("String({left_src})"),
        })
    }

    fn try_array(&mut self, arr: &ArrayExpression<'_>) -> Option<Edit> {
        if arr.elements.is_empty() {
            return None;
        }
        if !arr
            .elements
            .iter()
            .all(|e| matches!(e, ArrayExpressionElement::Elision(_)))
        {
            return None;
        }
        let count: usize = arr.elements.len();
        self.stats.array_holes_named += 1;
        Some(Edit {
            start: arr.span.start as usize,
            end: arr.span.end as usize,
            replacement: format!("Array({count})"),
        })
    }
}

fn is_empty_string(expr: &Expression<'_>) -> bool {
    matches!(expr, Expression::StringLiteral(s) if s.value.is_empty())
}

const fn is_string_literal(expr: &Expression<'_>) -> bool {
    matches!(expr, Expression::StringLiteral(_))
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::recover;
    use crate::unminify::ast::{Edit, RuleOutcome};

    fn apply(source: &str) -> String {
        let (outcome, _stats): (RuleOutcome, super::TypeConstructorStats) = recover(source);
        let mut sorted: Vec<&Edit> = outcome.edits.iter().collect();
        sorted.sort_by_key(|edit| core::cmp::Reverse(edit.start));
        let mut out: String = source.to_owned();
        for edit in sorted {
            out.replace_range(edit.start..edit.end, &edit.replacement);
        }
        out
    }

    #[test]
    fn unary_plus_ident_becomes_number_call() {
        assert_eq!(apply("var n = +x;"), "var n = Number(x);");
    }

    #[test]
    fn plus_empty_string_becomes_string_call() {
        assert_eq!(
            apply("var s = obj.value + '';"),
            "var s = String(obj.value);"
        );
    }

    #[test]
    fn all_holes_array_becomes_array_call() {
        assert_eq!(apply("var a = [,,,];"), "var a = Array(3);");
    }

    #[test]
    fn leaves_unary_plus_on_literal_alone() {
        let source: &str = "var n = +5;";
        let (outcome, _stats): (RuleOutcome, super::TypeConstructorStats) = recover(source);
        assert!(outcome.edits.is_empty());
    }

    #[test]
    fn leaves_string_literal_plus_empty_alone() {
        let source: &str = "var s = 'hi' + '';";
        let (outcome, stats): (RuleOutcome, super::TypeConstructorStats) = recover(source);
        assert!(outcome.edits.is_empty());
        assert_eq!(stats.string_coercions, 0);
    }

    #[test]
    fn leaves_populated_array_alone() {
        let source: &str = "var a = [1, , 3];";
        let (outcome, _stats): (RuleOutcome, super::TypeConstructorStats) = recover(source);
        assert!(outcome.edits.is_empty());
    }

    #[test]
    fn refuses_when_builtin_is_shadowed() {
        let source: &str = "function f(Number) { return +x; }";
        let (outcome, stats): (RuleOutcome, super::TypeConstructorStats) = recover(source);
        assert!(
            outcome.edits.is_empty(),
            "Number is shadowed by a parameter; +x must not become Number(x)"
        );
        assert_eq!(stats.number_coercions, 0);
    }
}
