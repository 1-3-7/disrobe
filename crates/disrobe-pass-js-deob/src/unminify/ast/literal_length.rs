use oxc_allocator::Allocator;
use oxc_ast::Visit;
use oxc_ast::ast::{ArrayExpressionElement, Expression, StaticMemberExpression};
use oxc_parser::Parser;
use oxc_span::SourceType;

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct LiteralLengthStats {
    pub(super) lengths_folded: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, LiteralLengthStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), LiteralLengthStats::default());
    }

    let mut collector: Collector = Collector { edits: Vec::new() };
    collector.visit_program(&parsed.program);

    if collector.edits.is_empty() {
        return (RuleOutcome::empty(), LiteralLengthStats::default());
    }
    let lengths_folded: usize = collector.edits.len();
    (
        RuleOutcome {
            edits: collector.edits,
        },
        LiteralLengthStats { lengths_folded },
    )
}

struct Collector {
    edits: Vec<Edit>,
}

impl<'a> Visit<'a> for Collector {
    fn visit_static_member_expression(&mut self, member: &StaticMemberExpression<'a>) {
        if member.property.name.as_str() == "length"
            && let Some(length) = literal_length(&member.object)
        {
            self.edits.push(Edit {
                start: member.span.start as usize,
                end: member.span.end as usize,
                replacement: length.to_string(),
            });
        }
        oxc_ast::visit::walk::walk_expression(self, &member.object);
    }
}

fn literal_length(object: &Expression<'_>) -> Option<usize> {
    match object {
        Expression::ArrayExpression(array) => {
            for element in &array.elements {
                if matches!(
                    element,
                    ArrayExpressionElement::SpreadElement(_) | ArrayExpressionElement::Elision(_)
                ) {
                    return None;
                }
            }
            Some(array.elements.len())
        }
        Expression::StringLiteral(string) => Some(string.value.as_str().encode_utf16().count()),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::recover;
    use crate::unminify::ast::{Edit, RuleOutcome};

    fn apply(source: &str) -> String {
        let (outcome, _stats): (RuleOutcome, super::LiteralLengthStats) = recover(source);
        let mut sorted: Vec<&Edit> = outcome.edits.iter().collect();
        sorted.sort_by_key(|edit| core::cmp::Reverse(edit.start));
        let mut out: String = source.to_owned();
        for edit in sorted {
            out.replace_range(edit.start..edit.end, &edit.replacement);
        }
        out
    }

    #[test]
    fn folds_array_literal_length() {
        assert_eq!(apply("var n = [a, b, c].length;"), "var n = 3;");
    }

    #[test]
    fn folds_string_literal_length() {
        assert_eq!(apply(r#"var n = "abc".length;"#), "var n = 3;");
    }

    #[test]
    fn folds_empty_array_length() {
        assert_eq!(apply("var n = [].length;"), "var n = 0;");
    }

    #[test]
    fn counts_utf16_code_units() {
        assert_eq!(apply(r#"var n = "\u{1F600}".length;"#), "var n = 2;");
    }

    #[test]
    fn leaves_spread_array_alone() {
        let source: &str = "var n = [...xs, a].length;";
        let (outcome, stats): (RuleOutcome, super::LiteralLengthStats) = recover(source);
        assert!(outcome.edits.is_empty());
        assert_eq!(stats.lengths_folded, 0);
    }

    #[test]
    fn leaves_holes_alone() {
        let source: &str = "var n = [a, , c].length;";
        let (outcome, stats): (RuleOutcome, super::LiteralLengthStats) = recover(source);
        assert!(outcome.edits.is_empty());
        assert_eq!(stats.lengths_folded, 0);
    }

    #[test]
    fn leaves_identifier_length_alone() {
        let source: &str = "var n = arr.length;";
        let (outcome, stats): (RuleOutcome, super::LiteralLengthStats) = recover(source);
        assert!(outcome.edits.is_empty());
        assert_eq!(stats.lengths_folded, 0);
    }
}
