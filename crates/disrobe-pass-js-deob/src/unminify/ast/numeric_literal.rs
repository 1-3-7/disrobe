use oxc_allocator::Allocator;
use oxc_ast::Visit;
use oxc_ast::ast::NumericLiteral;
use oxc_parser::Parser;
use oxc_span::SourceType;

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct NumericLiteralStats {
    pub(super) literals_normalized: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, NumericLiteralStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), NumericLiteralStats::default());
    }

    let mut collector: Collector = Collector {
        source,
        edits: Vec::new(),
    };
    collector.visit_program(&parsed.program);

    if collector.edits.is_empty() {
        return (RuleOutcome::empty(), NumericLiteralStats::default());
    }
    let literals_normalized: usize = collector.edits.len();
    (
        RuleOutcome {
            edits: collector.edits,
        },
        NumericLiteralStats {
            literals_normalized,
        },
    )
}

struct Collector<'s> {
    source: &'s str,
    edits: Vec<Edit>,
}

impl<'a> Visit<'a> for Collector<'_> {
    fn visit_numeric_literal(&mut self, literal: &NumericLiteral<'a>) {
        let Some(raw): Option<&str> = literal.raw.as_ref().map(oxc_span::Atom::as_str) else {
            return;
        };
        let Some(canonical): Option<String> = canonical_decimal(literal.value) else {
            return;
        };
        if raw == canonical {
            return;
        }
        let end: usize = literal.span.end as usize;
        let replacement: String = if needs_member_guard(&canonical, self.source, end) {
            format!("({canonical})")
        } else {
            canonical
        };
        self.edits.push(Edit {
            start: literal.span.start as usize,
            end,
            replacement,
        });
    }
}

fn needs_member_guard(canonical: &str, source: &str, literal_end: usize) -> bool {
    if !canonical.bytes().all(|b: u8| b.is_ascii_digit()) {
        return false;
    }
    source.as_bytes().get(literal_end) == Some(&b'.')
}

fn canonical_decimal(value: f64) -> Option<String> {
    if !value.is_finite() || value.fract() != 0.0 {
        return None;
    }
    let rendered: String = value.to_string();
    let round_trip: f64 = rendered.parse::<f64>().ok()?;
    if round_trip.to_bits() != value.to_bits() {
        return None;
    }
    Some(rendered)
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::recover;
    use crate::unminify::ast::{Edit, RuleOutcome};

    fn apply(source: &str) -> String {
        let (outcome, _stats): (RuleOutcome, super::NumericLiteralStats) = recover(source);
        let mut sorted: Vec<&Edit> = outcome.edits.iter().collect();
        sorted.sort_by_key(|edit| core::cmp::Reverse(edit.start));
        let mut out: String = source.to_owned();
        for edit in sorted {
            out.replace_range(edit.start..edit.end, &edit.replacement);
        }
        out
    }

    #[test]
    fn normalizes_hex_to_decimal() {
        assert_eq!(apply("var x = 0xff;"), "var x = 255;");
    }

    #[test]
    fn normalizes_binary_and_octal() {
        assert_eq!(apply("a(0b101, 0o17, 0xA);"), "a(5, 15, 10);");
    }

    #[test]
    fn normalizes_exponential_and_separators() {
        assert_eq!(
            apply("var n = 1e3, m = 1_000_000;"),
            "var n = 1000, m = 1000000;"
        );
    }

    #[test]
    fn normalizes_nested_literals_in_array_and_object() {
        assert_eq!(
            apply("var o = {a: [0x1, 0x2], b: 0o10};"),
            "var o = {a: [1, 2], b: 8};"
        );
    }

    #[test]
    fn leaves_canonical_decimals_untouched() {
        let source: &str = "var x = 255, y = 0, z = 3.14;";
        let (outcome, stats): (RuleOutcome, super::NumericLiteralStats) = recover(source);
        assert!(outcome.edits.is_empty());
        assert_eq!(stats.literals_normalized, 0);
    }

    #[test]
    fn normalizes_large_hex_losslessly() {
        assert_eq!(
            apply("var big = 0x38D7EA4C68000;"),
            "var big = 1000000000000000;"
        );
    }

    #[test]
    fn hex_member_object_is_parenthesized() {
        assert_eq!(apply("0xff.toString();"), "(255).toString();");
    }

    #[test]
    fn octal_and_binary_member_objects_are_parenthesized() {
        assert_eq!(apply("0o17.toString(2);"), "(15).toString(2);");
        assert_eq!(apply("0b101.valueOf();"), "(5).valueOf();");
    }

    #[test]
    fn hex_member_with_separators_is_parenthesized() {
        assert_eq!(apply("0xff_ff.toString();"), "(65535).toString();");
    }

    #[test]
    fn computed_member_after_hex_is_not_parenthesized() {
        assert_eq!(apply("a = 0xff[k];"), "a = 255[k];");
    }

    #[test]
    fn hex_not_followed_by_member_stays_bare() {
        assert_eq!(apply("var x = 0xff + 1;"), "var x = 255 + 1;");
    }

    #[test]
    fn leaves_bigint_literals_untouched() {
        let source: &str = "var b = 0xffn;";
        let (outcome, stats): (RuleOutcome, super::NumericLiteralStats) = recover(source);
        assert!(outcome.edits.is_empty());
        assert_eq!(stats.literals_normalized, 0);
    }
}
