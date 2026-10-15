use std::collections::BTreeSet;

use oxc_allocator::Allocator;
use oxc_ast::Visit;
use oxc_ast::ast as oast;
use oxc_ast::visit::walk;
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType, Span};
use serde::Serialize;

use crate::sandbox_guard::nesting_is_safe;
use crate::scan_utils::reparses_script;
use crate::unminify::splice_spans;

const MAX_SETTLE_ROUNDS: usize = 16;
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;
const MAX_FOLDED_STRING_BYTES: usize = 4096;

#[derive(Debug, Clone, Default, Serialize)]
pub struct LiteralSettleStats {
    pub expressions_folded: usize,
    pub members_dotted: usize,
    pub strings_unescaped: usize,
    pub octal_numbers_rewritten: usize,
    pub rounds: usize,
}

#[must_use]
pub(super) fn settle_literals(source: &str) -> (String, LiteralSettleStats) {
    let mut stats: LiteralSettleStats = LiteralSettleStats::default();
    if !nesting_is_safe(source) {
        return (source.to_owned(), stats);
    }
    let mut current: String = source.to_owned();
    for _ in 0..MAX_SETTLE_ROUNDS {
        let Some(next): Option<String> = settle_once(&current, &mut stats) else {
            break;
        };
        stats.rounds += 1;
        current = next;
    }
    (current, stats)
}

fn settle_once(source: &str, stats: &mut LiteralSettleStats) -> Option<String> {
    let allocator: Allocator = Allocator::default();
    let parsed: oxc_parser::ParserReturn<'_> =
        Parser::new(&allocator, source, SourceType::cjs()).parse();
    if parsed.panicked || !parsed.errors.is_empty() {
        return None;
    }
    let mut collector: Collector<'_> = Collector {
        source,
        statement_expressions: BTreeSet::new(),
        dotted_objects: BTreeSet::new(),
        edits: Vec::new(),
        stats: LiteralSettleStats::default(),
    };
    collector.visit_program(&parsed.program);
    if collector.edits.is_empty() {
        return None;
    }
    let next: String = splice_spans(source, collector.edits)?;
    if next == source || !reparses_script(&next) {
        return None;
    }
    stats.expressions_folded += collector.stats.expressions_folded;
    stats.members_dotted += collector.stats.members_dotted;
    stats.strings_unescaped += collector.stats.strings_unescaped;
    stats.octal_numbers_rewritten += collector.stats.octal_numbers_rewritten;
    Some(next)
}

#[derive(Debug, Clone, PartialEq)]
enum Constant {
    Number(f64),
    Text(String),
}

fn safe_integer(value: f64) -> Option<f64> {
    (value.is_finite() && value.fract() == 0.0 && value.abs() <= MAX_SAFE_INTEGER).then_some(value)
}

fn evaluate(expr: &oast::Expression<'_>) -> Option<Constant> {
    match expr {
        oast::Expression::NumericLiteral(literal) => {
            safe_integer(literal.value).map(Constant::Number)
        }
        oast::Expression::StringLiteral(literal) => {
            Some(Constant::Text(literal.value.as_str().to_owned()))
        }
        oast::Expression::ParenthesizedExpression(paren) => evaluate(&paren.expression),
        oast::Expression::StaticMemberExpression(member)
            if !member.optional && member.property.name == "length" =>
        {
            string_length(&member.object)
        }
        oast::Expression::ComputedMemberExpression(member) if !member.optional => {
            match evaluate(&member.expression)? {
                Constant::Text(key) if key == "length" => string_length(&member.object),
                Constant::Text(_) | Constant::Number(_) => None,
            }
        }
        oast::Expression::UnaryExpression(unary)
            if unary.operator == oast::UnaryOperator::UnaryNegation =>
        {
            match evaluate(&unary.argument)? {
                Constant::Number(value) if value != 0.0 => Some(Constant::Number(-value)),
                Constant::Number(_) | Constant::Text(_) => None,
            }
        }
        oast::Expression::BinaryExpression(binary) => {
            let left: Constant = evaluate(&binary.left)?;
            let right: Constant = evaluate(&binary.right)?;
            fold_binary(binary.operator, left, right)
        }
        _ => None,
    }
}

fn string_length(object: &oast::Expression<'_>) -> Option<Constant> {
    match evaluate(object)? {
        Constant::Text(text) => {
            let units: u32 = u32::try_from(text.encode_utf16().count()).ok()?;
            Some(Constant::Number(f64::from(units)))
        }
        Constant::Number(_) => None,
    }
}

fn fold_binary(
    operator: oast::BinaryOperator,
    left: Constant,
    right: Constant,
) -> Option<Constant> {
    match (left, right) {
        (Constant::Number(a), Constant::Number(b)) => {
            let value: f64 = match operator {
                oast::BinaryOperator::Addition => a + b,
                oast::BinaryOperator::Subtraction => a - b,
                oast::BinaryOperator::Multiplication => a * b,
                oast::BinaryOperator::Division if b != 0.0 => a / b,
                _ => return None,
            };
            if value == 0.0 && value.is_sign_negative() {
                return None;
            }
            safe_integer(value).map(Constant::Number)
        }
        (Constant::Text(a), Constant::Text(b))
            if operator == oast::BinaryOperator::Addition
                && a.len() + b.len() <= MAX_FOLDED_STRING_BYTES =>
        {
            Some(Constant::Text(a + b.as_str()))
        }
        _ => None,
    }
}

fn render_string(value: &str) -> Option<String> {
    if !value.bytes().all(|b: u8| (0x20..=0x7e).contains(&b)) {
        return None;
    }
    let mut out: String = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            other => out.push(other),
        }
    }
    out.push('\'');
    Some(out)
}

fn render_number(value: f64) -> String {
    if value < 0.0 {
        format!("({})", value as i64)
    } else {
        format!("{}", value as u64)
    }
}

fn is_identifier_name(name: &str) -> bool {
    let mut bytes: std::str::Bytes<'_> = name.bytes();
    bytes
        .next()
        .is_some_and(|b: u8| b.is_ascii_alphabetic() || b == b'_' || b == b'$')
        && bytes.all(|b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'$')
}

fn legacy_decimal(raw: &str, value: f64) -> Option<String> {
    let digits: &str = raw.strip_prefix('0')?;
    if digits.is_empty() || !digits.bytes().all(|b: u8| b.is_ascii_digit()) {
        return None;
    }
    safe_integer(value).map(render_number)
}

fn is_plain_literal(expr: &oast::Expression<'_>) -> bool {
    match expr {
        oast::Expression::NumericLiteral(_) | oast::Expression::StringLiteral(_) => true,
        oast::Expression::UnaryExpression(unary) => {
            unary.operator == oast::UnaryOperator::UnaryNegation
                && matches!(unary.argument, oast::Expression::NumericLiteral(_))
        }
        _ => false,
    }
}

struct Collector<'s> {
    source: &'s str,
    statement_expressions: BTreeSet<(u32, u32)>,
    dotted_objects: BTreeSet<(u32, u32)>,
    edits: Vec<(usize, usize, String)>,
    stats: LiteralSettleStats,
}

impl Collector<'_> {
    fn raw(&self, span: Span) -> Option<&str> {
        self.source.get(span.start as usize..span.end as usize)
    }

    fn followed_by_dot(&self, span: Span) -> bool {
        self.source
            .get(span.end as usize..)
            .and_then(|rest: &str| rest.trim_start().bytes().next())
            == Some(b'.')
    }

    fn edit(&mut self, span: Span, replacement: String) {
        self.edits
            .push((span.start as usize, span.end as usize, replacement));
    }

    fn fold(&mut self, expr: &oast::Expression<'_>) -> bool {
        if is_plain_literal(expr) {
            return false;
        }
        let span: Span = expr.span();
        if self.statement_expressions.contains(&(span.start, span.end)) {
            return false;
        }
        let rendered: Option<String> = match evaluate(expr) {
            Some(Constant::Number(value)) => {
                let text: String = render_number(value);
                Some(
                    if value >= 0.0
                        && (self.followed_by_dot(span)
                            || self.dotted_objects.contains(&(span.start, span.end)))
                    {
                        format!("({text})")
                    } else {
                        text
                    },
                )
            }
            Some(Constant::Text(text)) => render_string(&text),
            None => None,
        };
        let Some(rendered) = rendered else {
            return false;
        };
        self.stats.expressions_folded += 1;
        self.edit(span, rendered);
        true
    }
}

impl<'a> Visit<'a> for Collector<'_> {
    fn visit_directive(&mut self, _directive: &oast::Directive<'a>) {}

    fn visit_expression_statement(&mut self, stmt: &oast::ExpressionStatement<'a>) {
        let span: Span = stmt.expression.span();
        self.statement_expressions.insert((span.start, span.end));
        walk::walk_expression_statement(self, stmt);
    }

    fn visit_expression(&mut self, expr: &oast::Expression<'a>) {
        if self.fold(expr) {
            return;
        }
        walk::walk_expression(self, expr);
    }

    fn visit_computed_member_expression(&mut self, member: &oast::ComputedMemberExpression<'a>) {
        if !member.optional
            && !matches!(member.object, oast::Expression::NumericLiteral(_))
            && let Some(Constant::Text(name)) = evaluate(&member.expression)
            && is_identifier_name(&name)
        {
            self.stats.members_dotted += 1;
            let start: u32 = member.object.span().end;
            self.edit(Span::new(start, member.span.end), format!(".{name}"));
            let object: Span = member.object.span();
            self.dotted_objects.insert((object.start, object.end));
            self.visit_expression(&member.object);
            return;
        }
        walk::walk_computed_member_expression(self, member);
    }

    fn visit_string_literal(&mut self, literal: &oast::StringLiteral<'a>) {
        let Some(raw) = self.raw(literal.span) else {
            return;
        };
        if !raw.contains('\\') {
            return;
        }
        if let Some(text) = render_string(literal.value.as_str()) {
            self.stats.strings_unescaped += 1;
            self.edit(literal.span, text);
        }
    }

    fn visit_numeric_literal(&mut self, literal: &oast::NumericLiteral<'a>) {
        let Some(raw) = self.raw(literal.span) else {
            return;
        };
        let Some(decimal) = legacy_decimal(raw, literal.value) else {
            return;
        };
        self.stats.octal_numbers_rewritten += 1;
        let text: String = if self.followed_by_dot(literal.span) {
            format!("({decimal})")
        } else {
            decimal
        };
        self.edit(literal.span, text);
    }
}

#[cfg(test)]
mod tests {
    use super::settle_literals;

    fn settled(source: &str) -> String {
        settle_literals(source).0
    }

    #[test]
    fn string_lengths_and_parenthesized_keys_fold_to_constants() {
        assert_eq!(
            settled("var f=('Xda'[('length')]-'kYa'[('length')]);"),
            "var f=0;"
        );
        assert_eq!(
            settled(
                "for(var V=('sc'['length']-'AW'['length']);V<n;V++){c((('ekS'[('length')]*'lDd'[('length')]+'N'[('length')])));}"
            ),
            "for(var V=0;V<n;V++){c(10);}"
        );
        assert_eq!(
            settled("window.console[('log')](window.JSON[('stringify')](q));"),
            "window.console.log(window.JSON.stringify(q));"
        );
    }

    #[test]
    fn escaped_keys_and_legacy_octal_numbers_are_rewritten() {
        assert_eq!(
            settled(r#"var q={"\x66\x69b\61\60":(01*0117+29)};"#),
            "var q={'fib10':108};"
        );
    }

    #[test]
    fn statement_strings_directives_and_number_members_keep_their_meaning() {
        let source: &str = "function f(){'use\\x20strict';('use'+' strict');return (2+3).toString()+(07).toFixed(0);}";
        let out: String = settled(source);
        assert!(out.contains("'use\\x20strict';"), "{out}");
        assert!(out.contains("('use strict');"), "{out}");
        assert!(out.contains("(5).toString()"), "{out}");
        assert!(out.contains("(7).toFixed(0)"), "{out}");
    }

    #[test]
    fn negative_results_and_keywords_never_glue_to_neighbours() {
        assert_eq!(settled("var a=b-(1-3);"), "var a=b-(-2);");
        assert_eq!(
            settled("function f(){return(2*3)}"),
            "function f(){return 6}"
        );
        assert_eq!(settled("var z=(0*-1);"), "var z=(0*-1);");
    }

    #[test]
    fn optional_members_and_non_ascii_text_are_left_alone() {
        let out: String = settled("var a=x?.['log'];var b='\\u00e9'.length;var c='\\u00e9';");
        assert!(out.contains("x?.['log']"), "{out}");
        assert!(out.contains("var b=1;"), "{out}");
        assert_eq!(
            settled("var n=5['toString'](2);var m=(5)['toFixed'](1);"),
            "var n=5['toString'](2);var m=(5).toFixed(1);"
        );
        assert!(out.contains("var c='\\u00e9';"), "{out}");
    }

    #[test]
    fn hostile_scripts_are_bounded_and_never_panic() {
        let deep: String = format!("var d={}1{};", "(".repeat(5000), ")".repeat(5000));
        assert_eq!(settled(&deep), deep);

        let piece: String = format!("'{}'", "x".repeat(1000));
        let long: String = format!("var s={};", vec![piece; 8].join("+"));
        let out: String = settled(&long);
        assert!(out.len() <= long.len(), "{}", out.len());
        assert!(
            !out.contains(&"x".repeat(super::MAX_FOLDED_STRING_BYTES + 1)),
            "a folded string must stay under the cap"
        );

        let mut state: u64 = 0x2545_F491_4F6C_DD1D;
        let alphabet: &[u8] = b"('ab'[('length')]+01*0117-\"\\x61\")[]{};var x=.,?";
        for _ in 0..512 {
            let mut text: Vec<u8> = Vec::with_capacity(128);
            for _ in 0..128 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                text.push(alphabet[(state % alphabet.len() as u64) as usize]);
            }
            let script: String = String::from_utf8(text).unwrap_or_default();
            let _settled: String = settled(&script);
        }
    }
}
