use oxc_allocator::Allocator;
use oxc_ast::Visit;
use oxc_ast::ast::{Argument, CallExpression, Expression};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct ThenCatchStats {
    pub(super) then_to_catch: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, ThenCatchStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), ThenCatchStats::default());
    }

    let mut collector: Collector = Collector {
        source,
        edits: Vec::new(),
    };
    collector.visit_program(&parsed.program);

    if collector.edits.is_empty() {
        return (RuleOutcome::empty(), ThenCatchStats::default());
    }
    let then_to_catch: usize = collector.edits.len();
    (
        RuleOutcome {
            edits: collector.edits,
        },
        ThenCatchStats { then_to_catch },
    )
}

struct Collector<'s> {
    source: &'s str,
    edits: Vec<Edit>,
}

impl<'a> Visit<'a> for Collector<'_> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if let Some(edit) = try_rewrite(call, self.source) {
            self.edits.push(edit);
        }
        oxc_ast::visit::walk::walk_call_expression(self, call);
    }
}

fn try_rewrite(call: &CallExpression<'_>, source: &str) -> Option<Edit> {
    let Expression::StaticMemberExpression(member) = &call.callee else {
        return None;
    };
    if member.property.name != "then" {
        return None;
    }
    if call.arguments.len() != 2 {
        return None;
    }
    let first: &Argument<'_> = &call.arguments[0];
    let second: &Argument<'_> = &call.arguments[1];
    let first_expr: &Expression<'_> = first.as_expression()?;
    if !is_null_or_undefined(first_expr) {
        return None;
    }
    let second_expr: &Expression<'_> = second.as_expression()?;

    let object_src: &str = member.object.span().source_text(source);
    let handler_src: &str = second_expr.span().source_text(source);
    Some(Edit {
        start: call.span.start as usize,
        end: call.span.end as usize,
        replacement: format!("{object_src}.catch({handler_src})"),
    })
}

fn is_null_or_undefined(expr: &Expression<'_>) -> bool {
    match expr {
        Expression::NullLiteral(_) => true,
        Expression::Identifier(ident) => ident.name == "undefined",
        _ => false,
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::recover;
    use crate::unminify::ast::{Edit, RuleOutcome};

    fn apply(source: &str) -> String {
        let (outcome, _stats): (RuleOutcome, super::ThenCatchStats) = recover(source);
        let mut sorted: Vec<&Edit> = outcome.edits.iter().collect();
        sorted.sort_by_key(|edit| core::cmp::Reverse(edit.start));
        let mut out: String = source.to_owned();
        for edit in sorted {
            out.replace_range(edit.start..edit.end, &edit.replacement);
        }
        out
    }

    #[test]
    fn then_null_handler_becomes_catch() {
        assert_eq!(apply("p.then(null, onError);"), "p.catch(onError);");
    }

    #[test]
    fn then_undefined_handler_becomes_catch() {
        assert_eq!(
            apply("fetch(u).then(undefined, fn);"),
            "fetch(u).catch(fn);"
        );
    }

    #[test]
    fn keeps_two_real_handlers() {
        let source: &str = "p.then(onOk, onError);";
        let (outcome, stats): (RuleOutcome, super::ThenCatchStats) = recover(source);
        assert!(outcome.edits.is_empty());
        assert_eq!(stats.then_to_catch, 0);
    }

    #[test]
    fn keeps_single_argument_then() {
        let source: &str = "p.then(onOk);";
        let (outcome, _stats): (RuleOutcome, super::ThenCatchStats) = recover(source);
        assert!(outcome.edits.is_empty());
    }

    #[test]
    fn preserves_a_chained_receiver() {
        assert_eq!(apply("a.b().then(null, h);"), "a.b().catch(h);");
    }
}
