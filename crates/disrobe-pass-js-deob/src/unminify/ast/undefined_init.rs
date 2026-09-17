use oxc_allocator::Allocator;
use oxc_ast::Visit;
use oxc_ast::ast::{
    BindingPatternKind, CallExpression, Expression, Program, VariableDeclaration,
    VariableDeclarationKind, WithStatement,
};
use oxc_parser::Parser;
use oxc_span::SourceType;

use super::{Edit, RuleOutcome, edit_overlaps_comments};

#[derive(Debug, Clone, Default)]
pub(super) struct UndefinedInitStats {
    pub(super) inits_dropped: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, UndefinedInitStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), UndefinedInitStats::default());
    }
    let program: &Program<'_> = &parsed.program;

    if !undefined_lookup_is_stable(program) {
        return (RuleOutcome::empty(), UndefinedInitStats::default());
    }

    let mut collector: Collector = Collector { edits: Vec::new() };
    collector.visit_program(program);
    collector
        .edits
        .retain(|edit: &Edit| !edit_overlaps_comments(edit, &program.comments));

    if collector.edits.is_empty() {
        return (RuleOutcome::empty(), UndefinedInitStats::default());
    }
    let inits_dropped: usize = collector.edits.len();
    (
        RuleOutcome {
            edits: collector.edits,
        },
        UndefinedInitStats { inits_dropped },
    )
}

pub(super) fn binding_named_undefined_exists(program: &Program<'_>) -> bool {
    let mut probe: BindingProbe = BindingProbe { found: false };
    probe.visit_program(program);
    probe.found
}

pub(super) fn undefined_lookup_is_stable(program: &Program<'_>) -> bool {
    !binding_named_undefined_exists(program) && !dynamic_undefined_lookup_exists(program)
}

struct BindingProbe {
    found: bool,
}

impl<'a> Visit<'a> for BindingProbe {
    fn visit_binding_identifier(&mut self, ident: &oxc_ast::ast::BindingIdentifier<'a>) {
        if ident.name == "undefined" {
            self.found = true;
        }
    }
}

fn dynamic_undefined_lookup_exists(program: &Program<'_>) -> bool {
    let mut probe: DynamicLookupProbe = DynamicLookupProbe { found: false };
    probe.visit_program(program);
    probe.found
}

struct DynamicLookupProbe {
    found: bool,
}

impl<'a> Visit<'a> for DynamicLookupProbe {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if is_direct_eval_callee(&call.callee) {
            self.found = true;
            return;
        }
        oxc_ast::visit::walk::walk_call_expression(self, call);
    }

    fn visit_with_statement(&mut self, _statement: &WithStatement<'a>) {
        self.found = true;
    }
}

fn is_direct_eval_callee(callee: &Expression<'_>) -> bool {
    match callee {
        Expression::Identifier(identifier) => identifier.name == "eval",
        Expression::ParenthesizedExpression(paren) => is_direct_eval_callee(&paren.expression),
        _ => false,
    }
}

struct Collector {
    edits: Vec<Edit>,
}

impl<'a> Visit<'a> for Collector {
    fn visit_variable_declaration(&mut self, decl: &VariableDeclaration<'a>) {
        if decl.kind == VariableDeclarationKind::Let {
            for declarator in &decl.declarations {
                if let Some(edit) = try_drop(declarator) {
                    self.edits.push(edit);
                }
            }
        }
        for declarator in &decl.declarations {
            if let Some(init) = declarator.init.as_ref() {
                self.visit_expression(init);
            }
        }
    }
}

fn try_drop(declarator: &oxc_ast::ast::VariableDeclarator<'_>) -> Option<Edit> {
    let BindingPatternKind::BindingIdentifier(binding) = &declarator.id.kind else {
        return None;
    };
    let init: &Expression<'_> = declarator.init.as_ref()?;
    if !is_plain_undefined(init) {
        return None;
    }
    Some(Edit {
        start: binding.span.end as usize,
        end: declarator.span.end as usize,
        replacement: String::new(),
    })
}

fn is_plain_undefined(expr: &Expression<'_>) -> bool {
    matches!(expr, Expression::Identifier(ident) if ident.name == "undefined")
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::recover;
    use crate::unminify::ast::{Edit, RuleOutcome};

    fn apply(source: &str) -> String {
        let (outcome, _stats): (RuleOutcome, super::UndefinedInitStats) = recover(source);
        let mut sorted: Vec<&Edit> = outcome.edits.iter().collect();
        sorted.sort_by_key(|edit| core::cmp::Reverse(edit.start));
        let mut out: String = source.to_owned();
        for edit in sorted {
            out.replace_range(edit.start..edit.end, &edit.replacement);
        }
        out
    }

    #[test]
    fn drops_undefined_init_from_let() {
        assert_eq!(apply("let x = undefined;"), "let x;");
    }

    #[test]
    fn retains_undefined_init_from_var() {
        assert_eq!(apply("var y = undefined;"), "var y = undefined;");
    }

    #[test]
    fn drops_only_the_undefined_declarator_in_a_group() {
        assert_eq!(
            apply("let a = undefined, b = 1, c = undefined;"),
            "let a, b = 1, c;"
        );
    }

    #[test]
    fn leaves_const_untouched() {
        let source: &str = "const x = undefined;";
        let (outcome, stats): (RuleOutcome, super::UndefinedInitStats) = recover(source);
        assert!(outcome.edits.is_empty());
        assert_eq!(stats.inits_dropped, 0);
    }

    #[test]
    fn leaves_real_value_inits_untouched() {
        let source: &str = "let x = 1, y = foo();";
        let (outcome, _stats): (RuleOutcome, super::UndefinedInitStats) = recover(source);
        assert!(outcome.edits.is_empty());
    }

    #[test]
    fn refuses_when_undefined_is_a_local_binding() {
        let source: &str = "function f(undefined) { let x = undefined; return x; }";
        let (outcome, stats): (RuleOutcome, super::UndefinedInitStats) = recover(source);
        assert!(
            outcome.edits.is_empty(),
            "undefined is shadowed by a parameter; the init is not the global undefined"
        );
        assert_eq!(stats.inits_dropped, 0);
    }

    #[test]
    fn refuses_when_with_can_resolve_undefined() {
        let source: &str = "with ({ undefined: 7 }) { let value = undefined; }";
        let (outcome, stats): (RuleOutcome, super::UndefinedInitStats) = recover(source);
        assert!(outcome.edits.is_empty());
        assert_eq!(stats.inits_dropped, 0);
        assert_eq!(apply(source), source);
    }

    #[test]
    fn drops_undefined_init_from_let_inside_nested_function() {
        assert_eq!(
            apply("function g() { let z = undefined; return z; }"),
            "function g() { let z; return z; }"
        );
    }
}
