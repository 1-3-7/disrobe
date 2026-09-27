use oxc_ast::ast::{
    ArrowFunctionExpression, Class, Expression, Function, IdentifierReference, MetaProperty, Super,
    ThisExpression, WithStatement, YieldExpression,
};
use oxc_ast::{Visit, visit::walk};
use oxc_semantic::{ScopeFlags, Semantic};
use oxc_span::Span;

use super::candidate::Outer;
use super::helpers::resolved_symbol;
use super::render::Wrap;

#[derive(Debug, Clone, Copy)]
pub(super) struct YieldSite {
    pub(super) span: Span,
    pub(super) argument: Option<Span>,
    pub(super) argument_wrap: Wrap,
    pub(super) delegate: bool,
}

#[derive(Debug, Default)]
pub(super) struct Usage {
    pub(super) this: bool,
    pub(super) arguments: bool,
    pub(super) super_or_meta: bool,
    pub(super) yields: Vec<YieldSite>,
}

pub(super) struct UsageProbe<'s, 'a> {
    semantic: &'s Semantic<'a>,
    usage: Usage,
}

impl<'s, 'a> UsageProbe<'s, 'a> {
    pub(super) fn new(semantic: &'s Semantic<'a>) -> Self {
        Self {
            semantic,
            usage: Usage::default(),
        }
    }

    pub(super) fn finish(self) -> Usage {
        self.usage
    }
}

impl<'a> Visit<'a> for UsageProbe<'_, 'a> {
    fn visit_function(&mut self, _function: &Function<'a>, _flags: ScopeFlags) {}

    fn visit_class(&mut self, class: &Class<'a>) {
        self.usage.this = true;
        walk::walk_class(self, class);
    }

    fn visit_arrow_function_expression(&mut self, arrow: &ArrowFunctionExpression<'a>) {
        walk::walk_arrow_function_expression(self, arrow);
    }

    fn visit_this_expression(&mut self, _this: &ThisExpression) {
        self.usage.this = true;
    }

    fn visit_super(&mut self, _super: &Super) {
        self.usage.super_or_meta = true;
    }

    fn visit_meta_property(&mut self, _meta: &MetaProperty<'a>) {
        self.usage.super_or_meta = true;
    }

    fn visit_identifier_reference(&mut self, reference: &IdentifierReference<'a>) {
        if reference.name == "arguments" && resolved_symbol(reference, self.semantic).is_none() {
            self.usage.arguments = true;
        }
    }

    fn visit_yield_expression(&mut self, expression: &YieldExpression<'a>) {
        self.usage.yields.push(YieldSite {
            span: expression.span,
            argument: expression.argument.as_ref().map(oxc_span::GetSpan::span),
            argument_wrap: expression
                .argument
                .as_ref()
                .map_or(Wrap::Bare, operand_wrap),
            delegate: expression.delegate,
        });
        walk::walk_yield_expression(self, expression);
    }
}

pub(super) fn uses_dynamic_scope<'a>(outer: Outer<'a>, semantic: &Semantic<'a>) -> bool {
    struct DynamicScopeProbe<'s, 'a> {
        semantic: &'s Semantic<'a>,
        found: bool,
    }
    impl<'a> Visit<'a> for DynamicScopeProbe<'_, 'a> {
        fn visit_identifier_reference(&mut self, reference: &IdentifierReference<'a>) {
            if reference.name == "eval" && resolved_symbol(reference, self.semantic).is_none() {
                self.found = true;
            }
        }

        fn visit_with_statement(&mut self, statement: &WithStatement<'a>) {
            self.found = true;
            walk::walk_with_statement(self, statement);
        }
    }
    let mut probe: DynamicScopeProbe<'_, 'a> = DynamicScopeProbe {
        semantic,
        found: false,
    };
    match outer {
        Outer::Function(function) | Outer::Method { function, .. } => {
            probe.visit_function(function, ScopeFlags::Function);
        }
        Outer::Arrow(arrow) => probe.visit_arrow_function_expression(arrow),
    }
    probe.found
}

pub(super) const fn operand_wrap(expression: &Expression<'_>) -> Wrap {
    match expression {
        Expression::BinaryExpression(_)
        | Expression::LogicalExpression(_)
        | Expression::ConditionalExpression(_)
        | Expression::AssignmentExpression(_)
        | Expression::SequenceExpression(_)
        | Expression::ArrowFunctionExpression(_)
        | Expression::YieldExpression(_)
        | Expression::PrivateInExpression(_) => Wrap::Parenthesized,
        _ => Wrap::Bare,
    }
}

pub(super) const fn primary_wrap(expression: &Expression<'_>) -> Wrap {
    match expression {
        Expression::Identifier(_)
        | Expression::ThisExpression(_)
        | Expression::NullLiteral(_)
        | Expression::BooleanLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::StringLiteral(_)
        | Expression::BigIntLiteral(_)
        | Expression::RegExpLiteral(_)
        | Expression::TemplateLiteral(_)
        | Expression::ArrayExpression(_)
        | Expression::ObjectExpression(_)
        | Expression::ParenthesizedExpression(_)
        | Expression::CallExpression(_)
        | Expression::StaticMemberExpression(_)
        | Expression::ComputedMemberExpression(_) => Wrap::Bare,
        _ => Wrap::Parenthesized,
    }
}
