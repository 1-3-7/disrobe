use oxc_ast::AstKind;
use oxc_ast::ast::{
    Argument, ArrowFunctionExpression, CallExpression, Expression, FormalParameters, Function,
    FunctionBody, MethodDefinitionKind, PropertyKey, PropertyKind, Statement,
};
use oxc_semantic::{Semantic, SymbolId};
use oxc_span::{GetSpan, Span};

use super::Refusal;
use super::helpers::{HelperBindings, HelperRole, HelperUse, is_void_zero, resolved_symbol};

#[derive(Debug, Clone, Copy)]
pub(super) enum Outer<'a> {
    Function(&'a Function<'a>),
    Method {
        key: &'a PropertyKey<'a>,
        function: &'a Function<'a>,
    },
    Arrow(&'a ArrowFunctionExpression<'a>),
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Candidate<'a> {
    pub(super) span: Span,
    pub(super) outer: Outer<'a>,
    pub(super) prologue: &'a [Statement<'a>],
    pub(super) call: &'a CallExpression<'a>,
    pub(super) awaiter: HelperUse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ThisArg {
    This,
    Captured(Option<SymbolId>),
}

#[derive(Debug, Clone, Copy)]
pub(super) struct AwaiterCall<'a> {
    pub(super) this_arg: ThisArg,
    pub(super) forwards_arguments: bool,
    pub(super) body: &'a Function<'a>,
}

impl<'a> Outer<'a> {
    pub(super) fn params(&self) -> &'a FormalParameters<'a> {
        match self {
            Self::Function(function) | Self::Method { function, .. } => &function.params,
            Self::Arrow(arrow) => &arrow.params,
        }
    }

    pub(super) fn body(&self) -> Option<&'a FunctionBody<'a>> {
        match self {
            Self::Function(function) | Self::Method { function, .. } => function.body.as_deref(),
            Self::Arrow(arrow) => Some(&arrow.body),
        }
    }

    pub(super) const fn scope(&self) -> Option<oxc_semantic::ScopeId> {
        match self {
            Self::Function(function) | Self::Method { function, .. } => function.scope_id.get(),
            Self::Arrow(arrow) => arrow.scope_id.get(),
        }
    }

    pub(super) const fn is_arrow(&self) -> bool {
        matches!(self, Self::Arrow(_))
    }

    pub(super) const fn span(&self) -> Span {
        match self {
            Self::Function(function) | Self::Method { function, .. } => function.span,
            Self::Arrow(arrow) => arrow.span,
        }
    }
}

pub(super) fn collect<'a>(semantic: &Semantic<'a>, helpers: &HelperBindings) -> Vec<Candidate<'a>> {
    let mut candidates: Vec<Candidate<'a>> = Vec::new();
    for node in semantic.nodes().iter() {
        let outer: Outer<'a> = match node.kind() {
            AstKind::Function(function) => {
                if function.r#async || function.generator {
                    continue;
                }
                match semantic.nodes().parent_kind(node.id()) {
                    Some(AstKind::MethodDefinition(method)) => {
                        if method.kind != MethodDefinitionKind::Method || method.computed {
                            continue;
                        }
                        Outer::Method {
                            key: &method.key,
                            function,
                        }
                    }
                    Some(AstKind::ObjectProperty(property)) if property.method => {
                        if property.kind != PropertyKind::Init || property.computed {
                            continue;
                        }
                        Outer::Method {
                            key: &property.key,
                            function,
                        }
                    }
                    _ => Outer::Function(function),
                }
            }
            AstKind::ArrowFunctionExpression(arrow) => {
                if arrow.r#async {
                    continue;
                }
                Outer::Arrow(arrow)
            }
            _ => continue,
        };
        if let Some(candidate) = candidate(outer, semantic, helpers) {
            candidates.push(candidate);
        }
    }
    candidates
}

fn candidate<'a>(
    outer: Outer<'a>,
    semantic: &Semantic<'a>,
    helpers: &HelperBindings,
) -> Option<Candidate<'a>> {
    let body: &'a FunctionBody<'a> = outer.body()?;
    let (last, prologue): (&'a Statement<'a>, &'a [Statement<'a>]) =
        body.statements.split_last()?;
    let call_expression: &'a Expression<'a> = match (outer, last) {
        (Outer::Arrow(arrow), Statement::ExpressionStatement(statement)) if arrow.expression => {
            &statement.expression
        }
        (_, Statement::ReturnStatement(ret)) => ret.argument.as_ref()?,
        _ => return None,
    };
    let Expression::CallExpression(call) = call_expression else {
        return None;
    };
    if call.optional {
        return None;
    }
    let awaiter: HelperUse = helpers.callee_use(&call.callee, semantic)?;
    if awaiter.role != HelperRole::Awaiter {
        return None;
    }
    let span: Span = match outer {
        Outer::Method { key, function } => Span::new(key.span().start, function.span.end),
        Outer::Function(function) => function.span,
        Outer::Arrow(arrow) => arrow.span,
    };
    Some(Candidate {
        span,
        outer,
        prologue,
        call,
        awaiter,
    })
}

pub(super) fn awaiter_call<'a>(
    call: &'a CallExpression<'a>,
    semantic: &Semantic<'a>,
) -> Result<AwaiterCall<'a>, Refusal> {
    let [this_arg, arguments_arg, promise_arg, body_arg] = call.arguments.as_slice() else {
        return Err(Refusal::AwaiterArguments);
    };
    let this_arg: ThisArg = match this_arg {
        Argument::ThisExpression(_) => ThisArg::This,
        Argument::Identifier(reference) => ThisArg::Captured(resolved_symbol(reference, semantic)),
        _ => return Err(Refusal::AwaiterArguments),
    };
    let forwards_arguments: bool = match arguments_arg {
        Argument::Identifier(reference)
            if reference.name == "arguments" && resolved_symbol(reference, semantic).is_none() =>
        {
            true
        }
        other => {
            if !is_undefined_argument(other, semantic) {
                return Err(Refusal::AwaiterArguments);
            }
            false
        }
    };
    if !is_undefined_argument(promise_arg, semantic) {
        return Err(Refusal::PromiseConstructorArgument);
    }
    let body: &'a Function<'a> = match body_arg {
        Argument::FunctionExpression(function) => function,
        _ => return Err(Refusal::AwaiterArguments),
    };
    if body.r#async || body.id.is_some() {
        return Err(Refusal::AwaiterArguments);
    }
    Ok(AwaiterCall {
        this_arg,
        forwards_arguments,
        body,
    })
}

fn is_undefined_argument(argument: &Argument<'_>, semantic: &Semantic<'_>) -> bool {
    match argument {
        Argument::Identifier(reference) => {
            reference.name == "undefined" && resolved_symbol(reference, semantic).is_none()
        }
        other => other.as_expression().is_some_and(is_void_zero),
    }
}
