use oxc_ast::Visit;
use oxc_ast::ast::{Function, FunctionBody};
use oxc_semantic::Semantic;

use super::candidate::AwaiterCall;
use super::emit::Out;
use super::probe::{Usage, UsageProbe, YieldSite};
use super::render::{Renderer, Replacement, Wrap};
use super::{Refusal, raw_statement};

pub(super) fn recover<'a>(
    call: &AwaiterCall<'a>,
    semantic: &Semantic<'a>,
    renderer: &mut Renderer<'_>,
    outer_is_arrow: bool,
) -> Result<(Vec<Out>, bool), Refusal> {
    let generator: &'a Function<'a> = call.body;
    let body: &'a FunctionBody<'a> = generator.body.as_deref().ok_or(Refusal::GeneratorShape)?;
    if !body.directives.is_empty() {
        return Err(Refusal::GeneratorShape);
    }
    let mut probe: UsageProbe<'_, 'a> = UsageProbe::new(semantic);
    probe.visit_function_body(body);
    let usage: Usage = probe.finish();
    if usage.super_or_meta {
        return Err(Refusal::SuperOrMetaProperty);
    }
    let has_params: bool = !generator.params.items.is_empty() || generator.params.rest.is_some();
    if usage.arguments && (outer_is_arrow || (!call.forwards_arguments && !has_params)) {
        return Err(Refusal::ArgumentsUse);
    }
    for site in &usage.yields {
        register_yield(site, renderer)?;
    }
    let outs: Vec<Out> = body
        .statements
        .iter()
        .map(|statement| raw_statement(statement, renderer))
        .collect::<Result<Vec<Out>, Refusal>>()?;
    Ok((outs, usage.this))
}

fn register_yield(site: &YieldSite, renderer: &mut Renderer<'_>) -> Result<(), Refusal> {
    let Some(operand) = site.argument else {
        return Err(Refusal::DelegatedOrEmptyYield);
    };
    if site.delegate {
        return Err(Refusal::DelegatedOrEmptyYield);
    }
    renderer.insert(
        site.span,
        Replacement::Await {
            operand,
            operand_wrap: site.argument_wrap,
            outer_wrap: Wrap::Bare,
        },
    )
}
