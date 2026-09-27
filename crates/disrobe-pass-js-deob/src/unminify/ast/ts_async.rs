mod candidate;
mod canon;
mod emit;
mod generator;
mod helpers;
mod machine;
mod order;
mod probe;
mod render;
mod structure;

use std::collections::BTreeSet;

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    AssignmentTarget, BindingPatternKind, Expression, ForStatementInit, FormalParameters,
    FunctionType, LabelIdentifier, Program, PropertyKey, SimpleAssignmentTarget, Statement,
    StringLiteral, UpdateExpression, VariableDeclaration,
};
use oxc_ast::{AstKind, Visit};
use oxc_parser::Parser;
use oxc_semantic::{ReferenceId, ScopeId, Semantic, SemanticBuilder, SymbolId};
use oxc_span::{GetSpan, SourceType, Span};

use super::{Edit, RuleOutcome};
use candidate::{AwaiterCall, Candidate, Outer, ThisArg};
use emit::{Labels, Out, Raw};
use helpers::{DirectHelper, HelperBindings};
use render::{Code, Renderer, Replacement};

const MAX_CANDIDATES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refusal {
    AwaiterArguments,
    PromiseConstructorArgument,
    OuterPrologue,
    ParameterShape,
    NameClash,
    ThisMismatch,
    ArgumentsUse,
    SuperOrMetaProperty,
    DynamicScope,
    GeneratorShape,
    DelegatedOrEmptyYield,
    MachineShape,
    UnknownInstruction,
    MisplacedInstruction,
    ImplicitFallThrough,
    StateMisuse,
    RegionShape,
    UnresolvedTransfer,
    IrreducibleFlow,
    SentPlacement,
    SentPrefixEffect,
    UnfoldedSpill,
    CatchBinding,
    TooLarge,
    TooDeep,
    OverlappingRewrite,
    Reparse,
}

impl Refusal {
    const fn reason(self) -> &'static str {
        match self {
            Self::AwaiterArguments => "awaiter-arguments",
            Self::PromiseConstructorArgument => "custom-promise-constructor",
            Self::OuterPrologue => "outer-prologue",
            Self::ParameterShape => "parameter-shape",
            Self::NameClash => "name-clash",
            Self::ThisMismatch => "this-mismatch",
            Self::ArgumentsUse => "arguments-use",
            Self::SuperOrMetaProperty => "super-or-meta-property",
            Self::DynamicScope => "dynamic-scope",
            Self::GeneratorShape => "generator-shape",
            Self::DelegatedOrEmptyYield => "delegated-or-empty-yield",
            Self::MachineShape => "state-machine-shape",
            Self::UnknownInstruction => "unknown-instruction",
            Self::MisplacedInstruction => "misplaced-instruction",
            Self::ImplicitFallThrough => "implicit-fall-through",
            Self::StateMisuse => "state-misuse",
            Self::RegionShape => "exception-region-shape",
            Self::UnresolvedTransfer => "unresolved-transfer",
            Self::IrreducibleFlow => "irreducible-flow",
            Self::SentPlacement => "sent-placement",
            Self::SentPrefixEffect => "sent-prefix-effect",
            Self::UnfoldedSpill => "unfolded-spill",
            Self::CatchBinding => "catch-binding",
            Self::TooLarge => "too-large",
            Self::TooDeep => "too-deep",
            Self::OverlappingRewrite => "overlapping-rewrite",
            Self::Reparse => "reparse",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct TsAsyncStats {
    pub(super) functions_restored: usize,
    pub(super) state_machines_restored: usize,
    pub(super) helpers_removed: usize,
}

struct Recovered {
    span: Span,
    text: String,
    consumed: Vec<Span>,
    state_machine: bool,
}

fn may_hold_helpers(source: &str) -> bool {
    source.contains("__awaiter")
        || (source.contains(".apply(") && source.contains(".next(") && source.contains("Promise"))
}

fn is_module(program: &Program<'_>) -> bool {
    program.body.iter().any(|statement: &Statement<'_>| {
        statement.is_module_declaration()
            || matches!(statement, Statement::ExpressionStatement(expression)
                if helpers::is_esmodule_marker(&expression.expression)
                    || matches!(&expression.expression, Expression::SequenceExpression(sequence)
                        if sequence.expressions.iter().any(helpers::is_esmodule_marker)))
    })
}

pub(super) fn recover(source: &str) -> (RuleOutcome, TsAsyncStats) {
    if !may_hold_helpers(source) {
        return (RuleOutcome::empty(), TsAsyncStats::default());
    }
    let allocator: Allocator = Allocator::default();
    let Ok(source_type) = SourceType::from_path("input.js") else {
        return (RuleOutcome::empty(), TsAsyncStats::default());
    };
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), TsAsyncStats::default());
    }
    let semantic: Semantic<'_> = SemanticBuilder::new().build(&parsed.program).semantic;
    let helpers: HelperBindings = HelperBindings::discover(&parsed.program, &semantic);
    if helpers.is_empty() {
        return (RuleOutcome::empty(), TsAsyncStats::default());
    }
    if promise_rebound(&parsed.program) {
        crate::debug::dbg_kv("ts-async-refused", || "promise-rebound".to_owned());
        return (RuleOutcome::empty(), TsAsyncStats::default());
    }
    let mut candidates: Vec<Candidate<'_>> = candidate::collect(&semantic, &helpers);
    if candidates.len() > MAX_CANDIDATES {
        crate::debug::dbg_kv("ts-async-refused", || Refusal::TooLarge.reason().to_owned());
        return (RuleOutcome::empty(), TsAsyncStats::default());
    }
    candidates.sort_by_key(|candidate: &Candidate<'_>| {
        (
            candidate.span.end - candidate.span.start,
            candidate.span.start,
        )
    });
    let reserved: BTreeSet<String> = label_names(&parsed.program);
    let functions: Vec<Span> = function_spans(&semantic);
    let mut renderer: Renderer<'_> = Renderer::new(source);
    let mut recovered: Vec<Recovered> = Vec::new();
    for candidate in &candidates {
        let checkpoint: render::Checkpoint = renderer.checkpoint();
        let outcome: Result<Recovered, Refusal> = recover_candidate(
            candidate,
            &semantic,
            &helpers,
            &mut renderer,
            &reserved,
            &functions,
        )
        .and_then(|site: Recovered| {
            renderer.insert(site.span, Replacement::Code(Code::text(&site.text)))?;
            Ok(site)
        });
        match outcome {
            Ok(site) => recovered.push(site),
            Err(refusal) => {
                renderer.rollback(checkpoint);
                crate::debug::dbg_kv("ts-async-refused", || {
                    format!("{} at {}", refusal.reason(), candidate.span.start)
                });
            }
        }
    }
    if recovered.is_empty() {
        return (RuleOutcome::empty(), TsAsyncStats::default());
    }
    let module: bool = is_module(&parsed.program);
    finish(source, &recovered, &helpers, &semantic, module)
}

fn line_end_after(source: &str, end: u32) -> usize {
    let start: usize = end as usize;
    let rest: &str = source.get(start..).unwrap_or("");
    let blank: usize = rest
        .find(|character: char| character != ' ' && character != '\t' && character != '\r')
        .unwrap_or(rest.len());
    if rest[blank..].starts_with('\n') {
        start + blank + 1
    } else {
        start
    }
}

fn finish(
    source: &str,
    recovered: &[Recovered],
    helpers: &HelperBindings,
    semantic: &Semantic<'_>,
    module: bool,
) -> (RuleOutcome, TsAsyncStats) {
    let mut stats: TsAsyncStats = TsAsyncStats {
        functions_restored: recovered.len(),
        state_machines_restored: recovered
            .iter()
            .filter(|site: &&Recovered| site.state_machine)
            .count(),
        helpers_removed: 0,
    };
    let mut edits: Vec<Edit> = Vec::new();
    let mut outermost: Vec<&Recovered> = recovered.iter().collect();
    outermost.sort_by_key(|site: &&Recovered| (site.span.start, u32::MAX - site.span.end));
    let mut covered_until: u32 = 0;
    for site in outermost {
        if site.span.start < covered_until {
            continue;
        }
        covered_until = site.span.end;
        edits.push(Edit {
            start: site.span.start as usize,
            end: site.span.end as usize,
            replacement: site.text.clone(),
        });
    }
    let consumed: BTreeSet<(u32, u32)> = recovered
        .iter()
        .flat_map(|site: &Recovered| site.consumed.iter())
        .map(|span: &Span| (span.start, span.end))
        .collect();
    for (symbol, helper) in &helpers.direct {
        let global: bool =
            semantic.symbols().get_scope_id(*symbol) == semantic.scopes().root_scope_id();
        if global && !module {
            continue;
        }
        let Some(removable) = helper_removal(*symbol, helper, &consumed, semantic) else {
            continue;
        };
        edits.push(Edit {
            start: removable.start as usize,
            end: line_end_after(source, removable.end),
            replacement: String::new(),
        });
        stats.helpers_removed += 1;
    }
    (RuleOutcome { edits }, stats)
}

fn helper_removal(
    symbol: SymbolId,
    helper: &DirectHelper,
    consumed: &BTreeSet<(u32, u32)>,
    semantic: &Semantic<'_>,
) -> Option<Span> {
    let removable: Span = helper.removable?;
    let references: &Vec<ReferenceId> = semantic.symbols().get_resolved_reference_ids(symbol);
    let all_consumed: bool = references.iter().all(|reference_id: &ReferenceId| {
        let node_id: oxc_semantic::NodeId =
            semantic.symbols().get_reference(*reference_id).node_id();
        let span: Span = semantic.nodes().get_node(node_id).kind().span();
        consumed.contains(&(span.start, span.end))
    });
    all_consumed.then_some(removable)
}

fn functions_inside(functions: &[Span], outer: Span) -> Vec<Span> {
    let first: usize = functions.partition_point(|span: &Span| span.start < outer.start);
    functions[first..]
        .iter()
        .take_while(|span: &&Span| span.start < outer.end)
        .filter(|span: &&Span| **span != outer && span.end <= outer.end)
        .copied()
        .collect()
}

fn function_spans(semantic: &Semantic<'_>) -> Vec<Span> {
    let mut spans: Vec<Span> = semantic
        .nodes()
        .iter()
        .filter_map(|node| match node.kind() {
            AstKind::Function(function) => Some(function.span),
            AstKind::ArrowFunctionExpression(arrow) => Some(arrow.span),
            _ => None,
        })
        .collect();
    spans.sort_by_key(|span: &Span| (span.start, span.end));
    spans
}

fn recover_candidate<'a>(
    candidate: &Candidate<'a>,
    semantic: &Semantic<'a>,
    helpers: &HelperBindings,
    renderer: &mut Renderer<'_>,
    reserved: &BTreeSet<String>,
    functions: &[Span],
) -> Result<Recovered, Refusal> {
    let call: AwaiterCall<'a> = candidate::awaiter_call(candidate.call, semantic)?;
    if probe::uses_dynamic_scope(candidate.outer, semantic) {
        return Err(Refusal::DynamicScope);
    }
    let prologue: Vec<Out> = outer_prologue(candidate.prologue, renderer)?;
    let mut labels: Labels = Labels::default();
    let mut consumed: Vec<Span> = vec![candidate.awaiter.reference];
    let (params, mut body, state_machine, uses_this): (Vec<Code>, Vec<Out>, bool, bool) =
        if call.body.generator {
            let params: Vec<Code> =
                merged_params(candidate, &call, &call.body.params, renderer, semantic)?;
            let (body, uses_this): (Vec<Out>, bool) =
                generator::recover(&call, semantic, renderer, candidate.outer.is_arrow())?;
            (params, body, false, uses_this)
        } else {
            let outer_scope: ScopeId = candidate.outer.scope().ok_or(Refusal::NameClash)?;
            let recovery: machine::MachineRecovery = machine::recover(
                &call,
                semantic,
                helpers,
                renderer,
                &mut labels,
                outer_scope,
                &functions_inside(functions, candidate.outer.span()),
            )?;
            consumed.push(recovery.generator_reference);
            let params: Vec<Code> = match recovery.params {
                Some((params, expected)) => {
                    check_forwarded_params(candidate, &call, semantic)?;
                    if expected != candidate.outer.params().items.len() {
                        return Err(Refusal::ParameterShape);
                    }
                    params
                }
                None => merged_params(candidate, &call, &call.body.params, renderer, semantic)?,
            };
            (params, recovery.body, true, recovery.uses_this)
        };
    let arrow_form: bool = match call.this_arg {
        ThisArg::This => false,
        ThisArg::Captured(Some(symbol))
            if captured_this_is_lexical(symbol, candidate, semantic) =>
        {
            true
        }
        ThisArg::Captured(_) if !uses_this => false,
        ThisArg::Captured(_) => return Err(Refusal::ThisMismatch),
    };
    check_name_clashes(candidate, &call, semantic)?;
    let mut full_body: Vec<Out> = prologue;
    full_body.append(&mut body);
    emit::simplify(&mut full_body);
    let text: String = assemble(
        candidate, arrow_form, &params, &full_body, renderer, reserved, &labels,
    )?;
    Ok(Recovered {
        span: candidate.span,
        text,
        consumed,
        state_machine,
    })
}

fn assemble(
    candidate: &Candidate<'_>,
    arrow_form: bool,
    params: &[Code],
    body: &[Out],
    renderer: &Renderer<'_>,
    reserved: &BTreeSet<String>,
    labels: &Labels,
) -> Result<String, Refusal> {
    let source: &str = renderer.source();
    let base_indent: String = line_indent(source, candidate.span.start);
    let mut parameter_text: String = String::new();
    for (index, param) in params.iter().enumerate() {
        if index > 0 {
            parameter_text.push_str(", ");
        }
        parameter_text.push_str(param.plain_text().ok_or(Refusal::OverlappingRewrite)?);
    }
    let header: String = match candidate.outer {
        Outer::Function(_) if arrow_form => format!("async ({parameter_text}) =>"),
        Outer::Function(function) => function.id.as_ref().map_or_else(
            || format!("async function ({parameter_text})"),
            |id| format!("async function {}({parameter_text})", id.name),
        ),
        Outer::Method { key, .. } => {
            let key_text: &str = renderer.slice(key.span().start, key.span().end)?;
            format!("async {key_text}({parameter_text})")
        }
        Outer::Arrow(_) => format!("async ({parameter_text}) =>"),
    };
    let body_text: String = emit::print(body, &base_indent, reserved, labels);
    let text: String = format!("{header} {{\n{body_text}{base_indent}}}");
    validate(candidate.outer, &text)?;
    Ok(text)
}

fn validate(outer: Outer<'_>, text: &str) -> Result<(), Refusal> {
    let wrapped: String = match outer {
        Outer::Function(_) | Outer::Arrow(_) => format!("({text});"),
        Outer::Method { .. } => format!("({{{text}}});"),
    };
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType =
        SourceType::from_path("input.js").map_err(|_| Refusal::Reparse)?;
    let parsed: oxc_parser::ParserReturn<'_> =
        Parser::new(&allocator, &wrapped, source_type).parse();
    if parsed.errors.is_empty() && !parsed.panicked {
        Ok(())
    } else {
        Err(Refusal::Reparse)
    }
}

fn captured_this_is_lexical(
    symbol: SymbolId,
    candidate: &Candidate<'_>,
    semantic: &Semantic<'_>,
) -> bool {
    let Outer::Function(function) = candidate.outer else {
        return false;
    };
    if function.r#type != FunctionType::FunctionExpression
        || function.id.is_some()
        || !candidate.prologue.is_empty()
    {
        return false;
    }
    let symbols: &oxc_semantic::SymbolTable = semantic.symbols();
    if symbols.symbol_is_mutated(symbol) || !symbols.get_redeclarations(symbol).is_empty() {
        return false;
    }
    let declaration: oxc_semantic::NodeId = symbols.get_declaration(symbol);
    let AstKind::VariableDeclarator(declarator) = semantic.nodes().kind(declaration) else {
        return false;
    };
    if !matches!(declarator.init, Some(Expression::ThisExpression(_))) {
        return false;
    }
    let Some(statement) = semantic.nodes().parent_id(declaration) else {
        return false;
    };
    if !matches!(
        semantic.nodes().parent_kind(statement),
        Some(AstKind::FunctionBody(_) | AstKind::Program(_))
    ) {
        return false;
    }
    if symbols.get_span(symbol).end > candidate.span.start {
        return false;
    }
    let Some(own_scope) = function.scope_id.get() else {
        return false;
    };
    let mut scope: Option<ScopeId> = semantic.scopes().get_parent_id(own_scope);
    while let Some(current) = scope {
        let flags: oxc_semantic::ScopeFlags = semantic.scopes().get_flags(current);
        if flags.is_top() || (flags.is_function() && !flags.is_arrow()) {
            break;
        }
        scope = semantic.scopes().get_parent_id(current);
    }
    scope == Some(symbols.get_scope_id(symbol))
}

fn line_indent(source: &str, offset: u32) -> String {
    let before: &str = source.get(..offset as usize).unwrap_or("");
    let line_start: usize = before.rfind('\n').map_or(0, |index: usize| index + 1);
    before
        .get(line_start..)
        .unwrap_or("")
        .chars()
        .take_while(|character: &char| *character == ' ' || *character == '\t')
        .collect()
}

fn raw_statement(statement: &Statement<'_>, renderer: &Renderer<'_>) -> Result<Out, Refusal> {
    let span: Span = statement.span();
    let code: Code = renderer.render(span)?;
    let source: &str = renderer.source();
    let text: &str = renderer.slice(span.start, span.end)?;
    let before: &str = source.get(..span.start as usize).unwrap_or("");
    let line_start: usize = before.rfind('\n').map_or(0, |index: usize| index + 1);
    let prefix: &str = before.get(line_start..).unwrap_or("");
    let reindentable: bool = prefix.chars().all(|c: char| c == ' ' || c == '\t')
        && !text.contains('`')
        && !text.contains("\\\n")
        && !text.contains("\\\r");
    Ok(Out::Raw(Raw {
        code,
        indent: reindentable.then(|| prefix.to_owned()),
    }))
}

fn outer_prologue(
    statements: &[Statement<'_>],
    renderer: &Renderer<'_>,
) -> Result<Vec<Out>, Refusal> {
    let mut outs: Vec<Out> = Vec::with_capacity(statements.len());
    let mut index: usize = 0;
    while index < statements.len() {
        let statement: &Statement<'_> = &statements[index];
        if is_captured_this_or_arguments(statement) {
            outs.push(raw_statement(statement, renderer)?);
            index += 1;
            continue;
        }
        if let Some(next) = statements.get(index + 1)
            && is_rest_copy(statement, next)
        {
            outs.push(raw_statement(statement, renderer)?);
            outs.push(raw_statement(next, renderer)?);
            index += 2;
            continue;
        }
        return Err(Refusal::OuterPrologue);
    }
    Ok(outs)
}

fn single_declarator<'b, 'a>(
    statement: &'b Statement<'a>,
) -> Option<(&'b str, Option<&'b Expression<'a>>)> {
    let Statement::VariableDeclaration(declaration) = statement else {
        return None;
    };
    single_var(declaration)
}

fn single_var<'b, 'a>(
    declaration: &'b VariableDeclaration<'a>,
) -> Option<(&'b str, Option<&'b Expression<'a>>)> {
    let [declarator] = declaration.declarations.as_slice() else {
        return None;
    };
    let BindingPatternKind::BindingIdentifier(binding) = &declarator.id.kind else {
        return None;
    };
    Some((binding.name.as_str(), declarator.init.as_ref()))
}

fn is_captured_this_or_arguments(statement: &Statement<'_>) -> bool {
    matches!(
        single_declarator(statement),
        Some((_, Some(Expression::ThisExpression(_))))
    ) || matches!(
        single_declarator(statement),
        Some((_, Some(Expression::Identifier(reference)))) if reference.name == "arguments"
    )
}

fn is_rest_copy(declaration: &Statement<'_>, copy: &Statement<'_>) -> bool {
    let Some((rest_name, Some(Expression::ArrayExpression(array)))) =
        single_declarator(declaration)
    else {
        return false;
    };
    if !array.elements.is_empty() {
        return false;
    }
    let Statement::ForStatement(for_statement) = copy else {
        return false;
    };
    let Some(ForStatementInit::VariableDeclaration(init)) = &for_statement.init else {
        return false;
    };
    let Some((index_name, Some(Expression::NumericLiteral(start)))) = single_var(init) else {
        return false;
    };
    let Some(Expression::BinaryExpression(test)) = &for_statement.test else {
        return false;
    };
    let test_ok: bool = test.operator == oxc_ast::ast::BinaryOperator::LessThan
        && matches!(&test.left, Expression::Identifier(left) if left.name == index_name)
        && matches!(&test.right, Expression::StaticMemberExpression(member)
            if member.property.name == "length"
                && matches!(&member.object, Expression::Identifier(object) if object.name == "arguments"));
    let update_ok: bool = matches!(&for_statement.update, Some(Expression::UpdateExpression(update))
        if is_increment_of(update, index_name));
    let body_ok: bool = rest_copy_body(&for_statement.body, rest_name, index_name, start.value);
    test_ok && update_ok && body_ok
}

fn is_increment_of(update: &UpdateExpression<'_>, name: &str) -> bool {
    update.operator == oxc_ast::ast::UpdateOperator::Increment
        && matches!(&update.argument, SimpleAssignmentTarget::AssignmentTargetIdentifier(target) if target.name == name)
}

fn rest_copy_body(body: &Statement<'_>, rest_name: &str, index_name: &str, start: f64) -> bool {
    let Statement::BlockStatement(block) = body else {
        return false;
    };
    let [Statement::ExpressionStatement(statement)] = block.body.as_slice() else {
        return false;
    };
    let Expression::AssignmentExpression(assignment) = &statement.expression else {
        return false;
    };
    let AssignmentTarget::ComputedMemberExpression(target) = &assignment.left else {
        return false;
    };
    let target_ok: bool = matches!(&target.object, Expression::Identifier(object) if object.name == rest_name)
        && match &target.expression {
            Expression::BinaryExpression(offset) => {
                offset.operator == oxc_ast::ast::BinaryOperator::Subtraction
                    && matches!(&offset.left, Expression::Identifier(left) if left.name == index_name)
                    && matches!(&offset.right, Expression::NumericLiteral(right) if right.value.to_bits() == start.to_bits())
            }
            Expression::Identifier(index) => index.name == index_name && start.to_bits() == 0,
            _ => false,
        };
    let Expression::ComputedMemberExpression(source) = &assignment.right else {
        return false;
    };
    let source_ok: bool = matches!(&source.object, Expression::Identifier(object) if object.name == "arguments")
        && matches!(&source.expression, Expression::Identifier(index) if index.name == index_name);
    target_ok && source_ok
}

fn expected_argument_count(params: &FormalParameters<'_>) -> usize {
    params
        .items
        .iter()
        .take_while(|param| !matches!(param.pattern.kind, BindingPatternKind::AssignmentPattern(_)))
        .count()
}

fn check_forwarded_params(
    candidate: &Candidate<'_>,
    call: &AwaiterCall<'_>,
    semantic: &Semantic<'_>,
) -> Result<(), Refusal> {
    let outer: &FormalParameters<'_> = candidate.outer.params();
    if !call.forwards_arguments || outer.rest.is_some() {
        return Err(Refusal::ParameterShape);
    }
    for param in &outer.items {
        let BindingPatternKind::BindingIdentifier(binding) = &param.pattern.kind else {
            return Err(Refusal::ParameterShape);
        };
        let symbol: SymbolId = binding.symbol_id.get().ok_or(Refusal::ParameterShape)?;
        if !semantic
            .symbols()
            .get_resolved_reference_ids(symbol)
            .is_empty()
        {
            return Err(Refusal::ParameterShape);
        }
    }
    Ok(())
}

fn merged_params(
    candidate: &Candidate<'_>,
    call: &AwaiterCall<'_>,
    inner: &FormalParameters<'_>,
    renderer: &Renderer<'_>,
    semantic: &Semantic<'_>,
) -> Result<Vec<Code>, Refusal> {
    let inner_has_params: bool = !inner.items.is_empty() || inner.rest.is_some();
    if !inner_has_params {
        return render_params(candidate.outer.params(), renderer);
    }
    check_forwarded_params(candidate, call, semantic)?;
    if expected_argument_count(inner) != candidate.outer.params().items.len() {
        return Err(Refusal::ParameterShape);
    }
    render_params(inner, renderer)
}

fn render_params(
    params: &FormalParameters<'_>,
    renderer: &Renderer<'_>,
) -> Result<Vec<Code>, Refusal> {
    let mut codes: Vec<Code> = params
        .items
        .iter()
        .map(|param| renderer.render(param.span))
        .collect::<Result<Vec<Code>, Refusal>>()?;
    if let Some(rest) = &params.rest {
        codes.push(renderer.render(rest.span)?);
    }
    Ok(codes)
}

fn scope_names(scope: ScopeId, semantic: &Semantic<'_>) -> BTreeSet<String> {
    semantic
        .scopes()
        .iter_bindings_in(scope)
        .map(|symbol: SymbolId| semantic.symbols().get_name(symbol).to_owned())
        .collect()
}

fn check_name_clashes(
    candidate: &Candidate<'_>,
    call: &AwaiterCall<'_>,
    semantic: &Semantic<'_>,
) -> Result<(), Refusal> {
    let outer_scope: ScopeId = candidate.outer.scope().ok_or(Refusal::NameClash)?;
    let inner_scope: ScopeId = call.body.scope_id.get().ok_or(Refusal::NameClash)?;
    let inner_has_params: bool =
        !call.body.params.items.is_empty() || call.body.params.rest.is_some();
    let dropped: BTreeSet<String> = if inner_has_params {
        candidate
            .outer
            .params()
            .items
            .iter()
            .filter_map(|param| match &param.pattern.kind {
                BindingPatternKind::BindingIdentifier(binding) => Some(binding.name.to_string()),
                _ => None,
            })
            .collect()
    } else {
        BTreeSet::new()
    };
    let outer_names: BTreeSet<String> = scope_names(outer_scope, semantic)
        .into_iter()
        .filter(|name: &String| !dropped.contains(name))
        .collect();
    let inner_names: BTreeSet<String> = scope_names(inner_scope, semantic);
    if outer_names.is_disjoint(&inner_names) {
        Ok(())
    } else {
        Err(Refusal::NameClash)
    }
}

fn label_names(program: &Program<'_>) -> BTreeSet<String> {
    struct LabelCollector {
        names: BTreeSet<String>,
    }
    impl<'a> Visit<'a> for LabelCollector {
        fn visit_label_identifier(&mut self, label: &LabelIdentifier<'a>) {
            self.names.insert(label.name.to_string());
        }
    }
    let mut collector: LabelCollector = LabelCollector {
        names: BTreeSet::new(),
    };
    collector.visit_program(program);
    collector.names
}

fn promise_rebound(program: &Program<'_>) -> bool {
    struct PromiseProbe {
        rebound: bool,
    }
    impl<'a> Visit<'a> for PromiseProbe {
        fn enter_node(&mut self, kind: AstKind<'a>) {
            match kind {
                AstKind::BindingIdentifier(binding) if binding.name == "Promise" => {
                    self.rebound = true;
                }
                AstKind::SimpleAssignmentTarget(target) => {
                    let named_promise: bool = match target {
                        SimpleAssignmentTarget::AssignmentTargetIdentifier(reference) => {
                            reference.name == "Promise"
                        }
                        SimpleAssignmentTarget::StaticMemberExpression(member) => {
                            member.property.name == "Promise"
                        }
                        _ => false,
                    };
                    self.rebound |= named_promise;
                }
                AstKind::ObjectProperty(property) => {
                    self.rebound |= matches!(&property.key, PropertyKey::StaticIdentifier(key) if key.name == "Promise");
                }
                AstKind::WithStatement(_) => self.rebound = true,
                _ => {}
            }
        }

        fn visit_string_literal(&mut self, literal: &StringLiteral<'a>) {
            if literal.value == "Promise" {
                self.rebound = true;
            }
        }
    }
    let mut probe: PromiseProbe = PromiseProbe { rebound: false };
    probe.visit_program(program);
    probe.rebound
}
