use indexmap::{IndexMap, IndexSet};
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, ArrayExpression, BinaryOperator, BindingPatternKind, CallExpression, Expression,
    FormalParameters, Function, FunctionBody, LogicalOperator, Statement, UnaryOperator,
};
use oxc_ast::{AstKind, Visit};
use oxc_parser::Parser;
use oxc_semantic::{
    AstNodes, ReferenceId, ScopeId, ScopeTree, Semantic, SemanticBuilder, SymbolId, SymbolTable,
};
use oxc_span::SourceType;

use super::import_rename::push_reference_edits;
use super::rename_scope::{RenameSafety, collect_reserved_names};
use super::require_alias::{derive_module_names, is_minified_local};
use super::{Edit, RuleOutcome, edit_overlaps_comments};

#[derive(Debug, Clone, Default)]
pub(super) struct AmdParamStats {
    pub(super) parameters_renamed: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, AmdParamStats) {
    let allocator: Allocator = Allocator::default();
    let Ok(source_type): Result<SourceType, _> = SourceType::from_path("input.js") else {
        return (RuleOutcome::empty(), AmdParamStats::default());
    };
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), AmdParamStats::default());
    }

    let semantic_ret: oxc_semantic::SemanticBuilderReturn<'_> = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .with_scope_tree_child_ids(true)
        .build(&parsed.program);
    if !semantic_ret.errors.is_empty() {
        return (RuleOutcome::empty(), AmdParamStats::default());
    }
    let semantic: Semantic<'_> = semantic_ret.semantic;
    let symbols: &SymbolTable = semantic.symbols();
    let scopes: &ScopeTree = semantic.scopes();
    let nodes: &AstNodes<'_> = semantic.nodes();
    let safety: RenameSafety<'_> = RenameSafety {
        symbols,
        scopes,
        nodes,
    };
    let mut reserved: IndexSet<String> = collect_reserved_names(&semantic);
    let mut next_suffixes: IndexMap<String, u32> = IndexMap::new();
    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: AmdParamStats = AmdParamStats::default();

    for node in nodes.iter() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        let Some(factory): Option<AmdFactory<'_>> = amd_factory(call, symbols) else {
            continue;
        };
        for (parameter, dependency) in factory.parameters.items.iter().zip(&factory.dependencies) {
            let specifier: &str = dependency.as_str();
            if is_amd_runtime_dependency(specifier) || specifier.contains('!') {
                continue;
            }
            let BindingPatternKind::BindingIdentifier(binding) = &parameter.pattern.kind else {
                continue;
            };
            let local_name: &str = binding.name.as_str();
            if !is_minified_local(local_name) {
                continue;
            }
            let Some(symbol_id): Option<SymbolId> = binding.symbol_id.get() else {
                continue;
            };
            let Some(preferred): Option<String> = derive_module_names(specifier).into_iter().next()
            else {
                continue;
            };
            if preferred == local_name {
                continue;
            }
            let owner_scope: ScopeId = symbols.get_scope_id(symbol_id);
            let Some(new_name): Option<String> = choose_name(
                &safety,
                symbol_id,
                owner_scope,
                local_name,
                &preferred,
                &reserved,
                &mut next_suffixes,
            ) else {
                continue;
            };
            let mut candidate_edits: Vec<Edit> = vec![Edit {
                start: binding.span.start as usize,
                end: binding.span.end as usize,
                replacement: new_name.clone(),
            }];
            push_reference_edits(symbols, nodes, symbol_id, &new_name, &mut candidate_edits);
            if candidate_edits
                .iter()
                .any(|edit: &Edit| edit_overlaps_comments(edit, &parsed.program.comments))
            {
                continue;
            }
            reserved.insert(new_name);
            edits.extend(candidate_edits);
            stats.parameters_renamed += 1;
        }
    }

    if edits.is_empty() {
        return (RuleOutcome::empty(), AmdParamStats::default());
    }
    (RuleOutcome { edits }, stats)
}

struct AmdFactory<'a> {
    dependencies: Vec<String>,
    parameters: &'a FormalParameters<'a>,
}

fn amd_factory<'a>(call: &'a CallExpression<'a>, symbols: &SymbolTable) -> Option<AmdFactory<'a>> {
    direct_amd_factory(call, symbols).or_else(|| umd_factory(call, symbols))
}

fn direct_amd_factory<'a>(
    call: &'a CallExpression<'a>,
    symbols: &SymbolTable,
) -> Option<AmdFactory<'a>> {
    if call.optional || call.type_parameters.is_some() {
        return None;
    }
    let Expression::Identifier(callee) = &call.callee else {
        return None;
    };
    if callee.name.as_str() != "define" {
        return None;
    }
    let reference_id: ReferenceId = callee.reference_id.get()?;
    if symbols.get_reference(reference_id).symbol_id().is_some() {
        return None;
    }
    let (dependencies, factory): (&Argument<'_>, &Argument<'_>) = match call.arguments.as_slice() {
        [dependencies, factory] => (dependencies, factory),
        [Argument::StringLiteral(_module_id), dependencies, factory] => (dependencies, factory),
        _ => return None,
    };
    let Argument::ArrayExpression(dependencies) = dependencies else {
        return None;
    };
    let (parameters, _body): (&FormalParameters<'_>, &FunctionBody<'_>) =
        safe_factory_parts(factory)?;
    let dependencies: Vec<String> = static_dependencies(dependencies)?;
    Some(AmdFactory {
        dependencies,
        parameters,
    })
}

fn umd_factory<'a>(call: &'a CallExpression<'a>, symbols: &SymbolTable) -> Option<AmdFactory<'a>> {
    if call.optional || call.type_parameters.is_some() {
        return None;
    }
    let Expression::FunctionExpression(wrapper) = call.callee.get_inner_expression() else {
        return None;
    };
    if wrapper.r#async
        || wrapper.generator
        || wrapper.type_parameters.is_some()
        || wrapper.params.rest.is_some()
        || wrapper.params.items.len() != call.arguments.len()
        || call
            .arguments
            .iter()
            .any(|argument: &Argument<'_>| matches!(argument, Argument::SpreadElement(_)))
        || wrapper.params.items.iter().any(|parameter| {
            !matches!(
                parameter.pattern.kind,
                BindingPatternKind::BindingIdentifier(_)
            )
        })
    {
        return None;
    }
    let body: &FunctionBody<'_> = wrapper.body.as_ref()?;
    if body_has_dynamic_scope(body) {
        return None;
    }

    let registration: UmdRegistration = guarded_umd_registration(body, symbols)?;
    for (parameter, argument) in wrapper.params.items.iter().zip(&call.arguments) {
        let BindingPatternKind::BindingIdentifier(binding) = &parameter.pattern.kind else {
            return None;
        };
        let factory_symbol: SymbolId = binding.symbol_id.get()?;
        if factory_symbol != registration.factory_symbol {
            continue;
        }
        if symbols
            .get_resolved_reference_ids(factory_symbol)
            .iter()
            .any(|&reference_id: &ReferenceId| symbols.get_reference(reference_id).is_write())
        {
            return None;
        }
        let (factory_parameters, _factory_body): (&FormalParameters<'_>, &FunctionBody<'_>) =
            safe_factory_parts(argument)?;
        return Some(AmdFactory {
            dependencies: registration.dependencies,
            parameters: factory_parameters,
        });
    }
    None
}

fn safe_factory_parts<'a>(
    factory: &'a Argument<'a>,
) -> Option<(&'a FormalParameters<'a>, &'a FunctionBody<'a>)> {
    let (parameters, body): (&FormalParameters<'_>, &FunctionBody<'_>) = match factory {
        Argument::FunctionExpression(factory) => (&factory.params, factory.body.as_ref()?),
        Argument::ArrowFunctionExpression(factory) => (&factory.params, &factory.body),
        _ => return None,
    };
    if body_has_dynamic_scope(body)
        || parameters.rest.is_some()
        || parameters.items.iter().any(|parameter| {
            !matches!(
                parameter.pattern.kind,
                BindingPatternKind::BindingIdentifier(_)
            )
        })
    {
        return None;
    }
    Some((parameters, body))
}

fn static_dependencies(dependencies: &ArrayExpression<'_>) -> Option<Vec<String>> {
    dependencies
        .elements
        .iter()
        .map(|element| {
            let Some(Expression::StringLiteral(specifier)) = element.as_expression() else {
                return None;
            };
            Some(specifier.value.as_str().to_owned())
        })
        .collect()
}

struct UmdRegistration {
    factory_symbol: SymbolId,
    dependencies: Vec<String>,
}

fn guarded_umd_registration(
    body: &FunctionBody<'_>,
    symbols: &SymbolTable,
) -> Option<UmdRegistration> {
    let mut all_defines: DefineProbe<'_> = DefineProbe::new(symbols);
    for statement in &body.statements {
        all_defines.visit_statement(statement);
    }
    if all_defines.count != 1 {
        return None;
    }
    let registration: UmdRegistration = all_defines.registration?;
    let mut guarded_matches: usize = 0;
    for statement in &body.statements {
        let Statement::IfStatement(if_statement) = statement else {
            continue;
        };
        let Some(alternate): Option<&Statement<'_>> = if_statement.alternate.as_ref() else {
            continue;
        };
        if !is_amd_guard(&if_statement.test, symbols) {
            continue;
        }
        let mut branch_defines: DefineProbe<'_> = DefineProbe::new(symbols);
        branch_defines.visit_statement(&if_statement.consequent);
        if branch_defines.count != 1
            || !branch_defines.registration.as_ref().is_some_and(
                |branch_registration: &UmdRegistration| {
                    branch_registration.factory_symbol == registration.factory_symbol
                        && branch_registration.dependencies == registration.dependencies
                },
            )
        {
            continue;
        }
        let mut fallback_calls: FactoryCallProbe<'_> = FactoryCallProbe {
            factory_symbol: registration.factory_symbol,
            symbols,
            found: false,
        };
        fallback_calls.visit_statement(alternate);
        if fallback_calls.found {
            guarded_matches = guarded_matches.saturating_add(1);
        }
    }
    (guarded_matches == 1).then_some(registration)
}

struct DefineProbe<'s> {
    symbols: &'s SymbolTable,
    count: usize,
    registration: Option<UmdRegistration>,
}

impl<'s> DefineProbe<'s> {
    const fn new(symbols: &'s SymbolTable) -> Self {
        Self {
            symbols,
            count: 0,
            registration: None,
        }
    }
}

impl<'a> Visit<'a> for DefineProbe<'_> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if is_global_define_call(call, self.symbols) {
            self.count = self.count.saturating_add(1);
            if let Some((dependencies, symbol_id)) = amd_factory_reference(call, self.symbols)
                && let Some(static_dependencies) = static_dependencies(dependencies)
            {
                self.registration = Some(UmdRegistration {
                    factory_symbol: symbol_id,
                    dependencies: static_dependencies,
                });
            }
        }
        visit_call_children(self, call);
    }

    fn visit_function(&mut self, _function: &Function<'a>, _flags: oxc::syntax::scope::ScopeFlags) {
    }

    fn visit_arrow_function_expression(
        &mut self,
        _arrow: &oxc_ast::ast::ArrowFunctionExpression<'a>,
    ) {
    }
}

struct FactoryCallProbe<'s> {
    factory_symbol: SymbolId,
    symbols: &'s SymbolTable,
    found: bool,
}

impl<'a> Visit<'a> for FactoryCallProbe<'_> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if !call.optional
            && call.type_parameters.is_none()
            && let Expression::Identifier(callee) = &call.callee
            && let Some(reference_id) = callee.reference_id.get()
            && self.symbols.get_reference(reference_id).symbol_id() == Some(self.factory_symbol)
        {
            self.found = true;
            return;
        }
        visit_call_children(self, call);
    }

    fn visit_function(&mut self, _function: &Function<'a>, _flags: oxc::syntax::scope::ScopeFlags) {
    }

    fn visit_arrow_function_expression(
        &mut self,
        _arrow: &oxc_ast::ast::ArrowFunctionExpression<'a>,
    ) {
    }
}

fn visit_call_children<'a>(visitor: &mut impl Visit<'a>, call: &CallExpression<'a>) {
    visitor.visit_expression(&call.callee);
    for argument in &call.arguments {
        match argument {
            Argument::SpreadElement(spread) => visitor.visit_expression(&spread.argument),
            argument => {
                if let Some(expression) = argument.as_expression() {
                    visitor.visit_expression(expression);
                }
            }
        }
    }
}

fn is_global_define_call(call: &CallExpression<'_>, symbols: &SymbolTable) -> bool {
    if call.optional || call.type_parameters.is_some() {
        return false;
    }
    let Expression::Identifier(callee) = &call.callee else {
        return false;
    };
    unresolved_identifier_is(callee, "define", symbols)
}

fn amd_factory_reference<'a>(
    call: &'a CallExpression<'a>,
    symbols: &SymbolTable,
) -> Option<(&'a ArrayExpression<'a>, SymbolId)> {
    let (dependencies, factory): (&Argument<'_>, &Argument<'_>) = match call.arguments.as_slice() {
        [dependencies, factory] => (dependencies, factory),
        [Argument::StringLiteral(_module_id), dependencies, factory] => (dependencies, factory),
        _ => return None,
    };
    let Argument::ArrayExpression(dependencies) = dependencies else {
        return None;
    };
    let Argument::Identifier(factory) = factory else {
        return None;
    };
    let reference_id: ReferenceId = factory.reference_id.get()?;
    let symbol_id: SymbolId = symbols.get_reference(reference_id).symbol_id()?;
    Some((dependencies, symbol_id))
}

fn is_amd_guard(test: &Expression<'_>, symbols: &SymbolTable) -> bool {
    let Expression::LogicalExpression(logical) = test.get_inner_expression() else {
        return false;
    };
    if logical.operator != LogicalOperator::And {
        return false;
    }
    (is_define_function_test(&logical.left, symbols)
        && is_define_amd_marker(&logical.right, symbols))
        || (is_define_function_test(&logical.right, symbols)
            && is_define_amd_marker(&logical.left, symbols))
}

fn is_define_function_test(expression: &Expression<'_>, symbols: &SymbolTable) -> bool {
    let Expression::BinaryExpression(binary) = expression.get_inner_expression() else {
        return false;
    };
    if !matches!(
        binary.operator,
        BinaryOperator::Equality | BinaryOperator::StrictEquality
    ) {
        return false;
    }
    (is_typeof_define(&binary.left, symbols) && is_function_literal(&binary.right))
        || (is_typeof_define(&binary.right, symbols) && is_function_literal(&binary.left))
}

fn is_typeof_define(expression: &Expression<'_>, symbols: &SymbolTable) -> bool {
    let Expression::UnaryExpression(unary) = expression.get_inner_expression() else {
        return false;
    };
    if unary.operator != UnaryOperator::Typeof {
        return false;
    }
    let Expression::Identifier(identifier) = unary.argument.get_inner_expression() else {
        return false;
    };
    unresolved_identifier_is(identifier, "define", symbols)
}

fn is_function_literal(expression: &Expression<'_>) -> bool {
    matches!(
        expression.get_inner_expression(),
        Expression::StringLiteral(literal) if literal.value.as_str() == "function"
    )
}

fn is_define_amd_marker(expression: &Expression<'_>, symbols: &SymbolTable) -> bool {
    let Expression::StaticMemberExpression(member) = expression.get_inner_expression() else {
        return false;
    };
    if member.optional || member.property.name.as_str() != "amd" {
        return false;
    }
    let Expression::Identifier(identifier) = member.object.get_inner_expression() else {
        return false;
    };
    unresolved_identifier_is(identifier, "define", symbols)
}

fn unresolved_identifier_is(
    identifier: &oxc_ast::ast::IdentifierReference<'_>,
    expected: &str,
    symbols: &SymbolTable,
) -> bool {
    if identifier.name.as_str() != expected {
        return false;
    }
    let Some(reference_id): Option<ReferenceId> = identifier.reference_id.get() else {
        return false;
    };
    symbols.get_reference(reference_id).symbol_id().is_none()
}

fn is_amd_runtime_dependency(specifier: &str) -> bool {
    matches!(specifier, "require" | "exports" | "module")
}

fn body_has_dynamic_scope(body: &FunctionBody<'_>) -> bool {
    let mut probe: DynamicScopeProbe = DynamicScopeProbe { found: false };
    for statement in &body.statements {
        probe.visit_statement(statement);
    }
    probe.found
}

struct DynamicScopeProbe {
    found: bool,
}

impl<'a> Visit<'a> for DynamicScopeProbe {
    fn visit_identifier_reference(&mut self, identifier: &oxc_ast::ast::IdentifierReference<'a>) {
        if identifier.name == "eval" {
            self.found = true;
        }
    }

    fn visit_with_statement(&mut self, _statement: &oxc_ast::ast::WithStatement<'a>) {
        self.found = true;
    }
}

fn choose_name(
    safety: &RenameSafety<'_>,
    symbol_id: SymbolId,
    owner_scope: ScopeId,
    local_name: &str,
    preferred: &str,
    reserved: &IndexSet<String>,
    next_suffixes: &mut IndexMap<String, u32>,
) -> Option<String> {
    if safety.rename_is_safe(symbol_id, owner_scope, preferred, reserved, local_name) {
        return Some(preferred.to_owned());
    }
    let mut suffix: u32 = next_suffixes
        .get(preferred)
        .copied()
        .map_or(1, core::convert::identity);
    let attempts: usize = safety
        .symbols
        .len()
        .saturating_add(reserved.len())
        .saturating_add(1);
    for _ in 0..attempts {
        let candidate: String = format!("{preferred}_{suffix}");
        suffix = suffix.checked_add(1)?;
        if safety.rename_is_safe(symbol_id, owner_scope, &candidate, reserved, local_name) {
            next_suffixes.insert(preferred.to_owned(), suffix);
            return Some(candidate);
        }
    }
    None
}
