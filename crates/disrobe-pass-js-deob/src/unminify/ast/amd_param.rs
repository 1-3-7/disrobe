use indexmap::{IndexMap, IndexSet};
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, ArrayExpression, AssignmentTarget, BinaryOperator, BindingPatternKind,
    CallExpression, Expression, FormalParameters, Function, FunctionBody, FunctionType,
    LogicalOperator, MemberExpression, ObjectExpression, ObjectPropertyKind, PropertyKey,
    PropertyKind, Statement, UnaryOperator,
};
use oxc_ast::{AstKind, Visit};
use oxc_parser::Parser;
use oxc_semantic::{
    AstNodes, NodeId, ReferenceId, ScopeId, ScopeTree, Semantic, SemanticBuilder, SymbolId,
    SymbolTable,
};
use oxc_span::{GetSpan, SourceType};

use super::import_rename::push_reference_edits;
use super::rename_scope::{
    RenameSafety, body_has_dynamic_scope, choose_name, collect_reserved_names,
    unresolved_identifier_is,
};
use super::require_alias::{derive_module_names, is_minified_local};
use super::{Edit, RuleOutcome, edit_overlaps_comments};

#[derive(Debug, Clone, Default)]
pub(super) struct AmdParamStats {
    pub(super) amd: usize,
    pub(super) commonjs: usize,
    pub(super) global_iife: usize,
    pub(super) parcel: usize,
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
    let root_has_unresolved_eval: bool = scopes.root_unresolved_references().contains_key("eval");
    let safety: RenameSafety<'_> = RenameSafety {
        symbols,
        scopes,
        nodes,
    };
    let root_reserved: IndexSet<String> = collect_reserved_names(&semantic);
    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: AmdParamStats = AmdParamStats::default();

    for node in nodes.iter() {
        let AstKind::ObjectExpression(registry) = node.kind() else {
            continue;
        };
        for factory in browserify_factories(registry) {
            let mut reserved: IndexSet<String> = root_reserved.clone();
            let mut next_suffixes: IndexMap<String, u32> = IndexMap::new();
            for (parameter, preferred) in factory
                .params
                .items
                .iter()
                .zip(["require", "module", "exports"])
            {
                let BindingPatternKind::BindingIdentifier(binding) = &parameter.pattern.kind else {
                    continue;
                };
                let local_name: &str = binding.name.as_str();
                if !is_minified_local(local_name) || local_name == preferred {
                    continue;
                }
                let Some(symbol_id): Option<SymbolId> = binding.symbol_id.get() else {
                    continue;
                };
                let owner_scope: ScopeId = symbols.get_scope_id(symbol_id);
                let Some(new_name): Option<String> = choose_name(
                    &safety,
                    symbol_id,
                    owner_scope,
                    local_name,
                    preferred,
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
            }
        }
        for selected in webpack_factories(registry, nodes, symbols) {
            let factory: &Function<'_> = selected.factory;
            let mut reserved: IndexSet<String> = root_reserved.clone();
            let mut next_suffixes: IndexMap<String, u32> = IndexMap::new();
            for (parameter, preferred) in factory.params.items.iter().zip(selected.roles) {
                let BindingPatternKind::BindingIdentifier(binding) = &parameter.pattern.kind else {
                    continue;
                };
                let local_name: &str = binding.name.as_str();
                if !is_minified_local(local_name) || local_name == preferred {
                    continue;
                }
                let Some(symbol_id): Option<SymbolId> = binding.symbol_id.get() else {
                    continue;
                };
                if preferred != "require"
                    && symbols.get_resolved_reference_ids(symbol_id).is_empty()
                {
                    continue;
                }
                let owner_scope: ScopeId = symbols.get_scope_id(symbol_id);
                let Some(new_name): Option<String> = choose_name(
                    &safety,
                    symbol_id,
                    owner_scope,
                    local_name,
                    preferred,
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
            }
        }
    }

    for factory in parcel_factories(nodes, symbols, root_has_unresolved_eval) {
        let mut reserved: IndexSet<String> = root_reserved.clone();
        let mut next_suffixes: IndexMap<String, u32> = IndexMap::new();
        for ((parameter, preferred), live) in factory
            .factory
            .params
            .items
            .iter()
            .zip(["module", "exports"])
            .zip(factory.live_roles)
        {
            if !live {
                continue;
            }
            let BindingPatternKind::BindingIdentifier(binding) = &parameter.pattern.kind else {
                continue;
            };
            let local_name: &str = binding.name.as_str();
            if !is_minified_local(local_name) || local_name == preferred {
                continue;
            }
            let Some(symbol_id): Option<SymbolId> = binding.symbol_id.get() else {
                continue;
            };
            let owner_scope: ScopeId = symbols.get_scope_id(symbol_id);
            let Some(new_name): Option<String> = choose_name(
                &safety,
                symbol_id,
                owner_scope,
                local_name,
                preferred,
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
            stats.parcel = stats.parcel.saturating_add(1);
        }
    }

    for node in nodes.iter() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        let Some(factory): Option<AmdFactory<'_>> = amd_factory(call, symbols) else {
            continue;
        };
        let mut reserved: IndexSet<String> = root_reserved.clone();
        let mut next_suffixes: IndexMap<String, u32> = IndexMap::new();
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
            match factory.kind {
                ModuleFactoryKind::Amd => stats.amd += 1,
                ModuleFactoryKind::CommonJs => stats.commonjs += 1,
                ModuleFactoryKind::GlobalIife => stats.global_iife += 1,
            }
        }
    }

    if edits.is_empty() {
        return (RuleOutcome::empty(), AmdParamStats::default());
    }
    (RuleOutcome { edits }, stats)
}

fn parcel_factories<'a>(
    nodes: &'a AstNodes<'a>,
    symbols: &'a SymbolTable,
    root_has_unresolved_eval: bool,
) -> Vec<ParcelFactory<'a>> {
    if root_has_unresolved_eval {
        return Vec::new();
    }
    let mut factories: Vec<ParcelFactory<'_>> = Vec::new();
    let aliases: IndexSet<SymbolId> =
        parcel_register_aliases(nodes, symbols, root_has_unresolved_eval);
    for node in nodes.iter() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        if !parcel_call_has_static_scope(node, nodes)
            || call.optional
            || call.type_parameters.is_some()
        {
            continue;
        }
        let Some((module_id, factory_argument)): Option<(&Expression<'_>, &Expression<'_>)> =
            parcel_registration_arguments(call, symbols, &aliases)
        else {
            continue;
        };
        if !is_static_parcel_module_id(module_id) {
            continue;
        }
        let Expression::FunctionExpression(factory) = factory_argument.get_inner_expression()
        else {
            continue;
        };
        let Some(body): Option<&FunctionBody<'_>> = factory.body.as_deref() else {
            continue;
        };
        if factory.r#async
            || factory.generator
            || factory.type_parameters.is_some()
            || factory.params.rest.is_some()
            || factory.params.items.len() != 2
            || factory.params.items.iter().any(|parameter| {
                !matches!(
                    parameter.pattern.kind,
                    BindingPatternKind::BindingIdentifier(_)
                )
            })
            || body_has_dynamic_scope(body)
        {
            continue;
        }
        let Some(live_roles): Option<[bool; 2]> = parcel_factory_role_evidence(factory, symbols)
        else {
            continue;
        };
        if live_roles.iter().any(|live: &bool| *live) {
            factories.push(ParcelFactory {
                factory,
                live_roles,
            });
        }
    }
    factories
}

fn parcel_register_aliases(
    nodes: &AstNodes<'_>,
    symbols: &SymbolTable,
    root_has_unresolved_eval: bool,
) -> IndexSet<SymbolId> {
    let mut aliases: IndexSet<SymbolId> = IndexSet::new();
    let mut dependents: IndexMap<SymbolId, Vec<SymbolId>> = IndexMap::new();
    if root_has_unresolved_eval {
        return aliases;
    }
    for node in nodes.iter() {
        let candidate: Option<(SymbolId, ParcelRegisterSource)> = match node.kind() {
            AstKind::VariableDeclarator(declarator) => {
                let BindingPatternKind::BindingIdentifier(binding) = &declarator.id.kind else {
                    continue;
                };
                let Some(symbol_id): Option<SymbolId> = binding.symbol_id.get() else {
                    continue;
                };
                let Some(initializer): Option<&Expression<'_>> = declarator.init.as_ref() else {
                    continue;
                };
                if !parcel_call_has_static_scope(node, nodes)
                    || symbols.symbol_is_mutated(symbol_id)
                    || !symbols.get_redeclarations(symbol_id).is_empty()
                {
                    continue;
                }
                parcel_register_source(initializer, symbols).map(|source| (symbol_id, source))
            }
            AstKind::AssignmentExpression(assignment) => {
                let AssignmentTarget::AssignmentTargetIdentifier(binding) = &assignment.left else {
                    continue;
                };
                let Some(reference_id): Option<ReferenceId> = binding.reference_id.get() else {
                    continue;
                };
                let Some(symbol_id): Option<SymbolId> =
                    symbols.get_reference(reference_id).symbol_id()
                else {
                    continue;
                };
                if !assignment.operator.is_assign()
                    || !parcel_call_has_static_scope(node, nodes)
                    || !symbols.get_redeclarations(symbol_id).is_empty()
                    || !parcel_alias_has_one_write(symbol_id, symbols)
                    || !parcel_alias_is_uninitialized(symbol_id, nodes)
                {
                    continue;
                }
                parcel_register_source(&assignment.right, symbols).map(|source| (symbol_id, source))
            }
            _ => None,
        };
        let Some((symbol_id, source)): Option<(SymbolId, ParcelRegisterSource)> = candidate else {
            continue;
        };
        match source {
            ParcelRegisterSource::Global => {
                aliases.insert(symbol_id);
            }
            ParcelRegisterSource::Alias(source_symbol) => {
                dependents.entry(source_symbol).or_default().push(symbol_id);
            }
        }
    }
    let mut index: usize = 0;
    while let Some(source_symbol) = aliases.get_index(index).copied() {
        if let Some(symbols) = dependents.shift_remove(&source_symbol) {
            aliases.extend(symbols);
        }
        index = index.saturating_add(1);
    }
    aliases
}

fn parcel_alias_has_one_write(symbol_id: SymbolId, symbols: &SymbolTable) -> bool {
    symbols
        .get_resolved_references(symbol_id)
        .filter(|reference| reference.is_write())
        .count()
        == 1
}

fn parcel_alias_is_uninitialized(symbol_id: SymbolId, nodes: &AstNodes<'_>) -> bool {
    nodes.iter().any(|node| {
        let AstKind::VariableDeclarator(declarator) = node.kind() else {
            return false;
        };
        let BindingPatternKind::BindingIdentifier(binding) = &declarator.id.kind else {
            return false;
        };
        binding.symbol_id.get() == Some(symbol_id) && declarator.init.is_none()
    })
}

fn parcel_call_has_static_scope(node: &oxc_semantic::AstNode<'_>, nodes: &AstNodes<'_>) -> bool {
    nodes
        .ancestors(node.id())
        .all(|ancestor| match ancestor.kind() {
            AstKind::WithStatement(_) => false,
            AstKind::Function(function) => function
                .body
                .as_deref()
                .is_some_and(|body: &FunctionBody<'_>| !body_has_dynamic_scope(body)),
            AstKind::ArrowFunctionExpression(function) => !body_has_dynamic_scope(&function.body),
            _ => true,
        })
}

fn parcel_registration_arguments<'a>(
    call: &'a CallExpression<'a>,
    symbols: &SymbolTable,
    aliases: &IndexSet<SymbolId>,
) -> Option<(&'a Expression<'a>, &'a Expression<'a>)> {
    if is_parcel_register_expression(&call.callee, symbols, aliases) {
        let [module_id, factory] = call.arguments.as_slice() else {
            return None;
        };
        return Some((module_id.as_expression()?, factory.as_expression()?));
    }
    let invocation: &MemberExpression<'_> =
        call.callee.get_inner_expression().as_member_expression()?;
    if invocation.optional()
        || !is_parcel_register_expression(invocation.object(), symbols, aliases)
    {
        return None;
    }
    match invocation.static_property_name()? {
        "call" => {
            let [_receiver, module_id, factory] = call.arguments.as_slice() else {
                return None;
            };
            Some((module_id.as_expression()?, factory.as_expression()?))
        }
        "apply" => {
            let [_receiver, arguments] = call.arguments.as_slice() else {
                return None;
            };
            let Expression::ArrayExpression(arguments) =
                arguments.as_expression()?.get_inner_expression()
            else {
                return None;
            };
            let [module_id, factory] = arguments.elements.as_slice() else {
                return None;
            };
            Some((module_id.as_expression()?, factory.as_expression()?))
        }
        _ => None,
    }
}

fn is_parcel_register_member(register: &MemberExpression<'_>, symbols: &SymbolTable) -> bool {
    if register.optional() || register.static_property_name() != Some("register") {
        return false;
    }
    let Some(runtime): Option<&MemberExpression<'_>> = register
        .object()
        .get_inner_expression()
        .as_member_expression()
    else {
        return false;
    };
    if runtime.optional()
        || !runtime
            .static_property_name()
            .is_some_and(is_parcel_runtime_property)
    {
        return false;
    }
    let Expression::Identifier(global) = runtime.object().get_inner_expression() else {
        return false;
    };
    ["globalThis", "self", "window"]
        .into_iter()
        .any(|name: &str| unresolved_identifier_is(global, name, symbols))
}

fn is_parcel_register_expression(
    expression: &Expression<'_>,
    symbols: &SymbolTable,
    aliases: &IndexSet<SymbolId>,
) -> bool {
    match parcel_register_source(expression, symbols) {
        Some(ParcelRegisterSource::Global) => true,
        Some(ParcelRegisterSource::Alias(symbol_id)) => aliases.contains(&symbol_id),
        None => false,
    }
}

enum ParcelRegisterSource {
    Global,
    Alias(SymbolId),
}

fn parcel_register_source(
    expression: &Expression<'_>,
    symbols: &SymbolTable,
) -> Option<ParcelRegisterSource> {
    if parcel_register_member(expression)
        .is_some_and(|member: &MemberExpression<'_>| is_parcel_register_member(member, symbols))
    {
        return Some(ParcelRegisterSource::Global);
    }
    parcel_register_alias(expression, symbols).map(ParcelRegisterSource::Alias)
}

fn parcel_register_alias(expression: &Expression<'_>, symbols: &SymbolTable) -> Option<SymbolId> {
    let identifier = match expression.get_inner_expression() {
        Expression::Identifier(identifier) => identifier,
        Expression::SequenceExpression(sequence) => {
            let [prefix, identifier] = sequence.expressions.as_slice() else {
                return None;
            };
            let Expression::NumericLiteral(prefix) = prefix.get_inner_expression() else {
                return None;
            };
            if prefix.value != 0.0 {
                return None;
            }
            let Expression::Identifier(identifier) = identifier.get_inner_expression() else {
                return None;
            };
            identifier
        }
        _ => return None,
    };
    let reference_id: ReferenceId = identifier.reference_id.get()?;
    symbols.get_reference(reference_id).symbol_id()
}

fn parcel_register_member<'a>(expression: &'a Expression<'a>) -> Option<&'a MemberExpression<'a>> {
    match expression.get_inner_expression() {
        expression if expression.as_member_expression().is_some() => {
            expression.as_member_expression()
        }
        Expression::SequenceExpression(sequence) => {
            let [prefix, register] = sequence.expressions.as_slice() else {
                return None;
            };
            let Expression::NumericLiteral(prefix) = prefix.get_inner_expression() else {
                return None;
            };
            if prefix.value != 0.0 {
                return None;
            }
            register.get_inner_expression().as_member_expression()
        }
        _ => None,
    }
}

fn is_static_parcel_module_id(expression: &Expression<'_>) -> bool {
    match expression.get_inner_expression() {
        Expression::StringLiteral(module_id) => !module_id.value.is_empty(),
        Expression::NumericLiteral(_) => true,
        _ => false,
    }
}

fn is_parcel_runtime_property(name: &str) -> bool {
    let Some(suffix): Option<&str> = name.strip_prefix("parcelRequire") else {
        return false;
    };
    suffix.is_empty() || suffix.bytes().all(|byte: u8| byte.is_ascii_hexdigit())
}

fn parcel_factory_role_evidence(
    factory: &Function<'_>,
    symbols: &SymbolTable,
) -> Option<[bool; 2]> {
    let parameter_symbols: [SymbolId; 2] = factory
        .params
        .items
        .iter()
        .map(|parameter| {
            let BindingPatternKind::BindingIdentifier(binding) = &parameter.pattern.kind else {
                return None;
            };
            binding.symbol_id.get()
        })
        .collect::<Option<Vec<SymbolId>>>()?
        .try_into()
        .ok()?;
    let body: &FunctionBody<'_> = factory.body.as_deref()?;
    let mut probe: ParcelRoleProbe<'_> = ParcelRoleProbe {
        parameter_symbols,
        symbols,
        module_exports: false,
        exports_member: false,
    };
    for statement in &body.statements {
        probe.visit_statement(statement);
    }
    Some([probe.module_exports, probe.exports_member])
}

struct ParcelFactory<'a> {
    factory: &'a Function<'a>,
    live_roles: [bool; 2],
}

fn browserify_factories<'a>(registry: &'a ObjectExpression<'a>) -> Vec<&'a Function<'a>> {
    let mut factories: Vec<&Function<'_>> = Vec::new();
    for property in &registry.properties {
        let ObjectPropertyKind::ObjectProperty(property) = property else {
            return Vec::new();
        };
        if property.kind != PropertyKind::Init
            || property.computed
            || property.method
            || property.shorthand
            || !matches!(property.key, PropertyKey::NumericLiteral(_))
        {
            return Vec::new();
        }
        let Expression::ArrayExpression(tuple) = property.value.get_inner_expression() else {
            continue;
        };
        let [factory, dependencies] = tuple.elements.as_slice() else {
            continue;
        };
        let Some(Expression::FunctionExpression(factory)) = factory.as_expression() else {
            continue;
        };
        let Some(body): Option<&FunctionBody<'_>> = factory.body.as_deref() else {
            continue;
        };
        let Some(dependency_expression): Option<&Expression<'_>> = dependencies.as_expression()
        else {
            continue;
        };
        if factory.r#async
            || factory.generator
            || factory.type_parameters.is_some()
            || factory.params.rest.is_some()
            || factory.params.items.len() != 3
            || factory.params.items.iter().any(|parameter| {
                !matches!(
                    parameter.pattern.kind,
                    BindingPatternKind::BindingIdentifier(_)
                )
            })
            || body_has_dynamic_scope(body)
            || !browserify_dependency_map(dependency_expression)
        {
            continue;
        }
        factories.push(factory);
    }
    factories
}

fn browserify_dependency_map(expression: &Expression<'_>) -> bool {
    let Expression::ObjectExpression(dependencies) = expression.get_inner_expression() else {
        return false;
    };
    !dependencies.properties.is_empty()
        && dependencies.properties.iter().all(|property| {
            let ObjectPropertyKind::ObjectProperty(property) = property else {
                return false;
            };
            property.kind == PropertyKind::Init
                && !property.computed
                && !property.method
                && !property.shorthand
                && matches!(
                    &property.key,
                    PropertyKey::StringLiteral(_) | PropertyKey::StaticIdentifier(_)
                )
                && matches!(
                    property.value.get_inner_expression(),
                    Expression::NumericLiteral(_)
                )
        })
}

fn webpack_factories<'a>(
    registry: &'a ObjectExpression<'a>,
    nodes: &AstNodes<'a>,
    symbols: &SymbolTable,
) -> Vec<WebpackFactory<'a>> {
    let registry_symbol: Option<SymbolId> = webpack_registry_symbol(registry, nodes);
    let chunk_registration: bool = is_webpack_chunk_registration(registry, nodes, symbols);
    if registry_symbol.is_none() && !chunk_registration {
        return Vec::new();
    }
    let mut candidates: Vec<WebpackFactoryCandidate<'_>> = Vec::new();
    let mut module_indices: IndexMap<u64, usize> = IndexMap::new();
    for property in &registry.properties {
        let ObjectPropertyKind::ObjectProperty(property) = property else {
            return Vec::new();
        };
        let PropertyKey::NumericLiteral(module_id) = &property.key else {
            return Vec::new();
        };
        if property.kind != PropertyKind::Init
            || property.computed
            || property.method
            || property.shorthand
        {
            return Vec::new();
        }
        let Expression::FunctionExpression(factory) = property.value.get_inner_expression() else {
            return Vec::new();
        };
        let factory: &Function<'_> = factory.as_ref();
        let Some(body): Option<&FunctionBody<'_>> = factory.body.as_deref() else {
            return Vec::new();
        };
        if factory.r#async
            || factory.generator
            || factory.type_parameters.is_some()
            || factory.params.rest.is_some()
            || factory.params.items.len() != 3
            || factory.params.items.iter().any(|parameter| {
                !matches!(
                    parameter.pattern.kind,
                    BindingPatternKind::BindingIdentifier(_)
                )
            })
            || body_has_dynamic_scope(body)
        {
            continue;
        }
        let module_key: u64 = module_id.value.to_bits();
        if module_indices
            .insert(module_key, candidates.len())
            .is_some()
        {
            return Vec::new();
        }
        candidates.push(WebpackFactoryCandidate {
            module_key,
            factory,
        });
    }

    if registry_symbol.is_none() && chunk_registration {
        return candidates
            .into_iter()
            .filter_map(|candidate: WebpackFactoryCandidate<'_>| {
                let roles: [&'static str; 3] = ["module", "exports", "require"];
                webpack_factory_has_role_evidence(candidate.factory, roles, symbols).then_some(
                    WebpackFactory {
                        factory: candidate.factory,
                        roles,
                    },
                )
            })
            .collect();
    }

    let Some(registry_symbol) = registry_symbol else {
        return Vec::new();
    };
    let mut exact_calls: IndexMap<u64, Vec<[&'static str; 3]>> = IndexMap::new();
    let mut cycle_dispatchers: Vec<[&'static str; 3]> = Vec::new();
    for node in nodes.iter() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        if let Some((module_key, roles)) = webpack_bootstrap_roles(call, registry_symbol, symbols) {
            exact_calls.entry(module_key).or_default().push(roles);
        }
        if let Some(roles) =
            webpack_cycle_dispatcher_roles(node, call, registry_symbol, nodes, symbols)
        {
            cycle_dispatchers.push(roles);
        }
    }
    let cycle_roles: Option<[&'static str; 3]> = match cycle_dispatchers.as_slice() {
        [roles] => Some(*roles),
        _ => None,
    };
    let cyclic_modules: IndexSet<u64> = if exact_calls.is_empty() {
        cycle_roles.map_or_else(IndexSet::new, |roles| {
            webpack_static_cycle_modules(&candidates, &module_indices, roles, symbols)
        })
    } else {
        IndexSet::new()
    };

    let mut factories: Vec<WebpackFactory<'_>> = Vec::new();
    for candidate in candidates {
        let exact_roles: Option<[&'static str; 3]> = exact_calls
            .get(&candidate.module_key)
            .and_then(
                |matches: &Vec<[&'static str; 3]>| match matches.as_slice() {
                    [roles] => Some(*roles),
                    _ => None,
                },
            );
        let roles: Option<[&'static str; 3]> = exact_roles.or_else(|| {
            cyclic_modules
                .contains(&candidate.module_key)
                .then_some(cycle_roles)
                .flatten()
        });
        let Some(roles) = roles else {
            continue;
        };
        if !webpack_factory_has_role_evidence(candidate.factory, roles, symbols) {
            continue;
        }
        factories.push(WebpackFactory {
            factory: candidate.factory,
            roles,
        });
    }
    factories
}

fn is_webpack_chunk_registration(
    registry: &ObjectExpression<'_>,
    nodes: &AstNodes<'_>,
    symbols: &SymbolTable,
) -> bool {
    nodes.iter().any(|node: &oxc_semantic::AstNode<'_>| {
        let AstKind::CallExpression(call) = node.kind() else {
            return false;
        };
        if call.optional || call.type_parameters.is_some() {
            return false;
        }
        let [Argument::ArrayExpression(payload)] = call.arguments.as_slice() else {
            return false;
        };
        let [chunk_ids, factory_map] = payload.elements.as_slice() else {
            return false;
        };
        let Some(chunk_ids): Option<&Expression<'_>> = chunk_ids.as_expression() else {
            return false;
        };
        let Some(factory_map): Option<&Expression<'_>> = factory_map.as_expression() else {
            return false;
        };
        if factory_map.get_inner_expression().span() != registry.span
            || !is_webpack_chunk_ids(chunk_ids)
        {
            return false;
        }
        let Expression::StaticMemberExpression(push) = call.callee.get_inner_expression() else {
            return false;
        };
        !push.optional
            && push.property.name.as_str() == "push"
            && is_global_webpack_chunk(&push.object, symbols)
    })
}

fn is_webpack_chunk_ids(expression: &Expression<'_>) -> bool {
    let Expression::ArrayExpression(chunk_ids) = expression.get_inner_expression() else {
        return false;
    };
    !chunk_ids.elements.is_empty()
        && chunk_ids.elements.iter().all(|element| {
            matches!(
                element
                    .as_expression()
                    .map(Expression::get_inner_expression),
                Some(Expression::NumericLiteral(_))
            )
        })
}

fn is_global_webpack_chunk(expression: &Expression<'_>, symbols: &SymbolTable) -> bool {
    let Expression::StaticMemberExpression(chunk) = expression.get_inner_expression() else {
        return false;
    };
    if chunk.optional || !chunk.property.name.as_str().starts_with("webpackChunk") {
        return false;
    }
    let Expression::Identifier(global) = chunk.object.get_inner_expression() else {
        return false;
    };
    ["globalThis", "self", "window"]
        .into_iter()
        .any(|name: &str| unresolved_identifier_is(global, name, symbols))
}

fn webpack_registry_symbol(
    registry: &ObjectExpression<'_>,
    nodes: &AstNodes<'_>,
) -> Option<SymbolId> {
    nodes.iter().find_map(|node: &oxc_semantic::AstNode<'_>| {
        let AstKind::VariableDeclarator(declarator) = node.kind() else {
            return None;
        };
        let BindingPatternKind::BindingIdentifier(binding) = &declarator.id.kind else {
            return None;
        };
        let init: &Expression<'_> = declarator.init.as_ref()?;
        (init.get_inner_expression().span() == registry.span)
            .then(|| binding.symbol_id.get())
            .flatten()
    })
}

fn webpack_bootstrap_roles(
    call: &CallExpression<'_>,
    registry_symbol: SymbolId,
    symbols: &SymbolTable,
) -> Option<(u64, [&'static str; 3])> {
    if call.optional || call.type_parameters.is_some() || call.arguments.len() != 3 {
        return None;
    }
    let Expression::ComputedMemberExpression(member) = call.callee.get_inner_expression() else {
        return None;
    };
    if member.optional {
        return None;
    }
    let Expression::NumericLiteral(module_id) = member.expression.get_inner_expression() else {
        return None;
    };
    let Expression::Identifier(registry) = member.object.get_inner_expression() else {
        return None;
    };
    let registry_reference: ReferenceId = registry.reference_id.get()?;
    if symbols.get_reference(registry_reference).symbol_id() != Some(registry_symbol) {
        return None;
    }
    let require_indices: Vec<usize> = call
        .arguments
        .iter()
        .enumerate()
        .filter_map(|(index, argument)| {
            let Expression::Identifier(require) = argument.as_expression()?.get_inner_expression()
            else {
                return None;
            };
            unresolved_identifier_is(require, "__webpack_require__", symbols).then_some(index)
        })
        .collect();
    if require_indices.len() != 1 {
        return None;
    }
    let roles: [&'static str; 3] = webpack_argument_roles(call, require_indices[0], symbols)?;
    Some((module_id.value.to_bits(), roles))
}

fn webpack_cycle_dispatcher_roles<'a>(
    node: &oxc_semantic::AstNode<'a>,
    call: &CallExpression<'a>,
    registry_symbol: SymbolId,
    nodes: &AstNodes<'a>,
    symbols: &SymbolTable,
) -> Option<[&'static str; 3]> {
    if call.optional || call.type_parameters.is_some() || call.arguments.len() != 3 {
        return None;
    }
    let Expression::ComputedMemberExpression(member) = call.callee.get_inner_expression() else {
        return None;
    };
    if member.optional {
        return None;
    }
    let Expression::Identifier(registry) = member.object.get_inner_expression() else {
        return None;
    };
    let registry_reference: ReferenceId = registry.reference_id.get()?;
    if symbols.get_reference(registry_reference).symbol_id() != Some(registry_symbol) {
        return None;
    }
    for ancestor in nodes.ancestors(node.id()) {
        match ancestor.kind() {
            AstKind::Function(dispatcher) => {
                let dispatcher_body: &FunctionBody<'_> = dispatcher.body.as_deref()?;
                let dispatcher_symbol: SymbolId = match dispatcher.r#type {
                    FunctionType::FunctionDeclaration => dispatcher.id.as_ref()?.symbol_id.get()?,
                    FunctionType::FunctionExpression => webpack_assigned_dispatcher_symbol(
                        ancestor.id(),
                        dispatcher.span,
                        nodes,
                        symbols,
                    )?,
                    FunctionType::TSDeclareFunction
                    | FunctionType::TSEmptyBodyFunctionExpression => {
                        return None;
                    }
                };
                return webpack_cycle_dispatcher_roles_for(
                    call,
                    member,
                    &WebpackDispatcher {
                        params: dispatcher.params.as_ref(),
                        body: dispatcher_body,
                        is_async: dispatcher.r#async,
                        is_generator: dispatcher.generator,
                        has_type_parameters: dispatcher.type_parameters.is_some(),
                        symbol: dispatcher_symbol,
                    },
                    symbols,
                );
            }
            AstKind::ArrowFunctionExpression(dispatcher) => {
                let dispatcher_symbol: SymbolId = webpack_assigned_dispatcher_symbol(
                    ancestor.id(),
                    dispatcher.span,
                    nodes,
                    symbols,
                )?;
                return webpack_cycle_dispatcher_roles_for(
                    call,
                    member,
                    &WebpackDispatcher {
                        params: dispatcher.params.as_ref(),
                        body: dispatcher.body.as_ref(),
                        is_async: dispatcher.r#async,
                        is_generator: false,
                        has_type_parameters: dispatcher.type_parameters.is_some(),
                        symbol: dispatcher_symbol,
                    },
                    symbols,
                );
            }
            _ => {}
        }
    }
    None
}

fn webpack_assigned_dispatcher_symbol(
    dispatcher_node: NodeId,
    dispatcher_span: oxc_span::Span,
    nodes: &AstNodes<'_>,
    symbols: &SymbolTable,
) -> Option<SymbolId> {
    let declarator =
        nodes
            .ancestors(dispatcher_node)
            .find_map(|ancestor| match ancestor.kind() {
                AstKind::VariableDeclarator(declarator) => Some(declarator),
                _ => None,
            })?;
    let BindingPatternKind::BindingIdentifier(binding) = &declarator.id.kind else {
        return None;
    };
    let init: &Expression<'_> = declarator.init.as_ref()?;
    if init.get_inner_expression().span() != dispatcher_span {
        return None;
    }
    let symbol: SymbolId = binding.symbol_id.get()?;
    (!symbols.symbol_is_mutated(symbol) && symbols.get_redeclarations(symbol).is_empty())
        .then_some(symbol)
}

struct WebpackDispatcher<'a> {
    params: &'a FormalParameters<'a>,
    body: &'a FunctionBody<'a>,
    is_async: bool,
    is_generator: bool,
    has_type_parameters: bool,
    symbol: SymbolId,
}

fn webpack_cycle_dispatcher_roles_for(
    call: &CallExpression<'_>,
    member: &oxc_ast::ast::ComputedMemberExpression<'_>,
    dispatcher: &WebpackDispatcher<'_>,
    symbols: &SymbolTable,
) -> Option<[&'static str; 3]> {
    if dispatcher.is_async
        || dispatcher.is_generator
        || dispatcher.has_type_parameters
        || dispatcher.params.rest.is_some()
        || dispatcher.params.items.len() != 1
        || body_has_dynamic_scope(dispatcher.body)
    {
        return None;
    }
    let BindingPatternKind::BindingIdentifier(index_binding) =
        &dispatcher.params.items[0].pattern.kind
    else {
        return None;
    };
    let index_symbol: SymbolId = index_binding.symbol_id.get()?;
    let Expression::Identifier(index) = member.expression.get_inner_expression() else {
        return None;
    };
    let index_reference: ReferenceId = index.reference_id.get()?;
    if symbols.get_reference(index_reference).symbol_id() != Some(index_symbol) {
        return None;
    }
    let require_indices: Vec<usize> = call
        .arguments
        .iter()
        .enumerate()
        .filter_map(|(index, argument)| {
            let Expression::Identifier(require) = argument.as_expression()?.get_inner_expression()
            else {
                return None;
            };
            let reference_id: ReferenceId = require.reference_id.get()?;
            (symbols.get_reference(reference_id).symbol_id() == Some(dispatcher.symbol))
                .then_some(index)
        })
        .collect();
    if require_indices.len() != 1 {
        return None;
    }
    webpack_argument_roles(call, require_indices[0], symbols)
}

fn webpack_argument_roles(
    call: &CallExpression<'_>,
    require_index: usize,
    symbols: &SymbolTable,
) -> Option<[&'static str; 3]> {
    let arguments: [&Expression<'_>; 3] = call
        .arguments
        .iter()
        .map(Argument::as_expression)
        .collect::<Option<Vec<&Expression<'_>>>>()
        .and_then(|values: Vec<&Expression<'_>>| values.try_into().ok())?;
    for (module_index, argument) in arguments.iter().enumerate() {
        let Expression::Identifier(module) = argument.get_inner_expression() else {
            continue;
        };
        let Some(module_reference): Option<ReferenceId> = module.reference_id.get() else {
            continue;
        };
        let Some(module_symbol): Option<SymbolId> =
            symbols.get_reference(module_reference).symbol_id()
        else {
            continue;
        };
        for (exports_index, candidate) in arguments.iter().enumerate() {
            let Expression::StaticMemberExpression(exports) = candidate.get_inner_expression()
            else {
                continue;
            };
            if exports.optional || exports.property.name.as_str() != "exports" {
                continue;
            }
            let Expression::Identifier(exports_module) = exports.object.get_inner_expression()
            else {
                continue;
            };
            let Some(exports_module_reference): Option<ReferenceId> =
                exports_module.reference_id.get()
            else {
                continue;
            };
            if symbols.get_reference(exports_module_reference).symbol_id() == Some(module_symbol)
                && module_index != exports_index
                && module_index != require_index
                && exports_index != require_index
            {
                let mut roles: [&'static str; 3] = [""; 3];
                roles[module_index] = "module";
                roles[exports_index] = "exports";
                roles[require_index] = "require";
                return Some(roles);
            }
        }
    }
    None
}

fn webpack_static_cycle_modules(
    candidates: &[WebpackFactoryCandidate<'_>],
    module_indices: &IndexMap<u64, usize>,
    roles: [&str; 3],
    symbols: &SymbolTable,
) -> IndexSet<u64> {
    let mut edges: Vec<Vec<usize>> = vec![Vec::new(); candidates.len()];
    for (index, candidate) in candidates.iter().enumerate() {
        if !webpack_factory_has_role_evidence(candidate.factory, roles, symbols) {
            continue;
        }
        let Some(targets): Option<IndexSet<u64>> =
            webpack_static_require_targets(candidate.factory, roles, symbols)
        else {
            continue;
        };
        let mut target_indices: Vec<usize> = Vec::with_capacity(targets.len());
        for target in targets {
            let Some(target_index): Option<&usize> = module_indices.get(&target) else {
                target_indices.clear();
                break;
            };
            target_indices.push(*target_index);
        }
        edges[index] = target_indices;
    }
    cyclic_scc_indices(&edges)
        .into_iter()
        .map(|index: usize| candidates[index].module_key)
        .collect()
}

fn webpack_static_require_targets(
    factory: &Function<'_>,
    roles: [&str; 3],
    symbols: &SymbolTable,
) -> Option<IndexSet<u64>> {
    let require_index: usize = roles.iter().position(|role: &&str| *role == "require")?;
    let BindingPatternKind::BindingIdentifier(require) =
        &factory.params.items.get(require_index)?.pattern.kind
    else {
        return None;
    };
    let body: &FunctionBody<'_> = factory.body.as_deref()?;
    let mut probe: WebpackCycleProbe<'_> = WebpackCycleProbe {
        require_symbol: require.symbol_id.get()?,
        symbols,
        targets: IndexSet::new(),
        invalid: false,
    };
    for statement in &body.statements {
        probe.visit_statement(statement);
    }
    (!probe.invalid && !probe.targets.is_empty()).then_some(probe.targets)
}

fn cyclic_scc_indices(edges: &[Vec<usize>]) -> IndexSet<usize> {
    let mut seen: Vec<bool> = vec![false; edges.len()];
    let mut finish_order: Vec<usize> = Vec::with_capacity(edges.len());
    for root in 0..edges.len() {
        if seen[root] {
            continue;
        }
        seen[root] = true;
        let mut stack: Vec<(usize, usize)> = vec![(root, 0)];
        while let Some((node, next_edge)) = stack.last_mut() {
            if let Some(target) = edges[*node].get(*next_edge).copied() {
                *next_edge += 1;
                if !seen[target] {
                    seen[target] = true;
                    stack.push((target, 0));
                }
            } else {
                finish_order.push(*node);
                stack.pop();
            }
        }
    }

    let mut reverse: Vec<Vec<usize>> = vec![Vec::new(); edges.len()];
    for (source, targets) in edges.iter().enumerate() {
        for target in targets {
            reverse[*target].push(source);
        }
    }
    let mut assigned: Vec<bool> = vec![false; edges.len()];
    let mut cyclic: IndexSet<usize> = IndexSet::new();
    for root in finish_order.into_iter().rev() {
        if assigned[root] {
            continue;
        }
        assigned[root] = true;
        let mut component: Vec<usize> = Vec::new();
        let mut stack: Vec<usize> = vec![root];
        while let Some(node) = stack.pop() {
            component.push(node);
            for source in &reverse[node] {
                if !assigned[*source] {
                    assigned[*source] = true;
                    stack.push(*source);
                }
            }
        }
        if component.len() > 1 || edges[root].contains(&root) {
            cyclic.extend(component);
        }
    }
    cyclic
}

fn webpack_factory_has_role_evidence(
    factory: &Function<'_>,
    roles: [&str; 3],
    symbols: &SymbolTable,
) -> bool {
    let parameter_symbols: Option<[SymbolId; 3]> = factory
        .params
        .items
        .iter()
        .map(|parameter| {
            let BindingPatternKind::BindingIdentifier(binding) = &parameter.pattern.kind else {
                return None;
            };
            binding.symbol_id.get()
        })
        .collect::<Option<Vec<SymbolId>>>()
        .and_then(|values: Vec<SymbolId>| values.try_into().ok());
    let Some(parameter_symbols) = parameter_symbols else {
        return false;
    };
    let Some(body): Option<&FunctionBody<'_>> = factory.body.as_deref() else {
        return false;
    };
    let mut probe: WebpackRoleProbe<'_> = WebpackRoleProbe {
        parameter_symbols,
        symbols,
        called: [false; 3],
        exports_member: [false; 3],
        other_member: [false; 3],
    };
    for statement in &body.statements {
        probe.visit_statement(statement);
    }
    roles
        .iter()
        .enumerate()
        .all(|(index, role): (usize, &&str)| match *role {
            "module" => probe.exports_member[index],
            "exports" => probe.other_member[index],
            "require" => probe.called[index],
            _ => false,
        })
}

struct WebpackFactory<'a> {
    factory: &'a Function<'a>,
    roles: [&'static str; 3],
}

struct WebpackFactoryCandidate<'a> {
    module_key: u64,
    factory: &'a Function<'a>,
}

struct AmdFactory<'a> {
    dependencies: Vec<String>,
    parameters: &'a FormalParameters<'a>,
    kind: ModuleFactoryKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModuleFactoryKind {
    Amd,
    CommonJs,
    GlobalIife,
}

fn amd_factory<'a>(call: &'a CallExpression<'a>, symbols: &SymbolTable) -> Option<AmdFactory<'a>> {
    direct_amd_factory(call, symbols)
        .or_else(|| umd_factory(call, symbols))
        .or_else(|| global_iife_factory(call, symbols))
}

fn global_iife_factory<'a>(
    call: &'a CallExpression<'a>,
    symbols: &SymbolTable,
) -> Option<AmdFactory<'a>> {
    if call.optional || call.type_parameters.is_some() {
        return None;
    }
    let (parameters, body): (&FormalParameters<'_>, &FunctionBody<'_>) =
        direct_iife_parts(&call.callee)?;
    if body_has_dynamic_scope(body)
        || parameters.rest.is_some()
        || parameters.items.len() != call.arguments.len()
        || parameters.items.is_empty()
        || parameters.items.iter().any(|parameter| {
            !matches!(
                parameter.pattern.kind,
                BindingPatternKind::BindingIdentifier(_)
            )
        })
        || call
            .arguments
            .iter()
            .any(|argument: &Argument<'_>| matches!(argument, Argument::SpreadElement(_)))
    {
        return None;
    }
    let mut dependencies: Vec<String> = Vec::with_capacity(call.arguments.len());
    let mut unique_dependencies: IndexSet<String> = IndexSet::new();
    for (parameter, argument) in parameters.items.iter().zip(&call.arguments) {
        let BindingPatternKind::BindingIdentifier(binding) = &parameter.pattern.kind else {
            return None;
        };
        let symbol_id: SymbolId = binding.symbol_id.get()?;
        if symbols
            .get_resolved_reference_ids(symbol_id)
            .iter()
            .any(|&reference_id: &ReferenceId| symbols.get_reference(reference_id).is_write())
        {
            return None;
        }
        let dependency: String = static_global_member_name(argument, symbols)?;
        if !unique_dependencies.insert(dependency.clone()) {
            return None;
        }
        dependencies.push(dependency);
    }
    Some(AmdFactory {
        dependencies,
        parameters,
        kind: ModuleFactoryKind::GlobalIife,
    })
}

fn direct_iife_parts<'a>(
    callee: &'a Expression<'a>,
) -> Option<(&'a FormalParameters<'a>, &'a FunctionBody<'a>)> {
    match callee.get_inner_expression() {
        Expression::FunctionExpression(function)
            if !function.r#async && !function.generator && function.type_parameters.is_none() =>
        {
            Some((&function.params, function.body.as_ref()?))
        }
        Expression::ArrowFunctionExpression(function)
            if !function.r#async && function.type_parameters.is_none() =>
        {
            Some((&function.params, &function.body))
        }
        _ => None,
    }
}

fn static_global_member_name(argument: &Argument<'_>, symbols: &SymbolTable) -> Option<String> {
    let expression: &Expression<'_> = argument.as_expression()?.get_inner_expression();
    let (object, property): (&Expression<'_>, &str) = match expression {
        Expression::StaticMemberExpression(member) if !member.optional => {
            (&member.object, member.property.name.as_str())
        }
        Expression::ComputedMemberExpression(member) if !member.optional => {
            let Expression::StringLiteral(property) = member.expression.get_inner_expression()
            else {
                return None;
            };
            (&member.object, property.value.as_str())
        }
        _ => return None,
    };
    if !is_static_global_chain(object, symbols) {
        return None;
    }
    derive_module_names(property).into_iter().next()
}

fn is_static_global_chain(expression: &Expression<'_>, symbols: &SymbolTable) -> bool {
    match expression.get_inner_expression() {
        Expression::Identifier(identifier) => ["globalThis", "self", "window"]
            .into_iter()
            .any(|name: &str| unresolved_identifier_is(identifier, name, symbols)),
        Expression::StaticMemberExpression(member) if !member.optional => {
            is_static_global_chain(&member.object, symbols)
        }
        Expression::ComputedMemberExpression(member)
            if !member.optional
                && matches!(
                    member.expression.get_inner_expression(),
                    Expression::StringLiteral(_)
                ) =>
        {
            is_static_global_chain(&member.object, symbols)
        }
        _ => false,
    }
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
        kind: ModuleFactoryKind::Amd,
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

    let registration: UmdRegistration = guarded_umd_registration(body, symbols)
        .or_else(|| guarded_commonjs_registration(body, symbols))?;
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
            kind: registration.kind,
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
    kind: ModuleFactoryKind,
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

fn guarded_commonjs_registration(
    body: &FunctionBody<'_>,
    symbols: &SymbolTable,
) -> Option<UmdRegistration> {
    let mut all_assignments: CommonJsProbe<'_> = CommonJsProbe::new(symbols);
    for statement in &body.statements {
        all_assignments.visit_statement(statement);
    }
    if all_assignments.count != 1 {
        return None;
    }
    let registration: UmdRegistration = all_assignments.registration?;
    let mut guarded_matches: usize = 0;
    for statement in &body.statements {
        let Statement::IfStatement(if_statement) = statement else {
            continue;
        };
        if !is_commonjs_guard(&if_statement.test, symbols) {
            continue;
        }
        let mut branch_assignments: CommonJsProbe<'_> = CommonJsProbe::new(symbols);
        branch_assignments.visit_statement(&if_statement.consequent);
        if branch_assignments.count == 1
            && branch_assignments.registration.as_ref().is_some_and(
                |branch_registration: &UmdRegistration| {
                    branch_registration.factory_symbol == registration.factory_symbol
                        && branch_registration.dependencies == registration.dependencies
                },
            )
        {
            guarded_matches = guarded_matches.saturating_add(1);
        }
    }
    (guarded_matches == 1).then_some(registration)
}

struct CommonJsProbe<'s> {
    symbols: &'s SymbolTable,
    count: usize,
    registration: Option<UmdRegistration>,
}

impl<'s> CommonJsProbe<'s> {
    const fn new(symbols: &'s SymbolTable) -> Self {
        Self {
            symbols,
            count: 0,
            registration: None,
        }
    }
}

impl<'a> Visit<'a> for CommonJsProbe<'_> {
    fn visit_assignment_expression(&mut self, assignment: &oxc_ast::ast::AssignmentExpression<'a>) {
        if is_global_module_exports_target(&assignment.left, self.symbols) {
            self.count = self.count.saturating_add(1);
            if let Some((dependencies, factory_symbol)) =
                commonjs_factory_reference(assignment, self.symbols)
            {
                self.registration = Some(UmdRegistration {
                    factory_symbol,
                    dependencies,
                    kind: ModuleFactoryKind::CommonJs,
                });
            }
        }
        oxc_ast::visit::walk::walk_assignment_expression(self, assignment);
    }

    fn visit_function(&mut self, _function: &Function<'a>, _flags: oxc::syntax::scope::ScopeFlags) {
    }

    fn visit_arrow_function_expression(
        &mut self,
        _arrow: &oxc_ast::ast::ArrowFunctionExpression<'a>,
    ) {
    }
}

fn commonjs_factory_reference(
    assignment: &oxc_ast::ast::AssignmentExpression<'_>,
    symbols: &SymbolTable,
) -> Option<(Vec<String>, SymbolId)> {
    if assignment.operator != oxc_ast::ast::AssignmentOperator::Assign
        || !is_global_module_exports_target(&assignment.left, symbols)
    {
        return None;
    }
    let Expression::CallExpression(call) = assignment.right.get_inner_expression() else {
        return None;
    };
    if call.optional || call.type_parameters.is_some() {
        return None;
    }
    let Expression::Identifier(factory) = &call.callee else {
        return None;
    };
    let reference_id: ReferenceId = factory.reference_id.get()?;
    let factory_symbol: SymbolId = symbols.get_reference(reference_id).symbol_id()?;
    let dependencies: Vec<String> = call
        .arguments
        .iter()
        .map(|argument: &Argument<'_>| static_require_specifier(argument, symbols))
        .collect::<Option<Vec<String>>>()?;
    (!dependencies.is_empty()).then_some((dependencies, factory_symbol))
}

fn static_require_specifier(argument: &Argument<'_>, symbols: &SymbolTable) -> Option<String> {
    let Expression::CallExpression(call) = argument.as_expression()?.get_inner_expression() else {
        return None;
    };
    if call.optional || call.type_parameters.is_some() || call.arguments.len() != 1 {
        return None;
    }
    let Expression::Identifier(require) = &call.callee else {
        return None;
    };
    if !unresolved_identifier_is(require, "require", symbols) {
        return None;
    }
    let Some(Expression::StringLiteral(specifier)) = call.arguments[0].as_expression() else {
        return None;
    };
    Some(specifier.value.as_str().to_owned())
}

fn is_global_module_exports_target(
    target: &oxc_ast::ast::AssignmentTarget<'_>,
    symbols: &SymbolTable,
) -> bool {
    let object: &Expression<'_> = match target {
        oxc_ast::ast::AssignmentTarget::StaticMemberExpression(member)
            if !member.optional && member.property.name.as_str() == "exports" =>
        {
            &member.object
        }
        oxc_ast::ast::AssignmentTarget::ComputedMemberExpression(member)
            if !member.optional
                && matches!(
                    member.expression.get_inner_expression(),
                    Expression::StringLiteral(literal) if literal.value.as_str() == "exports"
                ) =>
        {
            &member.object
        }
        _ => return false,
    };
    let Expression::Identifier(module) = object.get_inner_expression() else {
        return false;
    };
    unresolved_identifier_is(module, "module", symbols)
}

fn is_commonjs_guard(expression: &Expression<'_>, symbols: &SymbolTable) -> bool {
    let Expression::LogicalExpression(logical) = expression.get_inner_expression() else {
        return false;
    };
    if logical.operator != LogicalOperator::And {
        return false;
    }
    let left_exports_guard: bool =
        is_typeof_global_comparison(&logical.left, "exports", "object", true, symbols);
    let right_exports_guard: bool =
        is_typeof_global_comparison(&logical.right, "exports", "object", true, symbols);
    let left_module_defined: bool =
        is_typeof_global_comparison(&logical.left, "module", "undefined", false, symbols);
    let right_module_defined: bool =
        is_typeof_global_comparison(&logical.right, "module", "undefined", false, symbols);
    let left_module_object: bool =
        is_typeof_global_comparison(&logical.left, "module", "object", true, symbols);
    let right_module_object: bool =
        is_typeof_global_comparison(&logical.right, "module", "object", true, symbols);
    let left_module_exports: bool = is_global_module_exports_expression(&logical.left, symbols);
    let right_module_exports: bool = is_global_module_exports_expression(&logical.right, symbols);
    (left_exports_guard && right_module_defined)
        || (right_exports_guard && left_module_defined)
        || (left_module_object && right_module_exports)
        || (right_module_object && left_module_exports)
}

fn is_global_module_exports_expression(expression: &Expression<'_>, symbols: &SymbolTable) -> bool {
    let object: &Expression<'_> = match expression.get_inner_expression() {
        Expression::StaticMemberExpression(member)
            if !member.optional && member.property.name.as_str() == "exports" =>
        {
            &member.object
        }
        Expression::ComputedMemberExpression(member)
            if !member.optional
                && matches!(
                    member.expression.get_inner_expression(),
                    Expression::StringLiteral(literal) if literal.value.as_str() == "exports"
                ) =>
        {
            &member.object
        }
        _ => return false,
    };
    let Expression::Identifier(module) = object.get_inner_expression() else {
        return false;
    };
    unresolved_identifier_is(module, "module", symbols)
}

fn is_typeof_global_comparison(
    expression: &Expression<'_>,
    identifier_name: &str,
    literal_value: &str,
    equality: bool,
    symbols: &SymbolTable,
) -> bool {
    let Expression::BinaryExpression(binary) = expression.get_inner_expression() else {
        return false;
    };
    let operator_matches: bool = if equality {
        matches!(
            binary.operator,
            BinaryOperator::Equality | BinaryOperator::StrictEquality
        )
    } else {
        matches!(
            binary.operator,
            BinaryOperator::Inequality | BinaryOperator::StrictInequality
        )
    };
    operator_matches
        && ((is_typeof_global(&binary.left, identifier_name, symbols)
            && is_string_literal(&binary.right, literal_value))
            || (is_typeof_global(&binary.right, identifier_name, symbols)
                && is_string_literal(&binary.left, literal_value)))
}

fn is_typeof_global(
    expression: &Expression<'_>,
    identifier_name: &str,
    symbols: &SymbolTable,
) -> bool {
    let Expression::UnaryExpression(unary) = expression.get_inner_expression() else {
        return false;
    };
    if unary.operator != UnaryOperator::Typeof {
        return false;
    }
    let Expression::Identifier(identifier) = unary.argument.get_inner_expression() else {
        return false;
    };
    unresolved_identifier_is(identifier, identifier_name, symbols)
}

fn is_string_literal(expression: &Expression<'_>, expected: &str) -> bool {
    matches!(
        expression.get_inner_expression(),
        Expression::StringLiteral(literal) if literal.value.as_str() == expected
    )
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
                    kind: ModuleFactoryKind::Amd,
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

struct WebpackRoleProbe<'s> {
    parameter_symbols: [SymbolId; 3],
    symbols: &'s SymbolTable,
    called: [bool; 3],
    exports_member: [bool; 3],
    other_member: [bool; 3],
}

struct ParcelRoleProbe<'s> {
    parameter_symbols: [SymbolId; 2],
    symbols: &'s SymbolTable,
    module_exports: bool,
    exports_member: bool,
}

struct WebpackCycleProbe<'s> {
    require_symbol: SymbolId,
    symbols: &'s SymbolTable,
    targets: IndexSet<u64>,
    invalid: bool,
}

impl WebpackRoleProbe<'_> {
    fn parameter_index(&self, identifier: &oxc_ast::ast::IdentifierReference<'_>) -> Option<usize> {
        let reference_id: ReferenceId = identifier.reference_id.get()?;
        let symbol_id: SymbolId = self.symbols.get_reference(reference_id).symbol_id()?;
        self.parameter_symbols
            .iter()
            .position(|candidate: &SymbolId| *candidate == symbol_id)
    }
}

impl ParcelRoleProbe<'_> {
    fn parameter_index(&self, identifier: &oxc_ast::ast::IdentifierReference<'_>) -> Option<usize> {
        let reference_id: ReferenceId = identifier.reference_id.get()?;
        let symbol_id: SymbolId = self.symbols.get_reference(reference_id).symbol_id()?;
        self.parameter_symbols
            .iter()
            .position(|candidate: &SymbolId| *candidate == symbol_id)
    }
}

impl<'a> Visit<'a> for WebpackRoleProbe<'_> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if !call.optional
            && call.type_parameters.is_none()
            && let Expression::Identifier(callee) = &call.callee
            && let Some(index) = self.parameter_index(callee)
        {
            self.called[index] = true;
        }
        visit_call_children(self, call);
    }

    fn visit_static_member_expression(
        &mut self,
        member: &oxc_ast::ast::StaticMemberExpression<'a>,
    ) {
        if !member.optional
            && let Expression::Identifier(object) = member.object.get_inner_expression()
            && let Some(index) = self.parameter_index(object)
        {
            if member.property.name.as_str() == "exports" {
                self.exports_member[index] = true;
            } else {
                self.other_member[index] = true;
            }
        }
        self.visit_expression(&member.object);
    }

    fn visit_function(&mut self, _function: &Function<'a>, _flags: oxc::syntax::scope::ScopeFlags) {
    }

    fn visit_arrow_function_expression(
        &mut self,
        _arrow: &oxc_ast::ast::ArrowFunctionExpression<'a>,
    ) {
    }
}

impl<'a> Visit<'a> for ParcelRoleProbe<'_> {
    fn visit_static_member_expression(
        &mut self,
        member: &oxc_ast::ast::StaticMemberExpression<'a>,
    ) {
        if !member.optional
            && let Expression::Identifier(object) = member.object.get_inner_expression()
            && let Some(index) = self.parameter_index(object)
        {
            if index == 0 && member.property.name.as_str() == "exports" {
                self.module_exports = true;
            } else if index == 1 && member.property.name.as_str() != "exports" {
                self.exports_member = true;
            }
        }
        self.visit_expression(&member.object);
    }

    fn visit_function(&mut self, _function: &Function<'a>, _flags: oxc::syntax::scope::ScopeFlags) {
    }

    fn visit_arrow_function_expression(
        &mut self,
        _arrow: &oxc_ast::ast::ArrowFunctionExpression<'a>,
    ) {
    }
}

impl<'a> Visit<'a> for WebpackCycleProbe<'_> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if let Expression::Identifier(callee) = &call.callee
            && let Some(reference_id) = callee.reference_id.get()
            && self.symbols.get_reference(reference_id).symbol_id() == Some(self.require_symbol)
        {
            let target: Option<u64> = if call.optional || call.type_parameters.is_some() {
                None
            } else {
                let [argument] = call.arguments.as_slice() else {
                    self.invalid = true;
                    visit_call_children(self, call);
                    return;
                };
                argument.as_expression().and_then(|expression| {
                    let Expression::NumericLiteral(target) = expression.get_inner_expression()
                    else {
                        return None;
                    };
                    Some(target.value.to_bits())
                })
            };
            let Some(target) = target else {
                self.invalid = true;
                visit_call_children(self, call);
                return;
            };
            self.targets.insert(target);
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

fn is_amd_runtime_dependency(specifier: &str) -> bool {
    matches!(specifier, "require" | "exports" | "module")
}
