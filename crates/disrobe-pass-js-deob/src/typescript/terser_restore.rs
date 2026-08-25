use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::VecDeque;
use std::ops::Range;
use std::sync::Arc;

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, AssignmentOperator, BindingPatternKind, CallExpression, Expression, ForStatementLeft,
    FormalParameters, LogicalOperator, MemberExpression, Program, Statement, UnaryOperator,
    WithStatement,
};
use oxc_ast::{AstKind, Visit};
use oxc_parser::Parser;
use oxc_semantic::{
    AstNodes, NodeId, ScopeId, ScopeTree, Semantic, SemanticBuilder, SymbolId, SymbolTable,
};
use oxc_span::{GetSpan, SourceType};
use serde::Serialize;

use crate::mangled_names::{
    Context, ContextNameSource, CorpusNameSource, HeuristicNameSource, NameRegistry, RestoreStats,
    RestoredName, ScopeKey, SemanticRole, Suggestion, SymbolRole,
};
use crate::rename::scope_names::{conflicts_in_scope, is_js_reserved};

#[derive(Debug, Clone, Default, Serialize)]
pub struct TerserRestoreReport {
    pub identifiers_renamed: usize,
    pub references_rewritten: usize,
    pub restore_stats: RestoreStats,
    pub candidates: Vec<MangledCandidate>,
    pub renames: Vec<RestoredName>,
    pub rewritten: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MangledCandidate {
    pub original: String,
    pub declaration_offset: usize,
}

pub fn restore_terser_mangled(source: &str) -> crate::Result<TerserRestoreReport> {
    if source.len() > MAX_MANGLED_SOURCE_BYTES {
        return Err(crate::Error::SyntaxLimit {
            kind: "JavaScript source bytes",
            observed: source.len(),
            maximum: MAX_MANGLED_SOURCE_BYTES,
        });
    }
    Ok(restore_terser_mangled_bounded(source))
}

fn restore_terser_mangled_bounded(source: &str) -> TerserRestoreReport {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("terser.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if parsed.panicked {
        return TerserRestoreReport {
            rewritten: source.to_owned(),
            ..Default::default()
        };
    }
    if dynamic_name_lookup_exists(&parsed.program) {
        return TerserRestoreReport {
            rewritten: source.to_owned(),
            ..Default::default()
        };
    }
    let semantic_ret: oxc_semantic::SemanticBuilderReturn<'_> = SemanticBuilder::new()
        .with_check_syntax_error(false)
        .with_scope_tree_child_ids(true)
        .build(&parsed.program);
    if !semantic_ret.errors.is_empty() {
        return TerserRestoreReport {
            rewritten: source.to_owned(),
            ..Default::default()
        };
    }
    let semantic: Semantic<'_> = semantic_ret.semantic;
    let symbols: &SymbolTable = semantic.symbols();
    let scopes: &ScopeTree = semantic.scopes();
    let nodes: &AstNodes<'_> = semantic.nodes();
    let semantic_roles: BTreeMap<SymbolId, BTreeSet<SemanticRole>> =
        infer_semantic_roles(symbols, nodes);

    let registry: NameRegistry = NameRegistry::new()
        .with_source(Arc::new(CorpusNameSource::well_known_minified()))
        .with_source(Arc::new(ContextNameSource::new()))
        .with_source(Arc::new(HeuristicNameSource::new()));
    let mut free_references: BTreeSet<String> = BTreeSet::new();
    for name in scopes.root_unresolved_references().keys() {
        free_references.insert(name.to_string());
    }

    let mut contexts: BTreeMap<SymbolId, Context> = BTreeMap::new();
    for symbol_id in iter_symbols(symbols) {
        let original: String = symbols.get_name(symbol_id).to_owned();
        if !is_likely_mangled(&original) {
            continue;
        }
        let role: SymbolRole = role_for_symbol(symbol_id, symbols, nodes);
        let scope_id: ScopeId = symbols.get_scope_id(symbol_id);
        let mut ctx: Context = Context::new(original, role, ScopeKey(scope_id_to_u32(scope_id)));
        for &ref_id in symbols.get_resolved_reference_ids(symbol_id) {
            let node_id: NodeId = symbols.get_reference(ref_id).node_id();
            if let AstKind::IdentifierReference(id) = nodes.kind(node_id) {
                ctx.callers.insert(id.name.as_str().to_owned());
            }
            if let Some(member) = member_access_on_reference(nodes, node_id) {
                ctx.member_accesses.insert(member);
            }
            ctx.indexed_elements_called |= indexed_element_called_on_reference(nodes, node_id);
            ctx.called_as_predicate |= direct_call_used_as_condition(nodes, node_id);
            if let Some((member, literals)) =
                static_member_call_literals_on_reference(nodes, node_id)
                && !literals.is_empty()
            {
                let stored: usize = ctx.member_call_literals.values().map(BTreeSet::len).sum();
                let remaining: usize = MAX_MEMBER_CALL_LITERALS.saturating_sub(stored);
                if remaining > 0 {
                    ctx.member_call_literals
                        .entry(member)
                        .or_default()
                        .extend(literals.into_iter().take(remaining));
                }
            }
        }
        if let Some(name) = assigned_from_name(symbol_id, symbols, nodes)
            && is_usable_inferred_name(&name)
        {
            ctx.assigned_from.insert(name);
        }
        for text in declaration_string_literals(symbol_id, symbols, nodes) {
            ctx.nearby_strings.insert(text);
        }
        if let Some(roles) = semantic_roles.get(&symbol_id) {
            ctx.semantic_roles.extend(roles);
        }
        contexts.insert(symbol_id, ctx);
    }

    let mut candidates: Vec<MangledCandidate> = contexts
        .iter()
        .map(|(symbol_id, ctx): (&SymbolId, &Context)| MangledCandidate {
            original: ctx.original.clone(),
            declaration_offset: symbols.get_span(*symbol_id).start as usize,
        })
        .collect();
    candidates.sort_by_key(|candidate: &MangledCandidate| candidate.declaration_offset);

    let mut ordered: Vec<(SymbolId, &Context)> = contexts
        .iter()
        .map(|(symbol_id, ctx): (&SymbolId, &Context)| (*symbol_id, ctx))
        .collect();
    ordered.sort_by_key(|(symbol_id, _): &(SymbolId, &Context)| {
        (symbols.get_span(*symbol_id).start, *symbol_id)
    });

    let mut allocator: ScopeAllocator<'_> = ScopeAllocator {
        scopes,
        free_references: &free_references,
        assigned: BTreeMap::new(),
    };
    let mut restore_stats: RestoreStats = RestoreStats::default();
    let mut by_source: BTreeMap<String, usize> = BTreeMap::new();
    let mut plan: BTreeMap<SymbolId, String> = BTreeMap::new();
    let mut renames: Vec<RestoredName> = Vec::new();
    for (symbol_id, ctx) in ordered {
        let Some(suggestion): Option<Suggestion> = registry.best_suggestion(ctx.scope, ctx) else {
            restore_stats.fallback_to_original += 1;
            continue;
        };
        let owner: ScopeId = symbols.get_scope_id(symbol_id);
        let Some((new_name, suffixed)): Option<(String, bool)> =
            allocator.allocate(owner, &suggestion.name)
        else {
            restore_stats.fallback_to_original += 1;
            continue;
        };
        if suffixed {
            restore_stats.conflicts_resolved += 1;
        }
        restore_stats.suggestions_made += 1;
        *by_source
            .entry(suggestion.source_label.to_owned())
            .or_insert(0) += 1;
        renames.push(RestoredName {
            original: ctx.original.clone(),
            restored: new_name.clone(),
            confidence: suggestion.confidence,
            tier: suggestion.confidence.tier(),
            source_label: suggestion.source_label,
            declaration_offset: symbols.get_span(symbol_id).start as usize,
        });
        plan.insert(symbol_id, new_name);
    }
    restore_stats.by_source = by_source;

    let mut edits: Vec<(Range<usize>, String)> = Vec::new();
    let mut idents_renamed: usize = 0;
    let mut refs_rewritten: usize = 0;
    for (symbol_id, new_name) in &plan {
        idents_renamed = idents_renamed.saturating_add(1);
        let decl_span: oxc_span::Span = symbols.get_span(*symbol_id);
        edits.push((
            decl_span.start as usize..decl_span.end as usize,
            new_name.clone(),
        ));
        refs_rewritten = refs_rewritten.saturating_add(1);
        for &ref_id in symbols.get_resolved_reference_ids(*symbol_id) {
            let node_id: NodeId = symbols.get_reference(ref_id).node_id();
            if let AstKind::IdentifierReference(id) = nodes.kind(node_id) {
                edits.push((
                    id.span.start as usize..id.span.end as usize,
                    new_name.clone(),
                ));
                refs_rewritten = refs_rewritten.saturating_add(1);
            }
        }
    }

    edits.sort_by_key(|item: &(Range<usize>, String)| core::cmp::Reverse(item.0.start));
    let mut out: String = source.to_owned();
    for (range, replacement) in edits {
        if range.start <= range.end
            && range.end <= out.len()
            && out.is_char_boundary(range.start)
            && out.is_char_boundary(range.end)
        {
            out.replace_range(range, &replacement);
        }
    }

    renames.sort_by(|left: &RestoredName, right: &RestoredName| {
        left.declaration_offset.cmp(&right.declaration_offset)
    });
    TerserRestoreReport {
        identifiers_renamed: idents_renamed,
        references_rewritten: refs_rewritten,
        restore_stats,
        candidates,
        renames,
        rewritten: out,
    }
}

const MAX_SUFFIX_ATTEMPTS: u32 = 512;

struct ScopeAllocator<'s> {
    scopes: &'s ScopeTree,
    free_references: &'s BTreeSet<String>,
    assigned: BTreeMap<ScopeId, BTreeSet<String>>,
}

impl ScopeAllocator<'_> {
    fn already_assigned(&self, owner: ScopeId, name: &str) -> bool {
        let holds = |scope: ScopeId| -> bool {
            self.assigned
                .get(&scope)
                .is_some_and(|names: &BTreeSet<String>| names.contains(name))
        };
        holds(owner)
            || self.scopes.ancestors(owner).any(holds)
            || self.scopes.iter_all_child_ids(owner).any(holds)
    }

    fn allocate(&mut self, owner: ScopeId, base: &str) -> Option<(String, bool)> {
        for attempt in 0..MAX_SUFFIX_ATTEMPTS {
            let candidate: String = if attempt == 0 {
                base.to_owned()
            } else {
                format!("{base}_{}", attempt.saturating_add(1))
            };
            if is_js_reserved(&candidate)
                || self.free_references.contains(&candidate)
                || conflicts_in_scope(self.scopes, owner, &candidate)
                || self.already_assigned(owner, &candidate)
            {
                continue;
            }
            self.assigned
                .entry(owner)
                .or_default()
                .insert(candidate.clone());
            return Some((candidate, attempt > 0));
        }
        None
    }
}

fn iter_symbols(symbols: &SymbolTable) -> Vec<SymbolId> {
    symbols.symbol_ids().collect()
}

fn is_likely_mangled(name: &str) -> bool {
    if name.len() > 3 {
        return false;
    }
    if name.is_empty() {
        return false;
    }
    let first: char = name.chars().next().unwrap_or(' ');
    if !(first.is_ascii_alphabetic() || first == '_' || first == '$') {
        return false;
    }
    !matches!(name, "if" | "in" | "do" | "of" | "id")
}

fn role_for_symbol(symbol_id: SymbolId, symbols: &SymbolTable, nodes: &AstNodes<'_>) -> SymbolRole {
    let decl_node: NodeId = symbols.get_declaration(symbol_id);
    match nodes.kind(decl_node) {
        AstKind::Function(_) => SymbolRole::Function,
        AstKind::Class(_) => SymbolRole::Class,
        AstKind::FormalParameter(_) => SymbolRole::Parameter,
        _ => SymbolRole::Variable,
    }
}

fn member_access_on_reference(nodes: &AstNodes<'_>, reference_node: NodeId) -> Option<String> {
    let parent: &oxc_semantic::AstNode<'_> = nodes.parent_node(reference_node)?;
    let AstKind::MemberExpression(member) = parent.kind() else {
        return None;
    };
    member.static_property_name().map(str::to_owned)
}

fn indexed_element_called_on_reference(nodes: &AstNodes<'_>, reference_node: NodeId) -> bool {
    let Some(member_node) = nodes.parent_node(reference_node) else {
        return false;
    };
    let AstKind::MemberExpression(member) = member_node.kind() else {
        return false;
    };
    if member.static_property_name().is_some() {
        return false;
    }
    let Some(call_node) = nodes.parent_node(member_node.id()) else {
        return false;
    };
    let AstKind::CallExpression(call) = call_node.kind() else {
        return false;
    };
    call.callee.span() == member.span()
}

fn direct_call_used_as_condition(nodes: &AstNodes<'_>, reference_node: NodeId) -> bool {
    let Some(call_node) = nodes.parent_node(reference_node) else {
        return false;
    };
    let AstKind::CallExpression(call) = call_node.kind() else {
        return false;
    };
    if call.optional || call.type_parameters.is_some() {
        return false;
    }
    let AstKind::IdentifierReference(reference) = nodes.kind(reference_node) else {
        return false;
    };
    if call.callee.span() != reference.span {
        return false;
    }
    let Some(condition_node) = nodes.parent_node(call_node.id()) else {
        return false;
    };
    match condition_node.kind() {
        AstKind::ConditionalExpression(conditional) => conditional.test.span() == call.span,
        AstKind::IfStatement(statement) => statement.test.span() == call.span,
        _ => false,
    }
}

fn static_member_call_literals_on_reference(
    nodes: &AstNodes<'_>,
    reference_node: NodeId,
) -> Option<(String, Vec<String>)> {
    let member_node: &oxc_semantic::AstNode<'_> = nodes.parent_node(reference_node)?;
    let AstKind::MemberExpression(member) = member_node.kind() else {
        return None;
    };
    let member_name: String = member.static_property_name()?.to_owned();
    let call_node: &oxc_semantic::AstNode<'_> = nodes.parent_node(member_node.id())?;
    let AstKind::CallExpression(call) = call_node.kind() else {
        return None;
    };
    if call.callee.span() != member.span() {
        return None;
    }
    let literals: Vec<String> = call
        .arguments
        .iter()
        .filter_map(|argument| argument.as_expression())
        .filter_map(|argument| match argument.get_inner_expression() {
            Expression::StringLiteral(literal) => Some(literal.value.as_str().to_owned()),
            _ => None,
        })
        .take(MAX_NEARBY_STRINGS)
        .collect();
    Some((member_name, literals))
}

#[derive(Debug, Clone, Copy)]
struct PromiseChainEvidence {
    promise: SymbolId,
    transport: SymbolId,
    url: SymbolId,
    response: Option<SymbolId>,
    error: Option<SymbolId>,
    owner_function: Option<NodeId>,
    catch_function: Option<NodeId>,
}

fn infer_semantic_roles(
    symbols: &SymbolTable,
    nodes: &AstNodes<'_>,
) -> BTreeMap<SymbolId, BTreeSet<SemanticRole>> {
    let mut roles: BTreeMap<SymbolId, BTreeSet<SemanticRole>> = BTreeMap::new();
    let property_loops: BTreeMap<NodeId, PropertyIterationEvidence> =
        property_iteration_loops(symbols, nodes);
    let loop_ids: BTreeSet<NodeId> = property_loops.keys().copied().collect();
    let mut contexts: StructuralContexts = StructuralContexts::default();
    infer_property_iteration_roles(
        symbols,
        nodes,
        property_loops,
        &loop_ids,
        &mut contexts,
        &mut roles,
    );
    propagate_parameter_roles(symbols, nodes, &mut roles);
    let cache_index: CacheEvidenceIndex =
        CacheEvidenceIndex::build(symbols, nodes, &loop_ids, &mut contexts);
    let native_promise_transports: BTreeSet<SymbolId> =
        native_promise_transport_symbols(symbols, nodes);

    for symbol_id in iter_symbols(symbols) {
        let Some(chain): Option<PromiseChainEvidence> =
            promise_chain_for_symbol(symbol_id, symbols, nodes, &loop_ids, &mut contexts)
        else {
            continue;
        };
        let Some(response) = chain.response else {
            continue;
        };
        let Some((cache, url)) = cache_index.correlated_storage(chain) else {
            continue;
        };
        if !native_promise_transports.contains(&chain.transport) {
            continue;
        }
        insert_semantic_role(&mut roles, chain.promise, SemanticRole::Promise);
        insert_semantic_role(&mut roles, response, SemanticRole::Response);
        if let Some(error) = chain.error {
            insert_semantic_role(&mut roles, error, SemanticRole::Error);
        }
        insert_semantic_role(&mut roles, chain.transport, SemanticRole::Transport);
        insert_semantic_role(&mut roles, cache, SemanticRole::Cache);
        insert_semantic_role(&mut roles, url, SemanticRole::Url);
    }
    roles
}

fn insert_semantic_role(
    roles: &mut BTreeMap<SymbolId, BTreeSet<SemanticRole>>,
    symbol: SymbolId,
    role: SemanticRole,
) {
    roles.entry(symbol).or_default().insert(role);
}

fn promise_chain_for_symbol(
    promise: SymbolId,
    symbols: &SymbolTable,
    nodes: &AstNodes<'_>,
    loop_ids: &BTreeSet<NodeId>,
    contexts: &mut StructuralContexts,
) -> Option<PromiseChainEvidence> {
    let declaration: NodeId = symbols.get_declaration(promise);
    let AstKind::VariableDeclarator(declarator) = nodes.kind(declaration) else {
        return None;
    };
    let Expression::CallExpression(catch_call) = declarator.init.as_ref()?.get_inner_expression()
    else {
        return None;
    };
    let (then_expression, catch_callback): (&Expression<'_>, &Argument<'_>) =
        called_member_with_one_argument(catch_call, "catch")?;
    let Expression::CallExpression(then_call) = then_expression.get_inner_expression() else {
        return None;
    };
    let (transport_expression, then_callback): (&Expression<'_>, &Argument<'_>) =
        called_member_with_one_argument(then_call, "then")?;
    let Expression::CallExpression(transport_call) = transport_expression.get_inner_expression()
    else {
        return None;
    };
    if transport_call.optional
        || transport_call.type_parameters.is_some()
        || transport_call.arguments.len() != 1
    {
        return None;
    }
    let transport: SymbolId = expression_symbol(&transport_call.callee, symbols)?;
    let url: SymbolId = expression_symbol(transport_call.arguments[0].as_expression()?, symbols)?;
    let response: Option<SymbolId> = callback_parameter_symbol(then_callback).filter(|symbol| {
        symbol_has_member(*symbol, "ok", false, symbols, nodes)
            && symbol_has_member(*symbol, "json", true, symbols, nodes)
    });
    let catch_parameter: Option<SymbolId> = callback_parameter_symbol(catch_callback);
    let error: Option<SymbolId> =
        catch_parameter.filter(|symbol| symbol_is_directly_thrown(*symbol, symbols, nodes));
    let owner_function: Option<NodeId> = contexts.get(declaration, nodes, loop_ids).function;
    let catch_function: Option<NodeId> = catch_parameter.and_then(|symbol| {
        contexts
            .get(symbols.get_declaration(symbol), nodes, loop_ids)
            .function
    });
    Some(PromiseChainEvidence {
        promise,
        transport,
        url,
        response,
        error,
        owner_function,
        catch_function,
    })
}

fn called_member_with_one_argument<'a>(
    call: &'a CallExpression<'a>,
    expected: &str,
) -> Option<(&'a Expression<'a>, &'a Argument<'a>)> {
    if call.optional || call.type_parameters.is_some() || call.arguments.len() != 1 {
        return None;
    }
    let Expression::StaticMemberExpression(member) = call.callee.get_inner_expression() else {
        return None;
    };
    if member.optional || member.property.name.as_str() != expected {
        return None;
    }
    Some((&member.object, &call.arguments[0]))
}

fn callback_parameter_symbol(argument: &Argument<'_>) -> Option<SymbolId> {
    let parameters: &FormalParameters<'_> = match argument {
        Argument::FunctionExpression(function) => &function.params,
        Argument::ArrowFunctionExpression(function) => &function.params,
        _ => return None,
    };
    if parameters.rest.is_some() || parameters.items.len() != 1 {
        return None;
    }
    let parameter = &parameters.items[0];
    if parameter.pattern.optional || parameter.pattern.type_annotation.is_some() {
        return None;
    }
    let BindingPatternKind::BindingIdentifier(binding) = &parameter.pattern.kind else {
        return None;
    };
    binding.symbol_id.get()
}

fn symbol_has_member(
    symbol: SymbolId,
    expected: &str,
    must_be_called: bool,
    symbols: &SymbolTable,
    nodes: &AstNodes<'_>,
) -> bool {
    symbols.get_resolved_reference_ids(symbol).iter().any(|&reference_id| {
        let reference_node: NodeId = symbols.get_reference(reference_id).node_id();
        let Some(member_node) = nodes.parent_node(reference_node) else {
            return false;
        };
        let AstKind::MemberExpression(member) = member_node.kind() else {
            return false;
        };
        if member_is_optional(member) || member.static_property_name() != Some(expected) {
            return false;
        }
        if !must_be_called {
            return true;
        }
        nodes.parent_node(member_node.id()).is_some_and(|parent| {
            matches!(parent.kind(), AstKind::CallExpression(call) if !call.optional && call.callee.span() == member.span())
        })
    })
}

fn symbol_is_directly_thrown(
    symbol: SymbolId,
    symbols: &SymbolTable,
    nodes: &AstNodes<'_>,
) -> bool {
    symbols.get_resolved_reference_ids(symbol).iter().any(|&reference_id| {
        let reference_node: NodeId = symbols.get_reference(reference_id).node_id();
        let reference_span = nodes.get_node(reference_node).kind().span();
        let Some(mut parent) = nodes.parent_node(reference_node) else {
            return false;
        };
        let thrown_span = if let AstKind::SequenceExpression(sequence) = parent.kind() {
            if sequence.expressions.last().map(GetSpan::span) != Some(reference_span) {
                return false;
            }
            let Some(throw_parent) = nodes.parent_node(parent.id()) else {
                return false;
            };
            parent = throw_parent;
            sequence.span
        } else {
            reference_span
        };
        matches!(parent.kind(), AstKind::ThrowStatement(statement) if statement.argument.span() == thrown_span)
    })
}

fn member_is_optional(member: &MemberExpression<'_>) -> bool {
    match member {
        MemberExpression::ComputedMemberExpression(member) => member.optional,
        MemberExpression::StaticMemberExpression(member) => member.optional,
        MemberExpression::PrivateFieldExpression(member) => member.optional,
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct StructuralContext {
    function: Option<NodeId>,
    loop_id: Option<NodeId>,
    control_test: Option<NodeId>,
    control_body: Option<NodeId>,
    push_call: Option<NodeId>,
}

#[derive(Debug, Default)]
struct StructuralContexts {
    entries: BTreeMap<NodeId, StructuralContext>,
}

impl StructuralContexts {
    fn get(
        &mut self,
        node_id: NodeId,
        nodes: &AstNodes<'_>,
        loop_ids: &BTreeSet<NodeId>,
    ) -> StructuralContext {
        if let Some(context) = self.entries.get(&node_id) {
            return *context;
        }
        let mut path: Vec<NodeId> = Vec::new();
        let mut cursor: NodeId = node_id;
        while !self.entries.contains_key(&cursor) {
            path.push(cursor);
            let Some(parent) = nodes.parent_node(cursor) else {
                break;
            };
            cursor = parent.id();
        }
        while let Some(current) = path.pop() {
            let context: StructuralContext =
                nodes
                    .parent_node(current)
                    .map_or_else(StructuralContext::default, |parent| {
                        let inherited: StructuralContext =
                            self.entries.get(&parent.id()).copied().unwrap_or_default();
                        structural_child_context(inherited, parent.id(), current, nodes, loop_ids)
                    });
            self.entries.insert(current, context);
        }
        self.entries.get(&node_id).copied().unwrap_or_default()
    }
}

fn structural_child_context(
    mut context: StructuralContext,
    parent_id: NodeId,
    child_id: NodeId,
    nodes: &AstNodes<'_>,
    loop_ids: &BTreeSet<NodeId>,
) -> StructuralContext {
    let child_span = nodes.kind(child_id).span();
    match nodes.kind(parent_id) {
        AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => {
            context = StructuralContext {
                function: Some(parent_id),
                ..StructuralContext::default()
            };
        }
        AstKind::ForInStatement(statement) if span_contains(statement.body.span(), child_span) => {
            context.loop_id = loop_ids.contains(&parent_id).then_some(parent_id);
            context.control_test = None;
            context.control_body = None;
            context.push_call = None;
        }
        AstKind::IfStatement(statement) => {
            if span_contains(statement.test.span(), child_span) {
                context.control_test = Some(parent_id);
                context.control_body = None;
            } else if span_contains(statement.consequent.span(), child_span) {
                context.control_test = None;
                context.control_body = Some(parent_id);
            }
        }
        AstKind::LogicalExpression(logical) if logical.operator == LogicalOperator::And => {
            if span_contains(logical.left.span(), child_span) {
                context.control_test = Some(parent_id);
                context.control_body = None;
            } else if span_contains(logical.right.span(), child_span) {
                context.control_test = None;
                context.control_body = Some(parent_id);
            }
        }
        AstKind::CallExpression(call)
            if called_member_with_one_argument(call, "push")
                .is_some_and(|(_, argument)| span_contains(argument.span(), child_span)) =>
        {
            context.push_call = Some(parent_id);
        }
        _ => {}
    }
    context
}

const fn span_contains(outer: oxc_span::Span, inner: oxc_span::Span) -> bool {
    outer.start <= inner.start && inner.end <= outer.end
}

#[derive(Debug, Default)]
struct CacheAccessEvidence {
    stores: BTreeSet<(SymbolId, Option<NodeId>)>,
    guarded: BTreeSet<(Option<NodeId>, NodeId)>,
    returned: BTreeSet<(Option<NodeId>, NodeId)>,
    deleted_in: BTreeSet<Option<NodeId>>,
}

#[derive(Debug, Default)]
struct CacheEvidenceIndex {
    profiles: BTreeMap<(SymbolId, SymbolId), CacheAccessEvidence>,
    by_promise: BTreeMap<SymbolId, BTreeSet<(SymbolId, SymbolId)>>,
}

impl CacheEvidenceIndex {
    fn build(
        symbols: &SymbolTable,
        nodes: &AstNodes<'_>,
        loop_ids: &BTreeSet<NodeId>,
        contexts: &mut StructuralContexts,
    ) -> Self {
        let empty_objects: BTreeSet<SymbolId> = iter_symbols(symbols)
            .into_iter()
            .filter(|symbol| empty_object_binding(*symbol, symbols, nodes))
            .collect();
        let mut index: Self = Self::default();
        for node in nodes.iter() {
            let AstKind::MemberExpression(MemberExpression::ComputedMemberExpression(member)) =
                node.kind()
            else {
                continue;
            };
            if member.optional {
                continue;
            }
            let Some(cache) = expression_symbol(&member.object, symbols) else {
                continue;
            };
            if !empty_objects.contains(&cache) {
                continue;
            }
            let Some(url) = expression_symbol(&member.expression, symbols) else {
                continue;
            };
            let pair: (SymbolId, SymbolId) = (cache, url);
            let context: StructuralContext = contexts.get(node.id(), nodes, loop_ids);
            let parent_id: Option<NodeId> = effective_member_parent(node.id(), nodes);
            let profile: &mut CacheAccessEvidence = index.profiles.entry(pair).or_default();
            if let Some(control) = context.control_test {
                profile.guarded.insert((context.function, control));
            }
            if let (Some(control), Some(parent)) = (context.control_body, parent_id)
                && matches!(
                    nodes.kind(parent),
                    AstKind::ReturnStatement(statement)
                        if statement.argument.as_ref().is_some_and(|argument| argument.span() == member.span)
                )
            {
                profile.returned.insert((context.function, control));
            }
            let Some(parent) = parent_id else {
                continue;
            };
            match nodes.kind(parent) {
                AstKind::AssignmentExpression(assignment)
                    if assignment.operator == AssignmentOperator::Assign
                        && assignment.left.span() == member.span =>
                {
                    if let Some(promise) = expression_symbol(&assignment.right, symbols) {
                        profile.stores.insert((promise, context.function));
                        index.by_promise.entry(promise).or_default().insert(pair);
                    }
                }
                AstKind::UnaryExpression(unary)
                    if unary.operator == UnaryOperator::Delete
                        && unary.argument.span() == member.span =>
                {
                    profile.deleted_in.insert(context.function);
                }
                _ => {}
            }
        }
        index
    }

    fn correlated_storage(&self, chain: PromiseChainEvidence) -> Option<(SymbolId, SymbolId)> {
        let catch_function: NodeId = chain.catch_function?;
        let mut candidates: BTreeSet<(SymbolId, SymbolId)> = BTreeSet::new();
        for pair in self.by_promise.get(&chain.promise)? {
            if pair.1 != chain.url {
                continue;
            }
            let Some(profile) = self.profiles.get(pair) else {
                continue;
            };
            let guarded_return: bool = profile
                .guarded
                .iter()
                .any(|guard| guard.0 == chain.owner_function && profile.returned.contains(guard));
            if profile
                .stores
                .contains(&(chain.promise, chain.owner_function))
                && guarded_return
                && profile.deleted_in.contains(&Some(catch_function))
            {
                candidates.insert(*pair);
            }
        }
        (candidates.len() == 1)
            .then(|| candidates.first().copied())
            .flatten()
    }
}

fn effective_member_parent(node_id: NodeId, nodes: &AstNodes<'_>) -> Option<NodeId> {
    let mut parent: NodeId = nodes.parent_node(node_id)?.id();
    for _ in 0..3 {
        if !matches!(
            nodes.kind(parent),
            AstKind::SimpleAssignmentTarget(_) | AstKind::AssignmentTarget(_)
        ) {
            return Some(parent);
        }
        parent = nodes.parent_node(parent)?.id();
    }
    None
}

fn empty_object_binding(symbol: SymbolId, symbols: &SymbolTable, nodes: &AstNodes<'_>) -> bool {
    let AstKind::VariableDeclarator(declarator) = nodes.kind(symbols.get_declaration(symbol))
    else {
        return false;
    };
    matches!(declarator.init.as_ref().map(Expression::get_inner_expression), Some(Expression::ObjectExpression(object)) if object.properties.is_empty())
}

fn empty_array_binding(symbol: SymbolId, symbols: &SymbolTable, nodes: &AstNodes<'_>) -> bool {
    let AstKind::VariableDeclarator(declarator) = nodes.kind(symbols.get_declaration(symbol))
    else {
        return false;
    };
    matches!(declarator.init.as_ref().map(Expression::get_inner_expression), Some(Expression::ArrayExpression(array)) if array.elements.is_empty())
}

fn infer_property_iteration_roles(
    symbols: &SymbolTable,
    nodes: &AstNodes<'_>,
    mut loops: BTreeMap<NodeId, PropertyIterationEvidence>,
    loop_ids: &BTreeSet<NodeId>,
    contexts: &mut StructuralContexts,
    roles: &mut BTreeMap<SymbolId, BTreeSet<SemanticRole>>,
) {
    let mut joined_lists: BTreeSet<SymbolId> = BTreeSet::new();
    for node in nodes.iter() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        if let Some(list) = ampersand_join_receiver(call, symbols) {
            joined_lists.insert(list);
        }
    }
    for node in nodes.iter() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        let context: StructuralContext = contexts.get(node.id(), nodes, loop_ids);
        let Some(evidence) = context.loop_id.and_then(|loop_id| loops.get_mut(&loop_id)) else {
            continue;
        };
        if is_own_property_call(call, evidence.params, evidence.key, symbols)
            && let Some(control) = context.control_test
        {
            evidence.owning_controls.insert(control);
        }
        let Some(control) = context.control_body else {
            continue;
        };
        let Some(push_id) = context.push_call else {
            continue;
        };
        let Some(list) = push_receiver(push_id, symbols, nodes) else {
            continue;
        };
        let encoded: &mut EncodedPushEvidence = evidence
            .encoded_pushes
            .entry((control, push_id))
            .or_insert(EncodedPushEvidence {
                list,
                key: false,
                value: false,
            });
        if encoded.list != list {
            continue;
        }
        encoded.key |= is_encode_call(call, evidence.key, None, symbols);
        encoded.value |= is_encode_call(call, evidence.params, Some(evidence.key), symbols);
    }
    for evidence in loops.into_values() {
        let correlated: bool = evidence
            .encoded_pushes
            .iter()
            .any(|((control, _), encoded)| {
                evidence.owning_controls.contains(control)
                    && encoded.key
                    && encoded.value
                    && joined_lists.contains(&encoded.list)
                    && empty_array_binding(encoded.list, symbols, nodes)
            });
        if correlated {
            insert_semantic_role(roles, evidence.params, SemanticRole::Params);
            insert_semantic_role(roles, evidence.key, SemanticRole::Key);
        }
    }
}

fn property_iteration_loops(
    symbols: &SymbolTable,
    nodes: &AstNodes<'_>,
) -> BTreeMap<NodeId, PropertyIterationEvidence> {
    let mut loops: BTreeMap<NodeId, PropertyIterationEvidence> = BTreeMap::new();
    for node in nodes.iter() {
        let AstKind::ForInStatement(statement) = node.kind() else {
            continue;
        };
        let Some((key, params)) = for_in_symbols(statement, symbols) else {
            continue;
        };
        loops.insert(
            node.id(),
            PropertyIterationEvidence {
                key,
                params,
                owning_controls: BTreeSet::new(),
                encoded_pushes: BTreeMap::new(),
            },
        );
    }
    loops
}

#[derive(Debug, Clone)]
struct PropertyIterationEvidence {
    key: SymbolId,
    params: SymbolId,
    owning_controls: BTreeSet<NodeId>,
    encoded_pushes: BTreeMap<(NodeId, NodeId), EncodedPushEvidence>,
}

#[derive(Debug, Clone, Copy)]
struct EncodedPushEvidence {
    list: SymbolId,
    key: bool,
    value: bool,
}

fn for_in_symbols(
    statement: &oxc_ast::ast::ForInStatement<'_>,
    symbols: &SymbolTable,
) -> Option<(SymbolId, SymbolId)> {
    let ForStatementLeft::VariableDeclaration(declaration) = &statement.left else {
        return None;
    };
    if declaration.declarations.len() != 1 {
        return None;
    }
    let BindingPatternKind::BindingIdentifier(key) = &declaration.declarations[0].id.kind else {
        return None;
    };
    let key: SymbolId = key.symbol_id.get()?;
    let params: SymbolId = expression_symbol(&statement.right, symbols)?;
    Some((key, params))
}

fn is_own_property_call(
    call: &CallExpression<'_>,
    params: SymbolId,
    key: SymbolId,
    symbols: &SymbolTable,
) -> bool {
    if call.optional || call.type_parameters.is_some() || call.arguments.len() != 2 {
        return false;
    }
    let Expression::StaticMemberExpression(call_member) = call.callee.get_inner_expression() else {
        return false;
    };
    let Expression::StaticMemberExpression(has_own) = call_member.object.get_inner_expression()
    else {
        return false;
    };
    let Expression::StaticMemberExpression(prototype) = has_own.object.get_inner_expression()
    else {
        return false;
    };
    call_member.property.name.as_str() == "call"
        && has_own.property.name.as_str() == "hasOwnProperty"
        && prototype.property.name.as_str() == "prototype"
        && !call_member.optional
        && !has_own.optional
        && !prototype.optional
        && unresolved_global(&prototype.object, "Object", symbols)
        && call.arguments[0]
            .as_expression()
            .and_then(|argument| expression_symbol(argument, symbols))
            == Some(params)
        && call.arguments[1]
            .as_expression()
            .and_then(|argument| expression_symbol(argument, symbols))
            == Some(key)
}

fn is_encode_call(
    call: &CallExpression<'_>,
    object: SymbolId,
    computed_key: Option<SymbolId>,
    symbols: &SymbolTable,
) -> bool {
    if call.optional || call.type_parameters.is_some() || call.arguments.len() != 1 {
        return false;
    }
    if !unresolved_global(&call.callee, "encodeURIComponent", symbols) {
        return false;
    }
    let Some(argument) = call.arguments[0].as_expression() else {
        return false;
    };
    match computed_key {
        None => expression_symbol(argument, symbols) == Some(object),
        Some(key) => {
            let Expression::ComputedMemberExpression(member) = argument.get_inner_expression()
            else {
                return false;
            };
            !member.optional
                && expression_symbol(&member.object, symbols) == Some(object)
                && expression_symbol(&member.expression, symbols) == Some(key)
        }
    }
}

fn ampersand_join_receiver(call: &CallExpression<'_>, symbols: &SymbolTable) -> Option<SymbolId> {
    let (object, argument): (&Expression<'_>, &Argument<'_>) =
        called_member_with_one_argument(call, "join")?;
    let Expression::StringLiteral(delimiter) = argument.as_expression()?.get_inner_expression()
    else {
        return None;
    };
    (delimiter.value.as_str() == "&")
        .then(|| expression_symbol(object, symbols))
        .flatten()
}

fn push_receiver(call_id: NodeId, symbols: &SymbolTable, nodes: &AstNodes<'_>) -> Option<SymbolId> {
    let AstKind::CallExpression(call) = nodes.kind(call_id) else {
        return None;
    };
    let (object, _): (&Expression<'_>, &Argument<'_>) =
        called_member_with_one_argument(call, "push")?;
    expression_symbol(object, symbols)
}

fn propagate_parameter_roles(
    symbols: &SymbolTable,
    nodes: &AstNodes<'_>,
    roles: &mut BTreeMap<SymbolId, BTreeSet<SemanticRole>>,
) {
    let immutable_functions: BTreeSet<SymbolId> = immutable_function_symbols(symbols, nodes);
    let mut edges: BTreeMap<SymbolId, BTreeSet<SymbolId>> = BTreeMap::new();
    for node in nodes.iter() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        let Some(parameters) =
            called_function_parameters(&call.callee, symbols, nodes, &immutable_functions)
        else {
            continue;
        };
        if parameters.rest.is_some() || parameters.items.len() != call.arguments.len() {
            continue;
        }
        for (parameter, argument) in parameters.items.iter().zip(&call.arguments) {
            let BindingPatternKind::BindingIdentifier(binding) = &parameter.pattern.kind else {
                continue;
            };
            let Some(parameter_symbol) = binding.symbol_id.get() else {
                continue;
            };
            let Some(argument_symbol) = argument
                .as_expression()
                .and_then(|expression| expression_symbol(expression, symbols))
            else {
                continue;
            };
            edges
                .entry(parameter_symbol)
                .or_default()
                .insert(argument_symbol);
        }
    }
    let mut pending: VecDeque<SymbolId> = roles
        .iter()
        .filter_map(|(symbol, found)| found.contains(&SemanticRole::Params).then_some(*symbol))
        .collect();
    while let Some(source) = pending.pop_front() {
        let Some(targets) = edges.get(&source) else {
            continue;
        };
        for target in targets {
            let inserted: bool = roles
                .entry(*target)
                .or_default()
                .insert(SemanticRole::Params);
            if inserted {
                pending.push_back(*target);
            }
        }
    }
}

fn immutable_function_symbols(symbols: &SymbolTable, nodes: &AstNodes<'_>) -> BTreeSet<SymbolId> {
    iter_symbols(symbols)
        .into_iter()
        .filter(|symbol| {
            matches!(
                nodes.kind(symbols.get_declaration(*symbol)),
                AstKind::Function(_)
            ) && symbols.get_redeclarations(*symbol).is_empty()
                && symbols
                    .get_resolved_reference_ids(*symbol)
                    .iter()
                    .all(|reference_id| !symbols.get_reference(*reference_id).is_write())
        })
        .collect()
}

fn native_promise_transport_symbols(
    symbols: &SymbolTable,
    nodes: &AstNodes<'_>,
) -> BTreeSet<SymbolId> {
    let immutable_functions: BTreeSet<SymbolId> = immutable_function_symbols(symbols, nodes);
    let mut parameters: BTreeMap<SymbolId, Vec<(SymbolId, usize, bool)>> = BTreeMap::new();
    for function_symbol in &immutable_functions {
        let AstKind::Function(function) = nodes.kind(symbols.get_declaration(*function_symbol))
        else {
            continue;
        };
        for (index, parameter) in function.params.items.iter().enumerate() {
            let BindingPatternKind::BindingIdentifier(binding) = &parameter.pattern.kind else {
                continue;
            };
            if let Some(parameter_symbol) = binding.symbol_id.get() {
                parameters.entry(*function_symbol).or_default().push((
                    parameter_symbol,
                    index,
                    true,
                ));
            }
        }
    }

    let mut call_counts: BTreeMap<SymbolId, usize> = BTreeMap::new();
    for node in nodes.iter() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        let Some(function_symbol) = expression_symbol(&call.callee, symbols) else {
            continue;
        };
        if !immutable_functions.contains(&function_symbol) {
            continue;
        }
        *call_counts.entry(function_symbol).or_default() += 1;
        let exact_arguments: bool = nodes
            .kind(symbols.get_declaration(function_symbol))
            .as_function()
            .is_some_and(|function| {
                function.params.rest.is_none()
                    && function.params.items.len() == call.arguments.len()
            });
        if let Some(function_parameters) = parameters.get_mut(&function_symbol) {
            for (_, index, proven) in function_parameters {
                *proven &= exact_arguments
                    && call
                        .arguments
                        .get(*index)
                        .is_some_and(|argument| argument_returns_native_promise(argument, symbols));
            }
        }
    }

    parameters
        .into_iter()
        .flat_map(|(function, function_parameters)| {
            let call_count: usize = call_counts.get(&function).copied().unwrap_or_default();
            let all_references_are_calls: bool =
                call_count > 0 && call_count == symbols.get_resolved_reference_ids(function).len();
            function_parameters
                .into_iter()
                .filter_map(move |(parameter, _, proven)| {
                    (proven && all_references_are_calls).then_some(parameter)
                })
        })
        .collect()
}

fn argument_returns_native_promise(argument: &Argument<'_>, symbols: &SymbolTable) -> bool {
    match argument {
        Argument::FunctionExpression(function) if !function.generator => function
            .body
            .as_ref()
            .is_some_and(|body| statement_list_returns_native_promise(&body.statements, symbols)),
        Argument::ArrowFunctionExpression(function) if function.expression => function
            .body
            .statements
            .first()
            .is_some_and(|statement| match statement {
                Statement::ExpressionStatement(expression) => {
                    is_native_promise_expression(&expression.expression, symbols)
                }
                _ => false,
            }),
        Argument::ArrowFunctionExpression(function) => {
            statement_list_returns_native_promise(&function.body.statements, symbols)
        }
        _ => false,
    }
}

fn statement_list_returns_native_promise(
    statements: &[Statement<'_>],
    symbols: &SymbolTable,
) -> bool {
    let Some(Statement::ReturnStatement(returned)) = statements.last() else {
        return false;
    };
    if !returned
        .argument
        .as_ref()
        .is_some_and(|expression| is_native_promise_expression(expression, symbols))
    {
        return false;
    }
    let mut probe: NativePromiseReturnProbe<'_> = NativePromiseReturnProbe {
        symbols,
        all_returns_native: true,
    };
    for statement in statements {
        probe.visit_statement(statement);
    }
    probe.all_returns_native
}

struct NativePromiseReturnProbe<'s> {
    symbols: &'s SymbolTable,
    all_returns_native: bool,
}

impl<'a> Visit<'a> for NativePromiseReturnProbe<'_> {
    fn visit_return_statement(&mut self, returned: &oxc_ast::ast::ReturnStatement<'a>) {
        self.all_returns_native &= returned
            .argument
            .as_ref()
            .is_some_and(|expression| is_native_promise_expression(expression, self.symbols));
    }

    fn visit_function(
        &mut self,
        _function: &oxc_ast::ast::Function<'a>,
        _flags: oxc::syntax::scope::ScopeFlags,
    ) {
    }

    fn visit_arrow_function_expression(
        &mut self,
        _function: &oxc_ast::ast::ArrowFunctionExpression<'a>,
    ) {
    }
}

fn is_native_promise_expression(expression: &Expression<'_>, symbols: &SymbolTable) -> bool {
    match expression.get_inner_expression() {
        Expression::CallExpression(call) => {
            if call.optional || call.type_parameters.is_some() {
                return false;
            }
            let Expression::StaticMemberExpression(member) = call.callee.get_inner_expression()
            else {
                return false;
            };
            !member.optional
                && member.property.name.as_str() == "resolve"
                && unresolved_global(&member.object, "Promise", symbols)
        }
        Expression::NewExpression(construction) => {
            construction.type_parameters.is_none()
                && unresolved_global(&construction.callee, "Promise", symbols)
        }
        _ => false,
    }
}

fn called_function_parameters<'a>(
    callee: &'a Expression<'a>,
    symbols: &SymbolTable,
    nodes: &'a AstNodes<'a>,
    immutable_functions: &BTreeSet<SymbolId>,
) -> Option<&'a FormalParameters<'a>> {
    match callee.get_inner_expression() {
        Expression::Identifier(identifier) => {
            let reference_id = identifier.reference_id.get()?;
            let function_symbol: SymbolId = symbols.get_reference(reference_id).symbol_id()?;
            if !immutable_functions.contains(&function_symbol) {
                return None;
            }
            let AstKind::Function(function) = nodes.kind(symbols.get_declaration(function_symbol))
            else {
                return None;
            };
            Some(&function.params)
        }
        _ => None,
    }
}

fn expression_symbol(expression: &Expression<'_>, symbols: &SymbolTable) -> Option<SymbolId> {
    let Expression::Identifier(identifier) = expression.get_inner_expression() else {
        return None;
    };
    let reference_id = identifier.reference_id.get()?;
    symbols.get_reference(reference_id).symbol_id()
}

fn unresolved_global(expression: &Expression<'_>, expected: &str, symbols: &SymbolTable) -> bool {
    let Expression::Identifier(identifier) = expression.get_inner_expression() else {
        return false;
    };
    if identifier.name.as_str() != expected {
        return false;
    }
    let Some(reference_id) = identifier.reference_id.get() else {
        return false;
    };
    symbols.get_reference(reference_id).symbol_id().is_none()
}

fn assigned_from_name(
    symbol_id: SymbolId,
    symbols: &SymbolTable,
    nodes: &AstNodes<'_>,
) -> Option<String> {
    let decl_node: NodeId = symbols.get_declaration(symbol_id);
    let AstKind::VariableDeclarator(declarator) = nodes.kind(decl_node) else {
        return None;
    };
    match declarator.init.as_ref()? {
        Expression::CallExpression(call) => {
            object_keys_concat_name(call, symbols).or_else(|| match &call.callee {
                Expression::StaticMemberExpression(member) => {
                    Some(member.property.name.as_str().to_owned())
                }
                Expression::Identifier(id) => Some(id.name.as_str().to_owned()),
                _ => None,
            })
        }
        Expression::NewExpression(new_expr) => match &new_expr.callee {
            Expression::Identifier(id) => Some(id.name.as_str().to_owned()),
            _ => None,
        },
        _ => None,
    }
}

fn object_keys_concat_name(call: &CallExpression<'_>, symbols: &SymbolTable) -> Option<String> {
    if call.optional || call.type_parameters.is_some() {
        return None;
    }
    let Expression::StaticMemberExpression(concat) = call.callee.get_inner_expression() else {
        return None;
    };
    if concat.property.name.as_str() != "concat" {
        return None;
    }
    let Expression::CallExpression(keys_call) = concat.object.get_inner_expression() else {
        return None;
    };
    if keys_call.optional || keys_call.type_parameters.is_some() {
        return None;
    }
    let Expression::StaticMemberExpression(keys) = keys_call.callee.get_inner_expression() else {
        return None;
    };
    if keys.property.name.as_str() != "keys" {
        return None;
    }
    let Expression::Identifier(object) = keys.object.get_inner_expression() else {
        return None;
    };
    if object.name.as_str() != "Object" {
        return None;
    }
    let reference_id = object.reference_id.get()?;
    symbols
        .get_reference(reference_id)
        .symbol_id()
        .is_none()
        .then_some("keys".to_owned())
}

fn dynamic_name_lookup_exists(program: &Program<'_>) -> bool {
    let mut probe = DynamicNameLookupProbe { found: false };
    probe.visit_program(program);
    probe.found
}

struct DynamicNameLookupProbe {
    found: bool,
}

impl<'a> Visit<'a> for DynamicNameLookupProbe {
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

fn is_usable_inferred_name(candidate: &str) -> bool {
    !is_likely_mangled(candidate) && !is_js_reserved(candidate)
}

const MAX_NEARBY_STRINGS: usize = 4;
const MAX_MEMBER_CALL_LITERALS: usize = 8;
const MAX_STRING_SEARCH_DEPTH: usize = 8;
const MAX_MANGLED_SOURCE_BYTES: usize = 1 << 20;

fn declaration_string_literals(
    symbol_id: SymbolId,
    symbols: &SymbolTable,
    nodes: &AstNodes<'_>,
) -> Vec<String> {
    let decl_node: NodeId = symbols.get_declaration(symbol_id);
    let AstKind::VariableDeclarator(declarator) = nodes.kind(decl_node) else {
        return Vec::new();
    };
    let Some(init): Option<&Expression<'_>> = declarator.init.as_ref() else {
        return Vec::new();
    };
    let mut found: Vec<String> = Vec::new();
    collect_string_literals(init, 0, &mut found);
    found
}

fn collect_string_literals(expr: &Expression<'_>, depth: usize, found: &mut Vec<String>) {
    if depth >= MAX_STRING_SEARCH_DEPTH || found.len() >= MAX_NEARBY_STRINGS {
        return;
    }
    match expr.get_inner_expression() {
        Expression::StringLiteral(literal) => found.push(literal.value.as_str().to_owned()),
        Expression::CallExpression(call) => {
            for argument in &call.arguments {
                if let Some(inner) = argument.as_expression() {
                    collect_string_literals(inner, depth.saturating_add(1), found);
                }
            }
        }
        Expression::NewExpression(construction) => {
            for argument in &construction.arguments {
                if let Some(inner) = argument.as_expression() {
                    collect_string_literals(inner, depth.saturating_add(1), found);
                }
            }
        }
        _ => {}
    }
}

fn scope_id_to_u32(scope_id: ScopeId) -> u32 {
    use std::hash::{Hash, Hasher};
    let mut hasher: std::collections::hash_map::DefaultHasher =
        std::collections::hash_map::DefaultHasher::new();
    scope_id.hash(&mut hasher);
    u32::try_from(hasher.finish() & u64::from(u32::MAX)).unwrap_or(u32::MAX)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn restore_emits_plan_for_short_ids() {
        let src: &str = "function a(b){var c=b+1;return c;}";
        let r: TerserRestoreReport =
            restore_terser_mangled(src).expect("fixture must be within the source limit");
        assert!(r.identifiers_renamed > 0);
        assert!(!r.rewritten.is_empty());
    }

    #[test]
    fn does_not_rename_member_expression_fields() {
        let src: &str = "function f(){return obj.x;}";
        let r: TerserRestoreReport =
            restore_terser_mangled(src).expect("fixture must be within the source limit");
        assert!(r.rewritten.contains("obj.x"));
    }

    #[test]
    fn skips_already_long_names() {
        let src: &str = "function longFunctionName(){var alsoLong=1;return alsoLong;}";
        let r: TerserRestoreReport =
            restore_terser_mangled(src).expect("fixture must be within the source limit");
        assert_eq!(r.identifiers_renamed, 0);
    }
}
