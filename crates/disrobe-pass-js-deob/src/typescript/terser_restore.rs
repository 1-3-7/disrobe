use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ops::Range;
use std::sync::Arc;

use oxc_allocator::Allocator;
use oxc_ast::ast::{CallExpression, Expression, Program, WithStatement};
use oxc_ast::{AstKind, Visit};
use oxc_parser::Parser;
use oxc_semantic::{
    AstNodes, NodeId, ScopeId, ScopeTree, Semantic, SemanticBuilder, SymbolId, SymbolTable,
};
use oxc_span::{GetSpan, SourceType};
use serde::Serialize;

use crate::mangled_names::{
    Context, ContextNameSource, CorpusNameSource, HeuristicNameSource, NameRegistry, RestoreStats,
    RestoredName, ScopeKey, Suggestion, SymbolRole,
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

#[must_use]
pub fn restore_terser_mangled(source: &str) -> TerserRestoreReport {
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
        let r: TerserRestoreReport = restore_terser_mangled(src);
        assert!(r.identifiers_renamed > 0);
        assert!(!r.rewritten.is_empty());
    }

    #[test]
    fn does_not_rename_member_expression_fields() {
        let src: &str = "function f(){return obj.x;}";
        let r: TerserRestoreReport = restore_terser_mangled(src);
        assert!(r.rewritten.contains("obj.x"));
    }

    #[test]
    fn skips_already_long_names() {
        let src: &str = "function longFunctionName(){var alsoLong=1;return alsoLong;}";
        let r: TerserRestoreReport = restore_terser_mangled(src);
        assert_eq!(r.identifiers_renamed, 0);
    }
}
