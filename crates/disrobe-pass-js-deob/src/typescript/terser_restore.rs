use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ops::Range;
use std::sync::Arc;

use oxc_allocator::Allocator;
use oxc_ast::AstKind;
use oxc_parser::Parser;
use oxc_semantic::{
    AstNodes, NodeId, ScopeId, ScopeTree, Semantic, SemanticBuilder, SymbolId, SymbolTable,
};
use oxc_span::SourceType;
use serde::Serialize;

use crate::mangled_names::{
    Context, ContextNameSource, CorpusNameSource, HeuristicNameSource, NameRegistry, RestoreStats,
    ScopeKey, SymbolRole,
};

#[derive(Debug, Clone, Default, Serialize)]
pub struct TerserRestoreReport {
    pub identifiers_renamed: usize,
    pub references_rewritten: usize,
    pub restore_stats: RestoreStats,
    pub rewritten: String,
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

    let mut registry: NameRegistry = NameRegistry::new()
        .with_source(Arc::new(CorpusNameSource::well_known_minified()))
        .with_source(Arc::new(ContextNameSource::new()))
        .with_source(Arc::new(HeuristicNameSource::new()));
    for scope_id in scopes.descendants_from_root() {
        for name in scopes.get_bindings(scope_id).keys() {
            if !is_likely_mangled(name.as_str()) {
                registry.reserve(name.as_str().to_owned());
            }
        }
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
        }
        contexts.insert(symbol_id, ctx);
    }

    let context_by_name: BTreeMap<String, Context> = contexts
        .values()
        .map(|c: &Context| (c.original.clone(), c.clone()))
        .collect();
    let (plan, restore_stats): (BTreeMap<String, String>, RestoreStats) =
        registry.restore(&context_by_name);

    let mut edits: Vec<(Range<usize>, String)> = Vec::new();
    let mut idents_renamed: usize = 0;
    let mut refs_rewritten: usize = 0;
    let mut seen_originals: BTreeSet<String> = BTreeSet::new();
    for (symbol_id, ctx) in &contexts {
        let Some(new_name): Option<&String> = plan.get(&ctx.original) else {
            continue;
        };
        if seen_originals.insert(ctx.original.clone()) {
            idents_renamed = idents_renamed.saturating_add(1);
        }
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

    TerserRestoreReport {
        identifiers_renamed: idents_renamed,
        references_rewritten: refs_rewritten,
        restore_stats,
        rewritten: out,
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
