use indexmap::IndexSet;
use oxc_allocator::Allocator;
use oxc_ast::AstKind;
use oxc_ast::ast::ModuleExportName;
use oxc_parser::Parser;
use oxc_semantic::{
    AstNodes, NodeId, ScopeId, ScopeTree, Semantic, SemanticBuilder, SymbolId, SymbolTable,
};
use oxc_span::{SourceType, Span};

use super::rename_scope::{RenameSafety, collect_reserved_names, is_reserved_binding_name};
use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct ExportRenameStats {
    pub(super) exports_renamed: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, ExportRenameStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    if !source_type.is_module() {
        return (RuleOutcome::empty(), ExportRenameStats::default());
    }
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), ExportRenameStats::default());
    }

    let semantic_ret: oxc_semantic::SemanticBuilderReturn<'_> = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .with_scope_tree_child_ids(true)
        .build(&parsed.program);
    if !semantic_ret.errors.is_empty() {
        return (RuleOutcome::empty(), ExportRenameStats::default());
    }
    let semantic: Semantic<'_> = semantic_ret.semantic;
    let symbols: &SymbolTable = semantic.symbols();
    let scopes: &ScopeTree = semantic.scopes();
    let nodes: &AstNodes<'_> = semantic.nodes();
    let root_scope: ScopeId = scopes.root_scope_id();

    let mut reserved: IndexSet<String> = collect_reserved_names(&semantic);

    let candidates: Vec<ExportCandidate> = collect_candidates(&semantic, root_scope);
    if candidates.is_empty() {
        return (RuleOutcome::empty(), ExportRenameStats::default());
    }

    let safety: RenameSafety<'_> = RenameSafety {
        symbols,
        scopes,
        nodes,
    };
    let mut stats: ExportRenameStats = ExportRenameStats::default();
    let mut edits: Vec<Edit> = Vec::new();
    for candidate in candidates {
        let owner_scope: ScopeId = symbols.get_scope_id(candidate.symbol_id);
        let exported: &str = candidate.exported_name.as_str();
        if !safety.rename_is_safe(
            candidate.symbol_id,
            owner_scope,
            exported,
            &reserved,
            &candidate.local_name,
        ) {
            continue;
        }

        reserved.insert(candidate.exported_name.clone());
        reserved.shift_remove(candidate.local_name.as_str());

        edits.push(Edit {
            start: candidate.specifier_span.start as usize,
            end: candidate.specifier_span.end as usize,
            replacement: candidate.exported_name.clone(),
        });
        push_reference_edits(
            symbols,
            nodes,
            candidate.symbol_id,
            &candidate.exported_name,
            candidate.specifier_span,
            &mut edits,
        );
        stats.exports_renamed += 1;
    }

    if edits.is_empty() {
        return (RuleOutcome::empty(), ExportRenameStats::default());
    }
    (RuleOutcome { edits }, stats)
}

struct ExportCandidate {
    symbol_id: SymbolId,
    local_name: String,
    exported_name: String,
    specifier_span: Span,
}

fn collect_candidates(semantic: &Semantic<'_>, root_scope: ScopeId) -> Vec<ExportCandidate> {
    let nodes: &AstNodes<'_> = semantic.nodes();
    let scopes: &ScopeTree = semantic.scopes();
    let symbols: &SymbolTable = semantic.symbols();
    let mut candidates: Vec<ExportCandidate> = Vec::new();
    let mut claimed_targets: IndexSet<String> = IndexSet::new();
    for node in nodes.iter() {
        let AstKind::ExportNamedDeclaration(export) = node.kind() else {
            continue;
        };
        if export.source.is_some() {
            continue;
        }
        for specifier in &export.specifiers {
            let ModuleExportName::IdentifierReference(local) = &specifier.local else {
                continue;
            };
            let exported_name: &str = match &specifier.exported {
                ModuleExportName::IdentifierName(name) => name.name.as_str(),
                ModuleExportName::IdentifierReference(name) => name.name.as_str(),
                ModuleExportName::StringLiteral(_) => continue,
            };
            let local_name: &str = local.name.as_str();
            if exported_name == local_name {
                continue;
            }
            if exported_name.len() < local_name.len() {
                continue;
            }
            if is_reserved_binding_name(exported_name) {
                continue;
            }
            if claimed_targets.contains(exported_name) {
                continue;
            }
            let Some(symbol_id) = resolve_local_symbol(symbols, local) else {
                continue;
            };
            if symbols.get_scope_id(symbol_id) != root_scope {
                continue;
            }
            if is_import_binding(nodes, symbols, symbol_id) {
                continue;
            }
            if is_already_exported_name(scopes, root_scope, exported_name) {
                continue;
            }
            claimed_targets.insert(exported_name.to_owned());
            candidates.push(ExportCandidate {
                symbol_id,
                local_name: local_name.to_owned(),
                exported_name: exported_name.to_owned(),
                specifier_span: specifier.span,
            });
        }
    }
    candidates
}

fn resolve_local_symbol(
    symbols: &SymbolTable,
    local: &oxc_ast::ast::IdentifierReference<'_>,
) -> Option<SymbolId> {
    let reference_id: oxc_semantic::ReferenceId = local.reference_id.get()?;
    symbols.get_reference(reference_id).symbol_id()
}

fn is_import_binding(nodes: &AstNodes<'_>, symbols: &SymbolTable, symbol_id: SymbolId) -> bool {
    let declaration: NodeId = symbols.get_declaration(symbol_id);
    matches!(
        nodes.kind(declaration),
        AstKind::ImportSpecifier(_)
            | AstKind::ImportDefaultSpecifier(_)
            | AstKind::ImportNamespaceSpecifier(_)
    )
}

fn is_already_exported_name(scopes: &ScopeTree, root_scope: ScopeId, name: &str) -> bool {
    scopes.has_binding(root_scope, name)
}

fn push_reference_edits(
    symbols: &SymbolTable,
    nodes: &AstNodes<'_>,
    symbol_id: SymbolId,
    new_name: &str,
    specifier_span: Span,
    edits: &mut Vec<Edit>,
) {
    let declaration_span: Span = symbols.get_span(symbol_id);
    edits.push(Edit {
        start: declaration_span.start as usize,
        end: declaration_span.end as usize,
        replacement: new_name.to_owned(),
    });
    for &reference_id in symbols.get_resolved_reference_ids(symbol_id) {
        let node_id: NodeId = symbols.get_reference(reference_id).node_id();
        if let AstKind::IdentifierReference(ident) = nodes.kind(node_id) {
            if ident.span.start >= specifier_span.start && ident.span.end <= specifier_span.end {
                continue;
            }
            edits.push(Edit {
                start: ident.span.start as usize,
                end: ident.span.end as usize,
                replacement: new_name.to_owned(),
            });
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::recover;
    use crate::unminify::ast::{Edit, RuleOutcome};

    fn apply(source: &str) -> String {
        let (outcome, _stats): (RuleOutcome, super::ExportRenameStats) = recover(source);
        let mut sorted: Vec<&Edit> = outcome.edits.iter().collect();
        sorted.sort_by_key(|edit: &&Edit| core::cmp::Reverse(edit.start));
        let mut out: String = source.to_owned();
        for edit in sorted {
            out.replace_range(edit.start..edit.end, &edit.replacement);
        }
        out
    }

    #[test]
    fn aliased_export_restores_developer_name() {
        let source: &str = "function a() { return 1; }\nconst y = a();\nexport { a as compute };";
        let (_outcome, stats): (RuleOutcome, super::ExportRenameStats) = recover(source);
        assert_eq!(stats.exports_renamed, 1);
        let out: String = apply(source);
        assert!(
            out.contains("function compute()"),
            "binding rename missing: {out}"
        );
        assert!(
            out.contains("const y = compute();"),
            "ref rewrite missing: {out}"
        );
        assert!(
            out.contains("export { compute };"),
            "alias not collapsed: {out}"
        );
        assert!(!out.contains("as compute"), "stray `as` clause: {out}");
    }

    #[test]
    fn class_export_alias_recovers() {
        let source: &str = "class h {}\nexport { h as Widget };";
        let (_outcome, stats): (RuleOutcome, super::ExportRenameStats) = recover(source);
        assert_eq!(stats.exports_renamed, 1);
        let out: String = apply(source);
        assert!(out.contains("class Widget {}"), "class not renamed: {out}");
        assert!(
            out.contains("export { Widget };"),
            "export not collapsed: {out}"
        );
    }

    #[test]
    fn shorter_export_name_is_not_a_recovery() {
        let source: &str = "function longName() {}\nexport { longName as x };";
        let (_outcome, stats): (RuleOutcome, super::ExportRenameStats) = recover(source);
        assert_eq!(
            stats.exports_renamed, 0,
            "a shorter export name is not a developer-name recovery"
        );
    }

    #[test]
    fn collision_with_another_binding_blocks_rename() {
        let source: &str = "function a() {}\nfunction compute() {}\nexport { a as compute };\nconsole.log(compute);";
        let (_outcome, stats): (RuleOutcome, super::ExportRenameStats) = recover(source);
        assert_eq!(
            stats.exports_renamed, 0,
            "renaming `a`->`compute` collides with the existing `compute`"
        );
    }

    #[test]
    fn re_exported_import_is_not_renamed() {
        let source: &str = "import { foo as a } from 'm';\nexport { a as bar };";
        let (_outcome, stats): (RuleOutcome, super::ExportRenameStats) = recover(source);
        assert_eq!(
            stats.exports_renamed, 0,
            "an imported binding must not be promoted; that is the import owner's name"
        );
    }

    #[test]
    fn plain_export_without_alias_is_untouched() {
        let source: &str = "function compute() {}\nexport { compute };";
        let (_outcome, stats): (RuleOutcome, super::ExportRenameStats) = recover(source);
        assert_eq!(stats.exports_renamed, 0);
    }

    #[test]
    fn string_literal_export_name_is_untouched() {
        let source: &str = "function a() {}\nexport { a as 'weird-name' };";
        let (_outcome, stats): (RuleOutcome, super::ExportRenameStats) = recover(source);
        assert_eq!(stats.exports_renamed, 0);
    }

    #[test]
    fn re_exported_from_source_is_untouched() {
        let source: &str = "export { a as compute } from './other';";
        let (_outcome, stats): (RuleOutcome, super::ExportRenameStats) = recover(source);
        assert_eq!(
            stats.exports_renamed, 0,
            "`export ... from` re-exports a foreign binding, not a local one"
        );
    }
}
